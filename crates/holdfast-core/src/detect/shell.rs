//! OSC 133 shell-integration injection (spec §8.5).
//!
//! Holdfast types a one-line snippet into the session at start-up so the
//! shell emits semantic markers. §8.5 mandates *typing* it rather than
//! setting environment variables, and that is the only mechanism that
//! works: rc files run after the environment is read and would clobber an
//! inherited `PS1`, whereas a line the shell reads as its first input,
//! normally at its first prompt, wraps whatever prompt the user actually
//! ended up with. What has to be typed is
//! what *runs* the snippet, not its text: bash's typed line evaluates a
//! snippet the environment carries, because the whole snippet is longer
//! than macOS lets a typed line be (see [`BASH_INJECTION_LINE`]).
//!
//! Consequence, accepted for 0.0.2: the typed line is echoed by the shell
//! and therefore appears once in the session's output buffer.

/// Shells Holdfast knows how to integrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }

    /// The code that integrates this shell, as one line without a trailing
    /// newline. Complete in itself: typed at a prompt, it integrates the
    /// shell that reads it. What Holdfast types at start-up is
    /// [`Shell::injection_line`], which for bash evaluates this.
    pub fn integration_snippet(self) -> &'static str {
        match self {
            Self::Bash => BASH_INTEGRATION,
            Self::Zsh => ZSH_INTEGRATION,
            Self::Fish => FISH_INTEGRATION,
        }
    }

    /// The line Holdfast types at start-up, without its trailing newline:
    /// the snippet itself for zsh and fish, and [`BASH_INJECTION_LINE`] for
    /// bash, whose snippet is too long to type (see there).
    pub fn injection_line(self) -> &'static str {
        match self {
            Self::Bash => BASH_INJECTION_LINE,
            Self::Zsh | Self::Fish => self.integration_snippet(),
        }
    }

    /// The environment [`Shell::injection_line`] needs: bash's snippet,
    /// under [`BASH_INTEGRATION_CARRIER`]. Nothing for zsh and fish.
    pub fn injection_env(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Bash => &[(BASH_INTEGRATION_CARRIER, BASH_INTEGRATION)],
            Self::Zsh | Self::Fish => &[],
        }
    }

    /// Arguments Holdfast puts **ahead of** the caller's own when it spawns
    /// this shell: `-C` [`FISH_HISTORY_INIT`] for fish, so it never writes
    /// or reads a history file (GH #252; the whole policy is
    /// `session::launch::history_defaults`).
    ///
    /// Ahead, because an option after a script operand is the script's
    /// argument rather than fish's. Applied whether or not the snippet is
    /// typed, since it is not typed: it is how fish is started.
    pub fn spawn_args(self) -> &'static [&'static str] {
        match self {
            Self::Fish => &["-C", FISH_HISTORY_INIT],
            Self::Bash | Self::Zsh => &[],
        }
    }
}

/// What Holdfast puts ahead of the caller's arguments when it spawns
/// `command args` with the call's own `env` (GH #252): the recognised
/// shell's [`Shell::spawn_args`], unless the call sets a **non-empty**
/// `fish_history` itself.
///
/// Such a fish starts without the init command, as a plain fish with that
/// variable in its environment, so a config.fish that sets `fish_history`
/// still overrides the call's value. An empty `fish_history` is
/// Holdfast's own default restated and gets the init like any other
/// session: without it, config.fish's assignment wins and the session
/// saves to, and reads from, the operator's history (measured on fish
/// 3.7.0, 4.0.2 and 4.9.3).
pub fn history_spawn_args(
    command: &str,
    args: &[String],
    env: &[(String, String)],
) -> &'static [&'static str] {
    if env
        .iter()
        .any(|(k, v)| k == "fish_history" && !v.is_empty())
    {
        return &[];
    }
    detect_shell(command, args).map_or(&[], Shell::spawn_args)
}

/// fish's half of the history policy (GH #252), run by `-C`: after
/// config.fish and before the first prompt. Measured on fish 3.7.0, 4.0.2
/// and 4.9.3, with no config and with one that sets `fish_history`
/// globally, universally or from a `PWD` handler, through `exit`, EOF,
/// `SIGHUP` and `SIGKILL`: nothing reached disk, and the operator's
/// existing history file was not read.
///
/// - **`fish_history` empty**, which keeps history in memory only. Here
///   and not only in the environment, because config.fish runs after the
///   environment is read and its own assignment would win.
/// - **Pinned empty** by `__holdfast_history`, for configuration that
///   re-points it later — a per-directory history plugin does, on every
///   `cd` — **or erases it**. An erased `fish_history` is fish's default
///   session, which reads the operator's history file and offers its lines
///   into the output, and which fish 3.7's `history save` rewrites
///   (measured). Re-pinned exported, so a fish started inside the session
///   inherits the empty value either way.
/// - **`fish_private_mode` exported**, so a fish started inside the session
///   saves nothing whatever its own config.fish says. At the first prompt
///   and not here, because the default `fish_greeting` announces private
///   mode: by then this session's greeting has run (fish runs `fish_prompt`
///   handlers in the order they were defined, and the greeting's comes
///   first), so its output starts as a plain fish's does. A nested fish
///   prints the announcement; a fish that ran the handlers in another order
///   would too, and would still keep nothing. **Private is not unread:**
///   none of this runs in the nested fish, so a config.fish there that
///   names a history session still has that file read, its lines offered
///   as autosuggestions and listed by `history`, and an empty one created
///   where there was none (measured on 3.7.0, 4.0.2 and 4.9.3).
///
/// **Not `--private`**, which this was until measured: every session's
/// output began *fish is running in private mode, history will not be
/// persisted*; with a config.fish that sets `fish_history`, the session
/// read the operator's history file and offered its lines as
/// autosuggestions, into output the agent reads; and its
/// `fish_private_mode` is not exported, so a nested fish under that config
/// wrote its history.
pub const FISH_HISTORY_INIT: &str = concat!(
    "set -g fish_history ''; ",
    "function __holdfast_history --on-variable fish_history; ",
    "if not set -q fish_history; or test -n \"$fish_history\"; ",
    "set -gx fish_history ''; end; end; ",
    "function __holdfast_private --on-event fish_prompt; ",
    "set -gx fish_private_mode 1; functions -e __holdfast_private; end",
);

/// Recognise a shell from a `start_session` command line.
///
/// Only interactive shells are integrated: `bash -c '…'` never draws a
/// prompt, so a typed snippet would land in the command's stdin.
pub fn detect_shell(command: &str, args: &[String]) -> Option<Shell> {
    if args.iter().any(|a| a == "-c") {
        return None;
    }
    let base = command
        .rsplit('/')
        .next()
        .unwrap_or(command)
        .trim_end_matches(".exe");
    match base {
        "bash" => Some(Shell::Bash),
        "zsh" => Some(Shell::Zsh),
        "fish" => Some(Shell::Fish),
        _ => None,
    }
}

/// bash: `PS1` carries `A`/`B`, `PS0` carries `C`, `PROMPT_COMMAND`
/// carries `D;<code>`.
///
/// - `\[` / `\]` wrap the `PS1` markers so readline does not count them
///   toward the prompt width and mis-wrap long command lines.
/// - `PROMPT_COMMAND` runs *before* `PS1` expands and sees the real `$?`,
///   which is why the exit code is emitted there rather than from `PS1`.
/// - The guard variable is deliberately **not** exported: a shell nested
///   inside this one should be integrable in its own right (§8.5 nesting).
/// - The `PS1` test makes the snippet a no-op when the user's own
///   configuration already emits OSC 133.
///
/// **Nothing in it may abort, print, or end the shell because of how an rc
/// file configured it.** Three ways it could, each measured on bash 5.2 and
/// 5.3:
///
/// - **A readonly variable.** An assignment to one at an interactive prompt
///   discards the rest of the line, and for the carrier the rest of the
///   evaluated snippet. The history clause comes first, so an rc that makes
///   `HISTFILE` readonly — the audit-hardening pattern, and every `rbash` —
///   would print *HISTFILE: readonly variable* and cost the session all of
///   its integration, markers and `get_command_history` both. Under
///   `set -e` a readonly `PROMPT_COMMAND` or `PS1` ends the shell at
///   start-up. So `__holdfast_ro` tests the attribute first, for every
///   variable the snippet assigns that an rc might lock: `HISTFILE`,
///   `HISTFILESIZE`, `PROMPT_COMMAND`, `PS1` and `PS0`. With `PS1` or `PS0`
///   locked there is nothing to mark, and nothing past the history clause
///   is installed; with `PROMPT_COMMAND` locked, `A`, `B` and `C` arrive
///   without `D`, so commands keep their text and have no exit code. A
///   locked `HISTFILE` skips the history clause whole; a locked
///   `HISTFILESIZE` stays, and bash truncates a per-session file to it when
///   it saves at exit.
///   `${NAME[@]@a}` and not `${NAME@a}`, which fails under `set -u` for an
///   unset variable, and a variable can be readonly and unset. It answers
///   *not readonly* for a readonly **empty array**, whose `[@]` expands to
///   nothing, and the assignment then fails as it did before; no rc known
///   to Holdfast declares one (measured, bash 5.2 and 5.3). Not a trial
///   assignment: `printf -v` into a readonly variable ends a `set -e` shell
///   even inside an `if`, and the `2>/dev/null` that would silence it is
///   itself refused by `rbash`. `@a` needs bash 4.4; an older bash assigns
///   without asking.
/// - **`set -u`.** `${#PROMPT_COMMAND[@]}` counts a scalar's elements as
///   unbound: every session would print *PROMPT_COMMAND: unbound variable*
///   and lose the re-wrap below, and under `set -eu` the shell would exit
///   before its first prompt. `${!PROMPT_COMMAND[@]}` lists the indices
///   without complaint, and a space in the list means more than one
///   element, a sparse array's included: inside `[[ ]]` the list is joined
///   with a space whatever `IFS` is.
/// - **`set -e`.** `__holdfast_d` returns the status it reports (see
///   below), and a `PROMPT_COMMAND` member that returns non-zero ends a
///   `set -e` shell, so the first `false && true` — a failure `set -e`
///   exempts at the prompt — would end the session. ` && :` makes the call
///   a non-final member of an AND list, which `set -e` ignores, and leaves
///   the list's status, the `$?` the next member reads, as the call's.
///
/// **The prompt is re-wrapped at every prompt, not once (GH #220).** Until
/// then the snippet wrapped `PS1` a single time, and anything that
/// *regenerates* `PS1` erased the wrapping at the next prompt. starship is
/// the measured case — `starship_precmd` assigns `PS1="$(starship prompt
/// …)"` from `PROMPT_COMMAND` at every prompt — and the cost was the whole
/// of `get_command_history`'s command text: `C` and `D` still arrived,
/// so every entry had a correct exit code beside `command: ""`, and the
/// session's first command was dropped outright (see `history`'s
/// injection-line rule). `__holdfast_p` restores whichever wrapping is
/// missing and does nothing when both survive, so a static `PS1` is
/// untouched after the first call. It checks `PS0` as well; no framework
/// measured regenerates it (starship sets it once at init), and the check
/// is what keeps the next one from costing the `C`.
///
/// **It runs last**, which is the whole of the fix: after the user's
/// hooks, so after whatever regenerated the prompt. For a scalar — or a
/// one-element array — that is the end of the command list. For an array
/// of more than one element it is a new last element, because a
/// regenerator at index ≥ 1 runs after anything composed into index 0; the
/// array form also gets bash's per-element `$?` restore, and it is last
/// anyway, so no hook reads a status it left. Only bash ≥ 5.1 runs the
/// elements past index 0, so an older bash takes the scalar arm, which
/// appends to index 0 — the one element it does run. **Residual:** a hook
/// appended to `PROMPT_COMMAND` *after* the snippet ran — `eval "$(starship
/// init bash)"` typed into a live session — runs after `__holdfast_p` and
/// defeats it again. That is what `command_capture: "missing"`, and a
/// history entry's `command: null`, exist to report.
///
/// **Joined with a newline, never `; `** (review of GH #220). The call is
/// appended to text the user wrote, and a separator has to be valid after
/// anything that text can end in. `; ` is not: after a trailing `;` it
/// makes `;;`, after a trailing `; ` or newline a line that starts with
/// `;`, and after a trailing `# comment` it is swallowed by the comment.
/// Each of those is a working `PROMPT_COMMAND` by itself — the
/// history-sharing idiom `PROMPT_COMMAND="history -a; $PROMPT_COMMAND"`
/// leaves the `; ` whenever it began empty — and the first three made bash
/// print a syntax error at every prompt and run none of the line, `D`
/// included, while the fourth silently disabled the re-wrap. A newline
/// ends a comment and follows a `;` legally, and `$'\n'` keeps the typed
/// snippet on one line.
///
/// **Except bash-preexec's `__bp_interactive_mode`, which must stay last**
/// (review of GH #220). bash-preexec — what atuin, iTerm2's integration and
/// starship-under-bash-preexec hook through — arms its `DEBUG` trap in that
/// call and takes the next simple command bash runs to be the user's. With
/// `__holdfast_p` after it, the trap fired for `__holdfast_p`, recognised a
/// `PROMPT_COMMAND` member, disarmed, and **no `preexec` hook ran for any
/// command**: measured on bash-preexec 0.5.0 and 0.6.0 (and every command
/// but the first on master, which moves its call back to the end at each
/// prompt), with starship's `took 2s` lost the same way. So when the list
/// already ends in `__bp_interactive_mode` — bash-preexec's array element,
/// or the `\n__bp_interactive_mode` its scalar form ends in — the re-wrap
/// goes immediately before it: still after every hook bash-preexec runs,
/// `precmd_functions` included, and bash-preexec's trap is disarmed when it
/// runs, so the call is invisible to it. Measured with all three versions:
/// every command reaches `preexec`, and master's own re-ordering leaves
/// the pair in place. The `DEBUG`-trap timer starship installs only on
/// bash < 4.4 has the same shape and no such marker to find; that bash has
/// no `PS0` either, so no `C` marker, and it is not measured.
///
/// Array `PROMPT_COMMAND` (bash ≥ 5.1) survives intact. Assigning a
/// scalar to an existing array writes index 0, and `${PROMPT_COMMAND:+…}`
/// reads index 0, so index 0 becomes `__holdfast_d "$?" && :; <user index 0>`
/// and every later element is untouched and still runs. Measured on bash
/// 5.3: `PROMPT_COMMAND=('echo PC_ONE' 'echo PC_TWO')` becomes
/// `declare -a PROMPT_COMMAND=([0]="__holdfast_d \"\$?\" && :; echo PC_ONE" [1]="echo PC_TWO" [2]="__holdfast_p")`,
/// every element still executes, and the markers are correct. Array
/// `PROMPT_COMMAND` semantics have shifted across bash versions and 5.3 is
/// the only version measured, so treat older releases as untested.
///
/// **Every marker carries `;holdfast=1` (§8.5.1 rule 1)**, which is what lets
/// the detector tell its own markers from another emitter's. The exit code
/// **stays the first parameter after `D`**: parameters are order-free to a
/// consumer that looks them up by name, but Holdfast's own parser reads the
/// exit code *positionally* (`scanner::osc133`), so `D;holdfast=1;42` parses
/// to `None` and every command's exit code silently becomes "finished,
/// status unknown". That is the one ordering constraint in the scheme and
/// it is invisible to a test that greps for `holdfast=1` alone.
///
/// **`return "${1:-0}"` is not decoration — it is the repair of a measured
/// data-corruption defect (§8.5, REQ-PD-027).** Holdfast *prepends* itself
/// to `PROMPT_COMMAND`, which bash evaluates as a command list, so `$?` as
/// seen by the next element was `__holdfast_d`'s `printf` — 0, always.
/// Measured on bash 5.3.9: for a command that exited 42, a starship-shaped
/// third-party emitter reported `D;0`, so **every command a user's own
/// shell integration reports came back successful**, and a terminal
/// colouring failed commands reads the last `D` it saw. Returning the
/// status hands the true value on; `${1:-0}` guards the empty-argument
/// case, where a bare `return ""` is a bash error. bash saves and restores
/// `$?` around the whole of `PROMPT_COMMAND`, so nothing the user sees at
/// the next prompt changes.
///
/// **What this does not repair, stated because a partial fix that reads as
/// complete is the worse outcome.** `PIPESTATUS` is a second member of the
/// same class and `return` cannot recover it: measured, `false | (exit 9)`
/// reaches a following hook as `(0)` with the shipped snippet and `(9)`
/// with this one, where the truth is `(1 9)`. An explicit save-and-restore
/// does not help either, because the restoring assignment is itself a
/// command that resets `PIPESTATUS`. Accepted residual; the only complete
/// mitigation is not to share a command list, and bash restores both
/// variables between the elements of an *array* `PROMPT_COMMAND`, so a
/// user whose hooks live at indices ≥ 1 is unaffected in both.
const BASH_INTEGRATION: &str = concat!(
    // Whether the variable named by `$1` is readonly; false on a bash
    // older than 4.4, which has no `@a`. See the doc comment above.
    r#" __holdfast_ro() { (( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] >= 404 )) && "#,
    r#"eval "[[ \${$1[@]@a} == *r* ]]"; }; "#,
    // GH #252, ahead of the guard so it runs even when the snippet yields
    // to the user's own markers. `HOLDFAST_HISTFILE` carries the session's
    // history file past the rc files; empty, history goes to `/dev/null`.
    // An assignment rather than `unset`: with `HISTFILE` unset, `history
    // -a` in an rc's `PROMPT_COMMAND` appends to `~/.history` (measured).
    // Skipped whole when `HISTFILE` is readonly, the emptying below
    // included: the policy cannot apply there (SECURITY.md, shell history,
    // H1), and integration still can.
    //
    // Then the in-memory list is emptied (GH #274). bash has already read
    // the file the rc named, so `history`, `fc -l`, up-arrow and `!!` would
    // offer the operator's own history into output the agent reads; and
    // it has already added the line that runs this, which leaves with it.
    // `history -r` then reads what `HISTFILE` now names when that is a
    // readable file: `/dev/null` is not, a new per-session file is empty,
    // and a file the call named itself is loaded as bash would have loaded
    // it at start. Tested rather than silenced, because `rbash` refuses the
    // redirection that would silence it. `builtin` here and in
    // `__holdfast_h`, so an rc's `history` alias or function cannot take
    // any of the three calls: an alias is expanded as this is evaluated,
    // and `alias history='history 20'` made the per-command append fail at
    // every prompt, the session's file staying empty (measured, bash 5.2).
    //
    // Not when the rc rewrites its history file with `history -w`, because
    // then the list is what keeps the operator's entries in that file. Once
    // the agent runs `source ~/.bashrc`, an rc that hard-sets `HISTFILE`
    // names the operator's file again, and `history -w` from an emptied
    // list rewrote it with the session's commands alone, in either history
    // mode; the `history -n; history -w; history -c; history -r` sync recipe
    // lost the operator's first entries in per_session mode (SECURITY.md,
    // H1; measured, bash 5.2 and 5.3). Such a session keeps the list, and
    // the line running this with it: the agent can read the operator's
    // entries (H10), and in per_session mode the rc's `history -w` copies
    // them into the session's file. `history -a` appends, and `history -a;
    // history -c; history -r` reads back what `HISTFILE` names, so both
    // still get the emptying.
    //
    // What runs `history -w` is read from the shell rather than guessed:
    // `PROMPT_COMMAND` with an array's elements joined, the hook arrays of
    // bash-preexec (`precmd_functions`, `preexec_functions`) and of
    // oh-my-bash (`_omb_util_prompt_command`), and the traps, then each
    // alias and function they name, and each function those name, to the
    // end of the chain. That is how the `historymerge` recipe and its `trap
    // historymerge EXIT` are found, and `PROMPT_COMMAND=hw` under `alias
    // hw='history -w'`. Not the whole function table: fzf's key bindings
    // define a function that runs `history -w` on a key press, and every
    // fzf user kept the list. A function body shows the aliases it used
    // already expanded. `declare -F` lists which of the names it is given
    // are functions, and every function when given none, hence `(( $# ))`;
    // 32 links end a chain that never shortens, as under an rc's `enable -n
    // set` or a function named `builtin`, which hung the shell. One
    // `declare -f` per link: under liquidprompt the search took 0.2 s on
    // bash 5.2 and 0.6 s on 3.2. Without `extdebug`, which bash-preexec's
    // `__bp_enable_subshells` turns on and under which 3.2 took 15 to 25 s.
    //
    // It runs in a command substitution, so nothing it sets, traces or
    // prints reaches the session: under an rc's `set -eux`, a readonly
    // `BASH_REMATCH` (which ended a `set -e` bash 5.3) and `set -x`, which
    // printed the function table, it measured silent. Only an `e` it prints
    // empties the list, so a search that fails — a readonly variable it
    // assigns, a `DEBUG` trap that prints into it — keeps the list, as
    // Holdfast did before GH #274, rather than risk the operator's file. A
    // restricted shell refuses the redirection that silences it, and bash
    // 3.2's `rbash` gets this far, so it skips the search and empties.
    //
    // ble.sh keeps the list. It rewrites the history file at exit from its
    // own list through an unload hook the search cannot follow, whenever
    // `histappend` is off, and emptied, that lost every entry in none mode
    // (measured, bash 5.2 and 5.3).
    //
    // In none mode, not when the prompt's own path runs `history -c` after
    // `history -w`, as the sync recipe does. Such an rc empties the list at
    // every prompt, reading back `/dev/null`, so a list kept until the
    // first prompt protects nothing, and bash 3.2's `history -n` counted
    // that list as lines already read: the sync recipe sourced again as the
    // session's first command lost every entry, where emptying keeps them
    // (measured, bash 3.2.57; 4.2 and 4.3 read the same, by their source).
    // After `history -w`, because bash-it's precmd hook holds a `history
    // -c` that runs only when `HISTCONTROL` asks, and matching it emptied
    // the list under an `EXIT` trap's `history -w`, which lost every entry.
    //
    // Not seen: a `history -w` that exists only once the rc is sourced
    // again, which still loses every entry; one named through a variable
    // (`PROMPT_COMMAND='$f'`); and one behind any other hook array. bash's
    // own save at exit appends, unless the session has run more commands
    // than `HISTSIZE` holds, and then the list is the session's alone with
    // or without the emptying.
    //
    // With a session file: `__holdfast_h` appends after every command,
    // prepended to `PROMPT_COMMAND` for the reason `__holdfast_d` is and
    // handing on `$?` the same way; no `HISTFILESIZE`, which truncates the
    // file when bash saves at exit (Debian's rc sets 2000); and
    // `histappend`. Without it, the save at exit rewrites the file from the
    // in-memory list whenever more commands are unsaved than `HISTSIZE`
    // holds, which happens once the per-command append stops —
    // `PROMPT_COMMAND` replaced mid-session — and loses everything recorded
    // before; `bash-append-stopped` in `tests/shell_history.rs` is the row.
    r#"if ! __holdfast_ro HISTFILE; then HISTFILE=${HOLDFAST_HISTFILE:-/dev/null}; "#,
    r#"! builtin shopt -q restricted_shell && [[ $({ builtin set +euxT -f; builtin shopt -u extdebug; "#,
    r#"IFS=$' \t\n;&|(){}<>=$`"\''; __holdfast_r() { t=$1; s=$t; v=' '; i=0; "#,
    r#"while builtin set -- $s; (( $# && i++ < 32 )); do a=$(builtin alias -- "$@"); t+=" $a"; n=; "#,
    r#"for w in $(builtin declare -F -- "$@" $a); do [[ $v == *" $w "* ]] || { v+="$w "; n+="$w "; }; done; "#,
    r#"s=; [[ -n $n ]] && s=$(builtin declare -f -- $n); t+=" $s"; done; }; "#,
    r#"__holdfast_r "${PROMPT_COMMAND[*]-} ${precmd_functions[*]-} ${preexec_functions[*]-} ${_omb_util_prompt_command[*]-}"; "#,
    r#"p=$t; __holdfast_r "$t $(builtin trap -p)"; [[ -n ${BLE_VERSION-} ]] || "#,
    r#"[[ $t =~ history[[:blank:]]+-[[:alpha:]]*w && ( -n ${HOLDFAST_HISTFILE-} || "#,
    r#"! $p =~ history[[:blank:]]+-[[:alpha:]]*w[^[:alnum:]]*history[[:blank:]]+-[[:alpha:]]*c ) ]] "#,
    r#"|| builtin echo e; } 2>/dev/null) != e ]] || builtin history -c; "#,
    r#"if [[ -f $HISTFILE && -r $HISTFILE ]]; then builtin history -r || :; fi; "#,
    r#"if [ -n "${HOLDFAST_HISTFILE-}" ]; then "#,
    r#"__holdfast_ro HISTFILESIZE || unset HISTFILESIZE; shopt -s histappend; "#,
    r#"__holdfast_h() { builtin history -a; return "${1:-0}"; }; "#,
    r#"__holdfast_ro PROMPT_COMMAND || [[ "${PROMPT_COMMAND-}" == *__holdfast_h* ]] || "#,
    r#"PROMPT_COMMAND='__holdfast_h "$?" && :'"${PROMPT_COMMAND:+; $PROMPT_COMMAND}"; fi; fi; "#,
    r#"if [ -z "${HOLDFAST_SHELL_INTEGRATION-}" ] && [[ "${PS1-}" != *"133;A"* ]] "#,
    r#"&& ! __holdfast_ro PS1 && ! __holdfast_ro PS0; then "#,
    r#"HOLDFAST_SHELL_INTEGRATION=1; "#,
    r#"__holdfast_p() { [[ "${PS0-}" == *"133;C;holdfast=1"* ]] || PS0='\e]133;C;holdfast=1\a'"${PS0-}"; "#,
    r#"[[ "${PS1-}" == *"133;B;holdfast=1"* ]] || PS1='\[\e]133;A;holdfast=1\a\]'"${PS1-}"'\[\e]133;B;holdfast=1\a\]'; }; "#,
    r#"__holdfast_p; "#,
    r#"__holdfast_d() { printf '\033]133;D;%s;holdfast=1\007' "${1:-0}"; return "${1:-0}"; }; "#,
    r#"if ! __holdfast_ro PROMPT_COMMAND; then "#,
    r#"PROMPT_COMMAND='__holdfast_d "$?" && :'"${PROMPT_COMMAND:+; $PROMPT_COMMAND}"; "#,
    r#"if (( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] >= 501 )) && [[ ${!PROMPT_COMMAND[@]} == *' '* ]]; then "#,
    r#"if [[ ${PROMPT_COMMAND[-1]} == __bp_interactive_mode ]]; then "#,
    r#"unset 'PROMPT_COMMAND[-1]'; PROMPT_COMMAND+=(__holdfast_p __bp_interactive_mode); "#,
    r#"else PROMPT_COMMAND+=(__holdfast_p); fi; "#,
    r#"elif [[ $PROMPT_COMMAND == *$'\n'__bp_interactive_mode ]]; then "#,
    r#"PROMPT_COMMAND=${PROMPT_COMMAND%__bp_interactive_mode}$'__holdfast_p\n__bp_interactive_mode'; "#,
    r#"else PROMPT_COMMAND+=$'\n__holdfast_p'; fi; fi; "#,
    r#"fi"#,
);

/// The environment variable that carries [`BASH_INTEGRATION`] into a bash
/// session for [`BASH_INJECTION_LINE`] to evaluate.
pub const BASH_INTEGRATION_CARRIER: &str = "HOLDFAST_BASH_INTEGRATION";

/// What Holdfast types into a bash session: [`BASH_INTEGRATION`], evaluated
/// from [`BASH_INTEGRATION_CARRIER`], which [`Shell::injection_env`] puts in
/// the session's environment and this line unsets.
///
/// **The line is typed before bash's line editor has the terminal**, while
/// the line discipline is still assembling a canonical line, and a
/// canonical line has a limit. macOS's `MAX_CANON` is 1024 bytes, and macOS
/// drops every byte past it, the newline included. bash then reads those
/// 1024 bytes with the agent's first command appended, inside quotes and
/// braces the cut left open, and prompts `> ` for their continuation.
/// bash's snippet is longer than that; zsh's and fish's are typed whole.
/// Linux does not drop: a 70 000-byte line typed at a bash still in its rc
/// file arrived whole (measured, Linux 6.12), so only a Mac shows the cut.
/// `every_injection_line_fits_in_one_canonical_line_on_macos` holds all
/// three lines under the limit, with room to spare.
///
/// - **A variable and `eval`, not exported functions.** bash imports a
///   `BASH_FUNC_<name>%%` variable as a function, but it exports each
///   function it imports again, so every bash the agent starts would carry
///   them, and `bash -p` imports none (both measured, bash 5.2). The
///   variable is read once and unset by the line that reads it, so nothing
///   the session starts afterwards inherits it.
/// - **Not a file the line sources**, which would need a lifetime, a mode
///   and a path every bash Holdfast starts can read.
/// - **Not typed once bash has left canonical mode**, which would hold the
///   injection, and the agent's first input behind it, until a transition
///   the daemon would have to watch for and a bash without readline never
///   makes.
///
/// `${…-}` keeps the line quiet under an rc's `set -u`, and the snippet it
/// evaluates is quiet there too (see [`BASH_INTEGRATION`]). It starts with
/// a space for the reason every snippet does.
///
/// **The environment has to reach the bash that reads the line**, and an
/// rc can stop it: one that re-execs bash through `env -i` or `env -u`,
/// or defines its own `eval` function or alias, leaves the line nothing to
/// evaluate, and the session gets neither integration nor the snippet's
/// history policy (measured, bash 5.2 and 5.3). WSL's `bash.exe` started
/// from native Windows is expected to behave the same, since Windows does
/// not pass the environment into WSL without `WSLENV`; not measured.
const BASH_INJECTION_LINE: &str =
    r#" eval "${HOLDFAST_BASH_INTEGRATION-}"; unset HOLDFAST_BASH_INTEGRATION"#;

/// zsh: `precmd` carries `D;<code>`, `preexec` carries `C`, and `PS1`
/// carries `A`/`B` inside `%{…%}` so the markers are zero-width.
/// `local s=$?` must be the first statement in `precmd`.
///
/// **`precmd` re-wraps `PS1` when a hook regenerated it**, for bash's
/// reason (GH #220; see `BASH_INTEGRATION`). starship's zsh integration does
/// not need it — it sets `PROMPT` once, with `promptsubst`, and the wrapping
/// survives (measured) — but a configuration that assigns `PS1` from a
/// `precmd` does, and lost every command's text exactly as bash did.
/// Holdfast's hook is appended at injection, after every hook the rc file
/// registered, and zsh runs the bare `precmd` function before any
/// `precmd_functions` entry, so it is last for both.
///
/// **The bash `$?` defect has no zsh mirror. Measured before anything here
/// was changed, on zsh 5.9, through a real PTY, and *not* inferred from
/// the fact that `add-zsh-hook` appends:**
///
/// ```text
/// arrangement                           USER_SAW   Holdfast's D
/// bare `precmd` defined before Holdfast    42         42
/// add-zsh-hook user before Holdfast        42         42
/// add-zsh-hook user after Holdfast         42         42
/// ground truth, no Holdfast at all         42         —
/// ```
///
/// `add-zsh-hook precmd` appends, which invites the reading that Holdfast's
/// hook reads a preceding user hook's `$?`. It does not: zsh restores `$?`
/// before each `precmd_functions` entry independently. **So nobody should
/// "repair" zsh by reordering `precmd_functions` — it would change
/// behaviour to fix nothing** (§8.5).
///
/// **So `precmd` does not return the status it reports**, as bash's
/// `__holdfast_d` does. For `$?` a `return` is unobservable here — with one,
/// all three arrangements report 42, as they do without — and it is
/// observable another way: under an rc's `setopt err_exit` a hook that
/// returns non-zero ends the shell, so the first `false && true`, a failure
/// `err_exit` exempts at the prompt, would end the session (measured, zsh
/// 5.9).
///
/// **Nothing in it may abort, print, or end the shell because of how an rc
/// configured it**, for bash's reasons (see `BASH_INTEGRATION`). An
/// assignment to a readonly variable discards the rest of the typed line,
/// so a readonly `HISTFILE`, `SAVEHIST` or `HISTSIZE` would cost the
/// session all of its integration and print *read-only variable*, and a
/// readonly `PS1` ends an `err_exit` shell at start-up. Each is tested with
/// `${(t)NAME-}`, whose type names `readonly` for a readonly parameter. The
/// `-` is for an rc that unsets one under `nounset`, the usual way to turn
/// history off: `${(t)HISTFILE}` is then *parameter not set*, and the rest
/// of the typed line is discarded (measured, zsh 5.9). zsh has no readonly
/// unset parameter: `typeset -r` on an unset name makes an empty one, and
/// `unset` refuses a readonly one. The history clause is skipped whole when
/// any of its three is readonly: pointing `HISTFILE` at a session file
/// under the rc's `SAVEHIST` would save the rc's list there, and raising
/// `SAVEHIST` under the rc's `HISTFILE` would save the agent's commands
/// into the operator's.
///
/// **Corrected by re-measurement (GH #220): zsh 5.9 runs the bare `precmd`
/// function *first*, then `precmd_functions` in order** — whichever was
/// defined first. This comment said the reverse. Nothing depended on it
/// for `$?`, which zsh restores before every hook either way, but the
/// re-wrap above depends on the true order, and it was measured rather
/// than taken from here.
const ZSH_INTEGRATION: &str = concat!(
    // GH #252, ahead of the guard for bash's reason. `/dev/null` and not
    // `unset`, for bash's reason too and one of zsh's own: oh-my-zsh and
    // prezto assign `HISTFILE` only when it is empty, so an unset one is
    // re-armed by `source ~/.zshrc`, and an unset variable is not exported,
    // so `exec zsh` and a nested zsh start without it (measured). A session
    // history file needs `SAVEHIST` (0 by default) and is appended per
    // command, and both limits are raised whatever an rc set them to: zsh
    // trims the file to `SAVEHIST` as it appends, `SIGKILL` or not.
    // `/dev/null` gets `SAVEHIST=0`, so zsh never saves or locks it, and no
    // `hist_save_by_copy`, for an rc sourced again that sets `SAVEHIST`: see
    // `session::launch::history_defaults`.
    //
    // First the in-memory list is cut (GH #274). zsh has read the file the
    // rc named after the rc ran, so `fc -l`, up-arrow and `!!` offered the
    // operator's own history into output the agent reads. zsh has no way
    // to empty the list in place, and `HISTSIZE` cannot go below 1, so
    // `HISTSIZE=1` keeps only the newest entry, the line running this, and
    // the anonymous function puts the rc's value back. Not `fc -p`, which
    // starts a new list but parks the old one on zsh's history stack,
    // where `fc -P` brings it back and zsh saves it at exit (measured).
    // The value is read as `${HISTSIZE-30}` for an rc that unsets
    // `HISTSIZE` under `nounset`: a bare `$HISTSIZE` is then *parameter not
    // set*, which discards the rest of the typed line, the history policy
    // and the integration with it, so the session's commands went to the
    // rc's file and nothing marked its prompt (measured, zsh 5.9). 30 is
    // zsh's own default; an unset `HISTSIZE` keeps whatever limit it last
    // had, which the shell cannot be asked for.
    //
    // Only when the rc appends to its history file. Without
    // `append_history`, `inc_append_history` or `share_history`, zsh saves
    // by rewriting the file from the list, so once `source ~/.zshrc` has
    // put the rc's `HISTFILE` and `SAVEHIST` back, the save at exit
    // replaced the operator's file with the session's commands alone,
    // where without the cut it kept every entry and gained the session's
    // (SECURITY.md, H1; measured, zsh 5.9). Such a session keeps the list,
    // and the agent can read it (H10). The options are read here, before
    // the per-session branch sets `inc_append_history`, so they are the
    // rc's. `inc_append_history_time` appends too and is left out for the
    // bytes; an rc that turns off `append_history` and relies on it alone
    // keeps the list the same way, and loses nothing.
    //
    // A session file is then read with `fc -R`, which finds nothing in a
    // new per-session file and loads a file the call named itself as zsh
    // would have at start, and only when it is readable: `fc -R` on an
    // unreadable file that holds anything discards the rest of the typed
    // line, integration and all, `err_exit` or not (measured, zsh 5.9).
    r#" if [[ ${(t)HISTFILE-}${(t)SAVEHIST-}${(t)HISTSIZE-} != *readonly* ]]; then "#,
    r#"[[ -o append_history || -o inc_append_history || -o share_history ]] && "#,
    r#"() { HISTSIZE=1; HISTSIZE=$1 } ${HISTSIZE-30}; "#,
    r#"if [[ -n ${HOLDFAST_HISTFILE-} ]]; then HISTFILE=$HOLDFAST_HISTFILE; "#,
    r#"SAVEHIST=1000000000; HISTSIZE=1000000000; [[ -r $HISTFILE ]] && fc -R; "#,
    r#"setopt inc_append_history; else HISTFILE=/dev/null; SAVEHIST=0; unsetopt hist_save_by_copy; fi; fi; "#,
    r#"if [ -z "${HOLDFAST_SHELL_INTEGRATION-}" ] && [[ "${PS1-}" != *"133;A"* && ${(t)PS1-} != *readonly* ]]; then "#,
    r#"HOLDFAST_SHELL_INTEGRATION=1; "#,
    r#"__holdfast_preexec() { printf '\033]133;C;holdfast=1\007' }; "#,
    r#"__holdfast_p() { [[ "${PS1-}" == *"133;B;holdfast=1"* ]] || "#,
    "PS1=$'%{\\e]133;A;holdfast=1\\a%}'\"${PS1-}\"$'%{\\e]133;B;holdfast=1\\a%}'; }; ",
    r#"__holdfast_precmd() { local s=$?; printf '\033]133;D;%s;holdfast=1\007' "$s"; __holdfast_p }; "#,
    r#"__holdfast_p; "#,
    r#"autoload -Uz add-zsh-hook; "#,
    r#"add-zsh-hook precmd __holdfast_precmd; "#,
    r#"add-zsh-hook preexec __holdfast_preexec; "#,
    r#"fi"#,
);

/// fish has no "prompt finished" hook, so `fish_prompt` is copied aside
/// and wrapped — the non-destructive form §8.5 requires. `fish_postexec`
/// carries the exit status, which fish exposes as `$status`.
///
/// Untested by the spike (fish was inferred from documented hook
/// equivalence — §24). The 0.0.2 integration suite measures it where fish
/// is installed and skips otherwise.
///
/// **It injects unconditionally, and the native-marking guard that used to
/// stand here was deleted rather than repaired (REQ-PD-028, §8.5.1).**
/// What shipped through rev. 39 was `$version` ≥ 4 **and** `status
/// test-feature no-mark-prompt`, declining when it believed fish marked
/// prompts natively. That is *observe and decline* — the design rev. 36
/// rejected for bash and zsh in favour of tag-and-yield — moved to the
/// only moment at which declining is possible and therefore evaluated
/// against a version number instead of against a marker. Three
/// measurements across fish 3.7.0, 4.0.2 and 4.8.1 say to remove it, and
/// the first matters most because it is what anyone correcting the feature
/// name would reach for:
///
/// - `no-mark-prompt` is never a feature *name*, only the disabling
///   spelling, so `status test-feature no-mark-prompt` answers `2`
///   (unknown) on **every** fish. The probe distinguished nothing.
/// - The obvious repair — decline iff `status test-feature mark-prompt`
///   answers `0` — **injects on 4.0.2**, which marks natively and has no
///   such feature. It is strictly worse than the bug.
/// - Declining on fish 4.0–4.2 leaves the session with **no `B` marker at
///   all** (fish emits `A`, `C` and `D` there and never `B`), so the echo
///   capture has no span and `get_command_history` reports `command: null`
///   for every entry — permanently, and not disableable by the user
///   because the flag is not there. That is precisely the partial-foreign
///   -integration case §8.5.1's per-letter yielding exists for, reached
///   through the decline path instead: unguarded, Holdfast's tagged `B` is
///   never yielded because fish supplies none to yield to.
///
/// The hazard that blocked removal is discharged by measurement, not
/// argument: `functions -c fish_prompt` works on 3.7.0, 4.0.2 and 4.8.1
/// alike, **including when `fish_prompt` is the built-in default** — the
/// copy exits 0, the copy exists, and the wrapped prompt renders the real
/// prompt between the markers.
///
/// The separate `set -q HOLDFAST_SHELL_INTEGRATION` self-guard against a
/// **second Holdfast injection** is a different guard against a different
/// thing (REQ-PD-005) and is untouched.
///
/// **What remains unverified, stated rather than implied — and it is less
/// than this paragraph claimed until 2026-09-20.** It said fish is not
/// installed on the host this was written on, so nothing here had been run
/// by this workspace's suite and
/// `fish_integration_emits_the_measured_marker_stream_and_exact_exit_codes`
/// skipped. That row now RUNS AND PASSES on fish 3.7.0 (GH #217 / #98): it
/// was failing on a bash-ism in the suite's own shared assertion helper,
/// not on anything here, and it skips only where no fish is installed —
/// which today still includes CI. On a fish >= 4 it runs and fails on the
/// OSC 133 collision, which is §11.4's scenario and wants a
/// collision-aware row rather than a change here. The snippet body has
/// also been driven on live PTYs in containers for the three versions
/// above; those claims were taken out of band, and the one
/// question in the same class as the bash and zsh `$?` measurements is
/// still open here: **the `fish_prompt` wrapper's `printf` runs before the
/// copied prompt, so `$status` inside the user's own prompt function is
/// that `printf`'s 0.** §8.5 records that as measured on 4.8.1 and it is
/// **not repaired here** — it is REQ-PD-027's fish instance and the
/// measured repair (capture `$status` first, re-assert it immediately
/// before the call) is not applied by this milestone.
const FISH_INTEGRATION: &str = concat!(
    // The leading space keeps the line out of fish's history (GH #252);
    // `FISH_HISTORY_INIT` keeps everything else out.
    r#" if not set -q HOLDFAST_SHELL_INTEGRATION; "#,
    r#"set -g HOLDFAST_SHELL_INTEGRATION 1; "#,
    r#"functions -q __holdfast_orig_fish_prompt; "#,
    r#"or functions -c fish_prompt __holdfast_orig_fish_prompt; "#,
    r#"function fish_prompt; printf '\033]133;A;holdfast=1\007'; __holdfast_orig_fish_prompt; "#,
    r#"printf '\033]133;B;holdfast=1\007'; end; "#,
    r#"function __holdfast_preexec --on-event fish_preexec; printf '\033]133;C;holdfast=1\007'; end; "#,
    r#"function __holdfast_postexec --on-event fish_postexec; "#,
    r#"printf '\033]133;D;%s;holdfast=1\007' $status; end; "#,
    r#"end"#,
);

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn recognises_the_three_integrated_shells() {
        assert_eq!(detect_shell("bash", &[]), Some(Shell::Bash));
        assert_eq!(detect_shell("zsh", &[]), Some(Shell::Zsh));
        assert_eq!(detect_shell("fish", &[]), Some(Shell::Fish));
    }

    #[test]
    fn recognises_absolute_paths() {
        assert_eq!(detect_shell("/usr/bin/bash", &[]), Some(Shell::Bash));
        assert_eq!(
            detect_shell("/opt/homebrew/bin/fish", &[]),
            Some(Shell::Fish)
        );
    }

    #[test]
    fn interactive_flags_do_not_prevent_integration() {
        assert_eq!(
            detect_shell("bash", &args(&["--norc", "--noprofile"])),
            Some(Shell::Bash)
        );
        assert_eq!(detect_shell("zsh", &args(&["-f"])), Some(Shell::Zsh));
    }

    #[test]
    fn a_dash_c_command_is_never_integrated() {
        // `bash -c 'make'` draws no prompt. Typing the snippet at it would
        // feed the snippet to `make`'s stdin.
        assert_eq!(detect_shell("bash", &args(&["-c", "make"])), None);
        assert_eq!(detect_shell("zsh", &args(&["-c", "ls"])), None);
    }

    #[test]
    fn unintegrated_programs_are_not_shells() {
        for cmd in ["dash", "sh", "python3", "ssh", "less", "vim"] {
            assert_eq!(detect_shell(cmd, &[]), None, "{cmd}");
        }
    }

    #[test]
    fn every_snippet_is_a_single_line() {
        // The snippet is typed at a prompt. An embedded newline would
        // submit a partial command.
        for s in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            for snippet in [s.integration_snippet(), s.injection_line()] {
                assert!(
                    !snippet.contains('\n'),
                    "{} snippet has a newline",
                    s.as_str()
                );
                assert!(!snippet.contains('\r'), "{} snippet has a CR", s.as_str());
            }
        }
    }

    /// The most a line Holdfast types at start-up may be, newline included.
    ///
    /// The line reaches the terminal before the shell's line editor does,
    /// while the line discipline is assembling a canonical line, and macOS
    /// holds at most `MAX_CANON` bytes of one: 1024. It drops every byte
    /// past that, the newline among them, and the shell then reads the
    /// fragment with the agent's first command appended (see
    /// `BASH_INJECTION_LINE`). The bound sits under 1024 rather than on it,
    /// so that nothing rests on exactly how macOS counts the newline.
    ///
    /// FreeBSD's `<sys/syslimits.h>` declares a `MAX_CANON` of 255, which
    /// zsh's and fish's lines exceed. No FreeBSD runs a session in CI, and
    /// this bound says nothing about what FreeBSD's tty layer does with a
    /// longer line.
    const TYPED_LINE_BOUND: usize = 1000;

    #[test]
    fn every_injection_line_fits_in_one_canonical_line_on_macos() {
        for s in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let typed = s.injection_line().len() + 1;
            assert!(
                typed <= TYPED_LINE_BOUND,
                "{}: {typed} bytes typed at start-up, over {TYPED_LINE_BOUND}; macOS \
                 drops a canonical line's bytes past 1024",
                s.as_str()
            );
        }
    }

    /// bash types a line that evaluates its snippet from the variable the
    /// spawn sets, and unsets it; zsh and fish type their snippets whole.
    /// The line names the carrier as a literal, so this is what keeps it
    /// and `BASH_INTEGRATION_CARRIER` the same name.
    #[test]
    fn the_bash_line_evaluates_the_snippet_its_environment_carries_and_unsets_it() {
        assert_eq!(
            Shell::Bash.injection_env(),
            [(BASH_INTEGRATION_CARRIER, BASH_INTEGRATION)]
        );
        let c = BASH_INTEGRATION_CARRIER;
        assert_eq!(
            Shell::Bash.injection_line(),
            format!(r#" eval "${{{c}-}}"; unset {c}"#)
        );
        for s in [Shell::Zsh, Shell::Fish] {
            assert_eq!(s.injection_line(), s.integration_snippet());
            assert!(s.injection_env().is_empty(), "{}", s.as_str());
        }
    }

    #[test]
    fn every_snippet_emits_all_four_markers() {
        for s in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let snippet = s.integration_snippet();
            for marker in ["133;A", "133;B", "133;C", "133;D"] {
                assert!(
                    snippet.contains(marker),
                    "{} snippet is missing {marker}",
                    s.as_str()
                );
                // The bare substring is not enough: the double-injection
                // guard contains a literal `*"133;A"*` that emits nothing,
                // so `contains("133;A")` stays true even with the `PS1`
                // emitter deleted — a snippet that silently produces no
                // markers and drops the session to tier 3. Require the
                // escape-introduced form, which the guard does not have.
                let escape = format!(r"\e]{marker}");
                let octal = format!(r"\033]{marker}");
                assert!(
                    snippet.contains(&escape) || snippet.contains(&octal),
                    "{} snippet mentions {marker} but never emits it",
                    s.as_str()
                );
            }
        }
    }

    /// §8.5.1 rule 1: every marker Holdfast emits carries `holdfast=1`, and the
    /// exit code stays **first** after `D`.
    ///
    /// The order half is not cosmetic. Holdfast's parser reads the exit code
    /// positionally (`scanner::osc133`), so `D;holdfast=1;42` parses to
    /// `None` — every exit code silently becomes "status unknown", which
    /// `get_command_history` renders as null and no count assertion can
    /// see. A test that greps for `holdfast=1` alone cannot separate the two
    /// spellings, which is why the negative below is asserted as well as
    /// the positive.
    ///
    /// String-level, and it says so: seven mutations of these snippets
    /// pass every structural test in this file while emitting nothing at
    /// runtime. `assert_marker_stream_and_exit_codes` is the one that runs
    /// them.
    #[test]
    fn every_emitted_marker_carries_the_holdfast_tag_with_the_exit_code_first() {
        for s in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let snippet = s.integration_snippet();
            for letter in ['A', 'B', 'C'] {
                let escape = format!(r"\e]133;{letter};holdfast=1");
                let octal = format!(r"\033]133;{letter};holdfast=1");
                assert!(
                    snippet.contains(&escape) || snippet.contains(&octal),
                    "{} emits {letter} without the holdfast=1 tag",
                    s.as_str()
                );
            }
            assert!(
                snippet.contains(r"\033]133;D;%s;holdfast=1"),
                "{}: D must carry the exit code first, then the tag",
                s.as_str()
            );
            assert!(
                !snippet.contains(r"\033]133;D;holdfast=1"),
                "{}: `D;holdfast=1;<code>` does not parse — the code is positional",
                s.as_str()
            );
        }
    }

    /// The `$?` fix, at the string level. The runtime assertion is
    /// `a_prompt_that_already_emits_osc_133_meets_the_injected_snippet`,
    /// which drives a shell whose own `PROMPT_COMMAND` reads `$?` after
    /// Holdfast's has run.
    ///
    /// **bash only, and that is a measurement rather than an omission.**
    /// zsh restores `$?` before each `precmd_functions` entry
    /// independently (measured, see `ZSH_INTEGRATION`), so its `precmd` has
    /// no status to hand on, and returning one ended an `err_exit` shell.
    #[test]
    fn the_bash_completion_emitter_restores_the_status_it_reported() {
        let snippet = Shell::Bash.integration_snippet();
        // `__holdfast_d`'s body alone: `__holdfast_h` returns the same way.
        let at = snippet.find("__holdfast_d() {").expect("__holdfast_d");
        let s = &snippet[at..at + snippet[at..].find("}; ").expect("its end")];
        assert!(
            s.contains(r#"return "${1:-0}""#),
            "__holdfast_d must hand $? on to the rest of PROMPT_COMMAND: {s}"
        );
        // After the printf, or it never runs.
        let printf = s.find(r"\033]133;D;%s;holdfast=1").expect("emitter");
        let ret = s.find(r#"return "${1:-0}""#).expect("return");
        assert!(printf < ret, "the return precedes the emitter: {s}");
    }

    /// REQ-PD-028: the fish snippet injects unconditionally.
    ///
    /// Asserted as an **absence**, because the failure this forbids is a
    /// *respelled* probe — `mark-prompt` instead of `no-mark-prompt`, a
    /// `$version` comparison written a different way — and a test naming
    /// one spelling passes against the next one. The presence-asserting
    /// test that stood here (`the_fish_snippet_declines_when_fish_marks_
    /// prompts_itself`) is deleted with the guard rather than re-pointed:
    /// a test re-aimed at the new shape keeps the rejected design's
    /// vocabulary alive in the suite, and the next reader repairs the
    /// probe rather than reading the requirement.
    ///
    /// `HOLDFAST_SHELL_INTEGRATION` is asserted **present** in the same test.
    /// That is REQ-PD-005's double-injection self-guard and it is not what
    /// this removes — without that arm a snippet gutted of both guards
    /// passes.
    #[test]
    fn the_fish_snippet_carries_no_version_or_feature_probe() {
        let s = Shell::Fish.integration_snippet();
        assert!(!s.contains("$version"), "REQ-PD-028: version probe: {s}");
        assert!(
            !s.contains("test-feature"),
            "REQ-PD-028: feature probe: {s}"
        );
        assert!(
            s.contains("HOLDFAST_SHELL_INTEGRATION"),
            "REQ-PD-005's self-guard was removed too: {s}"
        );
    }

    /// GH #252 at the string level: every snippet starts with a space, so
    /// a shell that ignores space-led lines never records it, and the bash
    /// and zsh history clauses run **before** the double-injection guard,
    /// which would otherwise skip them for a user whose own configuration
    /// already emits markers. `tests/shell_history.rs` in the `holdfast`
    /// crate is what runs them against rc files.
    #[test]
    fn every_snippet_starts_with_a_space_and_sets_history_before_its_guard() {
        // The typed line is what a shell records; bash's snippet keeps its
        // space for a snippet typed by hand.
        for s in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            for snippet in [s.integration_snippet(), s.injection_line()] {
                assert!(snippet.starts_with(' '), "{}: {snippet}", s.as_str());
            }
        }
        let guard = "HOLDFAST_SHELL_INTEGRATION";
        let bash = Shell::Bash.integration_snippet();
        let set = bash
            .find("HISTFILE=${HOLDFAST_HISTFILE:-/dev/null}")
            .expect("bash assigns HISTFILE");
        assert!(set < bash.find(guard).unwrap(), "{bash}");
        // A per-session file's per-command append too: a user whose own
        // configuration emits markers still gets it.
        let append = bash.find("history -a").expect("bash appends per command");
        assert!(append < bash.find(guard).unwrap(), "{bash}");
        let zsh = Shell::Zsh.integration_snippet();
        let set = zsh
            .find("else HISTFILE=/dev/null;")
            .expect("zsh assigns HISTFILE");
        assert!(set < zsh.find(guard).unwrap(), "{zsh}");
        for snippet in [bash, zsh] {
            let unsets_histfile = snippet.match_indices("unset HISTFILE").any(|(at, word)| {
                !snippet[at + word.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
            });
            assert!(
                !unsets_histfile,
                "an unset HISTFILE is re-armed by a conditional rc and not \
                 inherited by `exec`: {snippet}"
            );
        }
    }

    /// GH #274 at the string level: bash, when the rc runs no `history -w`,
    /// empties the list it read from the rc's file once `HISTFILE` is
    /// re-pointed, and zsh, when the rc appends to that file, cuts it to the
    /// line running the snippet, both ahead of the guard; each then reads
    /// back a file the call named.
    /// `tests/shell_history.rs` in the `holdfast` crate is what lists and
    /// recalls through them.
    #[test]
    fn the_history_clauses_empty_the_list_the_rc_file_loaded() {
        let guard = "HOLDFAST_SHELL_INTEGRATION";
        let bash = Shell::Bash.integration_snippet();
        let set = bash.find("HISTFILE=${HOLDFAST_HISTFILE").expect("set");
        let clear = bash.find("builtin history -c;").expect("bash clears");
        let read = bash.find("builtin history -r").expect("bash reads back");
        assert!(set < clear && clear < read, "{bash}");
        assert!(read < bash.find(guard).unwrap(), "{bash}");
        // Only for an rc that does not rewrite the file with `history -w`,
        // which would write the emptied list over the operator's once the
        // rc is sourced again. Read before the per-session branch prepends
        // `__holdfast_h`, and in a command substitution, whose output alone
        // decides.
        let rewrites = bash
            .find("! builtin shopt -q restricted_shell && [[ $({ builtin set +euxT -f;")
            .expect("bash empties only a list no `history -w` rewrites from");
        assert!(set < rewrites && rewrites < clear, "{bash}");
        assert!(clear < bash.find("__holdfast_h()").unwrap(), "{bash}");
        // Only an `e` empties: a search that fails keeps the list.
        assert!(
            bash.contains("|| builtin echo e; } 2>/dev/null) != e ]] || builtin history -c;"),
            "{bash}"
        );
        // What the prompt, its hook arrays and the traps reach, not the
        // whole function table, where fzf's key bindings define one that
        // runs `history -w`.
        assert!(
            bash.contains(
                r#"__holdfast_r "${PROMPT_COMMAND[*]-} ${precmd_functions[*]-} ${preexec_functions[*]-} ${_omb_util_prompt_command[*]-}"; p=$t; __holdfast_r "$t $(builtin trap -p)";"#
            ),
            "{bash}"
        );
        assert!(
            !bash.contains("builtin declare -f;"),
            "the whole table: {bash}"
        );
        // `declare -F` with no names lists every function, and a chain that
        // never shortens is cut off; `extdebug` made bash 3.2 take seconds.
        assert!(
            bash.contains(
                r#"while builtin set -- $s; (( $# && i++ < 32 )); do a=$(builtin alias -- "$@");"#
            ),
            "{bash}"
        );
        assert!(
            bash.contains(r#"$(builtin declare -F -- "$@" $a)"#),
            "{bash}"
        );
        assert!(
            bash.contains("builtin set +euxT -f; builtin shopt -u extdebug;"),
            "{bash}"
        );
        // ble.sh rewrites at exit through a hook the search cannot follow.
        assert!(
            bash.contains("[[ -n ${BLE_VERSION-} ]] || [[ $t =~"),
            "{bash}"
        );
        // Kept in per_session mode, or where the prompt's path does not run
        // `history -c` after `history -w`: bash 3.2's `history -n` counts a
        // kept list, and bash-it's hook holds a `history -c` that rarely runs.
        assert!(
            bash.contains(
                "[[ $t =~ history[[:blank:]]+-[[:alpha:]]*w && ( -n ${HOLDFAST_HISTFILE-} || ! $p =~ history[[:blank:]]+-[[:alpha:]]*w[^[:alnum:]]*history[[:blank:]]+-[[:alpha:]]*c ) ]]"
            ),
            "{bash}"
        );
        let zsh = Shell::Zsh.integration_snippet();
        let cut = zsh
            .find("() { HISTSIZE=1; HISTSIZE=$1 } ${HISTSIZE-30};")
            .expect("zsh cuts the list and restores the limit");
        let read = zsh.find("fc -R;").expect("zsh reads back");
        assert!(cut < read && read < zsh.find(guard).unwrap(), "{zsh}");
        assert!(!zsh.contains("fc -p"), "a parked list comes back: {zsh}");
        // Only for an rc that appends: a rewriting save would replace the
        // operator's file with the cut list. Read before the per-session
        // branch sets an appending option of its own.
        let appends = zsh
            .find("[[ -o append_history || -o inc_append_history || -o share_history ]] && ")
            .expect("zsh cuts only a list whose rc appends");
        assert!(appends < cut && cut < zsh.find("setopt inc_append_history").unwrap());
    }

    /// Every assignment to a variable an rc can make readonly is behind a
    /// test for it, because the assignment would discard the rest of the
    /// snippet (review of GH #252). The rows that start real shells under
    /// such rc files are in `tests/detection.rs`; this pins the two forms
    /// of the test whose simpler spellings fail there: `${NAME@a}` under
    /// `set -u` for an unset variable, and `${(t)NAME}` under `nounset`.
    #[test]
    fn every_variable_an_rc_can_lock_is_tested_before_it_is_assigned() {
        let bash = Shell::Bash.integration_snippet();
        assert!(
            bash.contains(r#"eval "[[ \${$1[@]@a} == *r* ]]""#),
            "{bash}"
        );
        let tested = bash
            .find("if ! __holdfast_ro HISTFILE; then")
            .expect("HISTFILE");
        assert!(tested < bash.find("HISTFILE=${").unwrap(), "{bash}");
        assert!(
            bash.contains(r#"]] && ! __holdfast_ro PS1 && ! __holdfast_ro PS0; then"#),
            "the guard tests PS1 and PS0: {bash}"
        );
        // Each `PROMPT_COMMAND` assignment follows its own test.
        let mut from = 0;
        for (at, _) in bash.match_indices("PROMPT_COMMAND='__holdfast_") {
            let test = bash[from..at]
                .rfind("__holdfast_ro PROMPT_COMMAND")
                .unwrap_or_else(|| panic!("untested assignment at {at}: {bash}"));
            from += test + 1;
        }
        let zsh = Shell::Zsh.integration_snippet();
        let tested = zsh
            .find("${(t)HISTFILE-}${(t)SAVEHIST-}${(t)HISTSIZE-} != *readonly*")
            .expect("the history clause's three");
        assert!(tested < zsh.find("HISTFILE=").unwrap(), "{zsh}");
        assert!(zsh.contains("${(t)PS1-} != *readonly*"), "{zsh}");
    }

    #[test]
    fn only_fish_is_spawned_with_history_arguments() {
        assert_eq!(Shell::Fish.spawn_args(), ["-C", FISH_HISTORY_INIT]);
        assert!(Shell::Bash.spawn_args().is_empty());
        assert!(Shell::Zsh.spawn_args().is_empty());

        let none: &[(String, String)] = &[];
        let own = [("fish_history".to_string(), "work".to_string())];
        let empty = [("fish_history".to_string(), String::new())];
        assert_eq!(
            history_spawn_args("/usr/bin/fish", &args(&["-l"]), none),
            Shell::Fish.spawn_args()
        );
        assert!(
            history_spawn_args("fish", &[], &own).is_empty(),
            "a call that names its own history session starts a plain fish"
        );
        assert_eq!(
            history_spawn_args("fish", &[], &empty),
            Shell::Fish.spawn_args(),
            "an empty fish_history is the default restated, and config.fish \
             beats it unless the init runs"
        );
        assert!(history_spawn_args("fish", &args(&["-c", "ls"]), none).is_empty());
        assert!(history_spawn_args("bash", &[], none).is_empty());
    }

    #[test]
    fn posix_snippets_guard_against_double_injection() {
        for s in [Shell::Bash, Shell::Zsh] {
            let snippet = s.integration_snippet();
            assert!(snippet.contains("HOLDFAST_SHELL_INTEGRATION"));
            assert!(
                snippet.contains(r#"*"133;A"*"#),
                "{} must no-op when the user already emits markers",
                s.as_str()
            );
            assert!(
                !snippet.contains("export HOLDFAST_SHELL_INTEGRATION"),
                "{} must not export the guard: a nested shell needs its own",
                s.as_str()
            );
        }
    }
}
