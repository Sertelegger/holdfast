//! OSC 133 shell-integration injection (spec §8.5).
//!
//! CLASP types a one-line snippet into the session at start-up so the
//! shell emits semantic markers. §8.5 mandates *typing* it rather than
//! setting environment variables, and that is the only mechanism that
//! works: rc files run after the environment is read and would clobber an
//! inherited `PS1`, whereas a line typed at the first prompt wraps
//! whatever prompt the user actually ended up with.
//!
//! Consequence, accepted for 0.0.2: the snippet is echoed by the shell and
//! therefore appears once in the session's output buffer.

/// Shells CLASP knows how to integrate.
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

    /// The snippet to type, without its trailing newline.
    pub fn integration_snippet(self) -> &'static str {
        match self {
            Self::Bash => BASH_INTEGRATION,
            Self::Zsh => ZSH_INTEGRATION,
            Self::Fish => FISH_INTEGRATION,
        }
    }
}

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
/// Array `PROMPT_COMMAND` (bash ≥ 5.1) survives intact. Assigning a
/// scalar to an existing array writes index 0, and `${PROMPT_COMMAND:+…}`
/// reads index 0, so index 0 becomes `__clasp_d "$?"; <user index 0>` and
/// every later element is untouched and still runs. Measured on bash 5.3:
/// `PROMPT_COMMAND=('echo PC_ONE' 'echo PC_TWO')` becomes
/// `declare -a PROMPT_COMMAND=([0]="__clasp_d \"\$?\"; echo PC_ONE" [1]="echo PC_TWO")`,
/// both elements still execute, and the markers are correct. Array
/// `PROMPT_COMMAND` semantics have shifted across bash versions and 5.3 is
/// the only version measured, so treat older releases as untested.
///
/// **Every marker carries `;clasp=1` (§8.5.1 rule 1)**, which is what lets
/// the detector tell its own markers from another emitter's. The exit code
/// **stays the first parameter after `D`**: parameters are order-free to a
/// consumer that looks them up by name, but CLASP's own parser reads the
/// exit code *positionally* (`scanner::osc133`), so `D;clasp=1;42` parses
/// to `None` and every command's exit code silently becomes "finished,
/// status unknown". That is the one ordering constraint in the scheme and
/// it is invisible to a test that greps for `clasp=1` alone.
///
/// **`return "${1:-0}"` is not decoration — it is the repair of a measured
/// data-corruption defect (§8.5, spec rev. 42).** CLASP *prepends* itself
/// to `PROMPT_COMMAND`, which bash evaluates as a command list, so `$?` as
/// seen by the next element was `__clasp_d`'s `printf` — 0, always.
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
    r#"if [ -z "${CLASP_SHELL_INTEGRATION-}" ] && [[ "${PS1-}" != *"133;A"* ]]; then "#,
    r#"CLASP_SHELL_INTEGRATION=1; "#,
    r#"PS0='\e]133;C;clasp=1\a'"${PS0-}"; "#,
    r#"PS1='\[\e]133;A;clasp=1\a\]'"${PS1-}"'\[\e]133;B;clasp=1\a\]'; "#,
    r#"__clasp_d() { printf '\033]133;D;%s;clasp=1\007' "${1:-0}"; return "${1:-0}"; }; "#,
    r#"PROMPT_COMMAND='__clasp_d "$?"'"${PROMPT_COMMAND:+; $PROMPT_COMMAND}"; "#,
    r#"fi"#,
);

/// zsh: `precmd` carries `D;<code>`, `preexec` carries `C`, and `PS1`
/// carries `A`/`B` inside `%{…%}` so the markers are zero-width.
/// `local s=$?` must be the first statement in `precmd`.
///
/// **The bash `$?` defect has no zsh mirror. Measured before anything here
/// was changed, on zsh 5.9, through a real PTY, and *not* inferred from
/// the fact that `add-zsh-hook` appends:**
///
/// ```text
/// arrangement                        USER_SAW   CLASP's D
/// bare `precmd` defined before CLASP    42         42
/// add-zsh-hook user before CLASP        42         42
/// add-zsh-hook user after CLASP         42         42
/// ground truth, no CLASP at all         42         —
/// ```
///
/// `add-zsh-hook precmd` appends, which invites the reading that CLASP's
/// hook reads a preceding user hook's `$?`. It does not: zsh restores `$?`
/// before each `precmd_functions` entry independently. **So nobody should
/// "repair" zsh by reordering `precmd_functions` — it would change
/// behaviour to fix nothing** (§8.5).
///
/// **`return $s` is therefore defensive and is measured to be
/// unobservable here, which is stated rather than implied.** Re-measured
/// with the `return` removed, all three arrangements still report 42, so
/// **no test in this workspace can distinguish its presence from its
/// absence on zsh 5.9** and none pretends to. It is kept as the mirror of
/// bash's, where the same line is load-bearing, and because a shell that
/// did *not* restore independently would need it. Also measured: zsh runs
/// `precmd_functions` entries **before** the bare `precmd` function, so a
/// user hook typed into a live session always lands after CLASP's — the
/// arrangement in which the `return` would matter is not reachable from
/// inside a session at all.
const ZSH_INTEGRATION: &str = concat!(
    r#"if [ -z "${CLASP_SHELL_INTEGRATION-}" ] && [[ "${PS1-}" != *"133;A"* ]]; then "#,
    r#"CLASP_SHELL_INTEGRATION=1; "#,
    r#"__clasp_preexec() { printf '\033]133;C;clasp=1\007' }; "#,
    r#"__clasp_precmd() { local s=$?; printf '\033]133;D;%s;clasp=1\007' "$s"; return $s }; "#,
    "PS1=$'%{\\e]133;A;clasp=1\\a%}'\"${PS1-}\"$'%{\\e]133;B;clasp=1\\a%}'; ",
    r#"autoload -Uz add-zsh-hook; "#,
    r#"add-zsh-hook precmd __clasp_precmd; "#,
    r#"add-zsh-hook preexec __clasp_preexec; "#,
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
///   capture has no span and `get_command_history` reports `command: ""`
///   for every entry — permanently, and not disableable by the user
///   because the flag is not there. That is precisely the partial-foreign
///   -integration case §8.5.1's per-letter yielding exists for, reached
///   through the decline path instead: unguarded, CLASP's tagged `B` is
///   never yielded because fish supplies none to yield to.
///
/// The hazard that blocked removal is discharged by measurement, not
/// argument: `functions -c fish_prompt` works on 3.7.0, 4.0.2 and 4.8.1
/// alike, **including when `fish_prompt` is the built-in default** — the
/// copy exits 0, the copy exists, and the wrapped prompt renders the real
/// prompt between the markers.
///
/// The separate `set -q CLASP_SHELL_INTEGRATION` self-guard against a
/// **second CLASP injection** is a different guard against a different
/// thing (REQ-PD-005) and is untouched.
///
/// **What remains unverified, stated rather than implied.** fish is not
/// installed on the host this was written on, so nothing here has been run
/// *by this workspace's suite*; `fish_integration_emits_the_measured_
/// marker_stream_and_exact_exit_codes` is the row that measures it and it
/// skips. The snippet body itself has been driven on live PTYs in
/// containers for the three versions above, so the claims in this comment
/// are measurements — but they were taken out of band, and the one
/// question in the same class as the bash and zsh `$?` measurements is
/// still open here: **the `fish_prompt` wrapper's `printf` runs before the
/// copied prompt, so `$status` inside the user's own prompt function is
/// that `printf`'s 0.** §8.5 records that as measured on 4.8.1 and it is
/// **not repaired here** — it is REQ-PD-027's fish instance and the
/// measured repair (capture `$status` first, re-assert it immediately
/// before the call) is not applied by this milestone.
const FISH_INTEGRATION: &str = concat!(
    r#"if not set -q CLASP_SHELL_INTEGRATION; "#,
    r#"set -g CLASP_SHELL_INTEGRATION 1; "#,
    r#"functions -q __clasp_orig_fish_prompt; "#,
    r#"or functions -c fish_prompt __clasp_orig_fish_prompt; "#,
    r#"function fish_prompt; printf '\033]133;A;clasp=1\007'; __clasp_orig_fish_prompt; "#,
    r#"printf '\033]133;B;clasp=1\007'; end; "#,
    r#"function __clasp_preexec --on-event fish_preexec; printf '\033]133;C;clasp=1\007'; end; "#,
    r#"function __clasp_postexec --on-event fish_postexec; "#,
    r#"printf '\033]133;D;%s;clasp=1\007' $status; end; "#,
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
            let snippet = s.integration_snippet();
            assert!(
                !snippet.contains('\n'),
                "{} snippet has a newline",
                s.as_str()
            );
            assert!(!snippet.contains('\r'), "{} snippet has a CR", s.as_str());
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

    /// §8.5.1 rule 1: every marker CLASP emits carries `clasp=1`, and the
    /// exit code stays **first** after `D`.
    ///
    /// The order half is not cosmetic. CLASP's parser reads the exit code
    /// positionally (`scanner::osc133`), so `D;clasp=1;42` parses to
    /// `None` — every exit code silently becomes "status unknown", which
    /// `get_command_history` renders as null and no count assertion can
    /// see. A test that greps for `clasp=1` alone cannot separate the two
    /// spellings, which is why the negative below is asserted as well as
    /// the positive.
    ///
    /// String-level, and it says so: seven mutations of these snippets
    /// pass every structural test in this file while emitting nothing at
    /// runtime. `assert_marker_stream_and_exit_codes` is the one that runs
    /// them.
    #[test]
    fn every_emitted_marker_carries_the_clasp_tag_with_the_exit_code_first() {
        for s in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let snippet = s.integration_snippet();
            for letter in ['A', 'B', 'C'] {
                let escape = format!(r"\e]133;{letter};clasp=1");
                let octal = format!(r"\033]133;{letter};clasp=1");
                assert!(
                    snippet.contains(&escape) || snippet.contains(&octal),
                    "{} emits {letter} without the clasp=1 tag",
                    s.as_str()
                );
            }
            assert!(
                snippet.contains(r"\033]133;D;%s;clasp=1"),
                "{}: D must carry the exit code first, then the tag",
                s.as_str()
            );
            assert!(
                !snippet.contains(r"\033]133;D;clasp=1"),
                "{}: `D;clasp=1;<code>` does not parse — the code is positional",
                s.as_str()
            );
        }
    }

    /// The `$?` fix, at the string level. The runtime assertion is
    /// `a_prompt_that_already_emits_osc_133_meets_the_injected_snippet`,
    /// which drives a shell whose own `PROMPT_COMMAND` reads `$?` after
    /// CLASP's has run.
    ///
    /// **bash only, and that is a measurement rather than an omission.**
    /// zsh restores `$?` before each `precmd_functions` entry
    /// independently (measured, see `ZSH_INTEGRATION`), so its `return $s`
    /// is defensive and unobservable; asserting it here would be asserting
    /// a string, which is what this test file is otherwise careful not to
    /// mistake for behaviour.
    #[test]
    fn the_bash_completion_emitter_restores_the_status_it_reported() {
        let s = Shell::Bash.integration_snippet();
        assert!(
            s.contains(r#"return "${1:-0}""#),
            "__clasp_d must hand $? on to the rest of PROMPT_COMMAND: {s}"
        );
        // After the printf, or it never runs.
        let printf = s.find(r"\033]133;D;%s;clasp=1").expect("emitter");
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
    /// `CLASP_SHELL_INTEGRATION` is asserted **present** in the same test.
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
            s.contains("CLASP_SHELL_INTEGRATION"),
            "REQ-PD-005's self-guard was removed too: {s}"
        );
    }

    #[test]
    fn posix_snippets_guard_against_double_injection() {
        for s in [Shell::Bash, Shell::Zsh] {
            let snippet = s.integration_snippet();
            assert!(snippet.contains("CLASP_SHELL_INTEGRATION"));
            assert!(
                snippet.contains(r#"*"133;A"*"#),
                "{} must no-op when the user already emits markers",
                s.as_str()
            );
            assert!(
                !snippet.contains("export CLASP_SHELL_INTEGRATION"),
                "{} must not export the guard: a nested shell needs its own",
                s.as_str()
            );
        }
    }
}
