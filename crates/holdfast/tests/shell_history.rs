//! GH #252: a session's shell keeps nothing in the history files under
//! `$HOME`, however the session ends — and, when the operator opts in, it
//! keeps everything in a file of the session's own instead.
//!
//! Every way a session can end is here, because each one reaches the shell
//! differently and a shell saves its history on some of them and not
//! others: `exit`, EOF, a graceful `terminate` (which hangs the idle shell
//! up), a forced one (`SIGKILL`), `holdfast daemon stop`, and a daemon that
//! is itself `SIGKILL`ed (the kernel hangs the shell up when the PTY master
//! closes). Each against the configurations measured to write history:
//!
//! - bash with no rc of its own, with shell integration on and off — off is
//!   the row that only the environment (`HISTFILE=/dev/null`) protects;
//! - bash with an rc that hard-sets `HISTFILE`, `histappend` and
//!   `PROMPT_COMMAND="history -a"`, which writes after every command, and
//!   an existing `~/.history`, which is where `history -a` goes once
//!   `HISTFILE` is unset — the reason the snippet assigns rather than
//!   unsets;
//! - zsh with an empty `~/.zshrc`, which on macOS still reads
//!   `/etc/zshrc`'s `HISTFILE` and `SAVEHIST`;
//! - zsh with an oh-my-zsh-style history block, `inc_append_history` and
//!   `share_history` without `hist_ignore_space`, which writes each line
//!   before it runs;
//! - zsh with oh-my-zsh's and prezto's conditional `HISTFILE` line, after
//!   the agent runs `source ~/.zshrc` or `exec zsh` — the line re-arms
//!   `~/.zsh_history` whenever the session's `HISTFILE` is unset;
//! - fish, as Holdfast spawns it, with and without shell integration and
//!   a config that sets `fish_history` itself — at start-up, or on every
//!   `cd` as a per-directory history plugin does — or erases it at every
//!   prompt, and a fish the agent starts inside a fish session; and fish
//!   started through `env`, which Holdfast does not recognise and so
//!   reaches only through the environment;
//! - tcsh with a `savehist` rc, for the endings Holdfast brings about.
//!
//! A zsh whose history goes nowhere must also say nothing about it at exit,
//! which is `zsh_ends_without_a_history_error_under_an_rc_that_saves_history`,
//! and one whose rc rewrites its history file must leave the operator's
//! entries in it when the agent sources that rc again, which is
//! `a_zsh_rc_that_rewrites_its_history_file_keeps_the_operators_entries_when_sourced_again`
//! and, for a bash rc that runs `history -w` at a prompt or at exit,
//! `a_bash_rc_that_rewrites_its_history_file_keeps_the_operators_entries_when_sourced_again`.
//!
//! Every session gets its own `HOME`, and the assertion is over **every
//! file** under it rather than over the names a shell is expected to use:
//! a history written somewhere unexpected is the failure this exists for.
//!
//! Nothing here waits without a deadline, and a deadline that expires
//! panics rather than counting as a pass.
#![cfg(unix)]

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_holdfast");

/// How long the shim may take to answer one request. The first call of a
/// shim includes a daemon spawn, and the suite runs in parallel.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a shell may take to run the marker command or reach a prompt.
/// zsh's `compinit` alone takes seconds on a slow filesystem.
const SHELL_TIMEOUT: Duration = Duration::from_secs(30);

/// What the agent types, and what must never reach a file. The `''` keeps
/// the typed line's echo from matching the needle the output is polled for.
const MARK: &str = "HISTMARK_";

/// Text only Holdfast's integration snippets and the lines it types contain.
/// Either reaching a history file is part of GH #252 too. bash's typed line
/// names only the variable that carries its snippet.
const SNIPPET_MARKS: [&str; 3] = [
    "HOLDFAST_SHELL_INTEGRATION",
    "HOLDFAST_HISTFILE",
    "HOLDFAST_BASH_INTEGRATION",
];

const BASH_HARD_RC: &str =
    "HISTFILE=~/.bash_history\nshopt -s histappend\nPROMPT_COMMAND=\"history -a\"\n";

/// oh-my-zsh's history settings, minus `hist_ignore_space`, which would
/// keep the snippet's own line out and so hide the case `HISTORY_IGNORE`
/// exists for.
const ZSH_OMZ_RC: &str = "HISTFILE=~/.zsh_history\nHISTSIZE=10000\nSAVEHIST=10000\n\
                          setopt share_history inc_append_history\n";

/// oh-my-zsh's and prezto's own history line: `HISTFILE` assigned only when
/// it is empty. After an `unset HISTFILE` that re-arms `~/.zsh_history` on
/// `source ~/.zshrc`, on `exec zsh` (oh-my-zsh's `omz reload`) and in a
/// nested zsh, and `share_history` then writes every later line as it is
/// typed.
const ZSH_CONDITIONAL_RC: &str = "[ -z \"$HISTFILE\" ] && HISTFILE=\"$HOME/.zsh_history\"\n\
                                  HISTSIZE=10000\nSAVEHIST=10000\n\
                                  setopt share_history inc_append_history\n";

/// An rc that names a history file and then unsets `HISTSIZE` under
/// `nounset`. The history cut (GH #274) reads `HISTSIZE` to put the rc's
/// limit back; read bare, it was *parameter not set*, zsh discarded the
/// rest of the typed line, and every command, the snippet's own line
/// included, was saved to `~/.zsh_history` (measured, zsh 5.9).
const ZSH_NOUNSET_UNSET_HISTSIZE_RC: &str =
    "HISTFILE=~/.zsh_history\nSAVEHIST=100\nsetopt nounset\nunset HISTSIZE\n";

/// One shell configuration.
#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    command: &'static str,
    args: &'static [&'static str],
    /// Files written into the session's `HOME` first, relative to it.
    files: &'static [(&'static str, &'static str)],
    integration: bool,
    /// Lines the agent types before the marker, each with text to wait for
    /// in the output before typing on, or `""` to type straight on.
    before: &'static [(&'static str, &'static str)],
    /// Whether a graceful `terminate` or `daemon stop` hangs this shell up
    /// (GH #234) rather than waiting out the grace for `SIGKILL`.
    hung_up: bool,
    /// The program whose absence skips the case.
    needs: &'static str,
}

const BASH_AND_ZSH: [Case; 8] = [
    Case {
        name: "bash-no-rc",
        command: "bash",
        args: &[],
        files: &[],
        integration: true,
        before: &[],
        hung_up: true,
        needs: "bash",
    },
    Case {
        name: "bash-no-rc-unintegrated",
        command: "bash",
        args: &[],
        files: &[],
        integration: false,
        before: &[],
        hung_up: true,
        needs: "bash",
    },
    Case {
        name: "bash-hard-rc",
        command: "bash",
        args: &[],
        files: &[(".bashrc", BASH_HARD_RC), (".history", "")],
        integration: true,
        before: &[],
        hung_up: true,
        needs: "bash",
    },
    Case {
        name: "zsh-system-rc",
        command: "zsh",
        args: &[],
        files: &[(".zshrc", "")],
        integration: true,
        before: &[],
        hung_up: true,
        needs: "zsh",
    },
    Case {
        name: "zsh-omz",
        command: "zsh",
        args: &[],
        files: &[(".zshrc", ZSH_OMZ_RC)],
        integration: true,
        before: &[],
        hung_up: true,
        needs: "zsh",
    },
    Case {
        name: "zsh-conditional-rc-resourced",
        command: "zsh",
        args: &[],
        files: &[(".zshrc", ZSH_CONDITIONAL_RC)],
        integration: true,
        before: &[("source ~/.zshrc", "")],
        hung_up: true,
        needs: "zsh",
    },
    Case {
        name: "zsh-conditional-rc-exec-zsh",
        command: "zsh",
        args: &[],
        files: &[(".zshrc", ZSH_CONDITIONAL_RC)],
        integration: true,
        before: &[("exec zsh", "")],
        hung_up: true,
        needs: "zsh",
    },
    Case {
        name: "zsh-nounset-unset-histsize",
        command: "zsh",
        args: &[],
        files: &[(".zshrc", ZSH_NOUNSET_UNSET_HISTSIZE_RC)],
        integration: true,
        before: &[],
        hung_up: true,
        needs: "zsh",
    },
];

const FISH: [Case; 6] = [
    Case {
        name: "fish-default",
        command: "fish",
        args: &[],
        files: &[],
        integration: true,
        before: &[],
        hung_up: true,
        needs: "fish",
    },
    Case {
        name: "fish-config-sets-history",
        command: "fish",
        args: &[],
        files: &[
            (".config/fish/config.fish", FISH_SETS_HISTORY),
            (".local/share/fish/fish_history", FISH_OPERATOR_HISTORY),
        ],
        integration: true,
        before: &[("history | cat", "")],
        hung_up: true,
        needs: "fish",
    },
    Case {
        name: "fish-config-sets-history-unintegrated",
        command: "fish",
        args: &[],
        files: &[(".config/fish/config.fish", FISH_SETS_HISTORY)],
        integration: false,
        before: &[],
        hung_up: true,
        needs: "fish",
    },
    Case {
        name: "fish-config-repoints-history",
        command: "fish",
        args: &[],
        files: &[
            (".config/fish/config.fish", FISH_REPOINTS_HISTORY),
            (".local/share/fish/fish_history", FISH_OPERATOR_HISTORY),
        ],
        integration: true,
        before: &[("cd /", ""), ("history | cat", "")],
        hung_up: true,
        needs: "fish",
    },
    Case {
        name: "fish-config-erases-history",
        command: "fish",
        args: &[],
        files: &[
            (".config/fish/config.fish", FISH_ERASES_HISTORY),
            (".local/share/fish/fish_history", FISH_OPERATOR_HISTORY),
        ],
        integration: true,
        before: &[("history | cat", "")],
        hung_up: true,
        needs: "fish",
    },
    Case {
        name: "fish-through-env",
        command: "env",
        args: &["fish"],
        files: &[],
        integration: true,
        before: &[],
        hung_up: true,
        needs: "fish",
    },
];

/// A config.fish that names its own history session, which beats the
/// environment's empty `fish_history`.
const FISH_SETS_HISTORY: &str = "set -g fish_history fish\n";

/// What the operator's own fish history already holds. A session must not
/// read it either: fish offers its lines as autosuggestions and lists them
/// in `history`, and both land in the output the agent reads.
const FISH_OPERATOR_HISTORY: &str = "- cmd: echo OPERATORS_OWN_HISTORY\n  when: 1\n";

/// A per-directory history plugin's shape: `fish_history` re-pointed on
/// every `cd`, after anything that ran at start-up.
const FISH_REPOINTS_HISTORY: &str =
    "function per_dir_history --on-variable PWD\n  set -g fish_history fish\nend\n";

/// A config.fish that erases `fish_history` at every prompt, which leaves
/// fish on its default session: the operator's own history file, read into
/// the output and, on fish 3.7, rewritten by `history save`.
const FISH_ERASES_HISTORY: &str =
    "function erase_history --on-event fish_prompt\n  set -e fish_history\nend\n";

/// A fish the agent starts inside a fish session, under a config.fish that
/// names its own history session. Holdfast types nothing into it, so what
/// keeps it private is the session's exported `fish_private_mode`. Private
/// is not unread: it still reads the history its config.fish names, which
/// SECURITY.md registers, so this row gives it none of the operator's to
/// read. Only endings that reach both shells at once: an `exit` would end
/// the inner one alone.
const FISH_NESTED: Case = Case {
    name: "fish-nested",
    command: "fish",
    args: &[],
    files: &[(".config/fish/config.fish", FISH_SETS_HISTORY)],
    integration: true,
    // fish 4 reads its terminal's answers at start-up and drops what was
    // typed ahead of them, so the marker waits for the inner fish; its
    // private-mode announcement is also the sign that it is private.
    before: &[("fish", "fish is running in private mode")],
    hung_up: false,
    needs: "fish",
};

/// FreeBSD's default `.cshrc` history lines. tcsh reads nothing from the
/// environment that could redirect `savehist`, so with these it saves its
/// history on `exit`, on EOF and on a hangup — and Holdfast must never hang
/// it up. The prompt is tcsh's compiled-in one, set so a system rc (macOS
/// ships `/etc/csh.cshrc`) cannot change what the heuristic tier reads.
const TCSH_SAVEHIST_RC: &str = "if ($?prompt) then\n  set prompt = '%# '\n  set history = 1000\n  \
                                set savehist = (1000 merge)\nendif\n";

const TCSH: Case = Case {
    name: "tcsh-savehist",
    command: "tcsh",
    args: &[],
    files: &[(".tcshrc", TCSH_SAVEHIST_RC)],
    integration: true,
    before: &[],
    hung_up: false,
    needs: "tcsh",
};

/// How a session ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ending {
    Exit,
    Eof,
    Terminate,
    ForceTerminate,
    DaemonStop,
    DaemonKill,
}

const SESSION_ENDINGS: [Ending; 4] = [
    Ending::Exit,
    Ending::Eof,
    Ending::Terminate,
    Ending::ForceTerminate,
];

const ALL_ENDINGS: [Ending; 6] = [
    Ending::Exit,
    Ending::Eof,
    Ending::Terminate,
    Ending::ForceTerminate,
    Ending::DaemonStop,
    Ending::DaemonKill,
];

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| {
            let p = dir.join(program);
            std::fs::metadata(&p).is_ok_and(|m| m.is_file())
        })
    })
}

/// Whether every host-dependent row must run, as `detection.rs` reads it.
fn require_all() -> bool {
    std::env::var("HOLDFAST_REQUIRE_ALL_SHELLS").as_deref() == Ok("1")
}

/// One private daemon instance, with a home of its own, stopped and removed
/// on drop.
struct Instance {
    dir: PathBuf,
}

impl Instance {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        // `/tmp`, not `target/`: a socket path must fit `sun_path`.
        let dir = PathBuf::from(format!(
            "/tmp/holdfast-hist-{tag}-{}-{nanos}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        for d in [
            dir.clone(),
            dir.with_extension("home"),
            dir.with_extension("xdg"),
        ] {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&d)
                .unwrap();
        }
        Self { dir }
    }

    /// The instance's own `HOME`: the shim's, and so the base every
    /// session's environment is built on (GH #229).
    fn home(&self) -> PathBuf {
        self.dir.with_extension("home")
    }

    /// A `holdfast` command with an environment of this test's making only,
    /// so no `HISTFILE`, `PROMPT_COMMAND`, `ZDOTDIR` or `fish_history` of
    /// the developer's reaches a session through the shim.
    fn cmd(&self) -> Command {
        let mut c = Command::new(BIN);
        c.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            c.env("PATH", path);
        }
        c.env("HOME", self.home());
        c.env("HOLDFAST_RUNTIME_DIR", &self.dir);
        c.env("XDG_CONFIG_HOME", self.dir.with_extension("xdg"));
        c
    }

    fn write_config(&self, body: &str) {
        let dir = self.dir.with_extension("xdg").join("holdfast");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), body).unwrap();
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let mut child = self
            .cmd()
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run holdfast");
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.try_wait().expect("wait") {
                let out = child.wait_with_output().expect("output");
                return (
                    status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&out.stdout).into_owned(),
                    String::from_utf8_lossy(&out.stderr).into_owned(),
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("`holdfast {}` did not exit within 60s", args.join(" "));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn daemon_pid(&self) -> Option<u32> {
        let text = std::fs::read_to_string(self.dir.join("holdfast.pid")).ok()?;
        text.split_whitespace().next()?.parse().ok()
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let _ = self
            .cmd()
            .args(["daemon", "stop", "--force"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        std::thread::sleep(Duration::from_millis(150));
        for d in [
            self.dir.clone(),
            self.dir.with_extension("home"),
            self.dir.with_extension("xdg"),
        ] {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

/// A `holdfast mcp` process driven over stdio with raw JSON-RPC.
struct Shim {
    child: Child,
    lines: Receiver<String>,
    next_id: u64,
}

impl Shim {
    fn launch(inst: &Instance) -> Self {
        let mut child = inst
            .cmd()
            .current_dir(inst.home())
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn holdfast mcp");
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let mut shim = Self {
            child,
            lines,
            next_id: 1,
        };
        let init = shim.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "holdfast-test", "version": "0" }
            }),
        );
        assert!(init["result"].is_object(), "{init}");
        shim.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        shim
    }

    fn send(&mut self, msg: &Value) {
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{msg}").unwrap();
        stdin.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        loop {
            let line = match self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(line) => line,
                Err(RecvTimeoutError::Timeout) => {
                    panic!("the shim did not answer `{method}` within {RESPONSE_TIMEOUT:?}")
                }
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("the shim closed stdout before answering `{method}`")
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(line.trim())
                .unwrap_or_else(|e| panic!("non-JSON-RPC on the MCP transport: {line:?} ({e})"));
            if value["id"] == json!(id) {
                return value;
            }
        }
    }

    /// A tool call's envelope.
    fn call(&mut self, tool: &str, arguments: Value) -> Value {
        let resp = self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        );
        resp["result"]["structuredContent"].clone()
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A started session, and the `HOME` it was given.
struct Started {
    case: Case,
    id: String,
    pid: u32,
    home: PathBuf,
}

/// Start `case` in a fresh `HOME` under `inst`, type the marker, and wait
/// until the shell has run it and is back at its prompt.
fn start(inst: &Instance, shim: &mut Shim, case: Case, label: &str) -> Started {
    let home = inst.home().join(format!("{}-{label}", case.name));
    std::fs::create_dir_all(&home).unwrap();
    for (rel, body) in case.files {
        let path = home.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body).unwrap();
    }
    let h = home.to_str().unwrap().to_string();
    let env: BTreeMap<&str, String> = [
        ("HOME", h.clone()),
        ("ZDOTDIR", h.clone()),
        ("XDG_CONFIG_HOME", format!("{h}/.config")),
        ("XDG_DATA_HOME", format!("{h}/.local/share")),
        // Debian's `/etc/zsh/zshrc` runs `compinit` unless told not to, and
        // on a slow filesystem that is most of a shell's start-up. It sets
        // no history option either way; macOS's `/etc/zshrc` ignores it.
        ("skip_global_compinit", "1".to_string()),
    ]
    .into_iter()
    .collect();
    let started = shim.call(
        "start_session",
        json!({
            "command": case.command,
            "args": case.args,
            "cwd": h,
            "env": env,
            "shell_integration": case.integration,
        }),
    );
    assert_eq!(started["status"], "ok", "{}: {started}", case.name);
    let id = started["data"]["session_id"].as_str().unwrap().to_string();
    let pid = started["data"]["pid"].as_u64().expect("pid") as u32;
    let s = Started {
        case,
        id,
        pid,
        home,
    };
    // Typed back to back unless a line says otherwise: the shell reads
    // each line only once the one before it has finished, `exec` included.
    for (line, ready) in case.before {
        send(shim, &s, line, true);
        if !ready.is_empty() {
            await_output(shim, &s, ready);
        }
    }
    let mark = format!("{MARK}{}", case.name.replace('-', "_"));
    let (head, tail) = mark.split_at(MARK.len());
    send(shim, &s, &format!("echo {head}''{tail}"), true);
    await_output(shim, &s, &mark);
    await_prompt(shim, &s);
    let out = output(shim, &s);
    assert!(
        !out.contains("OPERATORS_OWN_HISTORY"),
        "{}: the session read the operator's history: {out:?}",
        case.name
    );
    s
}

/// Everything the session has printed so far.
fn output(shim: &mut Shim, s: &Started) -> String {
    let r = shim.call(
        "read_output",
        json!({ "session": s.id, "since_cursor": 0, "max_bytes": 262144 }),
    );
    r["data"]["output"].as_str().unwrap_or_default().to_string()
}

fn send(shim: &mut Shim, s: &Started, data: &str, newline: bool) {
    let r = shim.call(
        "send_input",
        json!({ "session": s.id, "data": data, "append_newline": newline }),
    );
    assert_eq!(r["status"], "ok", "{}: send_input: {r}", s.case.name);
}

fn await_output(shim: &mut Shim, s: &Started, needle: &str) {
    let deadline = Instant::now() + SHELL_TIMEOUT;
    loop {
        let out = output(shim, s);
        if out.contains(needle) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{}: `{needle}` never appeared; output: {out:?}",
            s.case.name
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait for the shell to be reading a new command line, so an EOF typed
/// next lands on an empty line rather than in the middle of a command.
fn await_prompt(shim: &mut Shim, s: &Started) {
    let deadline = Instant::now() + SHELL_TIMEOUT;
    loop {
        let r = shim.call("status", json!({ "session": s.id }));
        if r["data"]["interaction_mode"] == "AtPrompt" {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{}: never back at a prompt: {r}",
            s.case.name
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Whether `pid` is gone or a zombie. A zombie has already written
/// whatever it was going to, and a container whose pid 1 does not reap
/// keeps an orphan's zombie forever.
fn gone(pid: u32) -> bool {
    // SAFETY: signal 0 checks existence and delivers nothing.
    if unsafe { libc::kill(pid as i32, 0) } != 0 {
        return true;
    }
    Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().starts_with('Z'))
        .unwrap_or(false)
}

fn await_gone(s: &Started) {
    let deadline = Instant::now() + SHELL_TIMEOUT;
    while !gone(s.pid) {
        assert!(
            Instant::now() < deadline,
            "{}: the shell (pid {}) outlived its session",
            s.case.name,
            s.pid
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// End one session from inside it or through `terminate`.
fn end(shim: &mut Shim, s: &Started, how: Ending) {
    match how {
        Ending::Exit => send(shim, s, "exit", true),
        Ending::Eof => send(shim, s, "\u{4}", false),
        Ending::Terminate | Ending::ForceTerminate => {
            // A shell that is not hung up sits out the whole grace, so
            // give it a short one.
            let grace = if s.case.hung_up { 10 } else { 2 };
            let asked = Instant::now();
            let r = shim.call(
                "terminate",
                json!({
                    "session": s.id,
                    "force": how == Ending::ForceTerminate,
                    "timeout_secs": grace,
                }),
            );
            assert_eq!(r["status"], "ok", "{}: terminate: {r}", s.case.name);
            // The hangup is what ends the shell, not the `SIGKILL` after
            // the grace — which saves nothing either, so without this a
            // terminate that never hung up would pass every leak check.
            if how == Ending::Terminate && s.case.hung_up {
                assert_hung_up(s.case.name, "terminate", asked.elapsed(), grace);
            }
        }
        Ending::DaemonStop | Ending::DaemonKill => unreachable!("ends every session at once"),
    }
    await_gone(s);
}

/// `holdfast daemon stop`'s grace before it escalates to `SIGKILL`.
const DAEMON_STOP_GRACE_SECS: u64 = 10;

/// That a graceful ending took well under its grace, which only a hangup
/// (GH #234) makes it do for an idle shell.
fn assert_hung_up(name: &str, what: &str, took: Duration, grace_secs: u64) {
    assert!(
        took < Duration::from_secs(grace_secs) / 2,
        "{name}: {what} took {took:?} of a {grace_secs}s grace, so the shell \
         was not hung up and ended on the SIGKILL after it"
    );
}

/// Every file under `home` that holds the marker or the snippet.
fn leaks(home: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![home.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                let text =
                    String::from_utf8_lossy(&std::fs::read(&path).unwrap_or_default()).into_owned();
                for needle in std::iter::once(MARK).chain(SNIPPET_MARKS) {
                    if text.contains(needle) {
                        found.push(format!("{} holds {needle}: {text:?}", path.display()));
                    }
                }
            }
        }
    }
    found
}

fn assert_no_leaks(ended: &[(Started, Ending)]) {
    let mut all = Vec::new();
    for (s, how) in ended {
        for leak in leaks(&s.home) {
            all.push(format!("{} / {how:?}: {leak}", s.case.name));
        }
    }
    assert!(
        all.is_empty(),
        "shell history reached $HOME:\n{}",
        all.join("\n")
    );
}

/// The cases whose shells this host has, announcing any it skips.
fn available(cases: &[Case]) -> Vec<Case> {
    let mut out = Vec::new();
    for case in cases {
        // macOS's `/etc/zshrc` assigns `HISTFILE` unconditionally, and a zsh
        // the agent `exec`s reads it again after the snippet has run, so that
        // zsh saves to `~/.zsh_history`, and a per-session record stops at
        // the `exec`. No policy Holdfast types can reach a shell started
        // after it; SECURITY.md registers the case (shell history, a nested
        // or exec'd zsh). Linux's zsh ships no such line, so the row keeps
        // the measurement there.
        if cfg!(target_os = "macos") && case.before.iter().any(|(line, _)| *line == "exec zsh") {
            eprintln!(
                "not applicable on macOS: {} (its /etc/zshrc re-arms HISTFILE in an exec'd zsh)",
                case.name
            );
            continue;
        }
        if on_path(case.needs) {
            out.push(*case);
            continue;
        }
        assert!(
            !require_all(),
            "HOLDFAST_REQUIRE_ALL_SHELLS=1 and {} is not installed",
            case.needs
        );
        eprintln!(
            "skipping: {} not installed — shell-history case {} not measured",
            case.needs, case.name
        );
    }
    out
}

/// Run `cases` through every ending.
fn every_ending(tag: &str, cases: &[Case]) {
    run_endings(tag, cases, &ALL_ENDINGS);
}

/// Run `cases` through `endings`: those a session reaches by itself or
/// through `terminate` on one daemon, then `daemon stop` and a killed
/// daemon on one each.
fn run_endings(tag: &str, cases: &[Case], endings: &[Ending]) {
    let mut ended = Vec::new();
    let mut instances = Vec::new();

    let inst = Instance::new(tag);
    let mut shim = Shim::launch(&inst);
    for how in SESSION_ENDINGS.into_iter().filter(|h| endings.contains(h)) {
        for case in cases {
            let s = start(&inst, &mut shim, *case, &format!("{how:?}"));
            end(&mut shim, &s, how);
            ended.push((s, how));
        }
    }
    shim.kill();
    instances.push(inst);

    // `holdfast daemon stop`: a graceful stop, which hangs every idle
    // shell up (GH #234).
    if endings.contains(&Ending::DaemonStop) {
        let stop = Instance::new(&format!("{tag}-stop"));
        let mut shim = Shim::launch(&stop);
        let live: Vec<Started> = cases
            .iter()
            .map(|c| start(&stop, &mut shim, *c, "DaemonStop"))
            .collect();
        let asked = Instant::now();
        let (code, out, err) = stop.run(&["daemon", "stop"]);
        assert_eq!(code, 0, "daemon stop: {out} {err}");
        if cases.iter().all(|c| c.hung_up) {
            assert_hung_up(tag, "daemon stop", asked.elapsed(), DAEMON_STOP_GRACE_SECS);
        }
        for s in live {
            await_gone(&s);
            ended.push((s, Ending::DaemonStop));
        }
        shim.kill();
        instances.push(stop);
    }

    // A daemon that dies: the kernel hangs up each session's shell when
    // the PTY master closes with it.
    if endings.contains(&Ending::DaemonKill) {
        let crash = Instance::new(&format!("{tag}-kill"));
        let mut shim = Shim::launch(&crash);
        let live: Vec<Started> = cases
            .iter()
            .map(|c| start(&crash, &mut shim, *c, "DaemonKill"))
            .collect();
        let daemon = crash.daemon_pid().expect("holdfast.pid");
        // SAFETY: a pid read from this instance's own pid file.
        assert_eq!(unsafe { libc::kill(daemon as i32, libc::SIGKILL) }, 0);
        for s in live {
            await_gone(&s);
            ended.push((s, Ending::DaemonKill));
        }
        shim.kill();
        instances.push(crash);
    }

    assert_no_leaks(&ended);
    // Held to here so every `HOME` is still on disk for the assertion.
    drop(instances);
}

#[test]
fn bash_and_zsh_keep_nothing_in_home_however_a_session_ends() {
    let cases = available(&BASH_AND_ZSH);
    every_ending("sh", &cases);
}

/// fish in its own row, because CI's `test` job has no fish and its
/// `fish-req-ts-008` job runs exactly this row against fish 4. The
/// `measured against` line is what lets that job tell a run from a skip.
#[test]
fn fish_keeps_nothing_in_home_however_a_session_ends() {
    if !on_path("fish") {
        assert!(
            !require_all(),
            "HOLDFAST_REQUIRE_ALL_SHELLS=1 and fish is not installed"
        );
        eprintln!("skipping: fish not installed — fish's shell-history rows are not measured");
        return;
    }
    every_ending("fish", &FISH);
    run_endings(
        "fish-nested",
        &[FISH_NESTED],
        &[Ending::ForceTerminate, Ending::DaemonKill],
    );
    fish_starts_as_a_plain_fish_does();
    let version = Command::new("fish")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    eprintln!("shell-history measured against {version}");
}

/// A fish Holdfast spawns prints nothing a plain fish would not: no
/// private-mode announcement from `fish_greeting`, which `--private` put at
/// the top of every fish session's output.
fn fish_starts_as_a_plain_fish_does() {
    let inst = Instance::new("fish-greeting");
    let mut shim = Shim::launch(&inst);
    let s = start(&inst, &mut shim, FISH[0], "Greeting");
    let out = output(&mut shim, &s);
    assert!(!out.contains("private mode"), "{out:?}");
    end(&mut shim, &s, Ending::ForceTerminate);
    shim.kill();
}

/// tcsh, which Holdfast neither hangs up nor reaches through the
/// environment: a graceful `terminate` and `daemon stop` send it `SIGTERM`,
/// which an interactive tcsh ignores, and then `SIGKILL`, on which it saves
/// nothing. Its `exit`, EOF and the kernel's hangup when the daemon dies
/// all save `~/.history` under a `savehist` rc; those are the csh family's
/// registered residual (SECURITY.md) and are not rows.
#[test]
fn tcsh_is_never_hung_up_so_holdfast_ending_it_saves_nothing() {
    let cases = available(&[TCSH]);
    if cases.is_empty() {
        return;
    }
    run_endings(
        "tcsh",
        &cases,
        &[
            Ending::Terminate,
            Ending::ForceTerminate,
            Ending::DaemonStop,
        ],
    );
}

/// The operator's own bash history, which the rc names.
const BASH_OPERATOR_HISTORY: &str = "echo OPERATORS_OWN_HISTORY_1\necho OPERATORS_OWN_HISTORY_2\n";

/// The same in zsh's extended format, which oh-my-zsh's rc writes.
const ZSH_OPERATOR_HISTORY: &str = ": 1700000000:0;echo OPERATORS_OWN_HISTORY_1\n\
                                    : 1700000001:0;echo OPERATORS_OWN_HISTORY_2\n";

/// Shells whose rc names a history file the operator has already filled.
/// bash and zsh read it as they start, before the snippet runs (GH #274).
/// One bash rc appends to its file from `PROMPT_COMMAND`, which writes only
/// the lines entered in the session, so a per-session file gets none of the
/// operator's; an rc's `history -w` would write them all there.
const OPERATOR_HISTORY: [Case; 3] = [
    Case {
        name: "bash-operator-history",
        command: "bash",
        args: &[],
        files: &[
            (".bashrc", "HISTFILE=~/.bash_history\n"),
            (".bash_history", BASH_OPERATOR_HISTORY),
        ],
        integration: true,
        before: &[],
        hung_up: true,
        needs: "bash",
    },
    Case {
        name: "bash-operator-history-appends",
        command: "bash",
        args: &[],
        files: &[
            (
                ".bashrc",
                "HISTFILE=~/.bash_history\nPROMPT_COMMAND='history -a'\n",
            ),
            (".bash_history", BASH_OPERATOR_HISTORY),
        ],
        integration: true,
        before: &[],
        hung_up: true,
        needs: "bash",
    },
    Case {
        name: "zsh-operator-history",
        command: "zsh",
        args: &[],
        files: &[
            (".zshrc", ZSH_OMZ_RC),
            (".zsh_history", ZSH_OPERATOR_HISTORY),
        ],
        integration: true,
        before: &[],
        hung_up: true,
        needs: "zsh",
    },
];

/// Poll until `needle` has appeared `n` times in the session's output.
fn await_count(shim: &mut Shim, s: &Started, needle: &str, n: usize) {
    let deadline = Instant::now() + SHELL_TIMEOUT;
    loop {
        let out = output(shim, s);
        if out.matches(needle).count() >= n {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{}: `{needle}` never appeared {n} times; output: {out:?}",
            s.case.name
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// GH #274: bash and zsh read the history file an rc names as they start,
/// before the snippet runs, so the operator's own history is in the
/// session's memory, where `history`, `fc -l` and up-arrow put it into the
/// output the agent reads. zsh's snippet cuts that list, when the rc
/// appends to its file, to one entry, the line Holdfast typed, and reads
/// back only what the session's own `HISTFILE` holds. bash's keeps the
/// list whole: emptied, it is what an rc's `history -w`, sourced again,
/// writes over the operator's file (see
/// [`a_bash_rc_that_rewrites_its_history_file_keeps_the_operators_entries_when_sourced_again`]).
///
/// Each session recalls a command two back with up-arrow and the last with
/// `!!`, and lists after that: its own commands present, and in zsh none of
/// the operator's, in bash every one. A per-session file keeps every
/// command the agent ran and none of the operator's, since the snippet's
/// per-command append writes only lines entered in the session, and the
/// operator's file is byte for byte what it was.
#[test]
fn zsh_lists_none_of_the_operators_history_and_bash_keeps_all_of_it() {
    let cases = available(&OPERATOR_HISTORY);
    for per_session in [false, true] {
        let inst = Instance::new(if per_session { "op-ps" } else { "op" });
        if per_session {
            inst.write_config("[terminal]\nshell_history_file = \"per_session\"\n");
        }
        let mut shim = Shim::launch(&inst);
        let mut ended = Vec::new();
        for case in &cases {
            let row = format!("{} / per_session {per_session}", case.name);
            let s = start(&inst, &mut shim, *case, "Operator");
            send(&mut shim, &s, "echo RECALL''_ONE", true);
            await_count(&mut shim, &s, "RECALL_ONE", 1);
            await_prompt(&mut shim, &s);
            send(&mut shim, &s, "echo RECALL''_TWO", true);
            await_count(&mut shim, &s, "RECALL_TWO", 1);
            await_prompt(&mut shim, &s);
            // Two back: a list cut short keeps only the last.
            send(&mut shim, &s, "\u{1b}[A", false);
            send(&mut shim, &s, "\u{1b}[A", false);
            send(&mut shim, &s, "\r", false);
            await_count(&mut shim, &s, "RECALL_ONE", 2);
            await_prompt(&mut shim, &s);
            send(&mut shim, &s, "!!", true);
            await_count(&mut shim, &s, "RECALL_ONE", 3);
            await_prompt(&mut shim, &s);

            let listed_from = output(&mut shim, &s).len();
            let zsh = case.command == "zsh";
            send(&mut shim, &s, if zsh { "fc -l 1" } else { "history" }, true);
            // Only the listing prints the marker's command with its quotes
            // after this point.
            await_output_after(&mut shim, &s, listed_from, "HISTMARK_''");
            await_prompt(&mut shim, &s);
            let listed = output(&mut shim, &s);
            let listed = listed.get(listed_from..).unwrap_or(&listed);
            assert!(
                listed.contains("echo RECALL''_TWO"),
                "{row}: the listing lacks the agent's own commands: {listed:?}"
            );
            if zsh {
                let out = output(&mut shim, &s);
                assert!(
                    !out.contains("OPERATORS_OWN_HISTORY"),
                    "{row}: the operator's history reached the output: {out:?}"
                );
            } else {
                for entry in BASH_OPERATOR_HISTORY.lines() {
                    assert!(
                        listed.contains(entry),
                        "{row}: bash's list lost the operator's `{entry}`: {listed:?}"
                    );
                }
            }
            end(&mut shim, &s, Ending::ForceTerminate);
            ended.push((s, Ending::ForceTerminate));
        }
        shim.kill();

        for (s, _) in &ended {
            let (rel, body) = s.case.files[1];
            assert_eq!(
                std::fs::read_to_string(s.home.join(rel)).unwrap(),
                body,
                "{}: the operator's history file changed",
                s.case.name
            );
            if !per_session {
                continue;
            }
            let file = inst
                .dir
                .join("logs")
                .join("history")
                .join(format!("{}.history", s.id));
            let text = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("{}: no {}: {e}", s.case.name, file.display()));
            for needle in [MARK, "echo RECALL''_ONE", "echo RECALL''_TWO"] {
                assert!(
                    text.contains(needle),
                    "{}: {} lacks {needle}: {text:?}",
                    s.case.name,
                    file.display()
                );
            }
            // bash's file begins with the line Holdfast typed, which is in
            // its list like any other and names only bash's carrier.
            let marks = SNIPPET_MARKS
                .into_iter()
                .filter(|m| s.case.command == "zsh" || *m != "HOLDFAST_BASH_INTEGRATION");
            for needle in std::iter::once("OPERATORS_OWN_HISTORY").chain(marks) {
                assert!(
                    !text.contains(needle),
                    "{}: {} holds {needle}: {text:?}",
                    s.case.name,
                    file.display()
                );
            }
        }
        assert_no_leaks(&ended);
        drop(inst);
    }
}

/// A zsh rc that saves by rewriting its history file, with none of
/// `append_history`, `inc_append_history` and `share_history`.
const ZSH_REWRITING_RC: &str = "HISTFILE=~/.zsh_history\nHISTSIZE=1000\nSAVEHIST=1000\n\
                                unsetopt append_history\n";

/// A zsh whose rc rewrites its history file, sourced again in the session,
/// keeps the operator's entries in that file (review of GH #274).
/// `source ~/.zshrc` puts the rc's `HISTFILE` and `SAVEHIST` back, and zsh
/// then saves at exit by rewriting the file from its list. The GH #274 cut
/// had left that list holding the session's commands alone, so the
/// operator's file came out with nothing else in it; the snippet now cuts
/// only a list whose rc appends (measured, zsh 5.9, exit and hangup).
///
/// The session's own commands still reach the operator's file, as they do
/// under any rc sourced again (SECURITY.md, H1), and that is the proof the
/// save happened at all: without it the operator's file is intact because
/// nothing was written, and this row measures nothing.
#[test]
fn a_zsh_rc_that_rewrites_its_history_file_keeps_the_operators_entries_when_sourced_again() {
    let case = Case {
        name: "zsh-rewriting-rc-resourced",
        command: "zsh",
        args: &[],
        files: &[
            (".zshrc", ZSH_REWRITING_RC),
            (".zsh_history", ZSH_OPERATOR_HISTORY),
        ],
        integration: true,
        before: &[("source ~/.zshrc", "")],
        hung_up: true,
        needs: "zsh",
    };
    if available(&[case]).is_empty() {
        return;
    }
    let inst = Instance::new("rewriting-rc");
    let mut shim = Shim::launch(&inst);
    let mut ended = Vec::new();
    for how in [Ending::Exit, Ending::Terminate] {
        let s = start(&inst, &mut shim, case, &format!("{how:?}"));
        end(&mut shim, &s, how);
        ended.push((s, how));
    }
    shim.kill();
    for (s, how) in &ended {
        let file = s.home.join(".zsh_history");
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("{} / {how:?}: {}: {e}", s.case.name, file.display()));
        assert!(
            text.contains(MARK),
            "{} / {how:?}: zsh never saved to {}, so this measured nothing: {text:?}",
            s.case.name,
            file.display()
        );
        for needle in ["OPERATORS_OWN_HISTORY_1", "OPERATORS_OWN_HISTORY_2"] {
            assert!(
                text.contains(needle),
                "{} / {how:?}: the operator's {} lost {needle}: {text:?}",
                s.case.name,
                file.display()
            );
        }
    }
    drop(inst);
}

/// bash rc files that hard-set `HISTFILE` and rewrite it from the
/// in-memory list: at every prompt, by `history -w` alone and by the sync
/// recipe that first reads what other shells appended; by that recipe as
/// the `historymerge` function and `EXIT` trap it is usually shared as;
/// and at exit alone, by a trap. Limits above anything a row writes, so
/// none trims what it measures.
const BASH_REWRITING_RCS: [Case; 4] = [
    bash_rewriting(
        "bash-history-w-resourced",
        &[
            (".bashrc", BASH_HISTORY_W_RC),
            (".bash_history", BASH_OPERATOR_HISTORY),
        ],
    ),
    bash_rewriting(
        "bash-history-sync-resourced",
        &[
            (".bashrc", BASH_HISTORY_SYNC_RC),
            (".bash_history", BASH_OPERATOR_HISTORY),
        ],
    ),
    bash_rewriting(
        "bash-historymerge-resourced",
        &[
            (".bashrc", BASH_HISTORYMERGE_RC),
            (".bash_history", BASH_OPERATOR_HISTORY),
        ],
    ),
    bash_rewriting(
        "bash-exit-trap-resourced",
        &[
            (".bashrc", BASH_EXIT_TRAP_RC),
            (".bash_history", BASH_OPERATOR_HISTORY),
        ],
    ),
];

const BASH_HISTORY_W_RC: &str = "HISTFILE=~/.bash_history\nHISTSIZE=1000\nHISTFILESIZE=2000\n\
                                 PROMPT_COMMAND='history -w'\n";

const BASH_HISTORY_SYNC_RC: &str = "HISTFILE=~/.bash_history\nHISTSIZE=1000\nHISTFILESIZE=2000\n\
                                    PROMPT_COMMAND='history -n; history -w; history -c; history -r'\n";

const BASH_HISTORYMERGE_RC: &str = "HISTFILE=~/.bash_history\nHISTSIZE=1000\nHISTFILESIZE=2000\n\
                                    historymerge() { history -n; history -w; history -c; history -r; }\n\
                                    trap historymerge EXIT\nPROMPT_COMMAND=historymerge\n";

const BASH_EXIT_TRAP_RC: &str = "HISTFILE=~/.bash_history\nHISTSIZE=1000\nHISTFILESIZE=2000\n\
                                 trap 'history -w' EXIT\n";

/// A bash session under one of [`BASH_REWRITING_RCS`]'s rc files, which
/// runs a command and then sources the rc again before its marker. The
/// command comes first, or the sync recipe's line count is the operator's
/// own and it loses nothing.
const fn bash_rewriting(
    name: &'static str,
    files: &'static [(&'static str, &'static str)],
) -> Case {
    Case {
        name,
        command: "bash",
        args: &[],
        files,
        integration: true,
        before: &[("echo before''_source", ""), ("source ~/.bashrc", "")],
        hung_up: true,
        needs: "bash",
    }
}

/// A bash whose rc rewrites its history file with `history -w`, sourced
/// again in the session, keeps every one of the operator's entries in that
/// file, in both history modes (SD-2, review of GH #274). `source
/// ~/.bashrc` puts the rc's `HISTFILE` back, and the next `history -w` —
/// at the next prompt, or the `EXIT` trap's — writes the list over the
/// operator's file.
/// GH #274's bash half emptied that list, which then held the session's
/// commands alone, so `history -w` kept none of the operator's entries; the
/// sync recipe's `history -n` reads the file back from the line count bash
/// last recorded, and in per_session mode that count, the session file's,
/// skipped as many of the operator's first entries as the session had run
/// commands. bash now keeps the list it read, and this is the row that goes
/// red if anything empties it again (measured, bash 5.2 and 5.3, exit and
/// hangup).
///
/// The session's commands reach the operator's file, as under any rc
/// sourced again (SECURITY.md, H1), and that is the proof the rewrite
/// happened at all.
#[test]
fn a_bash_rc_that_rewrites_its_history_file_keeps_the_operators_entries_when_sourced_again() {
    // Every row's loss, not the first: which recipes lose what in which
    // mode is the measurement.
    let mut lost = Vec::new();
    for per_session in [false, true] {
        let inst = Instance::new(if per_session { "bash-rw-ps" } else { "bash-rw" });
        if per_session {
            inst.write_config("[terminal]\nshell_history_file = \"per_session\"\n");
        }
        let mut shim = Shim::launch(&inst);
        let mut ended = Vec::new();
        for case in available(&BASH_REWRITING_RCS) {
            for how in [Ending::Exit, Ending::Terminate] {
                let s = start(&inst, &mut shim, case, &format!("{how:?}"));
                end(&mut shim, &s, how);
                ended.push((s, how));
            }
        }
        shim.kill();
        for (s, how) in &ended {
            let file = s.home.join(".bash_history");
            let text = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("{} / {how:?}: {}: {e}", s.case.name, file.display()));
            let row = format!("{} / per_session {per_session} / {how:?}", s.case.name);
            if !text.contains(MARK) {
                lost.push(format!(
                    "{row}: nothing rewrote {}, so this measured nothing: {text:?}",
                    file.display()
                ));
            }
            let missing: Vec<&str> = BASH_OPERATOR_HISTORY
                .lines()
                .filter(|line| !text.lines().any(|l| l == *line))
                .collect();
            if !missing.is_empty() {
                lost.push(format!(
                    "{row}: the operator's {} lost {missing:?}: {text:?}",
                    file.display()
                ));
            }
        }
        drop(inst);
    }
    assert!(lost.is_empty(), "{}", lost.join("\n"));
}

/// `await_output` for text printed after byte `from` of the output.
fn await_output_after(shim: &mut Shim, s: &Started, from: usize, needle: &str) {
    let deadline = Instant::now() + SHELL_TIMEOUT;
    loop {
        let out = output(shim, s);
        if out.get(from..).is_some_and(|tail| tail.contains(needle)) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{}: `{needle}` never appeared after byte {from}; output: {out:?}",
            s.case.name
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Everything the session has printed, once it has stopped printing: the
/// last of a shell's output can arrive after the shell has gone.
fn settled_output(shim: &mut Shim, s: &Started) -> String {
    let deadline = Instant::now() + SHELL_TIMEOUT;
    let mut last = output(shim, s);
    loop {
        std::thread::sleep(Duration::from_millis(300));
        let now = output(shim, s);
        if now == last {
            return now;
        }
        assert!(
            Instant::now() < deadline,
            "{}: output never settled",
            s.case.name
        );
        last = now;
    }
}

/// A zsh whose history goes to `/dev/null` says nothing about it as it
/// ends. Under an rc that sets `SAVEHIST`, zsh locks the history file
/// before it saves by creating `/dev/null.LOCK`, which fails, and it
/// printed *zsh: locking failed for /dev/null: permission denied* into the
/// output at `exit` and at EOF. The snippet's `SAVEHIST=0` is what stops it
/// saving at all.
#[test]
fn zsh_ends_without_a_history_error_under_an_rc_that_saves_history() {
    let cases = available(&[BASH_AND_ZSH[4]]);
    let Some(case) = cases.first().copied() else {
        return;
    };
    assert_eq!(case.name, "zsh-omz");
    let inst = Instance::new("zsh-quiet");
    let mut shim = Shim::launch(&inst);
    for how in [Ending::Exit, Ending::Eof] {
        let s = start(&inst, &mut shim, case, &format!("Quiet{how:?}"));
        let before = output(&mut shim, &s).len();
        end(&mut shim, &s, how);
        let out = settled_output(&mut shim, &s);
        let ending = out.get(before..).unwrap_or(&out);
        assert!(
            !ending.contains("zsh:"),
            "{} / {how:?}: zsh complained as it ended: {ending:?}",
            case.name
        );
    }
    shim.kill();
}

/// The per-session rows beyond `BASH_AND_ZSH`'s, each with the ending
/// that exposes it.
///
/// - a bash whose own configuration emits OSC 133, so the snippet yields
///   its markers — its per-command append must not yield with them;
/// - a bash and a zsh with history limits of 3, below the six commands a
///   row runs: bash truncates its file to `HISTFILESIZE` when it saves at
///   exit, and without `histappend` that save overwrites the file with the
///   three-entry list; zsh trims to `SAVEHIST` as it appends;
/// - a bash with shell integration off, where only `HISTFILE` in the
///   environment names the file and the shell writes it when it exits;
/// - [`BASH_APPEND_STOPPED`], whose per-command append stops after the
///   marker;
/// - a bash whose rc aliases `history`, which is expanded into the
///   snippet's functions as it is evaluated: the per-command append failed
///   at every prompt and the file stayed empty until the snippet called
///   `builtin history`.
const PER_SESSION_EXTRA: [(Case, Ending); 6] = [
    (
        Case {
            name: "bash-own-markers",
            command: "bash",
            args: &[],
            files: &[(".bashrc", BASH_OWN_MARKERS_RC)],
            integration: true,
            before: &[],
            hung_up: true,
            needs: "bash",
        },
        Ending::ForceTerminate,
    ),
    (
        Case {
            name: "bash-small-limits",
            command: "bash",
            args: &[],
            files: &[(".bashrc", BASH_SMALL_LIMITS_RC)],
            integration: true,
            before: &[],
            hung_up: true,
            needs: "bash",
        },
        Ending::Exit,
    ),
    (
        Case {
            name: "zsh-small-limits",
            command: "zsh",
            args: &[],
            files: &[(".zshrc", "HISTSIZE=3\nSAVEHIST=3\n")],
            integration: true,
            before: &[],
            hung_up: true,
            needs: "zsh",
        },
        Ending::ForceTerminate,
    ),
    (BASH_AND_ZSH[1], Ending::Exit),
    (BASH_APPEND_STOPPED, Ending::Exit),
    (
        Case {
            name: "bash-history-alias",
            command: "bash",
            args: &[],
            files: &[(".bashrc", "alias history='history 20'\n")],
            integration: true,
            before: &[],
            hung_up: true,
            needs: "bash",
        },
        Ending::ForceTerminate,
    ),
];

const BASH_SMALL_LIMITS_RC: &str = "HISTFILE=~/.bash_history\nHISTSIZE=3\nHISTFILESIZE=3\n";

/// A bash whose per-command append stops once the marker is recorded, with
/// limits of 3 — fewer than the commands typed after it. [`STOP_THE_APPEND`]
/// redefines the snippet's `__holdfast_h` to hand on the status and append
/// nothing, as happens when something replaces `PROMPT_COMMAND`
/// mid-session; bash's own save at exit does not go through it. That save
/// is then all that writes: with `histappend` it appends the last three
/// commands, and without it bash rewrites the file from its three-entry
/// list, losing the marker and everything else recorded before.
const BASH_APPEND_STOPPED: Case = Case {
    name: "bash-append-stopped",
    command: "bash",
    args: &[],
    files: &[(".bashrc", BASH_SMALL_LIMITS_RC)],
    integration: true,
    before: &[],
    hung_up: true,
    needs: "bash",
};

/// Typed into [`BASH_APPEND_STOPPED`] once its marker is recorded. Not a
/// `history` function shadowing the builtin: the snippet calls `builtin
/// history -a`, so that an rc's `history` alias cannot stop it.
const STOP_THE_APPEND: &str = "__holdfast_h() { return \"${1:-0}\"; }";

/// A user's own complete OSC 133 integration, untagged, which Holdfast's
/// snippet yields to.
const BASH_OWN_MARKERS_RC: &str = "PS1='\\[\\e]133;A\\a\\]$ \\[\\e]133;B\\a\\]'\n\
                                   PS0='\\e]133;C\\a'\n\
                                   PROMPT_COMMAND='printf \"\\e]133;D;%s\\a\" \"$?\"'\n";

/// `[terminal] shell_history_file = "per_session"`: each session's shell
/// writes its history to `<log dir>/history/<session_id>.history`, `0600`
/// in a `0700` directory, one command at a time — so a forced `terminate`,
/// which gives the shell no chance to save, still leaves the record — and
/// the file outlives the session. `$HOME` still gets nothing.
#[test]
fn a_per_session_history_file_keeps_what_the_agent_ran_and_home_keeps_nothing() {
    use std::os::unix::fs::PermissionsExt;

    // The daemon inherits this process's umask, and `022` clears no bit of
    // `0600` or `0700`: the modes asserted below are then Holdfast's, not
    // a strict runner's.
    // SAFETY: `umask` cannot fail; this test is its own process under
    // nextest and creates everything else with an explicit mode.
    unsafe { libc::umask(0o022) };
    let inst = Instance::new("per-session");
    inst.write_config("[terminal]\nshell_history_file = \"per_session\"\n");
    let mut shim = Shim::launch(&inst);
    let rows: Vec<(Case, Ending)> = BASH_AND_ZSH
        .iter()
        .filter(|c| c.integration)
        .map(|c| (*c, Ending::ForceTerminate))
        .chain(PER_SESSION_EXTRA)
        .collect();
    let commands: Vec<String> = (2..=6).map(|n| format!("echo command''_{n}")).collect();
    let mut ended = Vec::new();
    for (case, how) in rows {
        if available(&[case]).is_empty() {
            continue;
        }
        let s = start(&inst, &mut shim, case, "PerSession");
        if case.name == BASH_APPEND_STOPPED.name {
            send(&mut shim, &s, STOP_THE_APPEND, true);
            await_prompt(&mut shim, &s);
        }
        for command in &commands {
            send(&mut shim, &s, command, true);
            let printed = command.trim_start_matches("echo ").replace("''", "");
            await_output(&mut shim, &s, &printed);
            await_prompt(&mut shim, &s);
        }
        end(&mut shim, &s, how);
        ended.push((s, how));
    }
    shim.kill();

    let dir = inst.dir.join("logs").join("history");
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700, "{}", dir.display());
    for (s, how) in &ended {
        let file = dir.join(format!("{}.history", s.id));
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("{}: no {}: {e}", s.case.name, file.display()));
        assert_eq!(mode(&file), 0o600, "{}", file.display());
        if s.case.name == BASH_APPEND_STOPPED.name {
            // The first command after the stop is absent, or the append
            // never stopped and this row measured nothing; the last is
            // present, or bash never saved at exit.
            let (first, last) = (&commands[0], &commands[commands.len() - 1]);
            assert!(
                text.contains(MARK)
                    && !text.contains(first.as_str())
                    && text.contains(last.as_str()),
                "{} / {how:?}: {} should hold the marker and {last}, and not {first}: {text:?}",
                s.case.name,
                file.display()
            );
            continue;
        }
        for needle in std::iter::once(MARK).chain(commands.iter().map(String::as_str)) {
            assert!(
                text.contains(needle),
                "{} / {how:?}: {} lacks {needle}: {text:?}",
                s.case.name,
                file.display()
            );
        }
    }

    // A fish session is pointed at its file and gets none: its history
    // never reaches one, so creating it would leave an empty file per
    // session. A stand-in named `fish`, because Holdfast recognises the
    // program by name and the file is made before the program runs; it
    // measures the same where no fish is installed.
    let stand_in = inst.home().join("stand-in").join("fish");
    std::fs::create_dir_all(stand_in.parent().unwrap()).unwrap();
    std::fs::write(&stand_in, "#!/bin/sh\nexec cat\n").unwrap();
    std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut shim = Shim::launch(&inst);
    let started = shim.call(
        "start_session",
        json!({ "command": stand_in, "cwd": inst.home() }),
    );
    assert_eq!(started["status"], "ok", "{started}");
    let id = started["data"]["session_id"].as_str().unwrap().to_string();
    let r = shim.call("terminate", json!({ "session": id, "force": true }));
    assert_eq!(r["status"], "ok", "{r}");
    shim.kill();
    let file = dir.join(format!("{id}.history"));
    assert!(
        !file.exists(),
        "a fish session was given {}",
        file.display()
    );

    assert_no_leaks(&ended);
}
