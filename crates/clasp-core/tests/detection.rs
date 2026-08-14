//! 0.0.2 acceptance tests: the §8.7 measurement matrix and OSC 133 shell
//! integration, **measured against real PTYs** rather than replayed.
//!
//! `detector.rs` replays the same rows as byte streams, which pins the
//! classifier against bytes someone typed into a test. This file is the
//! other half: it pins the bytes themselves — that a stock `bash` really
//! does drive bracketed paste, that `read -s` really does drop `ECHO`,
//! and that the §8.5 snippet really does make a shell emit markers. No
//! amount of unit testing can establish any of that.
//!
//! **Three rules every test here follows.**
//!
//! 1. *Assert a derived value, never an echo.* A PTY echoes what is typed,
//!    so a test that searches the buffer for a marker it just typed passes
//!    against a session running `sleep 300`. Three of 0.0.1's first-draft
//!    tests failed exactly that way. Everything asserted below is
//!    `interaction_mode`, `detection_tier`, a confidence, an exit code, a
//!    cursor span, or an ESC-introduced escape sequence — none of which the
//!    echo of a command line can produce. Where a text marker is
//!    unavoidable, `echo CLASP''_SPAN` echoes as `CLASP''_SPAN` and *prints*
//!    `CLASP_SPAN`, and the test searches for the latter.
//! 2. *Assert the tier and the confidence, not just the mode.* Five modes
//!    is low enough cardinality that a mode assertion alone is satisfied by
//!    several different rungs of the §8.3 ladder firing — measured: a REPL
//!    test once passed via the shell's stale `C` marker instead of the
//!    REPL's own bracketed paste, returning the right mode from the wrong
//!    branch. `mode + tier` identifies the rung uniquely; the confidence is
//!    what an agent thresholds on.
//! 3. *Assert the session history a row depends on.* §8.7's rows are not a
//!    function of their three sampled signals alone — `Seen BrktPst` is a
//!    column because two rows show identical signals and classify
//!    differently on history. Rows that differ only in history degrade into
//!    duplicates of each other unless the history is asserted too, so each
//!    row below asserts the mode transitions and the raw escape sequences
//!    that establish its own history.
//!
//! The one place the echo *is* the hazard rather than the assertion is
//! OSC 133: the integration snippet's text contains `\e]133;A\a` as six
//! literal characters, so a `contains("133;A")` test passes against a
//! snippet that mentions markers and emits none. `markers()` below scans
//! for real ESC-introduced sequences for that reason.

use clasp_core::mcp::tools::{
    GetCommandHistoryArgs, ReadOutputArgs, SendInputArgs, StartSessionArgs, StatusArgs,
};
use clasp_core::mcp::ClaspServer;
use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

fn body(r: &rmcp::model::CallToolResult) -> Value {
    r.structured_content.clone().expect("structured content")
}

/// What a row in this file needs from the host beyond a PTY.
///
/// **A need is not always a program**, and stating one as a program is how
/// this file shipped a row that meant two different things on two
/// machines. `matrix_row_the_python_repl_is_at_prompt_with_no_repl_
/// specific_config` was gated on `python3` being on `PATH` while what it
/// actually requires is a Python whose REPL *drives bracketed paste* —
/// which is a version claim, not a presence one. On the author's 3.14 it
/// asserted `AtPrompt`; on `ubuntu-24.04`'s 3.12.3 the same row answers
/// `AwaitingSecret`, reproducibly, on three runner VMs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Need {
    /// A program that must be on `PATH`.
    Program(&'static str),
    /// A CPython whose REPL drives bracketed paste with **no**
    /// configuration: 3.13 or newer, where PyREPL replaced the readline
    /// REPL and enables bracketed paste itself.
    ///
    /// The version is the honest statement of the requirement, and it is
    /// deliberately conservative. Bracketed paste at a *readline* REPL
    /// depends on the readline build and on `inputrc`, so a 3.12 may or
    /// may not drive it; PyREPL always does. Measured here with
    /// `tcgetattr` on the master fd and a scan for `ESC[?2004h`:
    ///
    /// ```text
    /// python3.14 -q                       bracketed paste yes
    /// python3.13 -q                       bracketed paste yes
    /// python3.14 -q PYTHON_BASIC_REPL=1   bracketed paste NO
    /// python3.13 -q PYTHON_BASIC_REPL=1   bracketed paste NO
    /// ```
    ///
    /// — which is why `PYTHON_BASIC_REPL` is part of the need rather than
    /// an environmental detail: set in the runner's environment, it turns
    /// any interpreter here back into the pre-3.13 case, and the row would
    /// once again be measuring something other than what it names.
    PyreplPython,
}

impl Need {
    fn met(self) -> bool {
        match self {
            Self::Program(p) => on_path(p),
            Self::PyreplPython => pyrepl_interpreter().is_some(),
        }
    }

    /// What to tell someone whose host does not meet it.
    fn unmet(self) -> String {
        match self {
            Self::Program(p) => format!("{p} is not on PATH"),
            Self::PyreplPython => format!(
                "no CPython >= 3.13 (PyREPL) usable here — scanned: {}{}",
                python_scan(),
                if basic_repl_forced() {
                    ", and PYTHON_BASIC_REPL is set in the environment, \
                     which turns PyREPL off on every one of them"
                } else {
                    ""
                }
            ),
        }
    }
}

/// Every row in this file that needs something beyond `bash`, and what it
/// needs.
///
/// The table exists so the *number of rows that actually ran* is a
/// quantity the suite can assert on. Eight of these nineteen tests
/// early-`return` when their need is unmet; libtest reports each as `ok`
/// and swallows the `eprintln!` without `--nocapture`. Measured: with
/// `fish` absent this file prints its full pass count and nothing anywhere
/// says a row never ran.
///
/// The exposure is not `fish`. `an_alt_screen_episode_leaves_a_dash_prompt_
/// on_the_heuristic_tier` needs **both** `dash` and `less`, and it is the
/// only PTY-level test of the add-alt-screen direction. On a slim container
/// it vanishes silently along with the `dash` degradation row, the PS2
/// threshold row, the pager row and both `python3` rows — and the task
/// report's claim that "REQ-PD-015 is pinned at the PTY level in both
/// directions" quietly becomes conditional on the host.
///
/// `have()` refuses a need that appears in no row here, so a new gated row
/// cannot introduce a new dependency without this table learning about it.
/// Residual, stated rather than papered over: a new row reusing a need
/// already listed adds no entry, so the census below does not tighten with
/// it.
const HOST_DEPENDENT_ROWS: &[(&str, &[Need])] = &[
    (
        "matrix_row_getpass_is_awaiting_secret_with_no_bracketed_paste_history",
        &[Need::Program("python3")],
    ),
    (
        "matrix_row_the_python_repl_is_at_prompt_with_no_repl_specific_config",
        &[Need::PyreplPython],
    ),
    ("matrix_row_a_pager_is_fullscreen", &[Need::Program("less")]),
    (
        "matrix_row_dash_degrades_silently_to_the_heuristic_tier",
        &[Need::Program("dash")],
    ),
    (
        "an_alt_screen_episode_leaves_a_dash_prompt_on_the_heuristic_tier",
        &[Need::Program("dash"), Need::Program("less")],
    ),
    (
        "the_heuristic_decides_at_exactly_the_threshold_on_a_real_ps2_prompt",
        &[Need::Program("dash")],
    ),
    (
        "zsh_integration_emits_the_measured_marker_stream_and_exact_exit_codes",
        &[Need::Program("zsh")],
    ),
    (
        "fish_integration_emits_the_measured_marker_stream_and_exact_exit_codes",
        &[Need::Program("fish")],
    ),
];

/// The rows that may skip before this file's green stops meaning anything
/// — **by name**, not as a count.
///
/// A count permits the wrong two: `less` alone gates two rows, so a slim
/// container could sit inside a budget of two while losing the only
/// PTY-level test of the add-alt-screen direction. Naming them says which
/// absences are tolerated and leaves every other one red.
///
/// - `fish` is not installable on the development host (no sudo, no
///   network, no binary anywhere on the filesystem), so its snippet
///   remains UNVERIFIED at runtime.
/// - CPython 3.13 is newer than the system Python of a current LTS —
///   `ubuntu-24.04` ships 3.12.3 — so the PyREPL row is genuinely
///   unrunnable on mainstream hosts rather than merely inconvenient. It
///   skips *loudly enough to be fixed*: `CLASP_REQUIRE_ALL_SHELLS=1` turns
///   it into a failure that names the interpreters it scanned.
///
/// Every other need here is met by an ordinary POSIX host.
const ROWS_THAT_MAY_SKIP: &[&str] = &[
    "matrix_row_the_python_repl_is_at_prompt_with_no_repl_specific_config",
    "fish_integration_emits_the_measured_marker_stream_and_exact_exit_codes",
];

/// The environment variable that turns every skip into a failure.
///
/// CI's Linux job sets it, so a runner missing `fish` — or `dash`, or
/// `less`, or a PyREPL-era Python — fails loudly instead of reporting a
/// green nineteen.
const REQUIRE_ALL: &str = "CLASP_REQUIRE_ALL_SHELLS";

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
        .unwrap_or(false)
}

/// True when the environment forces the pre-3.13 readline REPL.
fn basic_repl_forced() -> bool {
    std::env::var_os("PYTHON_BASIC_REPL").is_some_and(|v| !v.is_empty())
}

/// `python3` plus every `python3.<minor>` on `PATH`.
fn python_interpreters() -> Vec<String> {
    let mut names = vec!["python3".to_string()];
    let Some(paths) = std::env::var_os("PATH") else {
        return names;
    };
    for dir in std::env::split_paths(&paths) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let file = entry.file_name();
            let Some(name) = file.to_str() else { continue };
            let Some(minor) = name.strip_prefix("python3.") else {
                continue;
            };
            if !minor.is_empty()
                && minor.bytes().all(|b| b.is_ascii_digit())
                && !names.iter().any(|n| n == name)
            {
                names.push(name.to_string());
            }
        }
    }
    names
}

/// `(major, minor)` as the interpreter itself reports it, and `None` for
/// anything that is not a runnable CPython.
///
/// Asked of the interpreter rather than parsed out of its file name: a
/// `python3.13` on `PATH` may be a wrapper, a symlink to something else,
/// or not executable at all, and this row's requirement is about what runs.
fn python_version(program: &str) -> Option<(u32, u32)> {
    let out = std::process::Command::new(program)
        .args([
            "-c",
            "import sys; print(sys.implementation.name, sys.version_info[0], sys.version_info[1])",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let mut fields = text.split_whitespace();
    if fields.next()? != "cpython" {
        return None;
    }
    Some((fields.next()?.parse().ok()?, fields.next()?.parse().ok()?))
}

/// The newest CPython >= 3.13 on `PATH`, or `None`.
fn pyrepl_interpreter() -> Option<String> {
    if basic_repl_forced() {
        return None;
    }
    let mut best: Option<((u32, u32), String)> = None;
    for name in python_interpreters() {
        let Some(v) = python_version(&name) else {
            continue;
        };
        if v >= (3, 13) && best.as_ref().is_none_or(|(seen, _)| *seen < v) {
            best = Some((v, name));
        }
    }
    best.map(|(_, name)| name)
}

/// What the scan found, for the message a skip or a `REQUIRE_ALL` failure
/// carries. "python3 is CPython 3.12" is the sentence that turns an
/// unexplained red into an install command.
fn python_scan() -> String {
    let found: Vec<String> = python_interpreters()
        .iter()
        .map(|p| match python_version(p) {
            Some((major, minor)) => format!("{p} is CPython {major}.{minor}"),
            None => format!("{p} reported no CPython version"),
        })
        .collect();
    if found.is_empty() {
        "no python3 on PATH".to_string()
    } else {
        found.join(", ")
    }
}

fn have(need: Need) -> bool {
    assert!(
        HOST_DEPENDENT_ROWS
            .iter()
            .any(|(_, needs)| needs.contains(&need)),
        "{need:?} gates a row but appears in no entry of \
         HOST_DEPENDENT_ROWS, so the skip census cannot see it"
    );
    if need.met() {
        return true;
    }
    assert!(
        std::env::var(REQUIRE_ALL).as_deref() != Ok("1"),
        "{REQUIRE_ALL}=1 is set and {}. This row would otherwise be \
         skipped and reported as `ok`. Satisfy it, or unset {REQUIRE_ALL} \
         and accept that this file's green covers fewer rows than its name \
         suggests.",
        need.unmet()
    );
    false
}

/// The interpreter the PyREPL row runs, once `have()` has applied the
/// same `REQUIRE_ALL` rule every other row gets.
fn pyrepl_python() -> Option<String> {
    have(Need::PyreplPython).then(pyrepl_interpreter).flatten()
}

/// `fish`'s major version, as the binary reports it (`fish, version
/// 4.0.2`), or `None` when it cannot be asked.
fn fish_major_version() -> Option<u32> {
    let out = std::process::Command::new("fish")
        .arg("--version")
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    text.split_whitespace()
        .next_back()?
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// How the fish row starts fish.
///
/// `--no-config` always, so no rc file participates. On fish 4 and later,
/// also `--features=no-mark-prompt`: fish marks prompts itself from 4.0
/// and `shell.rs`'s guard therefore declines to inject there, which would
/// leave that row measuring fish's own marker stream instead of the
/// snippet's. Turning fish's marking off restores the row's subject.
///
/// Version-gated rather than passed unconditionally because fish 3 has
/// never heard of the flag, and fish 3 is the version the row passes on
/// today. **Unverified: fish is not installed on this host**, so neither
/// the flag nor the version parse has been run against a real fish.
fn fish_args() -> Vec<String> {
    let mut args = vec!["--no-config".to_string()];
    if fish_major_version().is_some_and(|major| major >= 4) {
        args.push("--features=no-mark-prompt".to_string());
    }
    args
}

/// The census that stops the row count dropping silently.
///
/// Independent of whether any other test in this file has run: it asks the
/// host the same question `have()` asks, for every row that asks one. That
/// is what makes it a floor rather than a report.
#[test]
fn the_pty_matrix_runs_every_host_dependent_row_but_the_two_it_names() {
    let skipped: Vec<&str> = HOST_DEPENDENT_ROWS
        .iter()
        .filter(|(_, needs)| !needs.iter().all(|n| n.met()))
        .map(|(row, _)| *row)
        .collect();

    if std::env::var(REQUIRE_ALL).as_deref() == Ok("1") {
        assert!(
            skipped.is_empty(),
            "{REQUIRE_ALL}=1 but {} row(s) would skip: {skipped:?}",
            skipped.len()
        );
    }
    let unexpected: Vec<&&str> = skipped
        .iter()
        .filter(|row| !ROWS_THAT_MAY_SKIP.contains(row))
        .collect();
    assert!(
        unexpected.is_empty(),
        "{unexpected:?} would skip and be reported as `ok`. Only \
         {ROWS_THAT_MAY_SKIP:?} may — every other need in this file is met \
         by an ordinary POSIX host, so this is the slim-container case the \
         suite's green used to hide. All skips: {skipped:?}"
    );
}

/// Every session here runs with `TERM` pinned.
///
/// Not shell configuration — §8.2's "no configuration required" claim is
/// about rc files, and a terminal identifying itself is what every real
/// terminal does. It is pinned because the child inherits the *test
/// runner's* environment, where `TERM` may be unset or `dumb`: readline
/// suppresses bracketed paste on a dumb terminal and `less` does not use
/// the alternate screen without `smcup`, so half this matrix would
/// silently measure a degraded terminal instead of the one §8.7 sampled.
fn term() -> Option<HashMap<String, String>> {
    Some(HashMap::from([(
        "TERM".to_string(),
        "xterm-256color".to_string(),
    )]))
}

async fn start(server: &ClaspServer, args: StartSessionArgs) -> String {
    let r = server
        .start_session(Parameters(args))
        .await
        .expect("start_session must not be a protocol error");
    let b = body(&r);
    assert_eq!(b["status"], "ok", "start_session failed: {b}");
    b["data"]["session_id"]
        .as_str()
        .expect("session_id")
        .to_string()
}

/// Stock `bash --norc --noprofile`: no rc file, no profile, no prompt
/// configuration of any kind (REQ-PD-003).
fn bash() -> StartSessionArgs {
    StartSessionArgs {
        command: "bash".into(),
        args: vec!["--norc".into(), "--noprofile".into()],
        env: term(),
        ..Default::default()
    }
}

/// A `command` run under `bash -c`, which `detect_shell` never integrates
/// — used for the rows that need a program with no shell around it.
fn bash_c(command: &str) -> StartSessionArgs {
    StartSessionArgs {
        command: "bash".into(),
        args: vec![
            "--norc".into(),
            "--noprofile".into(),
            "-c".into(),
            command.into(),
        ],
        env: term(),
        ..Default::default()
    }
}

/// A `bash` whose **own** prompt emits OSC 133 before CLASP types
/// anything.
///
/// The markers come from a command substitution rather than from `PS1`'s
/// literal text — which is how starship, Kitty's integration and WezTerm's
/// emit them, and is exactly why §8.5's `PS1` string guard cannot see
/// them. bash imports `PS1`, `PS0` and `PROMPT_COMMAND` from the
/// environment before it draws its first prompt (measured), so the shell
/// is already marking at the instant the snippet arrives — the state a
/// fish 4.0 session is in for a different reason.
fn already_marking_bash() -> StartSessionArgs {
    let env: HashMap<String, String> = [
        ("TERM", "xterm-256color"),
        ("CLASP_MARK_A", r"\033]133;A\007"),
        ("CLASP_MARK_B", r"\033]133;B\007"),
        ("CLASP_MARK_C", r"\033]133;C\007"),
        ("CLASP_MARK_D", r"\033]133;D;%s\007"),
        (
            "PS1",
            r#"$(printf "$CLASP_MARK_A")clasp$ $(printf "$CLASP_MARK_B")"#,
        ),
        ("PS0", r#"$(printf "$CLASP_MARK_C")"#),
        ("PROMPT_COMMAND", r#"printf "$CLASP_MARK_D" "$?""#),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
    .collect();
    StartSessionArgs {
        command: "bash".into(),
        args: vec!["--norc".into(), "--noprofile".into()],
        env: Some(env),
        ..Default::default()
    }
}

fn program(command: &str, args: &[&str]) -> StartSessionArgs {
    StartSessionArgs {
        command: command.into(),
        args: args.iter().map(|a| (*a).to_string()).collect(),
        env: term(),
        ..Default::default()
    }
}

async fn status(server: &ClaspServer, id: &str) -> Value {
    let r = server
        .status(Parameters(StatusArgs { session: id.into() }))
        .await
        .expect("status must not be a protocol error");
    body(&r)["data"].clone()
}

/// Poll `status` until `pred` accepts a record, and return *that* record —
/// not a fresh one — so every assertion in a row describes one sample.
async fn await_status(
    server: &ClaspServer,
    id: &str,
    what: &str,
    mut pred: impl FnMut(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let s = status(server, id).await;
        if pred(&s) {
            return s;
        }
        assert!(
            Instant::now() < deadline,
            "never reached {what}; last status was {s}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Poll until `interaction_mode` reaches `want`.
async fn await_mode(server: &ClaspServer, id: &str, want: &str) -> Value {
    await_status(server, id, want, |s| s["interaction_mode"] == want).await
}

/// Poll until the detector reports `last_line` *and* full quiescence.
///
/// Two distinct reasons, both measured.
///
/// Tier 3's confidence is `quiescent_score * max(pattern, cursor)`, so the
/// exact numbers §8.7 records are only the session's answer once the settle
/// window has saturated.
///
/// And a *mode* wait is not enough for any row that also asserts the line
/// the mode was reached on, because a program reaches a mode and prints
/// the line that explains it as two separate events, in that order.
/// PyREPL enables bracketed paste *before* it draws `>>> `, so a mode-only
/// wait there returns with an empty last line and the row's own assertion
/// fails for a reason that has nothing to do with the row. Waiting for the
/// line as well makes the wait an assertion about *these* bytes rather
/// than about however long the test took to get here.
///
/// It was also, until this milestone closed it, the workaround for a
/// product defect. Between a command being submitted and its first byte of
/// output, `ECHO` was sampled through a 50 ms cache that could still be
/// holding readline's echo-off reading while bracketed paste had already
/// gone off — so §8.3's echo rung answered `AwaitingSecret` at 0.95, with
/// an empty tail line, for an ordinary command. Roughly one workspace run
/// in ten failed `matrix_row_bash_read_s_..._flags_a_write` on it. The
/// cache is gone (`pty::echo_freshness`) and the sample is now taken with
/// the detector held (`session::no_output_is_classified_between_...`), so
/// the wait below is no longer load-bearing for that; it is kept for the
/// PyREPL reason above, which is not going anywhere.
async fn await_settled(server: &ClaspServer, id: &str, last_line: &str) -> Value {
    await_status(server, id, &format!("a settled {last_line:?}"), |s| {
        s["prompt"]["last_line"] == last_line && s["prompt"]["quiescent_score"] == 1.0
    })
    .await
}

async fn kill(server: &ClaspServer, id: &str) {
    if let Ok(s) = server.registry.get(id) {
        // The whole process group (§4.4): these sessions leave `sleep`s and
        // nested shells behind otherwise.
        let _ = s.signal(clasp_core::pty::Signal::Kill);
    }
}

async fn send(server: &ClaspServer, id: &str, data: &str) -> Value {
    write(server, id, data, true).await
}

/// `send_input` without the trailing newline — for keys, like `less`'s `q`.
async fn keypress(server: &ClaspServer, id: &str, data: &str) -> Value {
    write(server, id, data, false).await
}

async fn write(server: &ClaspServer, id: &str, data: &str, newline: bool) -> Value {
    let r = server
        .send_input(Parameters(SendInputArgs {
            session: id.into(),
            data: data.into(),
            append_newline: Some(newline),
        }))
        .await
        .expect("send_input must not be a protocol error");
    let b = body(&r);
    assert_eq!(b["status"], "ok", "send_input failed: {b}");
    b
}

/// The session's whole raw buffer, escape sequences intact (0.0.2 does no
/// stripping on the read path).
async fn raw(server: &ClaspServer, id: &str) -> String {
    let r = body(
        &server
            .read_output(Parameters(ReadOutputArgs {
                session: id.into(),
                since_cursor: Some(0),
                max_bytes: Some(256 * 1024),
                ..Default::default()
            }))
            .await
            .expect("read_output must not be a protocol error"),
    );
    r["data"]["output"].as_str().expect("output").to_string()
}

async fn history(server: &ClaspServer, id: &str) -> Value {
    body(
        &server
            .get_command_history(Parameters(GetCommandHistoryArgs {
                session: id.into(),
                limit: None,
                since_index: None,
            }))
            .await
            .expect("get_command_history must not be a protocol error"),
    )
}

/// Poll until the history holds at least `n` entries and **every one of
/// them is closed**, and return that payload.
///
/// **A marker being visible is not the history having recorded it**, and
/// the gap between the two is a real window rather than a nicety. The
/// reader appends each chunk to the output buffer and feeds the detector —
/// which is what applies history events — *afterwards* (`session::spawn`),
/// so a `D` is readable through `read_output` strictly before it has
/// closed an entry. A row that waits on `await_markers` and then asserts
/// on `get_command_history` is licensing a claim about one observable with
/// a wait on another.
///
/// Measured with `mcp::detection`'s own probe, a 50 ms sleep injected
/// between the buffer push and the detector feed: with the probe applied
/// and this wait absent, all four history rows in this file fail every
/// run — two, three or four entries short, or missing the nested shell's
/// command entirely. With the wait they pass. Without the probe the window
/// is microseconds wide and closes on its own on an idle box, which is the
/// definition of the flake this file has already shipped once.
///
/// A floor, never the assertion: every caller still asserts the *exact*
/// entry count, commands and exit codes it expects.
async fn await_closed_history(server: &ClaspServer, id: &str, n: usize) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let h = history(server, id).await;
        let entries = h["data"]["entries"].as_array().cloned().unwrap_or_default();
        // `output_end_cursor` and `duration_ms` are what an open entry
        // lacks. `exit_code` is not the test: a `D` with no payload closes
        // an entry and still parses to `None`.
        if entries.len() >= n
            && entries
                .iter()
                .all(|e| e["output_end_cursor"].is_u64() && e["duration_ms"].is_u64())
        {
            return h;
        }
        assert!(
            Instant::now() < deadline,
            "the history never reached {n} closed entries; last was {h}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Every OSC 133 marker in `raw`, in order, as its payload — `"A"`, `"B"`,
/// `"C"`, `"D;42"`.
///
/// Only a genuine `ESC ] 1 3 3 ;` introducer counts, and that is the whole
/// point of this function. The shell *echoes* the integration snippet, and
/// the snippet's text contains `\e]133;A\a` — the six literal characters
/// `\`, `e`, `]`, `1`, `3`, `3` — with no ESC byte anywhere. A test that
/// searched for the string `133;A` would therefore be satisfied by a
/// snippet that never emits a marker, which is exactly the mutant class
/// this file exists to kill: seven separate mutations of the shipped
/// snippets pass every string-level test in the workspace while producing
/// zero markers on a real shell.
fn markers(raw: &str) -> Vec<String> {
    const INTRODUCER: &[u8] = b"\x1b]133;";
    let b = raw.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + INTRODUCER.len() <= b.len() {
        if &b[i..i + INTRODUCER.len()] != INTRODUCER {
            i += 1;
            continue;
        }
        let mut j = i + INTRODUCER.len();
        let mut payload = Vec::new();
        // BEL or ST terminates; both forms are legal and bash's `\a` emits
        // the former.
        while j < b.len() && b[j] != 0x07 && !(b[j] == 0x1b && b.get(j + 1) == Some(&b'\\')) {
            payload.push(b[j]);
            j += 1;
        }
        out.push(String::from_utf8_lossy(&payload).into_owned());
        i = j.max(i + 1);
    }
    out
}

/// Poll until at least `n` OSC 133 markers have arrived, and return them.
///
/// This is the synchronisation primitive for every integrated-shell test.
/// Waiting on `AtPrompt` instead is *wrong* here: the session is already
/// `AtPrompt` at the prompt a command was typed at, so a mode wait returns
/// before the command has run and the next assertion samples a
/// half-finished history. A marker count is monotonic and says exactly how
/// far the shell has got.
async fn await_markers(server: &ClaspServer, id: &str, n: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let m = markers(&raw(server, id).await);
        if m.len() >= n {
            return m;
        }
        assert!(
            Instant::now() < deadline,
            "expected {n} OSC 133 markers, saw {}: {m:?}",
            m.len()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[track_caller]
fn assert_classified(s: &Value, mode: &str, tier: &str, confidence: f64) {
    assert_eq!(s["interaction_mode"], mode, "interaction_mode: {s}");
    assert_eq!(s["detection_tier"], tier, "detection_tier: {s}");
    assert_eq!(s["prompt"]["confidence"], confidence, "confidence: {s}");
}

/// Assert the terminal-mode *history* a §8.7 row rests on, read straight
/// off the raw byte stream.
///
/// `Seen BrktPst` is a column in that matrix because two rows show
/// identical current signals and classify differently on what the session
/// has already observed. Nothing else in a response exposes it, and a row
/// whose history quietly stopped being established degrades into a
/// duplicate of another row that already passes.
#[track_caller]
fn assert_history(raw: &str, seen_bracketed_paste: bool, seen_alt_screen: bool) {
    assert_eq!(
        raw.contains("\x1b[?2004h"),
        seen_bracketed_paste,
        "Seen BrktPst"
    );
    assert_eq!(raw.contains("\x1b[?1049h"), seen_alt_screen, "Seen AltScr");
}

// ---------------------------------------------------------------------
// The §8.7 matrix, row by row
// ---------------------------------------------------------------------

#[tokio::test]
async fn matrix_row_an_idle_bash_prompt_is_at_prompt_via_terminal_mode() {
    // §8.7 row 1 (Seen BrktPst yes / ECHO off / BrktPst ON / AltScr off),
    // REQ-PD-003: stock `bash --norc --noprofile` with shell integration
    // declined, so only tier 2 can answer and it must do so with no
    // configuration whatsoever.
    let server = ClaspServer::new();
    let id = start(
        &server,
        StartSessionArgs {
            shell_integration: Some(false),
            ..bash()
        },
    )
    .await;

    // The wait is the separator from the degenerate case. `AtPrompt` is
    // what a session reports about a *prompt*, and a real bash prompt is
    // the only thing that puts `bash-<version>$ ` on the last line — so
    // this cannot be satisfied by a child that printed nothing, which is
    // what `a_session_that_never_prompts_is_never_reported_at_a_prompt`
    // measures. The version is not pinned: `--norc` bash renders `\s-\v\$`
    // and the release is not this test's business.
    let s = await_status(&server, &id, "a settled bash prompt", |s| {
        let line = s["prompt"]["last_line"].as_str().unwrap_or_default();
        s["interaction_mode"] == "AtPrompt" && line.starts_with("bash-") && line.ends_with("$ ")
    })
    .await;
    assert_classified(&s, "AtPrompt", "terminal_mode", 0.95);
    assert_eq!(s["shell_integration"], Value::Null);

    let raw = raw(&server, &id).await;
    assert_history(&raw, true, false);
    // REQ-PD-009's negative half: integration was declined, so no snippet
    // was typed and no marker can have arrived. Checked on the *escape*
    // rather than the text `133;A`, which the snippet itself contains.
    assert!(
        !raw.contains("\x1b]133;"),
        "a snippet was typed anyway: {raw:?}"
    );
    kill(&server, &id).await;
}

#[tokio::test]
async fn matrix_row_a_running_command_is_executing_via_terminal_mode() {
    // §8.7 row 2 (Seen BrktPst yes / ECHO ON / BrktPst off / AltScr off).
    //
    // This row is also §8.7's availability row 4 — the one inference
    // bracketed-paste availability legitimately licenses — and it is the
    // direction that fails if bracketed paste is *removed* from the
    // availability rule. Note what such a mutation does and does not
    // change: `interaction_mode` stays `Executing` and `confidence` stays
    // 0.00, because a settled `sleep 5` scores nothing on the T3 table
    // either. The tier is the only field that moves, which is why it is
    // asserted.
    let server = ClaspServer::new();
    let id = start(
        &server,
        StartSessionArgs {
            shell_integration: Some(false),
            ..bash()
        },
    )
    .await;
    // The prompt first: this row's `Seen BrktPst: yes` is established by
    // the shell having drawn one, not by anything the row itself does.
    await_mode(&server, &id, "AtPrompt").await;

    send(&server, &id, "sleep 5").await;
    let s = await_mode(&server, &id, "Executing").await;
    assert_classified(&s, "Executing", "terminal_mode", 0.0);
    assert_history(&raw(&server, &id).await, true, false);
    kill(&server, &id).await;
}

#[tokio::test]
async fn matrix_row_bash_read_s_is_awaiting_secret_and_flags_a_write() {
    // §8.7 row 4 (Seen BrktPst yes / ECHO off / BrktPst off / AltScr off),
    // REQ-PD-004. `read -s` disables ECHO and bracketed paste is off while
    // a command runs, which is the exact §8.3 signature.
    //
    // REQ-SEC-011 rides along on the same session: the warning exists to
    // be produced by a *real* echo-off shell, and the state a real shell
    // reaches is the thing a mock cannot establish.
    let server = ClaspServer::new();
    let id = start(
        &server,
        StartSessionArgs {
            shell_integration: Some(false),
            ..bash()
        },
    )
    .await;
    await_mode(&server, &id, "AtPrompt").await;

    // The negative first, on the same session: an ordinary write at an
    // ordinary prompt is not flagged. Without it, a `warning` hardcoded to
    // the string would pass the positive below.
    let plain = send(&server, &id, "echo plain").await;
    assert_eq!(plain["data"]["warning"], Value::Null);

    send(&server, &id, "read -s -p 'Password: ' pw").await;
    // Settled on the prompt `read -s` printed — not the echo of the
    // command line, which ends in ` pw`. This is the row that caught the
    // stale-`ECHO` transient described in `await_settled`, and asserting
    // the line keeps it an assertion about `read -s`'s own prompt rather
    // than about whatever state the shell was passing through.
    let s = await_settled(&server, &id, "Password: ").await;
    // 0.95 is what an agent thresholds on before calling
    // `request_secret_input` (§5.2, §9.5); a silent drop stops that tool
    // ever firing.
    assert_classified(&s, "AwaitingSecret", "terminal_mode", 0.95);
    assert_history(&raw(&server, &id).await, true, false);

    let flagged = send(&server, &id, "hunter2").await;
    assert_eq!(flagged["status"], "ok", "the write must still happen");
    assert_eq!(flagged["data"]["warning"], "session_awaiting_secret");
    kill(&server, &id).await;
}

#[tokio::test]
async fn matrix_row_getpass_is_awaiting_secret_with_no_bracketed_paste_history() {
    // §8.7 row 3, and the sharpest of the three `AwaitingSecret` rows.
    //
    // §8.7 notes that `getpass()` shows the same three signals a `dash`
    // prompt does — but only two of the three: `getpass()` turns ECHO
    // *off* where `dash` leaves it on, and that is the whole difference.
    // So this row's `Seen BrktPst` column is not load-bearing, and the
    // measurement below proves it: `python3 -c 'getpass.getpass()'` never
    // drives bracketed paste at all, and still answers `AwaitingSecret`.
    // That pins §8.3's rule that the echo rung is **not** availability
    // gated — gating it would leave a real password prompt on a
    // non-readline program answering via T3 instead.
    if !have(Need::Program("python3")) {
        eprintln!("skipping: python3 not installed");
        return;
    }
    let server = ClaspServer::new();
    let id = start(
        &server,
        program("python3", &["-c", "import getpass; getpass.getpass()"]),
    )
    .await;

    let s = await_settled(&server, &id, "Password: ").await;
    assert_classified(&s, "AwaitingSecret", "terminal_mode", 0.95);
    assert_history(&raw(&server, &id).await, false, false);
    kill(&server, &id).await;
}

/// One `ECHO off` state, the terminal flags that distinguish it, and what
/// §8.3's ladder answers for it.
struct EchoOffRow {
    what: &'static str,
    /// Driven with `stty` wherever the state can be set directly, so the
    /// row does not depend on which Python — or readline, or libedit — the
    /// host happens to have. That dependence is what made §8.7's REPL row
    /// mean two different things on two machines.
    command: &'static str,
    /// The line the session settles on, so the answer below describes
    /// *this* prompt rather than whatever the session passed through.
    last_line: &'static str,
    /// What `stty -a` must report for `icanon` in the session's own
    /// output. `None` for a row whose state is set by the program under
    /// test, where dumping the flags would displace the prompt the row is
    /// asserted on — the value is then measured out of band and named in
    /// the comment.
    canonical: Option<bool>,
    /// **The flip point: `(interaction_mode, detection_tier, confidence)`
    /// as §8.3's ladder answers today.** The rung consults `ECHO` alone,
    /// so all three rows answer identically, and the first is a readline
    /// prompt being reported as a password prompt at 0.95 — the reading
    /// §8.4 tells the agent to answer with `request_secret_input`.
    ///
    /// When the rung consults `ICANON` (§14.1, REQ-PDS-001..003), rows 1
    /// and 3 move and row 2 does not. Edit these three literals; the
    /// sessions above them are the part that took the work.
    answer: (&'static str, &'static str, f64),
}

/// The `ECHO off` states a real PTY reaches, and what CLASP answers for
/// each of them.
///
/// **Why this exists.** CI ran §8.7's Python REPL row on `ubuntu-24.04`
/// and got `AwaitingSecret` where the row asserts `AtPrompt` — identically
/// on three runner VMs. The mechanism is not the interpreter: bracketed
/// paste was masking §8.3's echo rung on the author's machine and on
/// nothing else. Row 1 below drives the same state with `stty`, so the
/// mechanism is pinned where no host's Python can hide it again.
///
/// **`ICANON` is what separates the rows, and CLASP is not given it.**
/// Measured here with one `tcgetattr` per scenario on the master fd:
///
/// ```text
/// bash idle prompt                ECHO off / ICANON off
/// python3 -q (PyREPL 3.13, 3.14)  ECHO off / ICANON off
/// python3 -q PYTHON_BASIC_REPL=1  ECHO off / ICANON off
/// getpass()                       ECHO off / ICANON ON
/// bash read -s                    ECHO off / ICANON ON
/// bash read -s -n 1               ECHO off / ICANON off
/// ```
///
/// A line editor drops echo and *leaves* canonical mode because it draws
/// the characters itself; a program that wants a whole secret line drops
/// echo and *stays* canonical. `PtyBackend::echo_enabled` reports one bit
/// of that, so rows 1 and 2 are the same session as far as the ladder can
/// tell. Row 3 is the measured limit of the remedy rather than a case for
/// it (REQ-PDS-003): `read -s -n 1` is a genuine secret prompt in the
/// readline shape, because a single-character read leaves canonical mode
/// by construction.
#[tokio::test]
async fn echo_off_prompts_with_and_without_canonical_mode() {
    const ROWS: &[EchoOffRow] = &[
        EchoOffRow {
            what: "a line editor's prompt: echo off, canonical mode off",
            command: "stty -echo -icanon; stty -a; printf '>>> '; sleep 30",
            last_line: ">>> ",
            canonical: Some(false),
            answer: ("AwaitingSecret", "terminal_mode", 0.95),
        },
        EchoOffRow {
            what: "a secret prompt: echo off, canonical mode on",
            command: "stty -echo; stty -a; printf 'Password: '; sleep 30",
            last_line: "Password: ",
            canonical: Some(true),
            answer: ("AwaitingSecret", "terminal_mode", 0.95),
        },
        EchoOffRow {
            what: "read -s -n 1: a secret prompt in the readline shape",
            // Measured out of band: `ECHO off / ICANON off`. `read` sets
            // the state itself, so the session cannot dump `stty -a`
            // without putting it on the line the row settles on.
            command: "read -s -n 1 -p 'Key: ' k",
            last_line: "Key: ",
            canonical: None,
            answer: ("AwaitingSecret", "terminal_mode", 0.95),
        },
    ];

    for row in ROWS {
        let server = ClaspServer::new();
        let id = start(&server, bash_c(row.command)).await;

        let s = await_settled(&server, &id, row.last_line).await;
        let (mode, tier, confidence) = row.answer;
        assert_eq!(s["interaction_mode"], mode, "{}: {s}", row.what);
        assert_eq!(s["detection_tier"], tier, "{}: {s}", row.what);
        assert_eq!(s["prompt"]["confidence"], confidence, "{}: {s}", row.what);

        let raw = raw(&server, &id).await;
        // No bracketed paste anywhere, which is what puts these rows on
        // the echo rung at all: with the paste on, the rung above answers
        // first and none of this is reachable (§8.3, §8.7 finding 1).
        assert_history(&raw, false, false);
        if let Some(canonical) = row.canonical {
            // The premise, read off the session's own `stty -a` rather
            // than assumed. Without it a mistyped `stty` argument turns
            // row 1 into row 2 — which asserts the same answer and would
            // keep passing while measuring nothing.
            assert_eq!(
                stty_flag(&raw, "icanon"),
                Some(canonical),
                "{}: ICANON as the session reports it",
                row.what
            );
            assert_eq!(
                stty_flag(&raw, "echo"),
                Some(false),
                "{}: ECHO as the session reports it",
                row.what
            );
        }
        kill(&server, &id).await;
    }
}

/// A terminal flag as `stty -a` reports it in `raw`: `Some(true)` for
/// `icanon`, `Some(false)` for `-icanon`, `None` if it never appeared.
///
/// Token-exact on purpose. `stty` spells a disabled flag by prefixing a
/// `-`, so `raw.contains("icanon")` is satisfied by both states and a test
/// written that way asserts nothing at all.
fn stty_flag(raw: &str, flag: &str) -> Option<bool> {
    let mut seen = None;
    for token in raw.split(|c: char| c.is_whitespace() || c == ';') {
        if token == flag {
            seen = Some(true);
        } else if token.strip_prefix('-') == Some(flag) {
            seen = Some(false);
        }
    }
    seen
}

#[tokio::test]
async fn matrix_row_the_python_repl_is_at_prompt_with_no_repl_specific_config() {
    // §8.7 row 6 and finding 2: readline-family REPLs drive bracketed
    // paste, so they classify deterministically without appearing in the
    // T3 pattern table and without any adapter.
    //
    // **The requirement is CPython >= 3.13, and it is stated because
    // leaving it unstated is how this row meant two different things.**
    // Finding 2's mechanism is bracketed paste at the REPL prompt, and
    // which Python drives it changed under the row: PyREPL landed in 3.13
    // and enables it itself, while a pre-3.13 readline REPL leaves it to
    // the readline build and `inputrc` — `ubuntu-24.04`'s 3.12.3 emits
    // none, measured on three runner VMs, and so does any 3.13+ started
    // with `PYTHON_BASIC_REPL=1` (measured here).
    //
    // Without the paste, §8.3's ladder does not reach the rung this row
    // asserts. It reaches the echo rung instead — readline holds `ECHO`
    // off at its prompt (§8.2 finding 1) — and answers `AwaitingSecret` /
    // `terminal_mode` / 0.95 at an ordinary REPL prompt, which §8.4 tells
    // the agent to answer by calling `request_secret_input`. That answer
    // is CLASP's, not this row's, and it is pinned as its own row in
    // `echo_off_prompts_with_and_without_canonical_mode`; what belongs
    // here is the refusal to run on a host where this row's premise does
    // not hold. `Need::PyreplPython` is that refusal, and
    // `CLASP_REQUIRE_ALL_SHELLS=1` turns it back into a failure so CI
    // cannot skip quietly.
    let Some(python) = pyrepl_python() else {
        eprintln!("skipping: {}", Need::PyreplPython.unmet());
        return;
    };
    let server = ClaspServer::new();
    let id = start(&server, program(&python, &["-q"])).await;

    // Settled on the prompt, not merely `AtPrompt`: PyREPL enables
    // bracketed paste *before* it draws `>>> `, so a mode-only wait returns
    // with an empty last line and the assertion below fails for a reason
    // that has nothing to do with the row.
    let s = await_settled(&server, &id, ">>> ").await;
    assert_classified(&s, "AtPrompt", "terminal_mode", 0.95);
    // `terminal_mode`, not `heuristic`: `>>> ` also scores 0.9 on the T3
    // table, so the mode alone is reached by either tier and only the tier
    // says which one answered. Finding 2 is a claim about *bracketed
    // paste*, so the tier is the finding.
    assert_eq!(s["prompt"]["pattern_score"], 0.9);
    let raw = raw(&server, &id).await;
    assert_history(&raw, true, false);
    assert!(!raw.contains("\x1b]133;"), "the REPL emitted OSC 133");
    kill(&server, &id).await;
}

#[tokio::test]
async fn matrix_row_a_pager_is_fullscreen() {
    // §8.7 row 7. Line-oriented prompt logic does not apply inside a TUI,
    // and the agent is told to read the screen instead (§5.2).
    if !have(Need::Program("less")) {
        eprintln!("skipping: less not installed");
        return;
    }
    let server = ClaspServer::new();
    let id = start(&server, bash_c("seq 1 500 | less")).await;

    let s = await_mode(&server, &id, "Fullscreen").await;
    // Zero on purpose: `Fullscreen` is a fact about the terminal, not a
    // graded belief about a prompt, and the agent has nothing to act on.
    assert_classified(&s, "Fullscreen", "terminal_mode", 0.0);
    assert_history(&raw(&server, &id).await, false, true);
    kill(&server, &id).await;
}

#[tokio::test]
async fn matrix_row_dash_degrades_silently_to_the_heuristic_tier() {
    // REQ-PD-006 and REQ-DM-002. `dash` drives no terminal mode and leaves
    // ECHO *on* at its prompt, so a T2 answer here would be actively wrong
    // (`Executing` at a live prompt) rather than merely absent. The
    // per-signal availability gate is what routes it to T3.
    if !have(Need::Program("dash")) {
        eprintln!("skipping: dash not installed");
        return;
    }
    let server = ClaspServer::new();
    let id = start(&server, program("dash", &[])).await;

    let s = await_settled(&server, &id, "$ ").await;
    assert_classified(&s, "AtPrompt", "heuristic", 0.6);
    assert_eq!(s["prompt"]["pattern_score"], 0.6);
    assert_eq!(s["prompt"]["quiescent_score"], 1.0);
    assert_eq!(s["prompt"]["cursor_score"], 0.0, "Tier B is 0.0.4");
    // confidence = quiescent x max(pattern, cursor) = 1.0 x 0.6, exactly.
    assert_history(&raw(&server, &id).await, false, false);

    // Degradation is silent *and* legible: REQ-DM-002 requires the history
    // tool to say why it has nothing rather than return an empty list.
    let h = history(&server, &id).await;
    assert_eq!(h["status"], "unavailable", "{h}");
    assert_eq!(
        h["data"]["reason"],
        "shell integration was not injected for this command"
    );
    kill(&server, &id).await;
}

#[tokio::test]
async fn matrix_row_an_exited_session_reports_exited() {
    let server = ClaspServer::new();
    let id = start(&server, bash_c("exit 3")).await;

    let mut s = await_mode(&server, &id, "Exited").await;
    // `status` samples liveness twice — once for the session record's
    // `exit_code`, once for the classification — so there is a one-
    // `try_wait` window in which the record still reports `exit_code:
    // null` while the detector already reports `Exited`. Re-read until the
    // two agree rather than asserting on whichever sample won the race.
    let deadline = Instant::now() + Duration::from_secs(5);
    while s["exit_code"].is_null() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
        s = status(&server, &id).await;
    }
    // 3, not "nonzero": only a shell that actually ran `exit 3` produces
    // it, and the whole session is otherwise silent.
    assert_eq!(s["exit_code"], 3, "{s}");
    // `heuristic` is honest rather than incidental: this child drove no
    // terminal mode before dying, so the tier reported is the best tier
    // the session ever *could* have answered at.
    assert_classified(&s, "Exited", "heuristic", 0.0);
    assert_eq!(s["prompt"]["quiescent_score"], 0.0);
    assert_eq!(s["prompt"]["pattern_score"], 0.0);

    // The premise the tier rests on, asserted directly rather than read
    // back out of the answer — the guard every other row in this file
    // carries and the one row that was missing it. `heuristic` here is a
    // claim about what the session *observed*, and all three tier-gating
    // flags have to be off for it to be the honest answer rather than a
    // coincidence. `assert_history` covers two of them; the third is
    // checked on the escape, since `bash -c` still has shell integration
    // enabled by default and a snippet reaching this child would take the
    // row to `semantic`.
    let raw = raw(&server, &id).await;
    assert_history(&raw, false, false);
    assert!(
        !raw.contains("\x1b]133;"),
        "an OSC 133 marker arrived, so `heuristic` is not what this \
         session could have answered at: {raw:?}"
    );
}

#[tokio::test]
async fn a_session_that_never_prompts_is_never_reported_at_a_prompt() {
    // The degenerate case every row above is separated from, asserted once
    // by name. A PTY matrix is peculiarly exposed to it: a row that
    // spawns something, waits, and asserts a mode passes if detection
    // works — and *also* passes if the child never started and some
    // default matched. This is that default, measured: a child that emits
    // nothing at all reports `Executing` at `heuristic` with every score
    // at zero and an empty last line, which is the answer no row above
    // asserts.
    let server = ClaspServer::new();
    let id = start(&server, program("sleep", &["300"])).await;

    let s = await_settled(&server, &id, "").await;
    assert_classified(&s, "Executing", "heuristic", 0.0);
    assert_eq!(s["prompt"]["pattern_score"], 0.0);
    assert_eq!(s["prompt"]["quiescent_score"], 1.0);
    // Alive, so this is the baseline for a *running* child that says
    // nothing rather than for one that died on the way up — which is a
    // different degenerate case with a different answer (`Exited`).
    assert_eq!(s["state"], "Running", "{s}");
    assert_eq!(raw(&server, &id).await, "", "`sleep` printed something");
    assert_eq!(history(&server, &id).await["status"], "unavailable");
    kill(&server, &id).await;
}

// ---------------------------------------------------------------------
// The §8.7 availability rows, measured live
// ---------------------------------------------------------------------

#[tokio::test]
async fn an_alt_screen_episode_leaves_a_dash_prompt_on_the_heuristic_tier() {
    // §8.7 availability rows 1, 2 and 5 (REQ-PD-011, REQ-PD-015), on one
    // session so that the *only* difference between the first assertion
    // and the last is the session's history. Rows 1 and 2 end on
    // byte-identical prompts; asserted on two separate sessions they
    // degrade into the same test.
    //
    // This is the direction that fails if alternate screen is *added* back
    // to the availability rule. Through spec rev. 27 it was in it, and
    // because availability is sticky one `less` marked the session
    // T2-available for life: the same `$ ` prompt then answered
    // `Executing` / `terminal_mode` / `0.00` — with `pattern_score: 0.60`
    // contradicting it in the same payload — and §8.4 tells the agent that
    // `Executing` at `terminal_mode` is deterministic and to wait. Nothing
    // in the session could ever clear it.
    if !have(Need::Program("dash")) || !have(Need::Program("less")) {
        eprintln!("skipping: dash or less not installed");
        return;
    }
    let server = ClaspServer::new();
    let id = start(&server, program("dash", &[])).await;

    // Row 1 — no mode ever seen.
    let before = await_settled(&server, &id, "$ ").await;
    assert_classified(&before, "AtPrompt", "heuristic", 0.6);
    assert_history(&raw(&server, &id).await, false, false);

    send(&server, &id, "seq 1 500 | less").await;

    // Row 5 — the alternate screen currently on, in a session that has
    // never driven bracketed paste. The `Fullscreen` rung reads
    // alt-screen's *current* value and sits above every availability
    // question, which is why the fix narrowed the executing rung instead
    // of dropping the signal from the classifier.
    let inside = await_mode(&server, &id, "Fullscreen").await;
    assert_classified(&inside, "Fullscreen", "terminal_mode", 0.0);
    assert_history(&raw(&server, &id).await, false, true);

    keypress(&server, &id, "q").await;

    // Row 2 — the same prompt as row 1, with an alt-screen episode behind
    // it. Byte-identical answer required, including the scores.
    let after = await_settled(&server, &id, "$ ").await;
    assert_classified(&after, "AtPrompt", "heuristic", 0.6);
    assert_eq!(
        after["prompt"], before["prompt"],
        "the episode changed the answer"
    );
    let raw = raw(&server, &id).await;
    assert_history(&raw, false, true);
    assert!(
        raw.contains("\x1b[?1049l"),
        "the pager never left the alternate screen, so this is still row 5"
    );
    kill(&server, &id).await;
}

// ---------------------------------------------------------------------
// The disjunctions §8.3 and §8.6 spell out, pinned on both sides
// ---------------------------------------------------------------------

#[tokio::test]
async fn an_osc133_prompt_start_marker_alone_answers_at_prompt_via_t1() {
    // §8.3's T1 prompt rung is "the last marker is A **or** B", and the
    // `B` half is the one every other integrated test lands on: bash emits
    // `A`, the prompt, and `B` in a single write, so a session sitting at
    // an integrated prompt always has `B` last. Narrowing the rule to `B`
    // alone therefore leaves the entire suite green while breaking the
    // state between the two.
    //
    // What it degrades to is the point, and this session reproduces it
    // exactly: ECHO off (readline's normal state at a prompt) with no
    // bracketed paste. With no `A` rung the ladder falls through to the
    // echo rung and answers `AwaitingSecret` at 0.95 — §8.7 finding 1's
    // false positive, telling the agent to prompt a human for a password
    // at an idle prompt.
    //
    // A `bash -c` child, so nothing is injected and the marker below is
    // the only OSC 133 in the session.
    let server = ClaspServer::new();
    let id = start(
        &server,
        bash_c(r"stty -echo; printf '\033]133;A\007clasp$ '; sleep 30"),
    )
    .await;

    let s = await_settled(&server, &id, "clasp$ ").await;
    assert_classified(&s, "AtPrompt", "semantic", 1.0);
    assert_eq!(markers(&raw(&server, &id).await), vec!["A"]);
    kill(&server, &id).await;
}

#[tokio::test]
async fn the_heuristic_decides_at_exactly_the_threshold_on_a_real_ps2_prompt() {
    // §8.6's T3 cut is `confidence >= 0.5`, and real input lands
    // *bit-exactly* on it rather than near it: `dash`'s continuation
    // prompt is the string `> `, the bundled `^>\s*$` row scores it 0.5,
    // a settled session scores 1.0, and 1.0 * 0.5 is 0.5 with no rounding
    // in f32. So `>=` versus `>` is not a boundary nicety — it silently
    // reclassifies every generic continuation prompt on every non-readline
    // program, in the one tier with no corroborating signal.
    if !have(Need::Program("dash")) {
        eprintln!("skipping: dash not installed");
        return;
    }
    let server = ClaspServer::new();
    let id = start(&server, program("dash", &[])).await;
    await_settled(&server, &id, "$ ").await;

    send(&server, &id, "for i in 1 2; do").await;
    let s = await_settled(&server, &id, "> ").await;
    assert_eq!(s["prompt"]["pattern_score"], 0.5);
    assert_eq!(s["prompt"]["quiescent_score"], 1.0);
    assert_classified(&s, "AtPrompt", "heuristic", 0.5);
    kill(&server, &id).await;
}

// ---------------------------------------------------------------------
// OSC 133 shell integration, end to end
// ---------------------------------------------------------------------

/// The marker stream a §8.5 integrated shell emits for a session that runs
/// `echo hello`, `false`, `(exit 42)` — measured, identical for bash 5.3
/// and zsh 5.9.
///
/// Read as five groups: the snippet's own completion (`D;0`) and the first
/// wrapped prompt (`A`, `B`), then `C`, `D;<code>`, `A`, `B` per command.
/// The snippet's command emits no `C` because it ran before `PS0`/`preexec`
/// existed, which is also why it leaves no history entry.
const MEASURED_MARKER_STREAM: [&str; 15] = [
    "D;0", "A", "B", //
    "C", "D;0", "A", "B", //
    "C", "D;1", "A", "B", //
    "C", "D;42", "A", "B",
];

/// Drive the three §8.5 commands and assert both what the shell *emitted*
/// and what CLASP *derived* from it.
///
/// The marker half is the one no other test in the workspace can do. Eight
/// unit tests inspect the snippet as a string, and seven separate mutations
/// of the shipped snippets pass all of them while emitting nothing at
/// runtime: wrapping the bash snippet in `if false && …` disables the
/// feature on every session with the suite fully green, and deleting the
/// `PROMPT_COMMAND` (or zsh `add-zsh-hook precmd`) wiring while leaving the
/// emitter function defined drops every exit code. A string-level test
/// cannot tell a marker that is *emitted* from one that is merely
/// *mentioned*, and it cannot tell an emitter from an emitter nobody
/// calls. The sequence and the `D` payloads are what separate them.
async fn assert_marker_stream_and_exit_codes(server: &ClaspServer, id: &str, shell: &str) {
    assert_eq!(
        status(server, id).await["shell_integration"],
        shell,
        "the session did not report the integration it was asked for"
    );

    // Synchronise on the marker count, not on `AtPrompt`: the session is
    // already `AtPrompt` at the prompt each command is typed at.
    await_markers(server, id, 3).await;
    for (command, total) in [("echo hello", 7), ("false", 11), ("(exit 42)", 15)] {
        send(server, id, command).await;
        await_markers(server, id, total).await;
    }

    let m = markers(&raw(server, id).await);
    assert_eq!(m, MEASURED_MARKER_STREAM, "{shell} marker stream");

    // Waited for, not sampled: `await_markers` above is satisfied by the
    // *buffer*, and the history is applied one step later (see
    // `await_closed_history`).
    let h = await_closed_history(server, id, 3).await;
    assert_eq!(h["status"], "ok", "history unavailable: {h}");
    let entries = h["data"]["entries"].as_array().expect("entries");
    // Exactly three: the line that installed the integration ran before
    // the shell could emit a `C`, so it leaves no entry behind.
    assert_eq!(entries.len(), 3, "unexpected history: {h}");
    let codes: Vec<i64> = entries
        .iter()
        .map(|e| e["exit_code"].as_i64().expect("exit code"))
        .collect();
    assert_eq!(codes, vec![0, 1, 42], "history: {h}");
    let commands: Vec<&str> = entries
        .iter()
        .map(|e| e["command"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(commands, vec!["echo hello", "false", "(exit 42)"]);
    // Every entry closed. `exit_code` alone cannot say so — a `D` with no
    // payload parses to `None` and looks identical to a running command —
    // and `duration_ms` is the agent-visible half of the same fact.
    for e in entries {
        assert!(e["output_end_cursor"].is_u64(), "unfinished entry: {e}");
        assert!(e["duration_ms"].is_u64(), "unfinished entry: {e}");
    }
}

#[tokio::test]
async fn bash_integration_emits_the_measured_marker_stream_and_exact_exit_codes() {
    // REQ-PD-005.
    let server = ClaspServer::new();
    let id = start(&server, bash()).await;
    assert_marker_stream_and_exit_codes(&server, &id, "bash").await;
    kill(&server, &id).await;
}

#[tokio::test]
async fn zsh_integration_emits_the_measured_marker_stream_and_exact_exit_codes() {
    // REQ-PD-005. §8.5 requires the marker stream to be *identical* to
    // bash's, which is why both share one expectation rather than each
    // carrying its own.
    if !have(Need::Program("zsh")) {
        eprintln!("skipping: zsh not installed");
        return;
    }
    let server = ClaspServer::new();
    let id = start(&server, program("zsh", &["-f"])).await;
    assert_marker_stream_and_exit_codes(&server, &id, "zsh").await;
    kill(&server, &id).await;
}

#[tokio::test]
async fn fish_integration_emits_the_measured_marker_stream_and_exact_exit_codes() {
    // **fish is unverified.** The spike measured bash and zsh; fish's
    // snippet was inferred from documented hook equivalence (§24) and has
    // never been executed anywhere — it passes structural Rust tests only,
    // and fish is not installed on the machine this milestone was built
    // on. This test is the measurement, and it has not run.
    //
    // The specific open question is `functions -c fish_prompt
    // __clasp_orig_fish_prompt`: whether copying `fish_prompt` works when
    // it is the built-in default rather than a user-defined function. If
    // it does not, the snippet redefines `fish_prompt` as a wrapper around
    // a function that does not exist and the shell loses its prompt
    // entirely — a failure no string-level test can see.
    //
    // Do not delete this test to make the file honest: the CI matrix
    // (0.0.11) installs fish, and this is the assertion that will run
    // there first.
    //
    // **What it measures is the snippet, and on fish 4 that has to be
    // arranged.** fish 4.0 emits OSC 133 itself, so a stock fish 4 session
    // is already marked before CLASP types anything; measured out of band
    // on fish 4.0.2, the un-guarded snippet then duplicated every marker,
    // was echoed as a command, and lost `D;42`. `shell.rs`'s guard makes
    // the snippet decline there, which would leave this row measuring
    // fish's *own* stream — a different stream (4.0–4.2 mark prompt start
    // but not prompt end) that nobody has measured and that this row's
    // expectation was never written for. `fish_args` turns fish's marking
    // off on fish 4+ so the row keeps measuring the thing it is named
    // after. What a *declined* fish 4 session looks like is asserted
    // nowhere and is an open question in the report.
    if !have(Need::Program("fish")) {
        eprintln!("skipping: fish not installed — the fish snippet remains UNVERIFIED at runtime");
        return;
    }
    let server = ClaspServer::new();
    let id = start(
        &server,
        StartSessionArgs {
            command: "fish".into(),
            args: fish_args(),
            env: term(),
            ..Default::default()
        },
    )
    .await;
    assert_marker_stream_and_exit_codes(&server, &id, "fish").await;
    kill(&server, &id).await;
}

#[tokio::test]
async fn a_prompt_that_already_emits_osc_133_meets_the_injected_snippet() {
    // §8.5 requires the snippet to be "a no-op if markers are already
    // present (the user's terminal may already do this)". The two POSIX
    // snippets implement that as a test on `PS1`'s *text*, and that test
    // sees a marker only when the user pasted the escape into `PS1`
    // literally. Every real emitter calls a function instead: starship,
    // Kitty's and WezTerm's integrations — and fish 4.0, which emits OSC
    // 133 from the shell binary and has no `PS1` at all. Measured out of
    // band on fish 4.0.2: every marker duplicated, the snippet echoed as a
    // command, `D;42` never arriving.
    //
    // This is that collision on a shell this host does have. It is a
    // record of today's behaviour, not of the desired behaviour: when the
    // integration learns to *observe* whether markers already arrive
    // rather than test a string, the injected half moves to one marker per
    // event and this test's expectation changes with it.
    //
    // **Every wait below is the length of what it is about to assert**,
    // and that is not a stylistic preference. Written as a bare `12` next
    // to an eighteen-marker expectation, the positive half returned at the
    // `C`, `C` pair `(exit 42)` opens with and compared a twelve-marker
    // *prefix* to the full stream. On an idle box bash's remaining six
    // markers land in the same PTY read and it passes; under core scarcity
    // the reader drains between the shell's writes and it does not. The
    // nightly flake hunt caught it on iteration 17 of 20 on a 2-vCPU
    // runner; here it was 15 red runs of 30 under `taskset -c 0`, and
    // iteration 9 of 20 under the hunt's own documented `taskset -c 0,1`
    // invocation. A count derived from the expectation cannot drift away
    // from it again.
    let server = ClaspServer::new();

    // The fixture's own first prompt: `D;0` from its `PROMPT_COMMAND`, `A`
    // and `B` from its `PS1`. Both halves start here, and in the declined
    // half it is the whole of the session's history so far.
    const FIRST_PROMPT: usize = 3;

    // The negative first, and it is what makes the positive mean anything:
    // the same shell with integration declined marks each event exactly
    // once. Without it, a fixture that had silently stopped emitting would
    // make the doubling below unreachable rather than visible.
    const ALONE: [&str; 7] = ["D;0", "A", "B", "C", "D;42", "A", "B"];
    let declined = start(
        &server,
        StartSessionArgs {
            shell_integration: Some(false),
            ..already_marking_bash()
        },
    )
    .await;
    await_markers(&server, &declined, FIRST_PROMPT).await;
    send(&server, &declined, "(exit 42)").await;
    let alone = await_markers(&server, &declined, ALONE.len()).await;
    assert_eq!(
        alone, ALONE,
        "the fixture's own prompt is not emitting the stream this test \
         rests on"
    );
    assert_eq!(
        status(&server, &declined).await["shell_integration"],
        Value::Null
    );
    kill(&server, &declined).await;

    // The same shell, integration left on. CLASP types its snippet at a
    // prompt that is already marking, and both emitters run from then on.
    const BOTH: [&str; 18] = [
        "D;0", "A", "B", // the shell's own first prompt
        "C", // the snippet's command, marked by the user's PS0
        "D;0", "D;0", // ... and completed by both PROMPT_COMMANDs
        "A", "A", "B", "B", // ... and prompted by both PS1s
        "C", "C", // `(exit 42)` starts, marked twice
        "D;42", "D;0", // and **the user's exit code is destroyed**
        "A", "A", "B", "B",
    ];
    // The prefix of `BOTH` that the collision itself consists of, before
    // any command is typed into it.
    const COLLIDING_PROMPT: usize = 10;

    let id = start(&server, already_marking_bash()).await;
    // Ten, not `FIRST_PROMPT`. Three is the fixture's prompt *before* the
    // snippet has run, so a wait for three types `(exit 42)` into a
    // session whose collision has not happened yet — the premise this row
    // is named for, assumed rather than observed. Ten is the first prompt
    // drawn by two emitters at once, and it exists only once the snippet
    // is installed. Asserted, not merely counted: the doubling at the
    // prompt is a separate finding from the doubling at the command, and
    // this is the half that a `PS1`-text guard was supposed to prevent.
    let colliding = await_markers(&server, &id, COLLIDING_PROMPT).await;
    assert_eq!(
        colliding.as_slice(),
        &BOTH[..COLLIDING_PROMPT],
        "the snippet did not land on a prompt that was already marking"
    );
    send(&server, &id, "(exit 42)").await;
    let both = await_markers(&server, &id, BOTH.len()).await;
    assert_eq!(
        both, BOTH,
        "a shell that was already marking was marked again"
    );
    // The last pair is the finding, and it is worse than duplication.
    // `PROMPT_COMMAND` becomes `__clasp_d "$?"; <the user's emitter>`, so
    // `$?` has already been overwritten by CLASP's own `printf` — exit 0 —
    // by the time the user's emitter reads it. Every command a
    // starship-style integration reports is therefore reported as
    // successful, in a session where CLASP's own `D;42` sits two bytes
    // away saying otherwise. A terminal consuming the same stream (this is
    // the mechanism terminals use to colour failed commands) reads the
    // last `D` it saw.
    assert_eq!(
        both.iter().filter(|m| *m == "D;42").count(),
        1,
        "the user's own exit code survived, which it must not while the \
         snippet prepends itself to PROMPT_COMMAND: {both:?}"
    );
    assert_eq!(status(&server, &id).await["shell_integration"], "bash");
    kill(&server, &id).await;
}

#[tokio::test]
async fn command_history_cursors_bound_exactly_one_commands_output() {
    // REQ-DM-001. `echo CLASP''_SPAN` echoes as `CLASP''_SPAN` and prints
    // `CLASP_SPAN`, so finding the latter inside the recorded span proves
    // the span covers real command *output* rather than the echoed command
    // line — and the two neighbours prove it stops at both ends.
    let server = ClaspServer::new();
    let id = start(&server, bash()).await;
    await_markers(&server, &id, 3).await;

    for (command, total) in [
        ("echo BEFORE''_SPAN", 7),
        ("echo CLASP''_SPAN", 11),
        ("echo AFTER''_SPAN", 15),
    ] {
        send(&server, &id, command).await;
        await_markers(&server, &id, total).await;
    }

    let h = await_closed_history(&server, &id, 3).await;
    let entries = h["data"]["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 3, "{h}");
    let target = &entries[1];
    assert_eq!(target["command"], "echo CLASP''_SPAN");

    let start_cursor = target["output_start_cursor"].as_u64().expect("start");
    let end_cursor = target["output_end_cursor"].as_u64().expect("finished");
    let r = body(
        &server
            .read_output(Parameters(ReadOutputArgs {
                session: id.clone(),
                since_cursor: Some(start_cursor),
                max_bytes: Some((end_cursor - start_cursor) as usize),
                ..Default::default()
            }))
            .await
            .expect("read_output"),
    );
    let out = r["data"]["output"].as_str().expect("output");
    assert!(
        out.contains("CLASP_SPAN"),
        "span missed its own output: {out:?}"
    );
    assert!(!out.contains("BEFORE_SPAN"), "span ran backwards: {out:?}");
    assert!(!out.contains("AFTER_SPAN"), "span ran forwards: {out:?}");
    // The neighbours pin the span to within one command; this pins it to
    // the byte. The span runs from just *past* the `C` sequence to the
    // start of the `D` one, so neither escape may fall inside it — and
    // both off-by-ones that put one there (`event.start` for the open,
    // `event.end` for the close) leave the three assertions above intact,
    // because the marker sits between the command's own output and its
    // neighbour's.
    assert!(
        !out.contains("\x1b]133;"),
        "an OSC 133 sequence is inside the output span: {out:?}"
    );
    kill(&server, &id).await;
}

#[tokio::test]
async fn osc133_markers_survive_shell_nesting() {
    // REQ-PD-007: the remote-over-ssh case without needing a remote host.
    // The inner shell's markers must reach CLASP through the outer one.
    let server = ClaspServer::new();
    let id = start(&server, bash()).await;
    await_markers(&server, &id, 3).await;

    // Which process is reading input, before nesting. `$$` is the shell's
    // own pid, and only a shell that *ran* the line can print it.
    send(&server, &id, "echo CLASP''_PID_A=$$").await;
    await_markers(&server, &id, 7).await;
    let outer_pid = printed_number(&server, &id, "CLASP_PID_A=").await;

    // A nested interactive bash. The guard variable is deliberately not
    // exported, so the inner shell is integrable in its own right.
    send(&server, &id, "bash --norc --noprofile").await;
    await_markers(&server, &id, 8).await;
    // The inner shell has drawn a prompt: bracketed paste is back on while
    // the outer shell's last marker is `C`, so the ladder answers
    // `AtPrompt` at `terminal_mode` — a state only the *child* can produce,
    // and one the outer shell cannot be in while a command runs.
    await_status(&server, &id, "the inner shell's own prompt", |s| {
        s["interaction_mode"] == "AtPrompt" && s["detection_tier"] == "terminal_mode"
    })
    .await;

    let snippet = clasp_core::detect::Shell::Bash.integration_snippet();
    send(&server, &id, snippet).await;
    // Eleven: the inner shell's snippet emits `D;0`, `A`, `B` and — like
    // the outer shell's — no `C`, because it ran before `PS0` existed.
    await_markers(&server, &id, 11).await;

    // Without this the whole test is vacuous. If the inner shell had
    // failed to start, the snippet would no-op against the outer shell's
    // already-set (non-exported, but same-shell) guard variable, `(exit 7)`
    // would run in the outer shell, and the outer shell would record it
    // with exit code 7 — every assertion below would pass while nothing
    // had been nested. A different pid is the proof that a *second* shell
    // process is the one reading input.
    send(&server, &id, "echo CLASP''_PID_B=$$").await;
    await_markers(&server, &id, 15).await;
    let inner_pid = printed_number(&server, &id, "CLASP_PID_B=").await;
    assert_ne!(
        outer_pid, inner_pid,
        "no nested shell was started; everything below would run in the \
         outer shell and prove nothing"
    );

    // Three entries so far — `echo CLASP_PID_A`, the nested `bash`, `echo
    // CLASP_PID_B` — and the count is read *after* they are all recorded
    // rather than while the last one is still on its way, because it is
    // the `since_index` the read below is scoped by.
    await_closed_history(&server, &id, 3).await;
    let before = status(&server, &id).await["command_count"]
        .as_u64()
        .expect("command_count");
    send(&server, &id, "(exit 7)").await;
    let m = await_markers(&server, &id, 19).await;

    // The inner shell's markers arrive through the outer one, unaltered
    // and in order. Group four is the inner shell's *first* prompt cycle,
    // which is where the documented limitation below comes from.
    assert_eq!(
        m,
        vec![
            "D;0", "A", "B", // outer: the snippet
            "C", "D;0", "A", "B", // outer: echo CLASP_PID_A
            "C", // outer: `bash --norc --noprofile` starts
            "D;0", "A", "B", // INNER: its own snippet, through the outer shell
            "C", "D;0", "A", "B", // inner: echo CLASP_PID_B
            "C", "D;7", "A", "B", // inner: (exit 7)
        ],
        "the nested shell's markers did not reach the detector intact"
    );

    // Four now, the fourth being `(exit 7)`. `await_markers` above proves
    // the shell *emitted* `D;7`; this proves the detector has applied it,
    // which is a later event and the one every assertion below is about.
    await_closed_history(&server, &id, 4).await;
    let h = body(
        &server
            .get_command_history(Parameters(GetCommandHistoryArgs {
                session: id.clone(),
                limit: None,
                since_index: Some(before),
            }))
            .await
            .expect("get_command_history"),
    );
    let inner = h["data"]["entries"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["command"] == "(exit 7)"))
        .cloned()
        .expect("the inner shell's command never reached the history");
    assert_eq!(inner["exit_code"], 7, "inner exit code was lost: {inner}");

    // The accepted defect, asserted so it cannot drift silently (§8.8's
    // pattern for known weaknesses).
    //
    // The marker stream carries no nesting information. The inner shell's
    // *first* `D` — group four above — is emitted by its own prompt hook
    // before it has run anything, and is byte-for-byte indistinguishable
    // from the outer shell's `bash` command completing, so it closes the
    // outer shell's still-open entry. `get_command_history` therefore
    // reports the `bash --norc --noprofile` entry as `exit_code: 0` with
    // an output span ending at the inner shell's first prompt, while that
    // shell is demonstrably still alive (`inner_pid` above). Terminal
    // emulators that consume OSC 133 have the same limitation, and
    // `get_command_history`'s own tool description warns about it.
    let all = history(&server, &id).await;
    let outer = all["data"]["entries"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["command"] == "bash --norc --noprofile"))
        .cloned()
        .expect("the outer shell never recorded launching the inner one");
    assert_eq!(
        outer["exit_code"], 0,
        "known limitation: the nested shell's first D closes the parent's \
         entry. If this now reports null, the limitation was fixed — update \
         the comment rather than the assertion: {outer}"
    );
    assert!(
        outer["output_end_cursor"].is_u64(),
        "the entry was closed early, so its span is closed too: {outer}"
    );

    kill(&server, &id).await;
}

/// The digits printed immediately after `marker`.
///
/// Callers write the marker with an embedded `''` in the command line
/// (`echo CLASP''_PID_A=$$`), so the PTY's echo carries `CLASP''_PID_A=`
/// and only a shell that *executed* the line can produce `CLASP_PID_A=`.
async fn printed_number(server: &ClaspServer, id: &str, marker: &str) -> String {
    let out = raw(server, id).await;
    let rest = out
        .rsplit(marker)
        .next()
        .unwrap_or_else(|| panic!("never saw {marker}: {out:?}"));
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    assert!(!digits.is_empty(), "no pid after {marker}: {out:?}");
    digits
}

// ---------------------------------------------------------------------
// Documented limitations
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_program_that_fakes_bracketed_paste_fools_tier_2() {
    // §8.8 / REQ-PD-010, asserted so the limitation cannot change
    // silently. `printf` is not a prompt by any measure — the pattern
    // score below is 0.0, i.e. tier 3 correctly sees nothing prompt-shaped
    // at all — yet the mode it *prints* is believed at 0.95. CLASP does
    // not defend against a hostile child; that is the agent permission
    // system's job (§9.1).
    let server = ClaspServer::new();
    let id = start(&server, bash_c(r"printf '\033[?2004h'; sleep 30")).await;

    let s = await_mode(&server, &id, "AtPrompt").await;
    assert_classified(&s, "AtPrompt", "terminal_mode", 0.95);
    assert_eq!(
        s["prompt"]["pattern_score"], 0.0,
        "the corroborating signal disagrees, and T2 answers anyway: {s}"
    );
    assert_eq!(s["prompt"]["last_line"], "");
    kill(&server, &id).await;
}
