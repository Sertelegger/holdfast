//! Milestone 0.0.4 — Tier-B terminal state against real PTYs (spec §4.5,
//! §5.2 `get_screen_state` and `resize`, §11.4 adaptive-tracking and
//! screen-diffing scenarios).

use clasp_core::mcp::tools::{GetScreenStateArgs, ReadOutputArgs, ResizeArgs, StartSessionArgs};
use clasp_core::mcp::ClaspServer;
use clasp_core::pty::{InProcessPty, LineDiscipline, PtyBackend, PtySpawnConfig, Signal};
use clasp_core::screen::{ScreenConfig, NO_SIGNAL_GRACE};
use clasp_core::session::{new_session_id, Session, SessionConfig};
use clasp_core::{ClaspError, Result};
use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};

const ROWS: u16 = 24;
const COLS: u16 = 80;

/// The geometry every `resize` test moves to. Deliberately **unequal**:
/// transposing rows and cols is invisible on a square terminal, and both
/// are `u16`.
const WIDE_COLS: u16 = 132;
const WIDE_ROWS: u16 = 43;

fn body(r: &rmcp::model::CallToolResult) -> Value {
    r.structured_content.clone().expect("structured content")
}

/// Start `bash --norc --noprofile` at a known 24x80 geometry.
async fn start_bash(server: &ClaspServer, screen_tracking: Option<&str>) -> String {
    let r = server
        // `..Default::default()` throughout this file, never an
        // exhaustive literal: `StartSessionArgs` carries eight fields
        // after 0.0.2 plus the one Task 7 adds, and later milestones add
        // more. Naming them all is `error[E0063]` today and a re-break
        // every milestone after.
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: vec!["--norc".into(), "--noprofile".into()],
            cols: Some(COLS),
            rows: Some(ROWS),
            screen_tracking: screen_tracking.map(String::from),
            ..Default::default()
        }))
        .await
        .expect("start_session");
    let b = body(&r);
    assert_eq!(b["status"], "ok", "start_session failed: {b}");
    b["data"]["session_id"].as_str().unwrap().to_string()
}

/// Poll `read_output` until `needle` appears, returning the last response.
///
/// Callers must pick a needle the *echoed command line* cannot contain: a
/// PTY echoes everything written to it, so waiting for `MARKER` right
/// after typing `echo MARKER` matches the echo and proves nothing about
/// whether the child ran. Every marker below embeds `''`, which bash
/// removes, so the echoed form and the executed output differ.
///
/// **`ansi: "raw"` is load-bearing and is not a preference.** Several
/// markers in this file are OSC window-title sequences
/// (`\033]0;PAINT_DONE\007`), chosen precisely because they paint no
/// cells — a marker that painted would contaminate the grid assertions
/// that are the point of the suite. But `AnsiMode::default()` is `Strip`
/// (0.0.3, `output/ansi.rs`), and the stripper's `Osc` state consumes
/// everything from `\x1b]` to BEL or ST, so on a default read the marker
/// is removed **in full** — payload included — and `acc` can never
/// contain it. The two properties are the same property: what makes a
/// marker invisible to the screen is what makes it invisible to a
/// stripped read.
///
/// `redact` stays at its default: no marker is secret-shaped, and leaving
/// it on keeps this helper reading the same bytes an agent would.
async fn read_until(server: &ClaspServer, session: &str, needle: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut cursor = 0u64;
    let mut acc = String::new();
    while Instant::now() < deadline {
        let r = server
            .read_output(Parameters(ReadOutputArgs {
                session: session.into(),
                since_cursor: Some(cursor),
                ansi: Some("raw".into()),
                ..Default::default()
            }))
            .await
            .expect("read_output");
        let b = body(&r);
        acc.push_str(b["data"]["output"].as_str().unwrap_or(""));
        cursor = b["data"]["cursor"].as_u64().unwrap_or(cursor);
        if acc.contains(needle) {
            return b;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never saw {needle:?}; buffer was:\n{acc}");
}

/// A `get_screen_state` call with §5.2's `redact` left absent, which is
/// what every test below wants: the default is what ships.
async fn screen_state(server: &ClaspServer, session: &str, diff_from: Option<u64>) -> Value {
    let r = server
        .get_screen_state(Parameters(GetScreenStateArgs {
            session: session.into(),
            diff_from,
            ..Default::default()
        }))
        .await
        .expect("get_screen_state");
    body(&r)
}

/// The same call with `redact: false` — §5.2's audited opt-out.
///
/// **This is the one literal in this file that names every field**, and
/// deliberately: `..Default::default()` beside a complete field list is
/// `clippy::needless_update`, and CI runs `-D warnings`. Keeping the
/// exhaustive form in a single helper means a field added in a later
/// milestone produces one compile error, here, instead of a lint failure
/// scattered across the callers.
async fn screen_state_raw(server: &ClaspServer, session: &str, diff_from: Option<u64>) -> Value {
    let r = server
        .get_screen_state(Parameters(GetScreenStateArgs {
            session: session.into(),
            diff_from,
            redact: Some(false),
        }))
        .await
        .expect("get_screen_state");
    body(&r)
}

async fn resize(server: &ClaspServer, session: &str, cols: u16, rows: u16) -> Value {
    let r = server
        .resize(Parameters(ResizeArgs {
            session: session.into(),
            cols,
            rows,
        }))
        .await
        .expect("resize must not be a protocol error");
    body(&r)
}

fn lines_of(data: &Value) -> Vec<String> {
    data["data"]["lines"]
        .as_array()
        .unwrap_or_else(|| panic!("expected a full grid, got {}", data["data"]))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

fn kill_all(server: &ClaspServer) {
    for s in server.registry.all() {
        let _ = s.signal(Signal::Kill);
    }
}

/// Repaint a base grid and apply a diff on top — what an agent holding
/// `lines` and `cursor` from an earlier call would do.
///
/// **The cursor is part of the base state, not decoration.**
/// `contents_diff`'s contract is that rendering the base and then the
/// diff equals rendering the new screen, and a diff is free to position
/// *relatively* from wherever the base left the cursor. Repainting the
/// lines alone leaves the cursor at the bottom row, so a relatively
/// positioned diff lands in the wrong place and the replay silently
/// reconstructs a different screen. Restoring `cursor` closes that.
fn replay(base: &Value, diff: &str) -> Vec<String> {
    let base_lines = lines_of(base);
    let (row, col) = (
        base["data"]["cursor"]["row"].as_u64().expect("cursor.row"),
        base["data"]["cursor"]["col"].as_u64().expect("cursor.col"),
    );
    let mut p = vt100::Parser::new(ROWS, COLS, 0);
    p.process(b"\x1b[H\x1b[2J");
    for (i, line) in base_lines.iter().enumerate() {
        p.process(format!("\x1b[{};1H", i + 1).as_bytes());
        p.process(line.as_bytes());
    }
    p.process(format!("\x1b[{};{}H", row + 1, col + 1).as_bytes());
    p.process(diff.as_bytes());
    p.screen().rows(0, COLS).collect()
}

// ------------------------------------------------------------ `resize`

/// A backend whose `resize` **fails**, and which is otherwise inert.
///
/// It exists because nothing else in the tree can produce a failed
/// resize, and without one the "reports the size it reached" property is
/// unfalsifiable: on a resize that succeeds, the size reached and the size
/// requested are the same number, so an implementation echoing its own
/// argument passes every assertion a real PTY can support.
struct ResizeRefusingPty;

impl PtyBackend for ResizeRefusingPty {
    fn write(&self, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn read(&self, _buf: &mut [u8]) -> Result<usize> {
        // Never any output. The reader thread treats `Ok(0)` from a live
        // backend as "nothing yet" and idles, which is what a quiet PTY
        // looks like.
        std::thread::sleep(Duration::from_millis(20));
        Ok(0)
    }

    fn signal(&self, _sig: Signal) -> Result<()> {
        Ok(())
    }

    fn resize(&self, _cols: u16, _rows: u16) -> Result<()> {
        Err(ClaspError::Pty("TIOCSWINSZ refused".into()))
    }

    fn is_alive(&self) -> bool {
        true
    }

    fn line_discipline(&self) -> LineDiscipline {
        LineDiscipline::UNKNOWN
    }

    fn exit_code(&self) -> Option<i32> {
        None
    }

    fn pid(&self) -> Option<u32> {
        Some(1)
    }
}

#[tokio::test]
async fn resize_is_visible_to_the_child() {
    // REQ-T-009: the tool's whole point is `SIGWINCH` reaching the child,
    // and `stty size` is the child's own answer rather than CLASP's.
    let server = ClaspServer::new();
    let id = start_bash(&server, None).await;
    read_until(&server, &id, "$").await;

    let r = resize(&server, &id, WIDE_COLS, WIDE_ROWS).await;
    assert_eq!(r["status"], "ok", "{r}");

    let session = server.registry.get(&id).unwrap();
    session.write_input(b"stty size\n").unwrap();
    // `stty size` prints "<rows> <cols>", so the transposition this
    // geometry exists to catch shows up as `132 43` here.
    read_until(&server, &id, "43 132").await;

    kill_all(&server);
}

#[tokio::test]
async fn resize_reflows_the_tracked_grid() {
    // The half that belongs to *this* milestone rather than to the PTY
    // seam: `ScreenTracker`'s `vt100::Parser` is built from `ScreenConfig`
    // and is never otherwise told the size changed, so a `resize` that
    // stops at the backend leaves `get_screen_state` rendering a 132x43
    // session through an 80x24 grid — silently, with no error anywhere and
    // no test able to see it.
    let server = ClaspServer::new();
    let id = start_bash(&server, Some("on")).await;
    read_until(&server, &id, "$").await;
    let session = server.registry.get(&id).unwrap();

    // The negative half first: at 80 columns a 99-character line wraps,
    // so the *same* payment below proves the reflow rather than proving
    // that the line was short enough either way.
    let filler = "x".repeat(94);
    session
        .write_input(format!("printf '\\033[H\\033[2JNARROW''_{filler}'\n").as_bytes())
        .unwrap();
    read_until(&server, &id, &format!("NARROW_{filler}")).await;
    let narrow = screen_state(&server, &id, None).await;
    assert_eq!(narrow["data"]["cols"], COLS);
    let narrow_lines = lines_of(&narrow);
    assert_eq!(
        narrow_lines[0].len(),
        usize::from(COLS),
        "a 99-character line must fill row 0 and wrap: {:?}",
        narrow_lines[0]
    );
    assert!(
        !narrow_lines[1].is_empty(),
        "the wrap must land on row 1: {:?}",
        narrow_lines[1]
    );

    let r = resize(&server, &id, WIDE_COLS, WIDE_ROWS).await;
    assert_eq!(r["data"]["cols"], WIDE_COLS, "{r}");

    session
        .write_input(format!("printf '\\033[H\\033[2JWIDE''_{filler}'\n").as_bytes())
        .unwrap();
    let painted = format!("WIDE_{filler}");
    read_until(&server, &id, &painted).await;

    let state = screen_state(&server, &id, None).await;
    assert_eq!(state["data"]["cols"], WIDE_COLS, "{}", state["data"]);
    assert_eq!(state["data"]["rows"], WIDE_ROWS, "{}", state["data"]);
    let lines = lines_of(&state);
    assert_eq!(
        lines.len(),
        usize::from(WIDE_ROWS),
        "the grid still has the old row count"
    );
    assert!(
        lines[0].starts_with(&painted),
        "the line was clipped at the old width: {:?}",
        lines[0]
    );

    kill_all(&server);
}

#[tokio::test]
async fn resize_reports_the_size_it_reached_not_the_size_requested() {
    let server = ClaspServer::new();
    let id = start_bash(&server, None).await;
    read_until(&server, &id, "$").await;
    let session = server.registry.get(&id).unwrap();
    assert_eq!(
        session.size(),
        (COLS, ROWS),
        "the session must know the geometry it was spawned at, or the \
         comparison below is between two copies of the request"
    );

    let r = resize(&server, &id, WIDE_COLS, WIDE_ROWS).await;
    assert_eq!(
        (
            r["data"]["cols"].as_u64().unwrap() as u16,
            r["data"]["rows"].as_u64().unwrap() as u16
        ),
        session.size(),
        "the response and the session disagree about the size"
    );
    assert_eq!(session.size(), (WIDE_COLS, WIDE_ROWS));
    kill_all(&server);

    // The separator, and it needs a backend that refuses: when the resize
    // succeeds, the size reached and the size requested are the same
    // number, so everything above passes against a tool that echoes its
    // own argument. Here they differ.
    let refusing = Session::new(
        new_session_id(),
        None,
        "refuses-resize".into(),
        vec![],
        Arc::new(ResizeRefusingPty) as Arc<dyn PtyBackend>,
        SessionConfig::default(),
    );
    let refusing_id = refusing.id.clone();
    server.registry.insert(refusing).expect("registry insert");
    let before = server.registry.get(&refusing_id).unwrap().size();

    let err = server
        .resize(Parameters(ResizeArgs {
            session: refusing_id.clone(),
            cols: WIDE_COLS,
            rows: WIDE_ROWS,
        }))
        .await
        .expect_err("a resize the terminal refused is not an `ok` response");
    assert!(
        !format!("{err:?}").contains(&WIDE_COLS.to_string()),
        "the refused request came back as if it had happened: {err:?}"
    );
    assert_eq!(
        server.registry.get(&refusing_id).unwrap().size(),
        before,
        "a failed resize must leave the recorded size alone"
    );

    kill_all(&server);
}

#[tokio::test]
async fn a_resize_to_the_current_size_changes_nothing_observable() {
    // The pairing that earns §5.3's `idempotentHint: true`. A real resize
    // must drop the retained revisions — a `vt100::Screen` captured at
    // 80 columns cannot be diffed against one at 132 — but a resize to the
    // size already in force must not, or every no-op costs the agent a
    // full grid.
    let server = ClaspServer::new();
    let id = start_bash(&server, Some("on")).await;
    read_until(&server, &id, "$").await;

    let first = screen_state(&server, &id, None).await;
    let rev0 = first["data"]["screen_revision"].as_u64().unwrap();

    // A real change: the base is now the wrong shape, so the next
    // `diff_from` degrades to a full grid.
    resize(&server, &id, WIDE_COLS, WIDE_ROWS).await;
    let after = screen_state(&server, &id, Some(rev0)).await;
    assert!(
        after["data"]["lines"].is_array(),
        "a revision captured at the old geometry must not be diffed \
         against: {}",
        after["data"]
    );
    let rev1 = after["data"]["screen_revision"].as_u64().unwrap();

    // The no-op, twice over: the same values come back, and the revision
    // the agent is holding still resolves.
    let again = resize(&server, &id, WIDE_COLS, WIDE_ROWS).await;
    assert_eq!(again["status"], "ok", "{again}");
    assert_eq!(again["data"]["cols"], WIDE_COLS);
    assert_eq!(again["data"]["rows"], WIDE_ROWS);

    let delta = screen_state(&server, &id, Some(rev1)).await;
    assert!(
        delta["data"]["diff"].is_string(),
        "the no-op resize dropped the retained revisions: {}",
        delta["data"]
    );
    assert_eq!(delta["data"]["base_revision"], rev1);
    assert_eq!(
        delta["data"]["screen_revision"].as_u64().unwrap(),
        rev1 + 1,
        "a resize must not consume a screen revision of its own"
    );

    kill_all(&server);
}

// ------------------------------- §11.4 "Adaptive Tier-B tracking"

#[tokio::test]
async fn tier_b_stays_off_for_a_plain_line_oriented_session() {
    // The default for an ordinary shell. Turning this on by accident is
    // the regression §4.2a's 86 MB/s measurement exists to prevent.
    let server = ClaspServer::new();
    let id = start_bash(&server, None).await;

    let session = server.registry.get(&id).unwrap();
    session.write_input(b"echo TIER''_B_OFF\n").unwrap();
    let last = read_until(&server, &id, "TIER_B_OFF").await;

    assert_eq!(
        last["data"]["screen_tracking"], "off",
        "read_output reported Tier B running on a line-oriented session"
    );
    assert_eq!(
        session.vt100_bytes_parsed(),
        0,
        "the VT100 parser ran without any §4.5 trigger"
    );
    kill_all(&server);
}

#[tokio::test]
async fn get_screen_state_enables_tier_b_and_seeds_the_grid_from_the_ring_buffer() {
    let server = ClaspServer::new();
    let id = start_bash(&server, None).await;
    let session = server.registry.get(&id).unwrap();

    // `GRID''_ONE` echoes with the quotes and prints without them, and the
    // \033[2J erases the echoed line before the text lands, so nothing but
    // a real screen render can satisfy the assertion below.
    session
        .write_input(b"printf '\\033[H\\033[2JGRID''_ONE\\r\\nGRID''_TWO\\r\\n'\n")
        .unwrap();
    read_until(&server, &id, "GRID_TWO").await;

    assert_eq!(
        session.vt100_bytes_parsed(),
        0,
        "Tier B enabled before anyone asked for a screen"
    );
    assert_eq!(session.screen_tracking(), "off");

    let state = screen_state(&server, &id, None).await;
    assert_eq!(state["status"], "ok");
    assert_eq!(state["data"]["screen_tracking"], "on");
    assert_eq!(state["data"]["rows"], ROWS);
    assert_eq!(state["data"]["cols"], COLS);

    let lines = lines_of(&state);
    assert_eq!(lines.len(), usize::from(ROWS));
    assert_eq!(
        lines[0].trim_end(),
        "GRID_ONE",
        "the grid was not reconstructed from the ring buffer: {lines:?}"
    );
    assert_eq!(lines[1].trim_end(), "GRID_TWO");
    assert!(
        session.vt100_bytes_parsed() > 0,
        "a seed should have been parsed"
    );
    kill_all(&server);
}

#[tokio::test]
async fn entering_the_alternate_screen_enables_tier_b_with_no_agent_call() {
    let server = ClaspServer::new();
    let id = start_bash(&server, None).await;
    let session = server.registry.get(&id).unwrap();

    session.write_input(b"echo BEFORE''_TUI\n").unwrap();
    read_until(&server, &id, "BEFORE_TUI").await;
    assert_eq!(session.screen_tracking(), "off");

    // A TUI's entry sequence: alternate screen, home, clear, paint.
    session
        .write_input(b"printf '\\033[?1049h\\033[H\\033[2JPAGER''_VIEW\\r\\n'\n")
        .unwrap();
    read_until(&server, &id, "PAGER_VIEW").await;

    assert_eq!(
        session.screen_tracking(),
        "on",
        "alt-screen entry did not enable Tier B"
    );
    let state = screen_state(&server, &id, None).await;
    assert_eq!(state["data"]["alt_screen"], true);
    assert_eq!(lines_of(&state)[0].trim_end(), "PAGER_VIEW");

    kill_all(&server);
}

#[tokio::test]
async fn a_session_with_no_deterministic_signal_enables_tier_b_after_the_grace_window() {
    // `cat` emits neither bracketed paste nor OSC 133, so §8.6's cursor
    // sub-signal is the only prompt evidence available and §4.5 turns
    // Tier B on for it. Driven through `Session` rather than the tool so
    // the trigger under test is the timer, not a screen-state request.
    let cfg = PtySpawnConfig::new("cat");
    let backend = InProcessPty::spawn(&cfg).expect("spawn cat");
    let session = Session::new(
        new_session_id(),
        None,
        "cat".into(),
        vec![],
        Arc::new(backend) as Arc<dyn PtyBackend>,
        SessionConfig::with_buffer_capacity(64 * 1024),
    );
    session.set_screen_config(ScreenConfig {
        rows: ROWS,
        cols: COLS,
        ..ScreenConfig::default()
    });

    session.write_input(b"ready\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.buffer_head() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(session.buffer_head() > 0, "cat produced nothing");

    assert_eq!(
        session.screen_tracking(),
        "off",
        "the grace window has not elapsed yet"
    );
    assert!(session.cursor_signal().is_none());

    std::thread::sleep(NO_SIGNAL_GRACE + Duration::from_millis(300));

    // The session is silent, so nothing else will advance the policy —
    // the observer poll has to.
    let signal = session
        .cursor_signal()
        .expect("Tier B should be on once the grace window elapses");
    assert_eq!(session.screen_tracking(), "on");
    assert!(signal.row < ROWS && signal.col < COLS);

    let _ = session.signal(Signal::Kill);
}

// --------------------------------------- §11.4 "Screen diffing"

/// A full-screen program: paints 24 rows, then waits on stdin, then
/// changes exactly one cell, then waits again.
///
/// Run through `bash -c`, so the script itself is argv and is never typed
/// into the PTY — there is no command-line echo to contaminate the grid.
/// `stty -echo` then suppresses the echo of the newlines the test writes
/// to step the script; readline is not involved, so it stays off.
/// Progress markers are OSC window-title sequences: they paint no cells,
/// and `read_until` sees them because it reads with `ansi: "raw"` — a
/// stripped read (0.0.3's default) removes them whole, which is the same
/// property read from the other side.
const TUI_SCRIPT: &str = "\
stty -echo
printf '\\033[?1049h\\033[H\\033[2J'
pad=............................................................
for r in $(seq 1 24); do printf '\\033[%d;1Hrow %02d %s' \"$r\" \"$r\" \"$pad\"; done
printf '\\033]0;PAINT_DONE\\007'
read -r _
printf '\\033[12;70HX'
printf '\\033]0;KEY_DONE\\007'
read -r _
";

#[tokio::test]
async fn a_single_cell_change_diffs_small_and_replays_to_the_new_screen() {
    let server = ClaspServer::new();
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: vec![
                "--norc".into(),
                "--noprofile".into(),
                "-c".into(),
                TUI_SCRIPT.into(),
            ],
            cols: Some(COLS),
            rows: Some(ROWS),
            ..Default::default()
        }))
        .await
        .expect("start_session");
    let id = body(&r)["data"]["session_id"].as_str().unwrap().to_string();
    let session = server.registry.get(&id).unwrap();

    read_until(&server, &id, "PAINT_DONE").await;
    let first = screen_state(&server, &id, None).await;
    let base_lines = lines_of(&first);
    let base_revision = first["data"]["screen_revision"].as_u64().unwrap();
    let full_grid_bytes: usize = base_lines.iter().map(|l| l.len() + 1).sum();
    assert!(
        base_lines[0].starts_with("row 01"),
        "the TUI never painted: {base_lines:?}"
    );

    // Step the script: one cell changes and nothing else.
    session.write_input(b"\n").unwrap();
    read_until(&server, &id, "KEY_DONE").await;

    let delta = screen_state(&server, &id, Some(base_revision)).await;
    let diff = delta["data"]["diff"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a diff, got {}", delta["data"]))
        .to_string();
    assert_eq!(delta["data"]["base_revision"], base_revision);

    assert!(
        diff.len() * 10 < full_grid_bytes,
        "diff is {} bytes against a {} byte grid — not an order of magnitude smaller",
        diff.len(),
        full_grid_bytes
    );

    // The size assertion above is also satisfied by an empty diff — and by
    // a diff that was never computed at all — which is why it is never the
    // only assertion. The screen must have changed, and replaying the diff
    // over the base grid must reproduce the change exactly.
    let after = screen_state(&server, &id, None).await;
    let new_lines = lines_of(&after);
    assert_ne!(
        new_lines, base_lines,
        "the screen did not change, so this test would pass on an empty diff"
    );
    assert!(new_lines[11].ends_with('X'), "row 12: {:?}", new_lines[11]);
    assert_eq!(
        replay(&first, &diff),
        new_lines,
        "applying the diff to the base grid did not reproduce the new screen"
    );

    kill_all(&server);
}

/// Paints a clean screen, waits on stdin, then paints a line carrying a
/// GitHub-token-shaped secret, and waits again.
///
/// Run through `bash -c` for the same reason `TUI_SCRIPT` is: the script
/// is argv, so nothing is typed into the PTY and there is no command-line
/// echo to put an *unredacted* second copy of the secret on the grid —
/// which would fail the absence assertions for a reason that has nothing
/// to do with redaction. The progress markers are OSC window titles: they
/// paint no cells, `read_until` sees them because it reads with
/// `ansi: "raw"`, and they let the test wait without ever waiting on the
/// secret itself (which after 0.0.3 `read_output` will have redacted
/// away). The `raw` read does not weaken that: `redact` is left at its
/// default, so the secret is redacted on this path too.
const SECRET_SCRIPT: &str = "\
stty -echo
printf '\\033[?1049h\\033[H\\033[2J'
printf '\\033[1;1Hharmless header line'
printf '\\033]0;CLEAN_DONE\\007'
read -r _
printf '\\033[2;1Hexport GH_TOKEN=ghp_0123456789abcdefghijABCDEFGHIJ012345'
printf '\\033]0;SECRET_DONE\\007'
read -r _
";

/// Spec §5.2: `get_screen_state` redacts by default, end to end through
/// the MCP tool. The unit test in `screen::tests` covers the same property
/// at the tracker; this one proves it survives the whole path an agent
/// actually uses.
#[tokio::test]
async fn a_secret_on_screen_is_redacted_in_both_the_grid_and_the_diff() {
    const SECRET: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
    let server = ClaspServer::new();
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: vec![
                "--norc".into(),
                "--noprofile".into(),
                "-c".into(),
                SECRET_SCRIPT.into(),
            ],
            cols: Some(COLS),
            rows: Some(ROWS),
            ..Default::default()
        }))
        .await
        .expect("start_session");
    let id = body(&r)["data"]["session_id"].as_str().unwrap().to_string();
    let session = server.registry.get(&id).unwrap();

    read_until(&server, &id, "CLEAN_DONE").await;
    let first = screen_state(&server, &id, None).await;
    let base_lines = lines_of(&first);
    let base_revision = first["data"]["screen_revision"].as_u64().unwrap();
    assert_eq!(base_lines[0].trim_end(), "harmless header line");

    // Painted *after* the base revision, so the secret is necessarily
    // inside the changed region the diff has to describe.
    session.write_input(b"\n").unwrap();
    read_until(&server, &id, "SECRET_DONE").await;

    let delta = screen_state(&server, &id, Some(base_revision)).await;
    let diff = delta["data"]["diff"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a diff, got {}", delta["data"]))
        .to_string();
    assert!(
        !diff.contains("ghp_"),
        "the secret reached the diff payload: {diff:?}"
    );
    assert!(
        diff.contains("[REDACTED:github]"),
        "the diff carries no redaction marker: {diff:?}"
    );

    let after = screen_state(&server, &id, None).await;
    let new_lines = lines_of(&after);
    assert!(
        !new_lines.iter().any(|l| l.contains("ghp_")),
        "the secret reached the full grid: {new_lines:?}"
    );
    // Absence is only half of it: an implementation returning empty lines
    // would satisfy every assertion above.
    assert_eq!(
        new_lines[0].trim_end(),
        "harmless header line",
        "redaction ate the untouched part of the screen"
    );
    assert_eq!(new_lines[1].trim_end(), "export GH_TOKEN=[REDACTED:github]");
    assert_ne!(new_lines, base_lines);
    assert_eq!(
        replay(&first, &diff),
        new_lines,
        "replaying the redacted diff did not reproduce the redacted screen"
    );

    // The raw bytes really did contain the secret, so the redaction above
    // was a redaction and not an accident of the script never running.
    let raw = session.read_tail_bytes(64 * 1024);
    assert!(
        String::from_utf8_lossy(&raw.bytes).contains(SECRET),
        "the PTY never carried the secret, so this test proves nothing"
    );

    kill_all(&server);
}

/// REQ-O-011's third obligation: `redact: false` is the **audited**
/// opt-out. §9.4's `redaction_disabled` row names `get_screen_state` as
/// one of the three values of `tool`, and 0.0.4 is the milestone that
/// supplies that call site.
///
/// This is also the negative for the test above. `redact: true` returning
/// `[REDACTED:github]` would be satisfied by a tool that returned that
/// marker unconditionally — or by a screen the secret never reached. So
/// the same script, the same grid, and `redact: false` must return the
/// **actual token**, or neither test is measuring redaction.
#[tokio::test]
async fn disabling_redaction_on_a_screen_read_returns_the_secret_and_is_audited() {
    const SECRET: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    // `ClaspServer::new()` builds a *disabled* audit log so tests never
    // write into the invoking user's home (0.0.3). This is the one test
    // here that needs a real one.
    let server = ClaspServer::with_audit_path(Some(audit_path.clone()));

    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: vec![
                "--norc".into(),
                "--noprofile".into(),
                "-c".into(),
                SECRET_SCRIPT.into(),
            ],
            cols: Some(COLS),
            rows: Some(ROWS),
            ..Default::default()
        }))
        .await
        .expect("start_session");
    let id = body(&r)["data"]["session_id"].as_str().unwrap().to_string();
    let session = server.registry.get(&id).unwrap();

    read_until(&server, &id, "CLEAN_DONE").await;
    session.write_input(b"\n").unwrap();
    read_until(&server, &id, "SECRET_DONE").await;

    // The default first, so the pair is measured against one screen.
    let redacted = screen_state(&server, &id, None).await;
    assert_eq!(
        lines_of(&redacted)[1].trim_end(),
        "export GH_TOKEN=[REDACTED:github]"
    );

    let raw = screen_state_raw(&server, &id, None).await;
    assert_eq!(
        lines_of(&raw)[1].trim_end(),
        format!("export GH_TOKEN={SECRET}"),
        "the spec'd escape hatch must actually return the secret"
    );

    let log = std::fs::read_to_string(&audit_path).unwrap();
    let entry: Value = serde_json::from_str(
        log.lines()
            .find(|l| l.contains("redaction_disabled"))
            .expect("no redaction_disabled entry was written"),
    )
    .unwrap();
    assert_eq!(entry["kind"], "redaction_disabled");
    // The literal at the call site, not an echo of a request argument —
    // §9.4 and REQ-SEC-018 forbid any path from request params to it.
    assert_eq!(entry["tool"], "get_screen_state");
    // No control connection exists before 0.0.5, so the caller really is
    // in-process; 0.0.5 derives this from the uid-checked handshake.
    assert_eq!(entry["client_kind"], "in_process");
    assert_eq!(entry["session_id"], id.as_str());
    // §9.4: audit lines carry no unredacted secrets *even when the read
    // they describe had redaction turned off*. `AuditLog::record` redacts
    // the payload, so this holds without this call site doing anything.
    assert!(
        !log.contains(SECRET),
        "the audit log carries the secret it is recording the disclosure of"
    );

    // And the negative for the audit half: the *default* read above must
    // not have written a record, or the log says nothing about anything.
    assert_eq!(
        log.lines()
            .filter(|l| l.contains("redaction_disabled"))
            .count(),
        1,
        "exactly one redaction_disabled entry: the redact: false call"
    );

    kill_all(&server);
}

/// REQ-O-011: a `diff_from` naming a revision rendered under a different
/// `redact` value returns a **full grid**, not a diff — the two
/// renderings differ by the markers themselves, so a diff between them
/// would describe the un-redaction. The unit twin is
/// `screen::tests::a_diff_across_redaction_modes_degrades_to_a_full_grid`;
/// this one proves it survives the tool boundary, where the `redact`
/// argument actually arrives.
#[tokio::test]
async fn a_diff_from_across_redaction_modes_returns_a_full_grid() {
    let server = ClaspServer::new();
    let id = start_bash(&server, None).await;

    let first = screen_state(&server, &id, None).await;
    let rev = first["data"]["screen_revision"].as_u64().unwrap();

    // Same revision, opposite mode: full grid.
    let across = screen_state_raw(&server, &id, Some(rev)).await;
    assert!(
        across["data"]["lines"].is_array(),
        "expected a full grid across redaction modes, got {}",
        across["data"]
    );
    assert!(across["data"]["diff"].is_null());

    // The negative: same revision, same mode, and it diffs. Without this
    // the test above passes against a tool that never diffs at all.
    let same = screen_state(&server, &id, Some(rev)).await;
    assert!(
        same["data"]["diff"].is_string(),
        "a same-mode diff_from must still diff, got {}",
        same["data"]
    );

    kill_all(&server);
}

#[tokio::test]
async fn screen_tracking_off_still_answers_but_never_parses_on_the_write_path() {
    let server = ClaspServer::new();
    let id = start_bash(&server, Some("off")).await;
    let session = server.registry.get(&id).unwrap();

    session
        .write_input(b"printf '\\033[?1049h\\033[H\\033[2JFORCED''_OFF\\r\\n'\n")
        .unwrap();
    read_until(&server, &id, "FORCED_OFF").await;
    assert_eq!(
        session.vt100_bytes_parsed(),
        0,
        "`off` parsed on the write path despite the alt-screen trigger"
    );

    // Spec §5.2: the call succeeds either way.
    let state = screen_state(&server, &id, None).await;
    assert_eq!(state["status"], "ok");
    assert_eq!(state["data"]["screen_tracking"], "off");
    assert_eq!(lines_of(&state)[0].trim_end(), "FORCED_OFF");

    kill_all(&server);
}

#[tokio::test]
async fn an_unknown_screen_tracking_mode_is_a_protocol_error() {
    let server = ClaspServer::new();
    let r = server
        .start_session(Parameters(StartSessionArgs {
            command: "bash".into(),
            args: vec!["--norc".into(), "--noprofile".into()],
            screen_tracking: Some("sometimes".into()),
            ..Default::default()
        }))
        .await;
    assert!(
        r.is_err(),
        "an unrecognised mode must not be silently defaulted"
    );
    assert!(
        server.registry.all().is_empty(),
        "nothing should have been spawned"
    );
}

#[tokio::test]
async fn get_screen_state_on_a_missing_session_is_an_error_envelope() {
    let server = ClaspServer::new();
    let r = server
        .get_screen_state(Parameters(GetScreenStateArgs {
            session: "sess_nope".into(),
            ..Default::default()
        }))
        .await
        .expect("must be an envelope, not a protocol error");
    assert_eq!(body(&r)["status"], "session_not_found");
    assert_eq!(r.is_error, Some(true));
}

#[tokio::test]
async fn an_exited_session_still_renders_its_final_screen() {
    let server = ClaspServer::new();
    let id = start_bash(&server, None).await;
    let session = server.registry.get(&id).unwrap();

    session
        .write_input(b"printf '\\033[H\\033[2JLAST''_SCREEN\\r\\n'; exit 3\n")
        .unwrap();
    read_until(&server, &id, "LAST_SCREEN").await;

    let deadline = Instant::now() + Duration::from_secs(5);
    while session.is_alive() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!session.is_alive(), "bash never exited");

    let state = screen_state(&server, &id, None).await;
    assert_eq!(state["status"], "session_died");
    assert_eq!(state["data"]["exit_code"], 3);
    assert_eq!(lines_of(&state)[0].trim_end(), "LAST_SCREEN");
}
