//! Milestone 0.0.4 — Tier-B terminal state against real PTYs (spec §4.5,
//! §5.2 `get_screen_state` and `resize`, §11.4 adaptive-tracking and
//! screen-diffing scenarios).

use clasp_core::mcp::tools::{GetScreenStateArgs, ReadOutputArgs, ResizeArgs, StartSessionArgs};
use clasp_core::mcp::ClaspServer;
use clasp_core::pty::{LineDiscipline, PtyBackend, Signal};
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
