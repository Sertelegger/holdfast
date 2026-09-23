//! The read path as the agent sees it: `read_output` and
//! `get_screen_state` driven through `HoldfastServer`, over a `MockPty`
//! session in the server's own registry.
//!
//! A mock rather than a shell because every row here is about *which
//! bytes* a read returns, and a real shell decides for itself when a
//! prompt lands and how its echo is split. The bytes a row queues are the
//! bytes the ring holds, so the arithmetic in each assertion is the
//! arithmetic the read performed.

use holdfast_core::mcp::tools::ReadOutputArgs;
use holdfast_core::mcp::HoldfastServer;
use holdfast_core::pty::{MockPty, PtyBackend};
use holdfast_core::session::{new_session_id, Session, SessionConfig};
use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn body(r: &rmcp::model::CallToolResult) -> Value {
    r.structured_content.clone().expect("structured content")
}

/// A `MockPty` session in `server`'s registry, with a ring large enough
/// that nothing a row queues is evicted.
fn mock_session_in(server: &HoldfastServer) -> (String, Arc<Session>, Arc<MockPty>) {
    let pty = Arc::new(MockPty::new());
    let session = Session::new(
        new_session_id(),
        None,
        "mock".into(),
        vec![],
        Arc::clone(&pty) as Arc<dyn PtyBackend>,
        SessionConfig::with_buffer_capacity(1024 * 1024),
    );
    let id = session.id.clone();
    server
        .registry
        .insert(Arc::clone(&session))
        .expect("registry insert");
    (id, session, pty)
}

/// Queue `bytes` and wait until the reader thread has published all of
/// them, so a read that follows sees exactly this buffer.
fn feed(session: &Session, pty: &MockPty, bytes: &[u8]) {
    let want = session.buffer_head() + bytes.len() as u64;
    pty.queue_output(bytes);
    let deadline = Instant::now() + Duration::from_secs(10);
    while session.buffer_head() < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(session.buffer_head(), want, "the reader thread fell behind");
}

async fn read(server: &HoldfastServer, args: ReadOutputArgs) -> Value {
    let r = server
        .read_output(Parameters(args))
        .await
        .expect("read_output must not be a protocol error");
    body(&r)["data"].clone()
}

/// **A `tail_bytes` read larger than `max_bytes` says it was cut** (GH #246).
///
/// The tool clamped `tail_bytes` to `max_bytes` before the session saw
/// it, so the session was asked for a tail that fit, returned it whole,
/// and reported `truncated_for_size: false` over a read that had dropped
/// most of what was asked for. `tail_lines` never had the clamp and
/// always reported the clip; the two selectors now agree.
///
/// **Paired**, in both directions, because the one-line fix and its
/// inverse are both plausible: a tail that fits must still say it was
/// not cut, and the cut one must still end at `head` with its cursor
/// there — front-clipping drops the *oldest* bytes (REQ-T-006).
#[tokio::test]
async fn an_oversized_tail_bytes_read_reports_the_front_clip() {
    let server = HoldfastServer::new();
    let (id, session, pty) = mock_session_in(&server);
    let mut text = String::new();
    for i in 0..6000 {
        text.push_str(&format!("line {i:05} padding padding\n"));
    }
    feed(&session, &pty, text.as_bytes());
    let head = session.buffer_head();
    const MAX: usize = 32 * 1024;
    assert!(head as usize > 4 * MAX, "the buffer must dwarf the page");

    let cut = read(
        &server,
        ReadOutputArgs {
            session: id.clone(),
            tail_bytes: Some(4 * MAX),
            max_bytes: Some(MAX),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(cut["bytes_returned"], MAX, "{cut}");
    assert_eq!(
        cut["truncated_for_size"],
        true,
        "a tail read that dropped {} of the bytes it was asked for must say \
         so: {cut}",
        3 * MAX
    );
    assert_eq!(cut["cursor"], head, "the newest bytes survive the clip");
    assert!(
        cut["output"]
            .as_str()
            .unwrap()
            .ends_with("line 05999 padding padding\n"),
        "front-clipping keeps the newest bytes"
    );

    // The negative: a tail that fits is not a clip.
    let fits = read(
        &server,
        ReadOutputArgs {
            session: id.clone(),
            tail_bytes: Some(MAX / 2),
            max_bytes: Some(MAX),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(fits["bytes_returned"], MAX / 2, "{fits}");
    assert_eq!(fits["truncated_for_size"], false, "{fits}");
    assert!(fits["next_cursor"].is_null(), "{fits}");
}
