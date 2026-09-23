//! The read path as the agent sees it: `read_output` and
//! `get_screen_state` driven through `HoldfastServer`, over a `MockPty`
//! session in the server's own registry.
//!
//! A mock rather than a shell because every row here is about *which
//! bytes* a read returns, and a real shell decides for itself when a
//! prompt lands and how its echo is split. The bytes a row queues are the
//! bytes the ring holds, so the arithmetic in each assertion is the
//! arithmetic the read performed.

use holdfast_core::mcp::tools::{
    GetScreenStateArgs, ReadOutputArgs, StatusArgs, WaitForPatternArgs,
};
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

// ------------------------------------------------ GH #243, #224, #242

/// A throwaway 4096-bit RSA key, stored without its boundaries — see
/// `output::pem::fixtures` for why, and for what generated it.
const RSA4096_BODY: &str = include_str!("fixtures/pem-bodies/rsa4096-pkcs1.body");

fn rsa4096() -> String {
    format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----\n",
        RSA4096_BODY.replace("\r\n", "\n")
    )
}

/// `text` with every regex metacharacter escaped — a base64 line carries
/// `+` and `/`.
fn regex_escape(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            let meta = "\\.+*?()|[]{}^$#&-~".contains(c);
            meta.then_some('\\').into_iter().chain(std::iter::once(c))
        })
        .collect()
}

/// A 16-character window of the key's body in `text`, if one is there.
fn leaked(text: &str) -> Option<&'static str> {
    RSA4096_BODY.lines().map(str::trim_end).find_map(|line| {
        (0..line.len().saturating_sub(15))
            .step_by(4)
            .map(|i| &line[i..i + 16])
            .find(|w| text.contains(w))
    })
}

/// **The dogfood pass's reproduction of GH #243 and GH #224, on the
/// tool surface.** `cat` of a complete 4096-bit key, then a prompt; then
/// every read an agent would make of it.
///
/// Measured on `main` at `a81b02d` through the real wire: `tail_lines: 30`
/// returned 26 raw body lines with `redactions: {}`, `tail_bytes` and a
/// cursor 700 bytes past `-----BEGIN` did the same, and `get_screen_state`
/// with the header scrolled off returned 36 raw body lines with
/// `held_back: false`. A cursor read from before the header was the one
/// shape that masked it. Every one of those reads is asserted here, and
/// each must say *something* was redacted — an empty `redactions` beside
/// an output with no key in it would mean the key was never there.
#[tokio::test]
async fn every_read_of_a_catted_key_is_masked_on_the_tool_surface() {
    let server = HoldfastServer::new();
    let (id, session, pty) = mock_session_in(&server);
    let pem = rsa4096();
    let text = format!("$ cat k.pem\r\n{}user@host:~$ ", pem.replace('\n', "\r\n"));
    feed(&session, &pty, text.as_bytes());
    let begin = text.find("-----BEGIN").unwrap() as u64;

    let mut reads: Vec<(String, ReadOutputArgs)> = Vec::new();
    for n in [10usize, 15, 20, 30] {
        reads.push((
            format!("tail_lines {n}"),
            ReadOutputArgs {
                session: id.clone(),
                tail_lines: Some(n),
                ..Default::default()
            },
        ));
    }
    for n in [1000usize, 2000] {
        reads.push((
            format!("tail_bytes {n}"),
            ReadOutputArgs {
                session: id.clone(),
                tail_bytes: Some(n),
                ..Default::default()
            },
        ));
    }
    for past in [700u64, 1200] {
        reads.push((
            format!("since_cursor BEGIN+{past}"),
            ReadOutputArgs {
                session: id.clone(),
                since_cursor: Some(begin + past),
                ..Default::default()
            },
        ));
    }
    for (name, args) in reads {
        let d = read(&server, args).await;
        let out = d["output"].as_str().unwrap();
        assert_eq!(leaked(out), None, "{name}: {out}");
        assert!(
            d["redactions"].as_object().is_some_and(|m| !m.is_empty()),
            "{name}: a read of key material reported nothing redacted: {d}"
        );
    }

    // `wait_for_pattern` from inside the key, on a pattern that matches
    // a body line: both `match.text` and `output_since_start` run the read
    // path from the cursor, and on `main` both returned the body raw.
    let line = RSA4096_BODY.lines().nth(20).unwrap().trim_end();
    let w = server
        .wait_for_pattern(Parameters(WaitForPatternArgs {
            session: id.clone(),
            pattern: Some(regex_escape(&line[..24])),
            timeout_secs: Some(2),
            since_cursor: Some(begin + 700),
            max_bytes: None,
        }))
        .await
        .expect("wait_for_pattern must not be a protocol error");
    let w = body(&w)["data"].clone();
    assert_eq!(w["matched"], true, "{w}");
    let rendered = w.to_string();
    assert_eq!(leaked(&rendered), None, "{rendered}");

    let g = server
        .get_screen_state(Parameters(GetScreenStateArgs {
            session: id.clone(),
            ..Default::default()
        }))
        .await
        .expect("get_screen_state must not be a protocol error");
    let g = body(&g)["data"].clone();
    let lines: Vec<&str> = g["lines"]
        .as_array()
        .expect("a full grid")
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    let screen = lines.join("\n");
    assert!(
        !screen.contains("-----BEGIN"),
        "the premise: the header has scrolled off a {}-row screen",
        lines.len()
    );
    assert_eq!(leaked(&screen), None, "{screen}");
    assert_eq!(g["held_back"], true, "{g}");
    assert!(screen.contains("user@host:~$"), "{screen}");
}

/// **One unterminated header no longer blinds the commands after it**
/// (GH #242), measured the way the dogfood pass measured it: the owner's
/// trigger, then a command at a time, each read with the cursor the last
/// read returned.
///
/// On `main` at `a81b02d` every one of the next thirty-odd commands came
/// back as a lone `[REDACTED:unresolved]`. The shell here is the one the
/// dogfood pass captured: bash with bracketed paste, a prompt with SGR
/// colour and non-ASCII glyphs, and the command echo that carries the
/// header a second time.
#[tokio::test]
async fn one_unterminated_header_does_not_blind_the_commands_after_it() {
    let server = HoldfastServer::new();
    let (id, session, pty) = mock_session_in(&server);
    let prompt = "\x1b[?2004h\r\n\x1b[1;36mholdfast\x1b[0m on \x1b[1;35m\u{e0a0} main\x1b[0m \r\n\
                  \x1b[1;32m\u{276f}\x1b[0m ";
    feed(&session, &pty, prompt.as_bytes());
    feed(
        &session,
        &pty,
        format!(
            "printf -- '-----BEGIN RSA PRIVATE KEY-----\\n'\r\n\x1b[?2004l\r\
             -----BEGIN RSA PRIVATE KEY-----\r\n{prompt}"
        )
        .as_bytes(),
    );
    let mut cursor = session.buffer_head();
    for n in 1..=5 {
        let command = format!("echo ok{n}\r\n\x1b[?2004l\rok{n}\r\n{prompt}");
        feed(&session, &pty, command.as_bytes());
        let d = read(
            &server,
            ReadOutputArgs {
                session: id.clone(),
                since_cursor: Some(cursor),
                ..Default::default()
            },
        )
        .await;
        let out = d["output"].as_str().unwrap();
        assert!(
            out.contains(&format!("\rok{n}\r\n")),
            "command {n} after the header came back masked: {d}"
        );
        assert!(
            d["redactions"].as_object().is_some_and(|m| m.is_empty()),
            "command {n}: {d}"
        );
        cursor = d["cursor"].as_u64().unwrap();
    }
}

/// **A key in a window title is masked wherever the title is reported**
/// (GH #224's `title` field, and `status`'s).
///
/// `printf '\033]0;%s\007' "$(head -n 8 id_rsa)"` puts a key cut short
/// into the title, which the emulator joins into one line. Titles were
/// redacted with `redact_str`, which replaces complete matches only, so
/// the eight lines came back on `get_screen_state`'s `title` and on
/// `status`'s — both `readOnlyHint` tools — while `read_output` masked the
/// same bytes. Found by an independent review of this branch.
///
/// Paired with an ordinary title, which must come back byte for byte.
#[tokio::test]
async fn a_key_in_a_window_title_is_masked_on_every_surface_that_reports_it() {
    let server = HoldfastServer::new();
    let (id, session, pty) = mock_session_in(&server);
    let cut: String = RSA4096_BODY
        .replace("\r\n", "\n")
        .lines()
        .take(8)
        .map(|l| format!("{l}\n"))
        .collect();
    let text = format!("$ set-title\r\n\x1b]0;-----BEGIN RSA PRIVATE KEY-----\n{cut}\x07$ ");
    feed(&session, &pty, text.as_bytes());

    let g = server
        .get_screen_state(Parameters(GetScreenStateArgs {
            session: id.clone(),
            ..Default::default()
        }))
        .await
        .expect("get_screen_state must not be a protocol error");
    let title = body(&g)["data"]["title"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !title.is_empty(),
        "the premise: the emulator reports a title"
    );
    assert_eq!(leaked(&title), None, "get_screen_state title: {title}");

    let st = server
        .status(Parameters(StatusArgs {
            session: id.clone(),
        }))
        .await
        .expect("status must not be a protocol error");
    let st = body(&st)["data"].clone();
    let status_title = st["title"].to_string();
    assert_ne!(
        st["title"],
        serde_json::Value::Null,
        "the premise: status reports a title: {st}"
    );
    assert_eq!(leaked(&status_title), None, "status title: {status_title}");

    let r = read(
        &server,
        ReadOutputArgs {
            session: id.clone(),
            since_cursor: Some(0),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(leaked(r["output"].as_str().unwrap()), None, "{r}");

    // The negative: an ordinary title is untouched.
    feed(&session, &pty, b"\x1b]0;cargo build\x07$ ");
    let st = server
        .status(Parameters(StatusArgs {
            session: id.clone(),
        }))
        .await
        .unwrap();
    assert_eq!(body(&st)["data"]["title"], "cargo build");
}
