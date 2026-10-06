//! **Digests and integrity strings after a mention of a private-key
//! header come back** (GH #260, `SECURITY.md` R19).
//!
//! A line that names a whole `-----BEGIN … PRIVATE KEY-----` header
//! without being a key — a `grep` hit, a code literal — opens a candidate
//! that stops short, and `pem::body_lines` follows it for 16 KiB, masking
//! every line that carries a run of 48 base64 characters that can be key
//! body. A SHA-256 digest is 64 hex digits, and the base64 of a `sha384-`
//! or `sha512-` integrity string is 64 or 88 characters: long enough, and
//! refused for what they are (`pem::Run`), so each row below asserts that
//! every surface shows them and reports nothing redacted.
//!
//! Driven through `HoldfastServer` over a `MockPty`, as `read_path.rs` is,
//! so each surface is the one an agent calls: a cursor read at the default
//! page size, the same bytes paged 1 KiB at a time, and
//! `get_screen_state`'s grid — and beside them the stream `holdfast watch`
//! is sent, through the `StreamRedactor` the daemon runs for it. **Each
//! row is paired** with a key printed after the same mention, which every
//! surface must still mask: a fix that stopped following the header would
//! pass the first half and fail the second.

use holdfast_core::attach::redact_stream::StreamRedactor;
use holdfast_core::mcp::tools::{GetScreenStateArgs, ReadOutputArgs};
use holdfast_core::mcp::HoldfastServer;
use holdfast_core::output::OutputProcessor;
use holdfast_core::pty::{MockPty, PtyBackend};
use holdfast_core::session::{new_session_id, Session, SessionConfig};
use rmcp::handler::server::wrapper::Parameters;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A throwaway 2048-bit RSA key, stored without its boundaries — see
/// `output::pem::fixtures` for why, and for what generated it.
const RSA_BODY: &str = include_str!("fixtures/pem-bodies/rsa-pkcs1.body");

fn key_lines() -> Vec<&'static str> {
    RSA_BODY.lines().map(str::trim_end).collect()
}

/// A 16-character window of the key's body in `text`, if one is there.
fn leaked(text: &str) -> Option<&'static str> {
    key_lines().into_iter().find_map(|line| {
        (0..line.len().saturating_sub(15))
            .step_by(4)
            .map(|i| &line[i..i + 16])
            .find(|w| text.contains(w))
    })
}

/// `n` bytes that look random and are the same on every run.
fn bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut state = seed;
    (0..n)
        .map(|_| {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)) as u8
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Standard base64 with padding, as an integrity string spells it.
fn base64(b: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &x)| n | u32::from(x) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

/// What each surface returned for `text`, fed to a fresh session: the
/// cursor read at the default page size, the 1 KiB pages joined, the
/// grid's rows joined by `\n`, and the stream `holdfast watch` is sent,
/// fed whole and in 61-byte pieces so that pieces end inside lines. Each
/// also says whether it reported a redaction: the reads' `redactions`, the
/// grid's `held_back`, a marker in the stream.
async fn surfaces(text: &str) -> Vec<(&'static str, String, bool)> {
    let server = HoldfastServer::new();
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
    pty.queue_output(text.as_bytes());
    let want = text.len() as u64;
    let deadline = Instant::now() + Duration::from_secs(10);
    while session.buffer_head() < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(session.buffer_head(), want, "the reader thread fell behind");

    let mut out = Vec::new();
    for (name, max_bytes) in [("cursor read", None), ("1 KiB pages", Some(1024))] {
        let (mut cursor, mut joined, mut redacted) = (0u64, String::new(), false);
        for _ in 0..200 {
            if cursor >= want {
                break;
            }
            let r = server
                .read_output(Parameters(ReadOutputArgs {
                    session: id.clone(),
                    since_cursor: Some(cursor),
                    max_bytes,
                    ..Default::default()
                }))
                .await
                .expect("read_output must not be a protocol error");
            let d = r.structured_content.expect("structured content")["data"].clone();
            joined.push_str(d["output"].as_str().unwrap());
            redacted |= d["redactions"].as_object().is_some_and(|m| !m.is_empty());
            let next = d["cursor"].as_u64().unwrap();
            assert!(next > cursor, "{name}: the read did not advance: {d}");
            cursor = next;
        }
        assert_eq!(cursor, want, "{name}: the pages never reached the end");
        out.push((name, joined, redacted));
    }

    let g = server
        .get_screen_state(Parameters(GetScreenStateArgs {
            session: id.clone(),
            ..Default::default()
        }))
        .await
        .expect("get_screen_state must not be a protocol error");
    let g = g.structured_content.expect("structured content")["data"].clone();
    let rows: Vec<&str> = g["lines"]
        .as_array()
        .expect("a full grid")
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    out.push(("grid", rows.join("\n"), g["held_back"] == true));

    let processor = Arc::new(OutputProcessor::builtin().unwrap());
    for (name, piece) in [
        ("watch stream", text.len()),
        ("watch stream, 61-byte pieces", 61),
    ] {
        let mut r = StreamRedactor::new(Arc::clone(&processor));
        let mut sent = Vec::new();
        for chunk in text.as_bytes().chunks(piece) {
            sent.extend(r.feed(chunk));
        }
        sent.extend(r.flush());
        let sent = String::from_utf8_lossy(&sent).into_owned();
        let marked = sent.contains("[REDACTED");
        out.push((name, sent, marked));
    }
    out
}

/// The lines that mention a header without being a key, each ending in
/// a prompt, and the command line the output under test follows.
fn mentions(command: &str) -> Vec<(&'static str, String)> {
    let hit = "docs/keys.md:14:-----BEGIN RSA PRIVATE KEY-----";
    vec![
        (
            "grep hit",
            format!("$ grep -rn 'BEGIN RSA PRIVATE KEY' docs/\r\n{hit}\r\n$ {command}\r\n"),
        ),
        (
            "coloured grep hit",
            format!(
                "$ grep -rn 'BEGIN RSA PRIVATE KEY' docs/\r\n\
                 \x1b[35m\x1b[Kdocs/keys.md\x1b[m\x1b[K\x1b[36m\x1b[K:\x1b[m\x1b[K\
                 \x1b[32m\x1b[K14\x1b[m\x1b[K\x1b[36m\x1b[K:\x1b[m\x1b[K\
                 \x1b[01;31m\x1b[K-----BEGIN RSA PRIVATE KEY-----\x1b[m\x1b[K\r\n$ {command}\r\n"
            ),
        ),
        (
            "code literal",
            format!(
                "$ rg -n PRIVATE src/tls.rs\r\n\
                 9:const HEADER: &str = \"-----BEGIN RSA PRIVATE KEY-----\";\r\n$ {command}\r\n"
            ),
        ),
        // Both commands on one line, so no prompt comes between the hit
        // and the first digest: the candidate's own walk reaches the
        // digests, which is the material test rather than the line test.
        (
            "one command line",
            format!("$ grep -rn 'BEGIN RSA PRIVATE KEY' docs/; {command}\r\n{hit}\r\n"),
        ),
    ]
}

/// **R19's reproduction: a `grep` hit naming a header, then `sha256sum`
/// over twelve files.** Every surface shows all twelve digest lines, after
/// each of the four mentions, and reports nothing redacted.
#[tokio::test]
async fn sha256sum_after_a_header_mention_comes_back_on_every_surface() {
    let digests: Vec<String> = (0..12).map(|i| hex(&bytes(i, 32))).collect();
    let listing: String = digests
        .iter()
        .enumerate()
        .map(|(i, d)| format!("{d}  dist/holdfast-0.0.9-{i:02}.tar.gz\r\n"))
        .collect();
    let mut wrong = Vec::new();
    for (mention, lead) in mentions("sha256sum dist/*") {
        let text = format!("{lead}{listing}$ ");
        for (surface, out, redacted) in surfaces(&text).await {
            let shown = digests.iter().filter(|d| out.contains(d.as_str())).count();
            if shown != 12 || out.contains("[REDACTED") || redacted {
                wrong.push(format!("{mention}, {surface}: {shown} of 12 shown:\n{out}"));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} surfaces masked a digest:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// **`package-lock.json`, `yarn.lock` and an HTML `<script>` tag after the
/// same mention: the integrity strings come back.** The base64 after
/// `sha512-` is 88 characters and after `sha384-` 64, long enough for the
/// line test. `sha256-` (44) is not, and follows a line that is already
/// released here; it is in the row so that all three prefixes reach every
/// surface, and `pem.rs`'s own tests pin its refusal.
#[tokio::test]
async fn integrity_strings_after_a_header_mention_come_back_on_every_surface() {
    let sri =
        |algorithm: &str, seed: u64, n: usize| format!("{algorithm}-{}", base64(&bytes(seed, n)));
    let mut values = Vec::new();
    let mut lock = String::from("{\r\n  \"lockfileVersion\": 3,\r\n  \"packages\": {\r\n");
    for (i, name) in ["left-pad", "is-odd", "chalk", "debug", "ms"]
        .iter()
        .enumerate()
    {
        let integrity = sri("sha512", 100 + i as u64, 64);
        lock.push_str(&format!(
            "    \"node_modules/{name}\": {{\r\n      \"version\": \"1.{i}.0\",\r\n      \
             \"resolved\": \"https://registry.npmjs.org/{name}/-/{name}-1.{i}.0.tgz\",\r\n      \
             \"integrity\": \"{integrity}\"\r\n    }},\r\n"
        ));
        values.push(integrity);
    }
    lock.push_str("  }\r\n}\r\n");
    let yarn = sri("sha512", 200, 64);
    let script = sri("sha384", 300, 48);
    let nix = sri("sha256", 400, 32);
    let rest = format!(
        "$ grep integrity yarn.lock index.html flake.lock\r\n\
         yarn.lock:  integrity {yarn}\r\n\
         index.html:<script src=\"/lib.js\" integrity=\"{script}\"></script>\r\n\
         flake.lock:      \"narHash\": \"{nix}\",\r\n$ "
    );
    values.extend([yarn, script, nix]);
    assert_eq!(
        values[0].len(),
        "sha512-".len() + 88,
        "the premise: a sha512 string"
    );
    let mut wrong = Vec::new();
    for (mention, lead) in mentions("cat package-lock.json") {
        let text = format!("{lead}{lock}{rest}");
        for (surface, out, redacted) in surfaces(&text).await {
            let shown = values.iter().filter(|v| out.contains(v.as_str())).count();
            if shown != values.len() || out.contains("[REDACTED") || redacted {
                wrong.push(format!(
                    "{mention}, {surface}: {shown} of {} shown:\n{out}",
                    values.len()
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} surfaces masked an integrity string:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// **The pair: after the same mentions, a key is still masked on every
/// surface, and so is a base64 blob.**
///
/// * A key cut short by `head` is the candidate's own walk; a key a pager
///   cut off with `bat`'s gutter in front of every line is
///   `pem::body_lines`.
/// * A key whose last line happens to be all hex digits, shown by `bat`
///   without its boundaries: that line follows a body line and is masked
///   with the rest, although on its own it would be a digest.
/// * A key straight after a line that ends in `sha256-`: the prefix
///   refuses only the run directly after it on the same line.
/// * Three lines of `base64 -w 64` output have the alphabet of key body
///   and are masked — the part of R19 that stays open, so a change that
///   releases them has to move the register with it.
#[tokio::test]
async fn a_key_and_a_base64_blob_after_a_header_mention_are_still_masked() {
    let lines = key_lines();
    let header = "-----BEGIN RSA PRIVATE KEY-----";
    let crlf = |ls: &[&str]| -> String { ls.iter().map(|l| format!("{l}\r\n")).collect() };
    let gutter = |ls: &[&str]| -> String {
        ls.iter()
            .enumerate()
            .map(|(i, l)| format!("{:>4} \u{2502} {l}\r\n", i + 2))
            .collect()
    };
    let pager = "\x1b[7m:\x1b[27m\x1b[K\r\x1b[K$ ";
    // The key's interior, then a last line of 40 hex digits: 30 bytes of
    // DER, a multiple of three, so no `=` pads it.
    let last_hex = hex(&bytes(600, 20));
    let mut hex_ended: Vec<&str> = lines[..lines.len() - 1].to_vec();
    hex_ended.push(&last_hex);
    // Three lines of `base64 -w 64` output.
    let blob = base64(&bytes(500, 144));
    assert!(
        blob.as_bytes()
            .chunks(64)
            .all(|l| l.iter().any(|b| !b.is_ascii_hexdigit())),
        "the premise: no line of the blob is all hex"
    );
    let shapes = [
        (
            "head -n 9",
            format!("$ head -n 9 id_rsa\r\n{header}\r\n{}$ ", crlf(&lines[..8])),
        ),
        (
            "bat, paged",
            format!("$ bat id_rsa\r\n{}{pager}", gutter(&lines[..12])),
        ),
        (
            "bat, last line all hex",
            format!(
                "$ bat -r 2:{} id_rsa\r\n{}{pager}",
                hex_ended.len() + 1,
                gutter(&hex_ended)
            ),
        ),
        (
            "after sha256-",
            format!(
                "$ printf 'sha256-\\n'; sed -n '2,13p' id_rsa\r\nsha256-\r\n{}$ ",
                crlf(&lines[..12])
            ),
        ),
        (
            "base64 blob",
            format!(
                "$ base64 -w 64 blob\r\n{}\r\n$ ",
                [&blob[..64], &blob[64..128], &blob[128..]].join("\r\n")
            ),
        ),
    ];
    for (mention, lead) in mentions("true") {
        for (shape, body) in &shapes {
            let text = format!("{lead}{body}echo done\r\ndone\r\n$ ");
            for (surface, out, redacted) in surfaces(&text).await {
                let at = format!("{mention}, {shape}, {surface}");
                assert_eq!(leaked(&out), None, "{at}: {out}");
                assert!(!out.contains(&last_hex), "{at}: {out}");
                for line in blob.as_bytes().chunks(64) {
                    let line = std::str::from_utf8(line).unwrap();
                    assert!(!out.contains(line), "{at}: {out}");
                }
                assert!(out.contains("[REDACTED"), "{at}: {out}");
                assert!(redacted, "{at}: reported nothing");
                assert!(out.contains("done"), "{at}: {out}");
            }
        }
    }
}
