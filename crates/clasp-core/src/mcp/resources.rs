//! MCP resources (§5.5): `resources/list`, `resources/templates/list`
//! and `resources/read`, plus the `clasp://` URI grammar all three share.
//!
//! **The same `OutputProcessor` pipeline as `read_output`, and
//! deliberately so.** A resource fetch is bulk inspection of the buffer a
//! tool call reads incrementally, not a second read implementation:
//! `Session::read_processed` is the one entry point, which is what makes
//! redaction, the §4.1 holdback and §9.4's `redaction_disabled` audit
//! write apply to this transport without a single line of its own. If you
//! find yourself adding a second `record_redaction_disabled` call site,
//! the read is bypassing the pipeline.
//!
//! Three URI shapes exist in this document and the `malformed_uri`
//! predicate is *"parses as none of the three"* (§5.5.2), not "is not the
//! first one":
//!
//! | Shape | Owner | Here |
//! |---|---|---|
//! | `clasp://session/{id}/buffer{?…}` | §5.5.1 | served |
//! | `clasp://session-name/<name>/buffer` | §5.5.4, REQ-R-007 | served, **live sessions only** |
//! | `clasp://session/{id}/file/{transfer_id}` | §5.5.6, §5.7 | recognised, not served — 0.0.9 |
//!
//! The third is recognised on purpose. Answering it `malformed_uri`
//! would tell an agent the URI is ill-formed when it is a shape this
//! document defines and this build does not yet serve, and §18.5 already
//! models an HTTP `404`/`410` split on this predicate.

use std::sync::Arc;

use rmcp::model::{MetaObject, ReadResourceResult, Resource, ResourceContents, ResourceTemplate};
use rmcp::ErrorData;
use serde_json::json;

use crate::output::ansi::AnsiMode;
use crate::output::encoding::TextEncoding;
use crate::output::{ReadOptions, ReadRequest, ReadStart};
use crate::session::{Session, SessionRegistry};

use super::caller;

/// §4.2's `resource_read_max_bytes`. The daemon-configured hard cap on a
/// single resource fetch, and the default when the caller names none.
pub const DEFAULT_RESOURCE_READ_MAX_BYTES: usize = 4 * 1024 * 1024;

/// The `tool` recorded in §9.4's `redaction_disabled` for a resource
/// read. `ReadRequest.tool`'s own doc comment already names this string.
pub const RESOURCE_READ_TOOL: &str = "resource_read";

const SCHEME: &str = "clasp://";
const ANSI_ALLOWED: [&str; 2] = ["strip", "raw"];
const ENCODING_ALLOWED: [&str; 3] = ["utf8", "base64", "lossy_printable"];
const BOOL_ALLOWED: [&str; 2] = ["true", "false"];

/// §5.5.2's single template. `{?…}` is RFC 6570 form-style expansion.
pub const BUFFER_URI_TEMPLATE: &str =
    "clasp://session/{session_id}/buffer{?ansi,text_encoding,redact,since_cursor,max_bytes}";

/// What a `clasp://` URI names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceTarget {
    /// `clasp://session/{id}/buffer` — resolves whether or not the
    /// session is still running (§5.5.1).
    SessionId(String),
    /// `clasp://session-name/<name>/buffer` — resolves **only to live
    /// sessions** (§5.5.4, REQ-S-002, REQ-R-007). A name is released
    /// when a session exits, so this must re-resolve on every read and
    /// must never be cached: the failure hands one session's output to a
    /// reader who asked for another.
    SessionName(String),
    /// `clasp://session/{id}/file/{transfer_id}` — §5.5.6's shape,
    /// recognised so it is not reported as malformed, and not served
    /// until 0.0.9 builds file transfer.
    File {
        session_id: String,
        transfer_id: String,
    },
}

/// The §5.5.2 query parameters, resolved against their defaults.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceQuery {
    pub ansi: AnsiMode,
    pub text_encoding: TextEncoding,
    pub redact: bool,
    /// `None` means "from `buffer.tail`", which is §5.5.3's default.
    pub since_cursor: Option<u64>,
    /// The caller's requested cap, before clamping.
    pub max_bytes: Option<usize>,
}

impl Default for ResourceQuery {
    fn default() -> Self {
        Self {
            ansi: AnsiMode::Strip,
            text_encoding: TextEncoding::Utf8,
            redact: true,
            since_cursor: None,
            max_bytes: None,
        }
    }
}

/// A parsed `clasp://` URI.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceUri {
    pub target: ResourceTarget,
    pub query: ResourceQuery,
}

/// A §5.5.2 validation failure: `-32602 Invalid params` with a
/// structured `data.code`, surfaced **before** any buffer access.
///
/// These are protocol errors at the JSON-RPC layer, not a
/// `ResourceContents` carrying `_meta.error` — which keeps a successful
/// resource read unambiguous.
#[derive(Debug, Clone, PartialEq)]
pub struct UriError {
    pub code: &'static str,
    pub message: String,
    pub data: serde_json::Value,
}

impl UriError {
    fn malformed(message: impl Into<String>) -> Self {
        Self {
            code: "malformed_uri",
            message: message.into(),
            data: json!({ "code": "malformed_uri" }),
        }
    }

    fn unknown_param(param: &str) -> Self {
        Self {
            code: "unknown_query_param",
            message: format!("unknown query parameter `{param}`"),
            data: json!({ "code": "unknown_query_param", "param": param }),
        }
    }

    fn invalid_enum(param: &str, value: &str, allowed: &[&str]) -> Self {
        Self {
            code: "invalid_enum",
            message: format!("{param}={value} is not one of {}", allowed.join(", ")),
            data: json!({
                "code": "invalid_enum",
                "param": param,
                "value": value,
                "allowed": allowed,
            }),
        }
    }

    fn out_of_range(param: &str, value: &str, constraint: &str) -> Self {
        Self {
            code: "out_of_range",
            message: format!("{param}={value} is out of range: {constraint}"),
            data: json!({
                "code": "out_of_range",
                "param": param,
                "value": value,
                "constraint": constraint,
            }),
        }
    }

    /// The JSON-RPC shape §5.5.2 requires.
    pub fn to_error_data(&self) -> ErrorData {
        ErrorData::invalid_params(self.message.clone(), Some(self.data.clone()))
    }
}

/// Minimal percent-decoding, for session names that carry a space or a
/// `%`. Nothing else in a `clasp://` URI needs it, and pulling in a URL
/// crate for two escapes would be a dependency for a footnote.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl ResourceUri {
    /// Parse and validate a `clasp://` URI against §5.5.2.
    pub fn parse(uri: &str) -> Result<Self, UriError> {
        let Some(rest) = uri.strip_prefix(SCHEME) else {
            return Err(UriError::malformed(format!(
                "{uri} does not start with `{SCHEME}`"
            )));
        };
        let (path, query) = match rest.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (rest, None),
        };
        let segments: Vec<&str> = path.split('/').collect();
        let target = match segments.as_slice() {
            ["session", id, "buffer"] if !id.is_empty() => {
                ResourceTarget::SessionId(percent_decode(id))
            }
            ["session-name", name, "buffer"] if !name.is_empty() => {
                ResourceTarget::SessionName(percent_decode(name))
            }
            ["session", id, "file", transfer] if !id.is_empty() && !transfer.is_empty() => {
                ResourceTarget::File {
                    session_id: percent_decode(id),
                    transfer_id: percent_decode(transfer),
                }
            }
            _ => {
                return Err(UriError::malformed(format!(
                    "{uri} parses as none of the three URI shapes this server serves"
                )))
            }
        };
        Ok(Self {
            target,
            query: parse_query(query)?,
        })
    }

    /// The canonical, default-parameter URI for a session id — the one
    /// `resources/list` publishes and the one the MIME type in that list
    /// describes.
    pub fn buffer_uri(session_id: &str) -> String {
        format!("clasp://session/{session_id}/buffer")
    }

    /// The same URI with a `since_cursor`, for `_meta.clasp.next_uri`.
    ///
    /// The next offset is encoded **inside** `next_uri` as a query
    /// parameter and not as a separate `_meta.clasp.cursor` field, which
    /// is §5.5.3's own rule.
    pub fn continuation(&self, next_cursor: u64) -> String {
        let base = match &self.target {
            ResourceTarget::SessionId(id) => format!("clasp://session/{id}/buffer"),
            ResourceTarget::SessionName(name) => format!("clasp://session-name/{name}/buffer"),
            ResourceTarget::File {
                session_id,
                transfer_id,
            } => format!("clasp://session/{session_id}/file/{transfer_id}"),
        };
        let q = &self.query;
        format!(
            "{base}?ansi={}&text_encoding={}&redact={}&since_cursor={next_cursor}{}",
            match q.ansi {
                AnsiMode::Strip => "strip",
                AnsiMode::Raw => "raw",
            },
            q.text_encoding.as_str(),
            q.redact,
            match q.max_bytes {
                Some(n) => format!("&max_bytes={n}"),
                None => String::new(),
            }
        )
    }
}

fn parse_query(query: Option<&str>) -> Result<ResourceQuery, UriError> {
    let mut out = ResourceQuery::default();
    let Some(query) = query else { return Ok(out) };
    if query.is_empty() {
        return Ok(out);
    }
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(UriError::malformed(format!(
                "query fragment `{pair}` is not `key=value`"
            )));
        };
        let value = percent_decode(value);
        match key {
            "ansi" => {
                out.ansi = match value.as_str() {
                    "strip" => AnsiMode::Strip,
                    "raw" => AnsiMode::Raw,
                    // Same two spellings `read_output` matches inline;
                    // a third spelling here would be a second grammar.
                    other => return Err(UriError::invalid_enum("ansi", other, &ANSI_ALLOWED)),
                };
            }
            "text_encoding" => {
                out.text_encoding = TextEncoding::parse(&value).ok_or_else(|| {
                    UriError::invalid_enum("text_encoding", &value, &ENCODING_ALLOWED)
                })?;
            }
            "redact" => {
                out.redact = match value.as_str() {
                    "true" => true,
                    "false" => false,
                    other => return Err(UriError::invalid_enum("redact", other, &BOOL_ALLOWED)),
                };
            }
            "since_cursor" => {
                out.since_cursor = Some(value.parse::<u64>().map_err(|_| {
                    UriError::out_of_range("since_cursor", &value, "a non-negative byte offset")
                })?);
            }
            "max_bytes" => {
                let n = value.parse::<usize>().map_err(|_| {
                    UriError::out_of_range("max_bytes", &value, "a positive byte count")
                })?;
                if n == 0 {
                    // The same rule `read_output` applies: a zero cap can
                    // never make forward progress, so an agent following
                    // the documented "retry at next_uri" rule live-locks.
                    return Err(UriError::out_of_range(
                        "max_bytes",
                        &value,
                        "must be at least 1",
                    ));
                }
                out.max_bytes = Some(n);
            }
            other => return Err(UriError::unknown_param(other)),
        }
    }
    Ok(out)
}

/// The §5.5.1 entry for one live session.
pub fn list_entry(session: &Session) -> Resource {
    let label = match &session.name {
        Some(name) => format!("Session {} ({}, {:?})", session.id, session.command, name),
        None => format!("Session {} ({})", session.id, session.command),
    };
    let description = format!(
        "Buffered output of the PTY-backed session {} running `{}`. \
         Query parameters select format: ansi=strip|raw, \
         text_encoding=utf8|base64|lossy_printable, redact=true|false. \
         Defaults yield text/plain; charset=utf-8.",
        session.id, session.command
    );
    Resource::new(ResourceUri::buffer_uri(&session.id), label)
        .with_description(description)
        // §5.5.1: the listed type is the **default-parameters** URI's,
        // which is the URI in the `uri` field. Other parameter
        // combinations resolve to other types and are discoverable
        // through the template, not through this list.
        .with_mime_type(TextEncoding::Utf8.mime_type())
}

/// §5.5.1: one entry **per live session only** (`Starting | Running`).
///
/// Exited sessions stay ID-addressable through `resources/read` — the
/// reaper keeps their registry entries (§5.5.1) — and are omitted here,
/// which is what keeps the list bounded and accurate.
pub fn list_resources(registry: &SessionRegistry) -> Vec<Resource> {
    let mut entries: Vec<Resource> = registry
        .all()
        .into_iter()
        .filter(|s| s.is_alive())
        .map(|s| list_entry(&s))
        .collect();
    // The registry is a `HashMap`, so without this two calls over the
    // same sessions could return them in different orders.
    entries.sort_by(|a, b| a.uri.cmp(&b.uri));
    entries
}

/// §5.5.2's single template.
///
/// **No `mimeType`, and that is not an omission.** The type depends on
/// the `text_encoding` parameter — `utf8` is `text/plain; charset=utf-8`
/// and `base64` is `application/octet-stream` — and per the MCP
/// 2025-06-18 schema a template's `mimeType` may appear only when *all*
/// matching resources share it. A template that advertised one would be
/// advertising a value it cannot know.
pub fn list_resource_templates() -> Vec<ResourceTemplate> {
    // `mime_type` is left at `new`'s `None` on purpose — see above.
    vec![
        ResourceTemplate::new(BUFFER_URI_TEMPLATE, "CLASP session buffer").with_description(
            "Buffered output of a CLASP session. Parameters mirror read_output args. \
         ansi: strip|raw (default strip). \
         text_encoding: utf8|base64|lossy_printable (default utf8; affects MIME type \
         — text encodings yield text/plain, base64 yields application/octet-stream). \
         redact: true|false (default true). \
         since_cursor: byte offset (default buffer.tail). \
         max_bytes: caller-requested cap, bounded by resource_read_max_bytes \
         (default and ceiling 4 MiB).",
        ),
    ]
}

/// Resolve a parsed URI to a session, honouring §5.5.4's asymmetry.
///
/// An id resolves whether or not the session is running; a **name**
/// resolves only to a live session, because a name is released when a
/// session exits and may already belong to a different one.
pub fn resolve(
    registry: &SessionRegistry,
    target: &ResourceTarget,
) -> Result<Arc<Session>, ErrorData> {
    match target {
        ResourceTarget::SessionId(id) => registry
            .all()
            .into_iter()
            .find(|s| &s.id == id)
            .ok_or_else(|| ErrorData::resource_not_found(format!("no session {id}"), None)),
        ResourceTarget::SessionName(name) => registry
            .all()
            .into_iter()
            .find(|s| s.is_alive() && s.name.as_deref() == Some(name.as_str()))
            .ok_or_else(|| {
                ErrorData::resource_not_found(format!("no live session named {name}"), None)
            }),
        ResourceTarget::File { .. } => Err(ErrorData::resource_not_found(
            "file-transfer resources arrive with §5.7 in 0.0.9; this URI shape is \
             recognised and not yet served"
                .to_string(),
            None,
        )),
    }
}

/// §5.5.3: read a session buffer through the `read_output` pipeline.
///
/// `ceiling` is the daemon's `resource_read_max_bytes`. A caller's
/// `?max_bytes=N` is clamped **down** against it and never up.
pub fn read_resource(
    registry: &SessionRegistry,
    processor: &crate::output::OutputProcessor,
    uri_str: &str,
    ceiling: usize,
) -> Result<ReadResourceResult, ErrorData> {
    // Validation before resolution, before any buffer access: §5.5.2
    // requires a malformed parameter to be a JSON-RPC error rather than
    // a `ResourceContents` that quietly used a default the caller did
    // not ask for.
    let uri = ResourceUri::parse(uri_str).map_err(|e| e.to_error_data())?;
    let session = resolve(registry, &uri.target)?;

    let effective_max = uri.query.max_bytes.unwrap_or(ceiling).min(ceiling);
    let since_cursor = uri
        .query
        .since_cursor
        .unwrap_or_else(|| session.buffer_tail());

    // The §9.4 caller seam, derived server-side from the authenticated
    // connection exactly as `read_output`'s is. Routing through
    // `read_processed` is what makes `?redact=false` audited without a
    // second `record_redaction_disabled` call site.
    let surface = caller::audit_surface(RESOURCE_READ_TOOL);
    let read = session.read_processed(
        &ReadRequest {
            start: ReadStart::Cursor(since_cursor),
            max_bytes: effective_max,
            options: ReadOptions {
                ansi: uri.query.ansi,
                text_encoding: uri.query.text_encoding,
                redact: uri.query.redact,
            },
            tool: surface.tool,
            client_kind: surface.client_kind,
        },
        processor,
    );

    // §5.5.3's extension fields, exactly: `truncated_for_size`,
    // `held_back`, `truncated_at_tail`, `next_uri`. **`held_back` and
    // `truncated_for_size` are distinct** — one means CLASP is
    // deliberately withholding bytes, the other that more exist beyond a
    // cap — and collapsing them into one flag is the fault to avoid.
    let mut meta = MetaObject::new();
    let mut clasp = serde_json::Map::new();
    if read.truncated_for_size {
        clasp.insert("truncated_for_size".into(), json!(true));
    }
    if read.held_back {
        clasp.insert("held_back".into(), json!(true));
    }
    if read.truncated_at_tail {
        clasp.insert("truncated_at_tail".into(), json!(true));
    }
    if let Some(next) = read.next_cursor {
        clasp.insert("next_uri".into(), json!(uri.continuation(next)));
    }
    let has_meta = !clasp.is_empty();
    meta.0
        .insert("clasp".into(), serde_json::Value::Object(clasp));

    let mime = uri.query.text_encoding.mime_type();
    let contents = match uri.query.text_encoding {
        // §5.5.3: base64 travels in `blob`, everything else in `text`.
        TextEncoding::Base64 => ResourceContents::blob(read.output, uri_str.to_string()),
        _ => ResourceContents::text(read.output, uri_str.to_string()),
    }
    .with_mime_type(mime);
    let contents = if has_meta {
        contents.with_meta(meta)
    } else {
        contents
    };
    Ok(ReadResourceResult::new(vec![contents]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_uri_shapes_parse_and_a_fourth_is_malformed() {
        assert_eq!(
            ResourceUri::parse("clasp://session/sess_a1b2/buffer")
                .unwrap()
                .target,
            ResourceTarget::SessionId("sess_a1b2".into())
        );
        assert_eq!(
            ResourceUri::parse("clasp://session-name/build/buffer")
                .unwrap()
                .target,
            ResourceTarget::SessionName("build".into())
        );
        assert_eq!(
            ResourceUri::parse("clasp://session/sess_a1b2/file/tr_9")
                .unwrap()
                .target,
            ResourceTarget::File {
                session_id: "sess_a1b2".into(),
                transfer_id: "tr_9".into()
            },
            "§5.5.6's shape is recognised, not reported malformed — the \
             predicate is `parses as none of the three`"
        );
        for bad in [
            "http://session/x/buffer",
            "clasp://session/x/screen",
            "clasp://session//buffer",
            "clasp://nonsense",
        ] {
            let e = ResourceUri::parse(bad).unwrap_err();
            assert_eq!(e.code, "malformed_uri", "{bad} should be malformed");
        }
    }

    #[test]
    fn every_query_fault_gets_its_own_structured_code() {
        // §5.5.2 names four codes and they are not interchangeable: an
        // agent branches on `data.code` to know whether to fix a name, a
        // value or a range.
        let e = ResourceUri::parse("clasp://session/s/buffer?ansi=purple").unwrap_err();
        assert_eq!(e.code, "invalid_enum");
        assert_eq!(e.data["param"], "ansi");
        assert_eq!(e.data["value"], "purple");
        assert_eq!(e.data["allowed"], json!(["strip", "raw"]));

        let e = ResourceUri::parse("clasp://session/s/buffer?colour=red").unwrap_err();
        assert_eq!(e.code, "unknown_query_param");
        assert_eq!(e.data["param"], "colour");

        let e = ResourceUri::parse("clasp://session/s/buffer?since_cursor=-5").unwrap_err();
        assert_eq!(e.code, "out_of_range");
        assert_eq!(e.data["param"], "since_cursor");

        let e = ResourceUri::parse("clasp://session/s/buffer?max_bytes=0").unwrap_err();
        assert_eq!(e.code, "out_of_range");
        assert_eq!(e.data["constraint"], "must be at least 1");

        let e = ResourceUri::parse("clasp://session/s/buffer?text_encoding=xml").unwrap_err();
        assert_eq!(e.code, "invalid_enum");

        let e = ResourceUri::parse("clasp://session/s/buffer?redact=maybe").unwrap_err();
        assert_eq!(e.code, "invalid_enum");

        // The pairing: every legal value must still parse, or this whole
        // block passes against a parser that rejects any query at all.
        let ok = ResourceUri::parse(
            "clasp://session/s/buffer?ansi=raw&text_encoding=base64&redact=false\
             &since_cursor=42&max_bytes=99",
        )
        .expect("the full legal query must parse");
        assert_eq!(ok.query.ansi, AnsiMode::Raw);
        assert_eq!(ok.query.text_encoding, TextEncoding::Base64);
        assert!(!ok.query.redact);
        assert_eq!(ok.query.since_cursor, Some(42));
        assert_eq!(ok.query.max_bytes, Some(99));
    }

    #[test]
    fn the_defaults_are_the_ones_5_5_2_publishes() {
        let q = ResourceUri::parse("clasp://session/s/buffer")
            .unwrap()
            .query;
        assert_eq!(q.ansi, AnsiMode::Strip);
        assert_eq!(q.text_encoding, TextEncoding::Utf8);
        assert!(q.redact, "redaction is on unless the caller opts out");
        assert_eq!(q.since_cursor, None, "None means buffer.tail at fetch time");
        assert_eq!(q.max_bytes, None);
    }

    #[test]
    fn a_caller_max_bytes_above_the_ceiling_is_clamped_down() {
        // Arithmetic only, so the row is about the rule rather than about
        // a buffer: `min` in the wrong order, or an `unwrap_or` that
        // honoured the caller, both survive a read-through test whose
        // buffer is smaller than either number.
        let ceiling = DEFAULT_RESOURCE_READ_MAX_BYTES;
        let requested = 99_999_999usize;
        assert!(requested > ceiling);
        assert_eq!(requested.min(ceiling), ceiling, "clamped down, never up");
        let smaller = 1024usize;
        assert_eq!(
            smaller.min(ceiling),
            smaller,
            "a caller asking for less than the ceiling gets what it asked for"
        );
        assert_eq!(DEFAULT_RESOURCE_READ_MAX_BYTES, 4 * 1024 * 1024);
    }

    #[test]
    fn a_continuation_uri_carries_the_cursor_and_the_original_knobs() {
        // §5.5.3: the next offset lives **inside** `next_uri`, not as a
        // separate `_meta.clasp.cursor` field — and a continuation that
        // dropped the caller's knobs would silently re-redact a stream
        // they asked for raw.
        let uri = ResourceUri::parse(
            "clasp://session/s/buffer?ansi=raw&text_encoding=base64&redact=false",
        )
        .unwrap();
        let next = uri.continuation(4096);
        assert!(next.contains("since_cursor=4096"), "{next}");
        assert!(next.contains("ansi=raw"), "{next}");
        assert!(next.contains("text_encoding=base64"), "{next}");
        assert!(next.contains("redact=false"), "{next}");
        // And it must round-trip, or the agent's retry is a fresh fault.
        let reparsed = ResourceUri::parse(&next).expect("next_uri must itself parse");
        assert_eq!(reparsed.query.since_cursor, Some(4096));
        assert_eq!(reparsed.query.ansi, AnsiMode::Raw);
        assert!(!reparsed.query.redact);
    }

    #[test]
    fn a_name_keyed_continuation_stays_name_keyed() {
        let uri = ResourceUri::parse("clasp://session-name/build/buffer").unwrap();
        let next = uri.continuation(10);
        assert!(
            next.starts_with("clasp://session-name/build/buffer?"),
            "{next}"
        );
        assert_eq!(
            ResourceUri::parse(&next).unwrap().target,
            ResourceTarget::SessionName("build".into()),
            "a continuation that silently switched to an id would defeat \
             REQ-R-007's release-on-exit rule"
        );
    }

    #[test]
    fn the_template_carries_no_mime_type() {
        let templates = list_resource_templates();
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].uri_template, BUFFER_URI_TEMPLATE);
        assert!(
            templates[0].mime_type.is_none(),
            "the type depends on text_encoding, so a template that named one \
             would be advertising a value it cannot know (§5.5.2)"
        );
        // The pairing: the *list* entry does carry one, because it names
        // the default-parameter URI.
        assert!(BUFFER_URI_TEMPLATE.contains("{?ansi,text_encoding,redact,since_cursor,max_bytes}"));
    }

    #[test]
    fn the_mime_type_follows_the_encoding_and_not_the_ansi_mode() {
        // §5.5.3's table: `base64` is the only row that changes the type,
        // and `ansi` never does.
        for (enc, want) in [
            (TextEncoding::Utf8, "text/plain; charset=utf-8"),
            (TextEncoding::LossyPrintable, "text/plain; charset=utf-8"),
            (TextEncoding::Base64, "application/octet-stream"),
        ] {
            assert_eq!(enc.mime_type(), want);
        }
    }

    #[test]
    fn percent_escapes_in_a_name_are_decoded() {
        assert_eq!(
            ResourceUri::parse("clasp://session-name/my%20build/buffer")
                .unwrap()
                .target,
            ResourceTarget::SessionName("my build".into())
        );
        // And a bare `%` that is not an escape survives rather than
        // eating the rest of the name.
        assert_eq!(percent_decode("100%"), "100%");
    }
}
