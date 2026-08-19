//! The §7.5 frame catalog.
//!
//! Each frame is a CBOR map with a string `type` field plus the variant's
//! other fields (§7.5: tagged-union via a `type` discriminator, chosen
//! over CBOR semantic tags for human-debuggability and cross-language
//! client portability).
//!
//! **No `deny_unknown_fields` anywhere in this file, deliberately.**
//! §12.3 makes same-major-different-minor forwards *and* backwards
//! compatible by adding optional fields; denying unknown fields turns
//! every future additive field into a hard break in one direction. The
//! falsifiability that attribute buys elsewhere is bought here by the
//! byte-pinned key-set tests at the bottom of this file.
//!
//! Strictness lives at the *variant* level, and it is asymmetric:
//!
//! * A **client** frame with an unrecognised `type` is a
//!   `ProtocolError { reason: "protocol_violation" }`. The daemon cannot
//!   act on a frame it does not understand, and silently discarding a
//!   client's write frame is worse than saying so.
//! * A **server** frame with an unrecognised `type` is *skipped* by the
//!   client ([`ServerFrame::Unknown`]). This is what lets §7.8's
//!   `AttentionRequired`/`AttentionResolved` land additively on an
//!   already-shipped protocol (REQ-SURF-002: "v0.1.0 clients that ignore
//!   the envelope still function unchanged"). Removing it is a major bump.

use serde::{Deserialize, Serialize};

use crate::protocol::handshake::ClientKind;

/// Whether a connection may write to the session (§7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachMode {
    ReadWrite,
    ReadOnly,
}

impl AttachMode {
    /// The wire spelling, and therefore §9.4's `mode` column.
    ///
    /// Beside the type rather than at the audit call site, so the token
    /// the log records and the token the wire carries cannot drift: this
    /// enum has no `rename_all`, so CamelCase **is** the serialisation.
    /// §7.5 notes that the CamelCase is inherited from §4.3 and *"is not
    /// a pattern to copy"* — which is exactly why it needs writing down
    /// once rather than retyping at every site.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadWrite => "ReadWrite",
            Self::ReadOnly => "ReadOnly",
        }
    }
}

/// Whether a connection receives raw or redacted bytes (§7.5, §9.2,
/// REQ-SEC-008a).
///
/// Orthogonal to [`AttachMode`]: `mode` answers *may this connection
/// write?*, `role` answers *does it get raw bytes?*. §7.5's orthogonality
/// paragraph is normative and forbids deriving this from `client_kind`,
/// from `mode`, or from which CLI dialled in; a client with a live
/// terminal pane and a watching pane opens **one connection per pane**.
/// Lower-case on the wire, like every other attach-protocol enum —
/// `mode`'s CamelCase is inherited from §4.3 and §7.5 says in as many
/// words that it "is not a pattern to copy".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttachRole {
    /// Raw fidelity. `holdfast attach`, and the web UI's live terminal.
    /// A redacted password prompt would corrupt what the human types
    /// back (§9.2).
    Interactive,
    /// Redacted. `holdfast watch`, and the web UI's "watching" mode.
    ///
    /// **`#[default]` — redacted is the default**, so a client that
    /// omits the field (an older one, or one whose author did not think
    /// about it) gets the safe stream. Raw fidelity must be asked for.
    ///
    /// Derived rather than a hand-written `impl Default`: enum defaults
    /// have been derivable via `#[default]` since Rust 1.62, and
    /// clippy's `derivable_impls` fires on the hand-written form — which
    /// Task 13 Step 5's `-D warnings` makes fatal.
    #[default]
    Observer,
}

impl AttachRole {
    /// The wire spelling, and therefore §9.4's `role` column — which is
    /// on **both** attach rows (REQ-SEC-008a), because the two entries
    /// share no connection identifier and "did this client receive raw
    /// output, and for how long?" would otherwise mean pairing connects
    /// to disconnects by ordering and hoping.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Observer => "observer",
        }
    }
}

/// Client → server (§7.5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientFrame {
    /// The mandatory initial frame. Anything else first is
    /// `ProtocolError { reason: "no_handshake" }` and closes.
    Attach {
        /// Session id **or** name; `Attached.session_id` answers with the
        /// canonical id either way.
        session: String,
        mode: AttachMode,
        /// **Optional on the wire; absent means `observer`** (§7.5).
        /// A client built against an older minor that has never heard
        /// of the field must not be handed unredacted output by
        /// omission. §25 carries the row, because the redacted stream
        /// arriving where raw was expected reads as a defect.
        #[serde(default)]
        role: AttachRole,
        client_kind: ClientKind,
        client_version: String,
        protocol_major: u32,
        protocol_minor: u32,
    },
    Input {
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    SecretInput {
        request_id: String,
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    Signal {
        sig: SignalName,
    },
    Detach,
}

/// §7.5's `Signal { sig }`. The spec gives "e.g., Ctrl+C, mapped to a
/// process-group signal — see §4.4" and enumerates nothing; these three
/// are the ones `crate::pty::Signal` can deliver. §18.4c (rev. 33)
/// catalogues exactly these three, with a per-value §4.4 delivery
/// target and the argument for why the set stops there.
///
/// **Declaration order is §18.4c's row order**, per §18's preamble
/// (rev. 47): where an implementation mirrors a §18 table as an enum,
/// the declaration order *is* the table's order restricted to the
/// implemented variants, so a value is inserted at its catalogued
/// position and never appended. This is the one §18 enum 0.0.6
/// declares; the order below is already correct and
/// `the_signal_names_are_the_three_18_4c_values_in_catalogue_order`
/// keeps it that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalName {
    /// SIGINT to the **foreground** group (`tcgetpgrp`), §4.4.
    Int,
    /// SIGTERM session sweep, §4.4.
    Term,
    /// SIGKILL session sweep, §4.4.
    Kill,
}

/// Server → client (§7.5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerFrame {
    Attached {
        session_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        cols: u16,
        rows: u16,
        /// `"Starting" | "Running" | "Exited" | "Dead"` — the same
        /// `SessionState::as_str()` the MCP surface already emits, with
        /// the code carried beside it. §7.5 writes this as
        /// `"Exited(code)"`; rev. 33 corrected it to the §18.2a bare
        /// token with the code in this sibling, *"never `\"Exited(0)\"`"*.
        /// §25 also records `dead_reason` as proposed and **rejected**.
        state: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        protocol_major: u32,
        protocol_minor: u32,
    },
    AttachReject {
        reason: String,
        message: String,
    },
    Output {
        session: String,
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    SessionExited {
        code: i32,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    AwaitingSecret {
        request_id: String,
        prompt_text: String,
    },
    SecretRequestClosed {
        request_id: String,
        /// `"fulfilled" | "cancelled" | "timeout"` (§7.5).
        outcome: String,
    },
    ProtocolError {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        frame_kind: Option<String>,
    },
    Detached {
        reason: String,
    },
    /// A `type` this build does not know. **Never constructed by the
    /// daemon and never encoded** — produced only by
    /// [`decode_server_frame`] so a client can skip forward.
    ///
    /// `#[serde(skip)]` on a variant of an internally-tagged enum is a
    /// **runtime** error, not a compile-time one: measured on ciborium
    /// 0.2.2, `into_writer(&ServerFrame::Unknown { .. })` returns
    /// `Err(Value("the enum variant ServerFrame::Unknown cannot be
    /// serialized"))`. So "never encoded" is a claim nothing enforces.
    /// The send site carries a `debug_assert!(!matches!(f,
    /// ServerFrame::Unknown { .. }), "Unknown is decode-only")` (Task 6,
    /// where the hub writes frames) so a debug build fails loudly at the
    /// line that made the mistake rather than dropping a frame in
    /// release.
    #[serde(skip)]
    Unknown {
        type_name: String,
    },
}

/// The frame kinds ReadOnly enforcement ranges over (§7.5, §4.3). A
/// separate enum, not `std::mem::discriminant`, because Task 8's
/// allowlist must be *enumerable* — a table you can assert the whole of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientFrameKind {
    Attach,
    Input,
    SecretInput,
    Resize,
    Signal,
    Detach,
}

impl ClientFrameKind {
    /// Every kind, in wire order. Task 8 asserts the allowlist against
    /// this, so adding a variant without deciding its ReadOnly status
    /// fails a test rather than defaulting to permitted.
    pub const ALL: [ClientFrameKind; 6] = [
        Self::Attach,
        Self::Input,
        Self::SecretInput,
        Self::Resize,
        Self::Signal,
        Self::Detach,
    ];

    /// The exact string that goes in `ProtocolError.frame_kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attach => "Attach",
            Self::Input => "Input",
            Self::SecretInput => "SecretInput",
            Self::Resize => "Resize",
            Self::Signal => "Signal",
            Self::Detach => "Detach",
        }
    }
}

// A **second** `impl ClientFrameKind` block. Task 2's — `ALL` and
// `as_str` — stays exactly as it is, above this one: merging the two
// would put the ReadOnly policy in the same place as the wire spellings,
// and it is the wire spellings that must not move.
impl ClientFrameKind {
    /// Which frames a `mode: ReadOnly` connection may send (§7.5).
    ///
    /// A **table**, not `matches!(f, Detach)`, because REQ-SURF-004a adds
    /// exactly one kind to this list when §7.8 ships: `AttentionAck` —
    /// an observation about the client's own display, which writes
    /// nothing to the PTY, changes no session state, and cannot answer
    /// anything. A table makes that a one-row edit and makes
    /// `the_readonly_allowlist_is_exactly_detach` the thing that notices.
    ///
    /// **`Attach` is in the table rather than short-circuited before it**,
    /// and the ordering at the call site is what makes that row reachable:
    /// `conn::read_loop` consults this gate *before* the out-of-order
    /// `Attach` arm, so a second `Attach` from a ReadOnly client is
    /// answered `read_only_attach` and from a ReadWrite client
    /// `protocol_violation`. §18.4's `read_only_attach` row is *"any frame
    /// but `Detach` from a `ReadOnly` client"*, with no carve-out. Check
    /// the gate second and this row can never be reached by any input,
    /// which is a policy nobody can observe.
    pub fn readonly_allowed(self) -> bool {
        match self {
            Self::Detach => true,
            Self::Attach => false,
            Self::Input | Self::SecretInput | Self::Resize | Self::Signal => false,
        }
    }
}

impl ClientFrame {
    pub fn kind(&self) -> ClientFrameKind {
        match self {
            Self::Attach { .. } => ClientFrameKind::Attach,
            Self::Input { .. } => ClientFrameKind::Input,
            Self::SecretInput { .. } => ClientFrameKind::SecretInput,
            Self::Resize { .. } => ClientFrameKind::Resize,
            Self::Signal { .. } => ClientFrameKind::Signal,
            Self::Detach => ClientFrameKind::Detach,
        }
    }
}

/// Decode a server frame body, mapping an unrecognised `type` onto
/// [`ServerFrame::Unknown`] instead of an error.
///
/// This is the forward-compatibility seam. A client built today must
/// keep running when a newer daemon sends a frame it has never heard of
/// — §12.3's minor-compatibility rule, and the precondition for §7.8
/// landing additively (REQ-SURF-002).
pub fn decode_server_frame(body: &[u8]) -> Result<ServerFrame, crate::protocol::FrameError> {
    match crate::protocol::frame::decode::<ServerFrame>(body) {
        Ok(f) => Ok(f),
        Err(e) => {
            // Distinguish "type we don't know" from "corrupt bytes" by
            // re-reading the map's `type` key. A body that is not even a
            // map with a string `type` is a genuine decode error.
            match crate::protocol::frame::decode::<ciborium::value::Value>(body) {
                Ok(ciborium::value::Value::Map(entries)) => {
                    for (k, v) in &entries {
                        if k.as_text() != Some("type") {
                            continue;
                        }
                        match v.as_text() {
                            Some(name) if !KNOWN_SERVER_TYPES.contains(&name) => {
                                return Ok(ServerFrame::Unknown {
                                    type_name: name.to_string(),
                                });
                            }
                            _ => {}
                        }
                    }
                    Err(e)
                }
                _ => Err(e),
            }
        }
    }
}

/// What a client frame body turned out to be.
///
/// The **asymmetric** half of the strictness rule this module's header
/// states: a server frame with an unknown `type` is skipped by the
/// client, and a client frame with an unknown `type` is a
/// `ProtocolError`. The daemon cannot act on a frame it does not
/// understand, and silently discarding a client's *write* frame is
/// worse than saying so.
#[derive(Debug)]
pub enum ClientDecode {
    Frame(ClientFrame),
    /// A `type` this build has never heard of. §18.4's
    /// `protocol_violation`, with this name echoed in
    /// `ProtocolError.frame_kind` — which is the whole reason the name
    /// is carried out rather than folded into [`Self::Malformed`]. A
    /// client that sent `Attch` learns which word was wrong.
    UnknownType(String),
    /// A `type` this build **does** implement, whose fields did not fit:
    /// a `Signal` with `sig: "stop"`, a `Resize` with a `cols` that is
    /// not a number, a missing required field.
    ///
    /// **Split out of [`Self::Malformed`] by Task 9, and §18.4c is why.**
    /// A `sig` outside `{int, term, kill}` must be answered
    /// `ProtocolError { reason: "protocol_violation", frame_kind:
    /// Some("Signal") }` — the kind is *nameable* here, and folding this
    /// case into `Malformed` makes it unnameable, which is a wire-shape
    /// difference and not a stylistic one. This module's earlier comment
    /// argued the opposite ("naming the kind there would say the wrong
    /// thing about why it failed"); §18.4c settles it the other way, and
    /// the reason it is right is that a client sending `sig: "9"` can act
    /// on "your Signal frame was wrong" and cannot act on "something you
    /// sent was wrong".
    BadFields(ClientFrameKind),
    /// Not a frame at all: bytes that are not CBOR, CBOR that is not a
    /// map, or a map with no string `type`. `frame_kind` is `None`,
    /// because there is nothing to name.
    Malformed,
}

/// Decode a client frame body, telling an unknown `type` from a
/// malformed one.
///
/// The mirror of [`decode_server_frame`], and deliberately *not* the
/// same answer: that one returns [`ServerFrame::Unknown`] so a client
/// can skip forward, this one returns a name so the daemon can refuse
/// by name. §12.3's minor-compatibility rule runs one way on this wire.
pub fn decode_client_frame(body: &[u8]) -> ClientDecode {
    if let Ok(f) = crate::protocol::frame::decode::<ClientFrame>(body) {
        return ClientDecode::Frame(f);
    }
    // Re-read the map's `type` to separate the three failures. A body
    // that is not a map with a string `type` is malformed; a `type` this
    // build does not implement is an unknown variant; a `type` it *does*
    // implement whose fields did not fit is `BadFields`, which is the
    // case that can name a kind.
    let Ok(ciborium::value::Value::Map(entries)) =
        crate::protocol::frame::decode::<ciborium::value::Value>(body)
    else {
        return ClientDecode::Malformed;
    };
    for (k, v) in &entries {
        if k.as_text() != Some("type") {
            continue;
        }
        if let Some(name) = v.as_text() {
            return match ClientFrameKind::ALL
                .iter()
                .find(|kind| kind.as_str() == name)
            {
                Some(kind) => ClientDecode::BadFields(*kind),
                None => ClientDecode::UnknownType(name.to_string()),
            };
        }
    }
    ClientDecode::Malformed
}

impl ServerFrame {
    /// This frame's wire `type` string, or `None` for the decode-only
    /// [`ServerFrame::Unknown`].
    ///
    /// **This match is the pin on [`KNOWN_SERVER_TYPES`], and it is
    /// exhaustive on purpose — no `_` arm.** §7.6.3 kept a second,
    /// hand-copied enumeration of this same frame set and it drifted
    /// three ways before anything was built; rev. 47 withdrew it. A
    /// `const` array is that artifact in Rust, so adding a variant to
    /// `ServerFrame` without adding it here must be a **compile**
    /// error rather than a silently short list. Do not add a catch-all.
    pub fn tag(&self) -> Option<&'static str> {
        match self {
            Self::Attached { .. } => Some("Attached"),
            Self::AttachReject { .. } => Some("AttachReject"),
            Self::Output { .. } => Some("Output"),
            Self::SessionExited { .. } => Some("SessionExited"),
            Self::Resize { .. } => Some("Resize"),
            Self::AwaitingSecret { .. } => Some("AwaitingSecret"),
            Self::SecretRequestClosed { .. } => Some("SecretRequestClosed"),
            Self::ProtocolError { .. } => Some("ProtocolError"),
            Self::Detached { .. } => Some("Detached"),
            Self::Unknown { .. } => None,
        }
    }
}

/// Every `type` string this build produces, **in §7.5's order**. Used
/// only by [`decode_server_frame`] to tell a future frame from a broken
/// one.
///
/// The order is §7.5's — the two handshake frames, then the bulleted
/// server list — restricted to the variants 0.0.6 implements.
/// `BindingApprovalRequired` inserts between `SecretRequestClosed` and
/// `TransferProgress` when 0.0.7 lands it, and `TransferProgress`
/// between that and `ProtocolError` when 0.0.9 does; **neither
/// appends**. Same rule §18's preamble states for the §18 catalogues,
/// applied to §7.5's for the same reason: an array that can be diffed
/// against the document by eye is worth the arithmetic.
pub const KNOWN_SERVER_TYPES: &[&str] = &[
    "Attached",
    "AttachReject",
    "Output",
    "SessionExited",
    "Resize",
    "AwaitingSecret",
    "SecretRequestClosed",
    "ProtocolError",
    "Detached",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::frame::{decode, encode};
    use ciborium::value::Value as Cbor;

    /// The decoded key set of an encoded frame, sorted.
    fn keys(frame_bytes: &[u8]) -> Vec<String> {
        let body = &frame_bytes[4..];
        let v: Cbor = decode(body).unwrap();
        let Cbor::Map(entries) = v else {
            panic!("a frame must encode as a CBOR map (§7.5)");
        };
        let mut ks: Vec<String> = entries
            .iter()
            .map(|(k, _)| k.as_text().expect("keys are text").to_string())
            .collect();
        ks.sort();
        ks
    }

    fn field(frame_bytes: &[u8], name: &str) -> Cbor {
        let v: Cbor = decode(&frame_bytes[4..]).unwrap();
        let Cbor::Map(entries) = v else {
            unreachable!()
        };
        entries
            .into_iter()
            .find(|(k, _)| k.as_text() == Some(name))
            .unwrap_or_else(|| panic!("no field {name}"))
            .1
    }

    #[test]
    fn output_bytes_encode_as_a_cbor_byte_string_not_an_array() {
        // THE load-bearing encoding test. A plain Vec<u8> serialises as
        // CBOR major type 4 (array of integers): three bytes per byte,
        // and unreadable as `bytes` by any other implementation. It
        // round-trips against itself perfectly, so only an assertion on
        // the CBOR major type can see the difference. §7.5 says <bstr>.
        let f = encode(&ServerFrame::Output {
            session: "sess_a1b2".into(),
            bytes: vec![0u8; 300],
        })
        .unwrap();
        assert!(
            matches!(field(&f, "bytes"), Cbor::Bytes(ref b) if b.len() == 300),
            "bytes must be a CBOR byte string (major type 2), not an array"
        );
        // 300 bytes as a bstr is 0x59 0x01 0x2C + 300 = 303 bytes; as an
        // array of 300 zero integers it would be 1 + 2 + 300 = 303 too,
        // so length alone cannot distinguish them. The variant check
        // above is the assertion; this one guards the frame's overall
        // size against a base64-in-a-string implementation.
        assert!(
            f.len() < 4 + 400,
            "frame is {} bytes; bytes were widened",
            f.len()
        );
    }

    #[test]
    fn secret_input_bytes_are_also_a_byte_string() {
        let f = encode(&ClientFrame::SecretInput {
            request_id: "secreq_1".into(),
            bytes: (0u8..=255).collect(),
        })
        .unwrap();
        assert!(matches!(field(&f, "bytes"), Cbor::Bytes(ref b) if b.len() == 256));
    }

    #[test]
    fn input_carries_every_byte_value_unchanged() {
        let original = ClientFrame::Input {
            bytes: (0u8..=255).collect(),
        };
        let f = encode(&original).unwrap();
        let back: ClientFrame = decode(&f[4..]).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn every_frame_carries_the_spec_type_tag() {
        // §7.5's examples, literally.
        for (frame, tag) in [
            (
                ServerFrame::Output {
                    session: "sess_a1b2".into(),
                    bytes: b"hi".to_vec(),
                },
                "Output",
            ),
            (
                ServerFrame::ProtocolError {
                    reason: "read_only_attach".into(),
                    frame_kind: Some("Input".into()),
                },
                "ProtocolError",
            ),
            (ServerFrame::SessionExited { code: 0 }, "SessionExited"),
            (
                ServerFrame::Detached {
                    reason: "slow_consumer".into(),
                },
                "Detached",
            ),
        ] {
            let f = encode(&frame).unwrap();
            assert_eq!(field(&f, "type").as_text(), Some(tag));
        }
    }

    #[test]
    fn the_attach_frame_key_set_is_exactly_the_spec_list() {
        // This is what replaces deny_unknown_fields. A field silently
        // dropped, renamed, or added fails here — a round-trip test is
        // blind to all three.
        let f = encode(&ClientFrame::Attach {
            session: "sess_a1b2".into(),
            mode: AttachMode::ReadWrite,
            role: AttachRole::Interactive,
            client_kind: ClientKind::Cli,
            client_version: "0.0.6".into(),
            protocol_major: 1,
            protocol_minor: 0,
        })
        .unwrap();
        assert_eq!(
            keys(&f),
            vec![
                "client_kind",
                "client_version",
                "mode",
                "protocol_major",
                "protocol_minor",
                "role",
                "session",
                "type",
            ]
        );
    }

    #[test]
    fn the_attached_frame_key_set_is_exactly_the_spec_list() {
        let f = encode(&ServerFrame::Attached {
            session_id: "sess_a1b2".into(),
            name: Some("build".into()),
            cols: 120,
            rows: 40,
            state: "Running".into(),
            exit_code: None,
            protocol_major: 1,
            protocol_minor: 0,
        })
        .unwrap();
        assert_eq!(
            keys(&f),
            vec![
                "cols",
                "name",
                "protocol_major",
                "protocol_minor",
                "rows",
                "session_id",
                "state",
                "type",
            ],
            "exit_code is skipped when None; name is not"
        );
    }

    #[test]
    fn mode_and_role_are_independent_fields_with_the_spec_spellings() {
        let f = encode(&ClientFrame::Attach {
            session: "s".into(),
            mode: AttachMode::ReadOnly,
            role: AttachRole::Observer,
            client_kind: ClientKind::Cli,
            client_version: "0.0.6".into(),
            protocol_major: 1,
            protocol_minor: 0,
        })
        .unwrap();
        // §7.5 spells the modes in PascalCase and `role` in lower case,
        // and says so explicitly: `mode`'s CamelCase is inherited from
        // §4.3 "and is not a pattern to copy". Every other wire enum in
        // this protocol is lower case (`outcome`, `sig`, `reason`).
        assert_eq!(field(&f, "mode").as_text(), Some("ReadOnly"));
        assert_eq!(field(&f, "role").as_text(), Some("observer"));
    }

    #[test]
    fn an_attach_frame_without_a_role_defaults_to_the_redacted_stream() {
        // A pre-rev.-32 client omits `role`. The safe stream is the
        // default; raw fidelity must be asked for. An implementation
        // that defaulted to Interactive would hand raw secrets to every
        // client that had not heard of the field.
        let mut map = vec![
            (Cbor::Text("type".into()), Cbor::Text("Attach".into())),
            (Cbor::Text("session".into()), Cbor::Text("s".into())),
            (Cbor::Text("mode".into()), Cbor::Text("ReadOnly".into())),
            (Cbor::Text("client_kind".into()), Cbor::Text("cli".into())),
            (
                Cbor::Text("client_version".into()),
                Cbor::Text("0.0.5".into()),
            ),
            (Cbor::Text("protocol_major".into()), Cbor::Integer(1.into())),
            (Cbor::Text("protocol_minor".into()), Cbor::Integer(0.into())),
        ];
        map.sort_by_key(|(k, _)| k.as_text().unwrap().to_string());
        let body = encode(&Cbor::Map(map)).unwrap();
        let f: ClientFrame = decode(&body[4..]).unwrap();
        assert!(matches!(
            f,
            ClientFrame::Attach {
                role: AttachRole::Observer,
                ..
            }
        ));
    }

    #[test]
    fn an_unknown_server_frame_type_is_skipped_and_the_stream_continues() {
        // The §7.8 forward-compatibility seam (REQ-SURF-002). A client
        // built today must survive a newer daemon's AttentionRequired.
        let map = vec![
            (
                Cbor::Text("type".into()),
                Cbor::Text("AttentionRequired".into()),
            ),
            (
                Cbor::Text("attention_id".into()),
                Cbor::Text("att_1".into()),
            ),
            (Cbor::Text("kind".into()), Cbor::Text("secret".into())),
        ];
        let body = encode(&Cbor::Map(map)).unwrap();
        let f = decode_server_frame(&body[4..]).unwrap();
        assert_eq!(
            f,
            ServerFrame::Unknown {
                type_name: "AttentionRequired".into()
            }
        );
    }

    #[test]
    fn corrupt_bytes_are_still_an_error_not_an_unknown_frame() {
        // The negative that separates "skip the future" from "swallow
        // everything". Without it, decode_server_frame could return
        // Unknown for genuine corruption and the previous test would
        // still pass.
        assert!(decode_server_frame(&[0xff, 0xff, 0xff]).is_err());
        let no_type = encode(&Cbor::Map(vec![(
            Cbor::Text("session".into()),
            Cbor::Text("s".into()),
        )]))
        .unwrap();
        assert!(decode_server_frame(&no_type[4..]).is_err());
    }

    #[test]
    fn known_server_types_is_exactly_the_declared_variants_in_spec_order() {
        // KNOWN_SERVER_TYPES is a second enumeration of ServerFrame, and
        // §7.6.3's hand-copied frame lists are the worked example of what
        // happens to those: three omissions before anything was built,
        // withdrawn at rev. 47. Two guards, and both are needed.
        //
        // (1) Membership, pinned by an exhaustive match. `tag()` has no
        // catch-all, so a new variant is a compile error there; this
        // asserts the array caught up.
        let one_of_each = [
            ServerFrame::Attached {
                session_id: "s".into(),
                name: None,
                cols: 80,
                rows: 24,
                state: "Running".into(),
                exit_code: None,
                protocol_major: 1,
                protocol_minor: 0,
            },
            ServerFrame::AttachReject {
                reason: "session_not_found".into(),
                message: "m".into(),
            },
            ServerFrame::Output {
                session: "s".into(),
                bytes: vec![],
            },
            ServerFrame::SessionExited { code: 0 },
            ServerFrame::Resize { cols: 80, rows: 24 },
            ServerFrame::AwaitingSecret {
                request_id: "r".into(),
                prompt_text: String::new(),
            },
            ServerFrame::SecretRequestClosed {
                request_id: "r".into(),
                outcome: "fulfilled".into(),
            },
            ServerFrame::ProtocolError {
                reason: "read_only_attach".into(),
                frame_kind: None,
            },
            ServerFrame::Detached {
                reason: "session_exit".into(),
            },
        ];
        let tags: Vec<&str> = one_of_each.iter().filter_map(|f| f.tag()).collect();
        // (2) **Sequence, not set.** A sorted or membership comparison is
        // green against every append, which is the fault §18's preamble
        // names for its own catalogues and which applies verbatim to a
        // frame list. This asserts §7.5's order.
        assert_eq!(tags.as_slice(), KNOWN_SERVER_TYPES);
        assert_eq!(
            KNOWN_SERVER_TYPES.len(),
            9,
            "nine of §7.5's eleven; two are deferred"
        );
        // The negative: Unknown is decode-only and must not be in the
        // list, or decode_server_frame would refuse to produce it.
        assert!(ServerFrame::Unknown {
            type_name: "X".into()
        }
        .tag()
        .is_none());
        assert!(!KNOWN_SERVER_TYPES.contains(&"Unknown"));
    }

    #[test]
    fn the_signal_names_are_the_three_18_4c_values_in_catalogue_order() {
        // §18's preamble (rev. 47): an enum mirroring a §18 table
        // declares its variants in that table's order. §18.4c's rows are
        // int, term, kill — in that order, and not alphabetically, and
        // not by signal number.
        //
        // **Three separate facts, because an assertion over the wire
        // spellings alone catches only the first — measured, not
        // assumed.** This test was written as that assertion, and the
        // mutation its own plan row names for it (reorder `SignalName`
        // to `Kill, Int, Term`) left it **green**: a hand-written
        // `[Int, Term, Kill]` array carries its own order and cannot see
        // the declaration's, and a hand-written array of three is blind
        // to a fourth variant as well. Both properties the comment
        // claimed were unasserted, so they are asserted below.
        //
        // (1) The wire spelling of each value. Read through the same
        // `field()` helper the rest of this module uses, so the
        // assertion is about the wire and not about a `Serialize` impl
        // in isolation.
        let wire: Vec<String> = [SignalName::Int, SignalName::Term, SignalName::Kill]
            .into_iter()
            .map(|sig| {
                let f = encode(&ClientFrame::Signal { sig }).unwrap();
                field(&f, "sig").as_text().expect("sig is text").to_string()
            })
            .collect();
        assert_eq!(wire, vec!["int", "term", "kill"]);

        // (2) The **declaration** order, read out of the compiler rather
        // than out of a list this test wrote. A fieldless enum's
        // discriminant is its declaration index, so this is the one
        // reading of the order that a reordering cannot restate.
        assert_eq!(SignalName::Int as u8, 0, "§18.4c's first row is int");
        assert_eq!(SignalName::Term as u8, 1, "§18.4c's second row is term");
        assert_eq!(SignalName::Kill as u8, 2, "§18.4c's third row is kill");

        // (3) That the catalogue stops at three. §18.4c argues a fourth
        // value must not exist, and no assertion over a three-element
        // array can see one being added — so the closure is pinned by an
        // exhaustive match with no catch-all, making a fourth variant a
        // **compile** error here. Same discipline `ServerFrame::tag()`
        // uses to keep `KNOWN_SERVER_TYPES` from going short.
        fn catalogue_position(sig: SignalName) -> u8 {
            match sig {
                SignalName::Int => 0,
                SignalName::Term => 1,
                SignalName::Kill => 2,
            }
        }
        for sig in [SignalName::Int, SignalName::Term, SignalName::Kill] {
            assert_eq!(catalogue_position(sig), sig as u8, "{sig:?}");
        }
    }

    #[test]
    fn client_frame_kinds_cover_every_variant() {
        // ALL is what Task 8's allowlist ranges over. A variant added to
        // ClientFrame without a matching ClientFrameKind makes the
        // ReadOnly table silently incomplete.
        assert_eq!(ClientFrameKind::ALL.len(), 6);
        for k in ClientFrameKind::ALL {
            assert!(!k.as_str().is_empty());
        }
        assert_eq!(ClientFrame::Detach.kind().as_str(), "Detach");
        assert_eq!(
            ClientFrame::Input { bytes: vec![] }.kind().as_str(),
            "Input"
        );
    }

    #[test]
    fn the_readonly_allowlist_is_exactly_detach() {
        // §7.5's ReadOnly rule as a table that can be read whole, which
        // is the property `matches!(f, Detach)` does not have. Both
        // directions are asserted: a kind moved onto the allowed side
        // fails, and a kind moved off it fails. When §7.8 lands
        // `AttentionAck` (REQ-SURF-004a) this is the row that has to be
        // edited on purpose.
        let allowed: Vec<&'static str> = ClientFrameKind::ALL
            .into_iter()
            .filter(|k| k.readonly_allowed())
            .map(ClientFrameKind::as_str)
            .collect();
        assert_eq!(
            allowed,
            vec!["Detach"],
            "exactly one kind is permitted from a ReadOnly connection"
        );

        // By name, so a failure says which kind changed side rather than
        // that a count moved.
        assert!(ClientFrameKind::Detach.readonly_allowed());
        for k in [
            ClientFrameKind::Attach,
            ClientFrameKind::Input,
            ClientFrameKind::SecretInput,
            ClientFrameKind::Resize,
            ClientFrameKind::Signal,
        ] {
            assert!(
                !k.readonly_allowed(),
                "{} is not writable from a ReadOnly connection",
                k.as_str()
            );
        }

        // The count is asserted separately from the names: a seventh
        // variant added to `ALL` without a decision about its ReadOnly
        // status would otherwise slip through the loop above, which only
        // ranges over the five it names.
        assert_eq!(
            ClientFrameKind::ALL.len(),
            6,
            "a new frame kind needs a ReadOnly decision, not a default"
        );
    }
}
