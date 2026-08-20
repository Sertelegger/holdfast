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
    /// Answers an outstanding [`ServerFrame::BindingApprovalRequired`]
    /// (§7.5, §9.6, §17.5). **ReadOnly clients: rejected** — §18.4's row
    /// names this frame explicitly, *"an authorisation decision, not an
    /// observation"*.
    ///
    /// **Between `Signal` and `Detach`, and that position is §7.5's.**
    /// The catalogue lists the client frames as `Input`, `SecretInput`,
    /// `Resize`, `Signal`, `ApproveBinding`, `Detach` — §5.2's
    /// `user_cancelled` note repeats the same six in the same order — and
    /// §18's preamble makes a catalogued position normative rather than
    /// decorative: a value is inserted where the table puts it and never
    /// appended. Here it is doubly load-bearing, because the declaration
    /// order **is** the order `serde`'s own variant list comes back in,
    /// and `tests/wire_shape.rs` records that list per protocol version.
    ///
    /// **No `decided_by` on the wire.** §9.4's `binding_approval` row
    /// carries one, and it is derived from the *connection*'s handshake
    /// `client_kind` — the same rule REQ-SEC-018 states for
    /// `redaction_disabled`. A field a client could fill in would be a
    /// self-declared identity in an authorisation record.
    ApproveBinding {
        approval_id: String,
        decision: ApprovalDecision,
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

/// §7.5's `ApproveBinding { decision }` — a **closed set of two**
/// (§18.4d, §9.6).
///
/// An enum and not a `String`, for exactly the reason [`SignalName`] is
/// one: §18.4 answers *"a closed-enum field carrying a value outside its
/// catalogue"* with `ProtocolError { reason: "protocol_violation",
/// frame_kind: … }` and **no part of the frame applied**, and a `String`
/// field cannot produce that answer — it decodes fine and leaves the
/// branch to a hand-written comparison downstream, whose natural spelling
/// (`decision == "approve"`) silently maps every typo onto *deny*. That is
/// a decision invented from a mistake, in an authorisation path.
///
/// With the enum, `decision: "maybe"` fails to deserialise into
/// [`ClientFrame`], [`decode_client_frame`] re-reads the `type`, finds
/// `ApproveBinding` in [`ClientFrameKind::ALL`], and answers
/// [`ClientDecode::BadFields`] — which `conn::read_loop` renders as
/// `protocol_violation` naming the frame. Identical machinery, no new
/// branch, and §18.4c's `sig` case is the standing precedent.
///
/// Lower case on the wire, like every attach-protocol vocabulary but
/// `mode` (§7.5: `mode`'s CamelCase *"is not a pattern to copy"*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalDecision {
    /// §17.5's `Approved`: resolve the reference, inject, zero, audit.
    Approve,
    /// §17.5's `Denied`: **fall through to the human-prompt path**
    /// (REQ-SEC-017). Not an error, and not an answer the agent ever sees
    /// as its own status — §18.1 deleted `binding_approval_denied`
    /// precisely because the fall-through is unconditional.
    Deny,
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
    /// §9.6's `require_confirm` approval, raised when a binding that
    /// carries it matches this session (§7.5, §17.5).
    ///
    /// **The binding's *name* and provider, never the reference and never
    /// the value** (REQ-SEC-016): *"approving is a decision about which
    /// credential, not an exposure of it."* The reference exists in the
    /// daemon's config at the moment this frame is built, so its absence
    /// here is a real omission and not an accident of ordering; the value
    /// does not exist yet at all, because resolution happens only *after*
    /// approval.
    ///
    /// **No expiry field, and that is REQ-T-018 rather than an
    /// oversight.** Rev. 47 widened the requirement to this surface and it
    /// now forbids a bare `expires_at`/`created_at` outright — a bare name
    /// being *"a claim the value does not support"*. If a later milestone
    /// puts the deadline on this frame (0.0.10 renders the same lifecycle
    /// at `GET /api/binding-approvals`), it is `expires_at_unix_secs`, an
    /// integer, from the first line it is written. §9.4's sibling defect
    /// on `confirmation/list_pending` is what that rule was learned from.
    ///
    /// **Between `SecretRequestClosed` and `ProtocolError`**, which is
    /// §7.5's order with `TransferProgress` (0.0.9) not yet present — see
    /// [`KNOWN_SERVER_TYPES`], whose comment already reserved the slot.
    BindingApprovalRequired {
        approval_id: String,
        /// §9.6's override key: *"the only part of a binding any surface
        /// shows"*.
        binding_name: String,
        /// The §9.6 config spelling, as `ArgvProvider::as_str` gives it.
        provider: String,
        /// The canonical session id, so a client watching several can put
        /// the affordance on the right one.
        session: String,
        /// The agent's `prompt_text` when a tool call raised the request
        /// and the raised text otherwise — **redacted either way**, on the
        /// same rule `AwaitingSecret.prompt_text` follows.
        prompt_text: String,
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
    ApproveBinding,
    Detach,
}

impl ClientFrameKind {
    /// Every kind, in wire order. Task 8 asserts the allowlist against
    /// this, so adding a variant without deciding its ReadOnly status
    /// fails a test rather than defaulting to permitted.
    pub const ALL: [ClientFrameKind; 7] = [
        Self::Attach,
        Self::Input,
        Self::SecretInput,
        Self::Resize,
        Self::Signal,
        Self::ApproveBinding,
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
            Self::ApproveBinding => "ApproveBinding",
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
            // **`ApproveBinding` is on this side by name, not by
            // default.** §18.4's row spells it out — *"including
            // `ApproveBinding` (an authorisation decision, not an
            // observation)"* — and §7.5 repeats it at the frame. It is
            // the one new kind whose ReadOnly status a reader might
            // guess at, because it writes nothing to the PTY and changes
            // no session state, which is the *shape* of the one frame
            // that will ever join the allowed side (§7.8.3's
            // `AttentionAck`). What separates them is that an `Ack` is a
            // statement about the client's own display and an approval
            // releases a credential.
            Self::Input
            | Self::SecretInput
            | Self::Resize
            | Self::Signal
            | Self::ApproveBinding => false,
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
            Self::ApproveBinding { .. } => ClientFrameKind::ApproveBinding,
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
            Self::BindingApprovalRequired { .. } => Some("BindingApprovalRequired"),
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
/// server list — restricted to the variants 0.0.7 implements.
/// `BindingApprovalRequired` **inserted** between `SecretRequestClosed`
/// and `TransferProgress` when 0.0.7 landed it, exactly where 0.0.6's
/// version of this comment reserved the slot; `TransferProgress` goes
/// between that and `ProtocolError` when 0.0.9 lands, and it does not
/// append either. Same rule §18's preamble states for the §18
/// catalogues, applied to §7.5's for the same reason: an array that can
/// be diffed against the document by eye is worth the arithmetic.
pub const KNOWN_SERVER_TYPES: &[&str] = &[
    "Attached",
    "AttachReject",
    "Output",
    "SessionExited",
    "Resize",
    "AwaitingSecret",
    "SecretRequestClosed",
    "BindingApprovalRequired",
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
    fn both_new_frames_encode_with_exactly_their_specified_keys() {
        // The same instrument `the_attach_frame_key_set_is_exactly_the_spec_list`
        // uses, for the same reason: a round-trip test is blind to a
        // field dropped by a `skip_serializing_if`, to a renamed one and
        // to an extra one, because it compares the type against itself.
        // §7.5 fixes these two key sets and REQ-SEC-016 fixes what is
        // *not* in the first of them.
        let f = encode(&ServerFrame::BindingApprovalRequired {
            approval_id: "appr_a1b2".into(),
            binding_name: "prod-ssh".into(),
            provider: "secret-service".into(),
            session: "sess_a1b2".into(),
            prompt_text: "a credential".into(),
        })
        .unwrap();
        assert_eq!(
            keys(&f),
            vec![
                "approval_id",
                "binding_name",
                "prompt_text",
                "provider",
                "session",
                "type",
            ],
            "§7.5's five fields and the tag — no `reference`, no `value`, and no bare \
             `expires_at` (REQ-SEC-016, REQ-T-018)"
        );
        assert_eq!(field(&f, "type").as_text(), Some("BindingApprovalRequired"));

        let f = encode(&ClientFrame::ApproveBinding {
            approval_id: "appr_a1b2".into(),
            decision: ApprovalDecision::Approve,
        })
        .unwrap();
        assert_eq!(
            keys(&f),
            vec!["approval_id", "decision", "type"],
            "§7.5's two fields and the tag — and no `decided_by`, which §9.4 derives from \
             the connection and never from the frame"
        );
        assert_eq!(field(&f, "type").as_text(), Some("ApproveBinding"));

        // **Both spellings of the closed set, read off the wire.** The
        // key set above is identical for either value, so without these
        // two lines the enum's serialisation is unpinned — and
        // `#[serde(rename_all = "lowercase")]` is one attribute away
        // from `"Approve"`, which is a different protocol.
        assert_eq!(field(&f, "decision").as_text(), Some("approve"));
        let denied = encode(&ClientFrame::ApproveBinding {
            approval_id: "appr_a1b2".into(),
            decision: ApprovalDecision::Deny,
        })
        .unwrap();
        assert_eq!(field(&denied, "decision").as_text(), Some("deny"));
    }

    #[test]
    fn a_decision_outside_the_closed_set_is_bad_fields_and_names_the_frame() {
        // §18.4's *"a closed-enum field carrying a value outside its
        // catalogue"* row, on the second frame that has one. The
        // classification is what `conn::read_loop` renders as
        // `ProtocolError { reason: "protocol_violation", frame_kind:
        // "ApproveBinding" }`, and it is asserted here as well as over
        // the socket because this is where a `String` field would change
        // the answer without changing any frame the socket test sends.
        let map = vec![
            (
                Cbor::Text("type".into()),
                Cbor::Text("ApproveBinding".into()),
            ),
            (
                Cbor::Text("approval_id".into()),
                Cbor::Text("appr_a1b2".into()),
            ),
            (Cbor::Text("decision".into()), Cbor::Text("maybe".into())),
        ];
        let body = encode(&Cbor::Map(map)).unwrap();
        match decode_client_frame(&body[4..]) {
            ClientDecode::BadFields(kind) => assert_eq!(kind.as_str(), "ApproveBinding"),
            other => panic!("expected BadFields(ApproveBinding), got {other:?}"),
        }

        // The pairing: the two catalogued values *do* decode, so the
        // refusal above is about `"maybe"` and not about a decoder that
        // rejects every `ApproveBinding`.
        for (spelling, expected) in [
            ("approve", ApprovalDecision::Approve),
            ("deny", ApprovalDecision::Deny),
        ] {
            let map = vec![
                (
                    Cbor::Text("type".into()),
                    Cbor::Text("ApproveBinding".into()),
                ),
                (
                    Cbor::Text("approval_id".into()),
                    Cbor::Text("appr_a1b2".into()),
                ),
                (
                    Cbor::Text("decision".into()),
                    Cbor::Text(spelling.to_string()),
                ),
            ];
            let body = encode(&Cbor::Map(map)).unwrap();
            match decode_client_frame(&body[4..]) {
                ClientDecode::Frame(ClientFrame::ApproveBinding { decision, .. }) => {
                    assert_eq!(decision, expected, "{spelling}")
                }
                other => panic!("{spelling} did not decode: {other:?}"),
            }
        }
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
            ServerFrame::BindingApprovalRequired {
                approval_id: "appr_1".into(),
                binding_name: "prod-ssh".into(),
                provider: "secret-service".into(),
                session: "s".into(),
                prompt_text: String::new(),
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
            10,
            "ten of §7.5's eleven; only TransferProgress (0.0.9) is deferred"
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
        //
        // **6 → 7 is 0.0.7's deliberate update**, licensed by §18.4:
        // `ApproveBinding` is a client frame and needs a `ClientFrameKind`
        // so the ReadOnly table can range over it.
        assert_eq!(ClientFrameKind::ALL.len(), 7);
        for k in ClientFrameKind::ALL {
            assert!(!k.as_str().is_empty());
        }
        assert_eq!(ClientFrame::Detach.kind().as_str(), "Detach");
        assert_eq!(
            ClientFrame::Input { bytes: vec![] }.kind().as_str(),
            "Input"
        );
        assert_eq!(
            ClientFrame::ApproveBinding {
                approval_id: "appr_1".into(),
                decision: ApprovalDecision::Approve,
            }
            .kind()
            .as_str(),
            "ApproveBinding"
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
        //
        // **`ApproveBinding` joins the denied side, and this is 0.0.7's
        // deliberate update to this row** — §18.4 rules it *"an
        // authorisation decision, not an observation"* and §7.5 repeats
        // the ruling at the frame. It is named in the loop below rather
        // than left to the count, because the count moving is what a
        // seventh kind does whichever side it lands on.
        assert!(ClientFrameKind::Detach.readonly_allowed());
        for k in [
            ClientFrameKind::Attach,
            ClientFrameKind::Input,
            ClientFrameKind::SecretInput,
            ClientFrameKind::Resize,
            ClientFrameKind::Signal,
            ClientFrameKind::ApproveBinding,
        ] {
            assert!(
                !k.readonly_allowed(),
                "{} is not writable from a ReadOnly connection",
                k.as_str()
            );
        }

        // The count is asserted separately from the names: an eighth
        // variant added to `ALL` without a decision about its ReadOnly
        // status would otherwise slip through the loop above, which only
        // ranges over the six it names.
        assert_eq!(
            ClientFrameKind::ALL.len(),
            7,
            "a new frame kind needs a ReadOnly decision, not a default"
        );
    }
}
