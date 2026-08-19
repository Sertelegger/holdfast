//! The submitted secret, between the wire and the PTY — and the
//! per-session slot that says one is outstanding (§5.2, §9.5, §9.6).
//!
//! **Nothing here crosses the MCP surface.** 0.0.6 raises the request
//! from an ECHO drop and delivers the answer; it returns no status to an
//! agent, because it has no tool to return one from. The agent cannot
//! name a secret, cannot read one, and does not learn that one was
//! solicited: §9.4's `secret_input_request` entry *"records a tool call,
//! and there was none"*, and a raise with no adopting call produces no
//! audit entry at all. That is the spec's disposition, not an omission
//! here — until §7.8 ships, the raise is visible to attached clients and
//! nowhere else.

/// The submitted secret. Milliseconds of lifetime, and no other exits
/// (§9.5).
///
/// Every property below is load-bearing and each has a guard:
///
/// * **No `Serialize`, and the build fails if anyone adds one** — see
///   [`secret_is_not_serializable`]. The type cannot be put into an MCP
///   response, an audit record, a `daemon.log` line, or a broadcast
///   frame, because none of those paths can accept a value that does not
///   serialise. This is the structural half of REQ-SEC-004. §9.2 is
///   explicit that the value is not *redacted* but **absent**, so there
///   is no second line of defence downstream.
/// * **No `Clone`.** One owner, one write, one drop.
/// * **Hand-written `Debug`.** `#[derive(Debug)]` would put the value in
///   the first `tracing` line anybody adds.
/// * **`Drop` zeroes, and no method hands the bytes out.** §9.6:
///   *"zeroed immediately after write."*
pub struct SecretBytes(Vec<u8>);

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes(<redacted, {} bytes>)", self.0.len())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SecretBytes {
    /// §5.2's normalisation, applied by the **daemon** so the behaviour
    /// does not depend on which client submitted: strip exactly one
    /// trailing `\r\n` or `\n`, then append `\n` when `append_newline`.
    /// Clients must not add the newline themselves.
    pub fn normalise(mut raw: Vec<u8>, append_newline: bool) -> Self {
        if raw.ends_with(b"\r\n") {
            raw.truncate(raw.len() - 2);
        } else if raw.ends_with(b"\n") {
            raw.truncate(raw.len() - 1);
        }
        if append_newline {
            raw.push(b'\n');
        }
        Self(raw)
    }

    /// The only reader: a **scoped** accessor. The bytes are borrowed for
    /// the duration of `f` and never escape the type, so the zeroing
    /// `Drop` still owns every copy.
    ///
    /// **There is deliberately no `into_pty_write(self) -> Vec<u8>`.** An
    /// earlier revision of the design had one, and it undid the whole
    /// thing at the one call site that matters: it yielded a plain
    /// `Vec<u8>` whose `Drop` does not zero, and that `Vec` then crossed
    /// the session write channel unprotected. A leak sanctioned by the
    /// type's own API is worse than one bolted on beside it, because it
    /// reads as intended.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.0)
    }

    /// What [`Drop`] does, as a method a test can call **while the
    /// allocation is still ours**.
    ///
    /// The obvious test — drop the value, then read the buffer back
    /// through a raw pointer — was written first and does not work. It
    /// reads freed memory, and the allocator has already written its own
    /// freelist bookkeeping there: measured, `hunter2` came back as
    /// `[34, 249, 249, 179, 76, 101, 0]`, which is neither the secret nor
    /// zeros and would have gone red or green depending on the allocator.
    /// A test that cannot say which answer it is looking at is not a
    /// guard. So the zeroing is asserted here, deterministically, and the
    /// fact that `Drop` *is* what calls it is asserted as a property of
    /// the source in `tests/source_guards.rs` — this project's existing
    /// idiom for a guarantee that is invisible from inside the program.
    fn zeroize(&mut self) {
        zero_bytes(&mut self.0);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Paired with `len` because clippy's `len_without_is_empty` fires
    /// otherwise, and the crate builds under `-D warnings`.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Zero a buffer that held secret material, defeating dead-store
/// elimination.
///
/// **For the frame body, which [`SecretBytes`] cannot reach.** A
/// `SecretInput` arrives as CBOR in a `Vec<u8>` read off the socket, and
/// that buffer holds the value in cleartext before anything has been
/// decoded from it. `SecretBytes` owns the *decoded* copy and zeroes
/// that; this is how the caller disposes of the other one. It is not a
/// complete answer — the kernel's socket buffer and any allocator
/// scratch are outside anything this process can reach — but it is the
/// copy with the longest lifetime, since a read buffer is reused for the
/// next frame rather than freed.
pub fn zero_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

/// A blanket impl that conflicts with [`SecretBytes`] **only when
/// `SecretBytes: Serialize`**. If anybody writes `#[derive(Serialize)]`
/// (or a manual impl) on it, the two impls overlap, `E0119` fires, and
/// **the crate stops compiling**, naming this module. If nobody does, the
/// bound is unsatisfiable for `SecretBytes` and this module compiles
/// silently.
///
/// REQ-SEC-004 is the one constraint in this system where "someone will
/// notice in review" is not good enough: §9.2 requires the value to be
/// *absent* from every surface rather than redacted on it, so there is no
/// downstream redactor that would catch the mistake.
///
/// **The `+ serde::Serialize` bound is the whole guard.** Without it —
/// `impl<T: ?Sized> NotSerialize for T {}` — the blanket impl covers
/// `SecretBytes` unconditionally and `E0119` fires *always*, whether or
/// not anything derives `Serialize`. That form never mentions
/// `Serialize` in its code at all, so it cannot be conditional on it: it
/// is a crate that does not build, not a guard, and an injection step run
/// against it cannot tell "the guard fired" from "the crate was already
/// broken".
mod secret_is_not_serializable {
    use super::SecretBytes;

    // `#[allow(dead_code)]`: the trait is never named outside this
    // module, and `-D warnings` makes `dead_code` fatal — a guard firing
    // for the wrong reason all over again.
    #[allow(dead_code)]
    pub trait NotSerialize {}

    impl<T: ?Sized + serde::Serialize> NotSerialize for T {}
    impl NotSerialize for SecretBytes {}

    // ------------------------------------------------- the `Clone` half
    //
    // 0.0.6 guarded "no `Serialize`" and left "no `Clone`" to the doc
    // comment on the type. 0.0.7 gives `SecretBytes` new construction
    // sites — a provider subprocess, an operator binding, an autofill
    // path — and "one owner, one write, one drop" stops being a property
    // anybody can hold in their head at the moment there is more than
    // one producer. A second live copy is a second `Drop`, and the one
    // that is *not* the write path is a value nothing accounts for.
    //
    // `#[allow(dead_code)]` is not tidiness. The trait is named nowhere
    // outside this module and the gate is
    // `cargo clippy --workspace --all-targets -- -D warnings`, under
    // which `dead_code` is fatal — measured: without it the crate fails
    // with ``error: trait `NotClone` is never used``, a guard firing for
    // a reason unrelated to what it guards.
    #[allow(dead_code)]
    pub trait NotClone {}

    // **The `Clone` bound IS the guard.** Without it —
    // `impl<T> NotClone for T {}` — the blanket impl covers
    // `SecretBytes` unconditionally, `E0119` fires whether or not
    // anything derives `Clone`, and what you have is a crate that does
    // not build rather than a guard: that form never mentions `Clone` at
    // all, so it cannot be conditional on it.
    //
    // No `?Sized` relaxation here, unlike the `NotSerialize` pair above:
    // `Clone: Sized`, so a `T: Clone` bound already implies `T: Sized`.
    impl<T: Clone> NotClone for T {}
    impl NotClone for SecretBytes {}
}

/// The one outstanding secret request on a session (§5.2: *"fixed at 1
/// and not configurable"* in v0.1.0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRequest {
    /// `secreq_<short uuid>`. **Allocated by the raise** — §5.2: *"Raising
    /// is what allocates the `request_id`"*, by an echo drop or by a tool
    /// call, whichever comes first. 0.0.7's `request_secret_input`
    /// *adopts* an echo-raised request rather than refusing it.
    pub request_id: String,
    /// The echo-off prompt the child just drew, redacted.
    ///
    /// **May legitimately be the empty string** (REQ-O-013): the
    /// session's `last_line` is `""` whenever its holdback is active or
    /// the line lost bytes off its front at §4.1's tail bound. An empty
    /// `prompt_text` is a correct frame, and a client renders the request
    /// without prompt text rather than suppressing it. Nothing asserts it
    /// is non-empty and nothing should.
    pub prompt_text: String,
}

impl SecretRequest {
    pub fn new(prompt_text: String) -> Self {
        let id = uuid::Uuid::new_v4().simple().to_string();
        Self {
            request_id: format!("secreq_{}", &id[..12]),
            prompt_text,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_debug_does_not_render_the_value() {
        let s = SecretBytes::normalise(b"hunter2".to_vec(), true);
        let rendered = format!("{s:?}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(
            !rendered.contains("hunter2"),
            "the value reached a Debug rendering: {rendered}"
        );
    }

    #[test]
    fn the_value_is_zeroed_while_the_allocation_is_still_ours() {
        // The half of "zeroed on drop" that is observable without reading
        // freed memory: `Drop` calls `zeroize`, and `zeroize` leaves
        // nothing. That `Drop` is what calls it is asserted against the
        // source in `tests/source_guards.rs`, because from inside the
        // program the only vantage point is a buffer the allocator has
        // already taken back.
        let mut s = SecretBytes::normalise(b"hunter2".to_vec(), false);
        assert_eq!(s.len(), 7);
        s.zeroize();
        s.with_bytes(|b| {
            assert!(
                b.iter().all(|c| *c == 0),
                "the value survived zeroing: {b:?}"
            )
        });
    }

    #[test]
    fn zero_bytes_defeats_the_dead_store() {
        // The primitive on its own, over a buffer that is read afterwards
        // so the optimiser cannot argue the writes are dead.
        let mut buf = b"hunter2".to_vec();
        zero_bytes(&mut buf);
        assert_eq!(buf, vec![0u8; 7]);
    }

    #[test]
    fn the_trailing_newline_is_normalised_exactly_once() {
        // §5.2's four cases, asserted on the **byte count** written
        // rather than on the text, so a normalisation that produced
        // `secret\n\n` fails rather than reading plausibly.
        for (raw, append, expect) in [
            (&b"secret\n"[..], true, &b"secret\n"[..]),
            (&b"secret"[..], true, &b"secret\n"[..]),
            (&b"secret\r\n"[..], true, &b"secret\n"[..]),
            (&b"secret"[..], false, &b"secret"[..]),
        ] {
            let s = SecretBytes::normalise(raw.to_vec(), append);
            assert_eq!(s.len(), expect.len(), "for {raw:?} append={append}");
            s.with_bytes(|b| assert_eq!(b, expect, "for {raw:?} append={append}"));
        }
    }

    #[test]
    fn the_scoped_accessor_is_the_only_way_out() {
        // The closure sees the right bytes, and what it returns is a
        // *derived* value — the guard against `into_pty_write` is that
        // `WriteRequest::Secret` owns a `SecretBytes`, a signature that
        // no longer accepts an escaped `Vec`.
        let s = SecretBytes::normalise(b"hunter2".to_vec(), false);
        let sum: u32 = s.with_bytes(|b| b.iter().map(|c| *c as u32).sum());
        assert_eq!(sum, b"hunter2".iter().map(|c| *c as u32).sum::<u32>());
        assert!(!s.is_empty());
    }

    #[test]
    fn a_request_id_is_prefixed_and_unique() {
        let a = SecretRequest::new("[sudo] password for ada:".into());
        let b = SecretRequest::new(String::new());
        assert!(a.request_id.starts_with("secreq_"), "{}", a.request_id);
        assert_ne!(a.request_id, b.request_id);
        // An empty prompt is a correct request (REQ-O-013), not a defect.
        assert_eq!(b.prompt_text, "");
    }
}
