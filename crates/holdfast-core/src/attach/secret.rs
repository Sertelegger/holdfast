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
        // **After the zeroing, and only in a test build.** See
        // [`drop_witness`]: this is the one vantage point from which the
        // zeroing is observable without reading freed memory.
        #[cfg(test)]
        drop_witness::record(&self.0);
    }
}

/// A `#[cfg(test)]` witness that [`SecretBytes::drop`] pushes its
/// **post-zeroing** buffer into, so a test can assert the zeroing from
/// inside the drop while the allocation is still ours.
///
/// **Why this and not a raw pointer read-back.** The obvious test — drop
/// the value, then read the buffer through a saved pointer — is a
/// use-after-free: undefined behaviour, a hard failure under Miri or
/// ASAN, and measured in 0.0.6 to return `[34, 249, 249, 179, 76, 101,
/// 0]` for `hunter2`, which is neither the secret nor zeros. A test that
/// cannot say which answer it is looking at is not a guard.
///
/// **Thread-local, so concurrent tests do not see each other's drops.**
/// libtest runs tests in threads; a process-wide witness would make every
/// assertion here depend on what else happened to be running. The cost is
/// that a value dropped on another thread — anything moved into
/// `spawn_blocking` or a writer thread — is invisible, so a test using
/// this must do its dropping on its own thread.
///
/// `pub(crate)` rather than private to this module: the zeroing is
/// asserted from `secret::provider`'s unit tests and, from 0.0.7 onward,
/// from `secret::request`'s as well. A witness private to `attach::secret`
/// is unreachable from either.
#[cfg(test)]
pub(crate) mod drop_witness {
    use std::cell::RefCell;

    thread_local! {
        static DROPPED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    /// Called from [`super::SecretBytes::drop`] **after** `zeroize`. If
    /// the zeroing loop is ever deleted, what lands here is the
    /// plaintext — which is exactly the mutation the assertion exists to
    /// kill.
    pub(crate) fn record(after_zeroing: &[u8]) {
        DROPPED.with(|d| d.borrow_mut().push(after_zeroing.to_vec()));
    }

    /// Drop everything seen so far, so a test asserts over its own drops
    /// only.
    pub(crate) fn reset() {
        DROPPED.with(|d| d.borrow_mut().clear());
    }

    /// How many drops are recorded, without consuming them — the "nothing
    /// happened yet" half of an assertion.
    pub(crate) fn peek_len() -> usize {
        DROPPED.with(|d| d.borrow().len())
    }

    /// Everything recorded on this thread since the last [`reset`] or
    /// [`taken`], leaving the witness empty.
    pub(crate) fn taken() -> Vec<Vec<u8>> {
        DROPPED.with(|d| std::mem::take(&mut *d.borrow_mut()))
    }
}

impl SecretBytes {
    /// §5.2's normalisation, applied by the **daemon** so the behaviour
    /// does not depend on which client submitted: strip exactly one
    /// trailing `\r\n` or `\n`, then append `\n` when `append_newline`.
    /// Clients must not add the newline themselves.
    ///
    /// **The source buffer is zeroed and never grown.** See
    /// [`normalise_from`](Self::normalise_from) for why that is a
    /// correctness property of this type rather than tidiness at the call
    /// site.
    pub fn normalise(mut raw: Vec<u8>, append_newline: bool) -> Self {
        Self::normalise_from(&mut raw, append_newline)
    }

    /// [`normalise`](Self::normalise) with the source buffer left in the
    /// caller's hands, so a test can assert what became of it.
    ///
    /// **The zeroing discipline is not closed under `Vec` growth, and
    /// this is where it was open.** The earlier form stripped in place and
    /// then did `raw.push(b'\n')`. `append_newline` defaults to `true`,
    /// and the buffer handed in on the attach path is the CBOR-decoded
    /// `SecretInput.bytes`, which has `len == capacity` — so the push
    /// reallocated: the allocator copied the plaintext to a new block and
    /// freed the old one **without zeroing it**, somewhere `Drop` can
    /// never reach. Driven on pointer inequality by the security review
    /// (F-2).
    ///
    /// **Reserving before the push is not the fix** — `reserve` is the
    /// same copy-and-free. The buffer is built at its final capacity from
    /// the start, so the one allocation it ever has is the one `Drop`
    /// zeroes, and the source is zeroed here rather than left to an
    /// ordinary `Vec::drop`, which does not.
    pub(crate) fn normalise_from(raw: &mut [u8], append_newline: bool) -> Self {
        let keep = if raw.ends_with(b"\r\n") {
            raw.len() - 2
        } else if raw.ends_with(b"\n") {
            raw.len() - 1
        } else {
            raw.len()
        };
        let mut out = Vec::with_capacity(keep + usize::from(append_newline));
        out.extend_from_slice(&raw[..keep]);
        if append_newline {
            out.push(b'\n');
        }
        zero_bytes(raw);
        Self(out)
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

    /// The allocation's capacity, for the one row whose subject is that
    /// the buffer was built at its final size and cannot grow.
    ///
    /// `#[cfg(test)]`: a capacity is not something any caller has business
    /// branching on, and a public accessor would invite one to.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.0.capacity()
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
    // ------------------------------------------- the guard for the guard
    //
    // **A guard that fires only when somebody writes the mistake is
    // invisible to a suite that nobody writes the mistake in**, and both
    // impls above could be deleted with the whole workspace staying
    // green: `#[derive(Clone)]` on `SecretBytes` would then compile, and
    // the review that found this deleted them to prove it.
    // `NotSerialize`'s half has been pinned since 0.0.6 —
    // `source_guards::secret_bytes_still_zeroes_itself_in_drop` reads the
    // text of this file — and 0.0.7 added the `Clone` half without adding
    // its pin.
    //
    // This is the compile-time half, and it needs no dependency
    // (`trybuild` is out under the Tech Stack, which is why the
    // `E0119` observations for this module are a manual procedure
    // recorded in a commit message rather than a `#[test]`). A generic
    // function body is type-checked at its *definition*, so both bounds
    // below have to be provable from what is in scope:
    //
    //   * `SecretBytes: NotClone` — deleting `impl NotClone for
    //     SecretBytes {}` stops this compiling;
    //   * `T: Clone` implies `T: NotClone` — deleting the blanket impl,
    //     or narrowing its bound (to `Copy`, say), stops this compiling.
    //
    // What it cannot see is the blanket impl being *widened* to the
    // unbounded `impl<T> NotClone for T {}` with the `SecretBytes` impl
    // deleted alongside it — that form satisfies both bounds and guards
    // nothing. `source_guards` carries that half, as a scan for the
    // unbounded spelling, exactly as it already does for `NotSerialize`.
    const _: () = {
        #[allow(dead_code)]
        fn is_not_clone<T: NotClone + ?Sized>() {}

        #[allow(dead_code)]
        fn pin<T: Clone>() {
            is_not_clone::<SecretBytes>();
            is_not_clone::<T>();
        }
    };
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

    /// **F-2: normalisation must not leave the plaintext in a block
    /// `Drop` can never reach.**
    ///
    /// The fixture is the shape the attach path actually hands in — a
    /// CBOR-decoded `Vec` with `len == capacity` — and the assertion is
    /// the pair that separates "no copy escaped" from "the value happened
    /// to be short": the source's allocation **did not move**, so there is
    /// no freed block holding it, and what is left in the one allocation
    /// that did exist is zeros.
    ///
    /// The output's capacity is asserted for the other half of the same
    /// rule: a buffer built at its final size cannot grow later, so the
    /// allocation `Drop` zeroes is the only one it ever had. Reading the
    /// old block back instead would be reading freed memory, which is the
    /// trap `zeroize`'s own doc comment records.
    #[test]
    fn normalisation_leaves_no_cleartext_in_a_block_drop_cannot_reach() {
        let mut raw = Vec::with_capacity(21);
        raw.extend_from_slice(b"hunter2-correct-horse");
        assert_eq!(
            raw.len(),
            raw.capacity(),
            "the fixture must be exact-capacity, or it proves nothing about a decode"
        );
        let before = raw.as_ptr();

        let s = SecretBytes::normalise_from(&mut raw, true);

        assert_eq!(
            raw.as_ptr(),
            before,
            "the source buffer was reallocated; the plaintext is in a freed block"
        );
        assert!(
            raw.iter().all(|b| *b == 0),
            "the source buffer still holds the value: {raw:?}"
        );
        s.with_bytes(|b| assert_eq!(b, b"hunter2-correct-horse\n"));
        assert_eq!(
            s.capacity(),
            22,
            "the normalised buffer has slack, so a later push would move it"
        );
    }

    /// The pairing: the same discipline when there is nothing to append,
    /// and when a terminator is stripped — the two other shapes the
    /// attach and provider paths produce.
    #[test]
    fn the_stripping_shapes_zero_their_source_too() {
        for (raw_bytes, append, want) in [
            (&b"hunter2"[..], false, &b"hunter2"[..]),
            (&b"hunter2\n"[..], true, &b"hunter2\n"[..]),
            (&b"hunter2\r\n"[..], false, &b"hunter2"[..]),
        ] {
            let mut raw = Vec::with_capacity(raw_bytes.len());
            raw.extend_from_slice(raw_bytes);
            let before = raw.as_ptr();
            let s = SecretBytes::normalise_from(&mut raw, append);
            assert_eq!(raw.as_ptr(), before, "{raw_bytes:?} moved its source");
            assert!(
                raw.iter().all(|b| *b == 0),
                "{raw_bytes:?} left its source unzeroed: {raw:?}"
            );
            s.with_bytes(|b| assert_eq!(b, want, "{raw_bytes:?} normalised wrong"));
            assert_eq!(s.capacity(), want.len(), "{raw_bytes:?} has slack");
        }
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
