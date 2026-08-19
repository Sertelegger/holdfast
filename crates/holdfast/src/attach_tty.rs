//! The *local* terminal, for `holdfast attach` (§6.1).
//!
//! Everything in this file is about the terminal the human is sitting at:
//! raw mode and its restoration, the window size, and the keystroke
//! grammar that decides which bytes are the session's and which are the
//! client's own. Nothing here speaks the attach protocol — that is
//! `commands::attach`.
//!
//! **Unix only, by `#[cfg]` at the declaration site** (`main.rs`), not by
//! a runtime refusal: `tcsetattr`, `TIOCGWINSZ` and `SIGWINCH` have no
//! Windows equivalents worth faking, and §3.6 marks `holdfast attach` `✗`
//! on Windows native permanently. The `windows-cross` job type-checks
//! `main.rs`'s match arms, so the refusal arm lives there.

use std::io;
use std::os::unix::io::RawFd;

/// §6.1 Layer 1's prefix key, `Ctrl-B` (`0x02`).
pub const PREFIX_KEY: u8 = 0x02;

/// `Ctrl-C` (`0x03`), REQ-SEC-019's way out of a secret prompt.
///
/// **Not a client command anywhere else.** Raw mode clears `ISIG`
/// deliberately, so on the ordinary input path this byte is the
/// session's and travels to it untouched. It is named here only because
/// §9.5's prompt is the one state in which keystrokes do *not* reach the
/// session, and REQ-SEC-019's cancellation is *"forwarding `Ctrl-C` as
/// ordinary `Input`"* — which a secret line that swallowed it would make
/// unreachable.
pub const CANCEL_KEY: u8 = 0x03;

/// The second half of the detach sequence, lowercase `d` (`0x64`).
///
/// §6.1 writes it as *"Ctrl-B then D"*; this is tmux's binding, and the
/// shift state of the second key is not something §6.1 is making a claim
/// about. The smoke script's `printf '\002d'` encodes the same choice —
/// if this ever becomes uppercase, both must move together.
pub const DETACH_KEY: u8 = 0x64;

/// The original `termios` of a terminal, restored when this is dropped.
///
/// **A guard type rather than a `defer`-by-convention**, because a
/// restore that has to be remembered on every exit path is one that gets
/// forgotten on exactly one of them — and the cost of forgetting is the
/// user's shell left with `ECHO` and `ICANON` off, which looks like a
/// hung machine. `Drop` runs on the normal path, on `?`, and while a
/// panic unwinds.
pub struct TermiosGuard {
    fd: RawFd,
    original: libc::termios,
}

impl TermiosGuard {
    /// Put `fd` into raw mode, remembering what it was.
    ///
    /// `cfmakeraw` and not a hand-rolled flag mask: raw mode is a dozen
    /// bits across four fields and every hand-rolled version of it in the
    /// wild is missing one. What matters for this client is that `ECHO`
    /// and `ICANON` go off (the session echoes, not the local terminal)
    /// and that `ISIG` goes off, so `Ctrl-C` reaches the session as
    /// `0x03` instead of killing the client.
    pub fn raw(fd: RawFd) -> io::Result<Self> {
        // SAFETY: `tcgetattr` writes a `termios` through the pointer and
        // reads nothing else; the storage is a live local.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = original;
        // SAFETY: takes one pointer to live storage.
        unsafe { libc::cfmakeraw(&mut raw) };
        // Block until at least one byte, with no inter-byte timer: the
        // reader thread is dedicated, so a spinning `VMIN = 0` read would
        // burn a core for nothing.
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        // SAFETY: as above.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, original })
    }
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        // SAFETY: `self.original` is the struct `tcgetattr` filled in.
        // The return value is deliberately ignored — there is no useful
        // recovery from a failed restore, and `Drop` cannot report.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

/// This terminal's `(cols, rows)`, from `TIOCGWINSZ`.
///
/// `(cols, rows)` in that order, matching §7.5's `Resize { cols, rows }`
/// and `Session::size()`. A square terminal cannot tell the two apart,
/// which is why the test that covers this uses 132×43.
pub fn window_size(fd: RawFd) -> io::Result<(u16, u16)> {
    // SAFETY: `TIOCGWINSZ` writes a `winsize` through the pointer.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((ws.ws_col, ws.ws_row))
}

/// The keystroke grammar of §6.1 Layer 1, as a state machine.
///
/// A *machine* and not a scan of each chunk, because the prefix and the
/// key that follows it routinely arrive in different `read`s — a human
/// typing `Ctrl-B` then `d` produces two chunks far more often than one,
/// and a per-chunk matcher detaches on neither.
#[derive(Debug, Default)]
pub struct DetachKey {
    /// A `Ctrl-B` has been seen and its partner has not arrived yet. The
    /// byte is **held**, not forwarded, which is what makes `Ctrl-B d`
    /// leave nothing behind in the session.
    pending: bool,
}

impl DetachKey {
    /// Split local keystrokes into what the session should receive and
    /// whether this client should detach.
    ///
    /// The three cases §6.1 fixes, and the reason each is written out:
    ///
    /// * `Ctrl-B d` → detach, and **neither byte is forwarded**.
    /// * `Ctrl-B x` → forward **both** bytes, in order. Without this,
    ///   "any `Ctrl-B` detaches" satisfies the case above and silently
    ///   eats a byte every time somebody uses readline's
    ///   `backward-char`.
    /// * `Ctrl-B Ctrl-B` → forward **one** literal `0x02`. The escape
    ///   hatch for a session that wants the prefix itself.
    ///
    /// Bytes after the detach in the same chunk are discarded: the
    /// connection is over, and there is nowhere to put them.
    pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, bool) {
        let mut out = Vec::with_capacity(input.len() + 1);
        for &b in input {
            if self.pending {
                self.pending = false;
                match b {
                    DETACH_KEY => return (out, true),
                    // The prefix, escaped: one literal byte, not two.
                    PREFIX_KEY => out.push(PREFIX_KEY),
                    other => {
                        out.push(PREFIX_KEY);
                        out.push(other);
                    }
                }
                continue;
            }
            if b == PREFIX_KEY {
                self.pending = true;
                continue;
            }
            out.push(b);
        }
        (out, false)
    }
}

/// One line typed in answer to an `AwaitingSecret` prompt (§9.5).
///
/// **There is no "switch the terminal to no-echo" step, and its absence
/// is the stronger property.** `holdfast attach` has already cleared
/// `ECHO` for the whole session — that is what raw mode is — so the local
/// terminal never echoes anything. What normally makes keystrokes appear
/// is the *session* echoing them back as `Output`, and the bytes
/// accumulated here are deliberately not forwarded to the session at all
/// until they leave as a `SecretInput`. So the value is unrendered by
/// construction on both paths, rather than by a flag that has to be set
/// and unset correctly around a read.
///
/// The buffer is zeroed when it is taken, when it is abandoned, and
/// again when it is dropped.
#[derive(Debug, Default)]
pub struct SecretLine {
    buf: Vec<u8>,
}

/// What a chunk of keystrokes did to a [`SecretLine`].
///
/// **Three outcomes and not two**, because a prompt a human cannot leave
/// is worse than no prompt at all: `sudo` asking on a host they did not
/// mean to reach is the ordinary case, and REQ-SEC-019's only named
/// affordance is the cancel below.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretKeys {
    /// Still being typed. Nothing leaves this client.
    Pending,
    /// `Enter` arrived: the line **without** its terminator, because
    /// §5.2's normalisation is the daemon's job and doing it twice
    /// appends two newlines.
    Line(Vec<u8>),
    /// `Ctrl-C` arrived: REQ-SEC-019's abandon. Whatever had been typed
    /// is already zeroed and is **not** in here — the payload is the
    /// bytes to forward to the session as ordinary `Input`, `0x03`
    /// first, so the session PTY's own line discipline raises `SIGINT`
    /// for the foreground group exactly as it would for a human sitting
    /// at the child directly.
    Cancelled(Vec<u8>),
}

impl SecretLine {
    /// Feed local keystrokes.
    ///
    /// The detach grammar has already run over this chunk (see
    /// `commands::attach`), so `Ctrl-B d` never arrives here and cannot
    /// be typed into a password.
    pub fn feed(&mut self, input: &[u8]) -> SecretKeys {
        for (i, &b) in input.iter().enumerate() {
            match b {
                b'\r' | b'\n' => return SecretKeys::Line(self.take()),
                // The partial value dies **here**, before the return, so
                // an abandoned prompt cannot leave a password behind in
                // this buffer for the next one to inherit.
                CANCEL_KEY => {
                    self.zero();
                    return SecretKeys::Cancelled(input[i..].to_vec());
                }
                // Backspace and DEL. A human correcting a password they
                // cannot see is the ordinary case, not the exotic one.
                0x08 | 0x7f => {
                    self.buf.pop();
                }
                other => self.buf.push(other),
            }
        }
        SecretKeys::Pending
    }

    fn take(&mut self) -> Vec<u8> {
        let line = self.buf.clone();
        self.zero();
        line
    }

    fn zero(&mut self) {
        holdfast_core::attach::secret::zero_bytes(&mut self.buf);
        self.buf.clear();
    }
}

impl Drop for SecretLine {
    fn drop(&mut self) {
        holdfast_core::attach::secret::zero_bytes(&mut self.buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_bytes_pass_straight_through() {
        let mut k = DetachKey::default();
        assert_eq!(k.feed(b"hello"), (b"hello".to_vec(), false));
    }

    #[test]
    fn the_prefix_and_the_detach_key_are_both_swallowed() {
        let mut k = DetachKey::default();
        let (out, detach) = k.feed(&[PREFIX_KEY, DETACH_KEY]);
        assert!(detach);
        assert!(
            out.is_empty(),
            "neither byte of the detach sequence reaches the session: {out:?}"
        );
    }

    #[test]
    fn the_prefix_followed_by_anything_else_forwards_both_bytes() {
        // The pairing that stops "any Ctrl-B detaches" from passing the
        // test above. Order matters: a client that forwarded `x` then
        // `0x02` would corrupt readline in a way nobody would trace back
        // here.
        let mut k = DetachKey::default();
        assert_eq!(k.feed(&[PREFIX_KEY, b'x']), (vec![PREFIX_KEY, b'x'], false));
    }

    #[test]
    fn the_prefix_twice_forwards_one_literal_prefix() {
        let mut k = DetachKey::default();
        assert_eq!(k.feed(&[PREFIX_KEY, PREFIX_KEY]), (vec![PREFIX_KEY], false));
    }

    #[test]
    fn the_sequence_is_recognised_across_two_reads() {
        // The reason this is a state machine. A human types the two keys
        // as two events far more often than as one, and a per-chunk
        // matcher detaches on neither — while still passing every
        // single-chunk test above.
        let mut k = DetachKey::default();
        assert_eq!(k.feed(&[PREFIX_KEY]), (Vec::new(), false));
        let (out, detach) = k.feed(&[DETACH_KEY]);
        assert!(detach);
        assert!(out.is_empty());
    }

    #[test]
    fn a_prefix_split_from_an_ordinary_key_still_forwards_both() {
        let mut k = DetachKey::default();
        assert_eq!(k.feed(&[PREFIX_KEY]), (Vec::new(), false));
        assert_eq!(k.feed(b"x"), (vec![PREFIX_KEY, b'x'], false));
    }

    #[test]
    fn a_secret_line_ends_at_the_terminator_and_does_not_carry_it() {
        // §5.2's normalisation is the daemon's, applied once, at the one
        // place that knows whether the prompt wants a newline. A client
        // that shipped the `\r` too would produce two.
        let mut s = SecretLine::default();
        assert_eq!(s.feed(b"hun"), SecretKeys::Pending);
        assert_eq!(s.feed(b"ter2\r"), SecretKeys::Line(b"hunter2".to_vec()));
    }

    #[test]
    fn backspace_shortens_the_secret_line() {
        let mut s = SecretLine::default();
        assert_eq!(
            s.feed(b"hunter3\x7f2\n"),
            SecretKeys::Line(b"hunter2".to_vec())
        );
    }

    #[test]
    fn a_taken_line_leaves_nothing_behind_for_the_next_prompt() {
        let mut s = SecretLine::default();
        assert_eq!(s.feed(b"first\n"), SecretKeys::Line(b"first".to_vec()));
        assert_eq!(s.feed(b"second\n"), SecretKeys::Line(b"second".to_vec()));
    }

    #[test]
    fn ctrl_c_abandons_the_line_and_forwards_only_the_interrupt() {
        // REQ-SEC-019. Two claims, and the second is the one a naive
        // "return the buffer so the caller can decide" would fail: the
        // half-typed password does **not** ride out on the cancel. What
        // leaves is the interrupt byte, which is what makes the session
        // PTY raise `SIGINT` and the child abandon its own prompt.
        let mut s = SecretLine::default();
        assert_eq!(s.feed(b"hun"), SecretKeys::Pending);
        assert_eq!(
            s.feed(&[CANCEL_KEY]),
            SecretKeys::Cancelled(vec![CANCEL_KEY])
        );
    }

    #[test]
    fn the_interrupt_carries_the_rest_of_its_chunk_with_it() {
        // A human typing fast, or a paste: `0x03` and the keys after it
        // arrive in one `read`. Everything from the interrupt onwards is
        // the session's, in order — dropping the tail would silently eat
        // keystrokes, and keeping the head would forward the secret.
        let mut s = SecretLine::default();
        assert_eq!(
            s.feed(b"hun\x03ls\r"),
            SecretKeys::Cancelled(b"\x03ls\r".to_vec())
        );
    }

    #[test]
    fn a_cancelled_line_leaves_nothing_behind_for_the_next_prompt() {
        // The pairing with `a_taken_line_leaves_nothing_behind…`. A
        // `Cancelled` arm that returned without zeroing would carry the
        // abandoned value into whatever the child asks for next — the
        // wrong-password-to-the-wrong-prompt failure §5.2 exists to
        // prevent.
        let mut s = SecretLine::default();
        assert_eq!(
            s.feed(b"abandoned\x03"),
            SecretKeys::Cancelled(vec![CANCEL_KEY])
        );
        assert_eq!(s.feed(b"second\n"), SecretKeys::Line(b"second".to_vec()));
    }
}
