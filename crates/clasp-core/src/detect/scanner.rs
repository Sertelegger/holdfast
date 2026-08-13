//! Tier-A mode scanner (spec §4.5): a bounded state machine over the raw
//! PTY byte stream that tracks bracketed paste, the alternate screen, the
//! window title, and OSC 133 semantic markers.
//!
//! It allocates no grid and keeps no history beyond a 512-byte tail line,
//! so it runs unconditionally on every output chunk. Tier B (full VT100
//! emulation) is 0.0.4.
//!
//! The scanner is also where escape sequences are recognised, so the tail
//! line it maintains is naturally free of them. That is *not* the
//! read-path ANSI stripper (spec §4.1) — that one has holdback-aligned
//! boundary rules and an `ansi: "raw"` mode, and lands in 0.0.3. This one
//! exists only to give the detector a clean last line.

use std::collections::VecDeque;

/// Bytes of post-escape text kept for last-line pattern matching (§4.1).
const TAIL_LINE_MAX: usize = 512;
/// Cap on an OSC payload we are willing to buffer. Beyond this the payload
/// is still consumed to its terminator (so the machine resynchronises) but
/// no longer accumulated.
const OSC_PAYLOAD_MAX: usize = 1024;
/// Cap on the echoed command line captured between OSC 133 `B` and `C`.
const COMMAND_CAPTURE_MAX: usize = 4096;
/// Hard ceiling on the bytes a single control sequence may *consume*
/// before the scanner abandons it — a **blindness budget** (§8.8).
///
/// `OSC_PAYLOAD_MAX` bounds what a sequence stores; this bounds how long
/// the scanner may be unable to see mode changes. Without it an OSC or DCS
/// whose terminator was lost — a `cat` of a binary file, a truncated
/// write, a background job interleaving on the same PTY — swallows the
/// rest of the session. That is not a degraded mode: the modes hidden
/// inside it are the availability flags §8.4 uses to *pick* a tier, so
/// losing them silently disables deterministic detection rather than
/// weakening it. The bound is not exact — `give_up` then discards to the
/// next newline, so the blind window runs to the end of the line the trip
/// landed on, which a bare-`\r` progress display can extend indefinitely.
/// Strictly better than the unbounded case it replaced, and stated here
/// rather than left implied by the word "bounds".
///
/// **What this value is chosen against, corrected at spec rev. 34.** It is
/// *not* "above what real programs emit", because no constant is: sixel
/// frames run from ~100 KiB to several MiB, so the previous
/// `64 * OSC_PAYLOAD_MAX` sat *below* the very class this comment cited as
/// the reason it had been raised from `8 *`. Worse, sixel needs no `ESC`
/// to reach the residual — `#` is its colour introducer and `$` its
/// graphics carriage return — so a legitimate image tripping the ceiling
/// leaves a `$`-terminated line the T3 table scores 0.60, with no
/// adversary anywhere. The honest framing is the one above: the ceiling is
/// chosen against how long an unterminated sequence may hide mode changes,
/// not against how large a legitimate payload can be.
///
/// So `1024 * OSC_PAYLOAD_MAX` (1 MiB), and the cost of the raise is
/// bounded on both sides. A well-formed sequence pays nothing for being
/// long — everything past `OSC_PAYLOAD_MAX` is already consumed without
/// being stored or interpreted — so the raise costs nothing at all in the
/// ordinary case; what it buys is that the routine sixel no longer trips
/// it. What it costs is the width of the blind window when a sequence
/// really is truncated, which is the one thing this constant exists to
/// bound. Raising it moves the threshold at which the `give_up` residual
/// becomes reachable; it does not close it, and cannot (see `give_up`).
/// REQ-PD-018 pins that residual at its real reach, expressed relative to
/// this constant so the assertions move with it.
pub(crate) const SEQUENCE_MAX: usize = 1024 * OSC_PAYLOAD_MAX;
/// Cap on CSI parameter bytes. Past this the sequence is consumed to its
/// final byte but not interpreted.
const CSI_PARAMS_MAX: usize = 64;

/// An OSC 133 semantic marker (§8.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Osc133 {
    /// `A` — the shell is starting to draw a prompt.
    PromptStart,
    /// `B` — the prompt is drawn; what follows is the typed command line.
    CommandStart,
    /// `C` — the command was submitted; what follows is its output.
    /// `command` is the text echoed between `B` and `C`.
    OutputStart { command: String },
    /// `D;<code>` — the command finished.
    CommandDone { exit_code: Option<i32> },
}

/// A marker plus the byte span of the escape sequence that carried it.
/// Offsets are absolute into the raw stream, so they line up with
/// `OutputBuffer` cursors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Osc133Event {
    /// Offset of the `\x1b` that introduced the sequence.
    pub start: u64,
    /// Offset just past the sequence's terminator.
    pub end: u64,
    pub marker: Osc133,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    /// Saw `\x1b`.
    Esc,
    /// Saw `\x1b` then an intermediate byte (0x20..=0x2f).
    EscIntermediate,
    /// Inside `\x1b[ … final`.
    Csi,
    /// Inside `\x1b] … BEL` or `\x1b] … \x1b\\`.
    Osc,
    /// Saw `\x1b` while inside an OSC payload: maybe the ST terminator.
    OscEsc,
    /// Inside a DCS/SOS/PM/APC string, which ends at ST.
    Str,
    /// Saw `\x1b` while inside such a string.
    StrEsc,
    /// A sequence was abandoned at `SEQUENCE_MAX`; bytes are dropped until
    /// the next newline rather than allowed to become terminal text.
    Discard,
}

/// The last logical line of printable text, bounded and escape-free.
#[derive(Debug, Default)]
struct TailLine {
    buf: VecDeque<u8>,
}

impl TailLine {
    fn push(&mut self, b: u8) {
        self.buf.push_back(b);
        while self.buf.len() > TAIL_LINE_MAX {
            self.buf.pop_front();
        }
    }

    /// `\r` and `\n` both start the line over: a prompt redrawn after a
    /// carriage return must not inherit the progress bar in front of it.
    fn reset(&mut self) {
        self.buf.clear();
    }

    fn backspace(&mut self) {
        self.buf.pop_back();
    }

    fn as_string(&mut self) -> String {
        String::from_utf8_lossy(self.buf.make_contiguous()).into_owned()
    }
}

/// Terminal modes observed so far, plus whether each was ever observed at
/// all — availability, not just current value, decides which detection
/// tier can answer (§8.4).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Modes {
    pub bracketed_paste: bool,
    pub alt_screen: bool,
    pub saw_bracketed_paste: bool,
    pub saw_alt_screen: bool,
    pub saw_osc133: bool,
}

#[derive(Debug)]
pub struct ModeScanner {
    state: State,
    modes: Modes,
    title: Option<String>,
    tail: TailLine,
    /// CSI parameter and intermediate bytes, without the final byte.
    params: Vec<u8>,
    /// True once the parameters exceeded `CSI_PARAMS_MAX`. Truncated
    /// parameters would decode as a different, shorter sequence, so an
    /// overflowed CSI is consumed but never applied.
    params_overflowed: bool,
    /// OSC payload, without the introducer or terminator.
    osc: Vec<u8>,
    /// True once the payload exceeded `OSC_PAYLOAD_MAX`; the rest is
    /// consumed but not kept, and the marker is not interpreted.
    osc_overflowed: bool,
    /// Offset of the `\x1b` that started the sequence being parsed.
    seq_start: u64,
    /// Bytes consumed by the sequence being parsed, against `SEQUENCE_MAX`.
    seq_len: usize,
    /// Echoed command line, accumulated between OSC 133 `B` and `C`.
    capture: Option<String>,
    /// Last OSC 133 marker letter seen (`A`/`B`/`C`/`D`), for the T1 state.
    last_marker: Option<u8>,
    /// A `\r` was seen and we do not yet know whether it is the first half
    /// of a `\r\n` line terminator or a bare column-0 return.
    pending_cr: bool,
}

impl Default for ModeScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ModeScanner {
    pub fn new() -> Self {
        Self {
            state: State::Ground,
            modes: Modes::default(),
            title: None,
            tail: TailLine::default(),
            params: Vec::new(),
            params_overflowed: false,
            osc: Vec::new(),
            osc_overflowed: false,
            seq_start: 0,
            seq_len: 0,
            capture: None,
            last_marker: None,
            pending_cr: false,
        }
    }

    pub fn modes(&self) -> Modes {
        self.modes
    }

    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    pub fn last_marker(&self) -> Option<u8> {
        self.last_marker
    }

    pub fn last_line(&mut self) -> String {
        self.tail.as_string()
    }

    /// Feed one chunk of raw PTY bytes. `base` is the absolute offset of
    /// `bytes[0]` in the raw stream. Returns the OSC 133 markers found, in
    /// stream order.
    ///
    /// The machine is persistent across calls, so an escape sequence split
    /// across two chunks is still recognised.
    pub fn feed(&mut self, bytes: &[u8], base: u64) -> Vec<Osc133Event> {
        let mut events = Vec::new();
        for (i, &b) in bytes.iter().enumerate() {
            let offset = base + i as u64;
            // Ahead of everything, including the resynchronisation rules
            // below: nothing in a discarded run is trusted — not as text,
            // and not as a sequence either. An `ESC` here is payload the
            // abandoned sequence chose, so honouring it would let that
            // payload set the very availability flags §8.4 gates on.
            if self.state == State::Discard {
                if b == b'\n' {
                    self.state = State::Ground;
                }
                continue;
            }
            // Resynchronisation, ahead of any state-specific handling. A
            // sequence that never terminates must not be able to blind the
            // scanner for the rest of the session.
            if self.state != State::Ground {
                // `CAN` and `SUB` abandon a sequence in progress. xterm and
                // VTE resynchronise on these precisely so that a truncated
                // write cannot poison everything after it.
                if b == 0x18 || b == 0x1a {
                    self.abort();
                    continue;
                }
                self.seq_len += 1;
                if self.seq_len > SEQUENCE_MAX {
                    self.give_up();
                    continue;
                }
            }
            match self.state {
                State::Ground => self.ground(b, offset),
                State::Esc => self.esc(b, offset),
                State::EscIntermediate => {
                    if b == 0x1b {
                        self.begin_escape(offset);
                    } else if !(0x20..=0x2f).contains(&b) {
                        self.state = State::Ground;
                    }
                }
                State::Csi => self.csi(b, offset),
                State::Osc => self.osc_byte(b, offset, &mut events),
                State::OscEsc => {
                    if b == b'\\' {
                        self.finish_osc(offset + 1, &mut events);
                    } else {
                        // Not ST, so the OSC's terminator was lost. The ESC
                        // begins a new sequence rather than joining the
                        // payload — that is what stops a title with a
                        // dropped terminator from eating the marker behind
                        // it. `- 1` is the ESC we are standing one byte past.
                        self.begin_escape(offset.saturating_sub(1));
                        self.esc(b, offset);
                    }
                }
                State::Str => {
                    if b == 0x1b {
                        self.state = State::StrEsc;
                    }
                }
                // Unlike OSC, a DCS/SOS/PM/APC payload stays opaque to a
                // non-ST escape: tmux passthrough carries doubled escapes
                // as data, and a mode set inside one is data too, not a
                // mode change. `CAN`/`SUB` and `SEQUENCE_MAX` above are
                // what rescue an unterminated one.
                State::StrEsc => {
                    self.state = if b == b'\\' {
                        State::Ground
                    } else {
                        State::Str
                    };
                }
                // Handled above, before the resynchronisation rules.
                State::Discard => unreachable!(),
            }
        }
        events
    }

    /// Abandon the sequence in progress and return to `Ground`, discarding
    /// what it accumulated. Nothing is emitted: a sequence that never
    /// terminated is not evidence of anything.
    fn abort(&mut self) {
        self.state = State::Ground;
        self.params.clear();
        self.params_overflowed = false;
        self.osc.clear();
        self.osc_overflowed = false;
        self.seq_len = 0;
    }

    /// Abandon a sequence that has consumed `SEQUENCE_MAX` bytes without
    /// terminating, and distrust the rest of the line it was sitting on.
    ///
    /// The byte that trips the ceiling is deliberately *not* reconsidered
    /// as ordinary text, and neither is anything up to the next newline.
    /// Returning straight to `Ground` re-opens the injection the
    /// resynchronisation rules exist to close, and does it for *correctly
    /// terminated* sequences: the remainder of the abandoned payload
    /// becomes terminal text, and the program emitting it chose that text.
    /// Measured — a 9 KiB BEL-terminated OSC 52 clipboard write whose
    /// payload ended `\r\nroot@prod:/etc# ` yielded exactly that as
    /// `last_line()`, which §8.6 scores 0.85, §8.4's act threshold. A
    /// forged prompt is worse than no prompt: a false `AtPrompt` tells the
    /// agent to type, where blindness only tells it to wait.
    ///
    /// The tail line is cleared for the same reason. Whatever preceded the
    /// abandoned sequence is not a line the scanner can still vouch for,
    /// and an empty tail scores 0.0 — the fail-safe direction.
    ///
    /// **The residual, at its real reach (§8.8 rev. 34, REQ-PD-018).** A
    /// sequence longer than `SEQUENCE_MAX` whose payload contains a newline
    /// hands *everything after that newline* to the full state machine,
    /// because the discard ends at the payload's own newline and the
    /// scanner resumes at `Ground` there. A prompt-shaped tail line is only
    /// the cheapest form of that. Measured, on a payload carrying `\r\n`
    /// before the smuggled bytes:
    ///
    /// - `root@prod:/etc# ` → `AtPrompt` / `heuristic` / 0.85 — the floor,
    ///   and the only case rev. 27 recorded
    /// - `\x1b[?2004h` → `AtPrompt` / `terminal_mode` / **0.95**, with
    ///   `saw_bracketed_paste` set, which is sticky and gates which rungs
    ///   may answer for the rest of the session
    /// - `\x1b[?1049h` → `Fullscreen` / `terminal_mode`, `saw_alt_screen`
    ///   set
    /// - `\x1b]133;A\x07root@prod:/etc# ` → a genuine `PromptStart`
    ///   **event**, `saw_osc133` set, and `AtPrompt` / **`semantic`** /
    ///   **1.00** — the highest-confidence answer the system can produce
    /// - `\x1b]133;B\x07ls\nrm -rf /\x1b]133;C\x07` → `OutputStart {
    ///   command: "ls\nrm -rf /" }`, text injected into the history §5.2
    ///   reports
    ///
    /// **"Well-formed" is not load-bearing**, and neither is the carrier:
    /// an *unterminated* run of the same length leaks byte-identically, and
    /// a DCS opener behaves exactly as an OSC one does. The leak comes from
    /// the discard-to-newline rule, not from what the sequence was.
    ///
    /// **It is not new and not a regression.** Before this path existed the
    /// trip returned straight to `Ground`, so all of the above was
    /// reachable at the then-8 KiB ceiling with no newline needed, and
    /// §8.8/REQ-PD-010 already accepts that a hostile child can print these
    /// bytes directly at any length with no ceiling involved. Nor does it
    /// need an adversary: an ESC-free sixel over the ceiling reaches the
    /// 0.60 rung by accident (see `SEQUENCE_MAX`).
    ///
    /// **It does not close.** At the moment the ceiling trips the scanner
    /// cannot know whether it is inside a huge well-formed sequence or a
    /// truncated one, so bounding how long an unterminated sequence can
    /// blind it and never promoting a well-formed one's payload to text are
    /// not simultaneously achievable. The ceiling is the only free
    /// parameter: raising it moves the threshold at which the residual
    /// becomes reachable.
    fn give_up(&mut self) {
        self.abort();
        self.tail.reset();
        self.pending_cr = false;
        self.state = State::Discard;
    }

    /// Begin a fresh escape sequence at `offset`, discarding anything in
    /// progress. `ESC` is the one byte that always means "a new sequence
    /// starts here", so a truncated sequence can neither be applied nor
    /// poison the one that follows it.
    fn begin_escape(&mut self, offset: u64) {
        self.abort();
        self.seq_start = offset;
        self.state = State::Esc;
    }

    fn ground(&mut self, b: u8, offset: u64) {
        // `\r\n` is an ordinary line terminator; a bare `\r` means the line
        // is about to be overwritten. Deciding needs one byte of
        // lookahead, which the persistent `pending_cr` flag supplies even
        // when the pair straddles two chunks. A *run* of `\r`s is still
        // just "go to column 0", so only the byte that ends the run
        // decides — `zsh` emits `\r\r\n` when a command is submitted.
        if self.pending_cr && b != b'\r' {
            self.pending_cr = false;
            if b != b'\n' {
                self.capture_return();
            }
        }
        match b {
            0x1b => self.begin_escape(offset),
            b'\n' => {
                self.tail.reset();
                self.capture_newline();
            }
            b'\r' => {
                self.tail.reset();
                self.pending_cr = true;
            }
            0x08 => {
                self.tail.backspace();
                self.capture_backspace();
            }
            b'\t' => self.text(b' '),
            0x00..=0x1f | 0x7f => {}
            _ => self.text(b),
        }
    }

    fn text(&mut self, b: u8) {
        self.tail.push(b);
        if let Some(cap) = self.capture.as_mut() {
            if cap.len() < COMMAND_CAPTURE_MAX {
                cap.push(b as char);
            }
        }
    }

    /// The capture obeys the same overwrite rules as the tail line. It has
    /// to: `zsh`'s line editor echoes the first keystroke, backspaces over
    /// it, and redraws. Appending blindly captures `eecho hello` instead
    /// of `echo hello` — measured, not hypothetical.
    fn capture_return(&mut self) {
        if let Some(cap) = self.capture.as_mut() {
            let keep = cap.rfind('\n').map(|i| i + 1).unwrap_or(0);
            cap.truncate(keep);
        }
    }

    fn capture_newline(&mut self) {
        if let Some(cap) = self.capture.as_mut() {
            if cap.len() < COMMAND_CAPTURE_MAX {
                cap.push('\n');
            }
        }
    }

    fn capture_backspace(&mut self) {
        if let Some(cap) = self.capture.as_mut() {
            cap.pop();
        }
    }

    fn esc(&mut self, b: u8, offset: u64) {
        if b == 0x1b {
            // `ESC ESC`: the first one introduced nothing.
            self.begin_escape(offset);
            return;
        }
        self.state = match b {
            b'[' => {
                self.params.clear();
                self.params_overflowed = false;
                State::Csi
            }
            b']' => {
                self.osc.clear();
                self.osc_overflowed = false;
                State::Osc
            }
            // DCS, SOS, PM, APC: string payloads terminated by ST.
            b'P' | b'X' | b'^' | b'_' => State::Str,
            0x20..=0x2f => State::EscIntermediate,
            _ => State::Ground,
        };
    }

    fn csi(&mut self, b: u8, offset: u64) {
        if b == 0x1b {
            // A truncated CSI must not be applied, and its parameter bytes
            // must not fall through to the tail line as text — that is how
            // a mangled sequence manufactures `$ `-shaped output for the
            // T3 matcher to mistake for a prompt.
            self.begin_escape(offset);
        } else if (0x40..=0x7e).contains(&b) {
            self.apply_csi(b);
            self.state = State::Ground;
        } else if self.params.len() < CSI_PARAMS_MAX {
            self.params.push(b);
        } else {
            self.params_overflowed = true;
        }
    }

    /// DEC private mode set/reset. `\x1b[?2004h` and friends may carry
    /// several parameters at once (`\x1b[?1049;2004h`), so each is applied.
    fn apply_csi(&mut self, final_byte: u8) {
        // Truncated parameters decode as a different, shorter sequence:
        // `?9…9;20041h` cut at the cap ends in `;2004` and would forge the
        // availability flag §8.4 gates on. Consume, do not interpret.
        if self.params_overflowed {
            return;
        }
        if final_byte != b'h' && final_byte != b'l' {
            return;
        }
        let Ok(params) = std::str::from_utf8(&self.params) else {
            return;
        };
        let Some(params) = params.strip_prefix('?') else {
            return;
        };
        let on = final_byte == b'h';
        for p in params.split(';') {
            match p {
                "2004" => {
                    self.modes.bracketed_paste = on;
                    self.modes.saw_bracketed_paste = true;
                }
                "1049" => {
                    self.modes.alt_screen = on;
                    self.modes.saw_alt_screen = true;
                }
                _ => {}
            }
        }
    }

    fn push_osc(&mut self, b: u8) {
        if self.osc.len() < OSC_PAYLOAD_MAX {
            self.osc.push(b);
        } else {
            self.osc_overflowed = true;
        }
    }

    fn osc_byte(&mut self, b: u8, offset: u64, events: &mut Vec<Osc133Event>) {
        match b {
            0x07 => self.finish_osc(offset + 1, events),
            0x1b => self.state = State::OscEsc,
            _ => self.push_osc(b),
        }
    }

    fn finish_osc(&mut self, end: u64, events: &mut Vec<Osc133Event>) {
        self.state = State::Ground;
        if self.osc_overflowed {
            self.osc.clear();
            return;
        }
        let payload = std::mem::take(&mut self.osc);
        let Ok(payload) = String::from_utf8(payload) else {
            return;
        };
        if let Some(rest) = payload.strip_prefix("133;") {
            if let Some(marker) = self.osc133(rest) {
                events.push(Osc133Event {
                    start: self.seq_start,
                    end,
                    marker,
                });
            }
            return;
        }
        // Window title: OSC 0 sets icon name + title, OSC 2 sets the title.
        for prefix in ["0;", "2;"] {
            if let Some(rest) = payload.strip_prefix(prefix) {
                self.title = Some(rest.to_string());
                return;
            }
        }
    }

    fn osc133(&mut self, rest: &str) -> Option<Osc133> {
        let kind = rest.as_bytes().first().copied()?;
        let marker = match kind {
            b'A' => {
                self.capture = None;
                Osc133::PromptStart
            }
            b'B' => {
                self.capture = Some(String::new());
                Osc133::CommandStart
            }
            b'C' => {
                let command = self.capture.take().unwrap_or_default().trim().to_string();
                Osc133::OutputStart { command }
            }
            b'D' => {
                self.capture = None;
                // `D` alone means "finished, status unknown"; `D;<n>`
                // carries it.
                let exit_code = rest[1..]
                    .strip_prefix(';')
                    .and_then(|s| s.split(';').next())
                    .and_then(|s| s.parse::<i32>().ok());
                Osc133::CommandDone { exit_code }
            }
            // Not a marker we model (`P`, `L`, …). Leave the T1 state
            // exactly as it was: an unmodelled marker is not evidence
            // about whether a command is running.
            _ => return None,
        };
        self.modes.saw_osc133 = true;
        self.last_marker = Some(kind);
        Some(marker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(input: &[u8]) -> (ModeScanner, Vec<Osc133Event>) {
        let mut s = ModeScanner::new();
        let ev = s.feed(input, 0);
        (s, ev)
    }

    #[test]
    fn bracketed_paste_on_and_off() {
        let (s, _) = scan(b"\x1b[?2004h");
        assert!(s.modes().bracketed_paste);
        assert!(s.modes().saw_bracketed_paste);

        let (s, _) = scan(b"\x1b[?2004h\x1b[?2004l");
        assert!(!s.modes().bracketed_paste);
        assert!(s.modes().saw_bracketed_paste);
    }

    #[test]
    fn alt_screen_on_and_off() {
        let (s, _) = scan(b"\x1b[?1049h");
        assert!(s.modes().alt_screen);
        let (s, _) = scan(b"\x1b[?1049h\x1b[?1049l");
        assert!(!s.modes().alt_screen);
        assert!(s.modes().saw_alt_screen);
    }

    #[test]
    fn multi_parameter_private_mode_sets_both() {
        let (s, _) = scan(b"\x1b[?1049;2004h");
        assert!(s.modes().alt_screen);
        assert!(s.modes().bracketed_paste);
    }

    #[test]
    fn unrelated_private_modes_are_ignored() {
        let (s, _) = scan(b"\x1b[?25l\x1b[?1h\x1b[?12;25h");
        assert!(!s.modes().alt_screen);
        assert!(!s.modes().bracketed_paste);
        assert!(!s.modes().saw_bracketed_paste);
    }

    #[test]
    fn an_overlong_csi_parameter_list_is_not_interpreted() {
        // Dropping parameter bytes past the cap and parsing the remainder
        // decodes a *different* sequence: this one truncates to `…;2004`
        // and would set both `bracketed_paste` and the availability flag
        // §8.4 gates on, from a sequence that says no such thing.
        let mut input = b"\x1b[?".to_vec();
        input.extend(std::iter::repeat_n(b'9', 58));
        input.extend_from_slice(b";20041h");
        let (s, _) = scan(&input);
        assert!(!s.modes().bracketed_paste);
        assert!(
            !s.modes().saw_bracketed_paste,
            "truncated parameters forged a tier-gating flag"
        );
    }

    #[test]
    fn a_sequence_split_across_chunks_is_still_recognised() {
        // The guard: a scanner that restarted per chunk would see
        // `\x1b[?20` and `04h` and set nothing at all.
        let mut s = ModeScanner::new();
        s.feed(b"\x1b[?20", 0);
        assert!(!s.modes().bracketed_paste, "must not fire on a partial");
        s.feed(b"04h", 5);
        assert!(s.modes().bracketed_paste, "split sequence was missed");
    }

    #[test]
    fn an_escape_cancels_the_sequence_it_interrupts() {
        // Each input truncates a sequence and starts the next one with no
        // separator, which is what a short write produces. Without a cancel
        // rule the scanner stays in the old state, eats the next sequence's
        // introducer, and spills the remainder into the tail line as text —
        // and a `$ `-shaped fragment there is exactly what the T3 matcher
        // would read as a prompt. One case per state that can be
        // interrupted.
        for raw in [
            &b"\x1b[?2004\x1b[?1049h"[..], // truncated CSI
            &b"\x1b\x1b[?1049h"[..],       // ESC that introduced nothing
            &b"\x1b#\x1b[?1049h"[..],      // truncated ESC-intermediate
        ] {
            let mut s = ModeScanner::new();
            s.feed(raw, 0);
            assert!(
                s.modes().alt_screen,
                "{raw:?}: the sequence after the truncated one was lost"
            );
            assert!(
                !s.modes().bracketed_paste,
                "{raw:?}: a sequence with no final byte was applied anyway"
            );
            assert!(!s.modes().saw_bracketed_paste, "{raw:?}");
            assert_eq!(
                s.last_line(),
                "",
                "{raw:?}: escape payload leaked into the tail line"
            );
        }
    }

    #[test]
    fn can_and_sub_abandon_a_sequence_in_progress() {
        // The C0 abort controls. Real terminals resynchronise on them, and
        // a scanner that does not stays blind until a final byte happens
        // to arrive — which, inside an OSC or DCS payload, may be never.
        //
        // No escape follows the abort byte, deliberately. An `ESC` would
        // cancel the stuck sequence on its own, and this test would then
        // pass with the C0 rule deleted — which is precisely what an
        // earlier draft of it did.
        for abort in [0x18u8, 0x1a] {
            for (introducer, rest) in [
                (&b"\x1b[?2004"[..], &b"ok$ "[..]),
                (&b"\x1b]0;ti"[..], &b"tle$ "[..]),
                (&b"\x1bPtmux;q"[..], &b"done$ "[..]),
            ] {
                let mut s = ModeScanner::new();
                s.feed(introducer, 0);
                s.feed(&[abort], introducer.len() as u64);
                s.feed(rest, introducer.len() as u64 + 1);
                let want = String::from_utf8(rest.to_vec()).unwrap();
                assert_eq!(
                    s.last_line(),
                    want,
                    "{abort:#04x} {introducer:?}: never left the sequence"
                );
                assert!(
                    !s.modes().bracketed_paste && !s.modes().saw_bracketed_paste,
                    "{abort:#04x} {introducer:?}: abandoned sequence was applied"
                );
                assert_eq!(s.title(), None, "{abort:#04x} {introducer:?}");
            }
        }
    }

    #[test]
    fn an_unterminated_string_gives_up_at_the_byte_ceiling() {
        // `OSC_PAYLOAD_MAX` bounds what a sequence *stores*; nothing there
        // bounds how long a lost terminator can blind the scanner. A `cat`
        // of a binary file is enough to trigger it, and DCS is not even
        // rescued by BEL. Both introducers must give up eventually.
        for introducer in [&b"\x1b]0;"[..], &b"\x1bPtmux;"[..]] {
            let mut s = ModeScanner::new();
            let mut input = introducer.to_vec();
            input.extend(std::iter::repeat_n(b'x', SEQUENCE_MAX));
            input.extend_from_slice(b"\r\nuser@host:~$ ");
            s.feed(&input, 0);
            assert_eq!(
                s.last_line(),
                "user@host:~$ ",
                "{introducer:?}: still trapped inside the payload"
            );
            assert_eq!(
                s.title(),
                None,
                "{introducer:?}: a payload with no terminator is not a title"
            );
        }
    }

    /// A `9 KiB` control string of `kind`, correctly terminated, whose
    /// payload ends with a newline and then `tail`.
    fn oversized_but_well_formed(introducer: &[u8], terminator: &[u8], tail: &str) -> Vec<u8> {
        let mut input = introducer.to_vec();
        let filler = 9 * 1024 - introducer.len() - tail.len() - 2;
        input.extend(std::iter::repeat_n(b'A', filler));
        input.extend_from_slice(b"\r\n");
        input.extend_from_slice(tail.as_bytes());
        input.extend_from_slice(terminator);
        input
    }

    #[test]
    fn a_well_formed_sequence_under_the_blindness_ceiling_does_not_forge_a_prompt() {
        // The byte ceiling is a blindness budget for sequences that never
        // terminate. Set below what real programs emit, it fired on
        // *correctly terminated* ones and handed their payload to the tail
        // line as text — so the emitting program chose what §8.6 matched
        // against. Both rows below are 9 KiB, which tmux/vim
        // `set-clipboard` writes and sixel images routinely exceed, and
        // both payloads end in something §8.6 scores at 0.85: §8.4's act
        // threshold. Measured at the old 8 KiB ceiling as
        // "root@prod:/etc# " and "user@host:~$ ".
        //
        // **What this establishes, and what it does not.** "Under the
        // blindness ceiling" is load-bearing and used to be missing from
        // the name. These rows are 9 KiB against a `SEQUENCE_MAX` of 1 MiB,
        // so they never trip it at all — the property they pin is that a
        // correctly terminated sequence *below* the ceiling pays nothing
        // for being long, however far past `OSC_PAYLOAD_MAX` it runs.
        //
        // Past the ceiling the claim is false, and measurably so: the
        // payload's `\r\n` ends the discard and everything after it reaches
        // the full state machine. That residual is pinned at its real reach
        // — up to `AtPrompt` / `semantic` / 1.00 and injected command text
        // — by `detector::tests::sequence_ceiling_residual` (REQ-PD-018),
        // and the boundary itself by
        // `an_abandoned_sequence_cannot_forge_a_mode_from_the_payload_
        // before_the_next_newline` below.
        for (introducer, terminator, tail) in [
            (&b"\x1b]52;c;"[..], &b"\x07"[..], "root@prod:/etc# "),
            (&b"\x1bPq"[..], &b"\x1b\\"[..], "user@host:~$ "),
        ] {
            let mut s = ModeScanner::new();
            s.feed(&oversized_but_well_formed(introducer, terminator, tail), 0);
            assert_eq!(
                s.last_line(),
                "",
                "{introducer:?}: a well-formed sequence under SEQUENCE_MAX \
                 promoted its payload to terminal text"
            );
        }
    }

    #[test]
    fn a_well_formed_sequence_under_the_blindness_ceiling_does_not_leak_into_the_command() {
        // The same leak reaching the other consumer of scanner state: an
        // OSC 52 write between `B` and `C` appended ~800 bytes of clipboard
        // payload to the command that gets reported to the agent.
        //
        // Same qualification as the test above, for the same measured
        // reason: the OSC 52 here is 9 KiB against a 1 MiB ceiling. Past
        // the ceiling the payload's own `\x1b]133;` bytes are parsed as
        // real markers, so command capture takes payload — the residual is
        // `OutputStart { command: "ls\nrm -rf /" }`, not a clean "ls", and
        // it is pinned in `detector::tests::sequence_ceiling_residual`.
        let mut s = ModeScanner::new();
        s.feed(b"\x1b]133;B\x07ls\r\n", 0);
        let osc = oversized_but_well_formed(b"\x1b]52;c;", b"\x07", "root@prod:/etc# ");
        s.feed(&osc, 12);
        let ev = s.feed(b"\x1b]133;C\x07", 12 + osc.len() as u64);
        assert_eq!(
            ev[0].marker,
            Osc133::OutputStart {
                command: "ls".into()
            },
            "a well-formed sequence under SEQUENCE_MAX leaked into the \
             captured command"
        );
    }

    #[test]
    fn an_abandoned_sequence_does_not_promote_its_payload_to_text() {
        // The give-up path itself, past the ceiling this time. Once a
        // sequence is abandoned, neither the byte that tripped the ceiling
        // nor the rest of its line may become text — the payload here has
        // no newline in it, so a scanner that simply returns to `Ground`
        // reports a prompt the payload wrote.
        for introducer in [&b"\x1b]0;"[..], &b"\x1bPtmux;"[..]] {
            let mut s = ModeScanner::new();
            let mut input = introducer.to_vec();
            input.extend(std::iter::repeat_n(b'A', SEQUENCE_MAX + 64));
            input.extend_from_slice(b"bash-5.3$ ");
            s.feed(&input, 0);
            assert_eq!(
                s.last_line(),
                "",
                "{introducer:?}: abandoned payload became the tail line"
            );
        }
    }

    #[test]
    fn an_abandoned_sequence_clears_the_line_it_interrupted() {
        // The other half of the give-up. The tail line standing when a
        // sequence is abandoned was assembled on the assumption that the
        // scanner was tracking the stream correctly, and giving up says it
        // was not. An empty tail scores 0.0 and reads as `Executing`; a
        // stale one reads as a prompt that may have scrolled away long ago.
        let mut s = ModeScanner::new();
        s.feed(b"user@host:~$ ", 0);
        let mut input = b"\x1b]0;".to_vec();
        input.extend(std::iter::repeat_n(b'A', SEQUENCE_MAX + 64));
        s.feed(&input, 13);
        assert_eq!(
            s.last_line(),
            "",
            "a line the scanner can no longer vouch for was kept"
        );
    }

    #[test]
    fn an_abandoned_sequence_cannot_forge_a_mode_from_the_payload_before_the_next_newline() {
        // Ending the discarded run at the next `ESC` would resynchronise
        // sooner, at the cost of letting the abandoned payload introduce
        // sequences. That payload is chosen by the program that emitted the
        // broken sequence, and `\x1b[?2004h` inside it would set the
        // availability flag §8.4 gates on — the same forgery the CSI
        // parameter cap exists to stop, arriving through another door.
        //
        // **The name carries "before the next newline" because that is the
        // whole of what this establishes.** `Discard` exits on `\n`, so the
        // protection lasts exactly to the end of the line that tripped the
        // ceiling. The input below has no newline after the filler, which
        // is why nothing is forged.
        //
        // With `\r\n` inserted before the smuggled bytes instead, all of it
        // gets through — up to a genuine `PromptStart` and `AtPrompt` /
        // `semantic` / 1.00. That is asserted, row by row, in
        // `detector::tests::sequence_ceiling_residual` (REQ-PD-018) rather
        // than described here.
        //
        // Not a regression and not a new exposure: before the give-up path
        // existed the trip returned straight to `Ground`, so the same
        // forgeries were reachable at 8 KiB, and §8.8/REQ-PD-010 already
        // accepts that a hostile child can print `\x1b[?2004h` directly.
        // Nor does it take an adversary — the "accidental forgery needs an
        // ESC in a payload that by construction has none" reading was
        // wrong, since sixel reaches the 0.60 rung with no `ESC` at all
        // (§8.8 rev. 34). What was wrong about *this* test was its name,
        // which read as the unqualified claim.
        let mut s = ModeScanner::new();
        let mut input = b"\x1b]0;".to_vec();
        input.extend(std::iter::repeat_n(b'A', SEQUENCE_MAX + 64));
        input.extend_from_slice(b"\x1b[?2004hbash-5.3$ ");
        s.feed(&input, 0);
        assert!(
            !s.modes().saw_bracketed_paste,
            "payload before the next newline forged a tier-gating flag"
        );
        assert!(!s.modes().bracketed_paste);
        assert_eq!(s.last_line(), "");
    }

    #[test]
    fn the_byte_ceiling_is_counted_per_sequence_not_cumulatively() {
        // `seq_len` is only ever cleared by `abort`. Leave it set and the
        // ceiling becomes permanent rather than per-sequence: after one
        // long sequence every later escape trips on its first few bytes,
        // which is precisely the permanent blinding the ceiling was added
        // to prevent. Nothing else in the suite observes the reset.
        let mut s = ModeScanner::new();
        let mut input = b"\x1b]0;".to_vec();
        input.extend(std::iter::repeat_n(b'x', SEQUENCE_MAX - 8));
        input.push(0x07);
        input.extend_from_slice(b"\x1b]133;A\x07");
        let ev = s.feed(&input, 0);
        assert_eq!(
            ev.len(),
            1,
            "the ceiling carried over into the next sequence"
        );
    }

    #[test]
    fn osc133_markers_are_reported_in_order_with_offsets() {
        let input =
            b"\x1b]133;A\x07$ \x1b]133;B\x07echo hi\r\n\x1b]133;C\x07hi\r\n\x1b]133;D;0\x07";
        let (_, ev) = scan(input);
        assert_eq!(ev.len(), 4);
        assert_eq!(ev[0].marker, Osc133::PromptStart);
        assert_eq!(ev[1].marker, Osc133::CommandStart);
        assert_eq!(
            ev[2].marker,
            Osc133::OutputStart {
                command: "echo hi".into()
            }
        );
        assert_eq!(ev[3].marker, Osc133::CommandDone { exit_code: Some(0) });

        // The C marker's `end` is where the command's output begins, and
        // the D marker's `start` is where it ends. A history entry built
        // from them must span exactly "hi\r\n".
        let out = &input[ev[2].end as usize..ev[3].start as usize];
        assert_eq!(out, b"hi\r\n");
    }

    #[test]
    fn the_captured_command_survives_a_line_editor_redraw() {
        // Measured `zsh` byte stream: it echoes the first keystroke, undoes
        // it with a backspace, redraws the line, then submits with
        // `\r\r\n`. Naive accumulation yields "eecho hello"; treating
        // every `\r` in the run as a bare return yields "". Both were
        // observed against a real PTY before this rule existed.
        let input =
            b"\x1b]133;B\x07\x1b[K\x1b[?2004he\x08echo hello\x1b[?2004l\r\r\n\x1b]133;C\x07";
        let (_, ev) = scan(input);
        assert_eq!(
            ev[1].marker,
            Osc133::OutputStart {
                command: "echo hello".into()
            }
        );
    }

    #[test]
    fn a_bare_carriage_return_overwrites_the_captured_command() {
        let (_, ev) = scan(b"\x1b]133;B\x07junk\rreal command\r\n\x1b]133;C\x07");
        assert_eq!(
            ev[1].marker,
            Osc133::OutputStart {
                command: "real command".into()
            }
        );
    }

    #[test]
    fn a_carriage_return_split_across_chunks_still_pairs_with_its_newline() {
        let mut s = ModeScanner::new();
        s.feed(b"\x1b]133;B\x07echo hi\r", 0);
        let ev = s.feed(b"\n\x1b]133;C\x07", 16);
        assert_eq!(
            ev[0].marker,
            Osc133::OutputStart {
                command: "echo hi".into()
            }
        );
    }

    #[test]
    fn a_bare_carriage_return_at_a_chunk_boundary_still_overwrites_the_capture() {
        // The sibling test above splits `\r` from its `\n`, which stays
        // green even if the lookahead is dropped at every chunk boundary:
        // the `\n` appends either way. This one splits a *bare* `\r` from
        // the text that overwrites it, so only a `pending_cr` that survives
        // the boundary gets it right. That is the likeliest instance of the
        // whole class — a PTY read ending just after a progress bar's `\r`
        // is what `cargo`, `curl` and every spinner produce all day.
        let mut s = ModeScanner::new();
        s.feed(b"\x1b]133;B\x07junk\r", 0);
        let ev = s.feed(b"real\r\n\x1b]133;C\x07", 13);
        assert_eq!(
            ev[0].marker,
            Osc133::OutputStart {
                command: "real".into()
            },
            "the carriage return did not carry across the chunk boundary"
        );
    }

    #[test]
    fn a_second_command_start_restarts_the_capture() {
        // `B` always begins a fresh command line; it does not resume an
        // open one. Reusing the capture concatenates two prompts' worth of
        // echo into a single command ("onetwo").
        let (_, ev) = scan(b"\x1b]133;B\x07one\x1b]133;B\x07two\r\n\x1b]133;C\x07");
        assert_eq!(
            ev[2].marker,
            Osc133::OutputStart {
                command: "two".into()
            }
        );
    }

    #[test]
    fn text_outside_a_b_to_c_span_is_not_captured() {
        // Prompt text sits between A and B and must not become the command.
        let (_, ev) = scan(b"\x1b]133;A\x07bash-5.3$ \x1b]133;B\x07ls\r\n\x1b]133;C\x07");
        assert_eq!(
            ev[2].marker,
            Osc133::OutputStart {
                command: "ls".into()
            }
        );
    }

    #[test]
    fn osc133_exit_codes_are_parsed() {
        for (raw, want) in [
            (&b"\x1b]133;D;0\x07"[..], Some(0)),
            (&b"\x1b]133;D;1\x07"[..], Some(1)),
            (&b"\x1b]133;D;42\x07"[..], Some(42)),
            (&b"\x1b]133;D\x07"[..], None),
        ] {
            let (_, ev) = scan(raw);
            assert_eq!(
                ev[0].marker,
                Osc133::CommandDone { exit_code: want },
                "{raw:?}"
            );
        }
    }

    #[test]
    fn osc133_accepts_the_st_terminator() {
        let (_, ev) = scan(b"\x1b]133;A\x1b\\");
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].marker, Osc133::PromptStart);
    }

    #[test]
    fn unknown_osc133_subcommands_do_not_move_the_t1_state() {
        // The T1 state is *two* things, and `saw_osc133` is the half that
        // decides everything: `detector::snapshot_at` reads it alone for
        // `session_tier` and for both T1 rungs. So the first rows here run
        // on a fresh scanner. The row at the bottom has a real `B` in front
        // of the unmodelled marker and so leaves the flag true in either
        // build — which is exactly how this half came to be unasserted
        // under a name that claims to cover it.
        //
        // Kitty and WezTerm shell integrations emit `133;P;k=i` and
        // `133;L`, and an rc file can emit them with no `A`/`B`/`C`/`D`
        // anywhere. Setting availability from one of those gives `t1 ==
        // true` with `at_marker` never true, which falls straight to the
        // T1 executing rung and reports `Executing` / `semantic` / 0.00 at
        // a live prompt for the rest of the session, with nothing able to
        // clear it — the rev.-27 `saw_alt_screen` defect in the T1
        // dimension. Pinned end-to-end in
        // `detector::tests::availability::an_unmodelled_osc_133_subcommand_
        // does_not_make_the_session_semantic`.
        for raw in [&b"\x1b]133;P;k=i\x07"[..], &b"\x1b]133;L\x07"[..]] {
            let (s, ev) = scan(raw);
            assert!(ev.is_empty(), "{raw:?}: an unmodelled marker was emitted");
            assert!(
                !s.modes().saw_osc133,
                "{raw:?}: an unmodelled marker forged T1 availability"
            );
            assert_eq!(s.last_marker(), None, "{raw:?}");
        }

        // Nor does it disturb a T1 state that a modelled marker really did
        // establish: availability stays set, `last_marker` stays on `B`.
        let (s, ev) = scan(b"\x1b]133;B\x07\x1b]133;P;k=i\x07");
        assert_eq!(ev.len(), 1, "only B is modelled");
        assert!(s.modes().saw_osc133, "a real B must still set availability");
        assert_eq!(s.last_marker(), Some(b'B'));
    }

    #[test]
    fn an_osc_with_a_lost_terminator_does_not_swallow_the_next_marker() {
        // Treating a non-ST escape as payload means one dropped `\x07`
        // consumes every marker until some later BEL arrives — and then
        // reports the wreckage as a window title.
        let (s, ev) = scan(b"\x1b]0;oops\x1b]133;A\x07");
        assert_eq!(ev.len(), 1, "the marker was eaten by the unterminated OSC");
        assert_eq!(ev[0].marker, Osc133::PromptStart);
        assert_eq!(
            s.title(),
            None,
            "a payload with no terminator was reported as a title"
        );
    }

    #[test]
    fn window_title_is_captured() {
        let (s, _) = scan(b"\x1b]0;user@host: ~\x07");
        assert_eq!(s.title(), Some("user@host: ~"));
        let (s, _) = scan(b"\x1b]2;just the title\x07");
        assert_eq!(s.title(), Some("just the title"));
    }

    #[test]
    fn escape_sequences_never_reach_the_tail_line() {
        let mut s = ModeScanner::new();
        s.feed(b"\x1b[1;32muser@host\x1b[0m:\x1b[34m~\x1b[0m$ ", 0);
        assert_eq!(s.last_line(), "user@host:~$ ");
    }

    #[test]
    fn carriage_return_restarts_the_tail_line() {
        let mut s = ModeScanner::new();
        s.feed(b"downloading 45%\rdownloading 90%", 0);
        assert_eq!(s.last_line(), "downloading 90%");
    }

    #[test]
    fn newline_restarts_the_tail_line() {
        let mut s = ModeScanner::new();
        s.feed(b"one\ntwo\nthree$ ", 0);
        assert_eq!(s.last_line(), "three$ ");
    }

    #[test]
    fn tail_line_keeps_the_newest_bytes_when_it_overflows() {
        let mut s = ModeScanner::new();
        let long = vec![b'x'; TAIL_LINE_MAX + 50];
        s.feed(&long, 0);
        s.feed(b"$ ", long.len() as u64);
        let line = s.last_line();
        assert_eq!(line.len(), TAIL_LINE_MAX);
        assert!(line.ends_with("$ "), "kept the head instead of the tail");
    }

    #[test]
    fn an_oversized_osc_payload_is_discarded_and_the_machine_resynchronises() {
        // Named for what it asserts: the payload is not trusted, and the
        // scanner picks the stream back up. It does *not* assert anything
        // about buffer growth — `OSC_PAYLOAD_MAX` is what bounds that, and
        // proving it here would mean exposing buffer sizes as API.
        let mut s = ModeScanner::new();
        let mut input = b"\x1b]0;".to_vec();
        input.extend(std::iter::repeat_n(b'A', OSC_PAYLOAD_MAX * 4));
        input.extend_from_slice(b"\x07after$ ");
        s.feed(&input, 0);
        assert_eq!(s.title(), None, "overflowed payload must not be trusted");
        assert_eq!(s.last_line(), "after$ ", "machine failed to resynchronise");
    }

    #[test]
    fn a_dcs_string_is_consumed_whole() {
        let mut s = ModeScanner::new();
        s.feed(b"\x1bPtmux;\x1b[?2004h\x1b\\clean$ ", 0);
        assert!(
            !s.modes().bracketed_paste,
            "a mode set inside a DCS payload is data, not a mode change"
        );
        assert_eq!(s.last_line(), "clean$ ");
    }

    #[test]
    fn offsets_are_absolute_across_feeds() {
        let mut s = ModeScanner::new();
        s.feed(b"hello", 1000);
        let ev = s.feed(b"\x1b]133;A\x07", 1005);
        assert_eq!(ev[0].start, 1005);
        assert_eq!(ev[0].end, 1013);
    }
}
