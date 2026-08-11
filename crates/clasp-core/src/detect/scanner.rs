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
    /// OSC payload, without the introducer or terminator.
    osc: Vec<u8>,
    /// True once the payload exceeded `OSC_PAYLOAD_MAX`; the rest is
    /// consumed but not kept, and the marker is not interpreted.
    osc_overflowed: bool,
    /// Offset of the `\x1b` that started the sequence being parsed.
    seq_start: u64,
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
            osc: Vec::new(),
            osc_overflowed: false,
            seq_start: 0,
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
            match self.state {
                State::Ground => self.ground(b, offset),
                State::Esc => self.esc(b),
                State::EscIntermediate => {
                    if !(0x20..=0x2f).contains(&b) {
                        self.state = State::Ground;
                    }
                }
                State::Csi => self.csi(b),
                State::Osc => self.osc_byte(b, offset, &mut events),
                State::OscEsc => {
                    if b == b'\\' {
                        self.finish_osc(offset + 1, &mut events);
                    } else {
                        // Not ST after all: the ESC belonged to the payload.
                        self.push_osc(0x1b);
                        self.state = State::Osc;
                        self.osc_byte(b, offset, &mut events);
                    }
                }
                State::Str => {
                    if b == 0x1b {
                        self.state = State::StrEsc;
                    }
                }
                State::StrEsc => {
                    self.state = if b == b'\\' {
                        State::Ground
                    } else {
                        State::Str
                    };
                }
            }
        }
        events
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
            0x1b => {
                self.seq_start = offset;
                self.state = State::Esc;
            }
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

    fn esc(&mut self, b: u8) {
        self.state = match b {
            b'[' => {
                self.params.clear();
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

    fn csi(&mut self, b: u8) {
        if (0x40..=0x7e).contains(&b) {
            self.apply_csi(b);
            self.state = State::Ground;
        } else if self.params.len() < 64 {
            self.params.push(b);
        }
    }

    /// DEC private mode set/reset. `\x1b[?2004h` and friends may carry
    /// several parameters at once (`\x1b[?1049;2004h`), so each is applied.
    fn apply_csi(&mut self, final_byte: u8) {
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
        let (s, ev) = scan(b"\x1b]133;B\x07\x1b]133;P;k=i\x07");
        assert_eq!(ev.len(), 1, "only B is modelled");
        assert_eq!(s.last_marker(), Some(b'B'));
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
    fn an_oversized_osc_payload_resynchronises_without_growing() {
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
