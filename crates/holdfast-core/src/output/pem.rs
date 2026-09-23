//! How far a `-----BEGIN` candidate is believed (GH #242).
//!
//! `private-key-block` is `-----BEGIN…PRIVATE KEY-----[\s\S]*?-----END…`,
//! and the lazy `[\s\S]*?` never reaches a dead state: from the moment the
//! header lands, *some* later byte could still complete the match. So an
//! unterminated header — which this repository's own `CHANGELOG.md`
//! contains several times as prose — kept its candidate believed until
//! the carry ran out, and every read surface masked the next 16 KiB: about
//! thirty-five commands, a quarter of the CHANGELOG, a third of it on the
//! `watch` stream.
//!
//! **The rule is not what this module narrows.** A complete
//! `-----BEGIN…-----END` pair is still matched by `[\s\S]*?` whatever lies
//! between the two boundaries — a key printed by `bat` with its gutter, a
//! removed key in `git show` with a `-` on every line, a key in a log with
//! a timestamp on every line all still redact as `private-key`, exactly as
//! before. What changes is the *candidate*: the region a read, the grid
//! and the stream mask when the closing boundary has **not** arrived.
//!
//! **A PEM body has a known alphabet** (RFC 7468 §3): base64 in lines,
//! optionally preceded by RFC 1421 / RFC 4880 armour headers
//! (`Proc-Type: 4,ENCRYPTED`, `DEK-Info: …`, `Comment: …`). So a candidate
//! is believed while what follows its header can still be PEM text, and
//! stops at the first byte that cannot be. `-----BEGIN RSA PRIVATE
//! KEY-----` followed by a closing backtick dies on the backtick; followed
//! by a shell prompt it dies on the prompt's first glyph or punctuation.
//! Two spellings of the body are accepted beyond the textbook one,
//! because a key reaches a terminal through both constantly: JSON's
//! escaped line breaks (`\n`, `\r\n`, `\/` — a GCP service-account file,
//! `terraform output -json`) and whitespace in place of line breaks
//! (`echo $KEY` unquoted).
//!
//! **Where the candidate stops is not where the mask stops.** A candidate
//! that dies *with key material behind it* — `head -n 15 id_rsa` and then
//! a prompt — is still a key body nobody will close, and it is masked from
//! its header to the byte that killed it. A candidate that dies with none
//! — prose — is not masked at all. "Material" is a run of
//! [`PEM_MATERIAL_RUN`] base64 characters; see that constant for why the
//! number is sixteen and what it costs.
//!
//! **Judged over every stream a read can emit, not over the raw bytes
//! alone**, for the reason `normalise` gives: a view may add a marker,
//! and this module only ever *extends* a mask relative to the raw
//! answer. The four 7-bit streams — raw, stripped, printable and
//! stripped-printable — are walked in lockstep, each through the same
//! filters `normalise::build` applies, and the candidate lives while any
//! of them does. The walk is exact over those four. It is **conservative
//! over the eight C1 streams**: until the first byte in `0x80..=0x9f` they
//! are identical to their 7-bit bases, and at that byte the walk gives up
//! and answers "alive to the end of the region" rather than modelling
//! `c1_mask`, which can consume arbitrary text after an introducer.
//! A well-formed non-ASCII character never reaches that arm while any
//! stream is alive, because its lead byte is not PEM text and kills every
//! stream at once — the lead is never a C1 byte, and no C1 view drops it.
//!
//! **What it does not model is the rendered grid**, where `\r` and cursor
//! movement can overwrite the byte that killed a candidate. The grid runs
//! this same walk over its *own* joined render (`ScreenTracker`), which is
//! the stream it emits, so a header still on screen is judged on what the
//! screen shows; a header scrolled off it is judged on the byte stream.

use super::ansi::AnsiStripper;
use super::encoding::lossy_printable_keeps;

/// A body is "key material" once it carries this many consecutive base64
/// characters, and only a candidate with material is masked after it
/// dies.
///
/// **Sixteen characters is twelve bytes of DER, and the number is chosen
/// against both sides.** Every body line a real key is printed with is
/// 64 characters (70 for OpenSSH), so any key cut after its first line
/// clears it by a factor of four. Prose rarely does: sixteen consecutive
/// letters or digits with no space or punctuation is a hash, a long path,
/// or `internationalization` — and the whole cost of one is that the line
/// it sits on is masked.
///
/// **The residual, stated rather than elided.** A key cut *inside the
/// first sixteen characters of its body* and followed on the same line by
/// a byte that cannot be PEM text is released. For RSA, PKCS#8 and
/// OpenSSH those characters are public structure — a DER `SEQUENCE`
/// header, a version, an algorithm identifier, the `openssh-key-v1`
/// magic. For a SEC1 EC key the private scalar starts at byte seven, so
/// such a cut can release up to five bytes of it. It takes `head -c` or a
/// program that prints a partial first line and then punctuation on the
/// same line.
pub const PEM_MATERIAL_RUN: u32 = 16;

/// The longest label accepted between `-----BEGIN` and the dashes that
/// close it. RFC 7468 sets none; the longest the rule set can match is
/// `[ A-Z]{0,20}PRIVATE KEY[ A-Z]{0,10}`, 42 bytes, and this is twice
/// that so a label the rule rejects still dies on the rule's own
/// automaton rather than here.
const MAX_LABEL: u16 = 84;

/// What the walk found for one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PemExtent {
    /// Index into the region one past the last byte the candidate is
    /// believed over: the region's length when [`alive`](Self::alive),
    /// the end of `-----END…-----` when a stream closed it, and otherwise
    /// the byte that killed the last stream to die — pulled back to the
    /// start of that byte's line when the line carried no material, so a
    /// prompt that happens to follow a truncated key keeps its text.
    pub end: usize,
    /// Some stream can still be PEM text at the region's end.
    pub alive: bool,
    /// Some stream carried [`PEM_MATERIAL_RUN`] base64 characters before
    /// it died or closed.
    pub material: bool,
}

/// Whether `region[at..]` opens an RFC 7468 pre-encapsulation boundary,
/// which is the one shape this module judges. A binary rule anchored on
/// anything else keeps its own automaton and nothing more.
pub fn opens_boundary(region: &[u8], at: usize) -> bool {
    region[at..].starts_with(b"-----BEGIN")
}

/// Walk the candidate at `region[at..]`, which [`opens_boundary`].
pub fn extent(region: &[u8], at: usize) -> PemExtent {
    debug_assert!(opens_boundary(region, at));
    let start = at + b"-----BEGIN".len();
    let mut lanes = [
        Lane::new(Filter::Raw, start),
        Lane::new(Filter::Stripped, start),
        Lane::new(Filter::Printable, start),
        Lane::new(Filter::StrippedPrintable, start),
    ];
    let mut i = start;
    // Continuation bytes still owed to the UTF-8 sequence the last lead
    // byte opened.
    let mut owed = 0u8;
    while i < region.len() {
        if lanes.iter().all(|l| !l.live()) {
            break;
        }
        let byte = region[i];
        let continuation = owed > 0 && (0x80..=0xbf).contains(&byte);
        owed = if continuation {
            owed - 1
        } else {
            match byte {
                0xc2..=0xdf => 1,
                0xe0..=0xef => 2,
                0xf0..=0xf4 => 3,
                _ => 0,
            }
        };
        // The C1 arm: see the module header. A lone `0x80..=0x9f`, or the
        // two-byte spelling `0xc2 0x80..=0x9f`, is dropped or consumed as
        // an introducer by the C1 streams, which this walk does not model;
        // while any stream is still alive, give up and believe the rest.
        //
        // **Except a continuation byte of a well-formed character that
        // introduces nothing**, which is the common case and was the
        // costly one: `✔` in a prompt's window title is `e2 9c 94`, both
        // continuations in the C1 range. A C1 stream only *drops* such a
        // byte, and every stream still alive at it is one that did not die
        // on the lead byte in front of it — so it is inside an escape
        // sequence the stripper is consuming (an OSC title, a DCS string),
        // where a dropped byte changes nothing. The one arrangement this
        // does not cover is a lead byte consumed as the single byte a
        // charset designator takes (`ESC (` directly in front of a
        // multi-byte character), after which the stripper emits the
        // continuation a C1 stream drops. The five that open a sequence
        // under `C1::Strip` —
        // `0x90`, `0x9b`, `0x9d`, `0x9e`, `0x9f` — can end that sequence's
        // terminator early or late, so they keep the arm (`”` is `e2 80
        // 9d`).
        let c1 = if continuation {
            matches!(byte, 0x90 | 0x9b | 0x9d | 0x9e | 0x9f)
        } else {
            (0x80..=0x9f).contains(&byte)
                || (byte == 0xc2 && region.get(i + 1).is_none_or(|n| (0x80..=0x9f).contains(n)))
        };
        if c1 && lanes.iter().any(Lane::live) {
            return PemExtent {
                end: region.len(),
                alive: true,
                material: lanes.iter().any(|l| l.material),
            };
        }
        for lane in lanes.iter_mut() {
            lane.feed(i, byte);
        }
        i += 1;
    }
    let alive = lanes.iter().any(Lane::live);
    PemExtent {
        end: if alive {
            region.len()
        } else {
            lanes.iter().map(Lane::believed_end).max().unwrap_or(start)
        },
        alive,
        material: lanes.iter().any(|l| l.material),
    }
}

/// Which of `normalise`'s 7-bit pipeline filters a lane applies before
/// its grammar sees a byte. Kept in step with `normalise::build` by using
/// the same two primitives: `AnsiStripper::feed` and
/// `lossy_printable_keeps`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filter {
    Raw,
    Stripped,
    Printable,
    StrippedPrintable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// After `-----BEGIN`: the label, up to the dashes that close it.
    Label {
        len: u16,
        dashes: u8,
    },
    /// At the start of a line, before anything but whitespace.
    LineStart,
    /// A line that is armour-header name characters so far.
    HeaderName {
        len: u16,
        dash: bool,
    },
    /// An armour header's value, up to its line break; `end_seen` counts
    /// the bytes of a `-----END` arriving inside it.
    HeaderValue {
        end_seen: u8,
    },
    /// Base64 text and whitespace.
    Body,
    /// A backslash: JSON's escaped line break, or `\/`. `in_value` says
    /// which phase it returns to.
    Backslash {
        in_value: bool,
    },
    /// Somewhere inside `-----END…-----`; `seen` counts the bytes of the
    /// fixed `-----END` matched, then `dashes` the closing run.
    End {
        seen: u8,
        label: u16,
        dashes: u8,
    },
    Dead,
    Closed,
}

struct Lane {
    filter: Filter,
    stripper: AnsiStripper,
    phase: Phase,
    /// The body has carried a run of [`PEM_MATERIAL_RUN`] base64
    /// characters outside any armour header, so no further header may
    /// open. A shorter run does not count: `cat -n` puts a line number in
    /// front of `Proc-Type:`, and that is not the body starting.
    seen_body: bool,
    run: u32,
    material: bool,
    /// Region index just past the most recent line break, and whether
    /// that line has carried material yet.
    line_start: usize,
    line_material: bool,
    /// Where the body began: headers and body both start after the
    /// label's closing dashes.
    body_start: usize,
    /// The byte that killed this lane, or one past the closing dash.
    stopped_at: Option<usize>,
}

impl Lane {
    fn new(filter: Filter, start: usize) -> Self {
        Self {
            filter,
            stripper: AnsiStripper::new(),
            phase: Phase::Label { len: 0, dashes: 0 },
            seen_body: false,
            run: 0,
            material: false,
            line_start: start,
            line_material: false,
            body_start: start,
            stopped_at: None,
        }
    }

    fn live(&self) -> bool {
        !matches!(self.phase, Phase::Dead | Phase::Closed)
    }

    /// Where this lane stops believing the candidate. Only meaningful
    /// once it has stopped.
    fn believed_end(&self) -> usize {
        let at = self.stopped_at.unwrap_or(self.line_start);
        match self.phase {
            Phase::Closed => at,
            // A line that carried no material is released from its start,
            // unless it is the header's own line — pulling back past the
            // header would put the end in front of the candidate.
            _ if !self.line_material && self.line_start > self.body_start => self.line_start,
            _ => at,
        }
    }

    fn feed(&mut self, at: usize, raw: u8) {
        if !self.live() {
            return;
        }
        let byte = match self.filter {
            Filter::Raw => Some(raw),
            Filter::Printable => lossy_printable_keeps(raw).then_some(raw),
            Filter::Stripped => self.stripper.feed(at as u64, raw),
            Filter::StrippedPrintable => self
                .stripper
                .feed(at as u64, raw)
                .filter(|b| lossy_printable_keeps(*b)),
        };
        if let Some(b) = byte {
            self.step(at, b);
        }
    }

    fn kill(&mut self, at: usize) {
        self.phase = Phase::Dead;
        self.stopped_at = Some(at);
    }

    fn line_break(&mut self, at: usize) {
        self.run = 0;
        self.line_start = at + 1;
        self.line_material = false;
        self.phase = Phase::LineStart;
    }

    fn base64(&mut self) {
        self.base64_in_value();
        self.seen_body |= self.run >= PEM_MATERIAL_RUN;
    }

    /// A base64 character that does not open the body — one inside an
    /// armour header's value.
    fn base64_in_value(&mut self) {
        self.run += 1;
        if self.run >= PEM_MATERIAL_RUN {
            self.material = true;
            self.line_material = true;
        }
    }

    fn step(&mut self, at: usize, b: u8) {
        match self.phase {
            Phase::Dead | Phase::Closed => {}
            Phase::Label { len, dashes } => {
                // RFC 7468 labels are printable ASCII; `\t` is accepted as
                // well because the rendered grid expands it into the
                // spaces the rule's `[ A-Z]` accepts, and a label the rule
                // rejects dies on the rule's automaton anyway.
                if !(b == b'\t' || (0x20..=0x7e).contains(&b)) || len >= MAX_LABEL {
                    return self.kill(at);
                }
                let dashes = if b == b'-' { dashes + 1 } else { 0 };
                if dashes == 5 {
                    self.body_start = at + 1;
                    self.line_start = at + 1;
                    self.phase = Phase::Body;
                } else {
                    self.phase = Phase::Label {
                        len: len + 1,
                        dashes,
                    };
                }
            }
            Phase::LineStart => match b {
                b' ' | b'\t' | b'\r' => {}
                b'\n' => self.line_break(at),
                _ => {
                    self.phase = Phase::Body;
                    self.step(at, b);
                }
            },
            Phase::HeaderName { len, dash } => match b {
                b':' => {
                    self.run = 0;
                    self.phase = Phase::HeaderValue { end_seen: 0 };
                }
                b'-' => {
                    self.phase = Phase::HeaderName {
                        len: len + 1,
                        dash: true,
                    }
                }
                _ if b.is_ascii_alphanumeric() && len < MAX_LABEL => {
                    self.run += 1;
                    self.phase = Phase::HeaderName { len: len + 1, dash };
                }
                // Not a header after all. A name with a dash in it is not
                // base64 either; one without is the first run of a body
                // line, and the byte that ended it is judged as body.
                _ if dash => self.kill(at),
                _ => {
                    let run = self.run;
                    self.run = 0;
                    for _ in 0..run {
                        self.base64();
                    }
                    self.phase = Phase::Body;
                    self.step(at, b);
                }
            },
            Phase::HeaderValue { end_seen } => {
                // A value runs to its line break — and in `echo $KEY`'s
                // spelling there is none, so the closing boundary can
                // arrive inside one and has to be recognised there.
                const OPEN: &[u8] = b"-----END";
                let end_seen = if b == OPEN[end_seen as usize] {
                    end_seen + 1
                } else {
                    u8::from(b == OPEN[0])
                };
                if end_seen as usize == OPEN.len() {
                    self.phase = Phase::End {
                        seen: end_seen,
                        label: 0,
                        dashes: 0,
                    };
                    return;
                }
                // The value's own base64 counts as material: a DEK-Info
                // IV is public, but in the flattened spelling the body
                // itself runs on inside the last header's value.
                if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=') {
                    self.base64_in_value();
                } else {
                    self.run = 0;
                }
                match b {
                    b'\n' => self.line_break(at),
                    b'\\' => self.phase = Phase::Backslash { in_value: true },
                    b'\t' | b'\r' | 0x20..=0x7e => self.phase = Phase::HeaderValue { end_seen },
                    _ => self.kill(at),
                }
            }
            Phase::Backslash { in_value } => match b {
                b'n' => self.line_break(at),
                b'\\' => {}
                b'r' | b't' => {
                    self.phase = if in_value {
                        Phase::HeaderValue { end_seen: 0 }
                    } else {
                        Phase::Body
                    }
                }
                b'/' if !in_value => {
                    self.base64();
                    self.phase = Phase::Body;
                }
                0x20..=0x7e if in_value => self.phase = Phase::HeaderValue { end_seen: 0 },
                _ => self.kill(at),
            },
            Phase::Body => match b {
                // Armour headers come before the body (RFC 1421, RFC 4880),
                // at a line start or — unquoted `echo $KEY` — after the
                // whitespace that replaced one. A name that turns out not
                // to be one is handed back as base64 by `HeaderName`.
                _ if !self.seen_body && self.run == 0 && b.is_ascii_alphabetic() => {
                    self.phase = Phase::HeaderName {
                        len: 1,
                        dash: false,
                    };
                    self.run = 1;
                }
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' => self.base64(),
                b' ' | b'\t' | b'\r' => self.run = 0,
                b'\n' => self.line_break(at),
                b'\\' => {
                    self.run = 0;
                    self.phase = Phase::Backslash { in_value: false };
                }
                b'-' => {
                    self.run = 0;
                    self.phase = Phase::End {
                        seen: 1,
                        label: 0,
                        dashes: 0,
                    };
                }
                _ => self.kill(at),
            },
            Phase::End {
                seen,
                label,
                dashes,
            } => {
                const OPEN: &[u8] = b"-----END";
                if (seen as usize) < OPEN.len() {
                    if b == OPEN[seen as usize] {
                        self.phase = Phase::End {
                            seen: seen + 1,
                            label,
                            dashes,
                        };
                    } else {
                        self.kill(at);
                    }
                    return;
                }
                if !(b == b'\t' || (0x20..=0x7e).contains(&b)) || label >= MAX_LABEL {
                    return self.kill(at);
                }
                let dashes = if b == b'-' { dashes + 1 } else { 0 };
                if dashes == 5 {
                    self.phase = Phase::Closed;
                    self.stopped_at = Some(at + 1);
                } else {
                    self.phase = Phase::End {
                        seen,
                        label: label + 1,
                        dashes,
                    };
                }
            }
        }
    }
}

/// Throwaway private keys in every format the rule has to hold, for the
/// tests of every surface that masks one.
///
/// **Generated for these tests on 2026-09-23 with OpenSSL 3.0.13 and
/// OpenSSH 9.6, and protecting nothing.** Each file holds the text between
/// a key's encapsulation boundaries and not the boundaries themselves, so
/// the repository carries no `-----BEGIN … PRIVATE KEY-----` block for a
/// secret scanner to page anybody about; [`Key::pem`] puts the boundaries
/// back. Stored rather than generated at test time because a test that
/// needs `openssl` on the host either fails on a runner without it or
/// skips there, and this suite's skip census admits no new skips.
#[cfg(test)]
pub(crate) mod fixtures {
    pub(crate) struct Key {
        pub name: &'static str,
        pub label: &'static str,
        body: &'static str,
    }

    impl Key {
        /// The key as `cat` prints it, with `\n` line ends whatever the
        /// checkout did to the fixture file.
        pub fn pem(&self) -> String {
            format!(
                "-----BEGIN {label}-----\n{body}-----END {label}-----\n",
                label = self.label,
                body = self.body.replace("\r\n", "\n")
            )
        }

        /// The base64 lines of the body — not the armour headers a legacy
        /// encrypted key carries, which are public.
        pub fn material_lines(&self) -> Vec<&'static str> {
            self.body
                .lines()
                .map(str::trim_end)
                .filter(|l| !l.is_empty() && !l.contains(':'))
                .collect()
        }

        /// A run of this key's material in `text`, if any: sixteen-byte
        /// windows at a four-byte step, so a leaked run of nineteen or more
        /// characters is found wherever it starts.
        pub fn leaked_in(&self, text: &str) -> Option<&'static str> {
            self.material_lines().into_iter().find_map(|line| {
                (0..line.len().saturating_sub(15))
                    .step_by(4)
                    .map(|i| &line[i..i + 16])
                    .find(|w| text.contains(w))
            })
        }
    }

    macro_rules! key {
        ($name:literal, $label:literal) => {
            Key {
                name: $name,
                label: $label,
                body: include_str!(concat!("../../tests/fixtures/pem-bodies/", $name, ".body")),
            }
        };
    }

    /// PKCS#1 RSA at two sizes, PKCS#8 plain and encrypted, legacy
    /// encrypted PKCS#1 with its `Proc-Type`/`DEK-Info` headers, SEC1 EC,
    /// traditional DSA, and OpenSSH Ed25519 and RSA.
    pub(crate) const KEYS: &[Key] = &[
        key!("rsa-pkcs1", "RSA PRIVATE KEY"),
        key!("rsa4096-pkcs1", "RSA PRIVATE KEY"),
        key!("pkcs8", "PRIVATE KEY"),
        key!("pkcs8-encrypted", "ENCRYPTED PRIVATE KEY"),
        key!("rsa-legacy-encrypted", "RSA PRIVATE KEY"),
        key!("ec-sec1", "EC PRIVATE KEY"),
        key!("dsa", "DSA PRIVATE KEY"),
        key!("openssh-ed25519", "OPENSSH PRIVATE KEY"),
        key!("openssh-rsa3072", "OPENSSH PRIVATE KEY"),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "-----BEGIN RSA PRIVATE KEY-----";
    const LINE: &str = "MIIEowIBAAKCAQEAy8Dbv8prpJ0123456789abcdefghijABCDEFGHIJ+/0123456";

    fn walk(text: &str) -> PemExtent {
        extent(text.as_bytes(), 0)
    }

    #[test]
    fn a_body_still_arriving_is_alive_with_material() {
        let text = format!("{HEADER}\n{LINE}\n{LINE}\n{}", &LINE[..20]);
        assert_eq!(
            walk(&text),
            PemExtent {
                end: text.len(),
                alive: true,
                material: true
            }
        );
    }

    #[test]
    fn prose_after_a_header_dies_at_once_and_carries_nothing() {
        let text = format!("`{HEADER}` as **prose**, in the paragraph");
        let e = extent(text.as_bytes(), 1);
        assert!(!e.alive);
        assert!(!e.material);
        assert_eq!(e.end, 1 + HEADER.len(), "dies on the closing backtick");
    }

    #[test]
    fn a_truncated_key_then_a_prompt_is_masked_to_the_prompts_line() {
        let text = format!("{HEADER}\r\n{LINE}\r\n{LINE}\r\nuser@host:~$ ");
        let e = walk(&text);
        assert!(!e.alive);
        assert!(e.material);
        assert_eq!(
            &text[e.end..],
            "user@host:~$ ",
            "the prompt's line carried no material, so it is released whole"
        );
    }

    #[test]
    fn a_closing_boundary_closes_the_candidate() {
        let text = format!("{HEADER}\n{LINE}\n-----END RSA PRIVATE KEY-----\nmore");
        let e = walk(&text);
        assert!(!e.alive);
        assert!(e.material);
        assert_eq!(&text[e.end..], "\nmore");
    }

    /// **Every real key format is believed at every point of its arrival,
    /// and closed by its own boundary** — the half of GH #242 that must not
    /// move. A key streamed into the ring is judged at whatever byte the
    /// last read happened to end on, so every prefix is asked, not a
    /// sample: a walk that dies anywhere inside a real key releases the
    /// rest of it to the read that follows.
    #[test]
    fn every_fixture_key_is_alive_at_every_cut_and_closed_at_its_end() {
        for key in fixtures::KEYS {
            let pem = key.pem();
            let end = pem.rfind("-----END").unwrap();
            for spelling in [pem.clone(), pem.replace('\n', "\r\n")] {
                let end = spelling.rfind("-----END").unwrap();
                for cut in 11..end {
                    let e = extent(&spelling.as_bytes()[..cut], 0);
                    assert!(
                        e.alive && e.end == cut,
                        "{}: cut at {cut} of {}: {e:?}",
                        key.name,
                        spelling.len()
                    );
                }
            }
            let e = walk(&pem);
            assert!(!e.alive && e.material, "{}: {e:?}", key.name);
            assert_eq!(
                &pem[e.end..],
                "\n",
                "{}: closed at its own boundary",
                key.name
            );
            assert!(end < e.end);
        }
    }

    /// The spellings a key reaches a terminal in besides `cat`, each one
    /// closed as a whole and alive at every line on the way.
    #[test]
    fn a_key_is_believed_in_every_spelling_a_terminal_shows_it_in() {
        for key in fixtures::KEYS {
            let pem = key.pem();
            let body_and_end = &pem[pem.find('\n').unwrap() + 1..];
            let header = &pem[..pem.find('\n').unwrap()];
            let spellings = [
                // JSON: a GCP service-account file, `terraform output -json`.
                ("json", pem.replace('\n', "\\n")),
                ("json crlf", pem.replace('\n', "\\r\\n")),
                // PHP's `json_encode` escapes the slash as well.
                ("json slash", pem.replace('\n', "\\n").replace('/', "\\/")),
                // `echo $KEY`, unquoted: every line break is a space.
                ("flattened", pem.replace('\n', " ")),
                // A YAML block scalar.
                ("yaml", pem.lines().map(|l| format!("    {l}\n")).collect()),
                // `cat -n`.
                (
                    "cat -n",
                    pem.lines()
                        .enumerate()
                        .map(|(i, l)| format!("{:6}\t{l}\n", i + 1))
                        .collect(),
                ),
                // Colour on every line, which a stripped read removes.
                (
                    "coloured",
                    format!(
                        "{header}\n{}",
                        body_and_end
                            .lines()
                            .map(|l| format!("\x1b[32m{l}\x1b[0m\n"))
                            .collect::<String>()
                    ),
                ),
            ];
            for (name, text) in spellings {
                let at = text.find("-----BEGIN").unwrap();
                let e = extent(text.as_bytes(), at);
                assert!(e.material, "{} {name}: {e:?}", key.name);
                assert!(
                    !e.alive && text[..e.end].ends_with("-----"),
                    "{} {name}: must close on its END boundary: {e:?}",
                    key.name
                );
                assert!(text[at..e.end].contains("-----END"), "{} {name}", key.name);
            }
        }
    }

    /// What ends a candidate, as the owner's shell actually prints it:
    /// the dogfood pass's trigger and its starship prompt, captured
    /// through a pty, and the same trigger at a `--norc` bash prompt.
    #[test]
    fn a_header_followed_by_a_prompt_dies_with_nothing_to_mask() {
        let starship = b"-----BEGIN RSA PRIVATE KEY-----\r\n\x1b[?2004h\r\n\
            \x1b[1;36mholdfast\x1b[0m on \x1b[1;35m\xee\x82\xa0 main\x1b[0m \
            \x1b[1;31m[$]\x1b[0m is \x1b[1;38;5;208m\xf0\x9f\x93\xa6 v0.0.7\x1b[0m \r\n\
            \x1b[1;2;31m\xe2\xac\xa2 [Docker]\x1b[0m \x1b[1;32m\xe2\x9d\xaf\x1b[0m echo ok1\r\n";
        let norc = b"-----BEGIN RSA PRIVATE KEY-----\r\n\x1b[?2004hbash-5.2$ echo ok1\r\n";
        // The command echo carries the header too, and dies on its quote.
        let echo = b"printf -- '-----BEGIN RSA PRIVATE KEY-----\\n'\r\n";
        for (name, text) in [
            ("starship", &starship[..]),
            ("norc", &norc[..]),
            ("echo", &echo[..]),
        ] {
            let at = text.windows(10).position(|w| w == b"-----BEGIN").unwrap();
            let e = extent(text, at);
            assert!(!e.alive && !e.material, "{name}: {e:?}");
        }
    }

    /// **Each of the four streams is load-bearing, and this row is the one
    /// that needs the stripped-printable one.** A body line carrying both
    /// a colour change and a DEL is dead in the raw stream (the `ESC`),
    /// in the printable stream (the `[` the printable filter leaves of the
    /// sequence) and in the stripped stream (the stripper keeps DEL) — and
    /// alive in the one stream that drops both, which is a stream a read
    /// with `ansi: "strip"` and `text_encoding: "lossy_printable"` emits.
    #[test]
    fn a_body_only_the_stripped_printable_stream_can_read_is_believed() {
        let text = format!(
            "{HEADER}\n{}\x1b[32m\x7f{}\n{LINE}\n",
            &LINE[..30],
            &LINE[30..]
        );
        let e = walk(&text);
        assert!(e.alive && e.material, "{e:?}");
    }

    /// Armour headers are accepted only in front of the body, which is
    /// where RFC 1421 and RFC 4880 put them — a `Name: value` line after
    /// the base64 has started is prose, not a header.
    #[test]
    fn armour_headers_open_a_body_and_do_not_interrupt_one() {
        let legacy =
            format!("{HEADER}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0A1B\n\n{LINE}\n");
        assert!(walk(&legacy).alive);
        let pgp = format!(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\nComment: https://example.org/k\n\n{LINE}\n=AbCd\n"
        );
        assert!(walk(&pgp).alive);
        let late = format!("{HEADER}\n{LINE}\nNote: this is prose\n");
        let e = walk(&late);
        assert!(!e.alive && e.material);
        assert_eq!(&late[e.end..], "Note: this is prose\n");
    }

    /// **A glyph in a window title does not keep a dead candidate alive.**
    /// `✔` is `e2 9c 94`: both continuation bytes are in the C1 range, and
    /// before the continuation arm the walk gave up on the first of them —
    /// so a key cut short and followed by a prompt that sets such a title
    /// was believed to the end of the region. That is a strand on the read
    /// and, on the `watch` stream, a key body the end-of-stream flush would
    /// have released. `”` (`e2 80 9d`) ends in an introducer and still
    /// gives up, which is what the arm is for.
    #[test]
    fn a_non_introducing_continuation_byte_is_not_a_c1_control() {
        let tick = format!("{HEADER}\n{LINE}\n\x1b]0;title \u{2714}\x07$ echo\n");
        let e = walk(&tick);
        assert!(!e.alive && e.material, "{e:?}");
        assert_eq!(&tick[e.end..], "\x1b]0;title \u{2714}\x07$ echo\n");

        let quote = format!("{HEADER}\n{LINE}\n\x1b]0;title \u{201d}\x07$ echo\n");
        assert!(
            walk(&quote).alive,
            "an introducer keeps the conservative arm"
        );
    }

    /// The C1 arm gives up *alive*, and only while some stream is.
    #[test]
    fn a_c1_byte_is_believed_while_any_stream_is_alive_and_ignored_after() {
        let mut live = format!("{HEADER}\n{LINE}\n").into_bytes();
        live.push(0x9b);
        live.extend_from_slice(b"...prose.");
        assert_eq!(
            extent(&live, 0),
            PemExtent {
                end: live.len(),
                alive: true,
                material: true
            }
        );
        let mut dead = format!("{HEADER}` prose").into_bytes();
        dead.push(0x9b);
        assert!(!extent(&dead, 0).alive, "every stream died on the backtick");
    }
}
