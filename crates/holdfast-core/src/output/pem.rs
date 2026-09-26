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
//!
//! **Where the candidate stops is not where the key stops, either** — the
//! half of this module the independent review of GH #242 found missing.
//! A key's body can go on after something that is not PEM text: `less`
//! paints a screenful and a `:` prompt, and the next screenful is more of
//! the same key; `sed -n '21,40p'` prints the middle of one after a prompt
//! and a command; `bat`, `git show`, `docker logs --timestamps` put a
//! decoration in front of every line, so the candidate stops on the first
//! decoration having seen no material at all. Each of those was masked
//! before GH #242, because `[\s\S]*?` kept the candidate believed for the
//! whole carry, and each was released by the narrowing. So a private-key
//! candidate that stopped short of its closing boundary is followed for
//! the rest of the carry by [`body_lines`], which masks every line that
//! carries a key-body run ([`KEY_LINE_RUN`]) and nothing else: the prompt,
//! the next command and ordinary output in between keep their text, which
//! is what GH #242 was for.

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

/// A line carrying a base64 run this long is a key-body line, wherever on
/// the line the run sits — the test [`body_lines`] applies after a
/// private-key candidate stopped short of its closing boundary.
///
/// **Forty-eight, and the number is chosen against both sides.** Every
/// body line a real key is printed with is 64 characters (70 for OpenSSH,
/// 76 where a MIME encoder wrapped it), so every full line clears it
/// whatever decoration sits in front of it: a timestamp, a `bat` gutter,
/// a diff's `-`, `grep -n`'s `12:`. It is above forty so a git object id
/// is never one, which matters because `git log` is the likeliest output
/// to follow a key header in prose. A SHA-256 digest (64) is one, and
/// that is the cost: inside the carry behind a private-key header, a
/// digest on its own line is masked. The last, short line of a key is
/// reached by the second arm of [`body_lines`] — a run of
/// [`PEM_MATERIAL_RUN`] on the line after a body line.
///
/// Measured on this repository's own `CHANGELOG.md`, `README.md` and
/// `ROADMAP.md`: no line within [`UNVOUCHED_CARRY_BYTES`] behind any
/// private-key header in them carries such a run, which
/// `the_documented_read_loop_drains_this_repositorys_own_changelog`
/// asserts through the read path.
///
/// [`UNVOUCHED_CARRY_BYTES`]: super::UNVOUCHED_CARRY_BYTES
pub const KEY_LINE_RUN: u32 = 48;

/// Whether the text a caller judges ends where it will end, or where more
/// of it can still arrive — which decides what [`body_lines`] makes of a
/// last line with no line break after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionEnd {
    /// More may follow: a read's window, the grid's scan to `buffer.head`,
    /// a live stream's carry. A last line that could still turn out to be
    /// a key-body line is reported as one to hold, and masked if what has
    /// arrived of it already carries material.
    Arriving,
    /// The text is whole: a window title, a rendered grid, a stream at its
    /// end. The last line is judged as a line.
    Final,
}

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
    /// Some stream got past the label's closing dashes: the anchor is a
    /// whole encapsulation boundary, not `-----BEGIN` and prose.
    pub header: bool,
    /// Some stream reached a closing `-----END…-----`.
    pub closed: bool,
}

impl PemExtent {
    /// The candidate stopped short of a closing boundary after a whole
    /// header — the case [`body_lines`] follows for the rest of the carry.
    pub fn stopped_short(&self) -> bool {
        self.header && !self.alive && !self.closed
    }
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
                header: lanes.iter().any(|l| l.header),
                closed: false,
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
        header: lanes.iter().any(|l| l.header),
        closed: lanes.iter().any(|l| l.phase == Phase::Closed),
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
    /// The label's closing dashes arrived.
    header: bool,
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
            header: false,
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
                    self.header = true;
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

/// What [`body_lines`] found after a candidate that stopped short.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BodyLines {
    /// Runs of key-body lines, as region indices: each from the first
    /// byte of its first line to the last byte of its last, so a run of
    /// consecutive body lines is one range and the line break after it is
    /// not in it. Sorted and disjoint.
    pub ranges: Vec<(usize, usize)>,
    /// With [`RegionEnd::Arriving`], where a last line begins that has no
    /// line break yet and ends inside a base64 run — a body line still
    /// arriving, as far as anything here can tell. A live stream holds
    /// from here rather than emitting half a line it may have to mask;
    /// whether the part that has arrived is masked already is in
    /// `ranges`.
    pub hold_from: Option<usize>,
}

/// The key-body lines of `region[from..to)`, which follows a private-key
/// candidate that stopped short of its closing boundary (see the module
/// header, and [`PemExtent::stopped_short`]).
///
/// **Line by line, and a line is masked or kept whole.** Lines end at a
/// raw `\n` or `\r` — a `\r` too, because a pager and a progress display
/// both repaint a row from column 0 with one, and what follows it is a new
/// line on screen. A line is a body line when some stream a read can emit
/// of it — raw, stripped, printable or stripped-printable, the four
/// [`extent`] walks — carries a base64 run of [`KEY_LINE_RUN`], or of
/// [`PEM_MATERIAL_RUN`] on the line after a body line (a key's last, short
/// line). A blank line — nothing but whitespace once escapes are gone —
/// neither ends a run of body lines nor starts one. Everything else is
/// kept: a prompt, a command, a pager's `:`, the `-----END` line itself.
///
/// **Why not the whole carry, as before GH #242.** That is the
/// alternative the review offered, and it is the one that undoes the
/// issue: `head -n 15 id_rsa` and then the next command masked every
/// command for 16 KiB, and one prose header in `CHANGELOG.md` masked a
/// quarter of it. A line test keeps both of those whole and still reaches
/// every body line that arrives after the candidate stopped.
///
/// A last line with no break after it is judged as a line when `end` is
/// [`RegionEnd::Final`], or when `to` is short of the region's end (the
/// carry ran out inside it, and the bytes after `to` are not this
/// candidate's). Otherwise it may still be arriving: it is reported as
/// [`BodyLines::hold_from`] if it ends inside a base64 run, and masked
/// already if it follows a body line or has carried [`PEM_MATERIAL_RUN`]
/// — so a read that lands mid-line in a key arriving under a decoration
/// masks the front of the line, and the next read masks the rest from the
/// line's own start.
pub fn body_lines(region: &[u8], from: usize, to: usize, end: RegionEnd) -> BodyLines {
    let to = to.min(region.len());
    let mut out = BodyLines::default();
    if from >= to {
        return out;
    }
    let mut lanes = [
        SegLane::new(Filter::Raw),
        SegLane::new(Filter::Stripped),
        SegLane::new(Filter::Printable),
        SegLane::new(Filter::StrippedPrintable),
    ];
    let mut seg_start = from;
    let mut prev_body = false;
    let mut open: Option<(usize, usize)> = None;
    // One whole line, `[seg_start, seg_end)`.
    fn judge(
        seg_start: usize,
        seg_end: usize,
        lanes: &[SegLane; 4],
        prev_body: &mut bool,
        open: &mut Option<(usize, usize)>,
        ranges: &mut Vec<(usize, usize)>,
    ) {
        // Blank in the stripped-printable stream: nothing a reader sees.
        if lanes[3].blank {
            return;
        }
        let run = lanes.iter().map(|l| l.max_run).max().unwrap_or(0);
        if run >= KEY_LINE_RUN || (*prev_body && run >= PEM_MATERIAL_RUN) {
            *open = Some((open.map_or(seg_start, |o| o.0), seg_end));
            *prev_body = true;
        } else {
            ranges.extend(open.take());
            *prev_body = false;
        }
    }
    for (i, &b) in region.iter().enumerate().take(to).skip(from) {
        for lane in lanes.iter_mut() {
            lane.feed(i, b);
        }
        if b == b'\n' || b == b'\r' {
            judge(
                seg_start,
                i,
                &lanes,
                &mut prev_body,
                &mut open,
                &mut out.ranges,
            );
            for lane in lanes.iter_mut() {
                lane.next_line();
            }
            seg_start = i + 1;
        }
    }
    if seg_start < to {
        if end == RegionEnd::Arriving && to == region.len() {
            let arriving = !lanes[3].blank && lanes.iter().any(|l| l.run > 0);
            if arriving {
                out.hold_from = Some(seg_start);
                let run = lanes.iter().map(|l| l.max_run).max().unwrap_or(0);
                if prev_body || run >= PEM_MATERIAL_RUN {
                    open = Some((open.map_or(seg_start, |o| o.0), to));
                }
            }
        } else {
            judge(
                seg_start,
                to,
                &lanes,
                &mut prev_body,
                &mut open,
                &mut out.ranges,
            );
        }
    }
    out.ranges.extend(open);
    out
}

/// One stream of one line, for [`body_lines`]: the same filters as
/// [`Lane`], and only the counts a line test needs. The stripper runs on
/// across lines, because an escape sequence does not end at one.
struct SegLane {
    filter: Filter,
    stripper: AnsiStripper,
    /// The base64 run the line currently ends in, and its longest.
    run: u32,
    max_run: u32,
    /// Nothing but spaces and tabs emitted on this line so far.
    blank: bool,
}

impl SegLane {
    fn new(filter: Filter) -> Self {
        Self {
            filter,
            stripper: AnsiStripper::new(),
            run: 0,
            max_run: 0,
            blank: true,
        }
    }

    fn next_line(&mut self) {
        self.run = 0;
        self.max_run = 0;
        self.blank = true;
    }

    fn feed(&mut self, at: usize, raw: u8) {
        let byte = match self.filter {
            Filter::Raw => Some(raw),
            Filter::Printable => lossy_printable_keeps(raw).then_some(raw),
            Filter::Stripped => self.stripper.feed(at as u64, raw),
            Filter::StrippedPrintable => self
                .stripper
                .feed(at as u64, raw)
                .filter(|b| lossy_printable_keeps(*b)),
        };
        let Some(b) = byte else { return };
        if b == b'\n' || b == b'\r' {
            return;
        }
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=') {
            self.run += 1;
            self.max_run = self.max_run.max(self.run);
        } else {
            self.run = 0;
        }
        self.blank &= matches!(b, b' ' | b'\t');
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

        /// Every way this key reaches a terminal that some surface has
        /// had to be taught, as a pty delivers it (`\r\n`), each followed
        /// by a command that must still reach the reader.
        ///
        /// Complete: `cat`, a colour change inside both labels, and three
        /// decorations the rule's own `[\s\S]*?` still covers (`git show`
        /// of a removed key, `bat`'s gutter, `grep -n`). Cut short: `head`,
        /// then the five the independent review of GH #242 reached — the
        /// next screenful of a pager, the middle of a key printed in
        /// chunks, and three decorated keys a pager cut off (so no
        /// `-----END` is ever in the buffer) — each of which the
        /// narrowing released and `[\s\S]*?` had masked.
        pub fn shapes(&self) -> Vec<Shape> {
            let pem = self.pem();
            let lines: Vec<&str> = pem.lines().collect();
            let header = lines[0];
            let body = &lines[1..lines.len() - 1];
            let half = (body.len() / 2).max(1);
            let crlf = |ls: &[&str]| -> String { ls.iter().map(|l| format!("{l}\r\n")).collect() };
            let deco = |ls: &[&str], f: &dyn Fn(usize) -> String| -> String {
                ls.iter()
                    .enumerate()
                    .map(|(i, l)| format!("{}{l}\r\n", f(i)))
                    .collect()
            };
            let first: Vec<&str> = std::iter::once(header)
                .chain(body[..half].iter().copied())
                .collect();
            let removed = |_: usize| "-".to_string();
            let gutter = |i: usize| format!("{:>4} \u{2502} ", i + 1);
            let grepped = |i: usize| format!("keys/id_key:{}:", i + 1);
            let stamped = |i: usize| format!("2026-09-23T12:00:{:02}.{:09}Z ", i % 60, i * 7919);
            // A pager's prompt, then what `q` leaves behind.
            let pager = "\x1b[7m:\x1b[27m\x1b[K\r\x1b[K";
            const DONE: &str = "$ echo done\r\ndone\r\n$ ";
            let kept = |extra: &[&str]| -> Vec<String> {
                extra
                    .iter()
                    .map(|s| s.to_string())
                    .chain(["$ echo done".to_string()])
                    .collect()
            };
            let painted = pem.replace("PRIVATE KEY", "PRIV\x1b[1;31mATE KEY\x1b[0m");
            vec![
                Shape {
                    name: "complete",
                    text: format!("$ cat id_key\r\n{}{DONE}", crlf(&lines)),
                    complete: true,
                    kept: kept(&[]),
                },
                Shape {
                    name: "painted",
                    text: format!("$ cat id_key\r\n{}{DONE}", painted.replace('\n', "\r\n")),
                    complete: true,
                    kept: kept(&[]),
                },
                Shape {
                    name: "git show",
                    text: format!("$ git show\r\n{}{DONE}", deco(&lines, &removed)),
                    complete: true,
                    kept: kept(&[]),
                },
                Shape {
                    name: "bat",
                    text: format!("$ bat id_key\r\n{}{DONE}", deco(&lines, &gutter)),
                    complete: true,
                    kept: kept(&[]),
                },
                Shape {
                    name: "grep -n",
                    text: format!("$ grep -n . id_key\r\n{}{DONE}", deco(&lines, &grepped)),
                    complete: true,
                    kept: kept(&[]),
                },
                Shape {
                    name: "head -n 9",
                    text: format!(
                        "$ head -n 9 id_key\r\n{}{DONE}",
                        crlf(&lines[..9.min(lines.len() - 1)])
                    ),
                    complete: false,
                    kept: kept(&[]),
                },
                Shape {
                    name: "less, next screenful",
                    // `less -XM`'s own prompt on the first screenful, erased
                    // by the `\r\x1b[K` in front of the second — which is a
                    // new line on screen, so the prompt keeps its text.
                    text: format!(
                        "$ less -XM id_key\r\n{}\x1b[7mid_key lines 1-{} 50%\x1b[27m\x1b[K\
                         \r\x1b[K{}{pager}{DONE}",
                        crlf(&first),
                        first.len(),
                        crlf(&body[half..])
                    ),
                    complete: false,
                    kept: kept(&["less -XM id_key", "id_key lines 1-"]),
                },
                Shape {
                    name: "sed, in chunks",
                    text: format!(
                        "$ sed -n '1,{a}p' id_key\r\n{}$ sed -n '{b},{c}p' id_key\r\n{}{DONE}",
                        crlf(&first),
                        crlf(&body[half..]),
                        a = half + 1,
                        b = half + 2,
                        c = body.len() + 1,
                    ),
                    complete: false,
                    kept: kept(&["$ sed -n '1,", &format!("$ sed -n '{},", half + 2)]),
                },
                Shape {
                    name: "git show, paged",
                    text: format!("$ git show\r\n{}{pager}{DONE}", deco(&first, &removed)),
                    complete: false,
                    kept: kept(&[]),
                },
                Shape {
                    name: "bat, paged",
                    text: format!("$ bat id_key\r\n{}{pager}{DONE}", deco(&first, &gutter)),
                    complete: false,
                    kept: kept(&[]),
                },
                Shape {
                    name: "docker logs, cut",
                    text: format!("$ docker logs -t app\r\n{}{DONE}", deco(&first, &stamped)),
                    complete: false,
                    kept: kept(&[]),
                },
            ]
        }
    }

    /// One of [`Key::shapes`].
    pub(crate) struct Shape {
        pub name: &'static str,
        pub text: String,
        /// The key's closing boundary is in `text`, so the rule itself
        /// matches it and a mask carries the rule's name.
        pub complete: bool,
        /// Text that must reach the reader verbatim — the commands around
        /// the key, which GH #242's narrowing exists to keep.
        pub kept: Vec<String>,
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
                material: true,
                header: true,
                closed: false,
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

    /// **What `body_lines` masks after a candidate stopped short, line by
    /// line** — the independent review's repros in miniature: a pager's
    /// prompt and then its next screenful, a short last line, a decorated
    /// line, and a line still arriving.
    #[test]
    fn body_lines_masks_key_body_and_keeps_everything_else() {
        let short = &LINE[..20];
        let text = format!(
            ":\r\x1b[K{LINE}\r\n\r\n{LINE}\r\n{short}\r\n$ echo ok\r\nok\r\n\
             2026-09-23T12:00:00Z {LINE}\r\n{short}\r\n"
        );
        let got = body_lines(text.as_bytes(), 0, text.len(), RegionEnd::Final);
        let masked: Vec<&str> = got.ranges.iter().map(|&(s, e)| &text[s..e]).collect();
        assert_eq!(
            masked,
            vec![
                // Two body lines around a blank one, and the short last
                // line after them: one range. The pager's `:` is kept, on
                // its own line because `\r` ends one.
                &text[text.find("\x1b[K").unwrap()..text.find("\r\n$ echo").unwrap()],
                // A decorated line is a body line; the short line after it
                // follows a body line.
                &text[text.find("2026").unwrap()..text.len() - 2],
            ]
        );
        assert_eq!(got.hold_from, None, "Final: nothing is arriving");

        // A short line that follows no body line is not one: sixteen
        // letters of prose after a prompt are prose.
        let prose = format!("$ echo\r\n{short}\r\n");
        assert!(
            body_lines(prose.as_bytes(), 0, prose.len(), RegionEnd::Final)
                .ranges
                .is_empty()
        );

        // Arriving: a last line that ends in a run is held, and masked
        // already when it follows a body line…
        let arriving = format!("{LINE}\r\n{}", &LINE[..5]);
        let got = body_lines(arriving.as_bytes(), 0, arriving.len(), RegionEnd::Arriving);
        assert_eq!(got.hold_from, Some(LINE.len() + 2));
        assert_eq!(got.ranges, vec![(0, arriving.len())]);
        // …or when what has arrived of it already carries material…
        let alone = format!("$ x\r\n{short}");
        let got = body_lines(alone.as_bytes(), 0, alone.len(), RegionEnd::Arriving);
        assert_eq!(got.ranges, vec![(5, alone.len())]);
        // …and only held, not masked, when it has neither.
        let word = "$ x\r\nabc";
        let got = body_lines(word.as_bytes(), 0, word.len(), RegionEnd::Arriving);
        assert_eq!((got.hold_from, got.ranges.len()), (Some(5), 0));
        // A prompt ends in a space and is neither.
        let prompt = "$ x\r\nuser@host:~$ ";
        let got = body_lines(prompt.as_bytes(), 0, prompt.len(), RegionEnd::Arriving);
        assert_eq!(got, BodyLines::default());
        // A line the carry cut short is judged as a line, not held.
        let got = body_lines(
            arriving.as_bytes(),
            0,
            arriving.len() - 1,
            RegionEnd::Arriving,
        );
        assert_eq!(got.hold_from, None);
    }

    /// **Only a header that stopped short is followed** — not one that
    /// closed, not one still alive, and not a label that never closed.
    #[test]
    fn only_a_candidate_that_stopped_short_is_followed() {
        let closed = walk(&format!(
            "{HEADER}\n{LINE}\n-----END RSA PRIVATE KEY-----\n"
        ));
        assert!(closed.closed && !closed.stopped_short());
        let alive = walk(&format!("{HEADER}\n{LINE}\n"));
        assert!(alive.alive && !alive.stopped_short());
        let stopped = walk(&format!("{HEADER}\n{LINE}\n$ prompt"));
        assert!(stopped.header && stopped.stopped_short());
        let prose = walk(&format!("{HEADER}` in prose"));
        assert!(
            prose.header && prose.stopped_short(),
            "prose is followed too"
        );
        let unclosed = walk("-----BEGIN RSA PRIVATE KEY\u{7f}");
        assert!(!unclosed.header && !unclosed.stopped_short());
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
                material: true,
                header: true,
                closed: false,
            }
        );
        let mut dead = format!("{HEADER}` prose").into_bytes();
        dead.push(0x9b);
        assert!(!extent(&dead, 0).alive, "every stream died on the backtick");
    }
}
