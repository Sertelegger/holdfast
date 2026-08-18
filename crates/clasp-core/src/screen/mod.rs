//! Tier B — adaptive full VT100 emulation (spec §4.5).
//!
//! Tier A is a bounded byte scan and is always on. Tier B keeps a
//! `vt100::Parser` per session and was measured at ~86 MB/s on the write
//! path (§4.2a): at the §11.4 stress target it would cost more than a
//! core before any other work happens. So it runs only when something
//! needs the rendered grid, and the default for an ordinary
//! line-oriented session is **off**.

pub mod cursor;
pub mod queries;
pub mod signals;
pub mod tracking;

pub use cursor::{CursorSignal, DEFAULT_CURSOR_STABLE_SAMPLES, DEFAULT_PROMPT_CHARS};
pub use queries::{QueryResponder, DEFAULT_TERMINAL_QUERY_REPLIES_PER_MIN};
pub use tracking::{EnableReason, ScreenTracking, TrackingPolicy};

use crate::buffer::OutputBuffer;
// `find_spans` + `marker` for the grid (REQ-O-011a needs the *spans*, so
// it can tell which rows a cross-row match covered); plain `redact_str`
// for the window title, which is one contiguous string with no rows in it.
use crate::output::redact::{find_spans, marker, redact_str, Span, UNRESOLVED_KIND};
use crate::output::rules::RuleSet;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Spec §4.2 `screen_tracking_idle_disable_secs`.
pub const DEFAULT_IDLE_DISABLE: Duration = Duration::from_secs(300);

/// Spec §4.5: "no bracketed-paste and no OSC 133 for 3 s after session
/// start".
pub const NO_SIGNAL_GRACE: Duration = Duration::from_secs(3);

/// Spec §4.5 seeds a mid-session parser from the most recent
/// `rows * cols * 4` bytes of the ring buffer.
pub const SEED_BYTES_PER_CELL: usize = 4;

/// How many past screens are retained so a `diff_from` can resolve. Four
/// covers an agent that is one or two calls behind; an unmatched
/// `diff_from` degrades to a full grid rather than an error.
pub const DEFAULT_RETAINED_REVISIONS: usize = 4;

/// Revision number that never matches a `diff_from`. Returned by the
/// one-shot render used when `screen_tracking = "off"`, where nothing is
/// retained to diff against.
pub const UNRETAINED_REVISION: u64 = 0;

/// Per-session Tier-B configuration. Field-for-field the §4.2 knobs plus
/// the PTY geometry, which the seed window is derived from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenConfig {
    pub mode: ScreenTracking,
    pub rows: u16,
    pub cols: u16,
    pub idle_disable: Duration,
    pub no_signal_grace: Duration,
    pub retained_revisions: usize,
    pub cursor_stable_samples: u32,
}

impl Default for ScreenConfig {
    fn default() -> Self {
        Self {
            mode: ScreenTracking::Adaptive,
            // Matches `PtySpawnConfig::new`, so a session created without
            // an explicit geometry seeds the right-sized grid.
            rows: 40,
            cols: 120,
            idle_disable: DEFAULT_IDLE_DISABLE,
            no_signal_grace: NO_SIGNAL_GRACE,
            retained_revisions: DEFAULT_RETAINED_REVISIONS,
            cursor_stable_samples: DEFAULT_CURSOR_STABLE_SAMPLES,
        }
    }
}

impl ScreenConfig {
    /// Bytes of scrollback replayed into a freshly enabled parser.
    pub fn seed_bytes(&self) -> usize {
        usize::from(self.rows) * usize::from(self.cols) * SEED_BYTES_PER_CELL
    }
}

/// A slice of the raw stream plus the absolute offset just past it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed {
    pub bytes: Vec<u8>,
    /// `buffer.head` at the moment the bytes were taken.
    pub head: u64,
}

/// A replay of a *past* range of the raw stream, for the render at
/// §4.1's `holdback_boundary`. `start` is where the returned bytes
/// actually begin, which is later than the requested start when the ring
/// buffer has evicted the front of the range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    pub bytes: Vec<u8>,
    pub start: u64,
}

/// Where a re-seed gets its bytes. Implemented for the session's ring
/// buffer; a plain `Vec` implementation lives in the unit tests.
pub trait SeedSource {
    fn recent(&self, n: usize) -> Seed;

    /// The raw stream in `[start, end)`, clamped to what the buffer still
    /// holds. Used only when §4.1 is withholding: the tracker replays its
    /// *own* input up to the boundary to obtain the render the withheld
    /// bytes had not yet touched.
    fn replay(&self, start: u64, end: u64) -> Replay;
}

impl SeedSource for Mutex<OutputBuffer> {
    fn recent(&self, n: usize) -> Seed {
        let buffer = self.lock();
        let read = buffer.read_tail_bytes(n);
        Seed {
            bytes: read.bytes,
            head: read.cursor,
        }
    }

    fn replay(&self, start: u64, end: u64) -> Replay {
        let buffer = self.lock();
        let from = start.max(buffer.tail());
        Replay {
            bytes: buffer.slice(from, end),
            start: from,
        }
    }
}

/// A full rendered grid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenGrid {
    pub screen_revision: u64,
    pub rows: u16,
    pub cols: u16,
    pub cursor_row: u16,
    pub cursor_col: u16,
    pub cursor_visible: bool,
    pub alt_screen: bool,
    pub title: Option<String>,
    pub lines: Vec<String>,
    /// Some cells carry `[REDACTED:unresolved]` instead of what the child
    /// painted, because §4.1 is withholding the bytes that wrote them.
    /// **`true` only when a cell was actually masked**, not merely when a
    /// holdback is open — an in-flight secret elsewhere in the session
    /// that never reached the screen costs this grid nothing, which is
    /// §4.1's own "ordinary output pays nothing" applied here.
    pub held_back: bool,
}

/// The changed regions between two retained revisions, as the terminal
/// byte stream `vt100::contents_diff` produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenDelta {
    pub screen_revision: u64,
    pub base_revision: u64,
    pub diff: String,
    /// As [`ScreenGrid::held_back`], and on this shape for the same
    /// reason `screen_tracking` is: §5.2's two response shapes are one
    /// closed `outputSchema`, and a field the tool emits on one shape and
    /// not the other fails validation the first time that path runs.
    pub held_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenCapture {
    Full(ScreenGrid),
    Delta(ScreenDelta),
}

/// Captures the window title so `get_screen_state` can report it.
///
/// Tier A (`crate::detect::scanner::ModeScanner`, milestone 0.0.2) is the authoritative
/// title source because it runs even when Tier B is off. This copy exists
/// so the field is populated in 0.0.4 and is limited by the seed window:
/// a title set before the seeded bytes is not recovered.
#[derive(Debug, Default, Clone)]
struct TitleSink {
    title: Option<String>,
}

impl vt100::Callbacks for TitleSink {
    fn set_window_title(&mut self, _: &mut vt100::Screen, title: &[u8]) {
        self.title = Some(String::from_utf8_lossy(title).into_owned());
    }
}

/// Owns the adaptive policy, the parser, and the retained revisions.
///
/// **Lock order.** The session holds this behind its own mutex and a
/// re-seed reaches into the ring buffer, so the order is always
/// `screen → buffer`. Nothing may take the buffer lock and then this one.
pub struct ScreenTracker {
    cfg: ScreenConfig,
    /// The §9.2 rule table. Held so that redaction happens *before*
    /// diffing — see [`ScreenTracker::rendered_screen`].
    rules: Arc<RuleSet>,
    policy: TrackingPolicy,
    probe: signals::TierAProbe,
    parser: Option<vt100::Parser<TitleSink>>,
    /// Absolute offset of the first stream byte the parser has *not* seen.
    consumed_head: u64,
    /// Absolute offset of the first stream byte the parser *has* seen —
    /// where its seed window began. With `consumed_head` it names the
    /// exact byte range the live grid is a function of, which is what
    /// lets the boundary render be an exact replay of the same input
    /// rather than an approximation of it (see `boundary_screen`).
    seeded_from: u64,
    next_revision: u64,
    /// `(revision, redacted, screen)`. The flag is not bookkeeping: §9.2's
    /// screen-state row requires a `diff_from` naming a revision rendered
    /// under a *different* `redact` value to return a full grid, because
    /// the two renderings differ by the redaction markers themselves and a
    /// diff between them would describe the un-redaction rather than the
    /// change (REQ-O-011).
    retained: VecDeque<(u64, bool, vt100::Screen)>,
    stability: cursor::CursorStability,
    parsed_bytes: u64,
}

impl ScreenTracker {
    pub fn new(cfg: ScreenConfig, rules: Arc<RuleSet>, now: Instant) -> Self {
        let policy = TrackingPolicy::new(cfg.mode, cfg.idle_disable, cfg.no_signal_grace, now);
        Self {
            cfg,
            rules,
            policy,
            probe: signals::TierAProbe::new(),
            parser: None,
            consumed_head: 0,
            seeded_from: 0,
            next_revision: UNRETAINED_REVISION + 1,
            retained: VecDeque::new(),
            stability: cursor::CursorStability::new(),
            parsed_bytes: 0,
        }
    }

    pub fn config(&self) -> &ScreenConfig {
        &self.cfg
    }

    pub fn policy(&self) -> &TrackingPolicy {
        &self.policy
    }

    /// `screen_tracking` as reported to the agent (spec §18.2a): whether
    /// emulation is running right now, not which mode was configured.
    ///
    /// **Derived from `policy.enabled()` and never from
    /// `policy.mode().as_str()`.** The wire value is two-valued
    /// (`"off" | "on"`) and the mode enum is three-valued; the two agree
    /// for `off` and `on` and disagree for `adaptive`, which is the
    /// default and therefore every session. The mode accessor would emit
    /// `"adaptive"` and fail the closed `outputSchema` on the first
    /// response, so this method — not the enum — is the one a response
    /// builder calls.
    pub fn tracking_state(&self) -> &'static str {
        if self.policy.enabled() {
            "on"
        } else {
            "off"
        }
    }

    /// Total bytes handed to a `vt100::Parser` for this session, seeds
    /// included. The §11.4 write-path guard asserts this stays at zero for
    /// line-oriented sessions.
    pub fn parsed_bytes(&self) -> u64 {
        self.parsed_bytes
    }

    /// One PTY chunk, straight off the reader thread.
    ///
    /// `start` is the chunk's absolute offset in the raw stream. **The
    /// caller must have already pushed the chunk into the ring buffer**:
    /// a re-seed reads the buffer's tail, so the chunk that triggered the
    /// enable is already inside the seed, and `consumed_head` is what
    /// stops it being applied twice.
    pub fn feed(&mut self, start: u64, chunk: &[u8], now: Instant, seed: &dyn SeedSource) {
        self.probe.scan(chunk);
        self.policy.observe(
            self.probe.alt_screen(),
            self.probe.saw_deterministic_signal(),
        );
        self.policy.evaluate(now);
        self.sync_parser(seed);
        self.process_range(start, chunk);
    }

    /// Advance the policy clock without new bytes. Used by observers (the
    /// §8.6 cursor signal) so the 3 s no-signal trigger and the idle
    /// disable still fire on a session that has gone quiet.
    pub fn poll(&mut self, now: Instant, seed: &dyn SeedSource) {
        self.policy.evaluate(now);
        self.sync_parser(seed);
    }

    /// Serve a screen-state request. Enables Tier B if it is off and the
    /// mode allows it — spec §5.2: the call succeeds either way, at the
    /// cost of one buffer re-seed.
    ///
    /// `redact` is §5.2's `get_screen_state.redact`, which **defaults to
    /// true** — the tool layer resolves the absent argument, never this
    /// one, so a caller that forgets cannot silently get the raw grid.
    /// The audit obligation for `redact: false` (§9.4) belongs to the tool
    /// layer too, because that is where the caller is known.
    ///
    /// **`holdback` is §4.1's boundary, and the grid is inside it.**
    /// §4.1 exempts `read_output`'s `tail_lines`/`tail_bytes` *arguments*
    /// and nothing else — the licence is the per-call opt-in, not the tail
    /// shape, and this tool has no such argument (REQ-O-003). `None` means
    /// the caller is not a holdback-bearing surface at all; `Some(b)` with
    /// `b` at or past `consumed_head` is the ordinary case and masks
    /// nothing. The value is computed by the *session*, from the same
    /// `OutputProcessor::holdback_boundary` call `read_output` uses, so
    /// this never becomes a second rule.
    pub fn capture(
        &mut self,
        diff_from: Option<u64>,
        redact: bool,
        now: Instant,
        seed: &dyn SeedSource,
        holdback: Option<u64>,
    ) -> ScreenCapture {
        if self.cfg.mode == ScreenTracking::Off {
            // The operator said never to run emulation on the write path.
            // Honour that, but still answer: render once from the seed
            // window and throw the parser away.
            //
            // **This is the second of two guards, and the first one is
            // the one under test.** `TrackingPolicy::note_consumer`
            // refuses to enable in `off` mode, and
            // `tracking::tests::off_never_enables_for_any_trigger` pins
            // that; with this early return deleted the code below reaches
            // the same one-shot through its `None` arm and every test
            // here still passes (measured). It stays because it says what
            // §5.2 means at the place a reader looks for it, and it keeps
            // an `off` session from touching the policy at all — but a
            // reader must not take `off_answers_without_ever_running_…`
            // as pinning this branch, because it does not.
            return ScreenCapture::Full(self.one_shot(redact, seed, holdback));
        }
        self.policy.note_consumer(now);
        self.policy.evaluate(now);
        self.sync_parser(seed);
        match self.parser.take() {
            Some(parser) => {
                let capture = self.render(&parser, diff_from, redact, seed, holdback);
                self.parser = Some(parser);
                capture
            }
            // Unreachable: note_consumer enables every non-`off` mode.
            // Answer anyway rather than inventing a failure status.
            None => ScreenCapture::Full(self.one_shot(redact, seed, holdback)),
        }
    }

    /// Reflow the tracked grid after the PTY's dimensions changed.
    ///
    /// **Both the live parser and `cfg` are updated, and the second one is
    /// the half that is easy to forget.** `set_size` fixes the parser that
    /// exists now; `cfg.rows`/`cfg.cols` are what `new_parser` and
    /// `seed_bytes` read, so leaving them stale means the *next* re-seed —
    /// after an idle disable, or the one-shot an `off` session renders —
    /// silently rebuilds the old geometry. A grid that is right until the
    /// tracker cycles is worse than one that is wrong immediately.
    ///
    /// `set_size` takes **rows first**, which is the transposition trap
    /// `Parser::new` carries as well; this method's own argument order is
    /// `(cols, rows)`, matching `PtyBackend::resize`.
    ///
    /// **A resize to the size already in force returns before touching
    /// anything**, which is what earns `resize`'s `idempotentHint: true`:
    /// the retained revisions survive, so an agent's outstanding
    /// `diff_from` still resolves. Clearing them unconditionally would make
    /// every no-op resize cost the agent a full grid.
    ///
    /// A *real* resize does drop them, and must: a retained `Screen` is the
    /// old geometry, and `contents_diff` between screens of different sizes
    /// describes a reflow the agent's replay cannot reproduce. Dropping
    /// them degrades the next `diff_from` to a full grid, which is the same
    /// graceful path an evicted revision already takes.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        if self.cfg.cols == cols && self.cfg.rows == rows {
            return;
        }
        self.cfg.cols = cols;
        self.cfg.rows = rows;
        if let Some(parser) = self.parser.as_mut() {
            parser.screen_mut().set_size(rows, cols);
        }
        self.retained.clear();
    }

    /// The §8.6 T3c sub-signal, or `None` when Tier B is not running.
    pub fn cursor_signal(&mut self, now: Instant, seed: &dyn SeedSource) -> Option<CursorSignal> {
        self.poll(now, seed);
        let parser = self.parser.as_ref()?;
        let screen = parser.screen();
        let (row, col) = screen.cursor_position();
        self.stability.observe((row, col));
        let stable = self.stability.is_stable(self.cfg.cursor_stable_samples);
        let score = if stable {
            cursor::raw_cursor_score(screen, DEFAULT_PROMPT_CHARS)
        } else {
            0.0
        };
        Some(CursorSignal {
            score,
            row,
            col,
            stable,
            stable_samples: self.stability.samples(),
        })
    }

    fn sync_parser(&mut self, seed: &dyn SeedSource) {
        match (self.policy.enabled(), self.parser.is_some()) {
            (true, false) => self.seed_parser(seed),
            (false, true) => {
                self.parser = None;
                self.retained.clear();
                self.stability.reset();
            }
            _ => {}
        }
    }

    fn new_parser(&self) -> vt100::Parser<TitleSink> {
        vt100::Parser::new_with_callbacks(self.cfg.rows, self.cfg.cols, 0, TitleSink::default())
    }

    /// Spec §4.5: seed from the ring buffer's most recent
    /// `rows * cols * 4` bytes so the visible grid is correct for
    /// anything currently on screen. Older scrollback is not recovered,
    /// which does not matter — the screen only shows the visible region.
    fn seed_parser(&mut self, seed: &dyn SeedSource) {
        let seed = seed.recent(self.cfg.seed_bytes());
        let mut parser = self.new_parser();
        parser.process(&seed.bytes);
        self.parsed_bytes += seed.bytes.len() as u64;
        self.parser = Some(parser);
        self.consumed_head = seed.head;
        self.seeded_from = seed.head - seed.bytes.len() as u64;
        self.retained.clear();
        self.stability.reset();
    }

    /// Feed only the part of `chunk` the parser has not already absorbed
    /// through a seed. Without this, a chunk that arrives just before a
    /// re-seed would be applied twice and the grid would show doubled
    /// output.
    fn process_range(&mut self, start: u64, chunk: &[u8]) {
        let Some(parser) = self.parser.as_mut() else {
            return;
        };
        let end = start + chunk.len() as u64;
        if end <= self.consumed_head {
            return;
        }
        let skip = usize::try_from(self.consumed_head.saturating_sub(start)).unwrap_or(chunk.len());
        let fresh = &chunk[skip.min(chunk.len())..];
        parser.process(fresh);
        self.parsed_bytes += fresh.len() as u64;
        self.consumed_head = end;
        let pos = parser.screen().cursor_position();
        self.stability.observe(pos);
    }

    fn one_shot(
        &mut self,
        redact: bool,
        seed: &dyn SeedSource,
        holdback: Option<u64>,
    ) -> ScreenGrid {
        let taken = seed.recent(self.cfg.seed_bytes());
        let mut parser = self.new_parser();
        parser.process(&taken.bytes);
        self.parsed_bytes += taken.bytes.len() as u64;
        // `off` is a performance switch, not a security one: the one-shot
        // render goes through the same redaction — and the same §4.1
        // mask — as every other capture. Its input range is the seed
        // window rather than the tracked range, so that is what the
        // boundary render replays.
        let from = taken.head - taken.bytes.len() as u64;
        let boundary = self.boundary_screen(&parser, from, taken.head, redact, seed, holdback);
        let (rendered, held_back) = self.rendered_screen(&parser, redact, boundary.as_ref());
        let title = self.rendered_title(&parser, redact);
        grid_of(rendered.screen(), title, UNRETAINED_REVISION, held_back)
    }

    /// The render as it stood at §4.1's `holdback_boundary` — the grid the
    /// withheld bytes had not yet written to. `None` when nothing is being
    /// withheld, which is the ordinary case and costs nothing.
    ///
    /// **It is an exact replay of the live parser's own input, truncated,
    /// and that is what makes the diff below mean what it says.** The live
    /// grid is a pure function of the stream range
    /// `[seeded_from, consumed_head)` (a seed window plus every chunk fed
    /// since), so feeding `[seeded_from, boundary)` to a fresh parser of
    /// the same geometry yields precisely the state the live parser passed
    /// through on its way here. No byte offset is mapped onto a cell
    /// anywhere in this: the extent is found by rendering twice and
    /// comparing cells, because a `\r` redraw, a multi-byte character and
    /// a withheld region spanning rows each break that arithmetic
    /// differently.
    ///
    /// **`redact: false` skips it, deliberately.** §4.1 answers the same
    /// way — `holdback_boundary` returns `head` when `!opts.redact` — and
    /// names the audited opt-out as the agent's recourse *from* the
    /// holdback. A masked grid under `redact: false` would be a hole in
    /// that recourse, not a second layer of safety.
    ///
    /// **The one residual, and it fails safe.** If the ring buffer has
    /// evicted the front of `[seeded_from, boundary)` the replay starts
    /// late and its grid is missing whatever those bytes painted; the
    /// affected cells then differ from the live ones and are *masked*
    /// rather than shown. Over-masking is the direction this must fail in,
    /// and it is the direction it does: a cell can only escape the mask by
    /// being identical to a cell the pre-boundary bytes produced.
    ///
    /// The replay is **not** added to `parsed_bytes`, on the same rule the
    /// repaint parser in `rendered_screen` already follows: that counter
    /// measures what the *write path* handed to an emulator (§11.4's guard
    /// asserts it stays at zero for a line-oriented session), and this is
    /// render-time reconstruction on a read.
    fn boundary_screen(
        &self,
        live: &vt100::Parser<TitleSink>,
        from: u64,
        head: u64,
        redact: bool,
        seed: &dyn SeedSource,
        holdback: Option<u64>,
    ) -> Option<vt100::Screen> {
        let boundary = holdback?;
        if !redact || boundary >= head {
            return None;
        }
        let replay = seed.replay(from, boundary);
        let (rows, cols) = live.screen().size();
        let mut parser = vt100::Parser::new(rows, cols, 0);
        parser.process(&replay.bytes);
        Some(parser.screen().clone())
    }

    /// Re-render the raw parser grid into the screen that leaves this
    /// module — redacted unless the caller passed §5.2's `redact: false`,
    /// which **defaults to true**.
    ///
    /// **The redaction runs over the rendered grid, not over the bytes
    /// that produced it, and that is REQ-O-011.** The grid is a
    /// reconstruction rather than a slice of the byte stream, so a secret
    /// can be split across cell boundaries by cursor positioning and is
    /// contiguous only once drawn; a redactor applied to the bytes on the
    /// way in never sees it. §4.1's boundary-window rules do not transfer
    /// either, because cells are the unit here, not byte offsets.
    ///
    /// **And it runs over the *whole render*, not row by row, which is
    /// REQ-O-011a — the second half of the same obligation.** REQ-O-011
    /// fixes *where* the redactor sits and is silent on *how much* it sees
    /// at a time. Every rule matches a span, and a span is found only when
    /// the whole of it lies inside the unit the redactor is run over, so a
    /// per-row unit returns two whole classes of secret with every test of
    /// it passing: `private-key-block` spans rows by construction and can
    /// never fire, and any value wider than `cols` (80 by default; JWTs
    /// and bearer tokens exceed that routinely) fragments across two rows
    /// and matches in neither.
    ///
    /// **The join is where the correctness sits, and both obvious joins
    /// are wrong in opposite directions.** Joining rows with `\n`
    /// re-creates the wrap bug exactly, because `\n` is in no rule's value
    /// class — the wrapped JWT still matches nothing, and whoever
    /// "enlarged the unit" that way has changed nothing while believing
    /// otherwise. Joining rows with no separator creates a different bug:
    /// two genuinely separate lines glue into a false match, and the
    /// redaction then spans a real line boundary and deletes output that
    /// was never a secret. So the join distinguishes a **wrapped
    /// continuation** from a **new line**, using `Screen::row_wrapped`,
    /// which is the flag the emulator already keeps for reflow.
    ///
    /// **The residual, stated rather than pretended away.** A whole-render
    /// redactor still cannot see a secret that continues above row 0 or
    /// below the last row — the grid is a window onto a stream. Same shape
    /// as §4.1's buffer-tail-eaten limit, same treatment: documented, and
    /// not confused with a case this closes.
    ///
    /// Both modes go through the same rebuild, and deliberately: the two
    /// renderings then differ only by the redaction markers, which is what
    /// makes "a `diff_from` across differing `redact` values degrades to a
    /// full grid" a *rule about markers* rather than an artefact of two
    /// unrelated rendering paths.
    ///
    /// Redaction happens *before* diffing, and that is a correctness
    /// requirement rather than a safety preference. The agent holds the
    /// redacted grid from its previous call. A diff computed between two
    /// *raw* screens and replayed onto a redacted base reproduces
    /// nothing: `[REDACTED:github]` and the forty-character token it
    /// replaced are different lengths, so every cell after it is offset.
    /// Diffing redacted screens keeps §5.2's replay contract exactly as
    /// it was, and means a secret never reaches `contents_diff` at all —
    /// there is nothing to leak rather than something leaky that gets
    /// scrubbed afterwards.
    ///
    /// The `vt100::Parser` itself keeps parsing **raw** bytes. It has to:
    /// redacting the byte stream would corrupt escape sequences, and the
    /// ring buffer it re-seeds from is raw by design (§4.1).
    ///
    /// **And after redaction comes §4.1's mask, in that order.** REQ-O-011
    /// and REQ-O-011a between them site the redactor and fix its extent
    /// and say nothing about the holdback; an implementation reading
    /// §4.1's tail-read bypass as covering the grid returns, on a
    /// `readOnlyHint: true` tool, exactly the in-flight bytes
    /// `read_output` is answering `held_back: true` about in the same
    /// moment. The bypass is licensed by a **per-call opt-in** — the
    /// `tail_lines`/`tail_bytes` arguments — and this tool has none, so
    /// the rule transfers (REQ-O-003).
    ///
    /// Its *remedy* does not. `prompt.last_line` may report nothing while
    /// a holdback is open because the agent's recourse is `read_output`;
    /// a full-screen program has no such recourse — `read_output` on a TUI
    /// is redraw soup, which is the whole reason this tool exists — so the
    /// grid is **masked, not suppressed**. `mask_against` is the render at
    /// the boundary; the cells where the live grid differs from it are
    /// exactly the region the withheld bytes wrote, and each differing run
    /// becomes one `[REDACTED:unresolved]`.
    ///
    /// **Redaction claims its spans first, and the mask covers what is
    /// left.** A value that is *complete* in the grid should come back as
    /// its own `[REDACTED:<kind>]` rather than as `unresolved`: the agent
    /// learns more from the kind, and the two markers mean different
    /// things — one names a rule that matched, the other says nothing
    /// matched and the bytes were withheld anyway. Neither ordering leaks,
    /// since both replace the cell's contents; the order is about which
    /// true thing the agent is told.
    fn rendered_screen(
        &self,
        parser: &vt100::Parser<TitleSink>,
        redact: bool,
        mask_against: Option<&vt100::Screen>,
    ) -> (vt100::Parser, bool) {
        let screen = parser.screen();
        let (rows, cols) = screen.size();
        let mut out = vt100::Parser::new(rows, cols, 0);
        if screen.alternate_screen() {
            out.process(b"\x1b[?1049h");
        }

        // 1. Join the rows into one render, recording where each row's
        //    text landed in it. A row whose *predecessor* is `row_wrapped`
        //    is a continuation and gets no separator; every other row
        //    break is a real one and gets a `\n`. That distinction is the
        //    normative part of REQ-O-011a — see the doc comment.
        //
        //    The rows are built cell by cell rather than by
        //    `Screen::rows`, which is the same walk (this reproduces its
        //    padding and its wide-character handling) with one thing added
        //    the mask needs: where each *cell* landed in the join, so a
        //    differing cell can be named as a byte range without ever
        //    converting a stream offset into a column.
        let mut joined = String::new();
        let mut at: Vec<(usize, usize)> = Vec::with_capacity(usize::from(rows));
        let mut masked: Vec<(usize, usize)> = Vec::new();
        for i in 0..rows {
            if i > 0 && !screen.row_wrapped(i - 1) {
                joined.push('\n');
            }
            let start = joined.len();
            write_row(screen, i, cols, &mut joined, mask_against, &mut masked);
            at.push((start, joined.len()));
        }

        // 2. One pass over the whole render. `find_spans` rather than
        //    `redact_str` because the repaint below needs to know *which*
        //    cells a match covered: a span crossing a row boundary emits
        //    one marker on the row it opened on, and the rows it continues
        //    onto lose the covered text rather than gaining a second
        //    marker each.
        let spans = if redact {
            find_spans(&self.rules, joined.as_bytes(), 0)
        } else {
            Vec::new()
        };

        // 3. Compose: the redaction's spans, plus whatever of the mask
        //    they did not already cover.
        let (cuts, held_back) = compose(&self.rules, &spans, &masked);

        // 4. Repaint row by row, at absolute positions, so the grid's
        //    geometry is exactly the source grid's. A redaction that
        //    shortens a wrapped value leaves its trailing rows blank; one
        //    that lengthens a line is clipped at `cols`, which is what the
        //    per-row version already did.
        for (i, &(start, end)) in at.iter().enumerate() {
            let mut line = String::new();
            let mut cursor = start;
            for cut in cuts.iter().filter(|c| c.start < end && c.end > start) {
                if cut.start > cursor {
                    line.push_str(char_slice(&joined, cursor, cut.start.min(end)));
                }
                if cut.start >= start {
                    line.push_str(&cut.text);
                }
                cursor = cut.end.max(cursor).min(end);
            }
            if cursor < end {
                line.push_str(char_slice(&joined, cursor, end));
            }
            if line.is_empty() {
                continue;
            }
            out.process(format!("\x1b[{};1H", i + 1).as_bytes());
            out.process(clip_to_cols(&line, cols).as_bytes());
        }

        let (row, col) = screen.cursor_position();
        out.process(format!("\x1b[{};{}H", row + 1, col + 1).as_bytes());
        if screen.hide_cursor() {
            out.process(b"\x1b[?25l");
        }
        (out, held_back)
    }

    /// The title is part of the screen this tool returns, so it is
    /// redacted too. §9.2's screen-state row names `get_screen_state.lines`
    /// and `.diff`; the title rides with them because a build script that
    /// puts a token in the window title would otherwise walk past the grid
    /// redaction untouched, which is exactly the one-exception hole
    /// REQ-O-011 exists to close. §9.2 gives it its own table row and
    /// REQ-T-011 names the field.
    ///
    /// **Plain `redact_str`, and that is not an oversight next to the
    /// grid's `find_spans` join.** §9.2 says in as many words that `title`
    /// is *not* an instance of REQ-O-011a's bounded-reconstruction class:
    /// a title is a single contiguous OSC payload, nothing is evicted from
    /// it, and an over-long one is discarded wholesale by the scanner
    /// rather than truncated — so the redactor already sees the whole of
    /// whatever it sees, and there is no unit to enlarge. The same field
    /// on the §5.4 block is redacted separately in `mcp::detection`, which
    /// renders from the detector rather than from this parser.
    fn rendered_title(&self, parser: &vt100::Parser<TitleSink>, redact: bool) -> Option<String> {
        let title = parser.callbacks().title.as_deref()?;
        Some(if redact {
            redact_str(&self.rules, title)
        } else {
            title.to_string()
        })
    }

    fn render(
        &mut self,
        parser: &vt100::Parser<TitleSink>,
        diff_from: Option<u64>,
        redact: bool,
        seed: &dyn SeedSource,
        holdback: Option<u64>,
    ) -> ScreenCapture {
        let revision = self.next_revision;
        self.next_revision += 1;

        // Redact first, then mask. Everything below — the diff, the
        // retained revision, the grid — is derived from this screen, never
        // from the raw one: §9.2 requires diffs between already-redacted
        // renderings and the mask joins that rule rather than getting a
        // second one, so a `diff_from` across a moving holdback describes
        // the masking as an ordinary screen change.
        let boundary = self.boundary_screen(
            parser,
            self.seeded_from,
            self.consumed_head,
            redact,
            seed,
            holdback,
        );
        let (redacted, held_back) = self.rendered_screen(parser, redact, boundary.as_ref());
        let title = self.rendered_title(parser, redact);

        // The `mode == redact` conjunct is REQ-O-011's second normative
        // test: a base captured under the other `redact` value differs
        // from this one by the redaction markers, so the diff would
        // describe the un-redaction. Degrade to a full grid — the same
        // graceful path an evicted revision already takes.
        let base = diff_from.and_then(|want| {
            self.retained
                .iter()
                .find(|(rev, mode, _)| *rev == want && *mode == redact)
                .map(|(rev, _, screen)| (*rev, screen))
        });

        let capture = match base {
            // `contents_diff` emits terminal escape codes, whose text runs
            // come from parsed `char`s, so the result is valid UTF-8. The
            // fallible conversion is a belt-and-braces guard: a full grid
            // is always a correct answer, an invalid string is not.
            Some((base_revision, base_screen)) => {
                match String::from_utf8(redacted.screen().contents_diff(base_screen)) {
                    Ok(diff) => ScreenCapture::Delta(ScreenDelta {
                        screen_revision: revision,
                        base_revision,
                        diff,
                        held_back,
                    }),
                    Err(_) => {
                        ScreenCapture::Full(grid_of(redacted.screen(), title, revision, held_back))
                    }
                }
            }
            None => ScreenCapture::Full(grid_of(redacted.screen(), title, revision, held_back)),
        };

        self.retained
            .push_back((revision, redact, redacted.screen().clone()));
        while self.retained.len() > self.cfg.retained_revisions {
            self.retained.pop_front();
        }
        capture
    }
}

/// Clip a redacted line to the grid width. A marker can be *longer* than
/// the secret it replaced — `TOKEN=abcdefgh` is 14 bytes, its redaction
/// is 23 — and an over-long line would wrap onto the next row and shift
/// every row below it. Clipping keeps the redacted grid the same shape as
/// the raw one, which is what makes the two comparable at all.
fn clip_to_cols(line: &str, cols: u16) -> String {
    line.chars().take(usize::from(cols)).collect()
}

/// `&text[start..end]` for offsets that came out of a **byte** regex, so
/// neither end is guaranteed to sit on a character boundary.
///
/// Row boundaries are boundaries by construction; span boundaries are
/// whatever the rule table produced. Every shipped rule ends its match on
/// an ASCII delimiter or consumes a permissive class whole, so today both
/// always land cleanly — but the rule table is operator-extensible (§9.2),
/// and one user rule with a byte-counted quantifier would otherwise turn
/// child output into a panic in the middle of a tool response. The snap
/// is **inward**, so a character the match split is withheld rather than
/// half-emitted: `start` moves forward to the next boundary, `end` back to
/// the previous one.
fn char_slice(text: &str, start: usize, end: usize) -> &str {
    let mut a = start.min(text.len());
    while a < text.len() && !text.is_char_boundary(a) {
        a += 1;
    }
    let mut b = end.min(text.len());
    while b > 0 && !text.is_char_boundary(b) {
        b -= 1;
    }
    if a >= b {
        ""
    } else {
        &text[a..b]
    }
}

fn grid_of(
    screen: &vt100::Screen,
    title: Option<String>,
    screen_revision: u64,
    held_back: bool,
) -> ScreenGrid {
    let (rows, cols) = screen.size();
    let (cursor_row, cursor_col) = screen.cursor_position();
    ScreenGrid {
        screen_revision,
        rows,
        cols,
        cursor_row,
        cursor_col,
        cursor_visible: !screen.hide_cursor(),
        alt_screen: screen.alternate_screen(),
        title,
        lines: screen.rows(0, cols).collect(),
        held_back,
    }
}

/// One replacement in the joined render: a byte range and the marker that
/// stands in for it.
struct Cut {
    start: usize,
    end: usize,
    text: String,
}

/// Append row `row`'s text to `joined` exactly as `Screen::rows` would
/// build it, and record — in `masked` — the byte ranges of the cells that
/// differ from `against`.
///
/// This mirrors `vt100::row::Row::write_contents`: a cell with no contents
/// emits nothing and is instead paid for by padding spaces in front of the
/// next cell that has some, the second half of a wide character is skipped,
/// and trailing empty cells emit nothing at all. Reproducing that walk is
/// what keeps `joined` byte-identical to the string the previous
/// implementation redacted, so the mask is additive rather than a second
/// rendering with its own rounding.
///
/// **Only a cell with contents can be masked.** A cell the withheld bytes
/// *blanked* holds nothing to withhold, and marking it would paint
/// `[REDACTED:unresolved]` where the child painted nothing — text the
/// agent would then have to disbelieve. The safety argument is unaffected:
/// a cell can only escape the mask by being empty or by being identical to
/// what the pre-boundary bytes put there.
fn write_row(
    screen: &vt100::Screen,
    row: u16,
    cols: u16,
    joined: &mut String,
    against: Option<&vt100::Screen>,
    masked: &mut Vec<(usize, usize)>,
) {
    let mut prev_was_wide = false;
    let mut prev_col = 0u16;
    let mut run: Option<(usize, usize)> = None;
    for col in 0..cols {
        let Some(cell) = screen.cell(row, col) else {
            break;
        };
        if prev_was_wide {
            prev_was_wide = false;
            continue;
        }
        prev_was_wide = cell.is_wide();
        if !cell.has_contents() {
            continue;
        }
        for _ in prev_col..col {
            joined.push(' ');
        }
        prev_col = col + if cell.is_wide() { 2 } else { 1 };
        let start = joined.len();
        joined.push_str(cell.contents());
        let end = joined.len();

        let differs = against.is_some_and(|base| {
            base.cell(row, col).map(vt100::Cell::contents) != Some(cell.contents())
        });
        match (differs, run) {
            // Cells adjacent in the join extend one run, so a withheld
            // value becomes one marker rather than one per character.
            (true, Some((s, e))) if e == start => run = Some((s, end)),
            (true, Some(prev)) => {
                masked.push(prev);
                run = Some((start, end));
            }
            (true, None) => run = Some((start, end)),
            (false, Some(prev)) => {
                masked.push(prev);
                run = None;
            }
            (false, None) => {}
        }
    }
    if let Some(prev) = run {
        masked.push(prev);
    }
}

/// Merge the redaction's spans with the holdback's masked runs into one
/// sorted, disjoint list of replacements (§9.2: join, redact, then mask),
/// and report whether any `unresolved` survived — which is exactly §5.2's
/// `held_back`.
///
/// **The spans win where the two overlap**, which is the whole of what
/// "redact first" decides: a complete value inside the withheld region
/// comes back as its own kind, and only the part of the mask no rule
/// claimed becomes `unresolved`. A masked run split by a span yields two
/// markers, one either side, because two separate runs of unvouched-for
/// cells is what that is.
///
/// **And a run that only *looks* split because it crossed a wrapped row
/// is rejoined first.** `write_row` flushes its run at every row
/// boundary, so a withheld region continuing onto a wrapped row arrives
/// here as two entries that touch exactly (`prev.end == start`) — the
/// join puts no separator between a wrapped row and its continuation.
/// Left alone they become two `[REDACTED:unresolved]` markers for one
/// region, which is precisely what `rendered_screen`'s step 2 says cannot
/// happen: a span crossing a row boundary emits one marker on the row it
/// opened on, and the rows it continues onto lose the covered text. Two
/// runs touch only in that case — within a row a flush means padding or
/// an unchanged cell came between, and an unwrapped row break puts a
/// `\n` between — so coalescing on `==` merges the wrap and nothing else.
fn compose(rules: &RuleSet, spans: &[Span], masked: &[(usize, usize)]) -> (Vec<Cut>, bool) {
    let unresolved = marker(UNRESOLVED_KIND);
    let mut cuts: Vec<Cut> = spans
        .iter()
        .map(|s| Cut {
            start: s.start as usize,
            end: s.end as usize,
            text: marker(&rules.rules[s.rule].kind),
        })
        .collect();
    let mut runs: Vec<(usize, usize)> = Vec::with_capacity(masked.len());
    for &(start, end) in masked {
        match runs.last_mut() {
            Some(last) if last.1 == start => last.1 = end,
            _ => runs.push((start, end)),
        }
    }
    let mut held_back = false;
    let mut mask = |start: usize, end: usize, cuts: &mut Vec<Cut>| {
        held_back = true;
        cuts.push(Cut {
            start,
            end,
            text: unresolved.clone(),
        });
    };
    for &(start, end) in &runs {
        let mut cursor = start;
        for span in spans
            .iter()
            .filter(|s| (s.start as usize) < end && (s.end as usize) > start)
        {
            let (s_start, s_end) = (span.start as usize, span.end as usize);
            if s_start > cursor {
                mask(cursor, s_start, &mut cuts);
            }
            cursor = cursor.max(s_end);
        }
        if cursor < end {
            mask(cursor, end, &mut cuts);
        }
    }
    cuts.sort_by_key(|c| c.start);
    (cuts, held_back)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `SeedSource` backed by a plain byte log, so the tracker's unit
    /// tests do not need a session or a PTY.
    #[derive(Default)]
    struct ByteLog {
        bytes: Vec<u8>,
    }

    impl ByteLog {
        fn push(&mut self, chunk: &[u8]) -> u64 {
            let start = self.bytes.len() as u64;
            self.bytes.extend_from_slice(chunk);
            start
        }
    }

    impl SeedSource for ByteLog {
        fn recent(&self, n: usize) -> Seed {
            let take = n.min(self.bytes.len());
            Seed {
                bytes: self.bytes[self.bytes.len() - take..].to_vec(),
                head: self.bytes.len() as u64,
            }
        }

        /// Nothing is ever evicted from a `Vec`, so `start` comes back
        /// unchanged — which is the case the session's ring buffer is in
        /// too until it wraps.
        fn replay(&self, start: u64, end: u64) -> Replay {
            let end = (end as usize).min(self.bytes.len());
            let start = (start as usize).min(end);
            Replay {
                bytes: self.bytes[start..end].to_vec(),
                start: start as u64,
            }
        }
    }

    fn rules() -> Arc<RuleSet> {
        crate::output::rules::builtin_shared()
    }

    fn cfg(mode: ScreenTracking) -> ScreenConfig {
        ScreenConfig {
            mode,
            rows: 24,
            cols: 80,
            ..ScreenConfig::default()
        }
    }

    /// Drive a tracker with a chunk, keeping the byte log and the
    /// tracker's view of the stream in step.
    fn feed(tracker: &mut ScreenTracker, log: &mut ByteLog, now: Instant, chunk: &[u8]) {
        let start = log.push(chunk);
        tracker.feed(start, chunk, now, log);
    }

    fn full(capture: ScreenCapture) -> ScreenGrid {
        match capture {
            ScreenCapture::Full(g) => g,
            ScreenCapture::Delta(d) => panic!("expected a full grid, got {d:?}"),
        }
    }

    fn delta(capture: ScreenCapture) -> ScreenDelta {
        match capture {
            ScreenCapture::Delta(d) => d,
            ScreenCapture::Full(g) => {
                panic!(
                    "expected a diff, got a full grid at revision {}",
                    g.screen_revision
                )
            }
        }
    }

    /// Replay a base grid and a diff into a fresh emulator, exactly as a
    /// client holding the base revision would.
    fn apply(base: &vt100::Screen, diff: &str) -> vt100::Parser {
        let mut p = vt100::Parser::new(base.size().0, base.size().1, 0);
        p.process(&base.contents_formatted());
        p.process(diff.as_bytes());
        p
    }

    #[test]
    fn a_line_oriented_session_never_touches_the_parser() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::Adaptive), rules(), t0);
        feed(&mut t, &mut log, t0, b"\x1b[?2004h$ ");
        for i in 1..2000 {
            feed(
                &mut t,
                &mut log,
                t0 + Duration::from_millis(i * 10),
                b"Compiling something v1.2.3\n",
            );
        }
        assert_eq!(t.tracking_state(), "off");
        assert_eq!(
            t.parsed_bytes(),
            0,
            "Tier B ran on a session that never asked for a screen"
        );
    }

    #[test]
    fn alt_screen_entry_enables_and_seeds_from_the_buffer() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::Adaptive), rules(), t0);

        feed(&mut t, &mut log, t0, b"\x1b[?2004h$ less file\r\n");
        assert_eq!(t.tracking_state(), "off");

        feed(
            &mut t,
            &mut log,
            t0,
            b"\x1b[?1049h\x1b[H\x1b[2JPAGER LINE ONE",
        );
        assert_eq!(t.tracking_state(), "on");

        let g = full(t.capture(None, true, t0, &log, None));
        assert!(g.alt_screen);
        assert_eq!(g.lines[0].trim_end(), "PAGER LINE ONE");
    }

    #[test]
    fn the_triggering_chunk_is_not_applied_twice() {
        // The chunk that fires a §4.5 trigger is already in the ring
        // buffer when the seed is taken. Re-processing it would paint its
        // text a second time; `consumed_head` is what prevents that.
        //
        // The payload carries neither `\x1b[2J` nor `\x1b[?1049h`: both
        // reset the grid, so a doubled apply would repaint over itself and
        // the assertion below would hold even with the guard removed. The
        // trigger used is therefore the no-signal timer, which changes no
        // cells at all.
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::Adaptive), rules(), t0);
        let fired = t0 + NO_SIGNAL_GRACE;
        feed(&mut t, &mut log, fired, b"ABC");
        assert_eq!(t.tracking_state(), "on", "the trigger did not fire");

        let g = full(t.capture(None, true, fired, &log, None));
        assert_eq!(
            g.lines[0].trim_end(),
            "ABC",
            "the seeded chunk was applied twice"
        );
        assert_eq!((g.cursor_row, g.cursor_col), (0, 3));
    }

    #[test]
    fn a_mid_session_seed_reconstructs_the_visible_grid() {
        // Tier B is off while a TUI paints, then the agent asks for the
        // screen. The grid must show what is currently visible even though
        // the parser did not exist while it was painted.
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::Adaptive), rules(), t0);

        feed(&mut t, &mut log, t0, b"\x1b[?2004h$ ");
        feed(&mut t, &mut log, t0, b"\x1b[H\x1b[2JHEADER\r\n");
        for i in 0..5 {
            feed(&mut t, &mut log, t0, format!("row {i}\r\n").as_bytes());
        }
        assert_eq!(t.parsed_bytes(), 0, "still off");

        let g = full(t.capture(None, true, t0, &log, None));
        assert_eq!(t.tracking_state(), "on");
        assert_eq!(g.lines[0].trim_end(), "HEADER");
        assert_eq!(g.lines[3].trim_end(), "row 2");
        assert!(t.parsed_bytes() > 0);
    }

    #[test]
    fn scrollback_older_than_the_seed_window_is_not_reconstructed() {
        // The documented limit in §4.5. Asserted so it cannot drift into
        // an unnoticed correctness claim.
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::Adaptive), rules(), t0);
        feed(&mut t, &mut log, t0, b"\x1b[?2004h");
        feed(&mut t, &mut log, t0, b"\x1b[H\x1b[2JANCIENT HEADER\r\n");
        // 24 * 80 * 4 = 7680 bytes of seed window; push well past it.
        for _ in 0..600 {
            feed(&mut t, &mut log, t0, b"filler line of output text\r\n");
        }
        let g = full(t.capture(None, true, t0, &log, None));
        assert!(
            !g.lines.iter().any(|l| l.contains("ANCIENT HEADER")),
            "header should have rolled out of the seed window"
        );
        assert!(g.lines.iter().any(|l| l.contains("filler line")));
    }

    #[test]
    fn a_diff_is_much_smaller_than_the_grid_and_replays_to_the_same_screen() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);

        // Paint every row so the full grid is genuinely large.
        feed(&mut t, &mut log, t0, b"\x1b[?1049h\x1b[H\x1b[2J");
        for row in 1..=24 {
            feed(
                &mut t,
                &mut log,
                t0,
                format!("\x1b[{row};1Hline {row:02} of the editor buffer, padded out a bit")
                    .as_bytes(),
            );
        }
        let first = full(t.capture(None, true, t0, &log, None));
        let base_screen = t.retained.back().expect("revision retained").2.clone();

        // One keystroke.
        feed(&mut t, &mut log, t0, b"\x1b[12;7HX");
        let second = t.capture(Some(first.screen_revision), true, t0, &log, None);
        let d = delta(second);
        assert_eq!(d.base_revision, first.screen_revision);

        let full_size: usize = first.lines.iter().map(|l| l.len() + 1).sum();
        assert!(
            d.diff.len() * 10 < full_size,
            "diff {} bytes vs full grid {} bytes — not an order of magnitude",
            d.diff.len(),
            full_size
        );

        // The size assertion alone is satisfied by an empty diff, so
        // prove the diff actually carries the change: replaying it over
        // the base must reproduce the new screen byte for byte.
        let replayed = apply(&base_screen, &d.diff);
        let expected = t.parser.as_ref().expect("parser").screen();
        assert_eq!(
            replayed.screen().contents_formatted(),
            expected.contents_formatted(),
            "replaying the diff did not reproduce the new screen"
        );
        let replayed_lines: Vec<String> = replayed.screen().rows(0, 80).collect();
        assert_ne!(
            replayed_lines, first.lines,
            "the screen did not change, so this test proves nothing"
        );
        assert!(replayed_lines[11].contains('X'));
    }

    #[test]
    fn an_unknown_diff_from_degrades_to_a_full_grid() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);
        feed(&mut t, &mut log, t0, b"hello");
        let g = full(t.capture(Some(9_999), true, t0, &log, None));
        assert_eq!(g.lines[0].trim_end(), "hello");
    }

    #[test]
    fn retained_revisions_are_bounded_and_evicted_oldest_first() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(
            ScreenConfig {
                retained_revisions: 2,
                ..cfg(ScreenTracking::On)
            },
            rules(),
            t0,
        );
        // Every capture mints and retains a revision, so three captures
        // with a retention of two leave only the newest two.
        feed(&mut t, &mut log, t0, b"a");
        let first = full(t.capture(None, true, t0, &log, None)).screen_revision;
        feed(&mut t, &mut log, t0, b"b");
        let second = full(t.capture(None, true, t0, &log, None)).screen_revision;
        feed(&mut t, &mut log, t0, b"c");
        let third = full(t.capture(None, true, t0, &log, None)).screen_revision;

        feed(&mut t, &mut log, t0, b"d");
        assert!(
            matches!(
                t.capture(Some(third), true, t0, &log, None),
                ScreenCapture::Delta(_)
            ),
            "the newest retained revision must still diff"
        );
        assert!(
            matches!(
                t.capture(Some(second), true, t0, &log, None),
                ScreenCapture::Full(_)
            ),
            "revision {second} should have been evicted by now"
        );
        assert!(
            matches!(
                t.capture(Some(first), true, t0, &log, None),
                ScreenCapture::Full(_)
            ),
            "revision {first} should have been evicted long ago"
        );
    }

    #[test]
    fn revisions_are_unique_and_increasing() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);
        feed(&mut t, &mut log, t0, b"x");
        let a = full(t.capture(None, true, t0, &log, None)).screen_revision;
        let b = full(t.capture(None, true, t0, &log, None)).screen_revision;
        assert!(a > UNRETAINED_REVISION);
        assert!(b > a);
    }

    #[test]
    fn off_answers_without_ever_running_on_the_write_path() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::Off), rules(), t0);
        feed(&mut t, &mut log, t0, b"\x1b[?1049h\x1b[H\x1b[2JTUI CONTENT");
        assert_eq!(
            t.parsed_bytes(),
            0,
            "`off` must not parse on the write path, even inside a TUI"
        );

        let g = full(t.capture(None, true, t0, &log, None));
        assert_eq!(g.lines[0].trim_end(), "TUI CONTENT");
        assert_eq!(g.screen_revision, UNRETAINED_REVISION);
        assert_eq!(t.tracking_state(), "off", "the one-shot must not latch on");

        // A revision that is never retained can never satisfy a diff.
        let again = full(t.capture(Some(UNRETAINED_REVISION), true, t0, &log, None));
        assert_eq!(again.screen_revision, UNRETAINED_REVISION);
    }

    #[test]
    fn the_idle_window_frees_the_parser_and_the_retained_screens() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::Adaptive), rules(), t0);
        feed(&mut t, &mut log, t0, b"\x1b[?2004h$ ");
        let g = full(t.capture(None, true, t0, &log, None));
        assert_eq!(t.tracking_state(), "on");
        assert!(t.parser.is_some());

        let later = t0 + DEFAULT_IDLE_DISABLE + Duration::from_secs(1);
        feed(&mut t, &mut log, later, b"more output\n");
        assert_eq!(t.tracking_state(), "off");
        assert!(t.parser.is_none());
        assert!(t.retained.is_empty());

        // Coming back is a fresh seed, so the stale revision cannot diff.
        let again = t.capture(Some(g.screen_revision), true, later, &log, None);
        assert!(matches!(again, ScreenCapture::Full(_)));
    }

    #[test]
    fn the_window_title_is_reported() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);
        feed(&mut t, &mut log, t0, b"\x1b]0;clasp: build\x07ready");
        let g = full(t.capture(None, true, t0, &log, None));
        assert_eq!(g.title.as_deref(), Some("clasp: build"));
    }

    #[test]
    fn the_cursor_signal_is_absent_until_tier_b_runs() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::Adaptive), rules(), t0);
        feed(&mut t, &mut log, t0, b"\x1b[?2004h$ ");
        assert!(t.cursor_signal(t0, &log).is_none());
    }

    #[test]
    fn the_cursor_signal_needs_a_stable_position_before_it_scores() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);
        feed(&mut t, &mut log, t0, b"$ ");

        let first = t.cursor_signal(t0, &log).expect("tier b is on");
        assert_eq!(first.score, 0.0, "one sample is not stability");
        assert!(!first.stable);

        t.cursor_signal(t0, &log);
        let third = t.cursor_signal(t0, &log).unwrap();
        assert!(third.stable);
        assert_eq!(third.score, 0.9);
        assert_eq!((third.row, third.col), (0, 2));
    }

    /// The other half of §8.6's "sampled as output arrives", and the one
    /// that reaches the sample `process_range` takes.
    ///
    /// **Written because a mutation showed the test below cannot reach
    /// it.** Deleting `process_range`'s `stability.observe` fails no test
    /// there, because `cursor_signal` observes the position itself before
    /// it answers — so a cursor that moved is caught by the poll's own
    /// sample whether or not the write path took one. What only the write
    /// path can do is *advance* the count: a chunk that repaints without
    /// moving the cursor is a parser update the cursor held position
    /// across, and §8.6 counts it. Here two polls and one such chunk reach
    /// three samples; without the write-path sample they reach two and
    /// the signal is still unstable.
    #[test]
    fn output_that_leaves_the_cursor_where_it_was_counts_as_a_sample() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);
        feed(&mut t, &mut log, t0, b"$ ");

        let first = t.cursor_signal(t0, &log).expect("tier b is on");
        assert_eq!(first.stable_samples, 1);

        // A repaint that puts the cursor back exactly where it was.
        feed(&mut t, &mut log, t0, b"\x1b[1;3H");
        let second = t.cursor_signal(t0, &log).unwrap();
        assert_eq!(
            second.stable_samples, 3,
            "the arriving chunk was not counted as a sample"
        );
        assert!(second.stable);
        assert_eq!(second.score, 0.9);
    }

    #[test]
    fn output_that_moves_the_cursor_resets_stability() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);
        feed(&mut t, &mut log, t0, b"$ ");
        for _ in 0..5 {
            t.cursor_signal(t0, &log);
        }
        assert!(t.cursor_signal(t0, &log).unwrap().stable);

        feed(&mut t, &mut log, t0, b"x");
        let after = t.cursor_signal(t0, &log).unwrap();
        assert!(!after.stable, "the cursor moved; the count must restart");
        assert_eq!(after.score, 0.0);
    }

    /// Spec §5.2 gives `get_screen_state` a `redact: bool?` that defaults
    /// to true. This is the test that says so, and it is written against
    /// the two ways a redaction test goes vacuous.
    ///
    /// *An implementation that returned nothing would pass an
    /// absence-only check*, so the surrounding screen is asserted present
    /// and byte-exact — including the `export GH_TOKEN=` label, which a
    /// context rule is supposed to leave visible.
    ///
    /// *A diff that never carried the secret would also pass*, so the
    /// secret is painted **after** the base revision is captured. It is
    /// therefore necessarily inside the changed region the diff has to
    /// describe; there is no way for the diff to be silently empty here.
    #[test]
    fn a_secret_is_redacted_in_the_full_grid_and_in_the_diff() {
        const SECRET: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);

        feed(&mut t, &mut log, t0, b"\x1b[?1049h\x1b[H\x1b[2J");
        feed(&mut t, &mut log, t0, b"\x1b[1;1Hharmless header line");
        let base = full(t.capture(None, true, t0, &log, None));
        let base_screen = t.retained.back().expect("revision retained").2.clone();
        assert_eq!(base.lines[0].trim_end(), "harmless header line");

        feed(
            &mut t,
            &mut log,
            t0,
            format!("\x1b[2;1Hexport GH_TOKEN={SECRET}").as_bytes(),
        );

        let d = delta(t.capture(Some(base.screen_revision), true, t0, &log, None));
        let after_screen = t.retained.back().expect("revision retained").2.clone();
        assert!(
            !d.diff.contains("ghp_"),
            "the secret reached the diff: {:?}",
            d.diff
        );
        assert!(
            d.diff.contains("[REDACTED:github]"),
            "the diff carries no redaction marker: {:?}",
            d.diff
        );
        assert!(
            d.diff.contains("export GH_TOKEN="),
            "the label should survive redaction: {:?}",
            d.diff
        );

        let g = full(t.capture(None, true, t0, &log, None));
        assert!(
            !g.lines.iter().any(|l| l.contains("ghp_")),
            "the secret reached the full grid: {:?}",
            g.lines
        );
        assert_eq!(
            g.lines[0].trim_end(),
            "harmless header line",
            "redaction ate the rest of the screen"
        );
        assert_eq!(g.lines[1].trim_end(), "export GH_TOKEN=[REDACTED:github]");

        // §5.2's replay contract has to survive redaction, which is the
        // reason the grids are redacted *before* they are diffed rather
        // than the diff being scrubbed afterwards.
        assert_ne!(
            base_screen.contents_formatted(),
            after_screen.contents_formatted(),
            "the screen did not change, so this test proves nothing"
        );
        let replayed = apply(&base_screen, &d.diff);
        assert_eq!(
            replayed.screen().contents_formatted(),
            after_screen.contents_formatted(),
            "replaying the redacted diff did not reproduce the redacted screen"
        );

        // The seam: Tier B keeps parsing **raw** bytes. Redaction is a
        // render-time transform, because redacting the byte stream would
        // corrupt escape sequences and the ring buffer is raw by design.
        let raw: Vec<String> = t
            .parser
            .as_ref()
            .expect("parser")
            .screen()
            .rows(0, 80)
            .collect();
        assert!(
            raw.iter().any(|l| l.contains(SECRET)),
            "the parser should still hold the raw bytes: {raw:?}"
        );
    }

    /// REQ-O-011's first normative test, and the one that separates this
    /// implementation from the one §9.2's screen-state row forbids.
    ///
    /// The test above writes the token in a single chunk, so a redactor
    /// bolted onto the **byte stream** passes it just as happily as one
    /// running on the rendered rows: the token is contiguous in both
    /// views. That is the "naive test" REQ-O-011 names. Here the token is
    /// painted in **two writes at two absolute cursor positions**, so it
    /// exists nowhere in the byte stream and nowhere in any window over
    /// it — it becomes contiguous only in the reconstructed grid, which is
    /// the whole reason the row exists.
    ///
    /// The arithmetic is deliberate and must be kept if the strings are
    /// changed: `export GH_TOKEN=` is 16 characters, so it fills columns
    /// 1-16; the 24-character head `ghp_0123456789abcdefghij` fills 17-40;
    /// the 16-character tail therefore starts at **column 41**. Land the
    /// tail one column early and the two halves overlap, the reassembled
    /// token is shorter than the 36 characters the `github` rule requires,
    /// nothing matches, and the test fails for a reason that has nothing
    /// to do with redaction.
    ///
    /// Mutate this one by moving `redact_str` to the byte stream (Step 5a),
    /// not by stubbing it — a stub is what the test above already kills.
    #[test]
    fn a_secret_painted_by_cursor_positioning_is_redacted_after_rendering() {
        const HEAD: &str = "ghp_0123456789abcdefghij";
        const TAIL: &str = "ABCDEFGHIJ012345";
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);

        feed(&mut t, &mut log, t0, b"\x1b[?1049h\x1b[H\x1b[2J");
        feed(
            &mut t,
            &mut log,
            t0,
            format!("\x1b[2;1Hexport GH_TOKEN={HEAD}").as_bytes(),
        );
        feed(&mut t, &mut log, t0, format!("\x1b[2;41H{TAIL}").as_bytes());

        // The premise, asserted rather than assumed: no single write, and
        // no concatenation of the writes as bytes, contains the token.
        let whole = format!("{HEAD}{TAIL}");
        assert!(
            !String::from_utf8_lossy(&log.bytes).contains(&whole),
            "the byte stream carries the token contiguously, so this test \
             cannot tell a stream redactor from a row redactor"
        );

        let g = full(t.capture(None, true, t0, &log, None));
        assert_eq!(
            g.lines[1].trim_end(),
            "export GH_TOKEN=[REDACTED:github]",
            "the token was reassembled by the grid and must be redacted there"
        );
        assert!(
            !g.lines.iter().any(|l| l.contains("ghp_")),
            "the secret reached the grid: {:?}",
            g.lines
        );
    }

    /// REQ-O-011's second normative test. `redact` is part of what a
    /// revision *is*: the two renderings differ by the markers themselves,
    /// so diffing across them would emit the un-redaction as if it were a
    /// screen change. Degrade to a full grid, like an evicted revision.
    ///
    /// The negative that stops this being vacuous is the second half: the
    /// *same* revision number diffs fine when the mode matches, so an
    /// implementation that simply never diffs does not pass.
    #[test]
    fn a_diff_across_redaction_modes_degrades_to_a_full_grid() {
        const SECRET: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);

        feed(&mut t, &mut log, t0, b"\x1b[?1049h\x1b[H\x1b[2J");
        feed(
            &mut t,
            &mut log,
            t0,
            format!("\x1b[1;1Hexport GH_TOKEN={SECRET}").as_bytes(),
        );

        let redacted = full(t.capture(None, true, t0, &log, None));
        assert_eq!(
            redacted.lines[0].trim_end(),
            "export GH_TOKEN=[REDACTED:github]"
        );

        // Same base revision, opposite mode: a full grid, and an
        // unredacted one, because that is what the caller asked for.
        let raw = full(t.capture(Some(redacted.screen_revision), false, t0, &log, None));
        assert_eq!(
            raw.lines[0].trim_end(),
            format!("export GH_TOKEN={SECRET}"),
            "redact: false must actually return the secret, or the \
             default-on tests above prove nothing"
        );

        // …and the negative: the mode-matched base still diffs, so the
        // degradation above is about the mode and not about diffing being
        // broken.
        feed(&mut t, &mut log, t0, b"\x1b[3;1Hone more line");
        assert!(
            matches!(
                t.capture(Some(redacted.screen_revision), true, t0, &log, None),
                ScreenCapture::Delta(_)
            ),
            "a base retained under the same redact value must still diff"
        );
    }

    /// REQ-O-011a, case 1: a rule that is *inherently* multi-row.
    ///
    /// `private-key-block` needs `-----BEGIN` on one row and `-----END`
    /// several rows below, so **a per-row redactor can never match it** —
    /// and a per-row redactor passes every other redaction test in this
    /// module, including REQ-O-011's own cursor-positioning fixture. This
    /// test and the wrap one below are the only two that separate the
    /// units, and neither is reachable from the other: this one is a
    /// short-line case with no wrapping in it at all.
    ///
    /// Every row here is well under 80 columns, deliberately. If the
    /// fixture fits inside one row it is not testing this rule; if it
    /// *wrapped*, it would also pass against an implementation that got
    /// only the wrap case right.
    #[test]
    fn a_pem_painted_across_rows_is_redacted_as_one_span() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);

        feed(&mut t, &mut log, t0, b"\x1b[?1049h\x1b[H\x1b[2J");
        for (i, row) in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIEpAIBAAKCAQEA0123456789abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnop",
            "-----END RSA PRIVATE KEY-----",
        ]
        .iter()
        .enumerate()
        {
            feed(
                &mut t,
                &mut log,
                t0,
                format!("\x1b[{};1H{row}", i + 3).as_bytes(),
            );
        }

        let g = full(t.capture(None, true, t0, &log, None));
        assert_eq!(
            g.lines[2].trim_end(),
            "[REDACTED:private-key]",
            "the block was not judged as one span: {:?}",
            g.lines
        );
        // The rows the span continued onto lose their text rather than
        // each gaining a marker of their own.
        assert!(
            !g.lines.iter().any(|l| l.contains("MIIEpAIBAAKCAQEA")),
            "the key body survived on a continuation row: {:?}",
            g.lines
        );
        assert_eq!(
            g.lines.iter().filter(|l| l.contains("[REDACTED")).count(),
            1,
            "one span must produce one marker, not one per row: {:?}",
            g.lines
        );
    }

    /// REQ-O-011a, case 2: a value that fits no row because it is wider
    /// than one.
    ///
    /// Driven at the default 80 columns, where every other fixture in
    /// this plan sits. The token is 128 characters: 11 characters of
    /// prefix put its start at column 12, its 43-character first segment
    /// and dot end at column 55, and the wrap therefore falls 22
    /// characters into the second segment — so row one ends after a
    /// single `.` and cannot match, and row two carries no `eyJ` anchor
    /// and cannot either. Keep that arithmetic if you change the strings:
    /// let the wrap fall inside the *third* segment instead and row one
    /// still satisfies the rule's `{10,}` tail, redacts a prefix, and the
    /// test passes against the implementation it exists to forbid.
    ///
    /// The second assertion is the geometry half, and it is why the
    /// fixture paints an untouched line four rows down: collapsing a
    /// two-row value into one marker must not shift the rest of the grid
    /// up. Each logical line is repainted at the row it started on.
    #[test]
    fn a_token_wider_than_the_grid_is_redacted_across_its_wrap() {
        const SEG: &str = "0123456789012345678901234567890123456789";
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);

        // `eyJ` + 40 + `.` + `eyJ` + 40 + `.` + 40 = 128 characters.
        let token = format!("eyJ{SEG}.eyJ{SEG}.{SEG}");
        assert_eq!(token.len(), 128, "the wrap position depends on this");

        feed(&mut t, &mut log, t0, b"\x1b[?1049h\x1b[H\x1b[2J");
        feed(
            &mut t,
            &mut log,
            t0,
            format!("\x1b[1;1Hexport JWT={token}").as_bytes(),
        );
        feed(&mut t, &mut log, t0, b"\x1b[4;1Hplain untouched line");

        let g = full(t.capture(None, true, t0, &log, None));
        assert_eq!(g.lines[0].trim_end(), "export JWT=[REDACTED:jwt]");
        assert!(
            !g.lines.iter().any(|l| l.contains("eyJ")),
            "a fragment of the token survived: {:?}",
            g.lines
        );
        assert_eq!(
            g.lines[3].trim_end(),
            "plain untouched line",
            "collapsing the wrapped value shifted the grid: {:?}",
            g.lines
        );
    }

    /// REQ-O-011a's join, from the side the other two fixtures cannot
    /// see: **rows that are not continuations must not be glued.**
    ///
    /// Two separate lines, neither of which matches anything on its own,
    /// whose *concatenation* is a valid JWT. An implementation that
    /// enlarged the unit by joining every row with no separator redacts
    /// them — and in doing so deletes two lines of output that were never
    /// a secret. Verified against the whole shipped rule table: neither
    /// row matches any rule, the two joined by `\n` match none, and the
    /// two concatenated match `jwt`.
    ///
    /// Note the lines carry no `token=`/`secret=` label, deliberately:
    /// `generic-secret-assignment` would fire on the first row alone and
    /// the test would pass for a reason that has nothing to do with the
    /// join.
    #[test]
    fn two_adjacent_unwrapped_lines_are_not_joined_into_one_match() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);

        feed(&mut t, &mut log, t0, b"\x1b[?1049h\x1b[H\x1b[2J");
        feed(&mut t, &mut log, t0, b"\x1b[1;1HeyJ0123456789012345");
        feed(
            &mut t,
            &mut log,
            t0,
            b"\x1b[2;1H6789.eyJ0123456789.0123456789012",
        );

        let g = full(t.capture(None, true, t0, &log, None));
        assert_eq!(g.lines[0].trim_end(), "eyJ0123456789012345");
        assert_eq!(g.lines[1].trim_end(), "6789.eyJ0123456789.0123456789012");
        // The premise, asserted rather than assumed: these two really do
        // form a match when concatenated, so a no-separator join would
        // have destroyed both lines.
        assert!(
            redact_str(
                &rules(),
                "eyJ01234567890123456789.eyJ0123456789.0123456789012"
            )
            .contains("[REDACTED:jwt]"),
            "the two lines do not concatenate into a match, so this test \
             cannot see a no-separator join"
        );
    }

    /// The paired negative REQ-O-011a names: ordinary multi-row text is
    /// returned **byte-identical**.
    ///
    /// Without it, "redact over the whole render" is satisfied by an
    /// implementation that mangles every grid it touches — and by one
    /// that returns blank rows, which every absence assertion above would
    /// also accept.
    #[test]
    fn ordinary_multi_row_text_is_returned_byte_identical() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);

        feed(&mut t, &mut log, t0, b"\x1b[?1049h\x1b[H\x1b[2J");
        for (i, row) in ["harmless header line", "second ordinary line"]
            .iter()
            .enumerate()
        {
            feed(
                &mut t,
                &mut log,
                t0,
                format!("\x1b[{};1H{row}", i + 1).as_bytes(),
            );
        }

        let redacted = full(t.capture(None, true, t0, &log, None));
        let raw = full(t.capture(None, false, t0, &log, None));
        assert_eq!(
            redacted.lines, raw.lines,
            "the whole-render pass altered text that contains no secret"
        );
        assert_eq!(redacted.lines[0].trim_end(), "harmless header line");
        assert_eq!(redacted.lines[1].trim_end(), "second ordinary line");
    }

    /// A span boundary that falls **inside a character**, which no
    /// shipped rule produces and an operator rule can (§9.2 makes the
    /// table extensible). Without the inward snap in [`char_slice`] the
    /// repaint slices a `String` off a boundary and panics, turning child
    /// output plus one config line into a crashed tool call.
    ///
    /// The paired half is the second assertion: the character the match
    /// did not cover is still there. A `char_slice` that returned `""`
    /// whenever anything looked awkward would pass the no-panic half
    /// alone.
    #[test]
    fn a_span_ending_inside_a_character_neither_panics_nor_eats_the_rest() {
        // `(?-u:.)` counts *bytes*, so a match of four of them covers
        // `MARK`, the whole of the first `❯` (three bytes) and the first
        // byte of the second — the boundary case the snap exists for.
        // **The count is load-bearing:** six bytes would cover both `❯`s
        // exactly, the match would end on a boundary, and the fixture
        // would pass against unsnapped slicing. Measured: it did, which
        // is why the arithmetic is written down here. Not a rule anyone
        // would write on purpose; the point is that the rule table is
        // data (§9.2 makes it operator-extensible) and this module must
        // not panic on any of it.
        let toml = r#"
source_version = "test-boundary"

[[rule]]
name = "byte-counted"
kind = "bytes"
pattern = '''MARK(?-u:.){4}'''
positive = ["MARKabcd"]
negative = ["MARK"]
"#;
        let custom = Arc::new(RuleSet::from_toml(toml).expect("test rule set compiles"));
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), custom, t0);

        feed(&mut t, &mut log, t0, b"\x1b[?1049h\x1b[H\x1b[2J");
        feed(
            &mut t,
            &mut log,
            t0,
            "\x1b[1;1HMARK\u{276f}\u{276f}tail".as_bytes(),
        );

        let g = full(t.capture(None, true, t0, &log, None));
        assert_eq!(
            g.lines[0].trim_end(),
            "[REDACTED:bytes]tail",
            "the split character must be withheld with the span, and the \
             text past it kept: {:?}",
            g.lines
        );
    }

    /// A marker can be **longer** than the secret it replaced, and a line
    /// that outgrows `cols` would wrap onto the row below and shift every
    /// row after it — so the redacted grid would no longer be the same
    /// shape as the raw one it is supposed to describe.
    ///
    /// **Written because a mutation showed nothing pinned `clip_to_cols`**
    /// — shortening it by a column failed no test, since every other
    /// fixture's lines are far narrower than 80 and the byte-identical
    /// negative clips both of its renderings equally.
    ///
    /// The row below the over-long one is left blank deliberately: the
    /// repaint paints rows in order at absolute positions, so a
    /// *populated* next row would overwrite the overflow and hide the
    /// damage. Blank is the case where it survives.
    #[test]
    fn a_marker_longer_than_its_secret_does_not_spill_onto_the_next_row() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);

        // 60 columns of padding, then `TOKEN=abcdefgh` (14) — 74 columns
        // raw. Redacted it is 60 + `TOKEN=` + `[REDACTED:generic]` = 84,
        // four columns past the right edge.
        let pad = "pad ".repeat(15);
        assert_eq!(pad.len(), 60);
        feed(&mut t, &mut log, t0, b"\x1b[?1049h\x1b[H\x1b[2J");
        feed(
            &mut t,
            &mut log,
            t0,
            format!("\x1b[1;1H{pad}TOKEN=abcdefgh").as_bytes(),
        );

        let g = full(t.capture(None, true, t0, &log, None));
        assert!(
            !g.lines[0].contains("abcdefgh"),
            "the secret survived: {:?}",
            g.lines[0]
        );
        assert_eq!(
            g.lines[0].chars().count(),
            80,
            "the redacted line is wider than the grid: {:?}",
            g.lines[0]
        );
        assert_eq!(
            g.lines[1], "",
            "the over-long line wrapped onto the row below: {:?}",
            g.lines[1]
        );
    }

    #[test]
    fn poll_fires_the_no_signal_trigger_on_a_quiet_session() {
        // dash prints its prompt once and then says nothing. Nothing else
        // will call `feed`, so the 3 s trigger has to be reachable from an
        // observer poll or it never fires at all.
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::Adaptive), rules(), t0);
        feed(&mut t, &mut log, t0, b"$ ");
        assert_eq!(t.tracking_state(), "off");

        let later = t0 + NO_SIGNAL_GRACE;
        assert!(t.cursor_signal(later, &log).is_some());
        assert_eq!(t.tracking_state(), "on");
    }

    /// Paint `text` after a holdback boundary onto an otherwise cleared
    /// grid, and hand back both renders: masked, and the same bytes with
    /// no holdback at all.
    ///
    /// The second is what keeps every assertion below off the degenerate
    /// reading. "Row 1 carries no marker" is satisfied by a grid that was
    /// never painted and by a mask that swallowed everything; only the
    /// unmasked render says which.
    fn masked_and_plain(text: &str) -> (ScreenGrid, ScreenGrid) {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);

        // Everything before the boundary: a cleared screen. So every cell
        // the withheld bytes paint differs from the boundary render, and
        // the masked extent is exactly `text`.
        feed(&mut t, &mut log, t0, b"\x1b[H\x1b[2J");
        let boundary = log.bytes.len() as u64;
        feed(&mut t, &mut log, t0, text.as_bytes());

        let masked = full(t.capture(None, true, t0, &log, Some(boundary)));
        let plain = full(t.capture(None, true, t0, &log, None));
        (masked, plain)
    }

    /// §4.1's mask, at this module's own level.
    ///
    /// A withheld region that continues onto a **wrapped** row is one
    /// region. `write_row` flushes its run at every row boundary, so it
    /// reaches `compose` as two entries that touch; without the coalesce
    /// there, rows 0 and 1 each get their own `[REDACTED:unresolved]` for
    /// one withheld thing — the exact case `rendered_screen`'s step 2
    /// states cannot happen, and one that spends the marker's 21
    /// characters of `clip_to_cols` budget on two rows instead of one.
    #[test]
    fn a_masked_region_crossing_a_wrapped_row_emits_one_marker() {
        let unresolved = marker(UNRESOLVED_KIND);
        // 90 columns of prose on an 80-column grid: row 0 fills and
        // wraps, row 1 takes the remaining 10 cells. Prose rather than a
        // filler run so no redaction rule claims part of it and turns the
        // marker count into a measurement of something else.
        let text: String = "the quick brown fox jumps over the lazy dog "
            .chars()
            .cycle()
            .take(90)
            .collect();
        let (masked, plain) = masked_and_plain(&text);

        // The control first: the bytes really did land, and they really
        // did wrap, so "row 1 is blank" below is the mask's doing.
        assert!(!plain.held_back);
        assert_eq!(plain.lines[0].trim_end(), &text[..80]);
        assert_eq!(plain.lines[1].trim_end(), &text[80..]);
        assert!(!plain.lines.iter().any(|l| l.contains("[REDACTED:")));

        assert!(masked.held_back, "the holdback was open");
        let markers: usize = masked
            .lines
            .iter()
            .map(|l| l.matches(&unresolved).count())
            .sum();
        assert_eq!(
            markers, 1,
            "one withheld region across a wrap must emit one marker; grid \
             rows 0-1 were {:?} / {:?}",
            masked.lines[0], masked.lines[1]
        );
        assert_eq!(masked.lines[0].trim_end(), unresolved);
        assert_eq!(
            masked.lines[1].trim_end(),
            "",
            "the wrapped continuation must lose the covered text, not gain \
             a second marker"
        );
    }

    /// The other side of the same coalesce: two masked runs on rows that
    /// are **not** a wrap are two regions and keep their own markers. A
    /// merge that keyed on anything looser than "the ranges touch" would
    /// glue these into one and delete the row break.
    #[test]
    fn two_masked_rows_that_are_not_a_wrap_keep_their_own_markers() {
        let unresolved = marker(UNRESOLVED_KIND);
        let (masked, plain) = masked_and_plain("alpha\r\nbeta");

        assert_eq!(plain.lines[0].trim_end(), "alpha");
        assert_eq!(plain.lines[1].trim_end(), "beta");

        assert!(masked.held_back);
        assert_eq!(masked.lines[0].trim_end(), unresolved);
        assert_eq!(masked.lines[1].trim_end(), unresolved);
    }

    /// An empty diff is the truthful answer to "nothing changed", and
    /// `render` says it as a `Delta` rather than degrading to a full grid.
    /// Nothing pinned that, so an implementation that fell back to a full
    /// grid on the empty case was indistinguishable to the suite.
    #[test]
    fn a_diff_across_no_change_is_an_empty_delta_that_still_replays() {
        let t0 = Instant::now();
        let mut log = ByteLog::default();
        let mut t = ScreenTracker::new(cfg(ScreenTracking::On), rules(), t0);
        feed(&mut t, &mut log, t0, b"\x1b[H\x1b[2Jhello");

        let first = full(t.capture(None, true, t0, &log, None));
        let base = t.retained.back().expect("base retained").2.clone();

        let quiet = delta(t.capture(Some(first.screen_revision), true, t0, &log, None));
        assert_eq!(quiet.base_revision, first.screen_revision);
        assert_eq!(quiet.diff, "", "no bytes were fed between the two captures");
        assert!(!quiet.held_back);
        let unchanged = t.retained.back().expect("revision retained").2.clone();
        assert_eq!(
            apply(&base, &quiet.diff).screen().contents_formatted(),
            unchanged.contents_formatted(),
            "the empty diff did not replay to the current screen"
        );

        // The negative that separates "correct on the empty case" from
        // "always empty": one byte of change must produce a diff that
        // carries it.
        feed(&mut t, &mut log, t0, b" world");
        let moved = delta(t.capture(Some(quiet.screen_revision), true, t0, &log, None));
        assert_eq!(moved.base_revision, quiet.screen_revision);
        assert!(
            !moved.diff.is_empty(),
            "the screen changed and the diff was still empty"
        );
        let after = t.retained.back().expect("revision retained").2.clone();
        assert_eq!(
            apply(&unchanged, &moved.diff).screen().contents_formatted(),
            after.contents_formatted()
        );
    }
}
