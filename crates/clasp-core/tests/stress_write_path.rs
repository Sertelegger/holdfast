//! Spec §11.4: "with Tier B *off*, stream 1 MiB/s through 100 concurrent
//! sessions and assert control-protocol p99 stays under 500 ms — the
//! §4.2a measurement says Tier A scanning is nearly free, and this guards
//! against a regression that silently enables Tier B globally."
//!
//! This file is the regression guard for that sentence. It is deliberately
//! a test binary of its own: the per-session VT100 byte counters it reads
//! must not be perturbed by other tests running in the same process.

use clasp_core::pty::{PtyBackend, Signal};
use clasp_core::screen::{ScreenConfig, ScreenTracking};
use clasp_core::session::{new_session_id, Session, SessionConfig, SessionRegistry};
use clasp_core::{ClaspError, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SESSIONS: usize = 100;
const CHUNK: usize = 8 * 1024;
/// 128 chunks of 8 KiB per second is 1 MiB/s per session.
const CHUNK_INTERVAL: Duration = Duration::from_micros(7_812);
const RUN_FOR: Duration = Duration::from_secs(3);
const SAMPLE_INTERVAL: Duration = Duration::from_millis(5);
const P99_BUDGET: Duration = Duration::from_millis(500);
/// The ring buffer is deliberately small: this test is about the write
/// path, and a 1 MiB ring would spend the whole run memmoving evictions.
const BUFFER_BYTES: usize = 64 * 1024;

/// A shell at a readline prompt that then streams build output at a fixed
/// rate.
///
/// The preamble matters. It is the bracketed-paste pair a real shell emits
/// around a command, and it is what makes this a *line-oriented* session:
/// §4.5 turns Tier B on for a session that shows no deterministic prompt
/// signal at all, because there the cursor heuristic is the only evidence
/// left. Without the preamble this test would be measuring the wrong
/// scenario.
///
/// After that the stream carries SGR colour but no `\x1b[?1049h` and no
/// OSC 133, so nothing in it is a Tier-B trigger — while the Tier-A
/// scanner still has real escape sequences to walk.
struct StreamPty {
    preamble: Vec<u8>,
    preamble_sent: AtomicBool,
    pattern: Vec<u8>,
    offset: std::sync::Mutex<usize>,
    next_due: std::sync::Mutex<Instant>,
    alive: AtomicBool,
    produced: AtomicU64,
}

impl StreamPty {
    fn new(start: Instant) -> Self {
        let line = b"\x1b[2m[12:04:57]\x1b[0m \x1b[32m   Compiling\x1b[0m clasp-core v0.0.1 (/w/clasp)\r\n";
        let mut pattern = Vec::with_capacity(CHUNK * 2);
        while pattern.len() < CHUNK * 2 {
            pattern.extend_from_slice(line);
        }
        Self {
            preamble: b"\x1b[?2004h$ cargo build --release\x1b[?2004l\r\n".to_vec(),
            preamble_sent: AtomicBool::new(false),
            pattern,
            offset: std::sync::Mutex::new(0),
            next_due: std::sync::Mutex::new(start),
            alive: AtomicBool::new(true),
            produced: AtomicU64::new(0),
        }
    }

    fn stop(&self) {
        self.alive.store(false, Ordering::Relaxed);
    }

    fn produced(&self) -> u64 {
        self.produced.load(Ordering::Relaxed)
    }
}

impl PtyBackend for StreamPty {
    fn write(&self, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.alive.load(Ordering::Relaxed) {
            return Err(ClaspError::Pty("stream ended".into()));
        }
        if !self.preamble_sent.swap(true, Ordering::Relaxed) {
            // **Not on the very first read, and the delay is the point.**
            // `Session::new` starts the reader thread, and the caller calls
            // `set_screen_config` immediately afterwards — which replaces
            // the whole tracker, Tier-A probe included. A deterministic
            // signal landing in that window is latched by the tracker that
            // is about to be discarded, so the session looks signal-less
            // and §4.5 correctly enables Tier B three seconds later.
            // `Session::set_screen_config` documents the window and 0.0.4
            // accepts it: it is microseconds wide and no real shell has
            // printed a prompt that early. A fixture that emits its
            // bracketed paste on the reader's *first* call is the one thing
            // that can be inside it, which would make `parsed == 0` depend
            // on winning a race rather than on the property it guards. One
            // failure in roughly twenty-five whole-workspace runs was
            // observed before this sleep, under a mutation that cannot
            // reach this file; the other two assertions have 3.7x and 460x
            // margins, so this is the only one that can plausibly have
            // moved.
            std::thread::sleep(CHUNK_INTERVAL);
            let n = buf.len().min(self.preamble.len());
            buf[..n].copy_from_slice(&self.preamble[..n]);
            self.produced.fetch_add(n as u64, Ordering::Relaxed);
            return Ok(n);
        }
        // Pace to the target rate. Sleeping here is what the reader thread
        // of a real PTY does while waiting on the master fd.
        let sleep_for = {
            let mut due = self.next_due.lock().unwrap();
            let now = Instant::now();
            let wait = due.saturating_duration_since(now);
            *due = (*due + CHUNK_INTERVAL).max(now);
            wait
        };
        if !sleep_for.is_zero() {
            std::thread::sleep(sleep_for);
        }
        if !self.alive.load(Ordering::Relaxed) {
            return Err(ClaspError::Pty("stream ended".into()));
        }

        let n = buf.len().min(CHUNK);
        let mut offset = self.offset.lock().unwrap();
        for slot in buf.iter_mut().take(n) {
            *slot = self.pattern[*offset];
            *offset = (*offset + 1) % self.pattern.len();
        }
        drop(offset);
        self.produced.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }

    fn signal(&self, _sig: Signal) -> Result<()> {
        self.stop();
        Ok(())
    }

    fn resize(&self, _cols: u16, _rows: u16) -> Result<()> {
        Ok(())
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    fn exit_code(&self) -> Option<i32> {
        (!self.is_alive()).then_some(0)
    }

    fn pid(&self) -> Option<u32> {
        Some(1)
    }
}

/// The cheap read-only state snapshot every control-protocol method
/// begins with: resolve the session, read its state fields.
///
/// Milestone 0.0.5 replaces this with a round trip over the real control
/// socket; the assertion it feeds does not change.
fn control_snapshot(registry: &SessionRegistry, id: &str) {
    let session = registry.get(id).expect("session present");
    let _ = session.state();
    let _ = session.buffer_head();
    let _ = session.buffer_tail();
    let _ = session.last_activity_ms();
    let _ = session.screen_tracking();
}

fn percentile(sorted: &[Duration], pct: f64) -> Duration {
    let idx = ((sorted.len() as f64 * pct).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

#[test]
fn tier_b_stays_off_and_the_control_path_stays_responsive_under_load() {
    let registry = SessionRegistry::new(SESSIONS + 8);
    let start = Instant::now();
    let mut ptys = Vec::with_capacity(SESSIONS);
    let mut ids = Vec::with_capacity(SESSIONS);

    for _ in 0..SESSIONS {
        let pty = Arc::new(StreamPty::new(start));
        // `SessionConfig`, not a bare `usize` — 0.0.2 collapsed the
        // constructor's tail arguments into it.
        let session = Session::new(
            new_session_id(),
            None,
            "build".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(BUFFER_BYTES),
        );
        session.set_screen_config(ScreenConfig {
            // The shipped default. Forcing this to `On` is what this test
            // is here to catch; see the plan's regression-guard note.
            mode: ScreenTracking::Adaptive,
            rows: 24,
            cols: 80,
            ..ScreenConfig::default()
        });
        ids.push(session.id.clone());
        registry.insert(session).expect("registry insert");
        ptys.push(pty);
    }

    let mut samples: Vec<Duration> = Vec::new();
    let deadline = Instant::now() + RUN_FOR;
    let mut next = 0usize;
    while Instant::now() < deadline {
        let id = &ids[next % SESSIONS];
        next += 1;
        let t = Instant::now();
        control_snapshot(&registry, id);
        samples.push(t.elapsed());
        std::thread::sleep(SAMPLE_INTERVAL);
    }

    for pty in &ptys {
        pty.stop();
    }

    // The load has to have actually happened, or every assertion below is
    // vacuous. Allow generous slack for scheduling on a busy CI box.
    let produced: u64 = ptys.iter().map(|p| p.produced()).sum();
    let nominal = (SESSIONS as u64) * (RUN_FOR.as_secs()) * 1024 * 1024;
    assert!(
        produced >= nominal / 2,
        "only {produced} bytes streamed against a {nominal} byte target — \
         the load never materialised, so this test proves nothing"
    );

    // The guard. A change that enables Tier B globally trips here
    // immediately and deterministically, on any machine.
    let parsed: u64 = registry.all().iter().map(|s| s.vt100_bytes_parsed()).sum();
    assert_eq!(
        parsed, 0,
        "Tier B parsed {parsed} bytes across {SESSIONS} line-oriented sessions; \
         §4.2a measured full VT100 emulation at ~86 MB/s, so at this load it \
         costs more than a core before any other work happens"
    );
    for session in registry.all() {
        assert_eq!(session.screen_tracking(), "off", "{}", session.id);
    }

    assert!(!samples.is_empty(), "no control-path samples were taken");
    samples.sort_unstable();
    let p99 = percentile(&samples, 0.99);
    assert!(
        p99 < P99_BUDGET,
        "control-path p99 was {p99:?}, over the {P99_BUDGET:?} budget \
         (max {:?}, {} samples, {produced} bytes streamed)",
        samples.last().unwrap(),
        samples.len()
    );
}
