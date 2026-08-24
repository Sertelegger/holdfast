//! The per-session secret slot and its three states (§5.2, REQ-SEC-010a).
//!
//! 0.0.6's slot had two: **vacant**, and **raised with nobody waiting** —
//! an echo drop that a human at an attached client may or may not answer.
//! 0.0.7 adds the third, **raised with a tool call waiting on it**, and
//! every transition out of it.
//!
//! ## What a waiting caller can learn
//!
//! [`Resolution`] carries a **count**, never bytes. That is the type-level
//! half of "the value never crosses the MCP wire": the tool's response is
//! built from this, so there is no field anywhere on that path capable of
//! holding the secret. §9.2 marks the value `n/a` for redaction precisely
//! because it reaches no boundary a redactor could run at — the protection
//! has to be structural or it does not exist.
//!
//! ## Adoption is the ordinary case
//!
//! REQ-SEC-010a: the `request_id` is allocated by whichever **raise**
//! comes first — the echo drop (§8.3) or the tool call. A call arriving
//! at a slot that is already raised with no waiter **adopts** it: same
//! id, no second broadcast, and *the stored `prompt_text` is not
//! touched*. Rewriting it would show two clients two different prompts
//! for one request, and would let an agent relabel a prompt a human may
//! already be typing into. §16.4 steps 3–7 are an adoption end to end.
//!
//! `concurrent_request_pending` is a **second-caller** condition, not a
//! "slot occupied" condition. Conflating the two passes a collision test
//! perfectly and breaks the ordinary flow.

use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::attach::secret::SecretRequest;

/// §9.5's buffer notice — escalation **rung 3**, which §7.8.3 calls *"the
/// terminal rung, the only one that requires nothing to be configured or
/// installed"*. The one thing Holdfast does when a session blocks and
/// nobody is looking.
///
/// **The bytes are §5.2's, verbatim.** §9.5 gives the same string hedged
/// with *"e.g."*, so §5.2 is the binding site; the two are identical, em
/// dash included.
///
/// **This line is not ASCII.** The separator is a spaced U+2014 em dash,
/// so `" — "` is **five** bytes (`20 E2 80 94 20`). Anything that
/// measures, truncates or slices this line works in bytes and must not
/// cut inside those three.
///
/// `<id>` is the **canonical session id** (`sess_…`), never the name —
/// the name is optional and the notice has to work for a session that has
/// none. Terminated with `\r\n`, because it lands in a raw PTY byte
/// stream that attached terminals render without translation.
pub fn buffer_notice(session_id: &str) -> Vec<u8> {
    format!(
        "[holdfast] awaiting secret input — run 'holdfast attach {session_id}' \
         or open the web UI\r\n"
    )
    .into_bytes()
}

/// How the request a call is bound to came into existence (§9.4).
///
/// **A property of the request, not of the call.** A second caller that
/// collides reports whatever raised the request it collided with, which
/// is what lets an operator see that a call adopted a request it did not
/// raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaisedBy {
    /// §8.3's termios `ECHO` drop. Never a password-prompt pattern list:
    /// `ECHO` is what distinguishes a real secret prompt from output that
    /// merely ends in `Password:`.
    EchoDrop,
    /// A `request_secret_input` call on a vacant slot.
    ToolCall,
}

impl RaisedBy {
    /// The §9.4 wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EchoDrop => "echo_drop",
            Self::ToolCall => "tool_call",
        }
    }
}

/// Why a raised request ended without a value (§5.2, §18.1).
///
/// Each variant has exactly one producer, and Task 4's
/// `every_secret_cancelled_reason_is_reachable` drives all four in one
/// run against an exhaustive match over this enum — so a variant added
/// later fails to compile until something emits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CancelReason {
    /// The echo-off condition cleared with no value written: a human
    /// aborting at an attached client, or the child abandoning its read.
    /// §7.5's client-frame catalogue carries no cancellation frame, so
    /// this signal is the only one there is.
    UserCancelled,
    /// The waiting call's own `timeout_secs` elapsed.
    Timeout,
    /// The submitted bytes exceeded the call's `max_secret_bytes`.
    TooLarge,
    /// A second call arrived while this session's request already had a
    /// tool call waiting on it. **The first caller's request is
    /// untouched.**
    ConcurrentRequestPending,
}

impl CancelReason {
    /// The §18.1 / §9.4 wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserCancelled => "user_cancelled",
            Self::Timeout => "timeout",
            Self::TooLarge => "too_large",
            Self::ConcurrentRequestPending => "concurrent_request_pending",
        }
    }

    /// Every reason, for the exhaustive-reachability guard.
    pub const ALL: [CancelReason; 4] = [
        Self::UserCancelled,
        Self::Timeout,
        Self::TooLarge,
        Self::ConcurrentRequestPending,
    ];
}

/// What a waiting call learns.
///
/// **A count, never bytes.** See the module header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Written to the PTY. `bytes_written` is post-normalisation and
    /// includes the appended `\n` when `append_newline`.
    Provided {
        bytes_written: u64,
    },
    Cancelled(CancelReason),
    /// The session exited while the call was waiting (§5.1).
    SessionDied {
        exit_code: Option<i32>,
    },
}

/// The answer to a call that arrived at a slot with somebody already
/// waiting on it.
///
/// Carries the **first** caller's identity, because that is what §9.4
/// records: the colliding call is bound to the request it collided with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collision {
    pub request_id: String,
    pub raised_by: RaisedBy,
}

/// A successful `raise_or_adopt`.
#[derive(Debug)]
pub struct Adopted {
    pub request_id: String,
    /// **The raise's**, not the call's. `EchoDrop` here means this call
    /// adopted a request a human was already being asked to answer.
    pub raised_by: RaisedBy,
    /// The prompt text the request is *actually* carrying — the raised
    /// one, which an adopting call does not replace.
    pub prompt_text: String,
    /// `true` when this call allocated the id, and therefore the only
    /// caller that broadcasts `AwaitingSecret`.
    pub raised_here: bool,
    pub rx: oneshot::Receiver<Resolution>,
}

/// One raised request: 0.0.6's `SecretRequest`, plus everything a
/// waiting caller adds.
#[derive(Debug)]
pub struct RaisedRequest {
    /// `request_id` + the redacted prompt the request was **raised**
    /// with. Never rewritten by an adopting call.
    pub request: SecretRequest,
    pub raised_by: RaisedBy,
    /// §9.5's buffer notice, at most once per request (Task 7).
    pub notice_written: bool,
    /// The waiting call's cap on the **received** `SecretInput.bytes`
    /// length, pre-normalisation. `None` when nobody is waiting: a human
    /// answering an unadopted echo-drop request has no tool argument to
    /// be bounded by.
    pub max_secret_bytes: Option<u32>,
    /// The waiting call's `append_newline`. `true` with no waiter,
    /// because an echo-off prompt is waiting for a line.
    pub append_newline: bool,
    waiter: Option<oneshot::Sender<Resolution>>,
}

impl RaisedRequest {
    pub fn request_id(&self) -> &str {
        &self.request.request_id
    }

    pub fn has_waiter(&self) -> bool {
        self.waiter.is_some()
    }

    /// Answer the waiting call, if there is one.
    ///
    /// Consumes, because a request that has been answered is over: a
    /// second answer to one call is a second MCP response, which the
    /// `oneshot` makes impossible to express rather than merely wrong.
    /// A send that fails means the caller went away, which is not an
    /// error.
    pub fn answer(self, outcome: Resolution) {
        if let Some(tx) = self.waiter {
            let _ = tx.send(outcome);
        }
    }
}

/// What [`SecretSlots::take_if_unadopted_matching`] found.
///
/// **Three, because the §9.6 autofill's decision needs three.** An
/// `Option` collapses *"nothing is outstanding"* and *"something is
/// outstanding that is not yours"* into one `None`, and those two require
/// opposite actions from the one caller that is about to write a
/// credential into a PTY: write, and do not write.
#[derive(Debug)]
pub enum SlotTake {
    /// The slot held an unadopted request and had not changed since the
    /// caller's snapshot, so the caller now owns it.
    Taken(RaisedRequest),
    /// Nothing is outstanding for this session.
    Vacant,
    /// Something is outstanding and it is not the caller's to take — a
    /// call is waiting on it — or the slot has been through a request
    /// since the caller looked.
    NotYours,
}

/// What a caller saw at the slot before it went away, and the thing its
/// write is made conditional on (GH #35).
///
/// **One field, and it is a count of closures rather than an id.** An id
/// says *which* request the caller was going to satisfy, and cannot see a
/// raise that both appeared and was answered inside the window — that
/// leaves the slot vacant again, which is byte-for-byte what "nothing ever
/// happened" looks like, and it is exactly the sequence an anticipatory
/// `request_secret_input` right after `start_session` produces. The count
/// sees it, and it subsumes the id besides: a *different* request cannot be
/// in the slot without the first having been closed, which ticks it.
///
/// **Constructed only by [`SecretSlots::snapshot`]**, under the lock. That
/// is not tidiness — it is what makes the reasoning above sound. A snapshot
/// a caller could assemble from separate reads, or write a field of, could
/// describe a state the slot cannot be in, and every argument here is about
/// states the slot *can* reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SlotSnapshot {
    /// How many requests this session's slot had closed by then.
    closed: u64,
}

/// The slot map and its closure counter, in a module of their own.
///
/// **The point of the module is the field privacy.** `requests` is private
/// to `slots`, so a `requests.remove(..)` written anywhere else in this
/// 1300-line file does not compile — and inside the module there is exactly
/// one, in [`Slots::close`]. Without that boundary the "one removal site"
/// property is a convention a future edit can break silently, and breaking
/// it silently reopens GH #35.
///
/// What it does **not** guarantee: that every *caller* routes through
/// `SecretSlots`. Nothing outside this file can construct a `Slots` at all,
/// so that is not a hole so much as the same statement one level out.
mod slots {
    use std::collections::HashMap;

    use super::RaisedRequest;

    #[derive(Default, Debug)]
    pub(super) struct Slots {
        requests: HashMap<String, RaisedRequest>,
        /// Per session, monotonic, and **never removed** — see
        /// [`super::SecretSlots::snapshot`].
        closed: HashMap<String, u64>,
    }

    impl Slots {
        pub(super) fn get(&self, session_id: &str) -> Option<&RaisedRequest> {
            self.requests.get(session_id)
        }

        pub(super) fn get_mut(&mut self, session_id: &str) -> Option<&mut RaisedRequest> {
            self.requests.get_mut(session_id)
        }

        /// Put a request into a slot the caller has already found vacant.
        ///
        /// **Vacant, and the `debug_assert` is the whole reason this is not
        /// a bare `insert`.** An insert over an existing entry would drop a
        /// `RaisedRequest` — its waiter unanswered — without going through
        /// [`close`](Self::close), so the count would not move and GH #35's
        /// check would be answering about a slot that had silently changed.
        /// Both callers test vacancy under this same lock.
        pub(super) fn insert_vacant(&mut self, session_id: &str, raised: RaisedRequest) {
            debug_assert!(
                !self.requests.contains_key(session_id),
                "insert_vacant over an occupied slot drops a request without counting it"
            );
            self.requests.insert(session_id.to_string(), raised);
        }

        /// Every session holding a raise with no call waiting on it.
        ///
        /// A method rather than an `iter()`, so `requests` stays inside.
        pub(super) fn unadopted(&self) -> Vec<String> {
            self.requests
                .iter()
                .filter(|(_, raised)| !raised.has_waiter())
                .map(|(session_id, _)| session_id.clone())
                .collect()
        }

        /// **The one removal site**, and the only place the count moves.
        pub(super) fn close(&mut self, session_id: &str) -> Option<RaisedRequest> {
            let raised = self.requests.remove(session_id)?;
            *self.closed.entry(session_id.to_string()).or_insert(0) += 1;
            Some(raised)
        }

        pub(super) fn closed(&self, session_id: &str) -> u64 {
            self.closed.get(session_id).copied().unwrap_or(0)
        }
    }
}

use slots::Slots;

/// Every session's slot. **Vacant is absence from the map**, so there is
/// no third state to keep consistent with the other two.
#[derive(Default, Debug)]
pub struct SecretSlots {
    inner: Mutex<Slots>,
}

impl SecretSlots {
    pub fn new() -> Self {
        Self::default()
    }

    /// 0.0.6's raise: allocate if vacant, otherwise hand back what is
    /// already there.
    ///
    /// **Idempotent, and that is what makes one `request_id` reach every
    /// client.** Every connection sees the same `AwaitingSecretEntered`
    /// event and every one of them calls this; the first allocates and
    /// the rest get the same request back, so the frames they send agree
    /// without any of them coordinating.
    ///
    /// The `bool` is `true` for the caller that allocated.
    pub fn raise(
        &self,
        session_id: &str,
        prompt_text: &str,
        raised_by: RaisedBy,
    ) -> (SecretRequest, bool) {
        let mut slots = self.inner.lock();
        match slots.get(session_id) {
            Some(existing) => (existing.request.clone(), false),
            None => {
                let request = SecretRequest::new(prompt_text.to_string());
                slots.insert_vacant(
                    session_id,
                    RaisedRequest {
                        request: request.clone(),
                        raised_by,
                        notice_written: false,
                        max_secret_bytes: None,
                        append_newline: true,
                        waiter: None,
                    },
                );
                (request, true)
            }
        }
    }

    /// The **only** entry point a tool call uses (REQ-SEC-010a).
    ///
    /// Takes a session and the call's own `prompt_text`; **never a
    /// `request_id`** — the id is returned to the agent and never
    /// accepted from it. Three behaviours, one per slot state:
    ///
    /// | Slot on entry | Behaviour | `raised_by` reported |
    /// |---|---|---|
    /// | vacant | **Raise.** Allocate, store this call's text, register the waiter | `tool_call` |
    /// | raised, no waiter | **Adopt.** Register the waiter on the existing request. No new id, no second broadcast, **stored text untouched** | the raise's |
    /// | raised, waiter | **Collide.** The first caller's request is untouched: no close, no slot change, no deadline reset | the first caller's |
    pub fn raise_or_adopt(
        &self,
        session_id: &str,
        prompt_text: &str,
        max_secret_bytes: Option<u32>,
        append_newline: bool,
    ) -> Result<Adopted, Collision> {
        let mut slots = self.inner.lock();
        let (tx, rx) = oneshot::channel();
        match slots.get_mut(session_id) {
            // Collide. Note the condition: a waiter, **not** an occupied
            // slot. Treating "occupied" as the collision condition passes
            // every collision test and breaks §16.4's ordinary flow.
            Some(raised) if raised.has_waiter() => Err(Collision {
                request_id: raised.request.request_id.clone(),
                raised_by: raised.raised_by,
            }),
            // Adopt. The call's `prompt_text` is not written anywhere
            // here; §9.4 logs it and no client is shown it.
            Some(raised) => {
                raised.waiter = Some(tx);
                raised.max_secret_bytes = max_secret_bytes;
                raised.append_newline = append_newline;
                Ok(Adopted {
                    request_id: raised.request.request_id.clone(),
                    raised_by: raised.raised_by,
                    prompt_text: raised.request.prompt_text.clone(),
                    raised_here: false,
                    rx,
                })
            }
            // Raise.
            None => {
                let request = SecretRequest::new(prompt_text.to_string());
                let id = request.request_id.clone();
                slots.insert_vacant(
                    session_id,
                    RaisedRequest {
                        request,
                        raised_by: RaisedBy::ToolCall,
                        notice_written: false,
                        max_secret_bytes,
                        append_newline,
                        waiter: Some(tx),
                    },
                );
                Ok(Adopted {
                    request_id: id,
                    raised_by: RaisedBy::ToolCall,
                    prompt_text: prompt_text.to_string(),
                    raised_here: true,
                    rx,
                })
            }
        }
    }

    /// The session's outstanding request, if any.
    pub fn outstanding(&self, session_id: &str) -> Option<SecretRequest> {
        self.inner.lock().get(session_id).map(|r| r.request.clone())
    }

    /// The slot's state, for a caller that is about to go away and come
    /// back — §9.6's autofill, and nothing else (GH #35).
    ///
    /// **Both fields under one lock**, so the id and the closure count
    /// cannot describe two different moments. Hand the result back to
    /// [`take_if_unadopted_matching`](Self::take_if_unadopted_matching);
    /// there is nothing else to do with it.
    ///
    /// **The count is never removed, and that is the point.** An entry
    /// here is one `u64` for a session that has had a secret request
    /// closed, and sweeping it on session exit would reset the generation
    /// to zero — after which a snapshot taken before the sweep matches
    /// again and the hole this closes is open once more. It is bounded by
    /// the same set the registry already retains: §4.1 keeps an exited
    /// session in the registry, so a per-session `u64` beside it adds no
    /// lifetime that was not already there.
    pub(crate) fn snapshot(&self, session_id: &str) -> SlotSnapshot {
        SlotSnapshot {
            closed: self.inner.lock().closed(session_id),
        }
    }

    /// The call's `max_secret_bytes` and `append_newline`, as the
    /// submitting connection needs them.
    ///
    /// `None` when the id names no outstanding request — which the
    /// caller must already have established through
    /// [`matches_outstanding`](Self::matches_outstanding).
    pub fn submission_bounds(
        &self,
        session_id: &str,
        request_id: &str,
    ) -> Option<(Option<u32>, bool)> {
        let slots = self.inner.lock();
        let raised = slots.get(session_id)?;
        (raised.request.request_id == request_id)
            .then_some((raised.max_secret_bytes, raised.append_newline))
    }

    /// **The single authority on "does this `request_id` name the
    /// session's current outstanding request?"**
    ///
    /// The attach handler answers a `false` with
    /// `ProtocolError { reason: "unknown_request_id" }`; 0.0.10's
    /// `POST /api/sessions/:id/secret` answers it with `409 conflict`
    /// (§18.5). **Two renderings, one check** — 0.0.10 calls this and
    /// does not re-implement it, which is the whole reason it is a named
    /// function rather than a comparison inlined in a frame handler.
    ///
    /// **The plan for this milestone said to rewire the attach handler's
    /// `unknown_request_id` branch through this function, and doing so
    /// would open a race the branch was written to avoid.** That branch
    /// closes the request *and* decides who fulfils it in one atomic
    /// step, because two clients answering the same prompt must produce
    /// one write; a `matches_outstanding` check followed by a `take` is
    /// exactly the check-then-clear both could pass. So the attach path
    /// keeps [`take`](Self::take)'s `expect_id`, which **is** this
    /// predicate evaluated under the lock that acts on it, and
    /// `the_two_renderings_of_the_id_check_agree` pins the two to the
    /// same answer. 0.0.10's HTTP path has no atomic action to fuse —
    /// it validates, then forwards — so it calls this one.
    /// Whether this session's request already has a tool call waiting on
    /// it — the exact condition that makes a further call collide.
    ///
    /// **Read-only, and that is the whole point.** The obvious way to ask
    /// this from outside is to try `raise_or_adopt` and look at the
    /// result, and that *adopts*: a poller written that way registers a
    /// waiter of its own, steals the slot from the call it was waiting
    /// for, and turns the thing it was observing into something else.
    /// Measured — it took two tests down on their first run.
    pub fn has_waiter(&self, session_id: &str) -> bool {
        self.inner
            .lock()
            .get(session_id)
            .is_some_and(|r| r.has_waiter())
    }

    pub fn matches_outstanding(&self, session_id: &str, request_id: &str) -> bool {
        self.inner
            .lock()
            .get(session_id)
            .is_some_and(|r| r.request.request_id == request_id)
    }

    /// Take the request out of the slot, whole — **including the waiting
    /// caller's channel** — and only for the caller that actually cleared
    /// it.
    ///
    /// `expect_id` is `Some` for a fulfilment, which must not close a
    /// request that has already been replaced by a later one, and `None`
    /// for the supersede path. Either way exactly one caller gets a
    /// `Some`, so exactly one close fan-out happens even though every
    /// connection tries.
    ///
    /// It hands back the whole [`RaisedRequest`] rather than answering
    /// the waiter itself because the answer is not always known yet: the
    /// fulfilment path has to clear the slot **before** it queues the
    /// write (or two clients answering one prompt produce two writes),
    /// and only learns `bytes_written` afterwards.
    pub fn take(&self, session_id: &str, expect_id: Option<&str>) -> Option<RaisedRequest> {
        let mut slots = self.inner.lock();
        match slots.get(session_id) {
            Some(raised) if expect_id.is_none_or(|id| id == raised.request.request_id) => {
                slots.close(session_id)
            }
            _ => None,
        }
    }

    /// The race in Step 4, and the one place this design can lose a
    /// value.
    ///
    /// A waiting call **must not** `select!` a timer against its receiver
    /// and drop the receiver on expiry: a `SecretInput` that lands in
    /// that window is written to the PTY and the agent is told `timeout`.
    /// So the timer does not decide anything. It asks *here*, under the
    /// same lock every other transition takes:
    ///
    /// * `Some(raised)` — the slot was still ours. We really did time
    ///   out, and we now own the close.
    /// * `None` — somebody resolved it between the timer firing and this
    ///   lock. Their answer is already on our receiver; read it and
    ///   report the truth rather than the timer.
    pub fn close_on_caller_timeout(
        &self,
        session_id: &str,
        request_id: &str,
    ) -> Option<RaisedRequest> {
        self.take(session_id, Some(request_id))
    }

    /// Every session holding a raise with **no call waiting on it** —
    /// the only slots a third party is allowed to release (GH #24).
    ///
    /// **A query rather than a sweep taking a predicate**, and the reason
    /// is lock order. The predicate the one caller needs — *is this
    /// session over?* — reads the [`crate::session::SessionRegistry`],
    /// and evaluating it under this mutex would put the slot lock ahead
    /// of the registry's `RwLock` on one path and behind it on none.
    /// Two short critical sections instead, and
    /// [`take_if_unadopted`](Self::take_if_unadopted) re-tests under the
    /// lock that acts, so a call adopting between the two loses nothing.
    pub fn unadopted_sessions(&self) -> Vec<String> {
        self.inner.lock().unadopted()
    }

    /// Take the slot, **but only while nothing is waiting on it**.
    ///
    /// The waiterless test and the removal are one critical section, and
    /// that is the whole of this function. §5.1's `session_died` is sited
    /// in the waiting caller — `await_secret` owns the close through
    /// [`close_on_caller_timeout`](Self::close_on_caller_timeout) — so a
    /// janitor able to take an *adopted* slot would leave that caller in
    /// its handover grace and then report `timeout` for a session that
    /// died. That is the defect `a2b747f` fixed, re-entering from the
    /// other side, and a check-then-`take` outside the lock is exactly
    /// the race that lets it.
    ///
    /// **This is the second of two copies of that predicate, not "the"
    /// guard, and the distinction is load-bearing when reading a mutation
    /// result.** The sweep's only caller reaches it through
    /// [`unadopted_sessions`](Self::unadopted_sessions), whose filter
    /// applies the same test one lock acquisition earlier. Deleting
    /// *either* copy alone leaves the daemon-level rows green — the other
    /// still stops the sweep — and only the unit row
    /// `only_a_slot_with_nobody_waiting_is_a_third_partys_to_take` fails,
    /// because it exercises both entry points directly. Measured; see
    /// that row and the comment in
    /// `a_call_waiting_on_a_dying_session_still_owns_its_own_session_died`.
    ///
    /// The duplication is deliberate and stays: the filter is a *query*
    /// and cannot be atomic with the action, so this re-test under the
    /// acting lock is what closes the window in which a call adopts
    /// between the two.
    ///
    /// **No `expect_id`, unlike [`take`](Self::take).** The caller here
    /// holds no id: it arrives at the slot from the session, not from a
    /// request, and any request it finds unadopted is by definition the
    /// current one. What it must not do is take an id somebody is
    /// waiting on, and that is the condition this checks.
    pub fn take_if_unadopted(&self, session_id: &str) -> Option<RaisedRequest> {
        let mut slots = self.inner.lock();
        match slots.get(session_id) {
            Some(raised) if !raised.has_waiter() => slots.close(session_id),
            _ => None,
        }
    }

    /// [`take_if_unadopted`](Self::take_if_unadopted) for a caller that
    /// **went away and came back** — §9.6's autofill, and nothing else.
    ///
    /// The autofill path is the one caller that reads the slot, then goes
    /// away for as long as `keychain_provider_timeout_secs` (default 10 s)
    /// while a credential store answers, and only then acts. Two things can
    /// change under it in that window, and `take_if_unadopted`'s `None`
    /// cannot tell them from "nothing was ever there":
    ///
    /// * a human at an attached client **answered** the raise while the
    ///   provider ran — `attach::conn`'s `SecretInput` arm reaches the slot
    ///   through `take(session_id, Some(&request_id))`, which requires only
    ///   a matching id and **not** the absence of a waiter, so it wins the
    ///   race outright;
    /// * another tool call **adopted** it.
    ///
    /// Writing anyway in the first case puts **two values into one
    /// `getpass`**: the human's is consumed and the resolved one is left in
    /// the tty input queue for whatever the child reads next — for a shell,
    /// a credential executed as a command and echoed into the ring buffer.
    /// That is the failure §9 exists to prevent, so the autofill has to be
    /// able to say *"the slot I am about to satisfy is still the slot I
    /// left"*, and [`SlotSnapshot`] is how it says it.
    ///
    /// **Three outcomes and not two**, because the caller's decision needs
    /// all three and an `Option` collapses two of them: *"nothing is
    /// outstanding"* and *"something is outstanding that is not yours"*
    /// require opposite actions from the one caller that is about to write
    /// a credential into a PTY.
    ///
    /// ## The two conditions, and why they are not one
    ///
    /// **The closure count** (GH #35) sees a raise that both **appeared and
    /// was answered** inside the window, starting from a vacant slot. That
    /// leaves the slot vacant again, which is byte-for-byte what "nothing
    /// ever happened" looks like — reproduced with a probe before the count
    /// existed as `secret_provided`, 8 bytes written, and the child's `got=`
    /// count **2**. **A re-check of "is the slot still vacant" is not
    /// sufficient, and that is the whole reason a count exists**:
    /// raise-then-answer returns the slot to vacant, so the re-check passes.
    /// The condition is that the slot is *in the state the decision was
    /// taken against*.
    ///
    /// It is not exotic: `start_session("ssh prod-01")` followed
    /// immediately by `request_secret_input`, before the prompt has been
    /// drawn, is exactly that shape, and it is the obvious thing for an
    /// agent that knows what it just started.
    ///
    /// **The count is closures, not raises, and the difference is a
    /// behaviour rather than a detail.** A raise that appeared inside the
    /// window and is *still outstanding* is unanswered, and is this value's
    /// to close — the ordinary anticipatory case working. A counter that
    /// ticked on raises would refuse it, drop a resolved credential, and
    /// prompt a human who did not need to be asked.
    ///
    /// **The waiter test** sees the thing the count cannot: an **adoption**
    /// closes nothing, so the count does not move. Each condition has a
    /// unit row that isolates it, and neither is evidence for the other.
    ///
    /// **There is deliberately no id comparison.** One was written and
    /// removed: `SlotSnapshot`'s field is private and `snapshot` is its only
    /// constructor, so a *different* request cannot be in the slot without
    /// the first having been closed — which ticks the count and refuses
    /// first, every time. The comparison could not fire, and the row that
    /// appeared to guard it only did so by writing a private field to
    /// fabricate a state `snapshot` cannot produce. A dead branch kept alive
    /// by a test that reaches around the type is worse than no branch.
    ///
    /// ## What it still cannot see
    ///
    /// **Everything here observes `SecretSlots`.** The child's read can be
    /// satisfied by routes that touch no slot at all — an MCP `send_input`,
    /// ordinary typing at an attached terminal, or the child abandoning the
    /// read — and with **nobody attached** none of those produces a raise,
    /// so nothing ticks. `mcp::tools::HoldfastServer::inject_resolved`
    /// consults `Session::is_awaiting_secret` for exactly that reason; the
    /// argument is at that call site.
    pub(crate) fn take_if_unadopted_matching(
        &self,
        session_id: &str,
        expect: &SlotSnapshot,
    ) -> SlotTake {
        let mut slots = self.inner.lock();
        // Evaluated on the request that is *there*, before the count, so
        // that a row driving one condition is not answered by the other.
        if slots
            .get(session_id)
            .is_some_and(|raised| raised.has_waiter())
        {
            return SlotTake::NotYours;
        }
        if slots.closed(session_id) != expect.closed {
            return SlotTake::NotYours;
        }
        match slots.close(session_id) {
            Some(raised) => SlotTake::Taken(raised),
            // Nothing there, and nothing has been closed since the
            // snapshot — so nothing happened, and this value is the only
            // one the child will receive.
            None => SlotTake::Vacant,
        }
    }

    /// Mark §9.5's buffer notice written, returning `true` for the caller
    /// that flipped it (Task 7). At most one notice per request.
    pub fn claim_notice(&self, session_id: &str, request_id: &str) -> bool {
        let mut slots = self.inner.lock();
        match slots.get_mut(session_id) {
            Some(raised) if raised.request.request_id == request_id && !raised.notice_written => {
                raised.notice_written = true;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "sess_1";

    #[test]
    fn a_vacant_slot_is_raised_by_the_call_that_finds_it() {
        let slots = SecretSlots::new();
        let a = slots
            .raise_or_adopt(S, "sudo password", Some(4096), true)
            .expect("a vacant slot raises");
        assert!(a.request_id.starts_with("secreq_"), "{}", a.request_id);
        assert_eq!(a.raised_by, RaisedBy::ToolCall);
        assert!(a.raised_here, "the raising call is the one that broadcasts");
        assert_eq!(a.prompt_text, "sudo password");
        assert!(slots.matches_outstanding(S, &a.request_id));
    }

    #[test]
    fn a_call_adopts_an_echo_raised_request_and_leaves_its_prompt_alone() {
        let slots = SecretSlots::new();
        let (raised, first) = slots.raise(S, "[sudo] password for ada:", RaisedBy::EchoDrop);
        assert!(first);

        let a = slots
            .raise_or_adopt(S, "a completely different label", Some(16), false)
            .expect("a raised slot with no waiter is adopted, not refused");
        assert_eq!(
            a.request_id, raised.request_id,
            "adoption must not allocate a second id for one request"
        );
        assert_eq!(
            a.raised_by,
            RaisedBy::EchoDrop,
            "raised_by is the request's"
        );
        assert!(
            !a.raised_here,
            "an adopting call must not broadcast a second AwaitingSecret"
        );
        assert_eq!(
            a.prompt_text, "[sudo] password for ada:",
            "the adopting call rewrote the prompt a human may already be typing into"
        );
        // And the stored text is the raised one, which is what a client
        // attaching later replays.
        assert_eq!(
            slots.outstanding(S).expect("still outstanding").prompt_text,
            "[sudo] password for ada:"
        );
    }

    #[test]
    fn the_collision_is_a_second_caller_not_a_second_request() {
        let slots = SecretSlots::new();
        // The pairing first: an occupied slot with **no** waiter adopts.
        slots.raise(S, "p", RaisedBy::EchoDrop);
        let first = slots
            .raise_or_adopt(S, "p", None, true)
            .expect("occupied-with-no-waiter must adopt");

        // Only now, with a waiter registered, does a second call collide.
        let c = slots
            .raise_or_adopt(S, "p", None, true)
            .expect_err("a second caller on a request that already has one must collide");
        assert_eq!(c.request_id, first.request_id);
        assert_eq!(c.raised_by, RaisedBy::EchoDrop, "the *first* caller's");

        // The first caller's request is untouched: still outstanding,
        // same id, and its receiver has not been resolved.
        assert!(slots.matches_outstanding(S, &first.request_id));
        let mut rx = first.rx;
        assert!(
            rx.try_recv().is_err(),
            "the collision resolved the first caller's request"
        );
    }

    #[test]
    fn taking_the_slot_hands_over_the_waiter_exactly_once() {
        let slots = SecretSlots::new();
        let mut a = slots.raise_or_adopt(S, "p", None, true).expect("raise");
        let taken = slots.take(S, Some(&a.request_id)).expect("first take wins");
        assert!(taken.has_waiter());
        assert!(
            slots.take(S, Some(&a.request_id)).is_none(),
            "two clients answering one prompt must produce one write, not two"
        );
        taken.answer(Resolution::Provided { bytes_written: 8 });
        assert_eq!(
            a.rx.try_recv().expect("the waiter was answered"),
            Resolution::Provided { bytes_written: 8 }
        );
    }

    #[test]
    fn a_take_naming_the_wrong_id_clears_nothing() {
        let slots = SecretSlots::new();
        let a = slots.raise_or_adopt(S, "p", None, true).expect("raise");
        assert!(
            slots.take(S, Some("secreq_notours")).is_none(),
            "a superseded client's keystrokes must not close whatever came next"
        );
        // The pairing: the correct id still works immediately afterwards,
        // which is what proves the wrong one was refused rather than the
        // slot being empty all along.
        assert!(slots.take(S, Some(&a.request_id)).is_some());
    }

    #[test]
    fn close_on_caller_timeout_reports_the_truth_rather_than_the_timer() {
        let slots = SecretSlots::new();
        let a = slots.raise_or_adopt(S, "p", None, true).expect("raise");
        // Somebody resolved it between the timer firing and the lock.
        let winner = slots.take(S, Some(&a.request_id)).expect("resolver wins");
        assert!(
            slots.close_on_caller_timeout(S, &a.request_id).is_none(),
            "the timer took a slot somebody else had already taken — the value would \
             be written to the PTY and the agent told `timeout`"
        );
        winner.answer(Resolution::Provided { bytes_written: 3 });

        // And the other way: nothing resolved it, so the timer owns it.
        let b = slots
            .raise_or_adopt(S, "p", None, true)
            .expect("raise again");
        assert!(slots.close_on_caller_timeout(S, &b.request_id).is_some());
    }

    /// The read-only predicate and the atomic one must not be able to
    /// disagree — that is what makes it honest to call them one check.
    #[test]
    fn the_two_renderings_of_the_id_check_agree() {
        for (label, expect) in [("the outstanding id", true), ("secreq_notours", false)] {
            let slots = SecretSlots::new();
            let a = slots.raise_or_adopt(S, "p", None, true).expect("raise");
            let id = if expect {
                a.request_id.clone()
            } else {
                label.to_string()
            };
            assert_eq!(
                slots.matches_outstanding(S, &id),
                expect,
                "the read-only rendering disagreed for {label}"
            );
            assert_eq!(
                slots.take(S, Some(&id)).is_some(),
                expect,
                "the atomic rendering disagreed for {label}"
            );
        }
        // And on a session with no request at all, both say no.
        let empty = SecretSlots::new();
        assert!(!empty.matches_outstanding(S, "secreq_anything"));
        assert!(empty.take(S, Some("secreq_anything")).is_none());
    }

    /// The bytes, pinned — including the three the em dash occupies, and
    /// the fact that `<id>` is substituted rather than printed.
    #[test]
    fn the_buffer_notice_is_the_5_2_line_with_the_session_id_in_it() {
        let notice = buffer_notice("sess_abc123");
        let text = String::from_utf8(notice.clone()).expect("utf-8");
        assert_eq!(
            text,
            "[holdfast] awaiting secret input — run 'holdfast attach sess_abc123' \
             or open the web UI\r\n"
        );
        assert!(
            !text.contains("<id>"),
            "the template shipped with its placeholder still in it"
        );
        // The separator is a **spaced U+2014**, not a hyphen and not an
        // ASCII dash: five bytes where a reader counting characters sees
        // three.
        assert!(
            notice
                .windows(5)
                .any(|w| w == [0x20, 0xE2, 0x80, 0x94, 0x20]),
            "the em dash was normalised away"
        );
        assert!(text.ends_with("\r\n"), "a raw PTY stream needs the CR");

        // **The template's own size, measured rather than remembered.**
        // The 0.0.7 plan states 74 characters and 76 bytes for this line;
        // both are wrong, and the numbers below are what `buffer_notice`
        // actually produces. Pinned here so a later edit to the string
        // has to say so.
        let template = String::from_utf8(buffer_notice("<id>")).expect("utf-8");
        let line = template.strip_suffix("\r\n").expect("CRLF");
        assert_eq!(line.chars().count(), 80, "characters, before <id> grows");
        assert_eq!(line.len(), 82, "bytes — two more, and both are the em dash");
        assert_eq!(
            line.bytes().filter(|b| *b >= 0x80).count(),
            3,
            "exactly one three-byte code point in the whole line"
        );
    }

    #[test]
    fn the_notice_is_claimed_at_most_once_per_request() {
        let slots = SecretSlots::new();
        let a = slots.raise_or_adopt(S, "p", None, true).expect("raise");
        assert!(slots.claim_notice(S, &a.request_id));
        assert!(!slots.claim_notice(S, &a.request_id), "§9.5: at most once");
        assert!(!slots.claim_notice(S, "secreq_other"));
    }

    #[test]
    fn the_submission_bounds_are_the_waiting_calls_own() {
        let slots = SecretSlots::new();
        let (r, _) = slots.raise(S, "p", RaisedBy::EchoDrop);
        // No waiter: no tool argument to be bounded by, and a line is
        // what an echo-off prompt is waiting for.
        assert_eq!(
            slots.submission_bounds(S, &r.request_id),
            Some((None, true))
        );
        let a = slots
            .raise_or_adopt(S, "p", Some(16), false)
            .expect("adopt");
        assert_eq!(
            slots.submission_bounds(S, &a.request_id),
            Some((Some(16), false))
        );
        assert_eq!(slots.submission_bounds(S, "secreq_other"), None);
    }

    /// GH #24's primitive, and the pairing that stops it becoming
    /// [`SecretSlots::take`] with extra steps.
    #[test]
    fn only_a_slot_with_nobody_waiting_is_a_third_partys_to_take() {
        let slots = SecretSlots::new();
        let (raised, _) = slots.raise(S, "[sudo] password for ada:", RaisedBy::EchoDrop);
        assert_eq!(slots.unadopted_sessions(), vec![S.to_string()]);

        let taken = slots
            .take_if_unadopted(S)
            .expect("an unadopted raise is the janitor's to release");
        assert_eq!(taken.request_id(), raised.request_id);
        assert!(!taken.has_waiter(), "there was nobody to answer");
        assert!(slots.outstanding(S).is_none());
        assert!(slots.unadopted_sessions().is_empty());
        assert!(
            slots.take_if_unadopted(S).is_none(),
            "a vacant slot is not a release"
        );

        // **The pairing.** The same slot with a call waiting on it is
        // untouchable: §5.1's answer is that call's, and a janitor that
        // took this would leave it reporting `timeout` for a session that
        // died.
        let a = slots.raise_or_adopt(S, "p", None, true).expect("raise");
        assert!(
            slots.unadopted_sessions().is_empty(),
            "a slot with a waiter was offered to the janitor"
        );
        assert!(
            slots.take_if_unadopted(S).is_none(),
            "the janitor took a slot §5.1's answer owns"
        );
        assert!(slots.matches_outstanding(S, &a.request_id));
        let mut rx = a.rx;
        assert!(
            rx.try_recv().is_err(),
            "the janitor answered a caller it does not own"
        );
        // And the owner can still close it, which is what proves the
        // refusal above left the request whole rather than half-taken.
        assert!(slots.close_on_caller_timeout(S, &a.request_id).is_some());
    }

    #[test]
    fn every_cancel_reason_has_a_distinct_wire_spelling() {
        // The exhaustive match is the guard: a variant added later fails
        // to compile here until it is given a spelling, and the set
        // comparison catches two variants sharing one.
        let spellings: std::collections::BTreeSet<&str> =
            CancelReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(spellings.len(), CancelReason::ALL.len());
        for r in CancelReason::ALL {
            let expect = match r {
                CancelReason::UserCancelled => "user_cancelled",
                CancelReason::Timeout => "timeout",
                CancelReason::TooLarge => "too_large",
                CancelReason::ConcurrentRequestPending => "concurrent_request_pending",
            };
            assert_eq!(r.as_str(), expect);
        }
        assert_eq!(RaisedBy::EchoDrop.as_str(), "echo_drop");
        assert_eq!(RaisedBy::ToolCall.as_str(), "tool_call");
    }

    /// **Every route that empties a slot moves the count, and nothing else
    /// does.**
    ///
    /// GH #35's whole fix rests on this, and the structural half of it is
    /// the `slots` module: `requests` is private to it, so a
    /// `requests.remove(..)` written anywhere else in this file does not
    /// compile, and inside it there is exactly one — in `Slots::close`.
    /// That is a compile-time property no runtime row can see, so this row
    /// states the runtime half: the four public routes out of a slot all
    /// reach it.
    ///
    /// **The negatives are the half that makes it a rule rather than a
    /// tally.** A count that also moved on a raise, on an adoption, or on
    /// a refused take would refuse writes the autofill must make — which
    /// is a dropped credential and a human asked for a password they did
    /// not need to type.
    #[test]
    fn every_route_that_empties_a_slot_moves_the_closure_count() {
        let count = |s: &SecretSlots| s.snapshot(S).closed;

        // The four routes, each on its own fresh raise.
        let slots = SecretSlots::new();
        assert_eq!(count(&slots), 0, "a session nothing happened to is zero");

        let (a, _) = slots.raise(S, "p", RaisedBy::EchoDrop);
        assert!(slots.take(S, Some(&a.request_id)).is_some());
        assert_eq!(count(&slots), 1, "`take`");

        slots.raise(S, "p", RaisedBy::EchoDrop);
        assert!(slots.take_if_unadopted(S).is_some());
        assert_eq!(count(&slots), 2, "`take_if_unadopted`");

        let before = slots.snapshot(S);
        slots.raise(S, "p", RaisedBy::EchoDrop);
        assert!(matches!(
            slots.take_if_unadopted_matching(S, &before),
            SlotTake::Taken(_)
        ));
        assert_eq!(count(&slots), 3, "`take_if_unadopted_matching`");

        let c = slots.raise_or_adopt(S, "p", None, true).expect("raise");
        assert!(slots.close_on_caller_timeout(S, &c.request_id).is_some());
        assert_eq!(count(&slots), 4, "`close_on_caller_timeout`");

        // **The negatives.** Nothing that leaves a request in place counts.
        let (d, first) = slots.raise(S, "p", RaisedBy::EchoDrop);
        assert!(first);
        assert_eq!(count(&slots), 4, "a raise is not a closure");
        slots.raise(S, "p", RaisedBy::EchoDrop);
        assert_eq!(count(&slots), 4, "an idempotent re-raise is not a closure");
        let e = slots.raise_or_adopt(S, "p", Some(16), true).expect("adopt");
        assert_eq!(e.request_id, d.request_id);
        assert_eq!(count(&slots), 4, "an adoption is not a closure");
        assert!(slots.claim_notice(S, &d.request_id));
        assert_eq!(count(&slots), 4, "the buffer notice is not a closure");
        assert!(slots.take(S, Some("secreq_notours")).is_none());
        assert_eq!(count(&slots), 4, "a refused take is not a closure");
        assert!(slots.take_if_unadopted(S).is_none());
        assert_eq!(count(&slots), 4, "a refused janitor take is not a closure");

        // And the count is **per session**: a second session starts at zero
        // and is unaffected by the four above.
        let other = "sess_2";
        assert_eq!(slots.snapshot(other).closed, 0);
        slots.raise(other, "p", RaisedBy::EchoDrop);
        assert!(slots.take(other, None).is_some());
        assert_eq!(slots.snapshot(other).closed, 1);
        assert_eq!(count(&slots), 4, "another session's closure moved this one");
    }

    /// **The closure count**, and the sequence it is the only thing that
    /// can see (GH #35).
    ///
    /// The autofill looked at a **vacant** slot, went away for as long as
    /// `keychain_provider_timeout_secs`, and in that window a raise
    /// appeared and a human answered it. The slot is vacant again — which
    /// is byte-for-byte what "nothing ever happened" looks like — so
    /// neither the id comparison (there is no id to compare) nor a
    /// re-check of vacancy can tell the two apart. Writing anyway puts
    /// **two values into one `getpass`**: the human's is consumed and the
    /// resolved one waits in the tty input queue for whatever the child
    /// reads next.
    #[test]
    fn the_autofills_take_refuses_a_slot_that_was_answered_while_it_was_away() {
        let slots = SecretSlots::new();
        // What the autofill saw before the provider call: nothing.
        let before = slots.snapshot(S);

        // Inside the window: the echo drop raises, and a human at an
        // attached client answers it through `take`.
        let (raised, _) = slots.raise(S, "[sudo] password for ada:", RaisedBy::EchoDrop);
        assert!(slots.take(S, Some(&raised.request_id)).is_some());
        assert!(
            slots.outstanding(S).is_none(),
            "the arrangement must leave the slot vacant, or this row is about \
             something else"
        );

        assert!(
            matches!(
                slots.take_if_unadopted_matching(S, &before),
                SlotTake::NotYours
            ),
            "a raise appeared and was answered while the provider ran, and the \
             autofill was told to write anyway — two values into one getpass"
        );

        // **The pairing, and it is the one that matters**: a snapshot taken
        // *after* that sequence, over the same vacant slot, still writes.
        // Without it the row passes against an implementation that never
        // writes at all, which would break every autofill instead of the
        // one case this is about.
        assert!(matches!(
            slots.take_if_unadopted_matching(S, &slots.snapshot(S)),
            SlotTake::Vacant
        ));

        // **The second pairing, and it is the behaviour a raise counter
        // would have broken.** A raise that appeared inside the window and
        // is *still outstanding* is unanswered, so it is this value's to
        // close — the ordinary anticipatory case, where an agent calls
        // `request_secret_input` before the prompt is drawn.
        let fresh = slots.snapshot(S);
        let (appeared, _) = slots.raise(S, "MySQL password:", RaisedBy::EchoDrop);
        let SlotTake::Taken(got) = slots.take_if_unadopted_matching(S, &fresh) else {
            panic!("an unanswered raise that appeared inside the window is the value's to close");
        };
        assert_eq!(got.request_id(), appeared.request_id);
    }

    /// **The waiter half**, and the second of the two conditions
    /// [`SecretSlots::take_if_unadopted_matching`] tests.
    ///
    /// A slot with a call waiting on it is never the autofill's to
    /// satisfy: that call owns the answer, and a credential written into
    /// the PTY behind it is a second value in one `getpass`. This is the
    /// half that stops an autofill writing into a raise **another tool
    /// call adopted inside its window** — the closure count cannot see an
    /// adoption, because adopting closes nothing.
    ///
    /// Dropping the `has_waiter` test left the whole workspace green
    /// before this row existed.
    #[test]
    fn the_autofills_take_refuses_a_slot_somebody_is_waiting_on() {
        let slots = SecretSlots::new();
        // **The control**, and it is what makes the refusal below evidence
        // of the waiter rather than of anything else: the same raise, under
        // the same snapshot, is takeable before anybody adopts it.
        let before = slots.snapshot(S);
        slots.raise(S, "[sudo] password for ada:", RaisedBy::EchoDrop);
        assert!(matches!(
            slots.take_if_unadopted_matching(S, &before),
            SlotTake::Taken(_)
        ));

        let now = slots.snapshot(S);
        let (raised, _) = slots.raise(S, "[sudo] password for ada:", RaisedBy::EchoDrop);
        let a = slots
            .raise_or_adopt(S, "a call", Some(16), true)
            .expect("a raised slot with no waiter is adopted");
        assert_eq!(a.request_id, raised.request_id);

        // **The closure count is unchanged** — an adoption closes nothing —
        // so the waiter test is the only thing that can refuse this.
        assert_eq!(now, slots.snapshot(S), "the arrangement closed a request");
        assert!(
            matches!(
                slots.take_if_unadopted_matching(S, &now),
                SlotTake::NotYours
            ),
            "the autofill took a slot a waiting call owns"
        );

        // Nothing was disturbed: the waiting call is unanswered and can
        // still close its own request, which is what proves the refusals
        // above did not half-take it.
        assert!(slots.matches_outstanding(S, &raised.request_id));
        let mut rx = a.rx;
        assert!(
            rx.try_recv().is_err(),
            "the autofill answered a caller it does not own"
        );
        assert!(slots
            .close_on_caller_timeout(S, &raised.request_id)
            .is_some());
    }

    /// **The zeroing on the client-submitted path**, and the twin of
    /// `secret::provider::tests::the_resolved_value_is_zeroed_after_the_write`.
    ///
    /// The two together are one claim — *"a `SecretBytes` is zeroed after
    /// the write on **every** path that builds one"* — and it takes two
    /// rows because the two paths construct the value in two different
    /// modules from two different sources: a client's frame here, a
    /// provider's stdout there. A single-path assertion is green while the
    /// other path leaks, which is the whole reason this row exists beside
    /// that one.
    ///
    /// **Not a raw-pointer read-back, on either path.** `Drop` zeroes the
    /// `Vec` and then frees it, so reading through a saved pointer
    /// afterwards is a use-after-free: undefined behaviour, a hard failure
    /// under Miri or ASAN, and — measured in 0.0.6 — an answer that is
    /// neither the secret nor zeros, because the allocator has already
    /// written its freelist bookkeeping into the same bytes.
    /// `attach::secret::drop_witness` is pushed to by the `Drop` itself,
    /// *after* the zeroing loop and while the allocation is still ours.
    ///
    /// It is a unit test here rather than in `tests/secrets.rs` because
    /// `#[cfg(test)]` is invisible from an integration target. The witness
    /// is thread-local, so this row sees its own drops and no other row's
    /// — which is also why the value is dropped **here** rather than
    /// handed to a session, whose writer thread would drop it out of
    /// sight.
    ///
    /// The construction is `attach::conn`'s `SecretInput` arm, byte for
    /// byte: the bounds come from [`SecretSlots::submission_bounds`] and
    /// the normalisation is [`crate::attach::secret::SecretBytes::normalise`],
    /// so a change to either is a change to what this row asserts.
    #[test]
    fn the_submitted_value_is_zeroed_after_the_write() {
        use crate::attach::secret::{drop_witness, SecretBytes};

        let slots = SecretSlots::new();
        let adopted = slots
            .raise_or_adopt(S, "a credential", Some(4096), true)
            .expect("a vacant slot raises");
        let (max, append) = slots
            .submission_bounds(S, &adopted.request_id)
            .expect("the waiting call's own bounds");
        assert_eq!(max, Some(4096));
        assert!(append, "the bounds are the call's, not a constant");

        drop_witness::reset();
        let secret = SecretBytes::normalise(b"hunter2".to_vec(), append);
        let len = secret.len();
        assert_eq!(len, 8, "seven bytes plus the appended newline");

        // The write, as the writer thread does it: the bytes are lent for
        // the duration of the call and never escape — asserted *inside*
        // the closure rather than on a copy it returns, because a copy is
        // the very thing the type exists to prevent.
        secret.with_bytes(|b| assert_eq!(b, b"hunter2\n", "the submitted value did not arrive"));
        assert_eq!(
            drop_witness::peek_len(),
            0,
            "something was dropped before the value under test"
        );

        drop(secret);

        let seen = drop_witness::taken();
        assert_eq!(
            seen.len(),
            1,
            "exactly one SecretBytes should have been dropped here, saw {}",
            seen.len()
        );
        assert_eq!(
            seen[0].len(),
            len,
            "the witness saw a buffer of the wrong length: the Drop zeroed \
             something other than the submitted value"
        );
        assert!(
            seen[0].iter().all(|b| *b == 0),
            "the submitted value survived its own Drop: {:?}",
            String::from_utf8_lossy(&seen[0])
        );

        // The pairing, and the reason the assertion above is not satisfied
        // by a `Drop` that truncates: the witness is capable of holding a
        // non-zero buffer, and does when it is handed one.
        drop_witness::record(b"hunter2");
        assert_eq!(drop_witness::taken(), vec![b"hunter2".to_vec()]);
    }
}
