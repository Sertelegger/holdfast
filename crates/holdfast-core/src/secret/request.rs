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

use std::collections::HashMap;

use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::attach::secret::SecretRequest;

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

/// Every session's slot. **Vacant is absence from the map**, so there is
/// no third state to keep consistent with the other two.
#[derive(Default, Debug)]
pub struct SecretSlots {
    inner: Mutex<HashMap<String, RaisedRequest>>,
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
                slots.insert(
                    session_id.to_string(),
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
                slots.insert(
                    session_id.to_string(),
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
                slots.remove(session_id)
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
}
