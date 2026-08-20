//! §17.5's binding-approval lifecycle: the per-session slot a
//! `require_confirm` binding waits in, and the window it waits for.
//!
//! **What this module is *not*: a second [`SecretSlots`].** The two look
//! alike — one per session, raised, decided or expired, broadcast to
//! attached clients — and they answer opposite questions. A secret
//! request asks *"what is the value?"* and its answer is bytes the daemon
//! must never look at. An approval asks *"may this credential be used
//! here?"* and its answer is one bit, which the daemon acts on. They are
//! kept apart because they can be **concurrently outstanding on one
//! session**: §5.2's fall-through raises a secret request *after* an
//! approval is denied or expires, and folding them into one slot would
//! make the fall-through overwrite the thing it fell through from.
//!
//! ## The value is not here, and cannot be
//!
//! Nothing in this module has a field, parameter or return type able to
//! hold a secret. That is the same structural claim [`SecretBytes`] makes
//! one layer down, applied to the surface REQ-SEC-016 is about: an
//! approval carries the binding's **name** and **provider** and stops
//! there, because *"approving is a decision about which credential, not
//! an exposure of it"* (§9.6). The reference is likewise absent, and its
//! absence is a real omission rather than an accident of ordering — the
//! reference exists in the daemon's config at the moment [`Approval`] is
//! built, so leaving it out is a decision. The **value** does not exist
//! yet at that moment (resolution happens only after approval), which is
//! precisely why an assertion that the value is absent *from this type*
//! could not fail and is not the assertion worth writing; the one worth
//! writing ranges over every frame and every audit line for the whole
//! flow, before and after approval.
//!
//! ## `expires_at_unix_secs`, spelled that way from the first line
//!
//! REQ-T-018, widened at rev. 47, binds the MCP tool surface, the control
//! protocol, the attach protocol and the HTTP API, and forbids a bare
//! `expires_at`/`created_at`/`started_at` outright: *"a bare name is a
//! claim the value does not support"*. Nothing this milestone puts on a
//! wire carries a timestamp at all — `BindingApprovalRequired` is
//! `{approval_id, binding_name, provider, session, prompt_text}` — so the
//! rule binds nothing today. It is applied here anyway, to a field that
//! is currently daemon-internal, because **this registry is where a later
//! hand adds one**: 0.0.10 renders this same lifecycle at
//! `GET /api/binding-approvals`, and the field crosses the HTTP API the
//! moment it does. 0.0.8's revision found exactly this shape on
//! `confirmation/list_pending`, whose `expires_at` had to become
//! `expires_at_unix_secs` after it shipped; this is its sibling, named
//! correctly before it exists. The tree's guard —
//! `no_declared_timestamp_carries_a_bare_name` in `tests/schema.rs` —
//! walks `TOOLS` and **reaches neither a frame nor this struct**, so on
//! these two surfaces the rule is held by reading rather than by a test.
//!
//! [`SecretSlots`]: super::SecretSlots
//! [`SecretBytes`]: crate::attach::secret::SecretBytes

use std::collections::HashMap;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::attach::frames::ApprovalDecision;
use crate::audit::AuditLog;

/// §17.5's four terminal states.
///
/// **Four states and three audit values, and that gap is the spec's
/// rather than this module's.** §9.4's `binding_approval.outcome` is
/// `approved | denied | expired`; §17.5's lifecycle has a fourth terminal
/// state, `Superseded`, and no revision has given it a value. The
/// vocabulary was written at rev. 22 in §18.7's prose, rev. 44 added the
/// fourth state without revisiting it, and rev. 48 moved the schema into
/// §9.4's table recording *"no field changes"* — so the count of three
/// crossed a revision that touched the row, as a transcription rather
/// than as a decision.
///
/// [`Outcome::audit_value`] answers `None` for it, and this task writes
/// **no** `binding_approval` line for a superseded approval: an absent
/// record beats an invented `outcome`, and the absence is asserted rather
/// than assumed. Flagged as **Q13** for a reviewer to decide rather than
/// inherit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A human said `approve`: resolve the reference, inject, zero, audit
    /// `binding_resolved`.
    Approved,
    /// A human said `deny`: **fall through to the human-prompt path**
    /// (REQ-SEC-017). Not an error and not a status of its own — §18.1
    /// deleted `binding_approval_denied` because the fall-through is
    /// unconditional in both §9.6 and §17.5.
    Denied,
    /// The approval window elapsed. The same fall-through, audited as
    /// `expired` and — because nobody decided — with **no `decided_by`**.
    Expired,
    /// The session exited, or the outstanding `request_secret_input` was
    /// cancelled. The approval is discarded and **nothing is injected**,
    /// even if a decision arrives afterwards.
    Superseded,
}

impl Outcome {
    /// §9.4's `binding_approval.outcome`, or `None` where the vocabulary
    /// has no value — see the type's doc for why that is not a bug here.
    pub fn audit_value(self) -> Option<&'static str> {
        match self {
            Self::Approved => Some("approved"),
            Self::Denied => Some("denied"),
            Self::Expired => Some("expired"),
            Self::Superseded => None,
        }
    }

    /// Every terminal state, for the exhaustive-reachability guard —
    /// the shape `CancelReason::ALL` already uses in this module's
    /// sibling.
    pub const ALL: [Outcome; 4] = [
        Self::Approved,
        Self::Denied,
        Self::Expired,
        Self::Superseded,
    ];
}

/// One pending approval, as [`ServerFrame::BindingApprovalRequired`]
/// and (from 0.0.10) `GET /api/binding-approvals` see it.
///
/// [`ServerFrame::BindingApprovalRequired`]:
///     crate::attach::frames::ServerFrame::BindingApprovalRequired
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub approval_id: String,
    /// §9.6's override key: *"the only part of a binding any surface
    /// shows"*. **Never the reference** (REQ-SEC-016) — there is no field
    /// here able to hold one.
    pub binding_name: String,
    /// The §9.6 config spelling, as `ArgvProvider::as_str` gives it.
    pub provider: String,
    pub session_id: String,
    /// Already redacted by the caller, on the same rule
    /// `AwaitingSecret.prompt_text` follows.
    pub prompt_text: String,
    /// **Not on any wire in this milestone** — see the module header for
    /// why it is nevertheless spelled `_unix_secs` from the first line.
    pub expires_at_unix_secs: u64,
}

impl Approval {
    /// Mint an approval with a fresh id, in the shape `SecretRequest::new`
    /// already uses for `secreq_`.
    pub fn new(
        session_id: &str,
        binding_name: &str,
        provider: &str,
        prompt_text: &str,
        expires_at_unix_secs: u64,
    ) -> Self {
        let id = uuid::Uuid::new_v4().simple().to_string();
        Self {
            approval_id: format!("appr_{}", &id[..12]),
            binding_name: binding_name.to_string(),
            provider: provider.to_string(),
            session_id: session_id.to_string(),
            prompt_text: prompt_text.to_string(),
            expires_at_unix_secs,
        }
    }
}

/// A decision that reached the slot.
///
/// **`decided_by` is the deciding *connection*'s handshake `client_kind`
/// (`cli` or `ui-bridge`), never a field of the frame** — the same rule
/// REQ-SEC-018 states for `redaction_disabled`, and the reason
/// [`crate::attach::frames::ClientFrame::ApproveBinding`] has no such
/// field to carry. §9.4 names the field and gives it no values; the three
/// handshake tokens are what its neighbours in that table
/// (`redaction_disabled`, `attach_connect`, `attach_disconnect`) all
/// carry, **verbatim**, so a consumer can join `client_kind` across rows
/// without a mapping table. Implemented on that convention and flagged as
/// **Q11**, because rev. 48's move of the row made the answer local rather
/// than automatic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decided {
    pub decision: ApprovalDecision,
    pub decided_by: String,
}

/// What [`BindingApprovals::decide`] found.
///
/// Two states rather than a `bool`, because the caller renders them as
/// two different frames — nothing, and a `ProtocolError` — and a `bool`
/// at that call site reads as *"succeeded?"* and invites being ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decide {
    /// The named approval was outstanding, is now consumed, and the
    /// waiting caller has been told.
    Recorded,
    /// No approval on this session, or one under a different id. The
    /// approval expired, was superseded, or was already decided —
    /// indistinguishable from here, and the same answer either way: do
    /// nothing.
    UnknownApprovalId,
}

/// Every session's pending approval. **Vacant is absence from the map**,
/// the same shape `SecretSlots` uses, so there is no third state to keep
/// consistent with the other two.
#[derive(Default, Debug)]
pub struct BindingApprovals {
    inner: Mutex<HashMap<String, Pending>>,
}

#[derive(Debug)]
struct Pending {
    approval: Approval,
    waiter: oneshot::Sender<Decided>,
}

impl BindingApprovals {
    pub fn new() -> Self {
        Self::default()
    }

    /// Raise an approval on this session, or refuse if one is already
    /// outstanding.
    ///
    /// **Not idempotent, unlike `SecretSlots::raise`, and the asymmetry is
    /// the point.** A secret request is raised by every connection that
    /// sees one echo drop, so handing them all the same request is what
    /// makes one `request_id` reach every client without a leader. An
    /// approval is raised by exactly one caller — the tool call that
    /// matched the binding — so a second raise is a second question about
    /// the same session, and answering it with the *first* one's id would
    /// let a decision about binding A be applied to binding B.
    ///
    /// `None` means somebody is already waiting; the caller falls through
    /// as it would for any other non-resolution.
    pub fn raise(&self, approval: Approval) -> Option<oneshot::Receiver<Decided>> {
        let mut slots = self.inner.lock();
        if slots.contains_key(&approval.session_id) {
            return None;
        }
        let (tx, rx) = oneshot::channel();
        slots.insert(
            approval.session_id.clone(),
            Pending {
                approval,
                waiter: tx,
            },
        );
        Some(rx)
    }

    /// The session's pending approval, if any.
    pub fn outstanding(&self, session_id: &str) -> Option<Approval> {
        self.inner
            .lock()
            .get(session_id)
            .map(|p| p.approval.clone())
    }

    /// §17.5's `Approved`/`Denied` edge, from an `ApproveBinding` frame.
    ///
    /// **The removal and the answer are one critical section.** Two
    /// clients pressing *approve* on one dialog must produce one
    /// resolution, and a `contains_key` followed by a `remove` is exactly
    /// the check-then-act both would pass — the same race
    /// `SecretSlots::take`'s `expect_id` closes for a fulfilment.
    ///
    /// `approval_id` must match, for the reason `take`'s does: a decision
    /// about an approval that has since been superseded and replaced must
    /// not be applied to its replacement.
    pub fn decide(
        &self,
        session_id: &str,
        approval_id: &str,
        decision: ApprovalDecision,
        decided_by: &str,
    ) -> Decide {
        let mut slots = self.inner.lock();
        match slots.get(session_id) {
            Some(p) if p.approval.approval_id == approval_id => {}
            _ => return Decide::UnknownApprovalId,
        }
        let Some(pending) = slots.remove(session_id) else {
            return Decide::UnknownApprovalId;
        };
        // A send that fails means the waiting call has already gone —
        // its own deadline fired, or the session died under it. The
        // approval is consumed either way: it has been answered, and the
        // caller that is gone is not going to inject anything.
        let _ = pending.waiter.send(Decided {
            decision,
            decided_by: decided_by.to_string(),
        });
        Decide::Recorded
    }

    /// §17.5's `Expired` edge: the window elapsed and this caller owns
    /// the close.
    ///
    /// `None` means a decision landed between the timer firing and this
    /// lock — the answer is already on the caller's receiver, and the
    /// caller reports **that** rather than the timer. Same discipline as
    /// `SecretSlots::close_on_caller_timeout`, and for the same reason:
    /// a timer that decided anything would lose a decision made in its
    /// own window.
    pub fn expire(&self, session_id: &str, approval_id: &str) -> Option<Approval> {
        let mut slots = self.inner.lock();
        match slots.get(session_id) {
            Some(p) if p.approval.approval_id == approval_id => {}
            _ => return None,
        }
        slots.remove(session_id).map(|p| p.approval)
    }

    /// §17.5's `Superseded` edge: the session exited, or the outstanding
    /// request was cancelled.
    ///
    /// **No id, deliberately.** The caller arrives from the *session*
    /// rather than from an approval — a child that has exited supersedes
    /// whatever is pending on it, whichever approval that is — which is
    /// the same argument `take_if_unadopted` gives for having no
    /// `expect_id`.
    ///
    /// Dropping the [`Pending`] drops its sender, so a waiting caller's
    /// receiver errs and it stops waiting. **No injection follows**, and a
    /// decision arriving afterwards finds nothing and answers
    /// [`Decide::UnknownApprovalId`].
    pub fn supersede(&self, session_id: &str) -> Option<Approval> {
        self.inner.lock().remove(session_id).map(|p| p.approval)
    }
}

/// §17.5's and §9.6's approval window — **the arithmetic, in one place,
/// as a value a test can assert directly.**
///
/// ```text
/// with a caller waiting:  min(configured, remaining / 2)
/// with no caller:         configured
/// ```
///
/// **Not *"bounded by the remaining deadline"*, which permits all of it
/// and closes nothing.** `binding_approval_timeout_secs` and
/// `request_secret_input.timeout_secs` **both default to 120**, so an
/// approval nobody answers consumes the caller's entire deadline: the
/// call returns `secret_cancelled { reason: "timeout" }` having never
/// prompted a human for the value, and REQ-SEC-017's required
/// fall-through never runs. §17.5 calls that *"a requirement whose
/// behaviour cannot occur under shipped defaults"* — a test that cannot
/// fail, hiding in a config default where nothing that inspects tests can
/// see it.
///
/// Halving is what makes the fall-through reachable rather than merely
/// permitted: the prompt path always inherits at least half of what is
/// left. **§9.6 carried the loose form until rev. 48**, so an implementer
/// who read §9.6 first would write `min(configured, remaining)` — which
/// is the mutation this function's own row exists to kill.
///
/// The no-caller branch is §9.6's `autofill_on_echo_off` path (Task 13),
/// which has no deadline to divide. It is built and asserted here rather
/// than left for that milestone, because the *rule* is this task's and a
/// branch nothing exercises is a rule nobody has checked.
///
/// **A very short caller deadline yields a very short window**, down to
/// zero: `remaining / 2` of one second is 500 ms and of a second already
/// spent is nothing. That is the honest reading — a caller with no time
/// to wait has no time to ask a human either, and the fall-through it
/// then gets is the whole point — and it is why the consequence, *an
/// operator can measure a window far shorter than the number they
/// configured*, is indexed at §25 rather than treated as a defect.
pub fn approval_window(configured_secs: u64, caller_remaining: Option<Duration>) -> Duration {
    let configured = Duration::from_secs(configured_secs);
    match caller_remaining {
        Some(remaining) => configured.min(remaining / 2),
        None => configured,
    }
}

/// §9.4's `binding_approval`: `{approval_id, binding_name, outcome,
/// decided_by}`.
///
/// **`decided_by` is absent on `expired`, not empty**: there is no
/// decider, and an empty string in an authorisation record is an actor
/// whose name nobody wrote down. The same reason
/// `secret_input_resolved.bytes_written` is absent rather than `0`.
///
/// **`Superseded` writes nothing at all** — see [`Outcome`] for the whole
/// argument. Returns whether a line was written, so a caller (and a test)
/// can tell "no line, by the rule" from "no line, because the audit log
/// is disabled".
pub fn audit_binding_approval(
    audit: &AuditLog,
    approval: &Approval,
    outcome: Outcome,
    decided_by: Option<&str>,
) -> bool {
    let Some(value) = outcome.audit_value() else {
        return false;
    };
    let mut fields = serde_json::Map::new();
    fields.insert(
        "approval_id".into(),
        serde_json::json!(approval.approval_id),
    );
    fields.insert(
        "binding_name".into(),
        serde_json::json!(approval.binding_name),
    );
    fields.insert("outcome".into(), serde_json::json!(value));
    if let Some(who) = decided_by {
        fields.insert("decided_by".into(), serde_json::json!(who));
    }
    audit.record(
        "binding_approval",
        Some(&approval.session_id),
        serde_json::Value::Object(fields),
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "sess_1";

    fn approval() -> Approval {
        Approval::new(S, "prod-ssh", "secret-service", "a credential", 0)
    }

    #[test]
    fn a_fresh_approval_carries_no_reference_and_no_field_that_could() {
        // REQ-SEC-016's structural half, on the type the frame and
        // 0.0.10's HTTP payload are both built from. Asserted through
        // `Debug`, which prints every declared field including one an
        // encoder would skip — the same instrument `tests/wire_shape.rs`
        // uses for the `declared:` line, and the reason a key-set test
        // alone is not enough.
        let a = approval();
        let rendered = format!("{a:?}");
        // **Each needle carries its `:`, so this reads *field names* and
        // not values.** Without the colon the row fails on
        // `provider: "secret-service"`, which is a sample value and not a
        // field — measured on the first run, and it is the same
        // false-positive `debug_field_names` in `tests/wire_shape.rs`
        // takes care to avoid.
        for absent in ["reference:", "secret:", "value:", "expires_at:"] {
            assert!(
                !rendered.contains(absent),
                "`{absent}` appears on the approval surface: {rendered}"
            );
        }
        // The pairing, or the four absences above are satisfied by a
        // `Debug` that renders nothing at all.
        assert!(rendered.contains("binding_name"), "{rendered}");
        assert!(rendered.contains("provider"), "{rendered}");
        assert!(rendered.contains("expires_at_unix_secs"), "{rendered}");
        assert!(a.approval_id.starts_with("appr_"), "{}", a.approval_id);
    }

    #[test]
    fn the_window_is_half_the_callers_remaining_time_and_not_all_of_it() {
        // Q10's arithmetic, both directions of the `min`, plus the
        // no-caller branch. This is the *unit* half of
        // `the_approval_window_leaves_time_for_the_fall_through`; that
        // row drives the same rule through a live call, and this one
        // separates the two mutations by name.
        //
        // The shipped defaults, which is where the defect lived: both
        // knobs 120, so the loose form gives the caller's whole deadline.
        assert_eq!(
            approval_window(120, Some(Duration::from_secs(120))),
            Duration::from_secs(60),
            "on stock configuration the approval must leave half the deadline for the \
             fall-through REQ-SEC-017 requires"
        );
        // The plan's own fixture: min(120, 10/2) = 5.
        assert_eq!(
            approval_window(120, Some(Duration::from_secs(10))),
            Duration::from_secs(5)
        );
        // The other side of the `min`, so the row is not satisfied by an
        // implementation that always halves and ignores the knob.
        assert_eq!(
            approval_window(3, Some(Duration::from_secs(120))),
            Duration::from_secs(3),
            "a configured window shorter than half the deadline is the one that applies"
        );
        // Exactly at the crossover, where `min` has to pick one.
        assert_eq!(
            approval_window(60, Some(Duration::from_secs(120))),
            Duration::from_secs(60)
        );
        // No caller: the configured value in full (§9.6's
        // `autofill_on_echo_off`, Task 13). Paired with the same
        // `configured` under a caller, so the branch is doing something.
        assert_eq!(approval_window(120, None), Duration::from_secs(120));
        assert_ne!(
            approval_window(120, None),
            approval_window(120, Some(Duration::from_secs(120)))
        );
        // A caller with nothing left asks nobody.
        assert_eq!(approval_window(120, Some(Duration::ZERO)), Duration::ZERO);
    }

    #[test]
    fn superseded_is_the_one_terminal_state_with_no_audit_value() {
        // Q13, pinned so the hole is visible rather than inherited. The
        // loop is over `ALL`, so a fifth state added without a decision
        // fails here instead of silently defaulting to "writes nothing".
        let with: Vec<&str> = Outcome::ALL
            .iter()
            .filter_map(|o| o.audit_value())
            .collect();
        assert_eq!(
            with,
            vec!["approved", "denied", "expired"],
            "§9.4's vocabulary is exactly three, in this order"
        );
        assert_eq!(Outcome::Superseded.audit_value(), None);
        assert_eq!(Outcome::ALL.len(), 4, "§17.5's lifecycle has four");
    }

    #[tokio::test]
    async fn a_decision_reaches_the_waiter_and_consumes_the_approval() {
        let approvals = BindingApprovals::new();
        let a = approval();
        let rx = approvals.raise(a.clone()).expect("a vacant slot raises");
        assert_eq!(approvals.outstanding(S).as_ref(), Some(&a));

        assert_eq!(
            approvals.decide(S, &a.approval_id, ApprovalDecision::Approve, "cli"),
            Decide::Recorded
        );
        assert_eq!(
            rx.await.expect("the waiter was answered"),
            Decided {
                decision: ApprovalDecision::Approve,
                decided_by: "cli".to_string(),
            }
        );
        // Consumed: a second decision on the same id finds nothing, so
        // two clients pressing approve produce one resolution.
        assert!(approvals.outstanding(S).is_none());
        assert_eq!(
            approvals.decide(S, &a.approval_id, ApprovalDecision::Approve, "ui-bridge"),
            Decide::UnknownApprovalId
        );
    }

    #[tokio::test]
    async fn a_decision_naming_the_wrong_approval_changes_nothing() {
        // The pairing that makes the id comparison load-bearing: without
        // it, a stale decision about a superseded approval would be
        // applied to its replacement.
        let approvals = BindingApprovals::new();
        let a = approval();
        let mut rx = approvals.raise(a.clone()).expect("raise");

        assert_eq!(
            approvals.decide(S, "appr_not_this_one", ApprovalDecision::Approve, "cli"),
            Decide::UnknownApprovalId
        );
        // Still outstanding, and the waiter is still unanswered — a
        // refusal that half-took the slot would fail here rather than
        // above.
        assert_eq!(approvals.outstanding(S).as_ref(), Some(&a));
        assert!(
            rx.try_recv().is_err(),
            "the waiter was answered by a stale id"
        );
        // And a different *session* does not reach this one.
        assert_eq!(
            approvals.decide("sess_2", &a.approval_id, ApprovalDecision::Deny, "cli"),
            Decide::UnknownApprovalId
        );
        assert_eq!(approvals.outstanding(S).as_ref(), Some(&a));
    }

    #[tokio::test]
    async fn a_second_raise_on_one_session_is_refused_rather_than_merged() {
        // The asymmetry with `SecretSlots::raise`, pinned. Merging would
        // hand the second caller the first approval's id, and a human
        // approving binding A would have approved binding B.
        let approvals = BindingApprovals::new();
        let first = approval();
        let _rx = approvals.raise(first.clone()).expect("raise");
        let second = Approval::new(S, "other-binding", "pass", "p", 0);
        assert!(
            approvals.raise(second).is_none(),
            "a second approval on one session was accepted"
        );
        assert_eq!(
            approvals
                .outstanding(S)
                .expect("still the first")
                .binding_name,
            "prod-ssh"
        );
    }

    #[tokio::test]
    async fn expiry_and_supersession_both_end_the_wait_and_refuse_a_late_decision() {
        // §17.5's two non-decision exits. Both take the slot, both leave a
        // late `ApproveBinding` with nothing to apply — which is the
        // property `a_session_exit_supersedes_a_pending_approval` asserts
        // end to end and this row asserts at the state machine.
        let approvals = BindingApprovals::new();

        let a = approval();
        let rx = approvals.raise(a.clone()).expect("raise");
        assert_eq!(approvals.expire(S, &a.approval_id).as_ref(), Some(&a));
        assert!(
            rx.await.is_err(),
            "the sender outlived the expiry, so a waiter would still be parked"
        );
        assert_eq!(
            approvals.decide(S, &a.approval_id, ApprovalDecision::Approve, "cli"),
            Decide::UnknownApprovalId,
            "an approval that expired must not still be approvable"
        );

        let b = Approval::new(S, "prod-ssh", "secret-service", "p", 0);
        let rx = approvals.raise(b.clone()).expect("raise");
        assert_eq!(approvals.supersede(S).as_ref(), Some(&b));
        assert!(rx.await.is_err());
        assert_eq!(
            approvals.decide(S, &b.approval_id, ApprovalDecision::Approve, "cli"),
            Decide::UnknownApprovalId
        );
        // The pairing for both: a slot that was never raised answers the
        // same way, so neither assertion above is evidence of a registry
        // that simply refuses everything.
        assert!(approvals.supersede("sess_never").is_none());
        assert!(approvals.expire("sess_never", "appr_x").is_none());
    }

    #[tokio::test]
    async fn expiry_yields_to_a_decision_that_landed_in_its_own_window() {
        // The `close_on_caller_timeout` discipline: a timer that decided
        // anything would lose a decision made between the deadline and
        // the lock. `expire` answering `None` is how the caller learns to
        // read its receiver instead of reporting the timer.
        let approvals = BindingApprovals::new();
        let a = approval();
        let rx = approvals.raise(a.clone()).expect("raise");
        assert_eq!(
            approvals.decide(S, &a.approval_id, ApprovalDecision::Deny, "ui-bridge"),
            Decide::Recorded
        );
        assert!(
            approvals.expire(S, &a.approval_id).is_none(),
            "the timer took a slot a decision had already taken"
        );
        assert_eq!(
            rx.await
                .expect("the decision is still on the receiver")
                .decision,
            ApprovalDecision::Deny
        );
    }
}
