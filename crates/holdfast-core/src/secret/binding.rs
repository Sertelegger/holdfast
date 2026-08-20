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
//! in, and it is the only entry point the daemon calls. Saying that of the
//! *module* would be false and is worth not saying: [`select`] is `pub`
//! and takes `command_line: &str`, as do `matches` and `pattern_matches`
//! below — bare subjects, supplied by their caller. `autofill` is that
//! caller everywhere but in tests, and it builds both subjects from the
//! session.
//!
//! **And one of those two subjects is the agent's own string.**
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
//! **The consequence, which the un-quoted join below makes sharper: the
//! agent controls both sides of a word-boundary straddle.** An operator
//! writing an **unanchored** `match_command` is writing a pattern the
//! agent can satisfy from an argument. `match_command = "ssh\\s+prod-01"`
//! is matched by `start_session(command: "cat", args: ["x", "ssh prod-01
//! y"])`, whose joined line is `cat x ssh prod-01 y` — and the credential
//! is then typed into `cat`, which echoes it into the ring buffer and out
//! through `read_output`. §9.6's published example is anchored
//! (`^ssh\s+(\S+@)?prod-0[12]\b`) and is safe; nothing in this code, in
//! `Config::validate`, or in §10.2 says why the anchor matters. **Anchor
//! your patterns.**
//!
//! In the same class: **`match_command = ""` is config-legal and matches
//! everything.** `Config::validate` compiles both patterns and
//! deliberately does not special-case the empty one; the empty regex
//! matches every subject, so an empty `match_command` is a credential
//! store handed to every session on the box — from a two-character config
//! value. Unlike `match_prompt`, whose empty spelling §9.6 gives a meaning
//! (*"does not select on the prompt"*), the empty `match_command` has no
//! documented meaning to apply, so this module implements it literally and
//! `an_empty_match_command_matches_every_session` pins that it is literal.
//! Rejecting it belongs at load, in `config.rs`, which this task does not
//! own.
//!
//! ## The two subjects
//!
//! **`match_command` is matched against `command` and `args` joined with
//! single spaces and not shell-quoted.** The join is built here, at match
//! time, and exists nowhere else: §9.4's `session_start` records the two
//! **element-wise, never joined**, and `mcp::tools`' `session_record`
//! gives the reason — *"joining with a space and redacting the result
//! would let a rule match across an argument boundary"*. So an operator
//! cannot lift a binding regex out of a log line, because no log line
//! carries this form; the plan claimed otherwise and was wrong. Adding a
//! joined field to the audit record to make the claim true would trade a
//! documentation convenience for the redaction hazard that shape was
//! chosen to avoid.
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
//! ## What is not here
//!
//! **`require_confirm` is Task 11's.** A binding carrying it does not
//! resolve in this build — see [`FellThrough::NeedsApproval`], which is
//! the seam the approval round-trip is written into.

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
fn matches(binding: &SecretBinding, command_line: &str, prompt_line: &str) -> bool {
    // **The subject here is agent-authored** — see the module header — so
    // an empty or unanchored pattern is one the agent can satisfy. Read
    // literally either way: unlike `match_prompt`, §9.6 gives the empty
    // `match_command` no meaning to apply, and inventing one here would be
    // a second place an operator's pattern means something other than what
    // a regex engine says it means. `an_empty_match_command_matches_every_session`
    // pins that it is literal, and says where the fix belongs.
    if !pattern_matches(
        binding,
        "match_command",
        &binding.match_command,
        command_line,
    ) {
        return false;
    }
    // An empty `match_prompt` is §9.6's "this binding does not select on
    // the prompt" — `config.rs` says so at the validation site and
    // deliberately does not special-case the empty regex there, which
    // leaves the reading to be applied here, at match time.
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

/// Compile and apply one of a binding's two patterns.
///
/// **A pattern that will not compile is not a match**, and it says so in
/// `daemon.log`. `Config::validate` rejects both patterns at load, so a
/// loaded daemon cannot reach this branch; a `SecurityConfig` built in
/// Rust can. The alternative — panicking, or treating an uncompilable
/// pattern as a match — would turn a config-shaped mistake into either a
/// dead daemon or a binding that fires on everything.
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
    /// **Task 11's seam.** The binding carries `require_confirm = true`,
    /// which §9.6 answers with a `BindingApprovalRequired` frame, a human
    /// approval inside `min(binding_approval_timeout_secs, remaining / 2)`
    /// and only then a resolution. None of that exists yet, so the binding
    /// does **not** resolve here: a `require_confirm` that silently
    /// resolved would be the operator's most explicit "ask me first"
    /// answered by "no". Task 11 replaces this arm with the round trip;
    /// until then the safe reading of an un-implemented confirmation is
    /// that it was not given.
    NeedsApproval { binding_name: String },
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
        });
    }

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

    use crate::config::Config;
    use crate::mcp::tools::RequestSecretInputArgs;
    use crate::mcp::HoldfastServer;
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

    /// A binding with everything defaulted except what a row is about,
    /// and **no provider fixture** — for the rows that match without
    /// resolving.
    fn plain_binding(name: &str, match_command: &str) -> SecretBinding {
        SecretBinding {
            name: name.to_string(),
            match_command: match_command.to_string(),
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
        let config = Config {
            security,
            ..Config::default()
        };
        let server =
            HoldfastServer::with_audit_path_and_config(Some(audit_log.to_path_buf()), &config);
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
        let mut with_prompt = plain_binding("p", "^ssh\\b");
        with_prompt.match_prompt = "(?i)password".to_string();
        let mut anything = plain_binding("a", "^ssh\\b");
        anything.match_prompt = ".*".to_string();
        let no_prompt = plain_binding("n", "^ssh\\b");

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

    /// **`match_command = ""` matches every session, and an unanchored one
    /// is satisfiable from an agent-supplied argument.**
    ///
    /// The empty-`match_prompt` rule has three rows; this is its missing
    /// sibling. Both cases are *literal regex behaviour* rather than
    /// implementation choices, and the row exists so that the behaviour is
    /// written down rather than discovered by an operator: an empty
    /// `match_command` loads (`Config::validate` compiles both patterns and
    /// deliberately does not special-case the empty one) and hands the
    /// credential store to every session on the box.
    ///
    /// The second half is the straddle the module header describes, driven:
    /// with an unanchored operator pattern, an agent that never runs `ssh`
    /// at all can still produce a joined command line that matches, by
    /// putting a space inside one argument. That is why §9.6's published
    /// example is anchored.
    ///
    /// **Neither is a defect in this module and the fix for both is at
    /// load, in `config.rs`, which this task does not own.** The row is
    /// here so the next person to open that file finds the case stated as
    /// a fact rather than as a worry.
    #[test]
    fn an_empty_match_command_matches_every_session() {
        let everything = plain_binding("open", "");
        for line in [
            "ssh prod-01",
            "psql -h staging",
            "bash",
            "",
            "some-utterly-unrelated-command --flag",
        ] {
            assert_eq!(
                select(std::slice::from_ref(&everything), line, "").map(|b| b.name.as_str()),
                Some("open"),
                "an empty match_command must be read literally, and the empty regex \
                 matches {line:?}"
            );
        }
        // The pairing: a non-empty pattern still discriminates, so the row
        // above is not satisfied by a `select` that answers `Some` always.
        let narrow = plain_binding("narrow", "^ssh\\b");
        assert!(select(std::slice::from_ref(&narrow), "ssh prod-01", "").is_some());
        assert!(select(std::slice::from_ref(&narrow), "psql -h staging", "").is_none());

        // The straddle, driven. The operator's pattern is unanchored and
        // the agent never runs `ssh`.
        let unanchored = plain_binding("unanchored", "ssh\\s+prod-01");
        let agent_line = command_line("cat", &["x".to_string(), "ssh prod-01 y".to_string()]);
        assert_eq!(agent_line, "cat x ssh prod-01 y");
        assert!(
            select(std::slice::from_ref(&unanchored), &agent_line, "").is_some(),
            "the un-quoted join lets an argument straddle a word boundary, and both \
             sides of that are agent-controlled"
        );
        // Anchored — §9.6's own spelling — and the same line no longer
        // matches. This is the pairing that makes the sentence in the
        // module header actionable rather than merely alarming.
        let anchored = plain_binding("anchored", "^ssh\\s+(\\S+@)?prod-0[12]\\b");
        assert!(
            select(std::slice::from_ref(&anchored), &agent_line, "").is_none(),
            "anchoring is what closes the straddle"
        );
        assert!(select(std::slice::from_ref(&anchored), "ssh user@prod-01", "").is_some());
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
        bad.match_command = "^ssh".into();
        bad.match_prompt = "(?P<".into();
        assert_eq!(select(std::slice::from_ref(&bad), "ssh prod-01", "x"), None);
        // The pairing, or the row above passes against a `select` that
        // always answers `None`.
        bad.match_prompt = "x".into();
        assert!(select(std::slice::from_ref(&bad), "ssh prod-01", "x").is_some());
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
        let mut b = sc.binding("gh", "^git\\b", &format!("printf '{PROBE}\\n'\n"));
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
        let mut first = sc.binding("zeta", "^ssh\\b", &format!("printf '{PROBE}\\n'\n"));
        first.provider = "pass".into();
        let mut second = sc.binding("alpha", "^ssh\\b", "printf 'wrong-one\\n'\n");
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
        let mut b = sc.binding("prod-ssh", "^ssh\\b", &format!("printf '{PROBE}\\n'\n"));
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
        let b = sc.binding("prod-ssh", "^ssh\\b", &format!("printf '{PROBE}\\n'\n"));
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
        let b2 = sc2.binding("prod-ssh", "^ssh\\b", &format!("printf '{PROBE}\\n'\n"));
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

    /// **`require_confirm` does not resolve in this build — Task 11's
    /// seam.**
    ///
    /// §9.6 answers `require_confirm = true` with a
    /// `BindingApprovalRequired` frame, a bounded human approval and only
    /// then a resolution. None of that exists yet, and a binding carrying
    /// the operator's most explicit *"ask me first"* must not be answered
    /// with *"no, here it is"*. It falls through, and the provider is not
    /// consulted.
    ///
    /// The pairing is the same binding with the flag cleared, which does
    /// resolve — otherwise this row passes against a `select` that never
    /// matches.
    #[tokio::test]
    async fn a_binding_requiring_confirmation_does_not_resolve_yet() {
        let mut sc = Scratch::new("confirm");
        let mut b = sc.binding("prod-ssh", "^ssh\\b", &format!("printf '{PROBE}\\n'\n"));
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
        let mut cleared = sc2.binding("prod-ssh", "^ssh\\b", &format!("printf '{PROBE}\\n'\n"));
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
            "^ssh\\b",
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
            "^ssh\\b",
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
            "^ssh\\b",
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
            "^ssh\\b",
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
        let failing = sc.binding("fails", "^ssh\\b", "exit 3\n");
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

        let no_match = keychain_mode(vec![plain_binding("nope", "^psql\\b")]);
        assert_eq!(
            autofill_reason(&no_match, &s, audit),
            FellThrough::NoBindingMatched
        );

        let mut confirmed = failing.clone();
        confirmed.require_confirm = true;
        assert_eq!(
            autofill_reason(&keychain_mode(vec![confirmed]), &s, audit),
            FellThrough::NeedsApproval {
                binding_name: failing.name.clone()
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
        let b = sc.binding("prod-ssh", "^ssh\\b", &format!("printf '{PROBE}\\n'\n"));
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
            "^ssh\\b",
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
}
