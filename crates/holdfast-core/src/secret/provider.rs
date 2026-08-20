//! §9.6's five keychain providers: five argv templates over one
//! killed-on-timeout subprocess boundary.
//!
//! **§9.6 gives a `Mechanism` column, not an argv column.** Its five
//! cells read `libsecret / secret-tool lookup`,
//! `security find-generic-password`, `pass show <path>`,
//! `op read <secret-reference>` and `Windows Credential Manager`. Only
//! the five *config spellings* below are carried verbatim from the
//! document — `secret-service`, `keychain`, `pass`, `onepassword`,
//! `wincred`. The flags, the ordering, the `attr=val` comma-splitting of
//! a `secret-service` reference, the choice of `secret-tool` over
//! libsecret, the spawn hygiene and the timeout are all engineering
//! decided in this milestone's plan (Decision 17 / Q15), and describing
//! them to a reviewer as if §9.6 pinned them would be wrong.
//!
//! The spellings are load-bearing beyond this file: `binding_resolved`
//! and `BindingApprovalRequired` put `provider` on the wire, so a
//! re-spelling here is a re-spelling in an audit log and in a
//! human-facing approval dialog.
//!
//! ## The six rules of the subprocess boundary
//!
//! 1. **argv, never a shell.** [`std::process::Command`] with an explicit
//!    vector, every time. A `reference` that reached `sh -c` would be a
//!    config-authored command injection into the daemon's own process.
//!    There is deliberately no code path in this module that joins argv
//!    into a string.
//! 2. **stdout is the value; stdin is closed; stderr is captured and
//!    discarded.** The resolved value takes exactly one path —
//!    `Output.stdout` moved into a [`SecretBytes`]. Nothing here calls
//!    `String::from_utf8_lossy` on it, which would leave an unzeroed
//!    copy behind. stderr is *captured* rather than nulled for one
//!    reason: inherited stderr on the daemon **is** `daemon.log`, and
//!    `pass`'s error messages contain the path, which *is* the
//!    reference.
//! 3. **On failure: the provider name and the exit status, and nothing
//!    else.** Never the stderr body, never the `reference`. §9.6 is
//!    explicit that the reference reaches no log and no surface, and no
//!    variant of [`ProviderError`] is able to carry one.
//! 4. **Exactly one trailing `\r\n` or `\n` comes off.** `pass show` and
//!    `security -w` both emit one, and a password with a trailing
//!    newline injected into a `getpass` read submits an empty second
//!    line. That strip is [`SecretBytes::normalise`] — §5.2's, applied by
//!    the daemon — and not a second implementation of it.
//! 5. **The child is bounded at `security.keychain_provider_timeout_secs`
//!    (default 10) and killed on expiry.** `op read` can block on
//!    biometric authentication indefinitely, and it would be blocking the
//!    session's only request slot while it did. Expiry is *no
//!    resolution*, not a call failure: the caller falls through to the
//!    prompt path (Q4).
//! 6. **The child inherits no Holdfast secret.** Nothing in this module
//!    calls `Command::env`, `Command::envs` or `Command::env_remove`, and
//!    the only argv is the one the template built from the reference.
//!    Note what rule 6 is *not*: a blanket `env_clear()`. Every one of
//!    the five needs the ambient environment to work at all —
//!    `secret-tool` needs `DBUS_SESSION_BUS_ADDRESS`, `pass` needs `HOME`
//!    and `GNUPGHOME`, `op` needs its session variables — so clearing it
//!    would not harden the boundary, it would break every provider behind
//!    it. Holdfast puts no secret of its own into its environment; the
//!    rule is that this module adds nothing.
//!
//! ## What is *not* here
//!
//! Nothing calls [`resolve`] yet. The operator bindings that choose a
//! provider, decide whether a session's command line matches one, and
//! write the `binding_resolved` audit entry are the next task's; this
//! module is the mechanism they will drive. It is not dead code awaiting
//! deletion.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::attach::secret::{zero_bytes, SecretBytes};
use crate::clock::Clock;
use crate::config::{SecretBinding, SecurityConfig};

/// How often the bounded wait asks whether the child has exited.
///
/// Small enough that `a_provider_that_hangs_is_killed_and_falls_through`
/// can assert "inside ~1 s" against a 1 s budget, large enough that a
/// 10 s default costs a few thousand `waitpid` calls rather than a spin.
const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// Why a binding did not resolve.
///
/// **No variant can carry a `reference` or a provider's stderr, and that
/// is the design.** Rule 3 is enforced by the shape of this type rather
/// than by the discipline of whoever writes the next `diag!`: there is no
/// field to put either in, so the natural mistake —
/// `String::from_utf8_lossy(&out.stderr)` in an error context — does not
/// type-check into anything here.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProviderError {
    /// The config named something that is not one of §9.6's five. The
    /// spelling is the operator's own text from `[security]`, not a
    /// reference, so naming it is what makes the error actionable.
    #[error("unknown secret provider `{0}`")]
    UnknownProvider(String),
    /// The reference is not in the shape this provider addresses items
    /// with — an empty string, or `attr=val` pairs that are not pairs.
    /// **The reference itself is not in the message.**
    #[error("secret provider `{provider}` cannot address an item with this reference")]
    MalformedReference { provider: String },
    /// One of the five, with no body in this build. `wincred` is
    /// 0.0.11's.
    #[error("secret provider `{provider}` is not implemented in this build")]
    NotImplemented { provider: String },
    /// The program could not be started at all — not installed, not on
    /// `PATH`, not executable. The ordinary case on a machine that does
    /// not have that credential store, and a fall-through rather than an
    /// error the agent sees.
    #[error("secret provider `{provider}` could not be started: {kind:?}")]
    NotStarted {
        provider: String,
        kind: std::io::ErrorKind,
    },
    /// It ran and exited non-zero: a locked keyring, an item that is not
    /// there, a denied biometric prompt.
    #[error("secret provider `{provider}` failed: {status}")]
    Failed { provider: String, status: String },
    /// Rule 5. The child outlived the budget and was killed.
    #[error("secret provider `{provider}` did not answer within {secs}s and was killed")]
    TimedOut { provider: String, secs: u64 },
    /// Exited 0 and printed no value.
    ///
    /// **A failure and not an `Ok` of length zero**, deliberately: an
    /// empty resolution written to a `getpass` read submits a blank
    /// password, and every "the secret is absent from X" assertion in
    /// this project passes trivially against a resolver that produces
    /// nothing.
    #[error("secret provider `{provider}` exited 0 and printed no value")]
    Empty { provider: String },
}

/// One provider, as the thing that turns a `reference` into an argv.
///
/// The five real ones are [`ArgvProvider`]s built from §9.6's table.
/// Tests inject a [`ScriptProvider`] running a file the test itself
/// wrote — REQ-TST-007: no test in this project may depend on a
/// credential store being installed, because none is, on any runner.
pub trait SecretProvider {
    /// The §9.6 config spelling. **The only thing about a provider that
    /// reaches a log, an audit entry or a human-facing dialog** — see
    /// rule 3.
    fn name(&self) -> &str;

    /// The argv this provider looks `reference` up with. Building it
    /// executes nothing, which is what lets the argv assertions run on a
    /// machine with none of the five installed.
    fn argv(&self, reference: &str) -> Result<Vec<String>, ProviderError>;
}

/// §9.6's five, by their config spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgvProvider {
    /// Linux. `secret-tool lookup <attr> <val> [<attr> <val> …]`.
    SecretService,
    /// macOS. `security find-generic-password -s <service> -a <account> -w`.
    Keychain,
    /// Any platform. `pass show <path>`.
    Pass,
    /// Any platform. `op read <secret-reference>`.
    OnePassword,
    /// Windows. Credential Manager is a Win32 API call rather than a
    /// program, so it has **no argv template**; see [`ArgvProvider::argv`].
    WinCred,
}

impl ArgvProvider {
    /// Every provider §9.6 names, for exhaustive drives.
    pub const ALL: [ArgvProvider; 5] = [
        Self::SecretService,
        Self::Keychain,
        Self::Pass,
        Self::OnePassword,
        Self::WinCred,
    ];

    /// The config spelling, verbatim from §9.6. **Hyphen in
    /// `secret-service`, one word in `onepassword`.**
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecretService => "secret-service",
            Self::Keychain => "keychain",
            Self::Pass => "pass",
            Self::OnePassword => "onepassword",
            Self::WinCred => "wincred",
        }
    }

    /// Parse `[[security.secret_bindings]] provider = "…"`.
    ///
    /// Exact match, no case folding and no aliases: the spelling is what
    /// an audit log records and what an approval dialog shows, and a
    /// loader that accepted `Keychain` would put two spellings of one
    /// provider into an operator's history.
    pub fn from_config(spelling: &str) -> Result<Self, ProviderError> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str() == spelling)
            .ok_or_else(|| ProviderError::UnknownProvider(spelling.to_string()))
    }
}

impl SecretProvider for ArgvProvider {
    fn name(&self) -> &str {
        self.as_str()
    }

    fn argv(&self, reference: &str) -> Result<Vec<String>, ProviderError> {
        let name = self.as_str();
        match self {
            // §9.6's example reference is `service=holdfast,account=prod-ssh`
            // and `secret-tool lookup` takes attribute/value pairs as
            // separate argv elements. Order is the reference's own: the
            // attribute set is arbitrary and the operator's ordering is
            // the only ordering there is.
            Self::SecretService => {
                let mut argv = vec!["secret-tool".to_string(), "lookup".to_string()];
                for (attr, value) in attr_pairs(name, reference)? {
                    argv.push(attr);
                    argv.push(value);
                }
                Ok(argv)
            }
            // The same `attr=val` reference, read as the two attributes
            // `find-generic-password` addresses an item by. Emitted in a
            // **fixed** order regardless of how the operator wrote them,
            // because these are flags rather than a set.
            //
            // **`-w` is not optional and is not a formatting flag.**
            // Without it `find-generic-password` prints the item's
            // *metadata* and not the password: a resolution that
            // succeeds, injects the wrong bytes, and looks correct in
            // every log.
            Self::Keychain => {
                let pairs = attr_pairs(name, reference)?;
                let service = pick(&pairs, "service", name)?;
                let account = pick(&pairs, "account", name)?;
                if pairs.len() != 2 {
                    return Err(ProviderError::MalformedReference {
                        provider: name.to_string(),
                    });
                }
                Ok(vec![
                    "security".to_string(),
                    "find-generic-password".to_string(),
                    "-s".to_string(),
                    service,
                    "-a".to_string(),
                    account,
                    "-w".to_string(),
                ])
            }
            // The reference is a store path and travels as **one** argv
            // element, whatever is in it. A `reference` containing `;`,
            // `$(…)` or a newline is a path with those characters in it
            // and nothing more, because nothing downstream of here parses
            // it.
            Self::Pass => Ok(vec![
                "pass".to_string(),
                "show".to_string(),
                whole(name, reference)?,
            ]),
            Self::OnePassword => Ok(vec![
                "op".to_string(),
                "read".to_string(),
                whole(name, reference)?,
            ]),
            // Windows Credential Manager is `CredReadW`, an API call —
            // there is no program to spawn and therefore no argv to
            // build, which is why `each_provider_builds_the_argv_the_plan_pins`
            // compares four vectors and not five. 0.0.11 builds the body;
            // until then every platform answers the same, so that a
            // binding naming it fails loudly rather than silently
            // resolving nothing on the one OS that could support it.
            Self::WinCred => Err(ProviderError::NotImplemented {
                provider: name.to_string(),
            }),
        }
    }
}

/// A provider that runs a program the **test itself wrote** (REQ-TST-007).
///
/// `secret-tool`, `security`, `pass` and `op` are all tools whose version
/// this project does not pin and whose presence it cannot assume — none
/// is installed on a CI runner. So the behavioural half of this module's
/// tests drives a script fixture instead, which pins *the daemon's
/// handling of a provider's output*: what this module is responsible for,
/// rather than `secret-tool`'s behaviour, which it is not.
///
/// `name` is the spelling a diagnostic will use, so a fixture standing in
/// for `pass` can be named `pass` and the log assertions read against a
/// real §9.6 spelling.
#[derive(Debug, Clone)]
pub struct ScriptProvider {
    name: String,
    path: PathBuf,
}

impl ScriptProvider {
    pub fn new(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
        }
    }
}

impl SecretProvider for ScriptProvider {
    fn name(&self) -> &str {
        &self.name
    }

    /// The script, then the reference as **one** element — the same shape
    /// every real template uses, so a mutation that joined argv into a
    /// command line is visible from a fixture as well as from the argv
    /// comparisons.
    fn argv(&self, reference: &str) -> Result<Vec<String>, ProviderError> {
        Ok(vec![
            self.path.to_string_lossy().into_owned(),
            reference.to_string(),
        ])
    }
}

/// Resolve one binding.
///
/// **The only input is a `&SecretBinding`**, which is constructed only by
/// config deserialisation — REQ-SEC-012's structural half: there is no
/// signature by which an agent-supplied string reaches this function.
///
/// `append_newline` is the waiting request's own (§5.2), and it is a
/// parameter rather than a constant because the plan's own test row pins
/// both answers: a provider printing `hunter2\n` must resolve to 8 bytes
/// with it and 7 without. It is **not** in the two-argument signature the
/// plan sketched; see the task report.
pub fn resolve(
    binding: &SecretBinding,
    limits: &SecurityConfig,
    append_newline: bool,
) -> Result<SecretBytes, ProviderError> {
    let provider = ArgvProvider::from_config(&binding.provider)?;
    resolve_with(&provider, &binding.reference, limits, append_newline)
}

/// [`resolve`] over any [`SecretProvider`] — the seam a test injects a
/// [`ScriptProvider`] at, and the whole of the subprocess boundary.
pub fn resolve_with(
    provider: &dyn SecretProvider,
    reference: &str,
    limits: &SecurityConfig,
    append_newline: bool,
) -> Result<SecretBytes, ProviderError> {
    let name = provider.name().to_string();
    let argv = provider.argv(reference)?;

    // Rule 5. **Read literally, including zero.** `[security]
    // keychain_provider_timeout_secs` carries no documented "disable"
    // value and `Config::validate` does not currently require it to be
    // non-zero, so a config saying `0` gets a zero-second budget and
    // every provider it runs is killed at the first poll. That is the
    // safe direction — the alternative is a subprocess holding the
    // session's only request slot with no bound at all — but the missing
    // `nonzero` row is recorded in the task report rather than repaired
    // from here.
    let budget = Duration::from_secs(u64::from(limits.keychain_provider_timeout_secs));

    let stdout = run(&name, &argv, budget)?;

    // Rule 2 and rule 4 in one statement: the `Vec<u8>` is **moved** into
    // the type whose `Drop` zeroes it, and §5.2's normalisation is the
    // strip. No `String`, no `from_utf8_lossy`, no second copy.
    let value = SecretBytes::normalise(stdout, append_newline);

    // A provider that exited 0 and printed nothing resolved nothing. With
    // `append_newline` the normalised buffer is the appended `\n` alone,
    // so the empty case is one byte rather than zero.
    if value.len() <= usize::from(append_newline) {
        crate::diag!("holdfast: secret provider `{name}` exited 0 and printed no value");
        return Err(ProviderError::Empty { provider: name });
    }
    Ok(value)
}

/// Spawn `argv`, bounded by `budget`, and hand back stdout.
///
/// Both pipes are drained on their own threads for the ordinary reason: a
/// child that fills the 64 KiB pipe buffer while we are blocked in
/// `try_wait` never exits, and a bounded wait that deadlocks is a worse
/// bug than no bound at all.
fn run(name: &str, argv: &[String], budget: Duration) -> Result<Vec<u8>, ProviderError> {
    let Some((program, args)) = argv.split_first() else {
        return Err(ProviderError::MalformedReference {
            provider: name.to_string(),
        });
    };

    // Rule 1: an explicit program and an explicit argument vector. No
    // shell, no `join`, no interpolation — the `reference` is one element
    // and the OS never parses it.
    let mut cmd = Command::new(program);
    cmd.args(args)
        // Rule 2. Closed stdin, so a provider that decides to prompt gets
        // EOF instead of the daemon's own stdin — which under
        // `holdfast mcp` is the JSON-RPC wire.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Rule 6: nothing is added to the child's environment here, and that
    // absence is the rule. See the module docs for why it is not
    // `env_clear()`.

    let mut child = cmd.spawn().map_err(|e| ProviderError::NotStarted {
        provider: name.to_string(),
        kind: e.kind(),
    })?;

    let mut out_pipe = child.stdout.take().expect("stdout was piped");
    let mut err_pipe = child.stderr.take().expect("stderr was piped");
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out_pipe.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        buf
    });

    // The crate's one clock (`clock.rs`) rather than a bare
    // `Instant::now()`, so there is still exactly one answer to "what
    // time is it" in this process. It is `system()` and not injectable on
    // purpose: this deadline bounds a real OS process, and a hand a test
    // moves cannot make a real `sleep 60` return sooner.
    let clock = Clock::system();
    let deadline = clock.now() + budget;
    let exited = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ProviderError::NotStarted {
                    provider: name.to_string(),
                    kind: e.kind(),
                });
            }
        }
        if clock.now() >= deadline {
            break None;
        }
        std::thread::sleep(POLL_INTERVAL);
    };

    let Some(status) = exited else {
        // Rule 5: kill the child, and reap it here so the daemon does not
        // accumulate zombies over a session's lifetime.
        let _ = child.kill();
        let _ = child.wait();
        // The two readers are **not** joined. They are blocked on pipes
        // the killed child has just released, so they finish on their
        // own; joining would reintroduce an unbounded wait on the one
        // path whose entire purpose is to be bounded — a provider that
        // left a grandchild holding the pipe would hang the session slot
        // exactly as if there had been no timeout. Their buffers are
        // discarded either way.
        drop(out_reader);
        drop(err_reader);
        let secs = budget.as_secs();
        crate::diag!(
            "holdfast: secret provider `{name}` did not answer within {secs}s and was killed"
        );
        return Err(ProviderError::TimedOut {
            provider: name.to_string(),
            secs,
        });
    };

    let mut stdout = out_reader.join().unwrap_or_default();
    // Rule 2's second half: **captured, and discarded here.** Captured so
    // the child's diagnostics cannot reach the daemon's inherited stderr,
    // which is `daemon.log`; zeroed rather than merely dropped because a
    // provider is free to print whatever it likes into it.
    let mut stderr = err_reader.join().unwrap_or_default();
    zero_bytes(&mut stderr);

    if !status.success() {
        // Rule 3, and this line is the whole of what a failure is allowed
        // to say: the provider's name and its exit status. Not
        // `String::from_utf8_lossy(&stderr)`, which is the natural thing
        // to write and puts `pass`'s store path — the reference — into a
        // file.
        crate::diag!("holdfast: secret provider `{name}` failed: {status}");
        // Whatever it managed to print before failing may be a partial
        // value; it is not going anywhere, but it is not left in a
        // buffer either.
        zero_bytes(&mut stdout);
        return Err(ProviderError::Failed {
            provider: name.to_string(),
            status: status.to_string(),
        });
    }
    Ok(stdout)
}

/// `attr=val,attr=val` — §9.6's example spelling for the two
/// attribute-addressed stores, split on the **first** `=` of each segment
/// so a value may contain one.
///
/// Nothing is trimmed. An attribute or a value with a leading space is
/// one with a leading space: a credential store's attributes are
/// arbitrary strings, and a daemon that quietly normalised them would
/// look up an item the operator did not write.
fn attr_pairs(provider: &str, reference: &str) -> Result<Vec<(String, String)>, ProviderError> {
    let malformed = || ProviderError::MalformedReference {
        provider: provider.to_string(),
    };
    if reference.is_empty() {
        return Err(malformed());
    }
    let mut pairs = Vec::new();
    for segment in reference.split(',') {
        let (attr, value) = segment.split_once('=').ok_or_else(malformed)?;
        if attr.is_empty() || value.is_empty() {
            return Err(malformed());
        }
        pairs.push((attr.to_string(), value.to_string()));
    }
    Ok(pairs)
}

fn pick(pairs: &[(String, String)], attr: &str, provider: &str) -> Result<String, ProviderError> {
    pairs
        .iter()
        .find(|(a, _)| a == attr)
        .map(|(_, v)| v.clone())
        .ok_or_else(|| ProviderError::MalformedReference {
            provider: provider.to_string(),
        })
}

/// A reference that travels whole, rejecting only the empty one — which
/// names no item and would make `pass show` print the whole store index.
fn whole(provider: &str, reference: &str) -> Result<String, ProviderError> {
    if reference.is_empty() {
        return Err(ProviderError::MalformedReference {
            provider: provider.to_string(),
        });
    }
    Ok(reference.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attach::secret::drop_witness;

    /// §9.6's own example reference, and the one Step 4 pins both
    /// attribute-addressed templates against.
    const ATTR_REFERENCE: &str = "service=holdfast,account=prod-ssh";

    /// **The zeroing, asserted from inside the `Drop` while the buffer is
    /// still alive.**
    ///
    /// Not a pointer read-back. `SecretBytes`'s `Drop` zeroes the `Vec`
    /// and then frees it, so reading through a saved raw pointer
    /// afterwards is a use-after-free: undefined behaviour, a hard
    /// failure under Miri or ASAN, and — measured in 0.0.6 — an answer
    /// that is neither the secret nor zeros, because the allocator has
    /// already written its freelist bookkeeping into the same bytes.
    /// `attach::secret::drop_witness` is pushed to by the `Drop` itself,
    /// *after* the zeroing loop and while the allocation is still ours.
    ///
    /// It is a unit test here and not in `tests/secrets.rs` because
    /// `#[cfg(test)]` is invisible from an integration target. The
    /// witness is thread-local, so this test observes its own drops and
    /// no other test's.
    ///
    /// The other half of the leak — copying the value into a plain
    /// `Vec<u8>` first — is closed structurally rather than here:
    /// `with_bytes` hands out a borrow and is the only accessor, and
    /// 0.0.6 makes reintroducing an owning one a mutation target of its
    /// own (`source_guards::the_write_channel_carries_the_secret_as_itself`).
    #[test]
    fn the_resolved_value_is_zeroed_after_the_write() {
        let dir = ScriptDir::new("zeroed");
        let script = dir.script("printf 'hunter2\\n'\n");

        drop_witness::reset();
        let secret = resolve_with(
            &ScriptProvider::new("pass", &script),
            "work/db",
            &SecurityConfig::default(),
            true,
        )
        .expect("the fixture resolves");

        // The write, as the writer thread does it: the bytes are lent for
        // the duration of the call and never escape — asserted *inside*
        // the closure rather than on a copy it returns, because a copy is
        // the very thing this module is not allowed to make.
        let len = secret.len();
        secret.with_bytes(|b| assert_eq!(b, b"hunter2\n", "the fixture's value did not arrive"));
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
             something other than the resolved value"
        );
        assert!(
            seen[0].iter().all(|b| *b == 0),
            "the resolved value survived its own Drop: {:?}",
            String::from_utf8_lossy(&seen[0])
        );
        // The pairing, and the reason the row above is not satisfied by a
        // `Drop` that truncates: the witness is capable of holding a
        // non-zero buffer, and does when it is handed one.
        drop_witness::record(b"hunter2");
        let control = drop_witness::taken();
        assert_eq!(control, vec![b"hunter2".to_vec()]);
    }

    // ------------------------------------------------------- fixtures
    //
    // Duplicated in spirit with `tests/secrets.rs`, which cannot see
    // anything `#[cfg(test)]`. Kept minimal here: the one row that has to
    // live in the library target is the witness assertion above.

    /// A scratch directory that removes itself **on unwind as well as on
    /// success**. Measured during this task's own mutation ladder: with
    /// the removal written as a statement at the end of the row, every
    /// injected mutation that reddened it left a `/tmp/holdfast-provider-*`
    /// behind — four of them, against a plan whose Global Constraint 11
    /// sweeps exactly that pattern.
    struct ScriptDir(PathBuf);

    impl ScriptDir {
        fn new(tag: &str) -> Self {
            let unique = uuid::Uuid::new_v4().simple().to_string();
            let dir = PathBuf::from(format!("/tmp/holdfast-provider-{tag}-{}", &unique[..8]));
            std::fs::create_dir_all(&dir).expect("create the fixture directory");
            Self(dir)
        }

        fn script(&self, body: &str) -> PathBuf {
            let path = self.0.join("provider.sh");
            std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("write the fixture");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod the fixture");
            }
            path
        }
    }

    impl Drop for ScriptDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ------------------------------------------------------- the argv

    /// The four templates, executed against nothing. Kept beside the
    /// integration copy on purpose: this one runs in the library target,
    /// where a `cargo test -p holdfast-core --lib` still pins the argv.
    #[test]
    fn the_four_argv_templates_are_pinned_here_too() {
        assert_eq!(
            ArgvProvider::SecretService.argv(ATTR_REFERENCE).unwrap(),
            vec![
                "secret-tool",
                "lookup",
                "service",
                "holdfast",
                "account",
                "prod-ssh"
            ]
        );
        assert_eq!(
            ArgvProvider::Keychain.argv(ATTR_REFERENCE).unwrap(),
            vec![
                "security",
                "find-generic-password",
                "-s",
                "holdfast",
                "-a",
                "prod-ssh",
                "-w"
            ]
        );
        assert_eq!(
            ArgvProvider::Pass.argv("work/db").unwrap(),
            vec!["pass", "show", "work/db"]
        );
        assert_eq!(
            ArgvProvider::OnePassword.argv("op://v/i/f").unwrap(),
            vec!["op", "read", "op://v/i/f"]
        );
    }

    /// The reference shapes each template refuses. Without these the
    /// templates above are satisfied by a builder that emits its flags
    /// and then whatever it was given.
    #[test]
    fn a_reference_the_template_cannot_address_an_item_with_is_refused() {
        for (provider, reference) in [
            // No `=` at all.
            (ArgvProvider::SecretService, "holdfast"),
            // A pair with an empty half.
            (ArgvProvider::SecretService, "service="),
            (ArgvProvider::SecretService, "=holdfast"),
            (ArgvProvider::SecretService, ""),
            // `keychain` needs both of its two, and only those two.
            (ArgvProvider::Keychain, "service=holdfast"),
            (ArgvProvider::Keychain, "account=prod-ssh"),
            (ArgvProvider::Keychain, "service=a,account=b,extra=c"),
            (ArgvProvider::Keychain, "service=a,service=b"),
            // A path-addressed store still needs a path.
            (ArgvProvider::Pass, ""),
            (ArgvProvider::OnePassword, ""),
        ] {
            let got = provider.argv(reference);
            assert_eq!(
                got,
                Err(ProviderError::MalformedReference {
                    provider: provider.as_str().to_string()
                }),
                "{} accepted {reference:?}",
                provider.as_str()
            );
            // Rule 3, on the error type itself: the reference is not in
            // the message, whatever the message says.
            let rendered = got.unwrap_err().to_string();
            assert!(
                reference.is_empty() || !rendered.contains(reference),
                "the reference reached an error message: {rendered}"
            );
        }
        // The pairing: a value containing `=` survives whole, so the
        // split is on the first `=` and not on every one.
        assert_eq!(
            ArgvProvider::Pass.argv("work/db=1").unwrap(),
            vec!["pass", "show", "work/db=1"]
        );
        assert_eq!(
            ArgvProvider::SecretService.argv("token=a=b").unwrap(),
            vec!["secret-tool", "lookup", "token", "a=b"]
        );
    }

    #[test]
    fn the_five_config_spellings_round_trip_and_nothing_else_parses() {
        for p in ArgvProvider::ALL {
            assert_eq!(ArgvProvider::from_config(p.as_str()), Ok(p));
        }
        assert_eq!(
            ArgvProvider::ALL.map(|p| p.as_str()),
            [
                "secret-service",
                "keychain",
                "pass",
                "onepassword",
                "wincred"
            ]
        );
        for wrong in ["Keychain", "secret_service", "1password", "", "prompt"] {
            assert_eq!(
                ArgvProvider::from_config(wrong),
                Err(ProviderError::UnknownProvider(wrong.to_string())),
                "{wrong:?} parsed as a provider"
            );
        }
    }
}
