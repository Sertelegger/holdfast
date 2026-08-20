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
/// Only `ScriptProvider` names a path, and it is `#[cfg(test)]`.
#[cfg(test)]
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
/// Tests inject a `ScriptProvider` (`#[cfg(test)]`, below) running a
/// file the test itself wrote — REQ-TST-007: no test in this project may depend on a
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
///
/// **`#[cfg(test)]`, and that is load-bearing rather than tidiness.**
/// This type plus [`resolve_with`] was, between them, a *public* API
/// meaning *"spawn this program with this argument as a secret
/// provider"* — in the one module whose entire premise (REQ-SEC-012's
/// structural half) is that no such signature exists. `holdfast-core` has
/// no `publish = false`, so `pub` here was a genuinely published surface
/// and not merely a workspace-internal one (review I-2).
///
/// `pub(crate)` would have been enough to close that. `#[cfg(test)]` is
/// what it is instead, because the type has exactly one caller — this
/// file's own tests — and a type that can name any program on the
/// filesystem should not merely be *unreachable* in a shipped daemon, it
/// should not be **in** one. The consequence is that every behavioural
/// row for this module lives in this file's `#[cfg(test)]` module rather
/// than in `tests/secrets.rs`; that is the price of the narrowing and it
/// is worth paying.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct ScriptProvider {
    name: String,
    path: PathBuf,
}

#[cfg(test)]
impl ScriptProvider {
    pub(crate) fn new(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
        }
    }
}

#[cfg(test)]
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
/// **This is the module's only public entry point, and its only input is
/// a `&SecretBinding`.** Inside the daemon a `SecretBinding` comes from
/// config deserialisation and from nowhere else, which is REQ-SEC-012's
/// **agent-facing** half: no MCP argument reaches this function, because
/// nothing on that path can build one. That claim is about the daemon's
/// call graph, and Task 10's `binding::select` is where it is enforced.
///
/// **What the *signature* closes is the arbitrary-program half, and only
/// that** — the sentence that used to stand here said the signature
/// admitted no caller-supplied string at all, and that was wrong.
/// [`SecretBinding`]'s fields are all `pub` and the struct is not
/// `#[non_exhaustive]`, so out of the crate
/// `resolve(&SecretBinding { reference: <any string>, .. }, …)` compiles
/// and carries that string to a lookup. What no caller can choose is the
/// **program**: `binding.provider` is matched against §9.6's five
/// spellings by [`ArgvProvider::from_config`] and anything else is
/// refused, so a reference can only ever become one argument to one of
/// five fixed argv templates — never a command line, and never a program
/// name.
///
/// **Naming a program is a separate seam, and it is named rather than
/// implied.**
/// [`resolve_with`] takes a `&dyn SecretProvider` and a bare `&str`, and
/// `ScriptProvider` can name any program on the filesystem. `resolve_with`
/// is `pub(crate)` and `ScriptProvider` is `#[cfg(test)]`, so the
/// program half stays closed to the published API and is not compiled
/// into a release at all; the claim is *"nothing outside this crate can
/// name a program, and the arbitrary-program half is not in a shipped
/// daemon"*, not *"the seam does not exist"*. Both visibilities are
/// pinned by `tests/source_guards.rs`'s
/// `the_arbitrary_program_seam_is_still_out_of_the_published_api`, because
/// a structural claim enforced only by review is one revision from being
/// untrue. Whoever wires the autofill path (Task 10) inherits the
/// obligation that the only string reaching `resolve_with` is a binding's
/// own `reference`.
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
/// `ScriptProvider` at, and the whole of the subprocess boundary.
///
/// **`pub(crate)`.** See [`resolve`]: this signature is the one an
/// agent-supplied string must never reach, so it is not offered to
/// anyone who is not this crate.
pub(crate) fn resolve_with(
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

    // **Rule 5's other half: the child leads its own process group.**
    //
    // `pass` is not a program, it is a shell script, and `pass show`
    // forks `gpg`, which forks `pinentry` and blocks on it — which is the
    // exact scenario rule 5's timeout exists for. `Child::kill` signals
    // the direct child only, so a timeout without this would kill the
    // `pass` shell and leave `gpg` and `pinentry` running unattended,
    // holding a tty or a GUI grab. `op read`'s biometric helper is the
    // same shape. Worse, the grandchild inherits the stdout pipe's write
    // end, so the reader thread — dropped rather than joined on the
    // timeout path, deliberately — would survive holding a **possibly
    // partial resolved value, un-zeroed**, for as long as the grandchild
    // lives. That is a secret buffer whose lifetime is bounded by a
    // process Holdfast has just decided it cannot control.
    //
    // `process_group(0)` makes the child its own group leader, so the
    // timeout can signal `-pid` and take the helpers with it. Detaching
    // the child from the daemon's group is the intended consequence: a
    // provider must not receive the terminal signals of whatever launched
    // the daemon.
    //
    // **It is not pure benefit, and the cost has one shape: the daemon
    // dying mid-resolve.** The timeout above is the only thing that
    // reaps this group, and it runs in *this* thread — so a daemon killed
    // between the spawn and the deadline leaves the provider and
    // everything it forked running, in a group nothing will ever signal,
    // because the group is no longer one the daemon's own killer reaches.
    // Before this call they were in the daemon's group and a
    // `kill(-daemon_pgid)` swept them for free. **Closing the pipes is no
    // substitute**: the concrete case is `pass` blocked on `pinentry`,
    // which is waiting for a human and has written nothing, so it never
    // reaches a `write` and never takes the `EPIPE`/`SIGPIPE` that would
    // end it — it sits on the tty or the GUI grab indefinitely. The trade
    // is still right (an unreapable group after a daemon kill is rarer
    // and less harmful than an unkillable one on every timeout), but a
    // daemon-exit sweep of outstanding provider groups is the thing that
    // would close it, and nothing here is that.
    //
    // §4.4 records that even `killpg` leaks a child that put *itself*
    // into a new group, which is why `terminate` does a session sweep for
    // PTY children. A provider is not a session and gets no sweep; this
    // closes the ordinary case (a fork that inherits the group) and not
    // that one.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    // **The `#[cfg(windows)]` seam goes here** — 0.0.11's. The Windows
    // counterpart is a job object with
    // `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, assigned to the child at
    // spawn, which §4.1 already names as this project's Windows answer to
    // process-group semantics. Not written blind: nothing in this
    // milestone compiles for Windows, and an uncompiled `#[cfg]` arm is
    // worse than a named gap.

    // **Not a branch, and not a behaviour: a lock acquisition that is
    // compiled out entirely.** See [`exec_guard`] for the hazard. It is
    // sited here because this is the only `fork` in the module, and the
    // hazard is a fork racing another thread's *write* — so the guard has
    // to be at the fork, wherever the writing happens.
    //
    // **Block-scoped, and that is load-bearing rather than style.** Bound
    // at function scope it would be held across the whole `try_wait`
    // polling loop below — up to the full budget — and
    // `parking_lot::RwLock` is task-fair, so one fixture write waiting on
    // the write lock would then block every fork queued behind it. This
    // file's own rows deliberately park a provider on a gate file for
    // about a second each. The lock covers the fork and nothing else.
    let spawned = {
        #[cfg(test)]
        let _no_writer_is_open = exec_guard::spawning();
        cmd.spawn()
    };
    let mut child = spawned.map_err(|e| ProviderError::NotStarted {
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
        // Rule 5: kill the child **and everything it forked**, then reap
        // it here so the daemon does not accumulate zombies over a
        // session's lifetime.
        //
        // The group goes first and while the child is still un-reaped:
        // the group id is the child's pid, and a pid that has been waited
        // for can be recycled, so signalling `-pid` after the reap is a
        // signal at whatever now holds that number.
        kill_group(&child);
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

/// The `ETXTBSY` interlock for tests that write a program and then run it.
///
/// **The hazard is not ours-and-ours-alone, which is why the remedy cannot
/// be local to a fixture writer.** `execve(2)` answers `ETXTBSY` when the
/// file is open for writing by *any* process. Rust's `Command::spawn`
/// forks, and a fork inherits every fd open for writing at that instant —
/// **including `O_CLOEXEC` ones**, because close-on-exec is processed after
/// the kernel's `ETXTBSY` check (rust-lang/rust#39237). So thread A writing
/// `a.sh` while thread B forks leaves B's child holding a write fd to
/// `a.sh`; if A execs `a.sh` before B reaches its own `execve`, **A** gets
/// `ETXTBSY` — a failure in A caused by B, for a file B has never heard of.
///
/// That is why the obvious fixture-side fixes do not work, and they were
/// measured rather than assumed: writing to a temporary name and
/// `rename`ing it into place leaves the inherited fd pointing at the same
/// **inode**, and an explicit `drop` + `fsync` before `chmod` only
/// guarantees *our* fd is closed, which was never the one at fault.
///
/// One refinement to the mechanism, which does not change any of that:
/// `fork` does not itself bump `i_writecount`. It duplicates the descriptor
/// table, so the **writer's** write-mode `struct file` outlives the
/// writer's own `close`, and the count is not released until the last
/// reference drops. The offending reference is in another process either
/// way, and cannot be closed from ours.
///
/// What does work is making the two operations mutually exclusive:
/// **writers take the write lock, and forks take the read lock.** Spawns
/// still run concurrently with each other, and both critical sections are
/// microseconds — the write is one `fs::write`, and `Command::spawn`
/// returns once the child has exec'd or reported failure, so the waiting on
/// a provider is outside the lock (which is why every site here is
/// **block**-scoped, `run()`'s included).
///
/// ## What it guarantees, exactly
///
/// **It is a two-sided protocol, and it only protects a pair where both
/// sides opt in: "no *guarded* fork overlaps a *guarded* write".** Not "no
/// fork can happen while a fixture write fd is open" — that is false of
/// this binary and would be an overclaim of the kind this module is
/// otherwise careful about. An unguarded **writer** is exposed to every
/// fork in the process, guarded ones included; an unguarded **fork** can
/// still break a guarded writer.
///
/// The four sites that do opt in are `run()`'s `cmd.spawn`, both test
/// helpers' `InProcessPty::spawn`, and the canary row's `/bin/sh` control.
/// Named because it is a live gap rather than a theoretical one:
/// **`daemon::spawn::tests::env_probe` is the same write-then-exec shape
/// and takes no lock** — a *writer*, which is the more dangerous of the two
/// roles — and an `ETXTBSY` on its `probe.sh` was observed at ~0.5 % per
/// full-lib run, at the **same rate with and without this guard**. It is
/// pre-existing, it is not caused or worsened here, and it is tracked
/// separately. `pty/in_process.rs`'s three test PTY spawns,
/// `mcp/tools.rs`'s `start_session` spawn and `diag.rs`'s subprocess row
/// are forks only.
///
/// ## Measured
///
/// The claim this carries is *"the `secret::` rows are closed"*, and it is
/// the suite's own numbers that carry it, not the arithmetic below. In the
/// configuration the flake was originally reported in — full lib target,
/// default threads — the `secret::`-attributable count goes **6/200 → 0/200**;
/// in the hot configuration (`secret::` at 256 threads), **18/250 → 0/250**,
/// both arms run interleaved under identical load. A standalone reproducer
/// of the same shape gives 600–661 `ETXTBSY` per 6400 unguarded and 0 per
/// 19200 guarded, which is corroboration of the kernel behaviour rather
/// than evidence about this suite: it exercises neither `portable-pty`'s
/// `forkpty` nor tokio's `spawn_blocking` pool, and those are what the
/// "a PTY spawn is a fork too" half rests on.
///
/// What makes the closure a *construction* rather than a probability is
/// that the remedy is a mutual exclusion; run counts alone could not
/// separate zero from a one-percent residual.
///
/// `#[cfg(test)]`, so a release build contains none of it.
#[cfg(test)]
pub(crate) mod exec_guard {
    use std::sync::OnceLock;

    use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};

    fn lock() -> &'static RwLock<()> {
        static LOCK: OnceLock<RwLock<()>> = OnceLock::new();
        LOCK.get_or_init(|| RwLock::new(()))
    }

    /// Hold this across writing a file that will later be executed —
    /// the whole of it, until the writing fd is closed.
    pub(crate) fn writing() -> RwLockWriteGuard<'static, ()> {
        lock().write()
    }

    /// Hold this across a `fork`, so it cannot inherit a write fd to
    /// somebody else's fixture.
    pub(crate) fn spawning() -> RwLockReadGuard<'static, ()> {
        lock().read()
    }
}

/// SIGKILL the process group the child leads, taking its forks with it.
///
/// Negative pid means "the group" to `kill(2)` — the same spelling
/// `pty::in_process::killpg` uses, kept as its own function here so the
/// `#[cfg]` split is one place rather than inline in the timeout path.
/// Errors are dropped: `ESRCH` means the group is already gone, which is
/// the outcome being asked for.
///
/// **The non-Unix body is a no-op and the caller's `Child::kill` is the
/// whole of the teardown there** — see the `#[cfg(windows)]` seam note at
/// the spawn site.
#[cfg(unix)]
fn kill_group(child: &std::process::Child) {
    // `process_group(0)` at spawn made the child its own group leader, so
    // its pid *is* the group id.
    let pid = child.id() as i32;
    if pid > 1 {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
}

#[cfg(not(unix))]
fn kill_group(_child: &std::process::Child) {}

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
    // **Every behavioural row for this module is here rather than in
    // `tests/secrets.rs`, and that is review I-2's remedy rather than a
    // preference.** `resolve_with` is `pub(crate)` and `ScriptProvider`
    // is `#[cfg(test)]`,
    // because together they are a public signature meaning "spawn this
    // program with this argument as a secret provider" inside the module
    // whose premise is that no such signature exists; an integration
    // target cannot see `pub(crate)`, so the rows follow the seam.
    // `tests/secrets.rs` keeps the one row that executes nothing.

    /// A scratch directory that removes itself **on unwind as well as on
    /// success**, plus any stray path a row created outside it. Measured
    /// during this task's own mutation ladder: with the removal written
    /// as a statement at the end of the row, every injected mutation that
    /// reddened it left a `/tmp/holdfast-provider-*` behind — four of
    /// them, against a plan whose Global Constraint 11 sweeps exactly
    /// that pattern.
    struct ScriptDir {
        dir: PathBuf,
        extra: Vec<PathBuf>,
    }

    impl ScriptDir {
        fn new(tag: &str) -> Self {
            let unique = uuid::Uuid::new_v4().simple().to_string();
            let dir = PathBuf::from(format!("/tmp/holdfast-provider-{tag}-{}", &unique[..8]));
            std::fs::create_dir_all(&dir).expect("create the fixture directory");
            Self {
                dir,
                extra: Vec::new(),
            }
        }

        fn script(&self, body: &str) -> PathBuf {
            self.named_script("provider.sh", body)
        }

        fn named_script(&self, name: &str, body: &str) -> PathBuf {
            let path = self.dir.join(name);
            // See [`exec_guard`]: the write fd this opens is inheritable by
            // any *other* thread's `fork`, and the row it then breaks is
            // that other thread's, not this one's.
            let guard = exec_guard::writing();
            std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("write the fixture");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod the fixture");
            }
            drop(guard);
            path
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.join(name)
        }
    }

    impl Drop for ScriptDir {
        fn drop(&mut self) {
            for p in &self.extra {
                let _ = std::fs::remove_file(p);
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// `[security]` with one knob moved. Built in Rust rather than from a
    /// TOML fixture on purpose: `keychain_provider_timeout_secs` has no
    /// §10.2 line to copy (it is one of 0.0.7's three additive keys, Q4),
    /// and `config.rs`'s own default-fold test already pins that it loads
    /// and defaults to 10.
    fn provider_limits(secs: u32) -> SecurityConfig {
        SecurityConfig {
            keychain_provider_timeout_secs: secs,
            ..SecurityConfig::default()
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// The one echo-off fixture (Global Constraint 14), **and an
    /// assertion that this copy is the same one**.
    ///
    /// GC14's requirement is one spelling everywhere, and the spelling
    /// this repo actually uses lives in `tests/secrets.rs`. An
    /// integration target and a library target cannot share a constant,
    /// so the copy is pinned to the original by reading the original's
    /// source — the `tests/source_guards.rs` idiom for a guarantee that
    /// is invisible from inside the program. See
    /// `the_echo_off_fixture_here_is_the_one_in_the_integration_suite`.
    ///
    /// Not `read -s`: rev. 36's classification has an **ICANON** rung, and
    /// `sh` is `dash` on most CI images, where `read -s` neither exists
    /// nor fails loudly. It prints its prompt because the `AwaitingSecret`
    /// edge is computed per read chunk, and it prints a *transform* of
    /// what it read so arrival is assertable without the value ever being
    /// printed.
    const ECHO_OFF_FIXTURE: &str = "stty -echo; printf 'Password: '; read x; stty echo; \
     printf 'got=%s\\n' \"$(printf %s \"$x\" | tr a-z A-Z)\"";

    /// A value matching **no** built-in redaction rule, so an absence
    /// assertion over it cannot pass because a redactor got there first.
    const PROBE: &str = "hunter2";

    /// A session on a real PTY — echo comes from the tty and not from us.
    /// No daemon and no registry: nothing below asserts on a socket.
    fn shell_session(script: &str) -> std::sync::Arc<crate::session::Session> {
        use crate::pty::{InProcessPty, PtyBackend, PtySpawnConfig};
        use crate::session::{new_session_id, Session, SessionConfig};
        let mut cfg = PtySpawnConfig::new("sh");
        cfg.args = vec!["-c".to_string(), script.to_string()];
        // A PTY spawn is a `fork`, and [`exec_guard`] is about forks —
        // see `secret::binding`'s `session_running` for the measurement.
        let pty = {
            let _no_writer_is_open = exec_guard::spawning();
            InProcessPty::spawn(&cfg).expect("spawn a real shell")
        };
        Session::new(
            new_session_id(),
            None,
            "sh".into(),
            cfg.args.clone(),
            std::sync::Arc::new(pty) as std::sync::Arc<dyn PtyBackend>,
            SessionConfig::with_buffer_capacity(256 * 1024),
        )
    }

    /// Put a resolved value on §4.3's write queue exactly as
    /// `attach::conn`'s `SecretInput` arm does, and answer with the count
    /// the PTY took — the number `Resolution::Provided { bytes_written }`
    /// carries.
    async fn write_secret(s: &crate::session::Session, secret: SecretBytes) -> usize {
        let (req, ack) = crate::session::WriteRequest::secret(secret);
        s.write_queue()
            .send(req)
            .await
            .expect("the write queue accepted");
        ack.await
            .expect("the writer answered")
            .expect("the PTY took the write")
    }

    fn buffered(s: &crate::session::Session) -> Vec<u8> {
        s.buffer_slice(s.buffer_tail(), s.buffer_head())
    }

    /// Poll the ring buffer until `needle` shows up, or fail.
    async fn buffer_until(s: &crate::session::Session, needle: &[u8], secs: u64) -> Vec<u8> {
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

    /// Wait until the child has dropped `ECHO`, observed through its own
    /// prompt — which `ECHO_OFF_FIXTURE` prints *after* `stty -echo`.
    /// Writing before that point would be echoed back into the ring
    /// buffer by the line discipline, which would fail the leak
    /// assertions for a reason that has nothing to do with the provider.
    async fn await_echo_off(s: &crate::session::Session) {
        buffer_until(s, b"Password: ", 20).await;
    }

    /// `resolve_with` off the async runtime. It blocks — it waits on an
    /// OS process — so a `#[tokio::test]` calling it inline would block
    /// the current-thread runtime the rest of the row needs.
    async fn resolve_off_thread(
        provider: ScriptProvider,
        reference: &str,
        limits: SecurityConfig,
        append_newline: bool,
    ) -> Result<SecretBytes, ProviderError> {
        let reference = reference.to_string();
        tokio::task::spawn_blocking(move || {
            resolve_with(&provider, &reference, &limits, append_newline)
        })
        .await
        .expect("the resolve task")
    }

    /// `kill(pid, 0)` — the POSIX liveness probe. Delivers nothing and
    /// answers `ESRCH` once the process is both dead and reaped.
    #[cfg(unix)]
    fn alive(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }

    /// Poll until `pid` is gone, or give up. Bounded so a surviving
    /// process is a red row rather than a hung job.
    #[cfg(unix)]
    async fn wait_gone(pid: i32) -> bool {
        for _ in 0..100 {
            if !alive(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[cfg(unix)]
    fn read_pid(path: &std::path::Path) -> i32 {
        let pid: i32 = std::fs::read_to_string(path)
            .expect("the fixture recorded its pid")
            .trim()
            .parse()
            .expect("a pid");
        assert!(pid > 1, "the fixture recorded a nonsense pid: {pid}");
        pid
    }

    /// Redirect this process's fd 2 into `path` for the duration of `f`.
    ///
    /// fd-level and not `eprintln!`-level because `diag::emit` writes
    /// through `std::io::stderr()` precisely to bypass libtest's capture
    /// — the daemon's diagnostics are the thing under test in more than
    /// one place in this repo, and a capture that ate them would make
    /// those tests lie.
    ///
    /// **The restore is a `Drop` and not a statement after the call.**
    /// libtest runs rows on threads of one process, and an `f` that
    /// panicked with the restore written inline would leave every other
    /// row's stderr pointing at a file this function is about to delete.
    ///
    /// **The redirect is process-wide while it is up** (review M-2, and
    /// now in a 750-row binary rather than a 45-row one). Two things make
    /// that safe and both must stay true: the window is one
    /// `resolve_with` call, and the only other test in this crate that
    /// asserts on stderr —
    /// `diag::tests::nothing_reaches_daemon_log_unredacted_not_even_a_panic`
    /// — reads a **subprocess's** fd 2 out of a file and is therefore
    /// immune. A second in-process stderr-asserting row and this helper
    /// cannot coexist; whoever adds one moves this to the subprocess
    /// idiom `diag.rs` already uses.
    #[cfg(unix)]
    fn with_captured_stderr<R>(path: &std::path::Path, f: impl FnOnce() -> R) -> (R, String) {
        use std::os::unix::io::AsRawFd;

        struct Restore(std::os::raw::c_int);
        impl Drop for Restore {
            fn drop(&mut self) {
                unsafe {
                    libc::dup2(self.0, 2);
                    libc::close(self.0);
                }
            }
        }

        let file = std::fs::File::create(path).expect("create the capture file");
        let saved = unsafe { libc::dup(2) };
        assert!(saved >= 0, "dup(2) failed");
        let restore = Restore(saved);
        assert!(
            unsafe { libc::dup2(file.as_raw_fd(), 2) } >= 0,
            "dup2 onto fd 2 failed"
        );
        let out = f();
        drop(restore);
        drop(file);
        (
            out,
            std::fs::read_to_string(path).expect("read the capture"),
        )
    }

    /// GC14, executed: this file's `ECHO_OFF_FIXTURE` and the integration
    /// suite's are the same string.
    ///
    /// Two targets cannot share a constant, and a comment saying "keep
    /// these in sync" is what drift looks like the day before it
    /// happens. So the copy is checked against the original's **source
    /// text**, the same way `tests/source_guards.rs` checks the things
    /// that are invisible from inside the program.
    #[test]
    fn the_echo_off_fixture_here_is_the_one_in_the_integration_suite() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let theirs = declared_echo_off_fixture(&manifest.join("tests").join("secrets.rs"));
        let ours =
            declared_echo_off_fixture(&manifest.join("src").join("secret").join("provider.rs"));
        assert_eq!(
            ours, theirs,
            "GC14: two spellings of the one echo-off fixture"
        );
        // Two pairings, because the row above is satisfied by an
        // extractor that returns the same wrong thing twice: what it
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
    ///
    /// Source text rather than the decoded value on purpose: GC14's
    /// requirement is that the fixture is *spelled* one way, so comparing
    /// two source spellings is the stricter and the simpler check — it
    /// needs no Rust unescaper, and a copy that wrote `\n` where the
    /// original wrote `\\n` would differ here as it should.
    fn declared_echo_off_fixture(path: &std::path::Path) -> String {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let (_, after) = text
            .split_once("const ECHO_OFF_FIXTURE: &str = ")
            .unwrap_or_else(|| panic!("{} no longer declares it", path.display()));
        let decl = after.split_once(";\n").expect("the declaration ends").0;

        let mut out = String::new();
        let mut it = decl.chars().peekable();
        while let Some(c) = it.next() {
            if c == '\\' && it.peek() == Some(&'\n') {
                it.next();
                while it.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
                    it.next();
                }
            } else {
                out.push(c);
            }
        }
        out
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

    // ------------------------------------------- the behavioural rows
    //
    // Moved here from `tests/secrets.rs` by review I-2: they inject a
    // `ScriptProvider` through `resolve_with`, both of which are now
    // `pub(crate)` and therefore invisible from an integration target.
    //
    // **What the move cost, stated rather than absorbed.** Two of these
    // rows (`…_fails_falls_through_…`, `…_hangs_is_killed_…`) previously
    // finished by driving a real `attach.sock` client and a
    // `request_secret_input` call. That half was never guarded: across
    // the ten injections of this task's mutation ladder and the five of
    // the review's independent one, **no mutation was ever killed by the
    // socket half** — M5 died on the `Failed` discriminant, M6a on the
    // elapsed-time ceiling, M6b on the process assertion. It could not
    // have been guarded, either: `resolve_with` touches no daemon state,
    // so "the prompt path still works afterwards" is true of an
    // implementation that never ran a provider at all. The fall-through
    // is now asserted where it *is* falsifiable — at the session, on the
    // bytes the child receives — and the broadcast half stays covered by
    // the seven `AwaitingSecret` rows already in `tests/secrets.rs`.

    /// **Two halves, because the argv half executes nothing and so cannot
    /// exercise a canary at all.**
    ///
    /// (a) the built argv carries the whole string as one element; (b) the
    /// same reference against a script provider that really is spawned,
    /// with a canary file whose path the reference tries to `rm -rf`.
    /// Without (b) the canary asserts nothing, because nothing ran.
    #[test]
    fn a_reference_with_shell_metacharacters_is_not_interpreted() {
        let mut fx = ScriptDir::new("meta");
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let canary = PathBuf::from(format!("/tmp/holdfast-canary-{}", &unique[..8]));
        std::fs::write(&canary, b"alive").expect("create the canary");
        fx.extra.push(canary.clone());

        let reference = format!("work/db; rm -rf {}", canary.display());

        // (a) — the whole string, as one element.
        assert_eq!(
            ArgvProvider::Pass.argv(&reference).unwrap(),
            vec!["pass".to_string(), "show".to_string(), reference.clone()],
            "the reference was split, quoted or interpolated"
        );

        // (b) — really spawned. The fixture records its `$1` so the argv
        // is assertable from the child's side too: a `sh -c` boundary
        // would give it `work/db` and run the rest as a command.
        let seen = fx.path("argv1");
        let script = fx.named_script(
            "meta.sh",
            &format!(
                "printf '%s' \"$1\" > '{}'\nprintf 'hunter2\\n'\n",
                seen.display()
            ),
        );
        let value = resolve_with(
            &ScriptProvider::new("pass", &script),
            &reference,
            &provider_limits(10),
            false,
        )
        .expect("the fixture resolves");
        assert_eq!(value.len(), 7, "the fixture's value did not arrive intact");

        assert!(
            canary.exists(),
            "the reference reached a shell: {} is gone",
            canary.display()
        );
        assert_eq!(
            std::fs::read_to_string(&seen).expect("the fixture recorded its argv"),
            reference,
            "the provider saw something other than the whole reference as $1"
        );
        // The pairing, and the reason the canary means anything: the same
        // string really would have deleted the file had a shell seen it.
        // Another `fork`, so another [`exec_guard`] site.
        let control_ok = {
            let _no_writer_is_open = exec_guard::spawning();
            std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("true {reference}"))
                .status()
                .expect("the control shell ran")
                .success()
        };
        assert!(control_ok, "the control could not run");
        assert!(
            !canary.exists(),
            "the control did not delete the canary, so the assertion above was \
             asserting nothing"
        );
    }

    /// **The positive control for every absence assertion in this
    /// module.**
    ///
    /// A provider that answers is a provider whose value reaches the
    /// child. Without this row, a resolver that returned `Ok` with an
    /// empty value satisfies "the value is not in the buffer", "not in
    /// the log" and "not in the response" perfectly.
    #[tokio::test]
    async fn a_provider_that_returns_a_value_resolves_it_to_the_child() {
        let s = shell_session(ECHO_OFF_FIXTURE);
        await_echo_off(&s).await;

        let fx = ScriptDir::new("ok");
        let script = fx.script("printf 'hunter2\\n'\n");
        let value = resolve_off_thread(
            ScriptProvider::new("pass", &script),
            "work/db",
            provider_limits(10),
            true,
        )
        .await
        .expect("a provider that prints a value resolves it");
        assert_eq!(
            value.len(),
            PROBE.len() + 1,
            "seven bytes plus the appended newline"
        );

        // Task 10's `Ok(v) => write it`, made here because nothing calls
        // `resolve` yet.
        assert_eq!(write_secret(&s, value).await, PROBE.len() + 1);

        // The child transformed what it read, which is how arrival is
        // asserted without the value ever being printed.
        let seen = buffer_until(&s, b"got=HUNTER2", 20).await;
        // ...and the value itself is not in the buffer, because the line
        // discipline had ECHO off when it arrived. This is the pairing
        // that separates "the provider resolved" from "the provider
        // echoed".
        assert!(
            !contains(&seen, PROBE.as_bytes()),
            "the resolved value reached the ring buffer:\n{}",
            String::from_utf8_lossy(&seen)
        );
        let _ = s.signal(crate::pty::Signal::Kill);
    }

    /// §5.2's strip, over a provider's output rather than a client's.
    ///
    /// `pass show` and `security -w` both emit a trailing newline, and a
    /// password with one injected into a `getpass` read submits an empty
    /// second line. The trailing-**space** row is the one that separates
    /// "strip exactly one newline" from `trim_end()`, which corrupts a
    /// password ending in a space.
    #[tokio::test]
    async fn the_providers_trailing_newline_is_stripped_exactly_once() {
        let s = shell_session("cat");
        let fx = ScriptDir::new("strip");

        for (name, body, with, without) in [
            ("lf.sh", "printf 'hunter2\\n'\n", 8usize, 7usize),
            ("crlf.sh", "printf 'hunter2\\r\\n'\n", 8, 7),
            ("bare.sh", "printf 'hunter2'\n", 8, 7),
            // A value that legitimately ends in a space. `trim_end()`
            // makes this 8/7 and injects the wrong password.
            ("space.sh", "printf 'hunter2 \\n'\n", 9, 8),
        ] {
            let script = fx.named_script(name, body);
            for (append, expect) in [(true, with), (false, without)] {
                let value = resolve_off_thread(
                    ScriptProvider::new("pass", &script),
                    "work/db",
                    provider_limits(10),
                    append,
                )
                .await
                .expect("the fixture resolves");
                assert_eq!(
                    value.len(),
                    expect,
                    "{name} with append_newline={append}: wrong normalised length"
                );
                // ...and the same number really is what the PTY takes,
                // which is the number `bytes_written` reports to the
                // agent.
                assert_eq!(
                    write_secret(&s, value).await,
                    expect,
                    "{name} with append_newline={append}: wrong byte count written"
                );
            }
        }
        let _ = s.signal(crate::pty::Signal::Kill);
    }

    /// §9.6's fall-through (Q4): a locked keyring is **not** a call
    /// failure.
    ///
    /// The flow it protects has a human fallback by design, and turning a
    /// non-zero exit into a hard error would make an unlocked-keyring
    /// requirement out of a convenience.
    ///
    /// **What is guarded and what is not.** The mutation this row kills
    /// is the *classification* — a non-zero exit produces `Err(Failed)`
    /// and not `Ok(whatever it printed)`. The *dispatch* it is named for
    /// (`Err(_) => prompt` rather than `Err(_) => tool error`) does not
    /// exist yet: nothing in the daemon calls `resolve`, so the
    /// fall-through below is this test's own `match`, and Task 10 owes
    /// the plan's row verbatim when it owns the property.
    #[tokio::test]
    async fn a_provider_that_fails_falls_through_to_the_prompt_path() {
        let s = shell_session(ECHO_OFF_FIXTURE);
        await_echo_off(&s).await;

        let fx = ScriptDir::new("fail");
        let script = fx.script("printf 'gpg: decryption failed\\n' >&2\nexit 1\n");
        let err = resolve_off_thread(
            ScriptProvider::new("pass", &script),
            "work/db",
            provider_limits(10),
            true,
        )
        .await
        .expect_err("a provider that exits 1 must resolve nothing");
        match &err {
            ProviderError::Failed { provider, status } => {
                assert_eq!(provider, "pass");
                assert!(
                    status.contains('1'),
                    "the exit status is not named: {status}"
                );
            }
            other => panic!("a non-zero exit should be `Failed`, got {other:?}"),
        }

        // The failure wrote nothing to the child — the negative half, and
        // what separates "resolved nothing" from "resolved something
        // wrong". The child is still sitting on its echo-off read.
        assert!(
            !contains(&buffered(&s), b"got="),
            "the child completed its read on a provider that failed"
        );

        // Task 10's `Err(_) => prompt`, at the level where it is
        // falsifiable: the value a human then submits is written by
        // exactly the path `attach::conn`'s `SecretInput` arm uses, and
        // it still reaches the child.
        let submitted = SecretBytes::normalise(PROBE.as_bytes().to_vec(), true);
        assert_eq!(write_secret(&s, submitted).await, PROBE.len() + 1);
        let seen = buffer_until(&s, b"got=HUNTER2", 20).await;
        assert!(
            !contains(&seen, PROBE.as_bytes()),
            "the submitted value reached the ring buffer"
        );
        let _ = s.signal(crate::pty::Signal::Kill);
    }

    /// Rule 5. `op read` can block on a biometric prompt indefinitely,
    /// and it would be holding the session's **only** request slot while
    /// it did.
    ///
    /// Three assertions, each killing a different thing: the budget was
    /// used (not ignored, not skipped), the child is **gone**, and the
    /// child's **grandchild** is gone too.
    ///
    /// The grandchild is the one that matters and it is not hypothetical:
    /// `pass` is a shell script, `pass show` forks `gpg`, and `gpg` forks
    /// `pinentry` and blocks on it. `Child::kill` signals the direct
    /// child only, so without `process_group(0)` at spawn and a `-pid`
    /// signal here, the timeout kills the `pass` shell and leaves
    /// `pinentry` holding a GUI grab — and leaves the dropped stdout
    /// reader thread alive holding a **possibly partial resolved value,
    /// un-zeroed**, for as long as the grandchild lives.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_provider_that_hangs_is_killed_and_falls_through() {
        let s = shell_session(ECHO_OFF_FIXTURE);
        await_echo_off(&s).await;

        let fx = ScriptDir::new("hang");
        let pidfile = fx.path("pid");
        let gpidfile = fx.path("gpid");
        // `exec` on purpose: the recorded pid stays the pid of the
        // process that is actually sleeping, so "the child is gone" is a
        // claim about the thing that was killed rather than about a shell
        // that had already left a grandchild behind. The backgrounded
        // `sleep` **is** that grandchild — it inherits the group and the
        // stdout pipe, exactly as `gpg`/`pinentry` do under `pass`.
        let script = fx.named_script(
            "hang.sh",
            &format!(
                "echo $$ > '{}'\nsleep 60 &\necho $! > '{}'\nexec sleep 60\n",
                pidfile.display(),
                gpidfile.display()
            ),
        );

        let started = std::time::Instant::now();
        let err = tokio::time::timeout(
            Duration::from_secs(25),
            resolve_off_thread(
                ScriptProvider::new("op", &script),
                "op://v/i/f",
                provider_limits(1),
                true,
            ),
        )
        .await
        .expect("the 1 s budget never fired: the provider was not bounded at all")
        .expect_err("a provider that never answers must resolve nothing");
        let elapsed = started.elapsed();

        assert_eq!(
            err,
            ProviderError::TimedOut {
                provider: "op".to_string(),
                secs: 1
            }
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the 1 s budget was ignored and something larger was used: {elapsed:?}"
        );
        // The pairing: it really did wait, rather than refusing to run
        // the provider at all.
        assert!(
            elapsed >= Duration::from_millis(900),
            "the provider was never given its second: {elapsed:?}"
        );

        // The child is **gone**, not merely unwaited-for...
        let pid = read_pid(&pidfile);
        assert!(
            wait_gone(pid).await,
            "pid {pid} is still running: the timeout abandoned the child rather \
             than killing it"
        );
        // ...and so is what it forked, which `Child::kill` alone would
        // have left behind.
        let gpid = read_pid(&gpidfile);
        assert_ne!(gpid, pid, "the fixture recorded one process twice");
        assert!(
            wait_gone(gpid).await,
            "the grandchild {gpid} outlived the timeout: the kill was a single \
             pid and not the process group, so a real `pass` would leave `gpg` \
             and `pinentry` running — and the dropped stdout reader alive with \
             a partial value in it"
        );

        // The fall-through, at the level where it is falsifiable: the
        // session was never touched by the provider and a submitted value
        // still reaches the child.
        assert!(
            !contains(&buffered(&s), b"got="),
            "the child completed its read on a provider that hung"
        );
        let submitted = SecretBytes::normalise(PROBE.as_bytes().to_vec(), true);
        assert_eq!(write_secret(&s, submitted).await, PROBE.len() + 1);
        buffer_until(&s, b"got=HUNTER2", 20).await;
        let _ = s.signal(crate::pty::Signal::Kill);
    }

    /// Rule 3: the provider **name** and the exit status reach the log,
    /// and the reference and the provider's stderr do not.
    ///
    /// `pass`'s error messages contain the store path, which *is* the
    /// reference — so `String::from_utf8_lossy(&out.stderr)` in an error
    /// context, the natural thing to write, puts §9.6's one
    /// never-log-this value into a file that is kept for weeks.
    ///
    /// **`daemon.log` only, and the `audit.log` half now lives next to the
    /// code that writes one.** The plan's row named both. At Task 9 there
    /// was no provider outcome in the audit trail at all —
    /// `binding_resolved` is Task 10's — so the second assertion would
    /// have been an absence assertion against a file no implementation
    /// wrote to, which is Global Constraint 3's named decorative shape,
    /// and it was left out and recorded. **Task 10 discharged it:** see
    /// `secret::binding::tests::a_failing_providers_reference_and_stderr_reach_no_audit_line`,
    /// which drives a failing provider through `autofill` with a live
    /// `AuditLog` and asserts the trail carries neither the reference nor
    /// the stderr body — paired with the `secret_input_request` entry that
    /// proves the file it is absent from is populated. The debt is closed;
    /// this row keeps the `daemon.log` half, which is still its own.
    ///
    /// The capture is fd 2 itself: `diag::emit` writes to
    /// `std::io::stderr()` and deliberately bypasses libtest's capture,
    /// and on the daemon that fd *is* `daemon.log`.
    #[cfg(unix)]
    #[test]
    fn a_failing_providers_stderr_and_reference_reach_no_log() {
        let fx = ScriptDir::new("nolog");
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let marker = format!("STDERRMARKER{}", &unique[..8]);
        let reference = format!("work/REFERENCEMARKER{}", &unique[8..16]);

        // The fixture prints its own `$1` — the reference — and a
        // distinctive string to stderr, then exits 2.
        let script = fx.named_script(
            "stderr.sh",
            &format!("printf '%s\\n' \"$1\" >&2\nprintf '{marker}\\n' >&2\nexit 2\n"),
        );

        let capture = fx.path("stderr.txt");
        let (outcome, log) = with_captured_stderr(&capture, || {
            resolve_with(
                &ScriptProvider::new("pass", &script),
                &reference,
                &provider_limits(10),
                true,
            )
        });
        let err = outcome.expect_err("exit 2 must resolve nothing");
        let ProviderError::Failed { provider, status } = &err else {
            panic!("expected `Failed`, got {err:?}")
        };

        // The positive half. Without it, every absence below is satisfied
        // by a daemon that logs nothing at all.
        assert!(
            log.contains(&format!("`{provider}`")),
            "the provider is not named in the log:\n{log}"
        );
        assert!(
            log.contains(status.as_str()),
            "the exit status ({status}) is not in the log:\n{log}"
        );
        assert!(
            status.contains('2'),
            "the exit code is not in the status: {status}"
        );

        // The absences.
        assert!(
            !log.contains(&reference),
            "the reference reached daemon.log:\n{log}"
        );
        assert!(
            !log.contains(&marker),
            "the provider's stderr body reached daemon.log:\n{log}"
        );
        // ...and on the error value itself, which is what the *caller*
        // will log. No variant of `ProviderError` can carry either
        // string, and this is that claim executed.
        let rendered = format!("{err}");
        assert!(!rendered.contains(&reference), "{rendered}");
        assert!(!rendered.contains(&marker), "{rendered}");
        assert!(rendered.contains("pass"), "{rendered}");

        // The control that says the capture works at all: a string this
        // test knows was written to fd 2 during the window.
        assert!(
            !log.is_empty(),
            "nothing at all was captured, so neither absence above means anything"
        );
    }
}
