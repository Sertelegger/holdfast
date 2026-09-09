# Known intermittent tests

Rows that fail under load and pass in isolation, with the issue that tracks
each. **This file exists because the issue numbers were not discoverable from
the repository**: a reviewer on another machine was asked to check whether two
of them reproduced, and could not, because neither number appeared anywhere in
the tree or the documents. A tracker number that only lives in the tracker is
useless to anyone running the suite.

**Adding a row here is not a way to make a failure acceptable.** A test that
fails under load is not yet a test — the entry records what is known, what has
been measured, and what would settle it.

| Issue | Test | Symptom |
|---|---|---|
| [#10](https://github.com/Sertelegger/holdfast/issues/10) | `send_input_wait_for_returns_the_identical_shape` (`crates/holdfast-core/tests/integration.rs`) | `matched differs between wait_for_pattern and send_input(wait_for=)`. Its file-mate `send_input_reaches_the_shell` fails the same way, so the issue title under-describes it by one row. |
| [#21](https://github.com/Sertelegger/holdfast/issues/21) | `the_exit_cleanup_leaves_a_successor…socket_and_pid_file_alone` | `AddrInUse` in `bind_control`. Under `--workspace` another target's daemon binds the control socket in the same instant; in isolation there is no competitor. |

## Linux CI evidence, 2026-09-01

The first runs after the Actions quota unblocked, and the first time anything
had executed the 0.0.7 work on Linux. Two rows fail there **reproducibly**,
not occasionally, and a `main` run under identical conditions was used as the
control:

| Row | main run 1 | main run 2 | branch run 1 | branch run 2 |
|---|---|---|---|---|
| [#39](https://github.com/Sertelegger/holdfast/issues/39) | fail | fail | fail | fail |
| [#60](https://github.com/Sertelegger/holdfast/issues/60) | pass | fail | fail | fail |

Both are therefore pre-existing rather than anything a branch introduced.

**#60's title and this file were both wrong about it, and the fix is not a
timing knob.** The assertion reads *"the two paths must be the same
processor, not two implementations"*, and the two strings differ by exactly
one trailing `bash-5.2$ `. It is not two implementations: it is one buffer
read twice with output arriving in between. `read_until(&client, &id, "$")`
matches the `$` inside the *injected shell-integration snippet* — `"${PS1-}"`
contains one — so the test proceeds while the shell is still printing, and
the prompt lands between the two reads. Fixed by waiting for the buffer to
stop growing before comparing.

**#39 is fixed, and it was never a timing row.** This file first said *"a
fixed `wait_exit(15)` outrun under load"*, which the evidence contradicted:
`wait_exit` **panics** on timeout and does not return a code, while the
observed failure was `assert_eq!(term.wait_exit(15), 0)` with **left: 2**.
That narrowed it to `EXIT_UNREACHABLE` and, from there, to a product bug
rather than a test one.

**Root cause.** `holdfast attach` sends one unsolicited startup `Resize` so
the session reflows to the new terminal. Against an already-exited session
the daemon has nothing to wait for — `forward_output` short-circuits on
`!session.is_alive()` — so it writes §7.5's whole ending (`Attached`,
`SessionExited`, `Detached { reason: "session_exit" }`) and closes while the
client is still installing signal handlers, taking raw mode and spawning its
readers. The `Resize` then hit `EPIPE`, and the client returned
`EXIT_UNREACHABLE` **from a failed write**, discarding a complete and correct
ending already sitting unread in its own receive buffer — silently, with no
diagnostic, which is why the failing terminal was blank.

**The same bug made the unreachable-daemon diagnostic unreachable.** Because
the startup write returned before the frame loop ever ran, `"holdfast attach:
the daemon closed the connection"` could not be printed in the one case it
was written for: a genuinely dead daemon also exited 2 onto an empty screen.

**Fixed** by making that write best effort and letting the reader name the
ending — `Detached` is a clean exit 0, a bare EOF is a diagnosed exit 2.
Pinned by two rows in `attach_cli.rs` that drive a stub which closes the
instant it answers, so the race is removed rather than raced:
`a_daemon_that_closes_the_instant_it_answers_still_delivers_its_ending` and
its separating negative
`a_daemon_that_closes_without_detaching_is_still_an_unreachable_daemon`.
Both are red without the fix.

**Why it read as a flake for so long.** Whether the client's write beats the
daemon's close is decided by machine speed, and the split is near-total in
both directions: 20 failures in 20 isolated runs on one checkout, 0 in 20 on
another of the same tree, and 0 in 5 whole-target runs where 26 neighbouring
tests loaded the machine enough for the client to win. A `git bisect` over
that signal named a commit touching only `.github/workflows/ci.yml`, which is
the tell that the bisect was measuring scheduling noise and not a change.

## Platform evidence

Measured on macOS 27.0 / arm64 against `e1cb7cb`, roughly ten full-suite runs
across two days:

- **#10 and #21 did not reproduce at all.** Evidence for Linux scheduling rather
  than logic.
- **#39 did reproduce** — about one full run in three, 0/5 in isolation — and
  **it also failed at the pristine `v0.0.6` tag**, so it predated the 0.0.7
  work entirely, as the root cause above confirms: the startup `Resize` and
  its `EXIT_UNREACHABLE` are both older than either milestone. Now fixed.
- **`a_resource_read_and_a_read_output_return_the_same_bytes`** behaved the
  same way on macOS, was filed as
  [#60](https://github.com/Sertelegger/holdfast/issues/60), and is **fixed and
  closed at v0.0.7** — it was never a flake. The two paths differed by one
  trailing `bash-5.2$ `: one buffer read twice with the prompt arriving in
  between, because `read_until(…, "$")` matches the `$` inside the injected
  shell-integration snippet rather than the shell's prompt. Kept here as the
  reason a row can look load-dependent and be a race in its own setup.

## #42 was a product bug, exactly as this section suspected

**Fixed 2026-09-08.** This section read: *"The final rescan reads the session
buffer rather than confirming the reader has caught up. If that is right, the
failure is not the test being impatient — it is `wait_for_pattern` answering
`SessionDied` over output a real child genuinely produced, which is a
user-visible correctness bug on a shipped tool."* The hypothesis was correct in
every part, including the warning not to close it by raising a timeout.

**The mechanism.** `for_pattern`'s final rescan fired on `!session.is_alive()`,
which flips the instant the child exits. The reader thread breaks only once
`read` returns 0 **and** the backend is dead, so it always drains the child's
last bytes — but a waiter polling liveness can look in the window between those
two events and search a buffer that does not yet hold them. It then answered
`SessionDied` for output that `read_output` would return a moment later.

**Proved causally, because sampling could not reach it here.** The row was green
in **60 isolated and 8 whole-lib contended runs** on a 2-core box — consistent
with the 0-in-141-idle already recorded above, and a reminder that this row
needs saturation rather than merely load. Inserting a 150 ms delay ahead of the
reader's `buffer.push` turned it into **10 failures in 10**, with exactly the
observed signature (`left: SessionDied, right: Matched`). One delayed component,
one predicted failure.

**The obvious fix does not work, and that is worth recording.** Treating
`RecvError::Closed` as "the reader is done" fails because `Session` holds
`output_tx` itself, so the sender outlives the reader thread and that arm is
unreachable while the caller holds an `Arc<Session>` — which it always does.
The fix is a positive signal: `Session::reader_finished()`, stored `Release` by
the reader as it leaves its loop and read `Acquire` by the rescan, so every
`buffer.push` before it is visible to the search.

Pinned by `session::wait::tests::a_slow_reader_does_not_turn_a_match_into_a_death`,
which uses `MockPty::set_read_delay` to make the window deterministic rather
than lucky. The original row is kept beside it: it is the same claim without the
widened window, and it is the one that reproduced on a slow host.

## #52 was #21's `fork` window, on a connected socket

**Fixed 2026-09-08, and its row is gone from the table above.**
[#52](https://github.com/Sertelegger/holdfast/issues/52) was
`daemon::server::tests::a_connection_mid_handshake_holds_off_the_client_less_exit`
— **2 failures in 54 whole-binary runs** and **0 in 800** filtered to
`daemon::server` alone, which the row read as needing the rest of the binary for
contention. It did, and not for the reason "contention" suggests. (#52's second
test was the row tracked as #21, so the pair overlapped and #52 contributed one
name, not two.)

Not a new mechanism: the same descriptor window the
`remove_runtime_files_we_own` note has documented all along, one layer over.

**Which assertion.** This row's `server.rs:3552` was recorded against the tree
at `38c7bf2`, where that line is not the mid-handshake claim the test is named
for but the **pairing** at the bottom — `drop(peer)` and then
*"the count was never given back, so the exit is now disabled for good"*. Every
reproduction, natural and forced, lands there. The row's own name points at the
wrong half of it, which is worth knowing before reading the test.

**The mechanism.** Every `fork` in this binary — `start_detached`, every PTY
spawn — hands its child a copy of *every* descriptor the process holds, and
`SOCK_CLOEXEC` closes it at the `exec` and not before. While a copy survives,
`drop(peer)` closes one descriptor and releases no socket: the daemon's
`read_frame` sees no EOF, `handle_connection` stays parked until
`HANDSHAKE_TIMEOUT` (5 s), and `in_flight` does not come back. The waiter was
`yield_until`, which is 500 yields and no wall clock — a few hundred
microseconds — so the row lost.

That is exactly the property the row recorded without recognising it: "needs the
rest of the binary for contention" is fork density, and the 0 in 800 filtered
runs are a module that barely forks.

**Measured.** On a 24-core box, `--test-threads=32`, four concurrent whole-binary
lanes: **1 failure in 100 runs before, 0 in 100 after**, same machine, same load,
same afternoon — consistent with the historical 2 in 54. Forced, it is not
probabilistic at all, and the forcing measures the row's tolerance directly: a
real `fork` whose child holds the inherited descriptor for **200 ms fails it 10
in 10**, for **1 ms, 20 in 20**, and for **100 µs, 1 in 20** — so the row's whole
budget is a few hundred microseconds, against a `fork`→`exec` latency this tree
has already measured at p50 75 µs with a 3.1 ms tail
(`spawn::socket_is_live`). An in-process `dup` — the same open file
description, which is what actually holds the socket — is **10 in 10**.

**Fixed by asking for the ending instead of inferring it.** `shutdown(2)` acts
on the socket, so every descriptor onto it sees the half-close and the daemon
reads EOF on its next poll; `close(2)` acts on a descriptor and sends nothing
while another copy survives. The row now half-closes and then drops.

**Pinned deterministically rather than by luck.** The test holds a `dup` of the
client descriptor across the drop — the inherited copy, made permanent — so the
hostile arrangement is always present. Without the half-close it is red 20 in
20; with it, green 20 in 20.

**No product defect.** The daemon is right to keep counting a connection whose
socket has not been released, and its one unbounded read is already covered by
`HANDSHAKE_TIMEOUT`. The defect is a test that inferred "the client is gone"
from `close`.

**And the runner matters, which is worth saying plainly rather than letting the
next person discover it.** The mechanism needs a sibling `fork` *in this
process*. Under libtest — `cargo test`, the raw binary with `--test-threads=N`,
which is what every measurement above used and what `scripts/ci-flake-hunt.sh`
still runs — every row is a thread in one process and a sibling's PTY spawn
duplicates this row's descriptors. Under `cargo nextest`, adopted in `f209c97`
and what CI's `test` job runs, each row is **its own process**: measured here,
9 concurrent processes at `-j 8`. A sibling's `fork` cannot reach this row's
descriptor table there, so the natural failure is unreachable under the gate as
it stands today. That is not the row being fixed — it is the row being hidden by
a change made for another reason, which is exactly the state in which a
fragility survives. The `dup` makes it runner-independent.

**And a sweep, because this is now twice.** `drop(…)` followed by a pure-yield
wait occurred exactly once in the tree, and it was this row. The comparable
waits in `attach_protocol.rs` spend a 5 s wall-clock deadline, which is orders
of magnitude past any `fork`→`exec` this binary produces. `yield_until`'s doc
comment now says what its budget is for.

## #56 is not the common cause this file said it was

**Withdrawn on evidence, 2026-08-27.** This section used to say that
[#56](https://github.com/Sertelegger/holdfast/issues/56) — the suite leaking a
`holdfast daemon run` into the **default** runtime directory — was the shared
cause behind #21 and #52, and told the reader to re-check both once it was
fixed. **Neither half survived measurement.**

**The suite does not leak a daemon.** Nine lanes each ran under their own
`XDG_RUNTIME_DIR`, so `$XDG_RUNTIME_DIR/holdfast` was the default path for that
lane. **It was never created in any of them** — across 13 `--workspace` runs,
41 lib-binary runs, 800 filtered runs and 2400 single-test hammer runs. Ten
`ps` snapshots found zero `holdfast daemon run`/`daemon start` processes.
`RuntimePaths::discover()` has exactly three callers, all in the CLI
(`crates/holdfast/src/commands.rs`), and every test reaching them goes through
a helper that sets `HOLDFAST_RUNTIME_DIR` (`daemon_cli.rs:75`,
`attach_cli.rs:346`, `mcp-smoke.sh:117`).

**And #56 could not explain #21 even if it were real.** Every captured
`AddrInUse` names `/tmp/holdfast-d16-exitsuccessor-<uuid8>/control.sock` — a
per-test scratch directory whose suffix is `Uuid::new_v4()`
(`server.rs:2526`). **No daemon in the default runtime directory can bind that
path.** The competitor is the test's *own predecessor listener*, whose tokio
`UnixListener` drop had not yet made `socket_is_live` — a plain
`UnixStream::connect` at `daemon/spawn.rs:125` — start failing.

So the re-check instruction is dropped for #21. #56 remains worth fixing on its
own terms; it is not a lead on anything in the table above.

**Separately, and not the suite's doing:** the default instance *has* been
used. `/run/user/1000/holdfast/{bind.lock,holdfast.lock}` and
`~/.holdfast/logs/audit.log` carry 9 `session_start` rows from 2026-08-26
18:40–18:44 UTC against an empty `daemon.log`. That is consistent with a
hand-run `holdfast mcp` or `daemon start`, not with `cargo test`.

## `secret::binding` — triaged; three of the four rows are closed

**2026-09-08.** This section was a table of counts headed *"`secret::binding`
is now the noisiest module in the suite"*, and it was right that the module
deserved triage before anything above it. The counts were the least
interesting thing about it. **None of the three rows now closed was
load-dependent in the sense that phrase carries, and none was a product
defect.** They are one mistake in three spellings: *the row synchronises
with a real `sh` child through a signal that does not mean what its next
line needs* — a broadcast edge that keeps nothing for a receiver that does
not yet exist, a ring buffer that remembers the previous round's prompt, a
file that exists before it has contents. Each is closed causally, by
delaying one component and predicting the failure, rather than by sampling.

**The fourth is a live flake and stays open**, and the first revision of
this section closed it wrongly on an argument its own text named the
falsification test for. It reproduces, the assertion it fails is correct,
and what it is catching is a **product** defect — see its paragraph at the
end.

| Row (`secret::binding::tests::`) | Before | After |
|---|---|---|
| `a_childs_prompt_line_reaches_the_terminal_with_nothing_that_can_act` | **8 failures in 25**, and **10 in 10** with the window widened | 0 in 25 |
| `max_uses_is_per_session_and_bounded` | **10 in 10** with the window widened | 10 in 10 green |
| `an_absolute_program_does_not_save_a_profile_from_an_agents_env` | **6 in 6** with the window widened | 6 in 6 green |
| `the_listener_and_a_connections_raise_ride_the_same_edge` | 2 recorded, **1 in 50** reproduced, **6 in 6** with a 20 ms delay injected | **open — the defect behind it is in the product** |

The contended figures are the `holdfast-core` lib binary filtered to
`secret::binding`, `--test-threads=16` under `taskset -c 0,1` on a 24-core
box; the whole-lib rate for the first row was 1 in 8 at the same settings.
**Every widened figure is now a committed property of its row rather than a
one-off experiment**: each of the three closed rows carries the delay that
produced it, so reverting the fix is a red rather than a rate. That was not
true of the third row in the first revision of this section — see its
paragraph.

**The first row armed a consumer on an edge and then hoped.** §8.3's echo
drop is published on a `tokio::sync::broadcast`, which keeps nothing for a
receiver that does not yet exist, and `session_running` returns with the
child already executing. `spawn_forwarder` subscribed after that, so a child
that printed its echo-off prompt first left the row waiting out `wait_for`
on a frame that had been sent to nobody — *"no AwaitingSecret reached the
client; it saw []"*, exactly as recorded. `gated_echo_off`'s own doc, one
section down in the same file, describes this defect for the *listener* and
gates every autofill row against it; this row is the one that did not. A
500 ms delay in front of the subscription made it **10 failures in 10** in
isolation. Fixed by gating the child, and the delay stays so the gate cannot
be removed quietly.

**The second row's `await_prompt` was satisfied by the wrong round.** The
ring buffer is cumulative and the row runs the fixture three times on one
session, so round two matched round *one's* `Password: ` and returned with
the child between reads — `stty echo` on. The credential then resolved,
spending a `max_uses` claim and writing the `binding_resolved` line, and was
declined `NotEchoOff` by the writer and dropped; step 1 fell through to a
human who was not attached, and the row waited out its ten-second deadline
for the recorded `secret_cancelled`/timeout. `await_prompt` now waits for
the line discipline as well as for the bytes.

**The third row waited on a file's existence and then read its contents.**
`printf '%s' "$x" > '<sink>'` creates the file and fills it in two steps
with a deschedulable gap between them, so the poll could return on an empty
file and the `assert_eq!` compare `""`. It now polls the value
(`await_capture`). Both GH #55 probes carried the same loop and both are
fixed.

**Its two `6 in 6`s are two different measurements of two different
causes, and the first revision of this section credited one number to
both.** They are separated here because a number that names the wrong
cause is worse than no number:

- **Remove `await_capture`** and the row fails 6 in 6 at the capture
  comparison with `left: ""`. That figure was originally taken with a
  one-off injected delay and stated as though it were a property of the
  tree; without one, reverting `await_capture` alone reproduces at about
  **1 in 8** — an intermittent, not a red. The two-step write is now
  spelled out in the fixture itself, so the 6 in 6 is the committed
  behaviour.
- **Remove `await_prompt`'s liveness arm** and the *same row* fails 6 in 6
  somewhere else entirely — at `await_prompt`, on `ECHO is None`. That is
  not the capture race at all: an `autofill_on_echo_off` row resolves and
  injects with no tool call, so prompt, credential, `got=` and exit can all
  be over before the first poll runs, and `line_discipline` answers
  `UNKNOWN` for a dead child.

**The arm is an opt-out, not a completion.** For any row whose child can
finish early the new echo guarantee is silently off and `await_prompt`
degrades to the containment wait it was before. That is the right answer
where the exchange it guards has already happened, but it is not the same
promise, and a row that needs the stronger one has to keep its child alive
to get it.

**And the second row's loop carried the same stale-ring defect one line
below the one that was fixed**, which the fix for it did not reach.
`buffer_until(&a, b"got=HUNTER2", …)` is containment over a cumulative
ring, so at iteration 2 it is answered by round one's copy and the row
never observes that the *second* credential reached the child.
Instrumented: one copy is already in the ring before that wait runs.
Measured by mutation rather than argued — a `write_secret_if_unread` that
answers `Written` while writing nothing for every write after a session's
first **passed all 54 rows in this module**, which would ship a
`request_secret_input` that answers `secret_provided`, audits
`binding_resolved` and spends a `max_uses` claim while the child's prompt
sits unanswered. `buffer_until_count` closes it: the same mutation is now
caught 3 in 3 with *"reached the buffer 1 time(s), wanted 2"*. The
counting idiom was already in this file —
`the_listener_and_a_connections_raise_ride_the_same_edge` counts `got=`
rather than testing for it.

**The fourth row is a live flake, and the first revision of this section
was wrong to close it.** That revision recorded 0 failures in 8 whole-lib
runs, 0 in 25 contended module runs and 0 in 48 runs under eight concurrent
binaries on two cores, and then argued the row's `fulfilled == PASSES`
claim was safe because `#[tokio::test]` is current-thread and
`autofill_from_binding` awaits `spawn_blocking` before it can reach
`take_if_unadopted_matching`. It also named the test that would falsify
that argument. **The test was run and the argument lost.**

- **Injected**: a 20 ms sleep in `spawn_forwarder` ahead of
  `hub.raise_secret` gives **6 failures in 6**, verbatim *"the two
  orderings did not converge on `fulfilled`"*, `left: 0, right: 6`.
- **Natural**: **1 failure in 50** contended runs (`taskset -c 0,1`,
  `--test-threads=16`), `left: 5, right: 6`.

**Where the argument went wrong** is worth keeping, because it is an easy
one to make again: yielding at `spawn_blocking(...).await` hands control to
the *runtime*, not to the forwarder. It only lets the forwarder raise first
if the forwarder is runnable at that moment, and it need not be —
`broadcast::send` wakes its receivers one at a time, so the reader thread
can be preempted between waking the autofill listener and waking the
forwarder, and the listener then runs its whole provider and takes a slot
the forwarder has not been woken to fill.

**The defect the row is catching is in the product, not in the row.**
Instrumentation of a losing pass shows all six requests closing with
`outcome: "cancelled"` while the credential *was* written to the child: the
autofill's `take_if_unadopted_matching` answered `Vacant`, so it wrote with
no raise to close, and the forwarder's late raise was then closed by the
`AwaitingSecretLeft` arm. An attached client is told
`SecretRequestClosed { outcome: "cancelled" }` for a request that was
fulfilled, having first been shown an `AwaitingSecret` prompt for a read
that was already answered — *"the affordance appearing and vanishing for no
reason a human can see"*, which `mcp::tools` names as the thing to avoid.
It is the exact mirror of the case `inject_resolved` already guards:
*"a write the writer declines would otherwise have told every attached
client `fulfilled` for a value the child never received"*. To be filed
against §7.5; the row's assertion is correct and stays as it is until the
product is.

## Caught in passing on the #52 lanes, not filed

`session::tests::no_output_is_classified_between_the_echo_sample_and_the_answer`
(`session/mod.rs:2932`) failed **once in the same 100 whole-binary runs**, with
`left: 0, right: 1` — its own message says 0 means *"the deferred chunk never
reached the history"*. Recorded here because an unfiled failure that nobody
wrote down is how this file came to exist; it was not investigated, and no
claim is made about whether it is a test or a product defect.

## What was not run

The lanes above were cut ~34 minutes short of their planned deadline, so the
denominators are roughly a third of what was intended; the idle arms suffered
most (9 and 9 runs, not ~30 and ~250). **`the_exit_cleanup_…` (#21) is
unresolved at `65531d9`** — 0 failures in 54 whole-binary runs and 0 in 2400
isolated ones — but the configuration that produced 6 of its historical hits
was never run: roughly 12 concurrent full lib binaries at the default 48
threads, unpinned. That is the highest-value follow-up on this file.
