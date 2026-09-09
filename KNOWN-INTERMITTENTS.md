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
| [#52](https://github.com/Sertelegger/holdfast/issues/52) | `daemon::server::tests::a_connection_mid_handshake_holds_off_the_client_less_exit` | **2 failures in 54 whole-binary runs**, load-dependent; 0 in 800 runs filtered to `daemon::server` alone, so it needs the rest of the binary for contention. Asserts at `server.rs:3552`. **#52's second test is the row already tracked as #21 above** — the pair overlaps, so #52 contributes one new name, not two. |

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

| Row (`secret::binding::tests::`) | Before | After |
|---|---|---|
| `a_childs_prompt_line_reaches_the_terminal_with_nothing_that_can_act` | **8 failures in 25**, and **10 in 10** with the window widened | 0 in 25 |
| `max_uses_is_per_session_and_bounded` | **10 in 10** with the window widened | 10 in 10 green |
| `an_absolute_program_does_not_save_a_profile_from_an_agents_env` | **6 in 6** with the window widened | 6 in 6 green |
| `the_listener_and_a_connections_raise_ride_the_same_edge` | 2 recorded hits | **not found — still open** |

The contended figures are the `holdfast-core` lib binary filtered to
`secret::binding`, `--test-threads=16` under `taskset -c 0,1` on a 24-core
box; the widened ones are that row alone, in isolation, with one delay
injected. The whole-lib rate for the first row was 1 in 8 at the same
settings.

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
file and the `assert_eq!` compare `""`. It now polls the value. Both GH #55
probes carried the same loop and both are fixed.

**The fourth row did not reproduce and is not explained.** 0 failures in 8
whole-lib runs, 0 in 25 contended module runs, and 0 in **48 runs under
eight concurrent copies of the binary** at `--test-threads=4`, all eight
pinned to the same two cores — which is the "several concurrent lib
binaries" arrangement the section below records as never having been run,
and it is the highest-contention configuration reached here. That is a
denominator, not a diagnosis: the row simply never failed. What was ruled
out, so the next attempt does not re-tread it:

- **Not the first row's cause.** Both consumers — `watch_for_autofill` and
  `spawn_forwarder` — subscribe before the child gate is opened, in both
  halves, so the edge cannot precede either subscription.
- **Not the second row's.** Every pass builds a fresh session, so there is
  no earlier round for the ring buffer to remember.
- **Not the third row's.** The row captures nothing to a file.
- **Probably not its own `fulfilled == PASSES`.** The obvious suspect is the
  raced half's claim that the two orderings converge: if the autofill's
  `take_if_unadopted_matching` ran before the forwarder's `raise_secret`,
  the slot would answer `Vacant`, the value would be written with no raise
  to close, and the forwarder's `AwaitingSecretLeft` arm would close a late
  raise `cancelled` instead. But `#[tokio::test]` is a **current-thread**
  runtime, and `autofill_from_binding` awaits `spawn_blocking` — a yield —
  before it can reach the take, so the forwarder is polled in between. That
  interleaving needs the blocking join to complete without yielding, which
  needs a `fork`/`exec` and a read to finish inside one poll. **This is an
  argument, not a measurement**, and it is the first thing to attack with an
  injected delay ahead of the forwarder's raise: if that turns the row red
  with *"the two orderings did not converge on `fulfilled`"*, the argument
  is wrong and the row's doc needs re-deriving with it.

## What was not run

The lanes above were cut ~34 minutes short of their planned deadline, so the
denominators are roughly a third of what was intended; the idle arms suffered
most (9 and 9 runs, not ~30 and ~250). **`the_exit_cleanup_…` (#21) is
unresolved at `65531d9`** — 0 failures in 54 whole-binary runs and 0 in 2400
isolated ones — but the configuration that produced 6 of its historical hits
was never run: roughly 12 concurrent full lib binaries at the default 48
threads, unpinned. That is the highest-value follow-up on this file.
