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
| [#42](https://github.com/Sertelegger/holdfast/issues/42) | `session::wait::tests::output_written_just_before_an_exit_still_matches` | Returns `SessionDied` where it expects `Matched`. **Possibly not a flake** — see below. |
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

## #42 deserves a different treatment from the rest

The final rescan **reads the session buffer rather than confirming the reader
has caught up**. If that is right, the failure is not the test being impatient —
it is `wait_for_pattern` answering `SessionDied` over output a real child
genuinely produced, which is a user-visible correctness bug on a shipped tool.

Measured: **17 failures in 500 runs under 96-way CPU saturation, 0 in 141 idle.**

**Do not close it by raising a timeout** until that question is settled. A raised
deadline would hide the defect if the hypothesis holds, and the issue title would
then be actively misleading.

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

## Unfiled — `secret::binding` is now the noisiest module in the suite

Caught in passing during the #52 hunt and **not yet filed as issues**. At 9
failures to `daemon::server`'s 2, this module deserves its own triage before
anything in the table above.

| Test (`secret::binding::tests::`) | count | note |
|---|---|---|
| `a_childs_prompt_line_reaches_the_terminal_with_nothing_that_can_act` | 5 | "no AwaitingSecret reached the client; it saw []" |
| `the_listener_and_a_connections_raise_ride_the_same_edge` | 2 | |
| `max_uses_is_per_session_and_bounded` | 1 | got `secret_cancelled`/timeout, wanted `secret_provided` |
| `an_absolute_program_does_not_save_a_profile_from_an_agents_env` | 1 | **failed on an idle lane** |

## What was not run

The lanes above were cut ~34 minutes short of their planned deadline, so the
denominators are roughly a third of what was intended; the idle arms suffered
most (9 and 9 runs, not ~30 and ~250). **`the_exit_cleanup_…` (#21) is
unresolved at `65531d9`** — 0 failures in 54 whole-binary runs and 0 in 2400
isolated ones — but the configuration that produced 6 of its historical hits
was never run: roughly 12 concurrent full lib binaries at the default 48
threads, unpinned. That is the highest-value follow-up on this file.
