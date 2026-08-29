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
| [#39](https://github.com/Sertelegger/holdfast/issues/39) | `attaching_to_an_already_exited_session_ends_instead_of_hanging` (`crates/holdfast/tests/attach_cli.rs`) | A fixed `wait_exit(15)` outrun under load. |
| [#42](https://github.com/Sertelegger/holdfast/issues/42) | `session::wait::tests::output_written_just_before_an_exit_still_matches` | Returns `SessionDied` where it expects `Matched`. **Possibly not a flake** — see below. |
| [#52](https://github.com/Sertelegger/holdfast/issues/52) | `daemon::server::tests::a_connection_mid_handshake_holds_off_the_client_less_exit` | **2 failures in 54 whole-binary runs**, load-dependent; 0 in 800 runs filtered to `daemon::server` alone, so it needs the rest of the binary for contention. Asserts at `server.rs:3552`. **#52's second test is the row already tracked as #21 above** — the pair overlaps, so #52 contributes one new name, not two. |

## Platform evidence

Measured on macOS 27.0 / arm64 against `e1cb7cb`, roughly ten full-suite runs
across two days:

- **#10 and #21 did not reproduce at all.** Evidence for Linux scheduling rather
  than logic.
- **#39 does reproduce** — about one full run in three, 0/5 in isolation — and
  **it also fails at the pristine `v0.0.6` tag**, so it predates the 0.0.7 work
  entirely.
- **`a_resource_read_and_a_read_output_return_the_same_bytes`** behaves the same
  way on macOS. Not yet filed; add it here when it is.

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
