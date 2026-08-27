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
| [#52](https://github.com/Sertelegger/holdfast/issues/52) | **two `daemon::server` tests, names not recorded** | One failed on an *idle* box, which does not fit the load-dependent triage the others got. The missing names are the issue's first task, and the reason this file exists. |

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

## A cause worth eliminating before triaging any of them

[#56](https://github.com/Sertelegger/holdfast/issues/56) records the suite
leaking a `holdfast daemon run` into the **default** runtime directory. A stray
daemon holding the default socket produces `AddrInUse` (#21) and a
`daemon::server` row failing without contention (#52) — and it would not
correlate with load, which is the one thing the triage of those two assumed.
Re-check both once it is fixed.
