#!/usr/bin/env bash
# Assert the EXACT set of measurements this suite did NOT make.
#
# Two shapes of shortfall. One census, because they are one defect:
#
#   1. A ROW THAT DID NOT RUN. Eight rows of
#      crates/clasp-core/tests/detection.rs early-`return` when their host
#      requirement is unmet. libtest reports every one of them as `ok` and
#      swallows the explanation unless `--show-output` is passed, so a
#      suite that measured half of what its name promises still prints a
#      green pass count. That is the defect this file exists to end.
#
#   2. AN ASSERTION THAT DID NOT RUN, INSIDE A ROW THAT DID. Spec §11.4's
#      control-path p99 is asserted only where `available_parallelism()`
#      reports >= 8 cores; below that the number measures the scheduler
#      rather than CLASP. Measured on the 2-vCPU runner: the sampling loop
#      gets 13 turns in three seconds instead of ~590, `percentile(0.99)`
#      of thirteen samples IS the maximum, and one 500.89 ms scheduling
#      stall failed a 500 ms budget. GitHub's standard hosted runners are
#      2-core on a private repository — which this one is — so on this
#      pipeline that assertion has NEVER run and will not until the runner
#      grows. The row still runs, still guards its other two assertions,
#      and still reports `ok`; the census counted zero skips, truthfully
#      and uselessly, because it had no vocabulary for this.
#
# THE TWO MARKERS, and why they are deliberately different strings:
#
#   `skipping: `      a whole test row early-returned.
#   `not-asserted: `  a row ran, and one assertion inside it was gated off.
#
# Emitting the second as `skipping: ` would trip the unexpected-skip rule
# below and paint CI red for a case the row census was never designed to
# describe, so it gets its own prefix, its own agreed list and its own
# rules rather than being forced into the other's. Both are LINE PREFIXES,
# matched anchored, so neither can be produced by prose in a panic message.
#
# `not-asserted: ` lines have a GRAMMAR, so that what this file reads is
# never a sentence somebody rephrased:
#
#   not-asserted: <id> <key>=<value> … — <prose, for whoever reads the log>
#
#   <id>    stable and `::`-qualified. It names the ASSERTION, never the
#           reason, and it is what the agreed list is keyed on.
#   <k=v>   the facts that decide whether the exemption is still true.
#           For the p99 entry: `cores=` (what the host had) and
#           `min_cores=` (what the gate demanded). BOTH ARE CHECKED
#           against the agreed list, so moving `P99_MIN_CORES` in the test
#           moves this file too, or the job goes red.
#
# THE RULES, both censuses, and the second half of each is the half that
# stops a gate rotting into a comment:
#
#   * A skip not on the agreed list fails. An agreed skip that stopped
#     happening fails.
#   * A `not-asserted: ` id not on the agreed list fails. An agreed entry
#     whose row RAN without emitting it means the assertion ran — a stale
#     exemption — and fails where the exemption is claimed (see
#     STRICTNESS). An agreed entry whose row is not in the log at all
#     fails ALWAYS: a log that never ran the row cannot certify anything
#     about it, and that is this addition's anti-vacuity gate, the
#     equivalent of the two `tests/detection.rs` / `test result:` gates
#     below.
#
# STRICTNESS, and why exactly one of the six rules has any. The p99
# exemption is a claim about a SMALL HOST. On the 2-core runner it is true
# and the marker appears; on a 48-core workstation the assertion runs and
# the marker correctly does not, and failing there would paint every
# developer's local run red for behaving BETTER than CI — which is how a
# script gets `|| true`-d. So the stale half of the gated census fails
# where the exemption is claimed, and prints a NOTE elsewhere:
#
#   HOLDFAST_CENSUS_GATED_STRICT=1   enforce it (what CI does)
#   HOLDFAST_CENSUS_GATED_STRICT=0   report it, do not fail
#   unset                         1 when GITHUB_ACTIONS or CI is set, else 0
#
# The day the runner has 8 cores, or the day someone lowers
# `P99_MIN_CORES`, CI stops seeing the marker and this turns red by
# itself. That is the entire point of the entry.
#
# Two guards already existed for the ROW census and neither closes it:
#
#   * `the_pty_matrix_runs_every_host_dependent_row_but_the_two_it_names`
#     (in the suite) fails on any skip OUTSIDE its allowlist. The two rows
#     INSIDE the allowlist may still skip silently, forever, on any host.
#   * `HOLDFAST_REQUIRE_ALL_SHELLS=1` turns every skip into a failure and
#     would supersede the row half of this script entirely. It is not set
#     yet, and the reason is measured and written down in ci.yml above the
#     `test` job: the fish row cannot pass on any fish available today.
#
# Run it locally exactly as CI does:
#
#   cargo test --workspace --locked --no-fail-fast -- \
#     --test-threads=4 --show-output 2>&1 | tee test-output.log
#   ./scripts/ci-skip-census.sh test-output.log
#
# `--show-output` is not optional: without it libtest captures the
# `skipping: …` and `not-asserted: …` notices and this script reads a log
# that cannot contain what it is looking for.
#
# And prove it can still fail, which is why every rule above sits inside a
# named `# --- gate: … ---` block that the self-test deletes one at a time:
#
#   ./scripts/ci-skip-census.sh --self-test
#
# Exit codes: 0 clean, 1 findings, 2 self-test failure or bad usage.
set -uo pipefail

# Every skip this pipeline tolerates, as a literal line PREFIX, one per
# entry, each with the reason it is tolerated and the condition that
# retires it. Adding an entry here is a deliberate, reviewable act; a row
# that starts skipping without one turns this job red.
#
#   fish — measured 2026-08-13, in containers on the ubuntu-24.04 base
#   image, at both fish versions obtainable there:
#     * fish 3.7.0 (noble's own archive): the snippet installs and marks
#       correctly, and the row still fails, because the shared assertion
#       helper sends `(exit 42)` — a SUBSHELL in bash and zsh, a command
#       SUBSTITUTION in fish, which fish rejects with "command
#       substitutions not allowed here" before running anything.
#     * fish >= 4: a marker collision the row asserts the absence of.
#   Neither is CI's to fix and neither is a reason to stop running the
#   other twenty rows. RETIRED BY: a fish the row can pass on — at which
#   point `fish` goes into the apt line in ci.yml and the probe job,
#   HOLDFAST_REQUIRE_ALL_SHELLS=1 gets set in ci.yml and nightly.yml, and
#   this entry is deleted, in one change.
EXPECTED=(
  "skipping: fish not installed"
)

# Every assertion this pipeline tolerates being gated OFF, keyed on the id
# in the `not-asserted: ` line, one record per entry:
#
#   <id>|<the test row that carries it>|<the min_cores it must report>
#
# The row is what makes the entry non-vacuous: it has to be in the log, or
# this log is not evidence about the entry either way. The `min_cores` is
# what makes the entry track the code: it is asserted equal to the value
# the test printed, so the exemption cannot outlive the constant it was
# written for.
#
#   stress_write_path::control_path_p99 — measured 2026-08-13. §11.4's p99
#   budget is a statement about a box that can carry 100 sessions at
#   1 MiB/s; on the 2-vCPU runner it is a statement about the Linux
#   scheduler (13 samples in 3 s, p99 == max, one stall at 500.89 ms
#   against a 500 ms budget). On 48 cores the same code answers p50 3.9 us,
#   p99 731 us, max 1.09 ms — 684x inside budget — which is what §4.2a
#   predicts and what the assertion is for. The OTHER two assertions in
#   that row (`parsed == 0`, and the produced-bytes floor that stops the
#   run passing vacuously) are unconditional and still guard on every host,
#   so this entry exempts one assertion and not the row.
#   RETIRED BY: a runner with >= 8 cores. GitHub's standard hosted runners
#   are 2-core while this repository is private and 4-core once it is
#   public, so going public does NOT retire it; a larger runner label, a
#   self-hosted runner, or a lowered `P99_MIN_CORES` does. Any of those
#   makes the marker stop appearing in CI, which fails the stale half
#   below — delete this entry then, and the gate in
#   crates/clasp-core/tests/stress_write_path.rs with it.
GATED_EXPECTED=(
  "stress_write_path::control_path_p99|tier_b_stays_off_and_the_control_path_stays_responsive_under_load|8"
)

# --------------------------------------------------------------------------
# The census
# --------------------------------------------------------------------------

marker_field() {
  # marker_field <line> <key> -> the value of `<key>=…`, or empty + rc 1.
  # Token-wise rather than by regex, so `min_cores=8` can never answer for
  # `cores=`, and `read -ra` rather than word splitting, so a `*` in the
  # prose cannot glob against the working directory.
  local key="$2" tok
  local -a toks
  read -ra toks <<<"$1"
  for tok in "${toks[@]}"; do
    case "$tok" in
      "$key="*) printf '%s' "${tok#*=}"; return 0 ;;
    esac
  done
  return 1
}

census() {
  local log="$1"

  if [ ! -f "$log" ]; then
    echo "SKIP CENSUS FAILED: no such log file: $log" >&2
    return 1
  fi

  # Where the stale half of the gated census is enforced. See STRICTNESS.
  local gated_strict="${HOLDFAST_CENSUS_GATED_STRICT:-}"
  # Validated rather than coerced. `HOLDFAST_CENSUS_GATED_STRICT=true` reads
  # as "on" to a person and would be "off" to a `= 1` test — a knob that
  # silently disables the half of this census that matters most, which is
  # the failure this whole file is about.
  case "$gated_strict" in
    "" | 0 | 1) ;;
    *)
      echo "SKIP CENSUS FAILED: HOLDFAST_CENSUS_GATED_STRICT='$gated_strict' is not 0, 1 or unset." >&2
      return 2
      ;;
  esac
  if [ -z "$gated_strict" ]; then
    if [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${CI:-}" ]; then
      gated_strict=1
    else
      gated_strict=0
    fi
  fi

  # --- anti-vacuity: a log that never ran the rows cannot certify them ---
  #
  # Without these, an empty file, a log from a build failure, or a log
  # whose `--show-output` was dropped all produce zero observed skips and
  # zero observed non-assertions — and every "unexpected" rule below would
  # pass on each of them. The expected-skip check catches most of that by
  # itself, but only while EXPECTED is non-empty, and this file's whole
  # purpose is to shrink EXPECTED to nothing.
  # --- gate: vacuity-detection ---
  if ! grep -qE 'tests/detection\.rs' "$log"; then
    echo "SKIP CENSUS FAILED: $log never mentions tests/detection.rs, so it is not" >&2
    echo "a log of a run that could have skipped anything. Did the build fail?" >&2
    return 1
  fi
  # --- /gate: vacuity-detection ---
  # --- gate: vacuity-result ---
  if ! grep -qE '^test result:' "$log"; then
    echo "SKIP CENSUS FAILED: $log contains no 'test result:' line — no test binary" >&2
    echo "reported a summary, so this log certifies nothing." >&2
    return 1
  fi
  # --- /gate: vacuity-result ---

  local -a observed gated_observed
  mapfile -t observed < <(grep -hE '^skipping: ' "$log" | sort -u)
  mapfile -t gated_observed < <(grep -hE '^not-asserted: ' "$log" | sort -u)

  echo "--- rows that skipped ---"
  if [ "${#observed[@]}" -eq 0 ]; then
    echo "  (none)"
  else
    printf '  %s\n' "${observed[@]}"
  fi

  echo "--- assertions gated off inside rows that ran ---"
  if [ "${#gated_observed[@]}" -eq 0 ]; then
    echo "  (none)"
  else
    printf '  %s\n' "${gated_observed[@]}"
  fi

  local fails=0
  local line want matched

  # 1. Every observed skip must be one this pipeline has agreed to tolerate.
  # --- gate: skip-unexpected ---
  for line in "${observed[@]:-}"; do
    [ -z "$line" ] && continue
    matched=0
    for want in "${EXPECTED[@]}"; do
      case "$line" in "$want"*) matched=1 ;; esac
    done
    if [ "$matched" -eq 0 ]; then
      echo "  UNEXPECTED SKIP: $line" >&2
      fails=$((fails + 1))
    fi
  done
  # --- /gate: skip-unexpected ---

  # 2. Every tolerated skip must still be happening. An exemption for a row
  #    that now runs is a lie in a file people read to find out what is
  #    covered, and it is the exact state this project keeps finding.
  # --- gate: skip-stale ---
  for want in "${EXPECTED[@]}"; do
    matched=0
    for line in "${observed[@]:-}"; do
      case "$line" in "$want"*) matched=1 ;; esac
    done
    if [ "$matched" -eq 0 ]; then
      echo "  STALE EXEMPTION: nothing skipped with the prefix '$want'." >&2
      echo "  If that row now runs, DELETE the entry — and check whether" >&2
      echo "  HOLDFAST_REQUIRE_ALL_SHELLS=1 can be set in ci.yml and nightly.yml," >&2
      echo "  which supersedes the row half of this script entirely." >&2
      fails=$((fails + 1))
    fi
  done
  # --- /gate: skip-stale ---

  # 3. Every observed non-assertion must be one this pipeline has agreed
  #    to tolerate. A malformed marker — no id, or an id nobody wrote down
  #    — lands here too, which is right: an assertion that stopped being
  #    made under a name this file does not know is exactly as invisible
  #    as one that was never announced.
  local id
  # --- gate: gated-unexpected ---
  for line in "${gated_observed[@]:-}"; do
    [ -z "$line" ] && continue
    id="$(awk '{print $2}' <<<"$line")"
    matched=0
    for want in "${GATED_EXPECTED[@]}"; do
      [ "${want%%|*}" = "$id" ] && matched=1
    done
    if [ "$matched" -eq 0 ]; then
      echo "  UNEXPECTED NON-ASSERTION: $line" >&2
      echo "  An assertion was gated off under the id '${id:-(none)}', which is not in" >&2
      echo "  GATED_EXPECTED. Either the gate is new — add an entry, with what" >&2
      echo "  retires it — or the marker is malformed: the grammar is" >&2
      echo "  'not-asserted: <id> <k>=<v> … — <prose>'." >&2
      fails=$((fails + 1))
    fi
  done
  # --- /gate: gated-unexpected ---

  # 4. Every tolerated non-assertion must still be a non-assertion, and the
  #    facts it reports must still match what was agreed.
  local want_id want_row want_min got_min got_cores
  for want in "${GATED_EXPECTED[@]}"; do
    IFS='|' read -r want_id want_row want_min <<<"$want"

    # 4a. ANTI-VACUITY, per entry. If the row that carries the assertion is
    #     not in this log, the log is not evidence either way — and without
    #     this, a log from a run that never built the stress binary reads
    #     as "the p99 was asserted".
    # --- gate: gated-absent-row ---
    if ! grep -qE "^test ${want_row} \.\.\." "$log"; then
      echo "  CANNOT CERTIFY: '$want_id' is exempted here, but its row" >&2
      echo "  '$want_row' never reported in this log." >&2
      echo "  A log that did not run the row proves nothing about an assertion" >&2
      echo "  inside it. Run the whole workspace, with --show-output." >&2
      fails=$((fails + 1))
      continue
    fi
    # --- /gate: gated-absent-row ---

    matched=0
    for line in "${gated_observed[@]:-}"; do
      [ -z "$line" ] && continue
      [ "$(awk '{print $2}' <<<"$line")" = "$want_id" ] || continue
      matched=1

      # Parsed OUTSIDE both gates below, deliberately: a gate block must
      # contain its own decision and nothing else, or deleting one to see
      # whether it was load-bearing breaks the next one instead of
      # exonerating it. Measured — the first version of this file put this
      # line inside the threshold gate, and the mutation run reported
      # `got_min: unbound variable` from the coherence gate.
      got_min="$(marker_field "$line" "min_cores")"
      got_cores="$(marker_field "$line" "cores")"

      # 4b. The gate must still be the gate that was agreed to. If
      #     `P99_MIN_CORES` moves, the exemption written for the old value
      #     is a different exemption and has to be re-argued, not inherited.
      # --- gate: gated-threshold ---
      if [ "$got_min" != "$want_min" ]; then
        echo "  GATE MOVED: '$want_id' reports min_cores='${got_min:-(absent)}'," >&2
        echo "  and this file agreed to '$want_min'. The constant in the test" >&2
        echo "  changed under the exemption: re-argue it here, or revert it there." >&2
        fails=$((fails + 1))
      fi
      # --- /gate: gated-threshold ---

      # 4c. The marker must be coherent with its own gate. A host that met
      #     the requirement and printed the non-assertion anyway means the
      #     emitting code no longer says what this file thinks it says.
      # --- gate: gated-incoherent ---
      if ! [[ "$got_cores" =~ ^[0-9]+$ ]] || ! [[ "$got_min" =~ ^[0-9]+$ ]] \
         || [ "$got_cores" -ge "$got_min" ]; then
        echo "  INCOHERENT MARKER: '$want_id' reports cores='${got_cores:-(absent)}'" >&2
        echo "  against min_cores='${got_min:-(absent)}'. The gate only fires below" >&2
        echo "  its own threshold, so this line cannot have come from the gate as" >&2
        echo "  written. Read it before believing either number." >&2
        fails=$((fails + 1))
      fi
      # --- /gate: gated-incoherent ---
    done

    # 4d. The row ran and said nothing: the assertion was MADE. That is
    #     good news and a stale exemption at the same time.
    # --- gate: gated-stale ---
    if [ "$matched" -eq 0 ] && [ "$gated_strict" = "1" ]; then
      echo "  STALE EXEMPTION: '$want_id' is exempted here, its row ran, and it" >&2
      echo "  emitted no 'not-asserted: ' line — so the assertion RAN." >&2
      echo "  DELETE the entry from GATED_EXPECTED, and delete the gate it" >&2
      echo "  describes from the test, in the same change." >&2
      fails=$((fails + 1))
    fi
    # --- /gate: gated-stale ---
    if [ "$matched" -eq 0 ] && [ "$gated_strict" != "1" ]; then
      echo "  NOTE: '$want_id' ran here — this host meets the condition the" >&2
      echo "  exemption is written for, so its absence is expected locally." >&2
      echo "  Where the exemption IS claimed (CI, or" >&2
      echo "  HOLDFAST_CENSUS_GATED_STRICT=1) this is a STALE EXEMPTION and fails." >&2
    fi
  done

  echo
  if [ "$fails" -ne 0 ]; then
    echo "SKIP CENSUS FAILED: $fails finding(s)" >&2
    return 1
  fi

  # Green here means "the shortfall is exactly the one we know about",
  # which is not the same as "nothing was skipped" and must not read like
  # it. Say so on the run summary page, every run, so the exemption is
  # visible to someone who never opens the log — and say the OTHER thing
  # on the day both lists are empty, rather than carrying a sentence about
  # fish into a run where fish ran.
  local note
  if [ "${#observed[@]}" -gt 0 ] || [ "${#gated_observed[@]}" -gt 0 ]; then
    note="skip census: ${#observed[@]} tolerated skip(s), ${#gated_observed[@]} tolerated non-assertion(s), 0 unexpected — what is listed above did NOT run"
  else
    note="skip census: nothing skipped, nothing gated off — every host-dependent row ran and every gated assertion was made"
  fi
  echo "SKIP CENSUS OK: $note"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      printf '### Skip census\n\n'
      printf '%s\n\n' "$note"
      # Guarded, because the state this file exists to reach is both lists
      # empty and nothing skipping, and `printf` with an empty array would
      # still emit one empty bullet — a summary that reports a skip that
      # does not exist.
      [ "${#observed[@]}" -gt 0 ] && printf -- '- `%s`\n' "${observed[@]}"
      [ "${#gated_observed[@]}" -gt 0 ] && printf -- '- `%s`\n' "${gated_observed[@]}"
    } >> "$GITHUB_STEP_SUMMARY"
  fi
  # No annotation when nothing skipped: a warning on a run with full
  # coverage trains people to ignore the warning that means something.
  if { [ "${#observed[@]}" -gt 0 ] || [ "${#gated_observed[@]}" -gt 0 ]; } \
     && [ -n "${GITHUB_ACTIONS:-}" ]; then
    printf '::warning::%s\n' "$note"
  fi
  return 0
}

# --------------------------------------------------------------------------
# The self-test
#
# A check nobody has watched fail is not a check. Every rule above sits in a
# named `# --- gate: … ---` block; this deletes them ONE AT A TIME from a
# copy of this file and asserts that the fixture each gate exists for stops
# being caught. A gate that can be deleted with every fixture still red was
# never doing the work its comment claims.
#
# The last check is the one that keeps this honest as the file grows: every
# gate sentinel in the source must appear in the mutation table, so a rule
# added without a mutation fails here rather than shipping unproven.
# --------------------------------------------------------------------------

SELF="${BASH_SOURCE[0]}"

self_test() {
  local td
  td="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$td'" EXIT

  local failures=0

  check() { # check <name> <got> <want> [<output to show on failure>]
    if [ "$2" = "$3" ]; then
      printf '  PASS  %s\n' "$1"
      printf '          got %s\n' "$2"
    else
      printf '  FAIL  %s\n' "$1"
      printf '          want %s\n' "$3"
      printf '          got  %s\n' "$2"
      [ -n "${4:-}" ] && printf '%s\n' "$4" | sed 's/^/          | /'
      failures=$((failures + 1))
    fi
  }

  run_census() { # run_census <script> <log> <strict> -> output on stdout, rc
    # The rc is returned rather than assigned to a global: the caller reads
    # this through a command substitution, which is a SUBSHELL, and a
    # variable set in there never comes back.
    local out rc
    out="$(env -u GITHUB_ACTIONS -u GITHUB_STEP_SUMMARY -u CI \
             HOLDFAST_CENSUS_GATED_STRICT="$3" bash "$1" "$2" 2>&1)"
    rc=$?
    printf '%s' "$out"
    return "$rc"
  }

  expect() { # expect <name> <log> <strict> <want_rc> [<want_substring>]
    local out got want rc
    out="$(run_census "$SELF" "$td/$2" "$3")"
    rc=$?
    got="rc=$rc"
    want="rc=$4"
    if [ -n "${5:-}" ]; then
      want="$want says=yes"
      if grep -qF -- "$5" <<<"$out"; then got="$got says=yes"; else got="$got says=no"; fi
    fi
    check "$1" "$got" "$want" "$out"
  }

  # ---- fixtures --------------------------------------------------------
  #
  # Shaped like the real thing, because the real thing is what the greps
  # are anchored against: `test result:` at column 0, the `---- NAME stdout
  # ----` banner `--show-output` prints for a PASSING test, and both
  # notices inside it. The `not-asserted: ` line below is the one a real
  # 2-core run of this suite emits, copied verbatim.
  cat > "$td/ci.log" <<'FIXTURE'
   Compiling clasp-core v0.0.4 (/repo/crates/clasp-core)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 41.02s
     Running tests/detection.rs (/repo/target/debug/deps/detection-0000000000000001)

running 21 tests
test the_pty_matrix_runs_every_host_dependent_row_but_the_two_it_names ... ok
test a_fish_prompt_is_marked ... ok

successes:

---- a_fish_prompt_is_marked stdout ----
skipping: fish not installed — the fish snippet remains UNVERIFIED by this suite (fish version: none)


successes:
    a_fish_prompt_is_marked

test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.00s

     Running tests/stress_write_path.rs (/repo/target/debug/deps/stress_write_path-0000000000000002)

running 1 test
test tier_b_stays_off_and_the_control_path_stays_responsive_under_load ... ok

successes:

---- tier_b_stays_off_and_the_control_path_stays_responsive_under_load stdout ----
not-asserted: stress_write_path::control_path_p99 cores=2 min_cores=8 — §11.4's p99 needs >= 8 cores to be a statement about CLASP rather than about the scheduler; this box has 2. Measured anyway: p99 1.109297052s, max 1.109297052s, 17 samples, 2343186436 bytes streamed.


successes:
    tier_b_stays_off_and_the_control_path_stays_responsive_under_load

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 127.70s
FIXTURE

  # A 48-core box: the same run, with the assertion MADE and so no notice.
  grep -v '^not-asserted: ' "$td/ci.log" > "$td/dev.log"
  # A gate nobody wrote down.
  { cat "$td/dev.log"
    echo "not-asserted: session::some_new_gate cores=2 min_cores=8 — a gate nobody wrote down"
  } > "$td/unknown.log"
  # The stress binary never ran: `cargo test --test detection` and nothing
  # else, or a build that died before it.
  sed '/Running tests\/stress_write_path.rs/,$d' "$td/ci.log" > "$td/norow.log"
  # `P99_MIN_CORES` moved under the exemption.
  sed 's/min_cores=8/min_cores=4/' "$td/ci.log" > "$td/thresh.log"
  # A marker from a host that met the gate's own condition.
  sed 's/cores=2 min_cores=8/cores=16 min_cores=8/' "$td/ci.log" > "$td/incoherent.log"
  # A row that started skipping without anyone agreeing to it.
  { cat "$td/ci.log"; echo "skipping: zsh not installed"; } > "$td/unexpected.log"
  # The fish row started passing.
  grep -v '^skipping: fish' "$td/ci.log" > "$td/stalefish.log"
  # A log that cannot be about the rows at all.
  grep -v 'tests/detection.rs' "$td/ci.log" > "$td/nodetect.log"
  # A log no test binary summarised: a build failure, or a truncated tee.
  grep -v '^test result:' "$td/ci.log" > "$td/nosummary.log"
  : > "$td/empty.log"

  echo "Self-test 1 — fixtures with known answers"
  echo

  # THE GREEN CASE, and it has to be green under CI's own strictness or the
  # entry could never be carried at all.
  expect "the log CI produces today is CLEAN under CI's strictness" \
    ci.log 1 0 "SKIP CENSUS OK"
  expect "...and it says what did NOT run, rather than reading as full coverage" \
    ci.log 1 0 "1 tolerated skip(s), 1 tolerated non-assertion(s)"
  expect "...and it names the gated assertion in the listing" \
    ci.log 1 0 "not-asserted: stress_write_path::control_path_p99 cores=2 min_cores=8"

  # THE TWO DEMONSTRATIONS THE BRIEF ASKS FOR.
  expect "a gated assertion nobody agreed to FAILS" \
    unknown.log 0 1 "UNEXPECTED NON-ASSERTION"
  expect "an agreed entry whose assertion RAN fails as a stale exemption" \
    dev.log 1 1 "STALE EXEMPTION: 'stress_write_path::control_path_p99'"

  # ANTI-VACUITY, the new half and the two that were already here.
  expect "a log that never ran the row cannot certify the entry" \
    norow.log 0 1 "CANNOT CERTIFY"
  expect "a log that never mentions tests/detection.rs certifies nothing" \
    nodetect.log 0 1 "never mentions tests/detection.rs"
  expect "a log with no 'test result:' line certifies nothing" \
    nosummary.log 0 1 "certifies nothing"
  expect "an EMPTY log is not a pass" \
    empty.log 0 1 ""
  expect "a log that does not exist is not a pass" \
    absent.log 0 1 "no such log file"

  # THE ENTRY TRACKS THE CODE, in both directions.
  expect "moving P99_MIN_CORES under the exemption FAILS" \
    thresh.log 0 1 "GATE MOVED"
  expect "a marker from a host that met the gate's own condition FAILS" \
    incoherent.log 0 1 "INCOHERENT MARKER"

  # THE ROW CENSUS, both directions, unchanged by all of the above.
  expect "an unexpected skip still FAILS" \
    unexpected.log 0 1 "UNEXPECTED SKIP: skipping: zsh not installed"
  expect "the fish exemption going stale still FAILS" \
    stalefish.log 0 1 "STALE EXEMPTION: nothing skipped with the prefix"

  expect "a strictness knob nobody can read is not a pass either" \
    ci.log yes 2 "is not 0, 1 or unset"

  # THE LOCAL CASE. A 48-core workstation must not be red for running MORE
  # than CI does — and must not be silent about it either.
  expect "off a claimed host, the assertion having run is a NOTE, not a failure" \
    dev.log 0 0 "NOTE: 'stress_write_path::control_path_p99' ran here"
  expect "...and that run is still a pass" \
    dev.log 0 0 "SKIP CENSUS OK"

  echo
  echo "Self-test 2 — every gate deleted, one at a time"
  echo

  # <gate name>|<fixture the gate is the only thing catching>|<strictness>
  local mutations=(
    "vacuity-detection|nodetect.log|0"
    "vacuity-result|nosummary.log|0"
    "skip-unexpected|unexpected.log|0"
    "skip-stale|stalefish.log|0"
    "gated-unexpected|unknown.log|0"
    "gated-absent-row|norow.log|0"
    "gated-threshold|thresh.log|0"
    "gated-incoherent|incoherent.log|0"
    "gated-stale|dev.log|1"
  )

  local m gate fixture strict before after mutant
  for m in "${mutations[@]}"; do
    IFS='|' read -r gate fixture strict <<<"$m"
    mutant="$td/mutant-$gate.sh"
    awk -v g="$gate" '
      $0 ~ ("^[[:space:]]*# --- gate: " g " ---") { skip = 1; next }
      $0 ~ ("^[[:space:]]*# --- /gate: " g " ---") { skip = 0; next }
      !skip { print }
    ' "$SELF" > "$mutant"
    before="$(wc -l < "$SELF")"
    after="$(wc -l < "$mutant")"
    if [ "$after" -ge "$before" ]; then
      check "MUTATION $gate — the gate block was found and removed" \
        "removed=0" "removed>0" "no '# --- gate: $gate ---' block in $SELF"
      continue
    fi
    local pristine_rc mutant_rc out
    run_census "$SELF" "$td/$fixture" "$strict" > /dev/null
    pristine_rc=$?
    out="$(run_census "$mutant" "$td/$fixture" "$strict")"
    mutant_rc=$?
    check "MUTATION — deleting gate '$gate' lets $fixture through" \
      "pristine_rc=$pristine_rc mutant_rc=$mutant_rc" "pristine_rc=1 mutant_rc=0" "$out"
  done

  # A gate with no mutation is a gate nobody has watched fail. This is what
  # makes the list above impossible to forget to extend.
  local -a declared covered missing
  mapfile -t declared < <(grep -oE '^[[:space:]]*# --- gate: [a-z-]+ ---' "$SELF" \
    | sed -E 's/.*# --- gate: ([a-z-]+) ---.*/\1/' | sort -u)
  mapfile -t covered < <(printf '%s\n' "${mutations[@]}" | cut -d'|' -f1 | sort -u)
  mapfile -t missing < <(comm -23 <(printf '%s\n' "${declared[@]}") <(printf '%s\n' "${covered[@]}"))
  echo
  check "every gate in this file has a mutation proving it load-bearing" \
    "gates=${#declared[@]} unmutated=[${missing[*]:-}]" \
    "gates=${#covered[@]} unmutated=[]"

  echo
  if [ "$failures" -ne 0 ]; then
    echo "SELF-TEST FAILED: $failures check(s)" >&2
    return 2
  fi
  echo "SELF-TEST OK"
  return 0
}

# --------------------------------------------------------------------------

case "${1:-}" in
  --self-test)
    self_test
    exit $?
    ;;
  "" | -h | --help)
    echo "usage: $0 <test-log>   (the log of a cargo test run made with --show-output)" >&2
    echo "       $0 --self-test  (delete each gate in turn and prove it was load-bearing)" >&2
    exit 2
    ;;
  *)
    census "$1"
    exit $?
    ;;
esac
