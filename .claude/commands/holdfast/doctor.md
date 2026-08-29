---
description: Diagnose a Holdfast install — daemon, sockets, permissions, version skew
allowed-tools: Bash(./target/debug/holdfast:*), Bash(holdfast:*), Bash(stat:*), Bash(ls:*), Bash(lsof:*), Bash(ss:*), Bash(ps:*), Bash(cargo:*), Bash(test:*), Bash(printenv:*)
---

Diagnose this Holdfast install and report what is wrong. **Read-only: change
nothing, start nothing, stop nothing.** If a fix is obvious, describe it and
ask — a doctor that treats without consent is how a diagnostic becomes an
outage.

Work out the instance first. The runtime directory is `$HOLDFAST_RUNTIME_DIR`
when set, else `~/.holdfast`; config is `$XDG_CONFIG_HOME/holdfast/config.toml`,
else `~/.config/holdfast/config.toml`. **`HOLDFAST_RUNTIME_DIR` deliberately
does not move the config** (REQ-CFG-005 is instance selection, not a
configuration knob), so a report that conflates them is wrong. Say which
instance you are describing.

Then check, and report only what is interesting:

1. **Is the daemon running?** `holdfast daemon status --json`. Report pid,
   uptime, version, live/retained session counts.
2. **Version skew.** Compare the daemon's reported `version` against
   `holdfast version`. A daemon that outlived a rebuild is the likeliest cause
   of "my fix did nothing", and it survives by design — sessions are supposed
   to outlive the binary that made them.
3. **Permissions.** The runtime directory must be `0700`; `control.sock`,
   `attach.sock`, `holdfast.pid`, `holdfast.lock` and `bind.lock` must be
   `0600`; `logs/` must be `0700`. Anything looser is the finding.
4. **`http.sock` must not exist.** It belongs to milestone 0.0.10; its presence
   means that milestone crept forward.
5. **No listening TCP socket** (REQ-D-001) — the daemon speaks Unix sockets
   only. Check the daemon pid's own listeners, not the machine's.
6. **Stale pid file.** A `holdfast.pid` naming a pid that is gone, or that is
   alive but is not a Holdfast daemon, is the dangerous case: the file is
   written at startup and removed only on a clean exit, so a killed daemon
   leaves one behind and the kernel is free to hand that pid to anything.
7. **Sessions.** Anything `AwaitingSecret` (blocked on a password prompt),
   anything retained after exit, anything close to its idle timeout.

**Use portable commands, and do not assume GNU.** This project has been bitten
repeatedly: `stat -c '%a'` is GNU and BSD wants `stat -f '%Lp'`; `printenv A B`
prints only `A` on BSD and exits 0; `ps -o comm=` omits arguments, so matching
on a command line against it silently never hits; `timeout` is absent from a
stock macOS. Ask GNU first and fall back, or read the mode with `ls -ld` and
say which you used.

Report as a short list of findings, worst first, each with the evidence that
produced it. **If everything checks out, say so in two or three lines** — do
not pad a clean bill of health into a report. Distinguish "checked and fine"
from "could not check", and never let a command that failed to run read as a
check that passed.
