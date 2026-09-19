#!/usr/bin/env python3
"""Assert the plugin and marketplace manifests say what the loader needs.

`claude plugin validate --strict` is the official check and it belongs in CI
too, but it is **not** a substitute for this file, and the gap is measured:
with `plugin/commands/holdfast/status.md` in place of `plugin/commands/
status.md` the official validator prints "Validation passed" while the three
commands are silently never loaded -- auto-discovery does not walk
subdirectories. A green official check is not evidence about the layout.

What is asserted here, and why each one is here rather than assumed:

  version lockstep   Three files, not the two spec section 12.5 names:
                     Cargo.toml, plugin/version.txt AND
                     plugin/.claude-plugin/plugin.json. The install cache is
                     keyed `cache/<marketplace>/<plugin>/<version>/` from
                     plugin.json, so a release that bumps version.txt alone
                     ships a plugin that never updates.
  author is an object  A bare string is a hard validator error.
  marketplace name   `/plugin install holdfast@holdfast` works because
                     marketplace.json's `name` is `holdfast`. It is not
                     derived from the repo name.
  braced variable    `${CLAUDE_PLUGIN_ROOT}` substitutes; the unbraced
                     `$CLAUDE_PLUGIN_ROOT` is passed through literally and the
                     server fails to start with ENOENT. Measured both ways.
  flat commands      The rule the official validator misses.
  no commands array  Declaring one makes `claude plugin details` under-report
                     its own components; auto-discovery needs no array.
  one namespace      Plugin commands are `<plugin>:<basename>` and project
                     commands are `<directory>:<basename>`, so
                     `plugin/commands/` and `.claude/commands/holdfast/`
                     land in ONE `holdfast:` namespace. A file in both is an
                     ambiguous name, not two commands.

Usage:  plugin-manifest-check.py [--self-test]
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

KEBAB = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
SEMVERISH = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+")


class Report:
    def __init__(self):
        self.fails = []
        self.oks = 0

    def ok(self, msg):
        self.oks += 1
        print("  ok    %s" % msg)

    def fail(self, msg):
        self.fails.append(msg)
        print("  FAIL  %s" % msg)

    def check(self, cond, ok_msg, fail_msg):
        if cond:
            self.ok(ok_msg)
        else:
            self.fail(fail_msg)
        return cond


def load_json(r, path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        r.fail("%s does not exist" % path)
    except ValueError as e:
        r.fail("%s is not valid JSON: %s" % (path, e))
    return None


def cargo_version(r, root):
    path = os.path.join(root, "Cargo.toml")
    try:
        text = open(path).read()
    except OSError:
        r.fail("cannot read %s" % path)
        return None
    m = re.search(r"^\[workspace\.package\]$(.*?)^\[", text, re.M | re.S)
    block = m.group(1) if m else text
    m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
    if not m:
        r.fail("no workspace version in Cargo.toml")
        return None
    return m.group(1)


def check_tree(root):
    r = Report()
    print("--- plugin and marketplace manifests (%s) ---" % root)

    mk_path = os.path.join(root, ".claude-plugin", "marketplace.json")
    pl_path = os.path.join(root, "plugin", ".claude-plugin", "plugin.json")
    mcp_path = os.path.join(root, "plugin", ".mcp.json")
    ver_path = os.path.join(root, "plugin", "version.txt")

    mk = load_json(r, mk_path)
    pl = load_json(r, pl_path)
    mcp = load_json(r, mcp_path)
    if mk is None or pl is None or mcp is None:
        return r

    # --- versions in lockstep ---------------------------------------------
    cv = cargo_version(r, root)
    try:
        vt = open(ver_path).read().strip()
    except OSError:
        r.fail("cannot read %s" % ver_path)
        vt = None
    pv = pl.get("version")
    if cv and vt and pv:
        r.check(cv == vt == pv,
                "version is %s in Cargo.toml, version.txt and plugin.json" % cv,
                "versions disagree: Cargo.toml=%s version.txt=%s plugin.json=%s "
                "-- the install cache keys on plugin.json, so a plugin that "
                "lags it never updates" % (cv, vt, pv))
    r.check(pv is not None and bool(SEMVERISH.match(str(pv))),
            "plugin.json version %r looks like semver" % pv,
            "plugin.json version %r is not X.Y.Z -- the validator does NOT "
            "check this, so nothing else will catch it" % pv)

    # --- plugin.json shape -------------------------------------------------
    name = pl.get("name")
    r.check(isinstance(name, str) and bool(KEBAB.match(name)),
            "plugin name %r is kebab-case" % name,
            "plugin name %r is not kebab-case -- Claude Code accepts it but "
            "the Claude.ai marketplace sync requires it" % name)
    r.check(isinstance(pl.get("author"), dict),
            "plugin.json author is an object",
            "plugin.json author must be an OBJECT; a bare string is a hard "
            "validator error")
    r.check("commands" not in pl,
            "plugin.json declares no `commands` array (auto-discovery needs none)",
            "plugin.json declares a `commands` array -- unnecessary, and it "
            "makes `claude plugin details` report its own components as zero")

    # --- marketplace.json shape -------------------------------------------
    r.check(mk.get("name") == "holdfast",
            "marketplace name is `holdfast`, so `/plugin install holdfast@holdfast` resolves",
            "marketplace name is %r; spec section 13.4's install line needs "
            "`holdfast`" % mk.get("name"))
    r.check(isinstance(mk.get("owner"), dict),
            "marketplace owner is an object",
            "marketplace owner must be an object")
    plugins = mk.get("plugins")
    if r.check(isinstance(plugins, list) and len(plugins) == 1,
               "marketplace lists exactly one plugin",
               "marketplace must list exactly one plugin, got %r" % (plugins,)):
        entry = plugins[0]
        src = entry.get("source")
        r.check(src == "./plugin",
                "marketplace source is ./plugin",
                "marketplace source is %r; paths resolve against the "
                "MARKETPLACE ROOT (the directory holding .claude-plugin/), "
                "not against marketplace.json" % src)
        r.check(entry.get("name") == name,
                "marketplace and plugin.json agree the plugin is %r" % name,
                "marketplace says %r, plugin.json says %r"
                % (entry.get("name"), name))

    # --- .mcp.json --------------------------------------------------------
    servers = mcp.get("mcpServers", mcp)
    r.check(isinstance(servers, dict) and len(servers) == 1,
            ".mcp.json registers exactly one server",
            ".mcp.json must register exactly one server, got %r" % (list(servers) if isinstance(servers, dict) else servers,))
    for sname, srv in (servers.items() if isinstance(servers, dict) else []):
        cmd = srv.get("command", "")
        r.check(cmd.startswith("${CLAUDE_PLUGIN_ROOT}/"),
                "server %r commands ${CLAUDE_PLUGIN_ROOT}/... (braced, absolute)" % sname,
                "server %r command is %r -- it must start with the BRACED "
                "${CLAUDE_PLUGIN_ROOT}/; the unbraced form is passed through "
                "literally, and a relative command resolves against the "
                "USER's cwd, not the plugin" % (sname, cmd))
        r.check("/bin/" not in cmd,
                "server %r command is not under bin/" % sname,
                "server %r command is under bin/, which the validator "
                "special-cases for the `binaries` map: it will report the "
                "file is not a declared binary and the server will not start"
                % sname)
        rel = cmd.replace("${CLAUDE_PLUGIN_ROOT}/", "", 1)
        target = os.path.join(root, "plugin", rel)
        r.check(os.path.isfile(target),
                "the command %r exists in the plugin tree" % rel,
                "the command %r does not exist in the plugin tree" % rel)
        r.check(os.path.isfile(target) and os.access(target, os.X_OK),
                "%r is executable (nothing interprets it -- it is spawned directly)" % rel,
                "%r is not executable; the loader spawns it with no shell, so "
                "the exec bit must be committed" % rel)
        r.check(srv.get("args") == ["mcp"],
                "server %r passes args [\"mcp\"]" % sname,
                "server %r args are %r, expected [\"mcp\"]" % (sname, srv.get("args")))

    # --- commands: flat, and one namespace --------------------------------
    pc_dir = os.path.join(root, "plugin", "commands")
    plugin_cmds = set()
    if os.path.isdir(pc_dir):
        subdirs = [e for e in sorted(os.listdir(pc_dir))
                   if os.path.isdir(os.path.join(pc_dir, e))]
        r.check(not subdirs,
                "plugin/commands/ is flat",
                "plugin/commands/ has subdirector%s %s -- command "
                "auto-discovery is FLAT-ONLY and does not walk them. "
                "`claude plugin validate --strict` calls this healthy; it is "
                "not." % ("y" if len(subdirs) == 1 else "ies", subdirs))
        plugin_cmds = {e[:-3] for e in os.listdir(pc_dir) if e.endswith(".md")}
        r.check(bool(plugin_cmds),
                "plugin/commands/ holds %d command(s): %s"
                % (len(plugin_cmds), ", ".join(sorted(plugin_cmds))),
                "plugin/commands/ holds no .md files, so this rule compared "
                "two empty sets")
    else:
        r.fail("plugin/commands/ does not exist")

    proj_dir = os.path.join(root, ".claude", "commands", "holdfast")
    proj_cmds = set()
    if os.path.isdir(proj_dir):
        proj_cmds = {e[:-3] for e in os.listdir(proj_dir) if e.endswith(".md")}
    clash = plugin_cmds & proj_cmds
    r.check(not clash,
            "plugin and project command names are disjoint (%d + %d in one "
            "`holdfast:` namespace)" % (len(plugin_cmds), len(proj_cmds)),
            "these names exist in BOTH plugin/commands/ and "
            ".claude/commands/holdfast/: %s. They resolve into one "
            "`holdfast:` namespace, so each is an ambiguous name rather than "
            "two commands." % ", ".join(sorted(clash)))

    # --- the files the bootstrap needs beside itself ----------------------
    for f in ("version.txt", "lib-safe-extract.sh", "bootstrap.ps1",
              "lib-safe-extract.ps1", "bootstrap.cmd", "README.md"):
        p = os.path.join(root, "plugin", f)
        r.check(os.path.isfile(p),
                "plugin/%s ships" % f,
                "plugin/%s is missing -- only the plugin/ subtree is copied "
                "to the install cache, so anything the bootstrap reads must "
                "be inside it" % f)

    return r


def git_mode(root, path):
    try:
        out = subprocess.check_output(
            ["git", "-C", root, "ls-files", "-s", "--", path],
            stderr=subprocess.DEVNULL).decode()
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.split()[0] if out.strip() else None


def check_git_modes(root, r):
    print("--- the exec bit is committed, not just set locally ---")
    for path in ("plugin/bootstrap", "scripts/plugin-archive-tests.sh",
                 "scripts/plugin-bootstrap-tests.sh",
                 "scripts/plugin-archive-corpus.py",
                 "scripts/plugin-manifest-check.py"):
        mode = git_mode(root, path)
        if mode is None:
            print("  skip  %s is not tracked yet" % path)
            continue
        r.check(mode == "100755",
                "%s is committed mode 100755" % path,
                "%s is committed mode %s; a bootstrap that loses its exec bit "
                "in git is a plugin that cannot start" % (path, mode))


# ---------------------------------------------------------------------------
# Self-test. Every rule above is deleted-by-fixture here, because a rule that
# has never fired is a rule nobody is holding. The fixtures are built by
# copying the REAL tree and breaking exactly one thing, so a case cannot pass
# by tripping some other rule.
# ---------------------------------------------------------------------------
def self_test(root):
    breakages = [
        ("nested commands",
         lambda d: (os.makedirs(os.path.join(d, "plugin/commands/holdfast")),
                    shutil.move(os.path.join(d, "plugin/commands/install.md"),
                                os.path.join(d, "plugin/commands/holdfast/install.md")))),
        ("author as a string", lambda d: _patch(d, "plugin/.claude-plugin/plugin.json",
                                                {"author": "Sascha Sertel"})),
        ("version.txt out of step", lambda d: _write(d, "plugin/version.txt", "9.9.9\n")),
        ("plugin.json version out of step",
         lambda d: _patch(d, "plugin/.claude-plugin/plugin.json", {"version": "9.9.9"})),
        ("a commands array", lambda d: _patch(d, "plugin/.claude-plugin/plugin.json",
                                              {"commands": ["./commands/attach.md"]})),
        ("marketplace renamed", lambda d: _patch(d, ".claude-plugin/marketplace.json",
                                                 {"name": "sertelegger"})),
        ("unbraced variable", lambda d: _patch_server(d, "command", "$CLAUDE_PLUGIN_ROOT/bootstrap")),
        ("relative command", lambda d: _patch_server(d, "command", "./bootstrap")),
        ("command under bin/", lambda d: _patch_server(d, "command", "${CLAUDE_PLUGIN_ROOT}/bin/holdfast")),
        ("bootstrap not executable", lambda d: os.chmod(os.path.join(d, "plugin/bootstrap"), 0o644)),
        ("a colliding command name",
         lambda d: shutil.copy(os.path.join(d, "plugin/commands/attach.md"),
                               os.path.join(d, "plugin/commands/doctor.md"))),
        ("version.txt deleted", lambda d: os.remove(os.path.join(d, "plugin/version.txt"))),
    ]
    failures = 0
    print("=== self-test: the real tree must pass ===")
    base = check_tree(root)
    if base.fails:
        print("SELF-TEST FAIL: the real tree does not pass its own rules")
        return 1
    print("  (%d assertion(s) green)\n" % base.oks)

    for label, breaker in breakages:
        d = tempfile.mkdtemp(prefix="hf-manifest-")
        try:
            for item in (".claude-plugin", "plugin", "Cargo.toml", ".claude"):
                s = os.path.join(root, item)
                t = os.path.join(d, item)
                if os.path.isdir(s):
                    shutil.copytree(s, t)
                elif os.path.isfile(s):
                    shutil.copy(s, t)
            breaker(d)
            rep = _quiet(lambda: check_tree(d))
            if rep.fails:
                print("  ok    caught: %s" % label)
            else:
                print("  FAIL  NOT caught: %s" % label)
                failures += 1
        finally:
            shutil.rmtree(d, ignore_errors=True)
    print("\nself-test: %d case(s), %d not caught" % (len(breakages), failures))
    return 1 if failures else 0


def _patch(d, rel, updates):
    p = os.path.join(d, rel)
    obj = json.load(open(p))
    obj.update(updates)
    json.dump(obj, open(p, "w"), indent=2)


def _patch_server(d, key, value):
    p = os.path.join(d, "plugin/.mcp.json")
    obj = json.load(open(p))
    for srv in obj["mcpServers"].values():
        srv[key] = value
    json.dump(obj, open(p, "w"), indent=2)


def _write(d, rel, text):
    open(os.path.join(d, rel), "w").write(text)


class _Sink:
    def write(self, _):
        pass

    def flush(self):
        pass


def _quiet(fn):
    old = sys.stdout
    sys.stdout = _Sink()
    try:
        return fn()
    finally:
        sys.stdout = old


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if "--self-test" in sys.argv[1:]:
        return self_test(root)
    r = check_tree(root)
    check_git_modes(root, r)
    print("\nplugin-manifest-check: %d ok, %d failed" % (r.oks, len(r.fails)))
    return 1 if r.fails else 0


if __name__ == "__main__":
    sys.exit(main())
