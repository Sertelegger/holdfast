//! The build identity `protocol::handshake::build_id()` reports (GH #178).
//!
//! That function is `option_env!("HOLDFAST_BUILD_SHA")`, and until this file
//! nothing set the variable outside the release pipeline — so every build from
//! source printed `(build unknown)`, the same string as the `v0.0.7` tag for a
//! tree a hundred commits past it, and the daemon's handshake said the same.
//! An operator asking "did my fix take effect?" had no answer from either.
//!
//! **This is the only place the identity is derived, and that is the point of
//! putting it in this crate rather than in the binary's.** `holdfast version`
//! and the daemon's `holdfast/handshake` reply both read `build_id()`, so the
//! CLI and the daemon it talks to cannot disagree about what a build is called.
//! Two build scripts deriving it independently could — one reruns and the other
//! does not — and a CLI and daemon printing different builds for the same
//! binary is a small copy of the confusion #178 is about.
//!
//! In order of precedence:
//!
//! 1. **`HOLDFAST_BUILD_SHA` from the environment, verbatim.** `release.yml`
//!    sets it to `github.sha`, and `scripts/package-release.sh` derives it when
//!    its caller did not, so a release binary names the exact commit it was
//!    built from. An explicit value is the caller's statement and is not
//!    shortened or second-guessed here.
//! 2. **`.cargo_vcs_info.json` beside this manifest.** `cargo package` writes
//!    it into every packaged crate, recording the commit the package was cut
//!    from — so `cargo install holdfast` from crates.io reports a real sha too,
//!    with no `.git` anywhere. Its presence also means "this is a package, not
//!    a checkout", which is why step 3 is not tried when it exists.
//! 3. **The git checkout this crate sits in — `../../.git`, exactly, and only
//!    from `crates/holdfast-core`.** Never a walk upward: a vendored copy or a
//!    registry source can sit below some unrelated repository (a dotfiles repo
//!    in `$HOME` is common), and walking up would report *that* repository's
//!    commit with complete confidence, which is worse than `unknown`. The
//!    fixed depth alone does not close that — `cargo vendor` puts this crate
//!    at `<project>/vendor/holdfast-core`, two levels below the *consuming*
//!    project's `.git` — so the directory above the manifest must also be
//!    this workspace's `crates`.
//! 4. `unknown`.
//!
//! **It never fails the build.** A tarball has no `.git`, a container may have
//! no `git` binary, and a checkout may be owned by another user; every one of
//! those falls through to the next step silently, because a build that stopped
//! over its own label would be the wrong trade.
//!
//! **Rerun precision is the correctness property, not a nicety.** A sha that
//! goes stale across commits in an incremental build prints a wrong id with
//! confidence. So the script watches the checkout's `HEAD`, the ref `HEAD`
//! names — or, for a packed branch, the nearest directory its next commit
//! will write the ref under — and `packed-refs`, and nothing broader, because
//! any rerun of this script recompiles `holdfast-core` and everything above
//! it, and a watch on all of `refs/` would rebuild the world whenever
//! *another* worktree of the same repository committed. The git plumbing it reads is resolved for a
//! linked worktree too, where `.git` is a file pointing into the main
//! repository's `worktrees/<name>/` and refs live in the common directory.

// The functions `tests/build_script.rs` drives are `pub`, because that file
// compiles this one as a module with `#[path]`.

use std::path::{Path, PathBuf};

const VAR: &str = "HOLDFAST_BUILD_SHA";

/// Length of the id derived from git or from `.cargo_vcs_info.json`, matching
/// `scripts/package-release.sh`'s `git rev-parse --short=12`.
const SHORT: usize = 12;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed={VAR}");

    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());

    let id = from_env()
        .or_else(|| from_vcs_info(&manifest))
        .or_else(|| {
            // Only a real checkout gets this far; a package stops at step 2
            // whether or not it found a sha there.
            if manifest.join(".cargo_vcs_info.json").exists() {
                return None;
            }
            let found = from_checkout(&manifest)?;
            for path in &found.watch {
                println!("cargo:rerun-if-changed={}", path.display());
            }
            found.id
        })
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env={VAR}={id}");
}

/// Step 1. Empty counts as unset, and anything that would not survive being a
/// `cargo:` directive line is refused rather than emitted.
fn from_env() -> Option<String> {
    let value = std::env::var(VAR).ok()?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.chars().any(|c| c.is_control()) {
        println!("cargo:warning={VAR} contains a control character and was ignored");
        return None;
    }
    Some(value.to_string())
}

/// Step 2. `{"git": {"sha1": "<40 hex>", ...}, "path_in_vcs": "..."}` — read by
/// looking for the one key rather than by a JSON parser, because a build
/// script's dependencies are compiled for every build of this crate and this
/// is the only JSON it reads.
pub fn from_vcs_info(manifest: &Path) -> Option<String> {
    let text = std::fs::read_to_string(manifest.join(".cargo_vcs_info.json")).ok()?;
    let after = text.split("\"sha1\"").nth(1)?;
    let value = after.split('"').nth(1)?;
    short_sha(value)
}

/// What step 3 found: the id if it could resolve one, and the files whose
/// change means it has to be resolved again.
pub struct Checkout {
    pub id: Option<String>,
    pub watch: Vec<PathBuf>,
}

/// Step 3.
pub fn from_checkout(manifest: &Path) -> Option<Checkout> {
    let crates = manifest.parent()?;
    if crates.file_name()? != "crates" {
        return None;
    }
    let root = crates.parent()?;
    let dotgit = root.join(".git");
    // A directory in an ordinary clone; a file in a linked worktree (and in a
    // submodule), holding `gitdir: <path>`, relative to the file's directory
    // when it is not absolute.
    let gitdir = if dotgit.is_dir() {
        dotgit
    } else if dotgit.is_file() {
        let text = std::fs::read_to_string(&dotgit).ok()?;
        let target = PathBuf::from(text.trim().strip_prefix("gitdir:")?.trim());
        if target.is_relative() {
            root.join(target)
        } else {
            target
        }
    } else {
        return None;
    };
    // A linked worktree keeps its own `HEAD` but shares refs with the main
    // repository, which `commondir` names (relative to the worktree's gitdir).
    let common = match std::fs::read_to_string(gitdir.join("commondir")) {
        Ok(text) => {
            let p = PathBuf::from(text.trim());
            if p.is_relative() {
                gitdir.join(p)
            } else {
                p
            }
        }
        Err(_) => gitdir.clone(),
    };

    let head_path = gitdir.join("HEAD");
    let head = std::fs::read_to_string(&head_path).ok()?;
    let mut watch = vec![head_path];
    let packed = common.join("packed-refs");
    if packed.is_file() {
        watch.push(packed.clone());
    }

    let head = head.trim();
    let sha = match head.strip_prefix("ref:") {
        None => short_sha(head),
        Some(name) => {
            let name = name.trim();
            let loose = common.join(name);
            if loose.is_file() {
                watch.push(loose.clone());
                std::fs::read_to_string(&loose)
                    .ok()
                    .and_then(|s| short_sha(s.trim()))
            } else {
                // Packed, or not yet born. The first commit on a packed branch
                // *creates* the loose file, which a watch on a file that does
                // not exist would miss — and cargo treats a missing watched
                // path as always stale, which would recompile this crate on
                // every build. So the nearest directory the file would appear
                // under is watched instead, and cargo scans a watched
                // directory's whole tree. Only in this case: it also changes
                // when a sibling branch moves, which is a spurious rebuild and
                // not a wrong answer.
                //
                // **The nearest that exists, not the parent.** `pack-refs
                // --prune` (and so `git gc`) removes a branch's directory once
                // it is empty, so for `feature/x` the parent is usually gone,
                // and the commit that recreates it touched nothing this used
                // to watch — the id went stale, which is the failure this file
                // exists to prevent. Bounded at `refs/`, which every
                // repository has.
                if let Some(dir) = nearest_existing_dir(&loose, &common.join("refs")) {
                    watch.push(dir);
                }
                std::fs::read_to_string(&packed)
                    .ok()
                    .and_then(|text| packed_ref(&text, name))
            }
        }
    };

    // The files above are git's plumbing, not its interface. A repository in
    // the `reftable` format keeps its refs elsewhere and answers none of the
    // reads above, so ask git itself before giving up — and watch the file
    // that format rewrites on every ref update.
    let sha = sha.or_else(|| {
        let tables = common.join("reftable").join("tables.list");
        if tables.is_file() {
            watch.push(tables);
        }
        rev_parse(root)
    });

    Some(Checkout { id: sha, watch })
}

/// The nearest ancestor directory of `path` that exists, no higher than
/// `bound` — the directory a file created at `path` will appear under.
fn nearest_existing_dir(path: &Path, bound: &Path) -> Option<PathBuf> {
    path.ancestors()
        .skip(1)
        .take_while(|d| d.starts_with(bound))
        .find(|d| d.is_dir())
        .map(Path::to_path_buf)
}

/// `<sha> <refname>` lines, after an optional `# pack-refs with:` header;
/// `^<sha>` lines peel the tag above them and are never what `HEAD` names.
fn packed_ref(text: &str, name: &str) -> Option<String> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('^'))
        .find_map(|l| {
            let (sha, refname) = l.split_once(' ')?;
            (refname.trim() == name).then(|| short_sha(sha)).flatten()
        })
}

fn rev_parse(root: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    short_sha(String::from_utf8_lossy(&out.stdout).trim())
}

/// A full object name — 40 hex for SHA-1, 64 for SHA-256 repositories —
/// shortened to [`SHORT`]. Anything else is not a sha and is not reported as
/// one.
pub fn short_sha(s: &str) -> Option<String> {
    let ok = (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit());
    ok.then(|| s[..SHORT].to_ascii_lowercase())
}
