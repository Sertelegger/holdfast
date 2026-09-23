//! `build.rs`'s derivation of the build id (GH #178) — what it watches, above
//! all, because a watch that misses a commit prints the old id with complete
//! confidence.
//!
//! **Why the script is compiled into a test at all.** A build script is its
//! own crate and `cargo test` never runs it with `--test`; what it computes
//! reaches the rest of the tree as one `rustc-env` line, and what it watches
//! reaches nobody. `#[path]` compiles the same file here as a module, so these
//! rows drive the code cargo runs.
//!
//! **What "watched" means, and the one fact every row leans on.** Cargo reruns
//! the script when a `rerun-if-changed` path's mtime is newer than the last
//! run — and for a **directory** it scans the whole tree under it. So a commit
//! is seen exactly when the file it writes is a watched path or lies under a
//! watched directory. That is what [`sees`] asserts, rather than comparing
//! mtimes: file timestamps are coarser than the time these rows take, so an
//! mtime comparison would be a race dressed as an assertion.

#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

use build_script::{derive, from_checkout, short_sha};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SHA_A: &str = "0123456789abcdef0123456789abcdef01234567";
const SHA_B: &str = "89abcdef0123456789abcdef0123456789abcdef";

fn short(sha: &str) -> String {
    short_sha(sha).expect("a full object name")
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// `<root>/crates/holdfast-core/`, the only layout step 3 accepts; returns
/// the manifest directory.
fn workspace(root: &Path) -> PathBuf {
    let manifest = root.join("crates").join("holdfast-core");
    fs::create_dir_all(&manifest).unwrap();
    manifest
}

/// Whether cargo would rerun the script when `written` is created or
/// rewritten: it is watched itself, or a watched directory contains it.
fn sees(watch: &[PathBuf], written: &Path) -> bool {
    watch
        .iter()
        .any(|w| w == written || (w.is_dir() && written.starts_with(w)))
}

/// Every watched path must exist: cargo reads a missing one as always stale,
/// and would recompile `holdfast-core` and everything above it on every build.
fn assert_all_exist(watch: &[PathBuf]) {
    for p in watch {
        assert!(p.exists(), "watches {}, which does not exist", p.display());
    }
}

/// **The review's case.** A branch whose name has a slash, packed by `git gc`
/// or `git pack-refs --all --prune` — which also removes the now-empty
/// `refs/heads/feature/`. The first commit on it creates that directory and
/// the loose file inside it, and changes neither `HEAD` nor `packed-refs`. The
/// script watched the directory the loose file *would* be in only when that
/// directory existed, so here it watched nothing a commit touches, and the
/// binary went on naming the commit before.
#[test]
fn a_packed_branch_whose_directory_is_gone_is_watched_where_its_next_commit_lands() {
    for branch in ["feature/x", "a/b/c"] {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = workspace(tmp.path());
        let git = tmp.path().join(".git");
        write(&git.join("HEAD"), &format!("ref: refs/heads/{branch}\n"));
        fs::create_dir_all(git.join("refs").join("heads")).unwrap();
        write(
            &git.join("packed-refs"),
            &format!(
                "# pack-refs with: peeled fully-peeled sorted \n{SHA_A} refs/heads/{branch}\n"
            ),
        );

        let found = from_checkout(&manifest).expect("a checkout");
        assert_eq!(found.id, short_sha(SHA_A), "{branch}");
        assert_all_exist(&found.watch);
        let loose = git.join("refs").join("heads").join(branch);
        assert!(
            sees(&found.watch, &loose),
            "{branch}: the first commit creates {}, and nothing watched contains it: {:?}",
            loose.display(),
            found.watch
        );
    }
}

/// The same case against real `git`, so the row is about what `git` does
/// rather than about a layout this file drew: `pack-refs --all --prune`
/// really does remove the branch's directory, and the next commit really
/// does write the loose file there.
#[test]
fn a_commit_on_a_packed_branch_is_seen_and_named() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let manifest = workspace(root);
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args([
                "-c",
                "user.name=holdfast-test",
                "-c",
                "user.email=holdfast-test@invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            // Nobody's own configuration: a global `init.defaultBranch`,
            // signing or template directory would change what is under test.
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    if git(&["--version"]).is_none() {
        println!("skipping: build.rs against real git — no `git` on PATH");
        return;
    }
    let head = |git: &dyn Fn(&[&str]) -> Option<String>| {
        git(&["rev-parse", "--short=12", "HEAD"]).expect("rev-parse")
    };
    git(&["init", "-q"]).expect("git init");
    git(&["commit", "-q", "--allow-empty", "-m", "one"]).expect("commit");
    git(&["checkout", "-q", "-b", "feature/x"]).expect("branch");
    git(&["commit", "-q", "--allow-empty", "-m", "two"]).expect("commit");
    git(&["pack-refs", "--all", "--prune"]).expect("pack-refs");
    let feature_dir = root.join(".git").join("refs").join("heads").join("feature");
    assert!(
        !feature_dir.exists(),
        "`pack-refs --prune` left {} behind, so this row no longer reaches the case it is for",
        feature_dir.display()
    );

    let before = from_checkout(&manifest).expect("a checkout");
    assert_eq!(before.id.as_deref(), Some(head(&git).as_str()));
    assert_all_exist(&before.watch);

    git(&["commit", "-q", "--allow-empty", "-m", "three"]).expect("commit");
    let loose = feature_dir.join("x");
    assert!(loose.is_file(), "the commit did not write the loose ref");
    assert!(
        sees(&before.watch, &loose),
        "a commit on a packed branch wrote {}, which nothing the script watched contains: {:?}",
        loose.display(),
        before.watch
    );
    // And the rerun that triggers names the new commit.
    let after = from_checkout(&manifest).expect("a checkout");
    assert_eq!(after.id.as_deref(), Some(head(&git).as_str()));
    assert_ne!(after.id, before.id);
}

/// The ordinary case, for contrast and against a fix that over-reaches: a
/// branch with a loose file is watched *as that file*, which a commit
/// rewrites — and nothing is watched for it that does not exist.
#[test]
fn a_loose_branch_is_watched_as_its_own_file() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = workspace(tmp.path());
    let git = tmp.path().join(".git");
    write(&git.join("HEAD"), "ref: refs/heads/feature/x\n");
    let loose = git.join("refs").join("heads").join("feature").join("x");
    write(&loose, &format!("{SHA_A}\n"));

    let found = from_checkout(&manifest).expect("a checkout");
    assert_eq!(found.id, short_sha(SHA_A));
    assert!(found.watch.contains(&loose), "{:?}", found.watch);
    assert!(found.watch.contains(&git.join("HEAD")), "{:?}", found.watch);
    assert_all_exist(&found.watch);
}

/// The climb stops at `refs/`. Above it is the whole `.git` directory,
/// objects and index included, which a watch would rescan on every build and
/// which changes on every `git add` — a spurious rebuild of everything above
/// `holdfast-core` for each one. A repository with no `refs/` is not one git
/// made, and gets nothing broader than `HEAD`.
#[test]
fn the_watch_never_climbs_above_refs() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = workspace(tmp.path());
    let git = tmp.path().join(".git");
    write(&git.join("HEAD"), "ref: refs/heads/feature/x\n");
    fs::create_dir_all(git.join("objects")).unwrap();

    let found = from_checkout(&manifest).expect("a checkout");
    assert_all_exist(&found.watch);
    for w in &found.watch {
        assert!(
            !git.starts_with(w),
            "watches {}, which contains the whole repository",
            w.display()
        );
    }
}

/// **Precedence, step 1 over the rest: the environment, verbatim.**
/// `release.yml` passes the full 40-hex `github.sha`, and the rehearsal
/// checks for exactly that, so it is not shortened; empty is unset; and a
/// value that would end the `rustc-env` directive line early — and make the
/// rest a directive of its own — is refused with a warning, and the next
/// step answers.
#[test]
fn the_environment_wins_verbatim_and_a_value_that_would_break_the_directive_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = workspace(tmp.path());
    write(&tmp.path().join(".git/HEAD"), &format!("{SHA_A}\n"));

    for given in [SHA_B, "v0.0.8-rc1+local"] {
        let d = derive(&manifest, Some(given));
        assert_eq!(d.id, given);
        assert!(d.watch.is_empty(), "{:?}", d.watch);
        assert!(d.warnings.is_empty(), "{:?}", d.warnings);
    }
    assert_eq!(derive(&manifest, Some("  ")).id, short(SHA_A));
    let d = derive(&manifest, Some("abc\ncargo:rustc-cfg=evil"));
    assert_eq!(d.id, short(SHA_A));
    assert_eq!(d.warnings.len(), 1, "{:?}", d.warnings);
}

/// **Step 2 over step 3: a package reports the commit it was cut from.**
/// `cargo package` writes `.cargo_vcs_info.json`, and a crate that has one
/// is a package whatever sits around it — so the `.git` beside it is never
/// consulted, even when the record carries no sha.
#[test]
fn a_package_reports_the_commit_it_was_cut_from_and_never_looks_for_git() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = workspace(tmp.path());
    write(&tmp.path().join(".git/HEAD"), &format!("{SHA_A}\n"));
    write(
        &manifest.join(".cargo_vcs_info.json"),
        &format!(
            "{{\n  \"git\": {{\n    \"sha1\": \"{SHA_B}\"\n  }},\n  \
             \"path_in_vcs\": \"crates/holdfast-core\"\n}}"
        ),
    );
    let d = derive(&manifest, None);
    assert_eq!(
        d.id,
        short(SHA_B),
        "the package's own record, not the checkout"
    );
    assert!(d.watch.is_empty(), "{:?}", d.watch);

    write(
        &manifest.join(".cargo_vcs_info.json"),
        "{\"path_in_vcs\": \"\"}",
    );
    let d = derive(&manifest, None);
    assert_eq!(d.id, "unknown");
    assert!(d.watch.is_empty(), "{:?}", d.watch);
}

/// **The wrong-sha-with-confidence case.** A vendored or registry copy of
/// this crate sits below somebody else's repository — `cargo vendor` puts it
/// exactly two levels under the consuming project's `.git` — and that
/// repository's commit says nothing about this build. The control is the
/// same repository in this workspace's own layout, so the rows above it are
/// not passing because the fixture's `.git` is unreadable.
#[test]
fn a_copy_that_is_not_this_workspace_never_borrows_a_containing_repositorys_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let outer = tmp.path();
    write(&outer.join(".git/HEAD"), &format!("{SHA_A}\n"));
    for copy in [
        outer.join("vendor").join("holdfast-core"),
        outer
            .join("index.crates.io-1949cf8c6b5b557f")
            .join("holdfast-core-0.0.8"),
    ] {
        fs::create_dir_all(&copy).unwrap();
        let d = derive(&copy, None);
        assert_eq!(d.id, "unknown", "{} borrowed {SHA_A}", copy.display());
        assert!(d.watch.is_empty(), "{:?}", d.watch);
    }
    assert_eq!(derive(&workspace(outer), None).id, short(SHA_A));
}

/// No `.git` at all — a tarball, or a copy with it stripped: `unknown`,
/// nothing watched, and no failure, because a build that stopped over its
/// own label would be the wrong trade.
#[test]
fn no_git_is_unknown_and_watches_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let d = derive(&workspace(tmp.path()), None);
    assert_eq!(d.id, "unknown");
    assert!(d.watch.is_empty(), "{:?}", d.watch);
    assert!(d.warnings.is_empty(), "{:?}", d.warnings);
}

/// **A linked worktree** — the layout this repository's own lanes build in.
/// `.git` is a file naming `<main>/.git/worktrees/<name>`, which holds the
/// worktree's own `HEAD` and a `commondir` pointing back at the refs every
/// worktree shares; the pointer may be absolute or relative to the file.
#[test]
fn a_linked_worktree_reads_its_own_head_and_the_shared_refs() {
    let tmp = tempfile::tempdir().unwrap();
    let main_git = tmp.path().join("main").join(".git");
    write(&main_git.join("HEAD"), "ref: refs/heads/main\n");
    write(&main_git.join("refs/heads/main"), &format!("{SHA_A}\n"));
    write(&main_git.join("refs/heads/lane"), &format!("{SHA_B}\n"));
    let wt_gitdir = main_git.join("worktrees").join("lane");
    write(&wt_gitdir.join("HEAD"), "ref: refs/heads/lane\n");
    write(&wt_gitdir.join("commondir"), "../..\n");

    for (label, pointer) in [
        ("absolute", wt_gitdir.display().to_string()),
        ("relative", "../main/.git/worktrees/lane".to_string()),
    ] {
        let root = tmp.path().join(format!("wt-{label}"));
        let manifest = workspace(&root);
        write(&root.join(".git"), &format!("gitdir: {pointer}\n"));

        let d = derive(&manifest, None);
        assert_eq!(
            d.id,
            short(SHA_B),
            "{label}: the worktree's branch, not main's"
        );
        assert_all_exist(&d.watch);
        let watched: Vec<PathBuf> = d.watch.iter().map(|p| p.canonicalize().unwrap()).collect();
        for want in [wt_gitdir.join("HEAD"), main_git.join("refs/heads/lane")] {
            assert!(
                watched.contains(&want.canonicalize().unwrap()),
                "{label}: {} is not watched: {:?}",
                want.display(),
                d.watch
            );
        }
    }
}

/// A detached `HEAD` is the commit itself, and `HEAD` is what changes.
#[test]
fn a_detached_head_is_the_commit_itself() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = workspace(tmp.path());
    let head = tmp.path().join(".git/HEAD");
    write(&head, &format!("{SHA_B}\n"));
    let d = derive(&manifest, None);
    assert_eq!(d.id, short(SHA_B));
    assert!(d.watch.contains(&head), "{:?}", d.watch);
}
