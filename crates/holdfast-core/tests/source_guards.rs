//! The guards that are lints rather than code, asserted as facts about
//! the source tree.
//!
//! A lint is only a guard over the code it is *scoped* to, and that
//! scope is invisible to every other test in this workspace: it is one
//! inner attribute in one file, and moving it, or writing `#[allow]`
//! beside a new call site, turns the guarantee off with nothing going
//! red. Re-review finding I-2 is what that costs — `clippy::print_stderr`
//! was denied across `daemon/` while `diag.rs` told the reader it made a
//! re-introduced `eprintln!` "a build failure, not a review finding", and
//! `mcp/mod.rs` — which the daemon calls to build its own server — wrote
//! a bare `eprintln!` into `daemon.log` for a whole milestone, one
//! directory outside the scope.
//!
//! This file is a test rather than a `clippy.toml` because the question
//! is not "does clippy complain" — it does — but "does the denial still
//! cover the modules that can reach a redacted boundary". That is a
//! property of the tree, so it is asserted against the tree.
//!
//! It lives in `tests/` and not next to [`holdfast_core::diag`] on purpose:
//! a scanner that looks for print macros in `src/` cannot spell the
//! macros it looks for if it lives in `src/` itself, and a scanner that
//! has to exclude its own file is a scanner with a hole in it.

use std::path::{Path, PathBuf};

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

/// Whether this line *calls* a print macro, as opposed to naming one.
///
/// Comment lines are the whole reason this is a function: `diag.rs`
/// discusses `eprintln!` five times in its module docs, and a scanner
/// that flagged those would be turned off within a day.
fn calls_a_print_macro(line: &str) -> bool {
    let code = line.trim_start();
    if code.starts_with("//") {
        return false;
    }
    // Written as the two shorter spellings deliberately: `eprintln!`
    // ends with `println!` and `eprint!` ends with `print!`, so these
    // two needles cover all four macros and cannot drift apart from the
    // list they stand for.
    code.contains("print!") || code.contains("println!")
}

/// The denial's scope, and the exemptions that would silently shrink it.
///
/// `holdfast-core` is scanned and `holdfast` is not: the binary crate's denial
/// is in `main.rs`, which *is* its crate root, so its scope is complete
/// by construction. This crate's was not, and a library has no single
/// entry point a reader can check at a glance.
#[test]
fn no_module_in_this_crate_can_print_around_the_redactor() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = rust_files(&src);

    // Reachability first. A walk that silently visited nothing — a typo
    // in the path, a `read_dir` that stopped at the top level — would
    // satisfy every assertion below by finding no offences, which is the
    // shape of guard this file exists because of.
    assert!(
        files.len() >= 10,
        "the walk found only {} files under {}",
        files.len(),
        src.display()
    );
    let named = |rel: &str| {
        let want = src.join(rel);
        assert!(
            files.contains(&want),
            "{} was not visited, so the walk does not reach the modules it must",
            want.display()
        );
    };
    // One at the top level, one a directory down, one two down: a walk
    // that only descends once is red here and nowhere else.
    named("lib.rs");
    named("mcp/mod.rs");
    named("daemon/server.rs");

    // And the detector itself, or a `calls_a_print_macro` that answered
    // `false` to everything would report a clean tree forever.
    assert!(
        calls_a_print_macro("        eprintln!(\"holdfast: {why}\");"),
        "the detector does not recognise the exact line this finding was about"
    );
    assert!(
        calls_a_print_macro("    println!(\"x\");"),
        "the stdout half of the denial is not detected"
    );
    assert!(
        !calls_a_print_macro("//!   only sanctioned way; a bare eprintln! is a build failure"),
        "the detector flags prose about the macros, which is how a scanner gets deleted"
    );

    let mut offences = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read a source file");
        for (n, line) in text.lines().enumerate() {
            if calls_a_print_macro(line) {
                offences.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
            // An `#[allow]` beside a call site is the other way to leave
            // the denial in place and still print: the lint stays green,
            // the boundary leaks, and a reader who greps for the deny
            // finds it exactly where it always was.
            if line.contains("allow(clippy::print_") || line.contains("expect(clippy::print_") {
                offences.push(format!(
                    "{}:{}: the denial is exempted here: {}",
                    file.display(),
                    n + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        offences.is_empty(),
        "every diagnostic in this crate goes through `holdfast_core::diag!`, which redacts; \
         the daemon's stderr is `daemon.log` (§9.2, a redacted boundary) and under \
         `holdfast mcp` its stdout is the JSON-RPC wire:\n{}",
        offences.join("\n")
    );

    // The denial itself, at the crate root — the scope, not the rule.
    // Re-scoping it to a subtree is what happened last time, and it is
    // invisible to the scan above until someone then adds a call site.
    let lib = std::fs::read_to_string(src.join("lib.rs")).expect("read lib.rs");
    assert!(
        lib.contains("#![deny(clippy::print_stderr, clippy::print_stdout)]"),
        "the crate-root denial is gone or reworded; if it moved to a subtree, this crate \
         is back to the scope that produced I-2"
    );
}

/// §9.6: a submitted secret is *"zeroed immediately after write"*, and
/// the destructor is what guarantees it.
///
/// **Here rather than in a `#[test]` beside the type, because from inside
/// the program there is no vantage point.** The obvious unit test — drop
/// the value, then read the buffer back through a raw pointer — reads
/// freed memory, and the allocator has already written its own freelist
/// bookkeeping there: measured, `hunter2` came back as
/// `[34, 249, 249, 179, 76, 101, 0]`, neither the secret nor zeros. That
/// test would have gone red or green depending on the allocator, which
/// is worse than no test. What *is* checkable is that `SecretBytes` has a
/// `Drop` and that the `Drop` runs the zeroing; the zeroing itself is
/// asserted deterministically by `attach::secret`'s own unit tests.
#[test]
fn secret_bytes_still_zeroes_itself_in_drop() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let text =
        std::fs::read_to_string(src.join("attach/secret.rs")).expect("read attach/secret.rs");

    let (_, after_impl) = text
        .split_once("impl Drop for SecretBytes {")
        .expect("SecretBytes has no Drop impl at all — §9.6's zeroing is gone");
    let body = after_impl
        .split_once("\n}")
        .expect("the Drop impl does not close")
        .0;
    assert!(
        body.contains("zeroize()"),
        "SecretBytes::drop no longer zeroes; §9.6 requires the value gone the \
         instant the write is done, and nothing else in this tree does it:\n{body}"
    );

    // The other half: a `Serialize` on the type would put the value on a
    // wire. The guard for that is a compile error (`E0119` against the
    // blanket impl in `secret_is_not_serializable`), so all this has to
    // check is that the guard is still there to fire — an implementer who
    // deleted the module to "fix a confusing error" removes the only
    // thing standing between REQ-SEC-004 and a derive.
    assert!(
        text.contains("impl<T: ?Sized + serde::Serialize> NotSerialize for T {}"),
        "the conflicting-impl guard on SecretBytes is gone; a #[derive(Serialize)] \
         would now compile, and §9.2 requires the value to be *absent* from every \
         surface rather than redacted on it — there is no downstream redactor to \
         catch it"
    );
    // **Code lines only.** The doc comment above that impl quotes the
    // unbounded form verbatim, to explain why it is wrong — and a scanner
    // that flagged the explanation would be deleted within a day, which
    // is the same lesson `calls_a_print_macro` above is written around.
    let unbounded = text
        .lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with("//"))
        .any(|l| l.contains("impl<T: ?Sized> NotSerialize for T {}"));
    assert!(
        !unbounded,
        "the guard lost its `+ serde::Serialize` bound, which makes it fire on every \
         build whether or not anything derives Serialize — a crate that does not \
         compile, not a guard"
    );
}
