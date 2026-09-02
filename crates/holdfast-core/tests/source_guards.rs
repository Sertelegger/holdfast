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

/// §9.5: the value crosses the write channel **as a `SecretBytes`**, not
/// as the bytes inside one.
///
/// **Asserted here because no runtime test can see it.** The mutation is
/// the writer copying the value out (`secret.with_bytes(|b| b.to_vec())`)
/// and writing the copy: the child still receives exactly the right
/// bytes, every absence assertion still holds, and the whole leak-detector
/// layer stays green — measured. What went wrong is invisible from
/// outside: a plain `Vec<u8>` whose `Drop` does not zero now holds the
/// password until the allocator reuses the page. The design's own note
/// says a leak sanctioned by the type's API is worse than one bolted on
/// beside it, and this is the assertion behind that sentence.
#[test]
fn the_write_channel_carries_the_secret_as_itself() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let text = std::fs::read_to_string(src.join("session/mod.rs")).expect("read session/mod.rs");

    assert!(
        text.contains("secret: SecretBytes,"),
        "WriteRequest::Secret no longer owns a SecretBytes; if it carries a Vec, \
         the zeroing Drop no longer owns every copy of the value (§9.6)"
    );

    let (_, arm) = text
        .split_once("WriteRequest::Secret { secret, ack } => {")
        .expect("the writer no longer has a Secret arm at all");
    let body = arm
        .split_once("\n                    }")
        .expect("arm ends")
        .0;
    assert!(
        body.contains("with_bytes"),
        "the writer no longer lends the bytes through the scoped accessor:\n{body}"
    );
    assert!(
        !body.contains("to_vec()") && !body.contains("to_owned()") && !body.contains("clone()"),
        "the writer copies the value out of the SecretBytes before writing it, which \
         puts the password in a buffer whose Drop does not zero:\n{body}"
    );
}

/// REQ-SEC-012's structural half, pinned as a fact about the tree.
///
/// **Here because the guarantee is a *visibility*, and no runtime test
/// can see one.** Task 9's review finding I-2 was that
/// `resolve_with(&dyn SecretProvider, &str, …)` and
/// `ScriptProvider::new(name, path)` were both `pub` and both re-exported
/// from `secret/mod.rs` — together, a published API meaning *"spawn this
/// program with this argument as a secret provider"*, inside the one
/// module whose premise is that no such signature exists. The fix was
/// `pub(crate)` on the first and `#[cfg(test)]` on the second. Nothing
/// fails if someone widens either back: the crate compiles, every test
/// stays green, and the only thing that changes is a word in a
/// declaration. A structural claim enforced solely by review is one
/// revision from being untrue, so it is enforced here instead.
///
/// **Code lines only.** Both files discuss these names at length in prose
/// — `provider.rs`'s doc on `resolve` names `resolve_with` as the
/// in-crate seam, and `mod.rs`'s doc on the re-export list explains why
/// neither name is in it — so a scanner that read comments would match
/// the explanation and fire on a tree that is correct. That is the same
/// lesson `calls_a_print_macro` above is written around.
#[test]
fn the_arbitrary_program_seam_is_still_out_of_the_published_api() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let provider =
        std::fs::read_to_string(src.join("secret/provider.rs")).expect("read secret/provider.rs");
    let module = std::fs::read_to_string(src.join("secret/mod.rs")).expect("read secret/mod.rs");

    // The two files, reduced to the lines that are actually compiled.
    let code = |text: &str| -> Vec<String> {
        text.lines()
            .map(|l| l.trim_start().to_string())
            .filter(|l| !l.starts_with("//"))
            .collect()
    };
    let provider_code = code(&provider);
    let module_code = code(&module);

    // The detector's own control: the filter must keep declarations and
    // drop prose, or every assertion below is satisfied by a stripper
    // that returned nothing at all.
    assert!(
        provider_code
            .iter()
            .any(|l| l.starts_with("pub enum ArgvProvider")),
        "the code-line filter dropped a declaration, so nothing below is being checked"
    );
    assert!(
        !provider_code
            .iter()
            .any(|l| l.starts_with("//") || l.starts_with("///")),
        "the code-line filter kept comment lines, so prose about these names counts as code"
    );

    let has = |lines: &[String], needle: &str| lines.iter().any(|l| l.contains(needle));

    // 1. `resolve_with` is in-crate and stays in-crate.
    assert!(
        has(&provider_code, "pub(crate) fn resolve_with("),
        "`resolve_with` is no longer declared `pub(crate)`; it takes a bare `&str` \
         reference and any `&dyn SecretProvider`, which is the signature REQ-SEC-012 \
         says must not be offered to anyone who is not this crate"
    );
    assert!(
        !has(&provider_code, "pub fn resolve_with("),
        "`resolve_with` is `pub` again — review finding I-2, re-entering"
    );

    // 2. `ScriptProvider` is not merely unreachable in a release build,
    //    it is not *in* one. `#[cfg(test)]` and not `pub(crate)` alone,
    //    because the type can name any program on the filesystem.
    let script = provider_code
        .iter()
        .position(|l| l.starts_with("pub(crate) struct ScriptProvider"))
        .expect(
            "`ScriptProvider` is no longer declared `pub(crate) struct ScriptProvider`; \
             a type that runs an arbitrary named program must not widen",
        );
    assert!(
        !has(&provider_code, "pub struct ScriptProvider"),
        "`ScriptProvider` is `pub` again — review finding I-2, re-entering"
    );
    let gate = provider_code[script.saturating_sub(3)..script]
        .iter()
        .any(|l| l == "#[cfg(test)]");
    assert!(
        gate,
        "`ScriptProvider` is no longer behind `#[cfg(test)]`, so a shipped daemon now \
         contains a type that spawns an arbitrary program as a secret provider:\n{:?}",
        &provider_code[script.saturating_sub(3)..=script]
    );

    // 3. Neither name is re-exported. The list, not the whole file: the
    //    doc comment above it names both deliberately.
    let list = module_code
        .iter()
        .find(|l| l.starts_with("pub use provider::{"))
        .expect("`secret/mod.rs` no longer re-exports from `provider` at all");
    assert!(
        !list.contains("resolve_with"),
        "`resolve_with` is re-exported again: {list}"
    );
    assert!(
        !list.contains("ScriptProvider"),
        "`ScriptProvider` is re-exported again: {list}"
    );
    // The anti-vacuity pairing. Without it this guard passes against a
    // `secret/mod.rs` that exports **nothing** — which is not the module
    // being correct, it is the module being gone.
    assert!(
        list.contains("resolve") && list.contains("ArgvProvider"),
        "the re-export list no longer carries `resolve` and `ArgvProvider`, so the two \
         absences above are not evidence of anything: {list}"
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

    // ------------------------------------------------- the `Clone` half
    //
    // **0.0.7 added the `NotClone` guard and not its pin**, and the
    // omission was found the only way it can be: by deleting both impls
    // and watching `cargo test --workspace` stay green while
    // `#[derive(Clone)] SecretBytes` became legal. `Clone` is the sharper
    // of the two for this milestone — the type gained three producers
    // (provider, binding, autofill), and a second live copy is a second
    // `Drop` with no write to account for it.
    //
    // Two assertions and not one, for the same reason as the pair above.
    // The `const _` pin in `attach/secret.rs` already makes deleting
    // either impl a **compile** error; what a trait bound cannot see is
    // the blanket impl being widened to the unbounded form while the
    // `SecretBytes` impl goes away with it — both bounds still hold and
    // the guard is gone. That is what this half is here for.
    assert!(
        text.contains("impl<T: Clone> NotClone for T {}"),
        "the conflicting-impl guard against `#[derive(Clone)] SecretBytes` is gone; \
         §9.6's one-owner-one-write-one-drop is back to being a comment"
    );
    let unbounded_clone = text
        .lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with("//"))
        .any(|l| l.contains("impl<T> NotClone for T {}"));
    assert!(
        !unbounded_clone,
        "the guard lost its `Clone` bound, which makes it fire on every build whether \
         or not anything derives Clone — a crate that does not compile, not a guard"
    );
}

/// C-1's third consequence: `read_loop`'s `SecretInput` arm zeroes the
/// frame body **before** its first await, so a cancellation cannot skip it.
///
/// **Here because the buffer is a local of a future nothing else can
/// reach.** `body` is the decoded frame, re-created per iteration and
/// dropped with the loop; there is no vantage point on it from an
/// integration target, from another task, or from the type system. Moving
/// `zero_bytes(&mut body)` back past `write_queue().send(write).await` is
/// **workspace-green** — measured — which is what leaves this consequence
/// undriven while the other three have rows.
///
/// What the siting is worth: `read_loop` is the last branch of `run`'s
/// `biased` `select!`, so it is dropped where it stands whenever a
/// shutdown fires or the output forwarder returns. A `zero_bytes` past the
/// await is a `zero_bytes` a cancellation skips, and what it skips is a
/// full cleartext copy of the credential in a `Vec` whose ordinary `Drop`
/// does not zero.
///
/// **Two facts, not one.** That the call is there at all, and that it is
/// *before* the await — the second is the whole finding, and a scan that
/// only looked for the call would pass against the defect.
///
/// **Code lines only**, for the reason the scans above give: the arm's own
/// comment explains the siting in prose and names both the call and the
/// await point, so a scanner that read comments would match the
/// explanation and pass against a tree that had lost the line.
#[test]
fn the_secret_frame_body_is_zeroed_before_the_arm_can_be_cancelled() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let text = std::fs::read_to_string(src.join("attach/conn.rs")).expect("read attach/conn.rs");

    let arm = text
        .split_once("ClientDecode::Frame(ClientFrame::SecretInput { request_id, bytes }) => {")
        .expect("`read_loop` no longer has a SecretInput arm at all")
        .1;
    // **The submitting branch only.** The over-cap branch above it and the
    // superseded branch below it each zero their own body, and neither
    // holds a taken request across an await — so neither is the case this
    // guard is about, and including them would let one of their
    // `zero_bytes` calls stand in for the one that matters.
    let submit = arm
        .split_once("Some(raised) => {")
        .expect("the SecretInput arm no longer has a branch that accepts a submission")
        .1;
    let submit = submit
        .split_once("None => {")
        .expect("the submitting branch no longer ends where the superseded branch begins")
        .0;

    let code: Vec<&str> = submit
        .lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with("//"))
        .collect();

    // The detector's own control, both directions — the filter must keep
    // statements and drop prose, or every assertion below is satisfied by
    // a stripper that returned nothing.
    assert!(
        code.iter()
            .any(|l| l.starts_with("let answer = SecretAnswer::new(")),
        "the code-line filter dropped a statement, so nothing below is being checked"
    );
    assert!(
        !code.iter().any(|l| l.starts_with("//")),
        "the code-line filter kept comment lines, so the prose explaining the siting \
         counts as code"
    );

    let zeroed = code
        .iter()
        .position(|l| l.contains("zero_bytes(&mut body)"))
        .expect(
            "the submitting branch no longer zeroes the frame body at all; the decoded \
             cleartext is left in a buffer the next frame reuses",
        );
    let first_await = code.iter().position(|l| l.contains(".await")).expect(
        "the submitting branch has no await left in it, so there is no cancellation \
         point and this guard is guarding nothing",
    );
    assert!(
        zeroed < first_await,
        "`zero_bytes(&mut body)` is sited past the arm's first await, so a `read_loop` \
         dropped there — a `daemon/stop`, a SIGTERM, a dead client socket — skips it \
         and leaves a full cleartext copy of the credential behind:\n{:?}",
        &code[zeroed.min(first_await)..=zeroed.max(first_await)]
    );

    // And the await it is before is the FIFO `send`. `SecretAnswer::drop`
    // reasons from *"the only await this guard is held across before the
    // hand-off is the FIFO `send`, and a cancelled `send` delivers
    // nothing"* — which is what licenses its "nothing was written"
    // classification. A new await inserted ahead of the send would leave
    // that sentence untrue with nothing going red.
    assert!(
        code[first_await].contains("write_queue().send(write).await"),
        "the arm's first await is no longer the FIFO enqueue, so `SecretAnswer::drop`'s \
         \"nothing was written\" no longer follows from where the cancellation happened: \
         {:?}",
        code[first_await]
    );
}

/// F-2's two sites that no runtime row can reach: the provider's pipe
/// buffers are sized once, and the timeout path zeroes what its readers
/// produced rather than detaching them.
///
/// **Here because the fix wave's own argument for leaving these undriven
/// stops one option short.** Its behavioural half is right — `drop_witness`
/// is thread-local by design so it cannot see a detached joiner's buffer,
/// and a process-wide counter shared across parallel tests is a row that
/// fails under load, which is worse than no row. But the dichotomy it then
/// offers ("a load-sensitive row, or nothing") omits this file, the tree's
/// own idiom for a guarantee that is invisible from inside the program —
/// and the same wave reached for it one commit later, to pin the
/// `NotClone` impls. A source scan is load-insensitive.
///
/// What the two sites are worth. `read_to_end` on an empty `Vec` grows by
/// doubling, and every doubling copies the credential read so far into a
/// new block and frees the old one **without zeroing it**: one un-zeroed
/// copy per reallocation, in memory nothing in this process can reach
/// again. And on the timeout path `drop(out_reader); drop(err_reader);`
/// detaches two threads that may be holding a *complete* credential — a
/// provider that answered a millisecond after the deadline — and leaves it
/// to an ordinary `Vec::drop`, which does not zero.
///
/// **Code lines only, and paired with what must be present**, for the
/// reason the scans above give: this module discusses `Vec::new` and the
/// `drop` it replaced in its own prose, and an absence assertion over a
/// file that lost everything is not evidence of anything.
#[test]
fn the_providers_credential_buffers_are_sized_once_and_zeroed_on_the_timeout_path() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let text =
        std::fs::read_to_string(src.join("secret/provider.rs")).expect("read secret/provider.rs");
    let code: Vec<&str> = text
        .lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with("//"))
        .collect();

    // The detector's own control, both directions.
    assert!(
        code.iter()
            .any(|l| l.starts_with("const PROVIDER_READ_CAPACITY: usize =")),
        "the code-line filter dropped a declaration, so nothing below is being checked"
    );
    assert!(
        !code.iter().any(|l| l.starts_with("//")),
        "the code-line filter kept comment lines, so this module's prose about `Vec::new` \
         and about the `drop` it replaced counts as code"
    );

    // ------------------------------------ 1. both readers size, then fill
    //
    // Asserted as *adjacency* rather than as two counts: a file with one
    // `with_capacity` and two `read_to_end`s satisfies "there are two of
    // each" and still has a doubling reader in it.
    let reads: Vec<usize> = code
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("read_to_end(&mut buf)"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        reads.len(),
        2,
        "the provider no longer has exactly two `read_to_end` pipe readers, so the \
         pairing below is not checking what it was written for: {reads:?}"
    );
    for i in reads {
        assert_eq!(
            code[i - 1],
            "let mut buf = Vec::with_capacity(capacity);",
            "a pipe reader fills a buffer it did not size, so `read_to_end` grows it by \
             doubling and every doubling frees an un-zeroed copy of the credential:\n{:?}",
            &code[i - 1..=i]
        );
    }
    assert!(
        code.iter()
            .any(|l| l.starts_with("let capacity = PROVIDER_READ_CAPACITY;")),
        "the readers' capacity is no longer `PROVIDER_READ_CAPACITY`; the size is the \
         whole of the guarantee, and a smaller one is a doubling reader with extra steps"
    );

    // ------------------- 2. the timeout path zeroes rather than detaches
    let timeout = text
        .split_once("let Some(status) = exited else {")
        .expect("the provider no longer has a timeout branch at all")
        .1;
    let timeout = timeout
        .split_once("return Err(ProviderError::TimedOut {")
        .expect("the timeout branch no longer ends in a `TimedOut` error")
        .0;
    let tcode: Vec<&str> = timeout
        .lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with("//"))
        .collect();

    // The anti-vacuity pairing, and it is what makes the absence below
    // mean something: this really is rule 5's kill-and-reap branch, and it
    // really does still name both readers.
    assert!(
        tcode.iter().any(|l| l.starts_with("kill_group(&child);")),
        "the region scanned is not the timeout branch any more: {tcode:?}"
    );
    assert!(
        tcode
            .iter()
            .any(|l| l.contains("for reader in [out_reader, err_reader]")),
        "the timeout path no longer disposes of both readers by name, so a later edit \
         that dropped one of them would be invisible here: {tcode:?}"
    );
    assert!(
        tcode.iter().any(|l| l.contains("reader.join()"))
            && tcode.iter().any(|l| l.contains("zero_bytes(&mut buf)")),
        "the timeout path no longer waits for its readers and zeroes what they read; a \
         provider that answered a millisecond late leaves a complete credential to an \
         ordinary `Vec::drop`, which does not zero: {tcode:?}"
    );
    assert!(
        !tcode
            .iter()
            .any(|l| l.contains("drop(out_reader)") || l.contains("drop(err_reader)")),
        "the timeout path detaches its readers again — F-2's fourth site, re-entering: \
         {tcode:?}"
    );
}

/// **GH #57: the decoded `SecretInput` submission is owned by the zeroing
/// type for the whole arm, not just on the path that writes it.**
///
/// The defect was two refusals — `too_large` and `unknown_request_id` —
/// dropping a bare `Vec<u8>`, which does not zero. The fix moves the
/// wrap to the decode, so the refusals are correct by construction and a
/// `select!` cancellation between the decode and the write is too.
///
/// **Asserted against the source because the unit tests cannot reach this
/// arm and the integration tests cannot see the difference.** From
/// outside, a refusal that zeroes and a refusal that does not send byte
/// for byte the same `ProtocolError` — measured; the whole attach suite
/// stays green either way. And `attach::secret`'s `drop_witness`, which
/// *can* see it, is `#[cfg(test)]` and therefore invisible from an
/// integration target. What is checkable is the shape that makes the
/// leak impossible: the binding is consumed into `SecretBytes` before the
/// arm branches.
#[test]
fn the_secret_input_arm_owns_its_submission_as_a_secret() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let text = std::fs::read_to_string(src.join("attach/conn.rs")).expect("read attach/conn.rs");

    let arm = text
        .split_once("ClientFrame::SecretInput { request_id, bytes }) => {")
        .expect("the SecretInput arm is gone or its binding was renamed")
        .1;
    let arm = arm
        .split_once("\n            ClientDecode::")
        .map_or(arm, |(b, _)| b);

    // **Comments are not code, and the first draft of this guard did not
    // know that.** The review that produced this version reintroduced GH
    // #57 in full — bare `Vec<u8>`, both refusals leaking — and added one
    // comment line naming `SecretBytes::received(bytes)`. Every suite went
    // green. A scanner that reads prose passes against the tree its own
    // explanation describes, which is the failure mode this file's other
    // four guards already strip for.
    let code: Vec<&str> = arm
        .lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with("//"))
        .collect();

    // The stripper's own control, both directions — it must keep
    // statements and drop prose, or everything below is satisfied by a
    // filter that returned nothing.
    assert!(
        code.iter().any(|l| l.starts_with("match daemon")),
        "the code-line filter dropped a statement, so nothing below is being checked"
    );
    assert!(
        !code.iter().any(|l| l.starts_with("//")),
        "the code-line filter kept comment lines, so the prose explaining the wrap \
         counts as code"
    );

    // The wrap is a statement, and it precedes the branch — so every exit
    // inherits it rather than each one having to remember.
    let wrapped = code
        .iter()
        .position(|l| l.starts_with("let bytes = super::secret::SecretBytes::received(bytes);"))
        .expect(
            "the decoded submission is not taken into SecretBytes as a statement; each \
             exit then has to remember to zero it, which is the shape GH #57 was filed \
             against",
        );
    let branched = code
        .iter()
        .position(|l| l.starts_with("match daemon"))
        .expect("the arm no longer branches");
    assert!(
        wrapped < branched,
        "the submission is wrapped after the arm branches, so the branches taken \
         before it still hold a bare Vec"
    );

    // **Every use of the binding, whitelisted.** The first draft blocked
    // two spellings of a copy — `to_vec()` and `bytes.clone()` — and the
    // review defeated both: `clone` cannot even compile (`SecretBytes` is
    // not `Clone`, pinned by `secret_is_not_clone`), so that half was
    // unreachable, and `with_bytes(|b| b.to_owned())` walked through the
    // other half carrying a real un-zeroed copy of the credential. A
    // blocklist of copy spellings is a list of the ones somebody thought
    // of; `Vec::from(b)`, `b.into()` and `b.iter().copied().collect()` are
    // the ones they did not.
    //
    // So this inverts it. Any *new* way of touching the binding fails
    // until it is named here deliberately.
    const ALLOWED: [&str; 4] = [
        "let bytes = super::secret::SecretBytes::received(bytes);",
        ".is_some_and(|cap| bytes.len() > cap as usize);",
        "drop(bytes);",
        "WriteRequest::secret(bytes.normalised(raised.append_newline));",
    ];
    // `bytes` as an *identifier*, not as a substring. A plain `contains`
    // matches `zero_bytes`, `SecretBytes` and `bytes_written` — the last
    // of which caught this guard out on its first run, which is the
    // cheapest possible demonstration that the boundary check is load
    // bearing rather than pedantry.
    let touches_binding = |l: &str| {
        let b = l.as_bytes();
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        l.match_indices("bytes").any(|(i, _)| {
            let before = i == 0 || !ident(b[i - 1]);
            let after = i + 5 >= b.len() || !ident(b[i + 5]);
            before && after
        })
    };
    for line in code.iter().filter(|l| touches_binding(l)) {
        assert!(
            ALLOWED.iter().any(|a| line.contains(a)),
            "a use of the decoded submission that this guard has not seen before:\n  \
             {line}\nIf it is legitimate, add it to ALLOWED and say why. If it copies \
             the value out of the zeroing type — `to_owned`, `Vec::from`, `into`, \
             `collect`, or a `with_bytes` whose result outlives the closure — the copy's \
             Drop does not zero and it is GH #57 again."
        );
    }
    // The whitelist is only a guard while it still matches something.
    // **Five, not four**: `drop(bytes);` is two of them, one per refusal,
    // and that is the count the fix is about. If a refusal stops
    // disposing of the submission this drops to four and fails here even
    // though every surviving line is still on the list.
    assert_eq!(
        code.iter().filter(|l| touches_binding(l)).count(),
        5,
        "the binding is used a different number of times than this guard enumerates; \
         it is checking a shape the arm no longer has"
    );
    assert_eq!(
        code.iter()
            .filter(|l| l.starts_with("drop(bytes);"))
            .count(),
        2,
        "a refusal path no longer disposes of the submission explicitly (GH #57)"
    );

    // **The superseded branch zeroes the frame body before it parks.**
    // `the_secret_frame_body_is_zeroed_before_the_arm_can_be_cancelled`
    // deliberately scopes itself to the submitting branch, on the grounds
    // that the others do not hold a *taken request* across an await. True
    // — but the property at issue is the cleartext *body*, and this
    // branch does hold that across `tx.send(…).await`. Review moved the
    // `zero_bytes` past that await and every suite stayed green, so this
    // is the assertion that was missing.
    let superseded = code
        .iter()
        .position(|l| l.starts_with("None => {"))
        .expect("the SecretInput arm no longer has a superseded branch");
    let tail = &code[superseded..];
    let zeroed = tail
        .iter()
        .position(|l| l.contains("zero_bytes(&mut body)"))
        .expect("the superseded branch no longer zeroes the cleartext frame body");
    let first_await = tail
        .iter()
        .position(|l| l.contains(".await"))
        .expect("the superseded branch has no await, so this guard is guarding nothing");
    assert!(
        zeroed < first_await,
        "the superseded branch zeroes the frame body only after it has already parked \
         on a send; a shutdown or a dead client socket at that suspension point drops \
         the cleartext body as a plain Vec"
    );
}
