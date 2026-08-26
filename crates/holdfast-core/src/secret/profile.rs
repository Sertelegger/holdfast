//! §9.6's operator-declared session profiles (GH #46): **the operator
//! writes the command line, the agent fills named slots in it.**
//!
//! ## Why this is a different problem from a regex over a command line
//!
//! Through 0.0.7 the agent authored the whole command line and a load-time
//! check tried to decide whether that string was one the operator meant.
//! That is a classification problem over adversary-authored input, and
//! **four guard shapes failed at it** — anchoring (bypassed at the other
//! end); a ~180-line syntactic scanner (20 accepted spellings); a 9-probe
//! behavioural corpus (the whole insertion class missed, so `^ssh.*prod-01$`
//! loaded and admitted GH #45's own reproduction line); and a 51-probe
//! corpus (46 bypasses, and **the cheapest dodge fell from six characters
//! to one**, `[^ ]*`, because a larger probe set shares more structure and
//! a negated class excludes shared structure in a single stroke). Widening
//! the corpus made the dodge *cheaper*, which is the measurement that ended
//! the argument.
//!
//! Profiles invert the direction, and the asymmetry — not the effort — is
//! what makes them different:
//!
//! * **A slot is bounded.** One value, matched **whole**, with no "rest of
//!   the line" left over to append to.
//! * **Arguments come from the template.** The agent cannot *add* one; it
//!   can only fill ones the operator declared.
//! * **Therefore a badly-written slot pattern is bounded damage.**
//!   `host = ".*"` lets the agent choose a hostname. It still cannot add a
//!   flag. One sloppy `match_command` gave it unlimited extra arguments.
//!
//! That last bullet is the whole argument, and it is why the next person to
//! touch this must not reintroduce a regex over the command line "for
//! convenience": the two are not the same kind of knob, and the difference
//! is structural rather than a matter of how carefully each is written.
//! `a_slot_pattern_that_admits_anything_still_cannot_add_an_argument`
//! drives it.
//!
//! ## The structural guarantee, stated where it lives
//!
//! **Substitution happens within one argv element.** [`SessionProfile::args`]
//! is a `Vec<String>`, [`render`] pushes exactly one output element per
//! template element, and a value containing spaces, quotes, `;`, `&&` or a
//! leading `-` therefore stays inside the element it was substituted into.
//! There is no join, no split and no shell, so a value **cannot become a
//! second argument**. That is a property of how the argv is built rather
//! than a check that could be bypassed —
//! `a_var_value_carrying_shell_metacharacters_stays_one_argv_element` is
//! the row, and it asserts the resulting argv length is exactly what the
//! template declared.
//!
//! ## The operator writes the **process**, not only the command line
//!
//! The first cut of this module applied the inversion to exactly one of
//! the two things `start_session` takes from the agent, and GH #55 drove
//! the other one twice:
//!
//! 1. `env: {PATH: …}` on a profile-started session. The operator's
//!    literal `program` — `ssh` — resolved to the agent's binary. The
//!    credential came back out of `read_output` in cleartext, with
//!    `redactions: {}`.
//! 2. `env: {LD_PRELOAD: …}` with `program` an **absolute path**, which is
//!    the obvious fix for the first. The operator's binary, the operator's
//!    argv, and the credential captured anyway.
//!
//! **`require_confirm` is not a mitigation for either.** The human was
//! shown `command_line: "ssh prod-01"` — the legitimate line, because it
//! *is* the legitimate line. The redirection lives in the environment,
//! which `BindingApprovalRequired` does not carry.
//!
//! **The class is the whole environment, not a list of dangerous names.**
//! An allowlist or a blocklist of variables is the wrong shape here for
//! exactly the reason the `match_command` scanner was: it enumerates the
//! ways an adversary can influence a process, and there is no complete
//! list. So `env` and `cwd` are **mutually exclusive with `profile`**,
//! precisely as `command` already is, and a profile declares its own —
//! operator-written and literal, because a slot there is the `program`
//! hole again ([`ProfileFault::NotALiteral`]).
//!
//! `mcp::tools`' `Launch` is where that becomes structural rather than
//! remembered: it carries the command, the argv, the environment and the
//! working directory, and `start_session` reads nothing else. An edit that
//! reached back for `args.env` on the profile arm is a compile error, not
//! a review catch — which is the argument that type's own doc already
//! made for the command line, applied to the second thing the agent
//! supplies.
//!
//! ## What this does not do, stated plainly
//!
//! **A session started with `command`/`args` can never receive a keychain
//! credential.** That is the safety property. It is also a real capability
//! loss and should be read as both: an agent can only run credentialed
//! sessions the operator anticipated, and an operator who forgets a profile
//! finds out when a legitimate workflow stops resolving.
//!
//! **The credential's *effect* is still not protected, only its bytes.** An
//! agent that reaches a profile-started session still obtains an
//! interactive shell on the target once injection succeeds. Profiles stop
//! it choosing *which* credential and redirecting the *bytes*; they do not,
//! and must not claim to, stop it using a session it was legitimately
//! given.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::SessionProfile;

use super::binding::whole_line;

/// One piece of a template argument: text the operator wrote, or a slot
/// the agent fills.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Literal(String),
    Slot(String),
}

/// A template argument that is not a template.
///
/// Refused at load, so the operator learns it at startup rather than at
/// 3am; refused again at [`render`], because a `SecurityConfig` built in
/// Rust never went through the loader and the two must agree about what a
/// slot is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateFault(String);

impl std::fmt::Display for TemplateFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// **The one parser**, shared by [`validate`] and [`render`].
///
/// GH #50's lesson generalised: when a validator and a matcher each
/// interpret the operator's text with their own code, the two can disagree
/// about what the operator wrote — and the daemon then starts with a rule
/// that means something other than what was checked. One function makes
/// disagreement impossible by construction rather than by both sides
/// remembering the same grammar.
///
/// The grammar is small on purpose:
///
/// * `{name}` is a slot. `name` is one or more of `[A-Za-z0-9_]`.
/// * `{{` and `}}` are literal `{` and `}`, on `format!`'s convention, so
///   a template can carry an argument that genuinely contains a brace
///   (`curl -d '{"a":1}'` is not a hypothetical). Without an escape an
///   operator with such an argument would have no spelling at all.
/// * **Every other brace is a fault.** Not "ignored" — a `{` that opens
///   nothing is a typo in a slot name, and silently treating it as a
///   literal is how an operator ends up with a template whose slot never
///   gets filled and whose value goes nowhere.
fn pieces(arg: &str) -> Result<Vec<Piece>, TemplateFault> {
    let mut out: Vec<Piece> = Vec::new();
    let mut literal = String::new();
    let mut rest = arg.char_indices().peekable();
    while let Some((i, c)) = rest.next() {
        match c {
            '{' if rest.peek().map(|(_, c)| *c) == Some('{') => {
                rest.next();
                literal.push('{');
            }
            '}' if rest.peek().map(|(_, c)| *c) == Some('}') => {
                rest.next();
                literal.push('}');
            }
            '{' => {
                let mut name = String::new();
                let mut closed = false;
                for (_, c) in rest.by_ref() {
                    if c == '}' {
                        closed = true;
                        break;
                    }
                    if !c.is_ascii_alphanumeric() && c != '_' {
                        return Err(TemplateFault(format!(
                            "has a `{{` at byte {i} whose slot name contains {c:?}; a slot \
                             is `{{name}}` with name made of letters, digits and `_`, and \
                             a literal brace is written `{{{{`"
                        )));
                    }
                    name.push(c);
                }
                if !closed {
                    return Err(TemplateFault(format!(
                        "has a `{{` at byte {i} that is never closed; a slot is `{{name}}`, \
                         and a literal brace is written `{{{{`"
                    )));
                }
                if name.is_empty() {
                    return Err(TemplateFault(format!(
                        "has an empty slot `{{}}` at byte {i}; a slot is `{{name}}`"
                    )));
                }
                if !literal.is_empty() {
                    out.push(Piece::Literal(std::mem::take(&mut literal)));
                }
                out.push(Piece::Slot(name));
            }
            '}' => {
                return Err(TemplateFault(format!(
                    "has a `}}` at byte {i} that closes no slot; a literal brace is written \
                     `}}}}`"
                )));
            }
            _ => literal.push(c),
        }
    }
    if !literal.is_empty() {
        out.push(Piece::Literal(literal));
    }
    Ok(out)
}

/// Why a profile does not load.
///
/// Every variant names a **key**, because an operator with six profiles
/// cannot act on a diagnostic that does not say which one is wrong — the
/// rule every other message in `Config::validate` already follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileFault {
    /// Rule 1. **`program`, `env` and `cwd` are literals and admit no
    /// `{…}`.** `site` names which one — `program`, `env.<NAME>`,
    /// `env.<NAME> (key)` or `cwd`.
    ///
    /// **One rule over three sites, because they are one hole.** If the
    /// agent could influence the program it chooses the binary, and every
    /// other rule here is irrelevant: a slot pattern bounds an argument,
    /// and an argument to a program of the agent's choosing bounds
    /// nothing. **The environment chooses the binary just as
    /// effectively**, and that is not an analogy — it was driven twice (GH
    /// #55). `PATH` decides which file a literal `program` of `ssh`
    /// resolves to. `LD_PRELOAD` decides what an *absolute* `program`
    /// executes once it has resolved, which is the obvious fix for the
    /// first and does not work. `cwd` joins them because a `program` may
    /// be relative, and because even an absolute one reads its
    /// configuration relative to where it runs.
    ///
    /// **So the class is the whole environment, not a list of names**, and
    /// there is deliberately no allowlist or blocklist of variables here.
    /// Enumerating the ways an adversary can influence a process is the
    /// shape that failed four times over `match_command`; the module
    /// header is the argument, and this is the same argument one level
    /// out. What replaces it is the same inversion: the operator writes
    /// the environment, and `start_session` refuses an agent-supplied
    /// `env` or `cwd` alongside a `profile` outright.
    ///
    /// Any brace at all is refused, not merely a well-formed slot: a
    /// program named `foo{bar}` is not a real case, and refusing the whole
    /// character is one rule instead of two.
    NotALiteral { site: String },
    /// A template argument whose braces do not spell a slot.
    BadTemplate { arg: usize, fault: TemplateFault },
    /// Rule 2, first direction: a `{name}` in `args` with no `vars` entry.
    /// The slot could never be filled, so the profile could never start.
    UndeclaredSlot { name: String },
    /// Rule 2, second direction: a `vars` entry no slot uses. **An unused
    /// var is a typo**, and the operator should learn it at startup rather
    /// than discover at 3am that the pattern they thought was guarding a
    /// hostname guards nothing.
    UnusedVar { name: String },
    /// Rule 3: the pattern does not compile **wrapped exactly as [`render`]
    /// wraps it**. Compiling the bare source here and the wrapped form
    /// there is GH #50 — two compiles that can disagree about whether the
    /// operator wrote a regex at all.
    BadPattern { name: String, error: String },
}

impl std::fmt::Display for ProfileFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotALiteral { site } => write!(
                f,
                ".{site} must be a literal and carries no `{{…}}`: a slot in `program`, in \
                 `env` or in `cwd` would let the agent choose which binary actually runs, \
                 which is the one choice no argument pattern can bound"
            ),
            Self::BadTemplate { arg, fault } => {
                write!(f, ".args[{arg}] {fault}")
            }
            Self::UndeclaredSlot { name } => write!(
                f,
                ".args uses the slot `{{{name}}}`, which has no entry under \
                 `vars`; every slot needs a pattern, or nothing bounds what fills it"
            ),
            Self::UnusedVar { name } => write!(
                f,
                ".vars declares `{name}`, which no slot in `args` uses. An unused var is a \
                 typo, and a pattern nothing consults is a guard nobody has"
            ),
            Self::BadPattern { name, error } => {
                write!(f, ".vars.{name} is not a valid regex: {error}")
            }
        }
    }
}

/// Why an agent's `vars` do not fill this profile.
///
/// **No variant carries the offending *value***, and that is §9.2's habit
/// rather than tidiness: a var value may be a hostname the operator
/// considers sensitive, and every diagnostic in this subsystem names the
/// field rather than the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarFault {
    /// A `vars` key with no matching slot. Refused rather than ignored: an
    /// agent that believes it supplied a value and did not is an agent
    /// acting on a session that is not the one it asked for.
    Unknown { name: String },
    /// A slot with no value.
    Missing { name: String },
    /// The value does not match the operator's pattern, **whole**.
    Rejected { name: String },
    /// The template or one of its patterns is not one [`validate`] would
    /// have accepted. Unreachable for a config that came through the
    /// loader; reachable for a `SecurityConfig` built in Rust, which is
    /// what this crate's own tests do. It **refuses** — the alternative,
    /// substituting anyway, would run a program on a template nobody
    /// checked.
    Unloadable { detail: String },
}

impl std::fmt::Display for VarFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown { name } => {
                write!(f, "`vars.{name}` names no slot in this profile's `args`")
            }
            Self::Missing { name } => write!(f, "`vars.{name}` is required by this profile"),
            // The **var**, never the value.
            Self::Rejected { name } => write!(
                f,
                "`vars.{name}` does not match the pattern this profile declares for it"
            ),
            Self::Unloadable { detail } => write!(f, "this profile does not load: {detail}"),
        }
    }
}

/// Rule 1 at one site: the operator wrote this, and it is a literal.
fn literal(site: &str, text: &str) -> Result<(), ProfileFault> {
    if text.contains('{') || text.contains('}') {
        return Err(ProfileFault::NotALiteral {
            site: site.to_string(),
        });
    }
    Ok(())
}

/// Every rule under §9.6's profile block, checked at load.
///
/// The name and its uniqueness are checked by the caller, which is the one
/// place that can see the other profiles.
pub fn validate(profile: &SessionProfile) -> Result<(), ProfileFault> {
    // Rule 1, and it is first because nothing below matters if it fails.
    //
    // **Three sites, one rule** (GH #55). `program` was the whole of it
    // until an agent-supplied `env` was driven past a profile twice — a
    // `PATH` that repointed a literal `ssh`, and an `LD_PRELOAD` that
    // captured the credential from an *absolute* `program` running the
    // operator's own argv. `cwd` is here for the same reason and not by
    // symmetry: a `program` may be relative.
    literal("program", &profile.program)?;
    if let Some(cwd) = &profile.cwd {
        literal("cwd", cwd)?;
    }
    for (name, value) in &profile.env {
        // The key as well as the value: `{k}` as a variable *name* chooses
        // which variable the agent sets, which is the same hole reached
        // from the other side.
        literal(&format!("env.{name} (key)"), name)?;
        literal(&format!("env.{name}"), value)?;
    }
    let mut used: BTreeSet<String> = BTreeSet::new();
    for (i, arg) in profile.args.iter().enumerate() {
        let parsed = pieces(arg).map_err(|fault| ProfileFault::BadTemplate { arg: i, fault })?;
        for piece in parsed {
            if let Piece::Slot(name) = piece {
                if !profile.vars.contains_key(&name) {
                    return Err(ProfileFault::UndeclaredSlot { name });
                }
                used.insert(name);
            }
        }
    }
    // Rule 2's second direction. Both directions are refused because each
    // one catches a different typo: a misspelt slot has no pattern, and a
    // misspelt `vars` key leaves the slot it meant to guard unguarded.
    for name in profile.vars.keys() {
        if !used.contains(name) {
            return Err(ProfileFault::UnusedVar { name: name.clone() });
        }
    }
    // Rule 3, compiled **through `whole_line`** — the same wrap `render`
    // applies, so this is the regex that will actually run.
    for (name, pattern) in &profile.vars {
        if let Err(e) = regex::Regex::new(&whole_line(pattern)) {
            return Err(ProfileFault::BadPattern {
                name: name.clone(),
                error: e.to_string(),
            });
        }
    }
    Ok(())
}

/// **The argv, built from the operator's template and the agent's values.**
///
/// The returned `Vec` has **exactly `profile.args.len()` elements**. That
/// is the guarantee the whole feature rests on and it is a property of the
/// loop below — one push per template element — rather than a check
/// something could route around. A value containing a space, a quote, a
/// `;`, an `&&` or a leading `-` stays inside the element it was
/// substituted into, because nothing here joins or splits.
///
/// The program is **not** rendered: [`validate`] refuses a `{` in it, and
/// this function never looks at it. An agent cannot choose the binary
/// because there is no code path that would let it.
///
/// Each value is matched **whole**, through
/// [`crate::secret::binding::whole_line`] — the same anchoring GH #45
/// arrived at for command lines, which was the correct half of that fix
/// and is now well tested. It is reused rather than reinvented.
pub fn render(
    profile: &SessionProfile,
    supplied: &BTreeMap<String, String>,
) -> Result<Vec<String>, VarFault> {
    // Unknown keys first. An agent that misspelt a var would otherwise get
    // `Missing` for the slot it meant, which names the wrong key.
    for name in supplied.keys() {
        if !profile.vars.contains_key(name) {
            return Err(VarFault::Unknown { name: name.clone() });
        }
    }
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    for (name, pattern) in &profile.vars {
        let Some(value) = supplied.get(name) else {
            return Err(VarFault::Missing { name: name.clone() });
        };
        let re = regex::Regex::new(&whole_line(pattern)).map_err(|e| VarFault::Unloadable {
            detail: format!("`vars.{name}` is not a valid regex: {e}"),
        })?;
        if !re.is_match(value) {
            return Err(VarFault::Rejected { name: name.clone() });
        }
        values.insert(name.as_str(), value.as_str());
    }

    let mut argv = Vec::with_capacity(profile.args.len());
    for arg in &profile.args {
        let parsed = pieces(arg).map_err(|fault| VarFault::Unloadable {
            detail: fault.to_string(),
        })?;
        let mut element = String::new();
        for piece in parsed {
            match piece {
                Piece::Literal(text) => element.push_str(&text),
                Piece::Slot(name) => {
                    let Some(value) = values.get(name.as_str()) else {
                        // `validate` refuses a slot with no `vars` entry, so
                        // this is the Rust-built-config path again.
                        return Err(VarFault::Unloadable {
                            detail: format!(
                                "`args` uses the slot `{{{name}}}`, which `vars` \
                                             does not declare"
                            ),
                        });
                    };
                    element.push_str(value);
                }
            }
        }
        argv.push(element);
    }
    debug_assert_eq!(
        argv.len(),
        profile.args.len(),
        "substitution changed the argument count, which is the one thing it may never do"
    );
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(args: &[&str], vars: &[(&str, &str)]) -> SessionProfile {
        SessionProfile {
            name: "prod-ssh".to_string(),
            program: "ssh".to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            env: BTreeMap::new(),
            cwd: None,
        }
    }

    fn supplied(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// **The structural guarantee, driven.**
    ///
    /// Every value here is something that *would* become a second argument
    /// if the argv were built by joining and re-splitting — spaces, both
    /// kinds of quote, `;`, `&&`, a leading `-`, a tab, and a `\r` that
    /// would rewrite the line a human is shown. The assertion is the argv's
    /// **length**: exactly what the template declared, for every one.
    ///
    /// The pattern is `(?s).*` deliberately. This row is not about a
    /// pattern refusing a hostile value — that is a different row — it is
    /// about the value being unable to add an argument **even when the
    /// operator's pattern admits it**, which is the asymmetry the module
    /// header argues.
    #[test]
    fn a_var_value_carrying_shell_metacharacters_stays_one_argv_element() {
        let p = profile(&["{host}", "-p", "22"], &[("host", "(?s).*")]);
        let hostile = [
            "prod-01 -o ProxyCommand=nc 127.0.0.1 2222",
            "prod-01; evil",
            "prod-01 && evil",
            "prod-01 | evil",
            "-oProxyCommand=/tmp/x",
            "--config=/dev/shm/evil",
            "'prod-01' \"prod-02\"",
            "prod-01\ttab",
            "prod-01\revil",
            "prod-01\nevil",
            "$(evil)",
            "`evil`",
            "",
        ];
        for value in hostile {
            let argv = render(&p, &supplied(&[("host", value)]))
                .unwrap_or_else(|e| panic!("{value:?} should render: {e}"));
            assert_eq!(
                argv.len(),
                p.args.len(),
                "{value:?} changed the argument count from {} to {}; substitution happens \
                 inside one argv element and may never add one",
                p.args.len(),
                argv.len()
            );
            assert_eq!(
                argv[0], value,
                "the value did not land whole in the element it was substituted into"
            );
            // The positive control: the operator's own arguments are still
            // there and still separate, so a `render` that returned one
            // element per *word* would not pass the length check by having
            // thrown the template away.
            assert_eq!(&argv[1..], &["-p".to_string(), "22".to_string()]);
        }
    }

    /// The negative that separates the row above from the degenerate case:
    /// two template elements are two argv elements, so the length check is
    /// counting something.
    #[test]
    fn the_argv_is_the_templates_own_shape() {
        let p = profile(
            &["-l", "{user}", "{host}"],
            &[("user", "[a-z]+"), ("host", "prod-0[12]")],
        );
        let argv = render(&p, &supplied(&[("user", "ada"), ("host", "prod-01")])).expect("renders");
        assert_eq!(argv, vec!["-l", "ada", "prod-01"]);
    }

    /// Two slots in one element is one element, which is §9.6's own
    /// published `{user}@{host}`.
    #[test]
    fn two_slots_in_one_element_stay_one_element() {
        let p = profile(
            &["{user}@{host}"],
            &[("user", "[a-z]+"), ("host", "prod-0[12]")],
        );
        let argv = render(&p, &supplied(&[("user", "ada"), ("host", "prod-02")])).expect("renders");
        assert_eq!(argv, vec!["ada@prod-02"]);
    }

    /// **The value is matched whole**, which is the half of GH #45 that was
    /// right. Reused rather than reinvented: this is
    /// `binding::whole_line`'s wrap, so a pattern that would match a
    /// *prefix* of a hostile value does not select.
    #[test]
    fn a_slot_pattern_matches_the_whole_value_and_not_a_prefix() {
        let p = profile(&["{host}"], &[("host", "prod-0[12]")]);
        assert_eq!(
            render(&p, &supplied(&[("host", "prod-01")])).expect("the exact value renders"),
            vec!["prod-01"]
        );
        assert_eq!(
            render(&p, &supplied(&[("host", "prod-01 -o ProxyCommand=nc 1 2")])),
            Err(VarFault::Rejected {
                name: "host".to_string()
            }),
            "a pattern that matched a prefix would admit everything after it"
        );
        assert_eq!(
            render(&p, &supplied(&[("host", "evil prod-01")])),
            Err(VarFault::Rejected {
                name: "host".to_string()
            })
        );
    }

    /// An operator's top-level alternation keeps its meaning, because
    /// `whole_line` wraps in `(?:…)`. Without the group `a|b` anchors as
    /// *"`a` at the start or `b` at the end"*, and the first branch is a
    /// prefix match again.
    ///
    /// Inherited from `an_alternation_needs_the_group_or_the_prefix_match_comes_back`,
    /// which asserted the same property of a `match_command`. The field is
    /// gone; the property moved here with the anchoring.
    #[test]
    fn an_alternation_in_a_slot_pattern_needs_the_wrappers_group() {
        let p = profile(&["{host}"], &[("host", "prod-01|prod-02")]);
        assert!(render(&p, &supplied(&[("host", "prod-01")])).is_ok());
        assert!(render(&p, &supplied(&[("host", "prod-02")])).is_ok());
        assert_eq!(
            render(&p, &supplied(&[("host", "prod-01 -X")])),
            Err(VarFault::Rejected {
                name: "host".to_string()
            }),
            "without the `(?:…)` the first branch is a prefix match and this admits"
        );
    }

    /// An operator's inline flag cannot reach the wrapper's anchors.
    /// `(?m)` makes `^`/`$` line anchors *inside* the group; `\A`/`\z` are
    /// end-of-text whatever flags are set, so a newline in a value cannot
    /// buy a second line to match on.
    ///
    /// Inherited from
    /// `an_operators_inline_multiline_flag_cannot_reach_the_wrappers_anchors`.
    #[test]
    fn an_inline_multiline_flag_cannot_reach_the_wrappers_anchors() {
        let p = profile(&["{host}"], &[("host", "(?m)^prod-01$")]);
        assert!(render(&p, &supplied(&[("host", "prod-01")])).is_ok());
        assert_eq!(
            render(&p, &supplied(&[("host", "prod-01\nevil")])),
            Err(VarFault::Rejected {
                name: "host".to_string()
            }),
            "`\\A`/`\\z` are end-of-text, so `(?m)` inside the group buys nothing"
        );
    }

    /// **A sloppy slot pattern is bounded damage, and that is the
    /// asymmetry the module header argues.**
    ///
    /// `host = ".*"` is as wide as a pattern gets. The agent still gets
    /// exactly one argument, in exactly the position the operator put it,
    /// and cannot add a flag — where one sloppy `match_command` gave it
    /// unlimited extra arguments.
    #[test]
    fn a_slot_pattern_that_admits_anything_still_cannot_add_an_argument() {
        let p = profile(&["{host}"], &[("host", ".*")]);
        let argv = render(
            &p,
            &supplied(&[("host", "prod-01 -o ProxyCommand=nc 127.0.0.1 2222")]),
        )
        .expect("`.*` admits it — that is the operator's choice to make");
        assert_eq!(argv.len(), 1);
        assert_eq!(argv, vec!["prod-01 -o ProxyCommand=nc 127.0.0.1 2222"]);
        // The comparison that makes the point: the argv `ssh` would need
        // for GH #45 is four elements, and this is two.
        assert_ne!(
            std::iter::once(p.program.clone())
                .chain(argv)
                .collect::<Vec<_>>(),
            vec!["ssh", "prod-01", "-o", "ProxyCommand=nc 127.0.0.1 2222"]
        );
    }

    #[test]
    fn a_vars_key_with_no_slot_is_refused_and_names_the_key() {
        let p = profile(&["{host}"], &[("host", "prod-0[12]")]);
        assert_eq!(
            render(&p, &supplied(&[("host", "prod-01"), ("hsot", "x")])),
            Err(VarFault::Unknown {
                name: "hsot".to_string()
            })
        );
    }

    #[test]
    fn a_slot_with_no_value_is_refused_and_names_the_key() {
        let p = profile(
            &["{user}@{host}"],
            &[("user", "[a-z]+"), ("host", "prod-0[12]")],
        );
        assert_eq!(
            render(&p, &supplied(&[("host", "prod-01")])),
            Err(VarFault::Missing {
                name: "user".to_string()
            })
        );
    }

    /// §9.2's habit: the message names the **field**, never the content. A
    /// var value may be a hostname the operator considers sensitive.
    #[test]
    fn a_rejected_value_is_never_echoed_back() {
        let p = profile(&["{host}"], &[("host", "prod-0[12]")]);
        let secret_ish = "bastion.internal.example.invalid";
        let e = render(&p, &supplied(&[("host", secret_ish)])).expect_err("refused");
        let rendered = e.to_string();
        assert!(rendered.contains("host"), "{rendered}");
        assert!(
            !rendered.contains(secret_ish),
            "the refusal echoed the value back: {rendered}"
        );
    }

    // ------------------------------------------------------ load-time

    fn not_a_literal(site: &str) -> Result<(), ProfileFault> {
        Err(ProfileFault::NotALiteral {
            site: site.to_string(),
        })
    }

    /// **Rule 1 at all three sites the operator writes literally**, and
    /// the three are one rule because they are one hole (GH #55).
    ///
    /// A slot in `program` lets the agent choose the binary. So does a
    /// slot in `env`: `PATH` decides which file a literal `ssh` resolves
    /// to, and `LD_PRELOAD` decides what an absolute `program` executes
    /// once it has — both driven end to end. `cwd` joins them because a
    /// `program` may be relative to it.
    ///
    /// **The accept half is what makes this a rule rather than a ban.**
    /// Each site is asserted to load with a brace-free value, so a
    /// `validate` that refused every profile could not pass.
    #[test]
    fn a_slot_in_program_env_or_cwd_is_refused() {
        let mut p = profile(&["{host}"], &[("host", "prod-0[12]")]);
        p.program = "{prog}".to_string();
        assert_eq!(validate(&p), not_a_literal("program"));
        p.program = "ssh{x}".to_string();
        assert_eq!(validate(&p), not_a_literal("program"));
        p.program = "/usr/bin/ssh".to_string();
        assert_eq!(validate(&p), Ok(()), "a literal program must still load");

        // The environment, by value — GH #55's first probe is a `PATH`
        // the agent chose, and a slot here is that hole with the
        // operator's own hand on it.
        p.env.insert("PATH".to_string(), "{p}".to_string());
        assert_eq!(validate(&p), not_a_literal("env.PATH"));
        p.env.insert("PATH".to_string(), "/usr/bin".to_string());
        assert_eq!(validate(&p), Ok(()), "a literal env value must still load");

        // And by **key**: `{k}` as a variable name chooses which variable
        // the agent sets, which is the same hole from the other side.
        p.env.insert("{k}".to_string(), "x".to_string());
        assert_eq!(validate(&p), not_a_literal("env.{k} (key)"));
        p.env.remove("{k}");
        assert_eq!(validate(&p), Ok(()));

        p.cwd = Some("/srv/{where}".to_string());
        assert_eq!(validate(&p), not_a_literal("cwd"));
        p.cwd = Some("/srv/deploy".to_string());
        assert_eq!(validate(&p), Ok(()), "a literal cwd must still load");
    }

    #[test]
    fn a_slot_with_no_vars_entry_is_refused() {
        let p = profile(&["{host}", "{port}"], &[("host", "prod-0[12]")]);
        assert_eq!(
            validate(&p),
            Err(ProfileFault::UndeclaredSlot {
                name: "port".to_string()
            })
        );
    }

    #[test]
    fn a_vars_entry_no_slot_uses_is_refused() {
        let p = profile(&["{host}"], &[("host", "prod-0[12]"), ("user", "[a-z]+")]);
        assert_eq!(
            validate(&p),
            Err(ProfileFault::UnusedVar {
                name: "user".to_string()
            })
        );
    }

    #[test]
    fn a_slot_pattern_that_does_not_compile_wrapped_is_refused() {
        let p = profile(&["{host}"], &[("host", "prod-0(")]);
        assert!(matches!(
            validate(&p),
            Err(ProfileFault::BadPattern { ref name, .. }) if name == "host"
        ));
    }

    /// The braces an operator can and cannot write, in one row, because
    /// the accept half is what makes the refuse half a rule rather than a
    /// blanket ban.
    #[test]
    fn the_brace_grammar_accepts_an_escape_and_refuses_a_typo() {
        // A literal brace, so a JSON argument has a spelling.
        let json = profile(
            &["-d", "{{\"host\":\"{host}\"}}"],
            &[("host", "prod-0[12]")],
        );
        assert_eq!(validate(&json), Ok(()));
        assert_eq!(
            render(&json, &supplied(&[("host", "prod-01")])).expect("renders"),
            vec!["-d", "{\"host\":\"prod-01\"}"]
        );

        for bad in ["{host", "}host", "{ho st}", "{}"] {
            let p = profile(&[bad], &[("host", "prod-0[12]")]);
            assert!(
                matches!(validate(&p), Err(ProfileFault::BadTemplate { .. })),
                "{bad:?} should not load"
            );
        }
    }

    /// A template with no slots at all is a fixed command line, which is
    /// the safest profile there is and must load.
    #[test]
    fn a_profile_with_no_slots_loads_and_renders_itself() {
        let p = SessionProfile {
            name: "prod-db".to_string(),
            program: "psql".to_string(),
            args: vec!["-h".to_string(), "prod".to_string()],
            vars: BTreeMap::new(),
            env: BTreeMap::new(),
            cwd: None,
        };
        assert_eq!(validate(&p), Ok(()));
        assert_eq!(
            render(&p, &BTreeMap::new()).expect("renders"),
            vec!["-h", "prod"]
        );
    }
}
