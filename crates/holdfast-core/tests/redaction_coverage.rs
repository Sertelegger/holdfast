//! Credential spellings the shipped rules did not recognise (GH #244).
//!
//! A dogfood pass printed a `.env` and a handful of command lines through
//! a real session and read them back: `postgres://` and `DB_PASSWORD=`
//! were masked, and every row of [`MISSED_BEFORE`] came back raw. Each is
//! a spelling rather than a mechanism — the scheme list had no `rediss`,
//! the user was required, the label list had no `pass` — so each is
//! closed in `data/redaction_default.toml` and pinned here.
//!
//! **Why the assertions here are not vacuous.**
//!
//! * Every row names the exact bytes that must not survive
//!   ([`Row::secret`]), and the arm asserts on those bytes rather than on
//!   "the output changed" — a rule that redacted the label and left the
//!   password would change the output too.
//! * Every row is paired with [`BEFORE_244`], the rules this family was
//!   covered by at `a81b02d`, spelled out rather than derived: each row
//!   must come back *with* its secret under that set, or it proves
//!   nothing about this change.
//! * The false-positive half, [`MUST_STAY_UNTOUCHED`], runs through the
//!   same surfaces and must come back byte-identical, so "redact
//!   everything" does not pass either.
//! * `not_vacuous` floors both tables.

use holdfast_core::output::redact::{find_spans, redact_str};
use holdfast_core::output::rules::RuleSet;
use holdfast_core::output::{OutputProcessor, ProcessedRead, ReadOptions, WindowSnapshot};

/// One spelling, and the bytes of it that are the credential.
struct Row {
    text: &'static str,
    secret: &'static str,
}

/// The rows GH #244 lists, in the issue's order, with a real-shaped
/// password in place of its `<pw>`.
const MISSED_BEFORE: &[Row] = &[
    // TLS Redis, Upstash's spelling.
    Row {
        text: "REDIS_URL=rediss://default:Zq7Pw9xLk2Mv@x.upstash.io:6379",
        secret: "Zq7Pw9xLk2Mv",
    },
    // Redis with `requirepass` and no ACL user: the user is empty.
    Row {
        text: "REDIS_URL=redis://:Zq7Pw9xLk2Mv@cache:6379/0",
        secret: "Zq7Pw9xLk2Mv",
    },
    // SQLAlchemy's `+driver`.
    Row {
        text: "SQLALCHEMY_DATABASE_URI=postgresql+psycopg2://app:Zq7Pw9xLk2Mv@db/app",
        secret: "Zq7Pw9xLk2Mv",
    },
    Row {
        text: "mysql+pymysql://app:Zq7Pw9xLk2Mv@db/app",
        secret: "Zq7Pw9xLk2Mv",
    },
    Row {
        text: "CELERY_BROKER_URL=amqps://app:Zq7Pw9xLk2Mv@mq/vhost",
        secret: "Zq7Pw9xLk2Mv",
    },
    Row {
        text: "mariadb://app:Zq7Pw9xLk2Mv@db/app",
        secret: "Zq7Pw9xLk2Mv",
    },
    Row {
        text: "mssql://sa:Zq7Pw9xLk2Mv@db/app",
        secret: "Zq7Pw9xLk2Mv",
    },
    // A raw `/` in the password, which SQLAlchemy keeps.
    Row {
        text: "postgresql+asyncpg://app:Zq7P/w9xLk2Mv@db/app",
        secret: "Zq7P/w9xLk2Mv",
    },
    // The label spellings.
    Row {
        text: "DB_PASS=Zq7Pw9xLk2Mv",
        secret: "Zq7Pw9xLk2Mv",
    },
    Row {
        text: "SMTP_PASS=Zq7Pw9xLk2Mv",
        secret: "Zq7Pw9xLk2Mv",
    },
    Row {
        text: "export MYSQL_PWD=Zq7Pw9xLk2Mv",
        secret: "Zq7Pw9xLk2Mv",
    },
    Row {
        text: "APP_KEY=base64:Zq7Pw9xLk2MvZq7Pw9xLk2MvZq7Pw9xLk2Mv",
        secret: "Zq7Pw9xLk2MvZq7Pw9xLk2MvZq7Pw9xLk2Mv",
    },
    // Basic auth, as `curl -v` prints it and as a `requests` dict holds it.
    Row {
        text: "> Authorization: Basic YWRtaW46WnE3UHc5eExrMk12",
        secret: "YWRtaW46WnE3UHc5eExrMk12",
    },
    Row {
        text: "{'Authorization': 'Basic YWRtaW46WnE3UHc5eExrMk12'}",
        secret: "YWRtaW46WnE3UHc5eExrMk12",
    },
    // Userinfo in an ordinary URL.
    Row {
        text: "curl https://admin:Zq7Pw9xLk2Mv@internal.example.com/api",
        secret: "Zq7Pw9xLk2Mv",
    },
    Row {
        text: "git clone https://oauth2:Zq7Pw9xLk2Mv@gitlab.example.com/org/repo.git",
        secret: "Zq7Pw9xLk2Mv",
    },
    // Passwords on a command line.
    Row {
        text: "$ mysql -u root -pZq7Pw9xLk2Mv app",
        secret: "Zq7Pw9xLk2Mv",
    },
    Row {
        text: "$ docker login -u ci -p Zq7Pw9xLk2Mv registry.example.com",
        secret: "Zq7Pw9xLk2Mv",
    },
];

/// Ordinary text that sits next to every one of those shapes and must
/// come back byte-identical: URLs with no userinfo, the forms that mean
/// "prompt me", the shell's own `PWD`, English after `Basic`.
const MUST_STAY_UNTOUCHED: &[&str] = &[
    "redis://localhost:6379/0",
    "postgresql://db.internal:5432/app",
    "mongodb+srv://cluster0.example.net/?retryWrites=true&w=majority",
    "https://example.com:8443/path?q=1",
    "  ➜  Local:   http://localhost:5173/@vite/client",
    "git@github.com:Sertelegger/holdfast.git",
    "ssh://git@github.com:22/org/repo.git",
    "https://user@example.com/login",
    "http://[::1]:8080/metrics",
    "$ mysql -u root -p app",
    "$ mysql -h db -P 3306 -u root -p",
    "$ echo $TOKEN | docker login -u ci --password-stdin ghcr.io",
    "$ docker run -p 8080:80 nginx",
    "$ mkdir -pv out && cp -pr a b",
    "OLDPWD=/home/dev/repos/holdfast",
    "PWD=/home/dev/repos/holdfast",
    "bypass=0123456789abcdef",
    "WWW-Authenticate: Basic realm=\"api\"",
    "Authorization: Basic authentication is required for this endpoint",
    "a second pass: reading the file again",
    "first_pass: bool,",
];

/// The rules that covered this family at `a81b02d`, **spelled out** so the
/// control cannot drift with the thing it controls. [`before`] removes the
/// four rules GH #244 *added* from the shipped file and puts these back by
/// name, so the control is the old coverage and not the new set with a
/// few rules rolled back.
const BEFORE_244: &str = r#"
[[rule]]
name = "database-connection-password"
kind = "connection-string"
pattern = '''\b(?:postgres|postgresql|mysql|mongodb\+srv|mongodb|redis|amqp)://[^:@/\s]+:(?P<value>[^@/\s]+)@'''
prefixes = ["postgres://", "postgresql://", "mysql://", "mongodb://", "mongodb+srv://", "redis://", "amqp://"]
positive = ["postgresql://svc:hunter2GOESHERE@db.internal:5432/app"]
negative = ["postgresql://db.internal:5432/app"]

[[rule]]
name = "secret-key-assignment"
kind = "generic"
pattern = '''(?i)\b[a-z0-9_.-]{0,32}(?:secret|private|encryption|signing|master|session)[_-]key\b["'\s]*[:=]\s*["']?(?P<value>[^:\s"';,)][^\s"';,)]{7,})'''
prefixes = ["secret_key", "secret-key", "private_key", "private-key", "encryption_key", "encryption-key", "signing_key", "signing-key", "master_key", "master-key", "session_key", "session-key"]
value_must_not_match = '''[^0-9]*[(<>\[\]{}|\\`][^0-9]*'''
positive = ["CLERK_SECRET_KEY=sk_test_0123456789abcdef01234567"]
negative = ["SECRET_KEY_FILE=/run/secrets/app"]

[[rule]]
name = "generic-secret-assignment"
kind = "generic"
pattern = '''(?i)\b[a-z0-9_.-]{0,32}(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)\b["'\s]*[:=]\s*["']?(?P<value>[^:\s"';,)][^\s"';,)]{7,})'''
prefixes = ["password", "passwd", "secret", "apikey", "api_key", "api-key", "accesstoken", "access_token", "access-token", "authtoken", "auth_token", "auth-token"]
value_must_not_match = '''[^0-9]*[(<>\[\]{}|\\`][^0-9]*'''
positive = ["export DB_PASSWORD=hunter2hunter2"]
negative = ["password: short"]

[[rule]]
name = "bearer-authorization"
kind = "bearer"
pattern = '''(?i)bearer\s+(?P<value>[A-Za-z0-9._~+/-]{20,}=*)'''
positive = ["Authorization: Bearer abcdefghijklmnopqrstuvwxyz"]
negative = ["Bearer short"]
"#;

/// The rules GH #244 added, which [`before`] removes.
const ADDED_BY_244: &[&str] = &[
    "url-userinfo-password",
    "basic-authorization",
    "mysql-cli-password",
    "registry-login-password",
];

fn builtin() -> RuleSet {
    RuleSet::builtin().expect("the vendored rule set must compile")
}

/// `a81b02d`'s coverage of this family — see [`BEFORE_244`]: the shipped
/// file with the rules GH #244 added removed and the four it widened put
/// back as they were.
fn before() -> RuleSet {
    use holdfast_core::output::rules::DEFAULT_RULES_TOML;
    let mut file: toml::Table = DEFAULT_RULES_TOML
        .parse()
        .expect("the vendored file parses");
    let old: toml::Table = BEFORE_244.parse().expect("the control parses");
    let old_rules = old["rule"].as_array().expect("the control has rules");
    let rules = file
        .get_mut("rule")
        .and_then(|r| r.as_array_mut())
        .expect("the vendored file has rules");

    let shipped = rules.len();
    rules.retain(|r| !ADDED_BY_244.contains(&r["name"].as_str().unwrap_or_default()));
    assert_eq!(
        shipped - rules.len(),
        ADDED_BY_244.len(),
        "every rule GH #244 added must be in the shipped file, or this control \
         removes nothing and measures nothing"
    );
    for o in old_rules {
        let name = o["name"].as_str().unwrap();
        let slot = rules
            .iter_mut()
            .find(|r| r["name"].as_str() == Some(name))
            .unwrap_or_else(|| {
                panic!("`{name}` is not a shipped rule, so overriding it controls nothing")
            });
        *slot = o.clone();
    }
    RuleSet::from_toml(&toml::to_string(&file).unwrap()).expect("the a81b02d control compiles")
}

fn not_vacuous<T>(table: &[T], floor: usize, name: &str) {
    assert!(
        table.len() >= floor,
        "`{name}` has {} rows and needs at least {floor}; below that the arms it \
         feeds prove less than they claim. Lower the floor deliberately.",
        table.len()
    );
}

// ------------------------------------------------------------- the rows

#[test]
fn every_spelling_gh_244_found_is_now_redacted() {
    not_vacuous(MISSED_BEFORE, 18, "MISSED_BEFORE");
    let rules = builtin();
    let mut leaked = Vec::new();
    for row in MISSED_BEFORE {
        assert!(
            row.text.contains(row.secret),
            "fixture error: {:?} does not contain its own secret",
            row.text
        );
        let out = redact_str(&rules, row.text);
        if out.contains(row.secret) || !out.contains("[REDACTED:") {
            leaked.push(format!("{:?}\n  -> {out:?}", row.text));
        }
    }
    assert!(
        leaked.is_empty(),
        "{} of {} GH #244 spellings still leak:\n{}",
        leaked.len(),
        MISSED_BEFORE.len(),
        leaked.join("\n")
    );
}

/// **The control: every row leaked on `a81b02d`.** A row the old rules
/// already caught is not evidence of anything this change did.
#[test]
fn every_one_of_those_spellings_leaked_before() {
    not_vacuous(MISSED_BEFORE, 18, "MISSED_BEFORE");
    let rules = before();
    let mut caught = Vec::new();
    for row in MISSED_BEFORE {
        if !redact_str(&rules, row.text).contains(row.secret) {
            caught.push(row.text);
        }
    }
    assert!(
        caught.is_empty(),
        "{} rows were already redacted before GH #244, so they prove nothing:\n{caught:#?}",
        caught.len()
    );
}

/// The kind each row is reported under, so an agent reading the marker
/// knows what was withheld — and so a row caught by some *other* rule by
/// accident (a generic label that happens to sit beside a URL) is seen
/// here rather than credited to the rule it was written for.
#[test]
fn each_spelling_is_reported_under_its_own_kind() {
    let rules = builtin();
    let expected: &[(&str, &str)] = &[
        ("rediss://default:", "connection-string"),
        ("redis://:", "connection-string"),
        ("postgresql+psycopg2://", "connection-string"),
        ("mysql+pymysql://", "connection-string"),
        ("amqps://", "connection-string"),
        ("mariadb://", "connection-string"),
        ("mssql://", "connection-string"),
        ("postgresql+asyncpg://", "connection-string"),
        ("DB_PASS=", "generic"),
        ("SMTP_PASS=", "generic"),
        ("MYSQL_PWD=", "generic"),
        ("APP_KEY=", "generic"),
        ("> Authorization: Basic", "basic-auth"),
        ("{'Authorization': 'Basic", "basic-auth"),
        ("curl https://admin:", "url-password"),
        ("git clone https://oauth2:", "url-password"),
        ("$ mysql -u root", "cli-password"),
        ("$ docker login", "cli-password"),
    ];
    assert_eq!(expected.len(), MISSED_BEFORE.len(), "one kind per row");
    for (row, (needle, kind)) in MISSED_BEFORE.iter().zip(expected) {
        assert!(row.text.contains(needle), "row order moved: {needle:?}");
        let spans = find_spans(&rules, row.text.as_bytes(), 0);
        let kinds: Vec<&str> = spans
            .iter()
            .map(|s| rules.rules[s.rule].kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            vec![*kind],
            "{:?} must come back as exactly one `{kind}` marker",
            row.text
        );
    }
}

/// The false-positive half: ordinary text beside every one of those
/// shapes is untouched, through `redact_str` and through `read_output`.
#[test]
fn the_neighbouring_ordinary_text_is_untouched() {
    not_vacuous(MUST_STAY_UNTOUCHED, 20, "MUST_STAY_UNTOUCHED");
    let rules = builtin();
    let mut altered = Vec::new();
    for row in MUST_STAY_UNTOUCHED {
        let out = redact_str(&rules, row);
        if out != *row {
            altered.push(format!("{row:?}\n  -> {out:?}"));
        }
    }
    assert!(
        altered.is_empty(),
        "{} ordinary rows came back altered:\n{}",
        altered.len(),
        altered.join("\n")
    );
}

// ---------------------------------------------------- the real surface

const TAIL: &str = "\nbuild finished in 13.72s\n";

fn read(processor: &OutputProcessor, buffer: &[u8]) -> ProcessedRead {
    let head = buffer.len() as u64;
    let scan_start = head.saturating_sub(processor.limits.partial_secret_scan_bytes as u64);
    let w = WindowSnapshot {
        window: buffer,
        window_start: 0,
        carry_region: buffer,
        carry_region_start: 0,
        tail_region: &buffer[scan_start as usize..],
        tail_region_start: scan_start,
        req_start: 0,
        head,
        cap_end: head,
        child_alive: true,
        bypass_holdback: false,
        front_clipped: false,
        truncated_at_tail: false,
    };
    processor.process(&w, &ReadOptions::default())
}

/// GH #244 was reported against `read_output`, not against the rule, so
/// the whole `.env` goes through `process` too: no secret survives, one
/// marker per row, and the ordinary rows around them are intact.
#[test]
fn read_output_of_the_whole_env_file_redacts_every_row_and_nothing_else() {
    let processor = OutputProcessor::builtin().unwrap();
    let mut source = String::new();
    for (row, plain) in MISSED_BEFORE.iter().zip(MUST_STAY_UNTOUCHED.iter().cycle()) {
        source.push_str(row.text);
        source.push('\n');
        source.push_str(plain);
        source.push('\n');
    }
    source.push_str(TAIL);
    let r = read(&processor, source.as_bytes());
    assert!(!r.held_back, "a terminated file must not be held back");
    for row in MISSED_BEFORE {
        assert!(
            !r.output.contains(row.secret),
            "read_output handed out {:?} from {:?}",
            row.secret,
            row.text
        );
    }
    for plain in MUST_STAY_UNTOUCHED.iter().take(MISSED_BEFORE.len()) {
        assert!(
            r.output.contains(plain),
            "read_output altered an ordinary row: {plain:?}"
        );
    }
    let total: usize = r.redactions.values().sum();
    assert_eq!(
        total,
        MISSED_BEFORE.len(),
        "one redaction per GH #244 row: {:?}",
        r.redactions
    );
}

/// **§4.1's partial-secret property on the new spellings: no byte of a
/// credential still arriving at the buffer head is handed out raw.**
///
/// Driven one byte at a time, because that is the property — a read can
/// land after any byte. Each read either withholds the arrived bytes
/// (`held_back`) or covers them with a marker, and which one depends on
/// the rule: an open-ended value (`{4,}`, `+`) is a whole match as soon
/// as its floor has arrived, so the redactor covers it and there is
/// nothing to withhold.
///
/// The index entries that make this hold are chosen so their prefix ends
/// where the credential begins — `authorization: basic `, `mysql `,
/// `https://x-access-token:` — which is why these four spellings and not
/// every spelling of each rule. The rest is the next test.
#[test]
fn no_byte_of_a_credential_still_arriving_is_handed_out_raw() {
    let processor = OutputProcessor::builtin().unwrap();
    for (context, secret) in [
        ("> Authorization: Basic ", "YWRtaW46WnE3UHc5eExrMk12"),
        ("git clone https://x-access-token:", "Zq7Pw9xLk2Mv"),
        ("$ mysql -p", "Zq7Pw9xLk2Mv"),
        ("DB_PASS=", "Zq7Pw9xLk2Mv"),
    ] {
        assert!(
            !context.contains(&secret[..1]),
            "fixture error: the context must not contain the secret's first byte"
        );
        let full = format!("{context}{secret}");
        for take in context.len() + 1..=full.len() {
            let arrived = &full[context.len()..take];
            let r = read(&processor, &full.as_bytes()[..take]);
            assert!(
                !r.output.contains(arrived),
                "{:?} handed out {arrived:?} raw: held_back={} output={:?}",
                &full[..take],
                r.held_back,
                r.output
            );
        }
    }
}

/// **REQ-TST-006: the spellings the holdback does *not* reach, stated.**
///
/// `url-userinfo-password` indexes only the token-carrying usernames,
/// because an entry at `https://` would hold every URL a program prints at
/// the buffer head (`ordinary_build_output_never_yields_a_boundary`). A
/// password behind any other username is therefore released while it is
/// still arriving, and redacted once its `@` lands. The arm pins both
/// halves: the leak window exists, and it closes.
#[test]
fn a_url_password_behind_an_ordinary_username_is_not_held_while_arriving() {
    let processor = OutputProcessor::builtin().unwrap();
    let growing = "curl https://admin:Zq7Pw9x";
    let r = read(&processor, growing.as_bytes());
    assert!(
        !r.held_back && r.output.contains("Zq7Pw9x"),
        "the documented window closed — a candidate is now held here. Rewrite \
         this row rather than deleting it: held_back={} output={:?}",
        r.held_back,
        r.output
    );
    let done = format!("{growing}Lk2Mv@internal.example.com/api\n");
    let r = read(&processor, done.as_bytes());
    assert!(
        !r.output.contains("Zq7Pw9x") && r.output.contains("[REDACTED:url-password]"),
        "once the `@` arrives the whole password is redacted: {:?}",
        r.output
    );
}

/// **The other half of the index entries' choice: what they must not
/// hold.** Each new rule's entry is the literal where its credential
/// begins, not the program or the scheme, because a context rule holds a
/// candidate while every byte after the prefix is printable — so an entry
/// at `mysql` would hold `mysqldump` at the buffer head, one at `docker`
/// would hold `docker-compose`, one at `authorization` would hold curl's
/// `Authorization:`, and one at `https://` would hold every URL a program
/// prints until its authority ends. Each row is every prefix of an
/// ordinary line, as a reader can see it arrive.
#[test]
fn ordinary_command_heads_are_not_held_back() {
    let processor = OutputProcessor::builtin().unwrap();
    for line in [
        "$ mysqldump --single-transaction app",
        "$ docker-compose up -d",
        "> Authorization: Bearer $GH_TOKEN",
        "Visit https://example.internal/docs for more",
        "  ➜  Local:   http://localhost:5173/",
        "$ podman-remote info",
    ] {
        for take in 1..=line.len() {
            if !line.is_char_boundary(take) {
                continue;
            }
            let r = read(&processor, &line.as_bytes()[..take]);
            assert!(
                !r.held_back,
                "ordinary output must not be held back: {:?} -> {:?}",
                &line[..take],
                r.output
            );
        }
    }
}
