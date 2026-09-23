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
/// `https://x-access-token:` — which is why these spellings and not
/// every spelling of each rule. The rest is the next tests.
///
/// **`basic-authorization` and `database-connection-password` get one row
/// per index entry**, because each entry is a separate spelling that is
/// held or not on its own: a review of GH #244 found every Basic spelling
/// but the canonical header released while arriving (the rule had one
/// entry), and deleting a scheme's entry (`rediss://`, `postgresql+`) went
/// unnoticed by every test. [`every_index_entry_of_those_two_rules_has_a_row`]
/// is what keeps a new entry from arriving without one.
const ARRIVING: &[(&str, &str)] = &[
    // basic-authorization, one row per index entry.
    ("> Authorization: Basic ", BASIC_SECRET),
    ("curl -H 'Authorization:Basic ", BASIC_SECRET),
    ("authorization: \"Basic ", BASIC_SECRET),
    ("authorization: 'Basic ", BASIC_SECRET),
    ("{\"Authorization\": \"Basic ", BASIC_SECRET),
    ("{\"Authorization\":\"Basic ", BASIC_SECRET),
    ("{'Authorization': 'Basic ", BASIC_SECRET),
    ("{'Authorization':'Basic ", BASIC_SECRET),
    ("proxy_set_header Authorization \"Basic ", BASIC_SECRET),
    ("AUTHORIZATION=Basic ", BASIC_SECRET),
    ("authorization = \"Basic ", BASIC_SECRET),
    ("authorization = 'Basic ", BASIC_SECRET),
    // database-connection-password, one row per index entry.
    ("URL=postgres://app:", "Zq7Pw9xLk2Mv"),
    ("URL=postgresql://app:", "Zq7Pw9xLk2Mv"),
    ("URL=postgresql+asyncpg://app:", "Zq7Pw9xLk2Mv"),
    ("URL=mysql://app:", "Zq7Pw9xLk2Mv"),
    ("URL=mysql+pymysql://app:", "Zq7Pw9xLk2Mv"),
    ("URL=mariadb://app:", "Zq7Pw9xLk2Mv"),
    ("URL=mariadb+mariadbconnector://app:", "Zq7Pw9xLk2Mv"),
    ("URL=mssql://sa:", "Zq7Pw9xLk2Mv"),
    ("URL=mssql+pyodbc://sa:", "Zq7Pw9xLk2Mv"),
    ("URL=sqlserver://sa:", "Zq7Pw9xLk2Mv"),
    ("URL=oracle://app:", "Zq7Pw9xLk2Mv"),
    ("URL=oracle+oracledb://app:", "Zq7Pw9xLk2Mv"),
    ("URL=cockroachdb://app:", "Zq7Pw9xLk2Mv"),
    ("URL=cockroachdb+psycopg://app:", "Zq7Pw9xLk2Mv"),
    ("URL=clickhouse://app:", "Zq7Pw9xLk2Mv"),
    ("URL=clickhouse+native://app:", "Zq7Pw9xLk2Mv"),
    ("URL=snowflake://app:", "Zq7Pw9xLk2Mv"),
    ("URL=mongodb://app:", "Zq7Pw9xLk2Mv"),
    ("URL=mongodb+srv://app:", "Zq7Pw9xLk2Mv"),
    ("URL=redis://:", "Zq7Pw9xLk2Mv"),
    ("URL=rediss://default:", "Zq7Pw9xLk2Mv"),
    ("URL=redis+sentinel://:", "Zq7Pw9xLk2Mv"),
    ("URL=valkey://:", "Zq7Pw9xLk2Mv"),
    ("URL=valkeys://default:", "Zq7Pw9xLk2Mv"),
    ("URL=amqp://app:", "Zq7Pw9xLk2Mv"),
    ("URL=amqps://app:", "Zq7Pw9xLk2Mv"),
    ("URL=neo4j://neo4j:", "Zq7Pw9xLk2Mv"),
    ("URL=neo4j+s://neo4j:", "Zq7Pw9xLk2Mv"),
    ("URL=bolt://neo4j:", "Zq7Pw9xLk2Mv"),
    ("URL=bolt+s://neo4j:", "Zq7Pw9xLk2Mv"),
    // One row each for the other rules that hold a credential arriving.
    ("git clone https://x-access-token:", "Zq7Pw9xLk2Mv"),
    ("$ mysql -p", "Zq7Pw9xLk2Mv"),
    ("DB_PASS=", "Zq7Pw9xLk2Mv"),
];

/// `admin:Zq7Pw9xLk2Mv`, in RFC 4648 base64.
const BASIC_SECRET: &str = "YWRtaW46WnE3UHc5eExrMk12";

#[test]
fn no_byte_of_a_credential_still_arriving_is_handed_out_raw() {
    let processor = OutputProcessor::builtin().unwrap();
    for (context, secret) in ARRIVING {
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

/// **The table above is complete for the two rules it enumerates.** An
/// index entry is a spelling the rule promises to hold while it arrives;
/// one added to the rule file without a row here is a promise nothing
/// checks. Matching is ASCII-case-insensitive, as the index's is.
#[test]
fn every_index_entry_of_those_two_rules_has_a_row() {
    let rules = builtin();
    let contexts: Vec<String> = ARRIVING
        .iter()
        .map(|(c, _)| c.to_ascii_lowercase())
        .collect();
    for name in ["basic-authorization", "database-connection-password"] {
        let rule = rules.rules.iter().find(|r| r.name == name).unwrap();
        let declared = rule
            .declared_prefixes
            .as_ref()
            .unwrap_or_else(|| panic!("`{name}` must declare its index entries"));
        assert!(
            declared.len() > 1,
            "`{name}` has one entry; this test measures nothing"
        );
        for prefix in declared {
            let prefix = String::from_utf8(prefix.clone()).unwrap();
            assert!(
                contexts.iter().any(|c| c.contains(&prefix)),
                "`{name}` indexes {prefix:?} and no row of ARRIVING exercises it"
            );
        }
    }
}

/// **A Basic spelling with no index entry of its own: what has arrived
/// may go out, and the refusal is what bounds how much.**
///
/// The index holds a header spelling only if it is listed, and whitespace
/// makes the spellings unbounded — two spaces, a tab. There, a value still
/// arriving is released unless `find_spans` covers it, and a refusal that
/// declines the partial value hands it out raw. With a length-only refusal
/// that was three reads in four, up to every byte but the last (found by
/// review of GH #244); refusing only an all-lower-case word leaves the
/// value floor, the three bytes before `{4,}` is a match. Both surfaces
/// that release from a buffer head are driven: `read_output`'s and the
/// live stream `attach` and `watch` use.
///
/// The arm pins both halves: the floor leak exists (so each spelling
/// really is unindexed and the bound is not satisfied vacuously by a
/// hold), and nothing past it does. The control is `b4f935e`'s
/// length-only refusal, under which every spelling here handed out far
/// more.
#[test]
fn an_unindexed_basic_spelling_hands_out_no_more_than_the_value_floor() {
    use holdfast_core::attach::StreamRedactor;
    use std::sync::Arc;
    const FLOOR: usize = 3;
    let processor = Arc::new(OutputProcessor::builtin().unwrap());
    let control = Arc::new(OutputProcessor::new(
        Arc::new(before_review()),
        processor.audit.clone(),
        processor.limits,
    ));
    let longest_raw_run = |out: &str, arrived: &str| {
        (1..=arrived.len())
            .rev()
            .find(|&k| out.contains(&arrived[..k]))
            .unwrap_or(0)
    };
    // The widest raw run any read or stream hands out while the value
    // arrives after `context`.
    let widest = |processor: &Arc<OutputProcessor>, context: &str| {
        let full = format!("{context}{BASIC_SECRET}");
        (context.len() + 1..=full.len())
            .map(|take| {
                let arrived = &full[context.len()..take];
                let r = read(processor, &full.as_bytes()[..take]);
                let mut stream = StreamRedactor::new(Arc::clone(processor));
                let streamed = stream.feed(&full.as_bytes()[..take]);
                let streamed = String::from_utf8_lossy(&streamed);
                longest_raw_run(&r.output, arrived).max(longest_raw_run(&streamed, arrived))
            })
            .max()
            .unwrap_or(0)
    };
    for context in [
        "> Authorization:  Basic ",
        "Authorization:\tBasic ",
        "Authorization: Basic  ",
        "authorization=\"Basic ",
    ] {
        assert!(!context.contains(&BASIC_SECRET[..1]), "fixture error");
        assert_eq!(
            widest(&processor, context),
            FLOOR,
            "{context:?}: a Basic value still arriving on an unindexed spelling must \
             hand out the value floor — more is a leak, less means an index entry \
             holds this spelling and the row does not measure the refusal"
        );
        assert!(
            widest(&control, context) > FLOOR,
            "{context:?}: the length-only control must hand out more than the floor, \
             or this row is not evidence about the refusal"
        );
    }
}

/// **The property the refusal's `[a-z]` half rests on, measured rather
/// than argued: a partial Basic value it refuses never decodes past the
/// user name and its colon.** A refused partial is one that may be handed
/// out raw while it arrives (the test above), so if it ever reached the
/// password's bytes the refusal would be a leak by construction.
///
/// Base64 of `user:` reaches an upper-case letter or a digit before the
/// password in practice — the colon itself encodes to `O` or `6` in two of
/// its three positions — but not by any law, so this sweeps common
/// service-account names against dictionary and generated passwords and
/// every partial length of each. Allowing digits in the refusal fails
/// here (`nginx:` encodes to `bmdpbng6`).
#[test]
fn a_refused_basic_partial_never_decodes_into_the_password() {
    use base64::Engine as _;
    let rules = builtin();
    let rule = rules
        .rules
        .iter()
        .find(|r| r.name == "basic-authorization")
        .unwrap();
    let users = [
        "admin",
        "root",
        "user",
        "ubuntu",
        "postgres",
        "elastic",
        "git",
        "api",
        "oauth2",
        "deploy",
        "ci",
        "jenkins",
        "test",
        "guest",
        "service",
        "svc",
        "bot",
        "apikey",
        "token",
        "alice",
        "bob",
        "dev",
        "build",
        "myuser",
        "username",
        "mongo",
        "redis",
        "rabbitmq",
        "oracle",
        "sa",
        "web",
        "www-data",
        "nginx",
        "app",
        "kibana",
        "grafana",
        "minio",
        "registry",
        "docker",
        "runner",
        "backup",
        "monitor",
        "zabbix",
        "ftp",
        "x-access-token",
        "gitlab-ci-token",
    ];
    let mut passwords: Vec<String> = [
        "password",
        "sunshine",
        "letmein",
        "dragon",
        "monkey",
        "football",
        "iloveyou",
        "whatever",
        "trustno1",
        "changeme",
        "correcthorsebatterystaple",
        "hunter2",
        "welcome",
        "shadow",
        "Tr0ub4dor&3",
        "Zq7Pw9xLk2Mv",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    // Generated passwords from a fixed LCG, so the sweep is deterministic.
    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#%&*";
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    for _ in 0..400 {
        let len = 8 + (state % 17) as usize;
        let pw: String = (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                alphabet[(state >> 33) as usize % alphabet.len()] as char
            })
            .collect();
        passwords.push(pw);
    }
    let mut refused_partials = 0usize;
    for user in users {
        for pw in &passwords {
            let b64 = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pw}"));
            for k in 1..=b64.len() {
                if rule.value_admissible(&b64.as_bytes()[..k]) {
                    continue;
                }
                refused_partials += 1;
                let decoded = k * 6 / 8;
                assert!(
                    decoded <= user.len() + 1,
                    "the refusal declines {:?}, the first {k} bytes of {user}:{pw}'s \
                     base64, which decode {decoded} bytes — past the user name and \
                     colon ({}) into the password",
                    &b64[..k],
                    user.len() + 1
                );
            }
        }
    }
    assert!(
        refused_partials > 0,
        "no partial was refused, so this measured nothing about the refusal"
    );
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

// ------------------------------------------------- the review of #244

/// **The four rules a review of GH #244 changed, exactly as the branch had
/// them before it** (`b4f935e`). Spelled out, never derived, for the same
/// reason as [`BEFORE_244`]: a control that moves with the thing it
/// controls controls nothing.
const BEFORE_REVIEW: &str = r#"
[[rule]]
name = "database-connection-password"
kind = "connection-string"
pattern = '''\b(?:postgres(?:ql)?|mysql|mariadb|mssql|sqlserver|oracle|cockroachdb|clickhouse|snowflake|mongodb|rediss?|valkeys?|amqps?|neo4j|bolt)(?:\+[A-Za-z0-9_]+)*://[^:@/\s]*:(?P<value>[^\s"'`]+)@'''
prefixes = ["postgres://", "postgresql://", "postgresql+", "mysql://", "mysql+", "mariadb://", "mariadb+", "mssql://", "mssql+", "sqlserver://", "oracle://", "oracle+", "cockroachdb://", "cockroachdb+", "clickhouse://", "clickhouse+", "snowflake://", "mongodb://", "mongodb+", "redis://", "rediss://", "redis+", "valkey://", "valkeys://", "amqp://", "amqps://", "neo4j://", "neo4j+", "bolt://", "bolt+"]
positive = ["postgresql://svc:hunter2GOESHERE@db.internal:5432/app"]
negative = ["postgresql://db.internal:5432/app"]

[[rule]]
name = "basic-authorization"
kind = "basic-auth"
pattern = '''(?i)\bauthorization\b["']?[ \t]*[:=]?[ \t]*["']?basic[ \t]+(?P<value>[A-Za-z0-9+/]{4,}={0,2})'''
prefixes = ["authorization: basic "]
value_must_not_match = '''(?:[A-Za-z0-9+/=]{4})*[A-Za-z0-9+/=]{1,3}'''
positive = ["Authorization: Basic dXNlcjpodW50ZXIyR09FU0hFUkU="]
negative = ["Authorization: Basic authentication is required"]

[[rule]]
name = "mysql-cli-password"
kind = "cli-password"
pattern = '''\b(?:mysql|mariadb)[a-z-]*\b[^\r\n|;&]*?[ \t]-p["']?(?P<value>[^\s"'`;|&<>]+)'''
prefixes = ["mysql ", "mariadb "]
positive = ["mysql -u root -phunter2GOESHERE app"]
negative = ["mysql -u root -p app"]

[[rule]]
name = "registry-login-password"
kind = "cli-password"
pattern = '''\b(?:docker|podman|nerdctl|buildah|skopeo|oras|helm[ \t]+registry)[ \t]+login\b[^\r\n|;&]*?[ \t](?:-p|--password)(?:[ \t]+|=)["']?(?P<value>[^\s"'`;|&<>]+)'''
prefixes = ["docker login", "podman login", "nerdctl login", "buildah login", "skopeo login", "oras login", "helm registry"]
positive = ["docker login -u ci -p hunter2GOESHERE registry.example.com"]
negative = ["docker login -u ci registry.example.com"]
"#;

fn before_review() -> RuleSet {
    RuleSet::builtin_with_extra(BEFORE_REVIEW).expect("the b4f935e control compiles")
}

/// One spelling whose **whole** secret must go under a marker, the kind
/// that marker must be, and whether `b4f935e` let some of it through.
struct WholeRow {
    text: &'static str,
    secret: &'static str,
    kind: &'static str,
    leaked_before_review: bool,
}

/// **Rows where part of a password came back, and rows that pin a
/// password's inside.** The first group is what the review found: a quote
/// or a backtick in a connection string's password (redacted at `a81b02d`,
/// raw at `b4f935e`), a quoted command-line password carrying a byte an
/// unquoted shell word stops at, and `docker login`'s attached `-p<pw>`.
/// The second group leaked nothing at `b4f935e` and is here because
/// nothing asserted it: a password with an `@` in it, a `-p=` flag.
///
/// **Asserted on every four-byte run of the secret, not on the secret
/// whole.** A rule that stops at the `&` of `Xk9#mP&2qLzQ` changes the
/// output and removes the full secret from it, and still hands out
/// `&2qLzQ` — which `contains(secret)` cannot see and which is exactly the
/// defect.
const WHOLE_SECRET: &[WholeRow] = &[
    WholeRow {
        text: "DATABASE_URL=postgres://app:Pa'ss9word@db/app",
        secret: "Pa'ss9word",
        kind: "connection-string",
        leaked_before_review: true,
    },
    WholeRow {
        text: "DATABASE_URL=postgres://app:Pa\"ss9word@db/app",
        secret: "Pa\"ss9word",
        kind: "connection-string",
        leaked_before_review: true,
    },
    WholeRow {
        text: "DATABASE_URL=postgres://app:Pa`ss9word@db/app",
        secret: "Pa`ss9word",
        kind: "connection-string",
        leaked_before_review: true,
    },
    WholeRow {
        text: "MONGO_URL=mongodb://app:Pa'ss9word@db/app",
        secret: "Pa'ss9word",
        kind: "connection-string",
        leaked_before_review: true,
    },
    WholeRow {
        text: "$ mysql -u root -p'Xk9#mP&2qLzQ' app",
        secret: "Xk9#mP&2qLzQ",
        kind: "cli-password",
        leaked_before_review: true,
    },
    WholeRow {
        text: "$ mysql -u root -p\"Xk9|mP;2qLzQ\" app",
        secret: "Xk9|mP;2qLzQ",
        kind: "cli-password",
        leaked_before_review: true,
    },
    WholeRow {
        text: "$ mysqldump -uroot -p'ab<cd>ef12gh' app > dump.sql",
        secret: "ab<cd>ef12gh",
        kind: "cli-password",
        leaked_before_review: true,
    },
    WholeRow {
        text: "$ mysql -u root -p'correct horse battery' app",
        secret: "correct horse battery",
        kind: "cli-password",
        leaked_before_review: true,
    },
    WholeRow {
        text: "$ docker login -u ci -p 'Xk9#mP&2qLzQ' ghcr.io",
        secret: "Xk9#mP&2qLzQ",
        kind: "cli-password",
        leaked_before_review: true,
    },
    WholeRow {
        text: "$ docker login -u ci --password \"Xk9;mP2qLzQ\" ghcr.io",
        secret: "Xk9;mP2qLzQ",
        kind: "cli-password",
        leaked_before_review: true,
    },
    WholeRow {
        text: "$ docker login -u ci -pXk9mP2qLzQ ghcr.io",
        secret: "Xk9mP2qLzQ",
        kind: "cli-password",
        leaked_before_review: true,
    },
    // Held at `b4f935e`, asserted by nothing.
    WholeRow {
        text: "$ docker login -u ci -p=Xk9mP2qLzQ ghcr.io",
        secret: "Xk9mP2qLzQ",
        kind: "cli-password",
        leaked_before_review: false,
    },
    WholeRow {
        text: "curl https://deploy:Zq7P@w9xLk2Mv@internal.example.com/api",
        secret: "Zq7P@w9xLk2Mv",
        kind: "url-password",
        leaked_before_review: false,
    },
    WholeRow {
        text: "REDIS_URL=redis://:Zq7P@w9xLk2Mv@cache:6379/0",
        secret: "Zq7P@w9xLk2Mv",
        kind: "connection-string",
        leaked_before_review: false,
    },
    WholeRow {
        text: "SQLALCHEMY_DATABASE_URI=postgresql+asyncpg://app:Zq7P/w9xLk2Mv@db/app",
        secret: "Zq7P/w9xLk2Mv",
        kind: "connection-string",
        leaked_before_review: false,
    },
];

/// The first four-byte run of `secret` that is visible in `out`, if any.
fn surviving_run<'a>(out: &str, secret: &'a str) -> Option<&'a str> {
    (0..=secret.len().saturating_sub(4))
        .map(|i| &secret[i..i + 4])
        .find(|run| out.contains(run))
}

#[test]
fn no_run_of_a_whole_secret_row_survives_redaction() {
    not_vacuous(WHOLE_SECRET, 15, "WHOLE_SECRET");
    let rules = builtin();
    let processor = OutputProcessor::builtin().unwrap();
    let mut leaked = Vec::new();
    for row in WHOLE_SECRET {
        let context = row.text.replacen(row.secret, "", 1);
        assert!(
            row.text.contains(row.secret) && surviving_run(&context, row.secret).is_none(),
            "fixture error: {:?} must contain its secret, and no run of the secret may \
             occur in the text around it",
            row.text
        );
        let spans = find_spans(&rules, row.text.as_bytes(), 0);
        let kinds: Vec<&str> = spans
            .iter()
            .map(|s| rules.rules[s.rule].kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            vec![row.kind],
            "{:?} must carry one `{}` marker",
            row.text,
            row.kind
        );

        let direct = redact_str(&rules, row.text);
        let source = format!("{}{TAIL}", row.text);
        let read_back = read(&processor, source.as_bytes()).output;
        for (surface, out) in [("redact_str", &direct), ("read_output", &read_back)] {
            if let Some(run) = surviving_run(out, row.secret) {
                leaked.push(format!(
                    "{surface}: {:?} -> {out:?} still shows {run:?}",
                    row.text
                ));
            }
        }
    }
    assert!(leaked.is_empty(), "{}", leaked.join("\n"));
}

/// **Control: the first group leaked at `b4f935e`**, so each row is
/// evidence about this change and not about one before it. The second
/// group did not, and is asserted not to — it is a pin, and saying so is
/// what keeps it from being read as a fix.
#[test]
fn the_rows_the_review_found_leaked_before_it() {
    let before = before_review();
    for row in WHOLE_SECRET {
        let out = redact_str(&before, row.text);
        assert_eq!(
            surviving_run(&out, row.secret).is_some(),
            row.leaked_before_review,
            "{:?} under b4f935e came back {out:?}; `leaked_before_review` says {}",
            row.text,
            row.leaked_before_review
        );
    }
}

/// **Every scheme each URL rule names is reached, one row apiece.** The
/// scheme lists are alternations, so deleting one leaves every other
/// row green; `neo4j`, `socks5h`, `ldaps` and friends had no positive
/// fixture and could go without a test noticing. `+driver` spellings are
/// here too, because that suffix is its own part of the pattern. The
/// table is written out rather than read from the pattern, so it cannot
/// shrink with it.
#[test]
fn every_scheme_the_two_url_rules_name_is_redacted() {
    const SECRET: &str = "Zq7Pw9xLk2Mv";
    let db = [
        "postgres",
        "postgresql",
        "postgresql+psycopg2",
        "mysql",
        "mysql+pymysql",
        "mariadb",
        "mssql",
        "mssql+pyodbc",
        "sqlserver",
        "oracle",
        "cockroachdb",
        "clickhouse",
        "snowflake",
        "mongodb",
        "mongodb+srv",
        "redis",
        "rediss",
        "valkey",
        "valkeys",
        "amqp",
        "amqps",
        "neo4j",
        "neo4j+s",
        "bolt",
        "bolt+s",
    ];
    let url = [
        "http",
        "https",
        "ftp",
        "ftps",
        "ssh",
        "git",
        "git+ssh",
        "git+http",
        "git+https",
        "svn",
        "svn+ssh",
        "ws",
        "wss",
        "smtp",
        "smtps",
        "imap",
        "imaps",
        "pop3",
        "pop3s",
        "ldap",
        "ldaps",
        "mqtt",
        "mqtts",
        "nats",
        "socks4",
        "socks4a",
        "socks5",
        "socks5h",
        "rtsp",
        "rtsps",
        "rtmp",
        "rtmps",
    ];
    let rules = builtin();
    let mut missed = Vec::new();
    for (schemes, rule) in [
        (&db[..], "database-connection-password"),
        (&url[..], "url-userinfo-password"),
    ] {
        for scheme in schemes {
            let text = format!("{scheme}://svc:{SECRET}@host.example/x");
            let names: Vec<String> = find_spans(&rules, text.as_bytes(), 0)
                .into_iter()
                .map(|s| rules.rules[s.rule].name.clone())
                .collect();
            let out = redact_str(&rules, &text);
            if names != vec![rule.to_string()] || out.contains(SECRET) {
                missed.push(format!("{text:?} -> {out:?} by {names:?}, want `{rule}`"));
            }
        }
    }
    assert!(missed.is_empty(), "{}", missed.join("\n"));
}

/// **A quoted password runs to its closing quote on its own line, and no
/// further.** Without the line guard a `-p'…` whose closing quote never
/// arrives — `ps` cuts a long command line at the terminal's width — ran on
/// to the next quote anywhere below it, taking the lines between with it.
/// The first line's value is still covered, by the unquoted branch, as far
/// as it goes.
#[test]
fn a_quoted_password_does_not_run_past_its_line() {
    let rules = builtin();
    for (first, next) in [
        (
            "root      4242  mysql -u root -p'Xk9mP2qLzQ",
            "root      4243  sh -c 'sleep 5; echo done'",
        ),
        (
            "ci        4244  docker login -u ci -p \"Xk9mP2qLzQ",
            "ci        4245  sh -c \"echo ready\"",
        ),
    ] {
        let text = format!("{first}\n{next}");
        let out = redact_str(&rules, &text);
        assert!(
            out.ends_with(&format!("\n{next}")),
            "the line after an unterminated quote was altered: {out:?}"
        );
        assert!(
            surviving_run(&out, "Xk9mP2qLzQ").is_none(),
            "the first line's password must still be covered: {out:?}"
        );
    }
}

/// **Where the marker goes, for each spelling of the registry flag.** The
/// flag and its `=` stay visible and only the password is replaced — so a
/// reader can see which argument was withheld. Attached `-p<pw>` subsumes
/// `-p=<pw>` as a *match*, with the `=` inside the value; this pins that the
/// `=` is read as the separator it is.
#[test]
fn each_registry_flag_spelling_keeps_its_flag_visible() {
    let rules = builtin();
    for (text, want) in [
        (
            "docker login -u ci -p Xk9mP2qLzQ ghcr.io",
            "docker login -u ci -p [REDACTED:cli-password] ghcr.io",
        ),
        (
            "docker login -u ci -pXk9mP2qLzQ ghcr.io",
            "docker login -u ci -p[REDACTED:cli-password] ghcr.io",
        ),
        (
            "docker login -u ci -p=Xk9mP2qLzQ ghcr.io",
            "docker login -u ci -p=[REDACTED:cli-password] ghcr.io",
        ),
        (
            "docker login -u ci --password=Xk9mP2qLzQ ghcr.io",
            "docker login -u ci --password=[REDACTED:cli-password] ghcr.io",
        ),
        (
            "docker login -u ci -p 'Xk9#mP&2qLzQ' ghcr.io",
            "docker login -u ci -p [REDACTED:cli-password] ghcr.io",
        ),
        (
            "mysql -u root -p'Xk9#mP&2qLzQ' app",
            "mysql -u root -p[REDACTED:cli-password] app",
        ),
    ] {
        assert_eq!(redact_str(&rules, text), want, "{text:?}");
    }
}
