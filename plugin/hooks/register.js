// Holdfast's Claude Code mod: the secret-request band.
//
// When the agent calls Holdfast's request_secret_input, the turn blocks until
// a human types the secret into `holdfast attach`. This module tells the human
// so: a toast, and a band above the prompt naming the session, what the agent
// says, the time left, and the attach command, with buttons to open it in a
// tmux split or copy it when there is a `holdfast` binary to name.
//
// What it must never do, and does not:
//   - take a secret: there is no text field here, and nothing is written to
//     any process's standard input. The secret is typed in `holdfast attach`;
//   - answer, rewrite, approve or hold up a call: each tool.call hook passes
//     the call on before it does anything else and returns its result
//     untouched, and there is no tool.check hook;
//   - call Holdfast: a mod's $.mcp.call is permission-checked like the
//     agent's own, so a read here would put a permission dialog in front of
//     the agent's secret request. Everything drawn comes from the agent's own
//     calls as they pass through these hooks;
//   - put anything in front of the model: no commands, no prompt submission,
//     no store.
// Session names and prompt text are the agent's text, so they are drawn only
// after control and bidi characters are stripped, labelled, and with the
// session id beside the name whenever the agent's own calls have shown it.

// Measured with this plugin loaded: the server is `plugin:holdfast:holdfast`,
// so Claude Code names the tools this.
const TOOL = 'mcp__plugin_holdfast_holdfast__request_secret_input'
// The agent's own calls whose results pair a session's name with its id.
const START_SESSION = 'mcp__plugin_holdfast_holdfast__start_session'
const LIST_SESSIONS = 'mcp__plugin_holdfast_holdfast__list_sessions'
const STATUS = 'mcp__plugin_holdfast_holdfast__status'
// `session/mod.rs` `new_session_id`.
const SESSION_ID = /^sess_[0-9a-f]{12}$/
// A name `holdfast attach` takes as it stands: it resolves a live session's
// name as it does an id. Leading with a letter or digit, it is never read as
// a flag, and nothing in it means anything to a shell.
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const TMUX_PANE = /^%[0-9]{1,9}$/
// Status and reason words from the daemon are enums; anything else is not
// drawn as one.
const WORD = /^[a-z][a-z0-9_]{0,63}$/
// request_secret_input's own default when the call names none.
const DEFAULT_TIMEOUT_SECS = 120
const OUTCOME_MS = 5000
const TOAST_MS = 8000
const CHECK_MS = 2000
// A request the hook never heard the end of (an abandoned turn) is dropped
// this long after its own deadline, so the band cannot stay up forever.
const STALE_AFTER_MS = 300_000
const TEXT_MAX = 160
// A name is the agent's to choose. Capped short, so that in an 80-column
// band the real id after it is never truncated away, whatever the name
// pretends to be.
const NAME_MAX = 24
// How many session names the module keeps an id for, and how many PATH
// entries it looks in for `holdfast`.
const KNOWN_MAX = 256
const PATH_DIRS_MAX = 64
// What Claude Code's own server resolved its daemon's runtime directory
// from, besides HOME (holdfast-core `RuntimePaths::discover`). The tmux
// pane gets them, because a pane is born with the tmux server's
// environment, not Claude Code's, and would otherwise dial another daemon.
const PANE_ENV = ['HOLDFAST_RUNTIME_DIR', 'XDG_RUNTIME_DIR']
// `holdfast` is on PATH only if the user put it there.
const NOT_ON_PATH_ISSUE = 'https://github.com/Sertelegger/holdfast/issues/280'

// Open requests by tool_use_id, oldest first; the closing lines still on
// show; and session name -> id, as the agent's own calls reported them.
// Module state: none of it outlives a reload of this module.
const pending = new Map()
let outcomes = []
let ticker = null
const known = new Map()

// ------------------------------------------------------------ pure helpers

// CSI, OSC and two-byte escapes; then line breaks and tabs, which become a
// space; then every remaining C0/C1 control, DEL, bidi mark, override or
// isolate, byte order mark, and invisible character (soft hyphen, zero
// widths, joiners, invisible operators, tags), which are dropped: an
// invisible character lets one name draw exactly like another.
const ESCAPES = /\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-_]/g
const BREAKS = /[\t\n\v\f\r\u0085\u2028\u2029]/g
const UNSAFE =
  /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2069\ufeff\ufff9-\ufffb\u{e0000}-\u{e007f}]/gu

export function clean(value, max = TEXT_MAX) {
  if (typeof value !== 'string') return ''
  const flat = value.replace(ESCAPES, '').replace(BREAKS, ' ').replace(UNSAFE, '').replace(/ +/g, ' ').trim()
  const chars = Array.from(flat)
  return chars.length > max ? chars.slice(0, max - 1).join('') + '\u2026' : flat
}

export function validSessionId(value) {
  return typeof value === 'string' && SESSION_ID.test(value) ? value : null
}

// What an attach command may name: an id, or a name in SAFE_NAME.
export function validTarget(value) {
  return validSessionId(value) || (typeof value === 'string' && SAFE_NAME.test(value) ? value : null)
}

function validWord(value) {
  return typeof value === 'string' && WORD.test(value) ? value : null
}

// An absolute path with nothing in it that a terminal or a shell would read
// as anything but a path.
function validPath(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.length > 4096) return null
  return value.replace(UNSAFE, '') === value ? value : null
}

export function shellQuote(value) {
  return "'" + value.replaceAll("'", "'\\''") + "'"
}

// `<binary> attach --keep-size <target>`, both quoted, or null when either is
// not what it must be. --keep-size because a half-width split must not
// reflow the agent's session.
export function attachCommand(binary, target) {
  if (!validPath(binary) || !validTarget(target)) return null
  return shellQuote(binary) + ' attach --keep-size ' + shellQuote(target)
}

// Run by `sh -c` with the binary as $0 and the target as $1, so neither is
// ever parsed by a shell. On a failure the pane stays open and says so; tmux
// would otherwise close it at once and take the reason with it.
const SPLIT_SCRIPT = `"$0" attach --keep-size "$1" || { s=$?; printf '\\nholdfast attach exited %s. Press Enter to close this pane.\\n' "$s"; read -r _; }`

// The same attach, as the argv of a tmux split, or null when the binary or
// the target is not what it must be. A command given to tmux as several
// arguments is executed directly (tmux 2.0 and later), not through the
// user's default-shell, whatever shell that is. `env` hands the pane each
// of PANE_ENV that Claude Code has as a valid path.
export function tmuxArgv(binary, target, pane, env = {}) {
  const bin = validPath(binary)
  const to = validTarget(target)
  if (!bin || !to) return null
  const at = typeof pane === 'string' && TMUX_PANE.test(pane) ? ['-t', pane] : []
  const assignments = PANE_ENV.filter((name) => validPath(env[name])).map((name) => name + '=' + env[name])
  // -d keeps the focus in Claude Code's pane, so whatever the human types
  // next still goes to the prompt and never into a waiting password read.
  return ['tmux', 'split-window', '-d', '-h', ...at, '--', '/usr/bin/env', ...assignments, '/bin/sh', '-c', SPLIT_SCRIPT, bin, to]
}

function parseJson(text) {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

function isEnvelope(value) {
  return value !== null && typeof value === 'object' && typeof value.status === 'string'
}

// Holdfast's `{ status, data, details }` from an MCP result: structured when
// Claude Code passes it on, else the first text block.
function envelopeOfMcp(result) {
  if (!result || typeof result !== 'object') return null
  if (isEnvelope(result.structuredContent)) return result.structuredContent
  const block = Array.isArray(result.content) ? result.content.find((b) => b && b.type === 'text') : null
  const parsed = block && typeof block.text === 'string' ? parseJson(block.text) : null
  return isEnvelope(parsed) ? parsed : null
}

// The same envelope from what next(e) resolves to for an MCP tool:
// `{ result, text }`, where `result` was measured to be the envelope's text.
export function envelopeOfToolResult(result) {
  if (!result || typeof result !== 'object') return null
  for (const candidate of [result.result, result.text]) {
    if (typeof candidate === 'string') {
      const parsed = parseJson(candidate)
      if (isEnvelope(parsed)) return parsed
    } else if (isEnvelope(candidate)) {
      return candidate
    } else {
      const inner = envelopeOfMcp(candidate)
      if (inner) return inner
    }
  }
  return null
}

// How the call closed, in the daemon's own words.
export function outcomeWords(result) {
  if (!result || typeof result !== 'object') return 'ended'
  if (typeof result.deny === 'string') return 'not run: refused'
  const env = envelopeOfToolResult(result)
  if (!env) return result.isError ? 'not sent: the call failed' : 'ended'
  const status = validWord(env.status) || 'unknown'
  const data = env.data && typeof env.data === 'object' ? env.data : {}
  if (status === 'secret_provided') {
    const n = Number.isSafeInteger(data.bytes_written) ? data.bytes_written : null
    return n === null ? status : status + ', ' + n + (n === 1 ? ' byte' : ' bytes') + ' written'
  }
  return 'not sent: ' + (validWord(data.reason) || status)
}

// ------------------------------------------------------- session identity

// What one of the agent's own start_session, list_sessions or status
// results says about sessions, kept in `names` as name -> id for the live
// ones. A session seen exited gives its name up, as the daemon does, since
// a later session may take it.
export function learn(names, env) {
  if (!isEnvelope(env) || env.status !== 'ok' || !env.data || typeof env.data !== 'object') return
  const records = Array.isArray(env.data.sessions) ? env.data.sessions : [env.data]
  for (const r of records) {
    if (!r || typeof r !== 'object') continue
    const id = validSessionId(r.id) || validSessionId(r.session_id)
    const name = typeof r.name === 'string' && r.name !== '' ? r.name : null
    if (!id || !name) continue
    // start_session's result has no state: the session it reports is new.
    if (r.state === undefined || r.state === 'Starting' || r.state === 'Running') {
      names.delete(name)
      names.set(name, id)
      while (names.size > KNOWN_MAX) names.delete(names.keys().next().value)
    } else if (names.get(name) === id) {
      names.delete(name)
    }
  }
}

// Who a request is for, from the agent's `session` argument: `id` when the
// argument is one or the agent's own calls paired the name with one; `name`
// to draw; and `target`, what the attach command names -- the id, else a
// name `holdfast attach` takes as it stands, else nothing.
export function identify(names, session) {
  const id = validSessionId(session)
  if (id) {
    let name = ''
    for (const [n, i] of names) if (i === id) name = n
    return { id, name: clean(name, NAME_MAX), target: id }
  }
  const asked = typeof session === 'string' ? session : ''
  const learned = names.get(asked) || null
  return { id: learned, name: clean(asked, NAME_MAX), target: learned || validTarget(asked) }
}

function label(req) {
  if (req.id) return req.name && req.name !== req.id ? req.name + ' (' + req.id + ')' : req.id
  return req.name ? 'session "' + req.name + '"' : 'a session'
}

function timeLeft(req, now) {
  const left = Math.ceil((req.startedAt + req.timeoutSecs * 1000 - now) / 1000)
  if (left <= 0) return 'time is up'
  return '~' + Math.floor(left / 60) + ':' + String(left % 60).padStart(2, '0') + ' left'
}

// ------------------------------------------------------------ the binary

// A regular file the user may run. $.fs says what kind of file it is; `test
// -x`, a builtin of every sh, says whether it runs, with the path as an
// argument no shell parses and nothing looked up on PATH. Where Claude Code
// has no $.process (the Desktop app), a regular file is taken as it stands.
async function executable($, path) {
  try {
    if ((await $.fs.stat(path)).kind !== 'file') return false
  } catch {
    return false
  }
  try {
    const run = await $.process.run(['/bin/sh', '-c', 'test -x "$1"', 'sh', path], { timeoutMs: CHECK_MS })
    return run.exitCode === 0
  } catch {
    return true
  }
}

// The `holdfast` the attach command names: HOLDFAST_BOOTSTRAP_BIN when it
// is an absolute path to an executable file, as the plugin's bootstrap
// would run it; else the first executable `holdfast` in an absolute
// directory on Claude Code's PATH; else none, and the band says so. Never
// the plugin's bootstrap: run from here, without the CLAUDE_PLUGIN_DATA of
// Claude Code's MCP start, it would download a release.
async function findBinary($) {
  const named = validPath(await $.env.get('HOLDFAST_BOOTSTRAP_BIN'))
  if (named && (await executable($, named))) return named
  const path = await $.env.get('PATH')
  const dirs = typeof path === 'string' ? path.split(':').slice(0, PATH_DIRS_MAX) : []
  for (const dir of dirs) {
    // A relative entry is relative to the session's working directory,
    // which the agent writes to.
    if (!validPath(dir)) continue
    const candidate = dir.replace(/\/+$/, '') + '/holdfast'
    if (await executable($, candidate)) return candidate
  }
  return null
}

// ------------------------------------------------------------ the request

function startTicker($) {
  if (ticker) return
  ticker = $.clock.every(1000, async () => {
    try {
      const now = await $.clock.now()
      for (const [key, req] of pending) {
        if (now > req.startedAt + req.timeoutSecs * 1000 + STALE_AFTER_MS) pending.delete(key)
      }
    } catch {
      // The countdown simply does not move this second.
    }
    if (pending.size === 0) stopTicker()
    $.ui.invalidate('ui.render')
  })
}

function stopTicker() {
  if (ticker) ticker.cancel()
  ticker = null
}

function close($, req, words) {
  pending.delete(req.key)
  if (pending.size === 0) stopTicker()
  if (words) {
    outcomes = [...outcomes.filter((o) => o.key !== req.key), { key: req.key, line: 'holdfast: ' + label(req) + ' - ' + words }]
    $.clock.after(OUTCOME_MS, () => {
      outcomes = outcomes.filter((o) => o.key !== req.key)
      $.ui.invalidate('ui.render')
    })
  }
  $.ui.invalidate('ui.render')
}

async function draws($) {
  const surfaces = await $.session.surfaces()
  return surfaces.some((s) => s === 'terminal' || s === 'desktop')
}

// Windows native runs Holdfast without a daemon, so there is no attach to
// point at and the daemon refuses the request at once.
async function onWindows($) {
  try {
    return (await $.env.get('OS')) === 'Windows_NT'
  } catch {
    return false
  }
}

// The rising edge, with the call already on its way: the band and the toast
// at once, from the call's own arguments, then the binary and tmux for the
// buttons. Resolves the request, or null where nothing draws, and never
// throws. A call that has ended before there was anything to draw
// (`call.ended`) gets its closing line and no toast.
async function open($, e, call, signal) {
  try {
    // Under -p, the Agent SDK and the VS Code chat panel nothing draws, so
    // nothing is looked at either.
    if (!(await draws($))) return null
    if (await onWindows($)) {
      $.ui.toast('holdfast: a secret request needs hybrid mode (Linux, macOS or WSL); on Windows it is refused.', { timeoutMs: TOAST_MS })
      return null
    }
    const timeout = Number(e.timeout_secs)
    const req = {
      key: String(e.tool_use_id),
      ...identify(known, e.session),
      agentSays: clean(e.prompt_text),
      timeoutSecs: Number.isSafeInteger(timeout) && timeout > 0 ? timeout : DEFAULT_TIMEOUT_SECS,
      startedAt: await $.clock.now(),
      located: false,
      binary: null,
      tmux: false,
      tmuxPane: null,
      paneEnv: {},
    }
    if (call.ended) return req
    pending.set(req.key, req)
    startTicker($)
    $.ui.invalidate('ui.render')
    if (signal) signal.addEventListener('abort', () => close($, req, ''), { once: true })
    $.ui.toast('holdfast: ' + label(req) + ' is waiting for a secret. Type it in holdfast attach, not here.', { timeoutMs: TOAST_MS })
    try {
      req.binary = await findBinary($)
      req.tmux = Boolean(await $.env.get('TMUX'))
      if (req.tmux) {
        req.tmuxPane = (await $.env.get('TMUX_PANE')) || null
        req.paneEnv = {
          HOLDFAST_RUNTIME_DIR: await $.env.get('HOLDFAST_RUNTIME_DIR'),
          XDG_RUNTIME_DIR: await $.env.get('XDG_RUNTIME_DIR'),
        }
      }
    } catch {
      // What was found stands; the rest of the band does not need it.
    }
    req.located = true
    $.ui.invalidate('ui.render')
    return req
  } catch {
    return null
  }
}

// ------------------------------------------------------------ the band

function requestBox($, e, req, now, more) {
  const { Box, Text, Button, Link } = $.ui.resolve(e)
  const roomy = e.props.maxRows >= 9
  const line = (key, text, extra = {}) => Text({ key, wrap: 'truncate-end', ...extra, children: [text] })
  const rows = [
    line('band-title', 'holdfast: ' + label(req) + ' is waiting for a secret  ' + timeLeft(req, now), { bold: true }),
    line('band-agent', 'agent says: ' + (req.agentSays ? '"' + req.agentSays + '"' : '(nothing)')),
    line('band-rule', 'Type it in holdfast attach, not here.', { bold: true }),
  ]
  const command = attachCommand(req.binary, req.target)
  if (!req.target) {
    rows.push(line('band-find', 'Find its id with `holdfast list`, then run `holdfast attach --keep-size <id>`.', { dimColor: true }))
  } else if (command) {
    const buttons = []
    // $.process exists only where Claude Code runs as the CLI, which is the
    // terminal surface; the Desktop app's Code tab has none.
    if (req.tmux && e.surface === 'terminal') {
      buttons.push(
        Button({
          key: 'band-tmux',
          label: 'open attach in tmux split (right)',
          hotkey: '1',
          plain: true,
          onPress: () => openSplit($, req),
        }),
      )
    }
    buttons.push(
      Button({
        key: 'band-copy',
        label: 'copy attach command',
        hotkey: '2',
        plain: true,
        onPress: (pe) => copyCommand($, req, pe),
      }),
    )
    rows.push(Box({ key: 'band-actions', flexDirection: 'row', columnGap: 4, children: buttons }))
  } else if (req.located) {
    rows.push(line('band-command', 'run: holdfast attach --keep-size ' + shellQuote(req.target)))
    rows.push(
      Text({
        key: 'band-no-binary',
        wrap: 'truncate-end',
        dimColor: true,
        children: [
          "holdfast is not on Claude Code's PATH, and HOLDFAST_BOOTSTRAP_BIN names none: see /holdfast:attach and ",
          Link({ href: NOT_ON_PATH_ISSUE, label: '#280' }),
        ],
      }),
    )
  }
  if (more.length) {
    rows.push(line('band-more', '+' + more.length + ' more waiting: ' + more.map(label).join(', '), { dimColor: true }))
  }
  return roomy
    ? Box({ key: 'band-request', flexDirection: 'column', borderStyle: 'round', paddingX: 1, children: rows })
    : Box({ key: 'band-request', flexDirection: 'column', children: rows })
}

// Both actions are harmless if a stray digit fires them: the split opens
// beside Claude Code without taking the focus, and the copy only fills the
// clipboard. Each rebuilds its command from a re-validated target.
async function openSplit($, req) {
  const argv = tmuxArgv(req.binary, req.target, req.tmuxPane, req.paneEnv)
  if (!argv) return
  try {
    const run = await $.process.run(argv, { timeoutMs: 5000 })
    if (run.exitCode === 0) {
      $.ui.toast('holdfast: attach is in the tmux pane to the right; switch to it to type. If it cannot attach, that pane says why.', {
        timeoutMs: TOAST_MS,
      })
    } else {
      $.ui.toast('holdfast: tmux split-window failed (exit ' + run.exitCode + '): ' + clean(run.stderr, 80), { timeoutMs: TOAST_MS })
    }
  } catch (err) {
    $.ui.toast('holdfast: could not run tmux: ' + clean(String(err && err.message ? err.message : err), 80), { timeoutMs: TOAST_MS })
  }
}

async function copyCommand($, req, pe) {
  const command = attachCommand(req.binary, req.target)
  if (!command) return
  const copied = await $.ui.copy(pe && pe.surface ? { text: command, surface: pe.surface } : { text: command })
  $.ui.toast((copied && copied.isCopied ? 'holdfast: copied ' : 'holdfast: could not copy; run ') + command, { timeoutMs: TOAST_MS })
}

// The agent's own session calls, watched as they pass: each result is
// returned untouched, and what it pairs a name with is the id the band shows
// beside that name and builds the attach command from.
async function watchSessions($, e, next) {
  const result = await next(e)
  try {
    learn(known, envelopeOfToolResult(result))
  } catch {
    // Nothing learned from this one.
  }
  return result
}

// ------------------------------------------------------------ registration

export function register(on, options) {
  // The userConfig switch: off, this module registers nothing at all.
  if (options && options.secret_band === false) return

  on('tool.call', { tool: TOOL }, async ($, e, next) => {
    // The call goes on first, exactly as the agent made it, so nothing the
    // band does ever waits in front of it.
    const going = next(e)
    const call = { ended: false }
    const opened = open($, e, call, next.signal)
    let words = ''
    try {
      const result = await going
      try {
        words = outcomeWords(result)
      } catch {
        words = 'ended'
      }
      return result
    } finally {
      call.ended = true
      opened.then((req) => {
        if (req) close($, req, words)
      })
    }
  })

  on('tool.call', { tool: START_SESSION }, watchSessions)
  on('tool.call', { tool: LIST_SESSIONS }, watchSessions)
  on('tool.call', { tool: STATUS }, watchSessions)

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.props.hasSurvey || (pending.size === 0 && outcomes.length === 0)) return next(e)
    const { Box, Text } = $.ui.resolve(e)
    const theirs = await next(e)
    const now = await $.clock.now()
    const children = []
    const [first, ...more] = pending.values()
    if (first) children.push(requestBox($, e, first, now, more))
    for (const o of outcomes.slice(-3)) {
      children.push(Text({ key: 'band-outcome-' + o.key, wrap: 'truncate-end', children: [o.line] }))
    }
    if (theirs) children.push(theirs)
    return Box({ key: 'band', flexDirection: 'column', children })
  })
}
