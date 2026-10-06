// Holdfast's Claude Code mod: the secret-request band.
//
// When the agent calls Holdfast's request_secret_input, the turn blocks until
// a human types the secret into `holdfast attach`. This module tells the human
// so: a toast, and a band above the prompt naming the session, what its
// terminal shows, what the agent says, the time left, and two buttons -- open
// `holdfast attach` in a tmux split, or copy that command.
//
// What it must never do, and does not:
//   - take a secret: there is no text field here, and nothing is written to
//     any process's standard input. The secret is typed in `holdfast attach`;
//   - answer, rewrite or approve the call: the tool.call hook awaits next(e)
//     and returns its result untouched, and there is no tool.check hook;
//   - call anything but `status` on Holdfast's server, with its default
//     redaction;
//   - put anything in front of the model: no commands, no prompt submission,
//     no store.
// Session names, prompt text and screen lines are the agent's or the
// program's text, so they are drawn only after control and bidi characters
// are stripped, labelled, and with the session id beside the name.

// Measured with this plugin loaded: the server is `plugin:holdfast:holdfast`,
// so Claude Code names the tool this.
const TOOL = 'mcp__plugin_holdfast_holdfast__request_secret_input'
// The server's key in this plugin's .mcp.json, which $.mcp.connect takes.
const SERVER_KEY = 'holdfast'
// `session/mod.rs` `new_session_id`: the only shape an attach command is
// ever built from.
const SESSION_ID = /^sess_[0-9a-f]{12}$/
const TMUX_PANE = /^%[0-9]{1,9}$/
// Status and reason words from the daemon are enums; anything else is not
// drawn as one.
const WORD = /^[a-z][a-z0-9_]{0,63}$/
// request_secret_input's own default when the call names none.
const DEFAULT_TIMEOUT_SECS = 120
const STATUS_WAIT_MS = 2000
const OUTCOME_MS = 5000
const TOAST_MS = 8000
// A request the hook never heard the end of (an abandoned turn) is dropped
// this long after its own deadline, so the band cannot stay up forever.
const STALE_AFTER_MS = 300_000
const TEXT_MAX = 160

// Open requests by tool_use_id, oldest first, and the closing lines still
// on show. Module state: a request outlives no reload of this module.
const pending = new Map()
let outcomes = []
let ticker = null

// ------------------------------------------------------------ pure helpers

// CSI, OSC and two-byte escapes; then line breaks and tabs, which become a
// space; then every remaining C0/C1 control, DEL, bidi mark, override or
// isolate, and byte order mark, which are dropped.
const ESCAPES = /\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-_]/g
const BREAKS = /[\t\n\v\f\r\u0085\u2028\u2029]/g
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]/g

export function clean(value, max = TEXT_MAX) {
  if (typeof value !== 'string') return ''
  const flat = value.replace(ESCAPES, '').replace(BREAKS, ' ').replace(UNSAFE, '').replace(/ +/g, ' ').trim()
  const chars = Array.from(flat)
  return chars.length > max ? chars.slice(0, max - 1).join('') + '\u2026' : flat
}

export function validSessionId(value) {
  return typeof value === 'string' && SESSION_ID.test(value) ? value : null
}

function validWord(value) {
  return typeof value === 'string' && WORD.test(value) ? value : null
}

// An absolute path with nothing in it that a terminal or a shell would read
// as anything but a path.
function validBinary(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.length > 4096) return null
  return value.replace(UNSAFE, '') === value ? value : null
}

export function shellQuote(value) {
  return "'" + value.replaceAll("'", "'\\''") + "'"
}

// `<binary> attach --keep-size <id>`, both quoted, or null when either is not
// what it must be. --keep-size because a half-width split must not reflow the
// agent's session.
export function attachCommand(binary, id) {
  if (!validBinary(binary) || !validSessionId(id)) return null
  return shellQuote(binary) + ' attach --keep-size ' + shellQuote(id)
}

export function tmuxArgv(command, pane) {
  const target = typeof pane === 'string' && TMUX_PANE.test(pane) ? ['-t', pane] : []
  // -d keeps the focus in Claude Code's pane, so whatever the human types
  // next still goes to the prompt and never into a waiting password read.
  return ['tmux', 'split-window', '-d', '-h', ...target, '--', command]
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
export function envelopeOfMcp(result) {
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

function errText(err) {
  return String(err && err.message ? err.message : err)
}

function label(req) {
  const name = req.name || req.asked
  if (req.id) return name && name !== req.id ? name + ' (' + req.id + ')' : req.id
  return name ? 'session "' + name + '"' : 'a session'
}

function timeLeft(req, now) {
  const left = Math.ceil((req.startedAt + req.timeoutSecs * 1000 - now) / 1000)
  if (left <= 0) return 'time is up'
  return '~' + Math.floor(left / 60) + ':' + String(left % 60).padStart(2, '0') + ' left'
}

// ------------------------------------------------------------ the request

async function readStatus($, req, session) {
  if (typeof session !== 'string' || session === '') {
    req.note = 'no session named'
    return
  }
  let env
  try {
    const link = await $.mcp.connect(SERVER_KEY)
    if (!link.isConnected) {
      req.note = 'status unavailable: ' + clean(String(link.reason || 'not connected'), 60)
      return
    }
    const answer = await withinMs($, $.mcp.call(link.server, 'status', { session }), STATUS_WAIT_MS)
    if (answer === TIMED_OUT) {
      req.note = 'status did not answer in time'
      return
    }
    env = envelopeOfMcp(answer)
  } catch (err) {
    req.note = 'status unavailable: ' + clean(errText(err), 60)
    return
  }
  if (!env || env.status !== 'ok' || !env.data || typeof env.data !== 'object') {
    req.note = 'status: ' + ((env && validWord(env.status)) || 'unreadable')
    return
  }
  const data = env.data
  req.id = validSessionId(data.id) || req.id
  req.name = clean(data.name, 48)
  req.terminalShows = clean(data.prompt && data.prompt.last_line)
  if (typeof data.profile === 'string' && data.profile !== '') {
    req.startedBy = 'profile ' + clean(data.profile, 48)
  } else {
    const argv = [data.command, ...(Array.isArray(data.args) ? data.args : [])].filter((a) => typeof a === 'string')
    req.startedBy = 'agent' + (argv.length ? ' (' + clean(argv.join(' '), 80) + ')' : '')
  }
  req.binary = validBinary(data.holdfast_binary)
  req.note = ''
}

const TIMED_OUT = Symbol('timed out')

function withinMs($, promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = $.clock.after(ms, () => resolve(TIMED_OUT))
    promise.then(
      (value) => {
        timer.cancel()
        resolve(value)
      },
      (err) => {
        timer.cancel()
        reject(err)
      },
    )
  })
}

// The binary the daemon runs, when it says; else the one the user named for
// the bootstrap; else the bootstrap itself, which finds the pinned release.
async function attachBinary($, req) {
  if (req.binary) return req.binary
  const named = validBinary(await $.env.get('HOLDFAST_BOOTSTRAP_BIN'))
  return named || $.plugin.root + '/bootstrap'
}

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
  if (!pending.delete(req.key)) return
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

// Everything the band needs before the call goes on. It never throws: a
// refused or failed call leaves that part of the band empty, and the agent's
// call goes on regardless.
async function prepare($, req, session) {
  try {
    await readStatus($, req, session)
    req.attachBinary = await attachBinary($, req)
    req.tmux = Boolean(await $.env.get('TMUX'))
    req.tmuxPane = (await $.env.get('TMUX_PANE')) || null
  } catch (err) {
    req.note = req.note || 'unavailable: ' + clean(errText(err), 60)
  }
  $.ui.toast('holdfast: ' + label(req) + ' is waiting for a secret. Type it in holdfast attach, not here.', { timeoutMs: TOAST_MS })
  $.ui.invalidate('ui.render')
}

async function draws($) {
  const surfaces = await $.session.surfaces()
  return surfaces.some((s) => s === 'terminal' || s === 'desktop')
}

// ------------------------------------------------------------ the band

function requestBox($, e, req, now, more) {
  const { Box, Text, Button } = $.ui.resolve(e)
  const roomy = e.props.maxRows >= 9
  const line = (key, text, extra = {}) => Text({ key, wrap: 'truncate-end', ...extra, children: [text] })
  const rows = [
    line('band-title', 'holdfast: ' + label(req) + ' is waiting for a secret  ' + timeLeft(req, now), { bold: true }),
    line('band-terminal', 'terminal shows: ' + (req.note ? '(' + req.note + ')' : req.terminalShows ? '"' + req.terminalShows + '"' : '(empty)')),
  ]
  if (roomy && req.startedBy) rows.push(line('band-started', 'started by:     ' + req.startedBy))
  rows.push(line('band-agent', 'agent says:     ' + (req.agentSays ? '"' + req.agentSays + '"' : '(nothing)')))
  rows.push(line('band-rule', 'Type it in holdfast attach, not here.', { bold: true }))
  const command = attachCommand(req.attachBinary, req.id)
  if (command) {
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
  } else {
    rows.push(line('band-find', 'Find its id with `holdfast list`, then run `holdfast attach --keep-size <id>`.', { dimColor: true }))
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
// clipboard. Each rebuilds its command from a re-validated id.
async function openSplit($, req) {
  const command = attachCommand(req.attachBinary, req.id)
  if (!command) return
  try {
    const run = await $.process.run(tmuxArgv(command, req.tmuxPane), { timeoutMs: 5000 })
    if (run.exitCode === 0) {
      $.ui.toast('holdfast: attach opened in the tmux pane to the right. Switch to it to type.', { timeoutMs: TOAST_MS })
    } else {
      $.ui.toast('holdfast: tmux split-window failed (exit ' + run.exitCode + '): ' + clean(run.stderr, 80), { timeoutMs: TOAST_MS })
    }
  } catch (err) {
    $.ui.toast('holdfast: could not run tmux: ' + clean(errText(err), 80), { timeoutMs: TOAST_MS })
  }
}

async function copyCommand($, req, pe) {
  const command = attachCommand(req.attachBinary, req.id)
  if (!command) return
  const copied = await $.ui.copy(pe && pe.surface ? { text: command, surface: pe.surface } : { text: command })
  $.ui.toast((copied && copied.isCopied ? 'holdfast: copied ' : 'holdfast: could not copy; run ') + command, { timeoutMs: TOAST_MS })
}

// ------------------------------------------------------------ registration

export function register(on, options) {
  // The userConfig switch: off, this module registers nothing at all.
  if (options && options.secret_band === false) return

  on('tool.call', { tool: TOOL }, async ($, e, next) => {
    // Under -p, the Agent SDK and the VS Code chat panel nothing draws, so
    // nothing is read either.
    if (!(await draws($))) return next(e)
    const key = String(e.tool_use_id)
    const timeout = Number(e.timeout_secs)
    const req = {
      key,
      asked: clean(e.session, 48),
      agentSays: clean(e.prompt_text),
      timeoutSecs: Number.isSafeInteger(timeout) && timeout > 0 ? timeout : DEFAULT_TIMEOUT_SECS,
      startedAt: await $.clock.now(),
      id: validSessionId(e.session),
      name: '',
      terminalShows: '',
      startedBy: '',
      binary: null,
      attachBinary: null,
      tmux: false,
      tmuxPane: null,
      note: 'reading status',
    }
    pending.set(key, req)
    startTicker($)
    $.ui.invalidate('ui.render')
    if (next.signal) next.signal.addEventListener('abort', () => close($, req, ''), { once: true })

    let words = ''
    try {
      // One status read, before the call goes on, so the band does not
      // depend on Claude Code running two calls to one server at once.
      await prepare($, req, e.session)
      const result = await next(e)
      try {
        words = outcomeWords(result)
      } catch {
        words = 'ended'
      }
      return result
    } finally {
      close($, req, words)
    }
  })

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
