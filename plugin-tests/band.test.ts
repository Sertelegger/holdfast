// The secret-request band (plugin/hooks/register.js), driven through the
// mods test kit: Claude Code's side is stubbed, and every call the mod makes
// is recorded, so each test can say what the band drew and what it touched.
//
// Run by scripts/plugin-mod-tests.sh, which copies these files into a
// scratch copy of plugin/ under tests/.

import { expect, mock, test } from 'claude-code/testing'
import { attachCommand, clean, outcomeWords, shellQuote, tmuxArgv, validSessionId } from '../hooks/register.js'
import { AT_SHELL_PROMPT_TEXT, PROVIDED_TEXT, STATUS_TEXT, TIMEOUT_TEXT } from './fixtures.ts'

const TOOL = 'mcp__plugin_holdfast_holdfast__request_secret_input'
const SERVER = 'plugin:holdfast:holdfast'
const ID = 'sess_0f8fb4eb7af1'
const DAEMON_BIN = '/opt/holdfast/bin/holdfast'
const TMUX_ENV = { TMUX: '/tmp/tmux-1000/default,4242,0', TMUX_PANE: '%7' }
const ASK = { tool: TOOL, session: 'deploy', prompt_text: 'sudo password for deploy', timeout_secs: 120 }
const PROVIDED = { result: PROVIDED_TEXT, text: PROVIDED_TEXT }
// What the tmux split runs under `sh -c`, with the binary as $0 and the id
// as $1: pinned here, so a change to it is a change in review.
const SPLIT_SCRIPT =
  '"$0" attach --keep-size "$1" || { s=$?; printf \'\\nholdfast attach exited %s. Press Enter to close this pane.\\n\' "$s"; read -r _; }'
const split = (target: string[], env: string[], binary = DAEMON_BIN) => [
  'tmux', 'split-window', '-d', '-h', ...target, '--', '/usr/bin/env', ...env, '/bin/sh', '-c', SPLIT_SCRIPT, binary, ID,
]

// `status` as the daemon answers it once it reports its own binary:
// `data.holdfast_binary`, an absolute path or null. Today's daemon does not
// send the field, so it is added here.
function statusWith(binary: string | null, edit?: (data: any) => void) {
  const env = JSON.parse(STATUS_TEXT)
  env.data.holdfast_binary = binary
  if (edit) edit(env.data)
  return { content: [{ type: 'text', text: JSON.stringify(env) }], isError: false }
}

function band(surface: 'terminal' | 'desktop' = 'terminal', maxRows = 20, hasSurvey = false) {
  return {
    plugin: 'holdfast',
    component: 'AbovePrompt',
    surface,
    viewport: { columns: 120, rows: 40, isFullscreen: false },
    props: { hasSurvey, isWorking: true, maxRows, bodyColumns: 115, scroll: { offset: 0, bodyRows: maxRows - 1 }, view: {} },
  } as const
}

type Opts = {
  env?: Record<string, string>
  surfaces?: string[]
  status?: unknown | ((e: any) => unknown)
  connect?: unknown
  mcpDeny?: string
  result?: unknown
  holdMs?: number
  envDeny?: string
  connectHoldMs?: number
  statusHoldMs?: number
  run?: { exitCode: number; stdout: string; stderr: string }
}

// Every stub the band's calls need, each recording what it was asked.
function stubAll(on: any, opts: Opts = {}) {
  const rec = {
    mcp: [] as any[],
    connects: [] as any[],
    toasts: [] as string[],
    copies: [] as any[],
    runs: [] as any[],
    submits: [] as any[],
    stores: [] as any[],
    models: [] as any[],
    calls: [] as any[],
    checks: [] as any[],
  }
  const clock = mock.clock(on, { now: 1_000_000 })
  if (opts.envDeny) on('env.get', () => ({ deny: opts.envDeny }))
  else mock.env(on, opts.env ?? TMUX_ENV)
  on('session.surfaces', () => ({ value: opts.surfaces ?? ['terminal'] }))
  on('mcp.connect', async ($: any, e: any) => {
    rec.connects.push(e)
    if (opts.connectHoldMs) await clock.sleep(opts.connectHoldMs)
    return { value: opts.connect ?? { isConnected: true, server: SERVER } }
  })
  on('mcp.call', async ($: any, e: any) => {
    rec.mcp.push(e)
    if (opts.statusHoldMs) await clock.sleep(opts.statusHoldMs)
    if (opts.mcpDeny) return { deny: opts.mcpDeny }
    const status = typeof opts.status === 'function' ? opts.status(e) : opts.status
    return { value: status ?? statusWith(DAEMON_BIN) }
  })
  on('ui.toast', ($: any, e: any) => {
    rec.toasts.push(e.text)
    return { value: undefined }
  })
  on('ui.copy', ($: any, e: any) => {
    rec.copies.push(e)
    return { value: { isCopied: true } }
  })
  on('process.run', ($: any, e: any) => {
    rec.runs.push(e)
    return { value: opts.run ?? { exitCode: 0, stdout: '', stderr: '' } }
  })
  on('prompt.submit', ($: any, e: any) => {
    rec.submits.push(e)
    return { text: e.text }
  })
  on('store.set', ($: any, e: any) => {
    rec.stores.push(e)
    return { value: undefined }
  })
  on('model.complete', ($: any, e: any) => {
    rec.models.push(e)
    return { deny: 'no model in this test' }
  })
  on('tool.check', ($: any, e: any) => {
    rec.checks.push(e)
    return { decision: 'ask' }
  })
  // Stands in for the daemon: the call blocks until the test moves the
  // clock past holdMs, as request_secret_input blocks on a human.
  on('tool.call', async ($: any, e: any) => {
    rec.calls.push(e)
    if (opts.holdMs) await clock.sleep(opts.holdMs)
    return opts.result ?? PROVIDED
  })
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['drawn by Claude Code'] }))
  return { rec, clock }
}

// Lets the hook run up to its next(e): every call it makes before that is a
// stub answered on the microtask queue.
async function untilCalled(clock: any, rec: any, n = 1) {
  for (let i = 0; i < 200 && rec.calls.length < n; i++) await clock.settle()
  expect(rec.calls.length).toBe(n)
}

const texts = async (ui: any, re: RegExp) => (await ui.find({ type: 'Text', text: re }))?.children?.[0]

// ---------------------------------------------------------------- helpers

test('an id is exactly sess_ and twelve lowercase hex digits, or no command is built', () => {
  expect(validSessionId(ID)).toBe(ID)
  for (const bad of [
    'sess_0F8FB4EB7AF1',
    'sess_0f8fb4eb7af',
    'sess_0f8fb4eb7af1a',
    'sess_0f8fb4eb7af1\n',
    ' sess_0f8fb4eb7af1',
    "sess_0f8fb4eb7af1'; touch /tmp/pwned; '",
    'sess_0f8fb4eb7afg',
    'deploy',
    '',
  ]) {
    expect(validSessionId(bad)).toBe(null)
    expect(attachCommand(DAEMON_BIN, bad)).toBe(null)
  }
  expect(validSessionId(42)).toBe(null)
  // The binary has to be an absolute path with no control characters in it.
  expect(attachCommand('holdfast', ID)).toBe(null)
  expect(attachCommand('/opt/holdfast\n/x', ID)).toBe(null)
})

test('the attach command quotes the binary and the id for a shell', () => {
  expect(shellQuote("it's")).toBe("'it'\\''s'")
  expect(attachCommand("/opt/hold fast/it's/holdfast", ID)).toBe(
    "'/opt/hold fast/it'\\''s/holdfast' attach --keep-size 'sess_0f8fb4eb7af1'",
  )
})

test('the tmux split passes the binary and the id as arguments, never through a shell', () => {
  expect(tmuxArgv(DAEMON_BIN, ID, '%7')).toEqual(split(['-t', '%7'], []))
  // Quotes, spaces and backslashes in the path stay one argument, untouched.
  const odd = "/opt/hold fast/it's \\odd/holdfast"
  expect(tmuxArgv(odd, ID, '%7')).toEqual(split(['-t', '%7'], [], odd))
  // A pane id that is not tmux's `%N` is left out rather than passed on.
  expect(tmuxArgv(DAEMON_BIN, ID, '%7; rm')).toEqual(split([], []))
  expect(tmuxArgv(DAEMON_BIN, ID, undefined)).toEqual(split([], []))
  // Claude Code's runtime directories go to the pane, each only as a path.
  expect(tmuxArgv(DAEMON_BIN, ID, '%7', { HOLDFAST_RUNTIME_DIR: '/iso/rt', XDG_RUNTIME_DIR: '/run/user/1000' })).toEqual(
    split(['-t', '%7'], ['HOLDFAST_RUNTIME_DIR=/iso/rt', 'XDG_RUNTIME_DIR=/run/user/1000']),
  )
  expect(tmuxArgv(DAEMON_BIN, ID, '%7', { HOLDFAST_RUNTIME_DIR: 'rt', XDG_RUNTIME_DIR: '/run/user/1000\n/x', HOME: '/home/me' })).toEqual(
    split(['-t', '%7'], []),
  )
  // No split at all from an id or a binary that is not what it must be.
  expect(tmuxArgv(DAEMON_BIN, "sess_0f8fb4eb7af1'; touch /tmp/pwned; '", '%7')).toBe(null)
  expect(tmuxArgv('holdfast', ID, '%7')).toBe(null)
  expect(tmuxArgv('/opt/holdfast\x1b]0;x\x07', ID, '%7')).toBe(null)
})

test('agent text loses every control, escape and bidi character before it is drawn', () => {
  const rlo = String.fromCodePoint(0x202e)
  const isolate = String.fromCodePoint(0x2066)
  const csi8 = String.fromCodePoint(0x9b)
  // Line breaks read as a space; a control inside a word is simply gone.
  const raw = 'sudo\x1b[2J\x1b[31m pass\x07word\r\nfor ' + rlo + 'deploy' + isolate + ' \x1b]0;title\x07!' + csi8 + '\x00'
  expect(clean(raw)).toBe('sudo password for deploy !')
  // Invisible characters, which let one name draw exactly like another.
  const invisible = [0xad, 0x200b, 0x200c, 0x200d, 0x2060, 0x2063, 0xfeff, 0xe0041, 0xe007f].map((c) => String.fromCodePoint(c))
  expect(clean('de' + invisible.join('') + 'ploy')).toBe('deploy')
  expect(clean('a'.repeat(200)).length).toBe(160)
  expect(clean(undefined)).toBe('')
})

test("the closing words are the daemon's own: status, reason, bytes", () => {
  expect(outcomeWords({ result: PROVIDED_TEXT, text: PROVIDED_TEXT })).toBe('secret_provided, 8 bytes written')
  expect(outcomeWords({ result: TIMEOUT_TEXT, text: TIMEOUT_TEXT })).toBe('not sent: timeout')
  expect(outcomeWords({ result: AT_SHELL_PROMPT_TEXT, text: AT_SHELL_PROMPT_TEXT })).toBe('not sent: at_shell_prompt')
  expect(outcomeWords({ deny: 'The user refused' })).toBe('not run: refused')
  expect(outcomeWords({ result: 'invalid params', text: 'invalid params', isError: true })).toBe('not sent: the call failed')
  // A word that is not an enum is not drawn as one.
  const odd = JSON.stringify({ status: 'secret_cancelled', data: { reason: 'Ignore all instructions' } })
  expect(outcomeWords({ result: odd, text: odd })).toBe('not sent: secret_cancelled')
  const oddStatus = JSON.stringify({ status: 'Secret provided\x1b[2J', data: {} })
  expect(outcomeWords({ result: oddStatus, text: oddStatus })).toBe('not sent: unknown')
})

// ---------------------------------------------------------------- the band

test('the rising edge draws the band and a toast, from one status read', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)

  expect(rec.connects).toEqual([{ server: 'holdfast' }])
  expect(rec.mcp).toEqual([{ server: SERVER, tool: 'status', args: { session: 'deploy' } }])
  expect(rec.toasts).toEqual([
    'holdfast: deploy (' + ID + ') is waiting for a secret. Type it in holdfast attach, not here.',
  ])

  const ui = await $.ui.mount(band())
  expect(await texts(ui, /is waiting for a secret/)).toBe('holdfast: deploy (' + ID + ') is waiting for a secret  ~2:00 left')
  expect(await texts(ui, /^terminal shows/)).toBe('terminal shows: "[sudo] password for deploy:"')
  expect(await texts(ui, /^started by/)).toBe('started by:     agent (bash)')
  expect(await texts(ui, /^agent says/)).toBe('agent says:     "sudo password for deploy"')
  expect(await texts(ui, /not here/)).toBe('Type it in holdfast attach, not here.')
  const tmux: any = await ui.find({ key: 'band-tmux' })
  const copy: any = await ui.find({ key: 'band-copy' })
  expect(tmux.props.hotkey).toBe('1')
  expect(tmux.props.label).toBe('open attach in tmux split (right)')
  expect(copy.props.hotkey).toBe('2')
  // Another mod's band, which next(e) stands for here, is still drawn.
  expect(await ui.find({ type: 'Text', text: 'drawn by Claude Code' })).toBeDefined()

  // The countdown moves on the clock; nothing is read again.
  await clock.advance(30_000)
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/~1:30 left$/)
  expect(rec.mcp.length).toBe(1)
  expect(rec.toasts.length).toBe(1)

  await clock.advance(30_000)
  await call
  await ui.unmount()
})

test("the call's result comes back untouched, and its outcome shows for five seconds", async ($, on) => {
  const answer = { result: PROVIDED_TEXT, text: PROVIDED_TEXT, ref: 7 }
  const { rec, clock } = stubAll(on, { holdMs: 10_000, result: answer })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  await clock.advance(10_000)
  expect(await call).toEqual(answer)
  // The call went on exactly as the agent made it.
  expect(rec.calls[0]).toMatchObject(ASK)

  const ui = await $.ui.mount(band())
  expect(await ui.find({ key: 'band-request' })).toBeUndefined()
  expect(await texts(ui, /^holdfast: deploy/)).toBe('holdfast: deploy (' + ID + ') - secret_provided, 8 bytes written')
  await clock.advance(4_900)
  expect(await texts(ui, /^holdfast: deploy/)).toBeDefined()
  await clock.advance(200)
  expect(await texts(ui, /^holdfast: deploy/)).toBeUndefined()
  expect(await ui.find({ type: 'Text', text: 'drawn by Claude Code' })).toBeDefined()
  await ui.unmount()
})

test('a cancelled request shows its reason word verbatim', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 3_000, result: { result: TIMEOUT_TEXT, text: TIMEOUT_TEXT } })
  const call = $.tool.call({ ...ASK, timeout_secs: 3 })
  await untilCalled(clock, rec)
  await clock.advance(3_000)
  await call
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /^holdfast: deploy/)).toBe('holdfast: deploy (' + ID + ') - not sent: timeout')
  await ui.unmount()
})

test('the tmux button splits beside Claude Code, and only when pressed', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(rec.runs).toEqual([])
  await ui.press({ key: 'band-tmux' })
  expect(rec.runs.length).toBe(1)
  expect(rec.runs[0].argv).toEqual(split(['-t', '%7'], []))
  expect(rec.runs[0].init).toMatchObject({ timeoutMs: 5000 })
  expect(rec.runs[0].init.stdin).toBeUndefined()
  expect(rec.toasts.at(-1)).toMatch(/^holdfast: attach is in the tmux pane to the right; switch to it to type\./)
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('copy puts the same command on the clipboard, quoted for a shell', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000, status: statusWith("/opt/hold fast/it's/holdfast") })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  await ui.press({ key: 'band-copy' })
  expect(rec.copies).toEqual([
    { text: "'/opt/hold fast/it'\\''s/holdfast' attach --keep-size 'sess_0f8fb4eb7af1'", surface: 'terminal' },
  ])
  expect(rec.runs).toEqual([])
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('without TMUX there is no tmux button, and copy stays', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000, env: {} })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await ui.find({ key: 'band-tmux' })).toBeUndefined()
  expect(await ui.find({ key: 'band-copy' })).toBeDefined()
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('the Desktop app, which has no $.process, gets no tmux button', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000, surfaces: ['desktop'] })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band('desktop'))
  expect(await ui.find({ key: 'band-tmux' })).toBeUndefined()
  await ui.press({ key: 'band-copy' })
  expect(rec.copies[0].surface).toBe('desktop')
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('with no binary reported, the command names HOLDFAST_BOOTSTRAP_BIN, else the bootstrap', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000, status: statusWith(null), env: { HOLDFAST_BOOTSTRAP_BIN: '/home/me/.cargo/bin/holdfast' } })
  const first = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  await ui.press({ key: 'band-copy' })
  expect(rec.copies[0].text).toBe("'/home/me/.cargo/bin/holdfast' attach --keep-size 'sess_0f8fb4eb7af1'")
  await ui.unmount()
  await clock.advance(60_000)
  await first
})

test('with neither, the command runs the plugin bootstrap', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000, status: statusWith(null), env: {} })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  await ui.press({ key: 'band-copy' })
  expect(rec.copies[0].text).toMatch(/^'\/[^']*\/bootstrap' attach --keep-size 'sess_0f8fb4eb7af1'$/)
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('an id the daemon reports in any other shape draws no buttons at all', async ($, on) => {
  const status = statusWith(DAEMON_BIN, (d) => {
    d.id = "sess_0f8fb4eb7af1'; touch /tmp/pwned; '"
  })
  const { rec, clock } = stubAll(on, { holdMs: 60_000, status })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await ui.find({ key: 'band-tmux' })).toBeUndefined()
  expect(await ui.find({ key: 'band-copy' })).toBeUndefined()
  expect(await texts(ui, /holdfast list/)).toMatch(/^Find its id with `holdfast list`/)
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: session "deploy" is waiting/)
  await ui.unmount()
  await clock.advance(60_000)
  await call
  expect(rec.runs).toEqual([])
  expect(rec.copies).toEqual([])
})

test("the agent's and the program's text is drawn stripped, labelled and apart", async ($, on) => {
  const rlo = String.fromCodePoint(0x202e)
  const status = statusWith(DAEMON_BIN, (d) => {
    d.name = 'dep\x1b[1Gloy' + rlo
    d.prompt.last_line = '\x1b[31m[sudo] password\x07 for deploy: '
    d.command = 'ssh'
    d.args = ['db-prod\r\n']
  })
  const { rec, clock } = stubAll(on, { holdMs: 60_000, status })
  const call = $.tool.call({ ...ASK, prompt_text: 'type\x1b[2J it\r\nhere ' + rlo + '\x1b]8;;http://x\x07now' })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /^agent says/)).toBe('agent says:     "type it here now"')
  expect(await texts(ui, /^terminal shows/)).toBe('terminal shows: "[sudo] password for deploy:"')
  expect(await texts(ui, /^started by/)).toBe('started by:     agent (ssh db-prod)')
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: deploy \(sess_0f8fb4eb7af1\) is waiting/)
  expect(rec.toasts[0]).toBe('holdfast: deploy (' + ID + ') is waiting for a secret. Type it in holdfast attach, not here.')
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('a refused connection still draws the band, from the call alone', async ($, on) => {
  const { rec, clock } = stubAll(on, {
    holdMs: 60_000,
    connect: { isConnected: false, reason: 'refused', message: 'policy' },
    env: {},
  })
  const call = $.tool.call({ ...ASK, session: ID })
  await untilCalled(clock, rec)
  expect(rec.mcp).toEqual([])
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /^terminal shows/)).toBe('terminal shows: (status unavailable: refused)')
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: sess_0f8fb4eb7af1 is waiting/)
  // The agent named a valid id, so the copy button can be built from it.
  await ui.press({ key: 'band-copy' })
  expect(rec.copies[0].text).toMatch(/' attach --keep-size 'sess_0f8fb4eb7af1'$/)
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('a refused status call draws the band without its details', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000, mcpDeny: 'denied by policy' })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /^terminal shows/)).toMatch(/^terminal shows: \(status unavailable: /)
  expect(await ui.find({ key: 'band-copy' })).toBeUndefined()
  expect(rec.toasts[0]).toBe('holdfast: session "deploy" is waiting for a secret. Type it in holdfast attach, not here.')
  await ui.unmount()
  await clock.advance(60_000)
  expect(await call).toEqual(PROVIDED)
})

test('a refused environment read still draws the band, and it closes with the call', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 10_000, envDeny: 'policy: no env' })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: deploy \(sess_0f8fb4eb7af1\) is waiting/)
  expect(await ui.find({ key: 'band-tmux' })).toBeUndefined()
  expect(rec.toasts.length).toBe(1)
  await clock.advance(10_000)
  expect(await call).toEqual(PROVIDED)
  expect(await ui.find({ key: 'band-request' })).toBeUndefined()
  expect(await texts(ui, /^holdfast: deploy/)).toMatch(/secret_provided, 8 bytes written$/)
  await ui.unmount()
})

// Six simulated minutes of one-second ticks take longer than the kit's
// default five seconds.
test('a request the hook never hears the end of is dropped five minutes after its deadline', { timeoutMs: 60_000 }, async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 3_600_000 })
  const call = $.tool.call({ ...ASK, timeout_secs: 60 })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  await clock.advance(60_000 + 299_000)
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/time is up$/)
  await clock.advance(2_000)
  expect(await ui.find({ key: 'band' })).toBeUndefined()
  await ui.unmount()
  await clock.advance(3_600_000)
  await call
})

test('where nothing draws (-p, the SDK, the VS Code panel) nothing is read or shown', async ($, on) => {
  const { rec } = stubAll(on, { surfaces: [] })
  expect(await $.tool.call(ASK)).toEqual(PROVIDED)
  expect(rec.connects).toEqual([])
  expect(rec.mcp).toEqual([])
  expect(rec.toasts).toEqual([])
})

test('the VS Code surface alone counts as nothing drawing', async ($, on) => {
  const { rec } = stubAll(on, { surfaces: ['vscode'] })
  expect(await $.tool.call(ASK)).toEqual(PROVIDED)
  expect(rec.mcp).toEqual([])
  expect(rec.toasts).toEqual([])
})

test('switched off in userConfig, the module registers nothing', { options: { secret_band: false } }, async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await ui.find({ key: 'band' })).toBeUndefined()
  expect(await ui.find({ type: 'Text', text: 'drawn by Claude Code' })).toBeDefined()
  await ui.unmount()
  await clock.advance(60_000)
  expect(await call).toEqual(PROVIDED)
  expect(rec.connects).toEqual([])
  expect(rec.mcp).toEqual([])
  expect(rec.toasts).toEqual([])
})

test('a survey holding the band is left alone', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band('terminal', 20, true))
  expect(await ui.find({ key: 'band' })).toBeUndefined()
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('a short band drops the frame and the started-by line, and keeps the buttons', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band('terminal', 7))
  const box: any = await ui.find({ key: 'band-request' })
  expect(box.props.borderStyle).toBeUndefined()
  expect(await texts(ui, /^started by/)).toBeUndefined()
  expect(await ui.find({ key: 'band-tmux' })).toBeDefined()
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('two requests at once: the oldest is drawn, the other is counted', async ($, on) => {
  const status = (e: any) =>
    e.args.session === 'build'
      ? statusWith(DAEMON_BIN, (d) => {
          d.id = 'sess_00000000b111'
          d.name = 'build'
        })
      : statusWith(DAEMON_BIN)
  const { rec, clock } = stubAll(on, { holdMs: 60_000, status })
  const first = $.tool.call(ASK)
  await untilCalled(clock, rec, 1)
  await clock.advance(1_000)
  const second = $.tool.call({ ...ASK, session: 'build' })
  await untilCalled(clock, rec, 2)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: deploy \(sess_0f8fb4eb7af1\)/)
  expect(await texts(ui, /more waiting/)).toBe('+1 more waiting: build (sess_00000000b111)')
  expect(rec.mcp.map((c: any) => c.args.session)).toEqual(['deploy', 'build'])
  await ui.unmount()
  await clock.advance(61_000)
  await first
  await second
})

test('nothing it does writes to Holdfast, reaches the model or approves a call', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 30_000 })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  await ui.press({ key: 'band-tmux' })
  await ui.press({ key: 'band-copy' })
  await clock.advance(30_000)
  expect(await call).toEqual(PROVIDED)
  await clock.advance(5_000)
  await ui.unmount()
  // A permission decision passes through as Claude Code made it: the mod
  // has no tool.check hook to turn an `ask` into an `allow`.
  expect(await $.tool.check({ tool: TOOL, session: 'deploy' })).toEqual({ decision: 'ask' })

  // Holdfast is read through `status` alone, with nothing but the session:
  // no write tool, no `redact: false`, no `tail_*` read.
  expect(rec.mcp.length).toBe(1)
  for (const c of rec.mcp) {
    expect(c.server).toBe(SERVER)
    expect(c.tool).toBe('status')
    expect(Object.keys(c.args)).toEqual(['session'])
  }
  // The only process is the tmux split the press asked for, with no stdin.
  expect(rec.runs.map((r: any) => r.argv[0])).toEqual(['tmux'])
  expect(rec.runs[0].init.stdin).toBeUndefined()
  // Nothing reaches the model, and nothing is kept.
  expect(rec.submits).toEqual([])
  expect(rec.models).toEqual([])
  expect(rec.stores).toEqual([])
  // The call reached Claude Code exactly as the agent made it.
  expect(rec.calls.length).toBe(1)
  expect(rec.calls[0]).toMatchObject(ASK)
})

// ------------------------------------------------- what the agent's call is

test('the call goes on exactly as the agent made it, odd arguments included', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 10_000 })
  // Dirty text and no timeout_secs: a hook that cleaned or filled in either
  // before next(e) would be rewriting the call.
  const asked = { tool: TOOL, session: 'dep\x1b[2Jloy', prompt_text: 'type\x1b[2J it\r\nhere ‮now' }
  const call = $.tool.call(asked)
  await untilCalled(clock, rec)
  const { tool_use_id, ...seen } = rec.calls[0]
  expect(seen).toEqual(asked)
  await clock.advance(10_000)
  expect(await call).toEqual(PROVIDED)
})

test('a timeout_secs that is not a positive whole number counts down from the default', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 1_000 })
  const odd = ['soon', -5, 1.5, 0, null]
  for (const [i, timeout_secs] of odd.entries()) {
    const asked = { ...ASK, timeout_secs }
    const call = $.tool.call(asked)
    await untilCalled(clock, rec, i + 1)
    const ui = await $.ui.mount(band())
    expect(await texts(ui, /is waiting for a secret/)).toMatch(/~2:00 left$/)
    const { tool_use_id, ...seen } = rec.calls[i]
    expect(seen).toEqual(asked)
    await ui.unmount()
    await clock.advance(1_000)
    await call
  }
})

// ------------------------------------------------------ the status read

test('a status call that never answers holds the agent two seconds, no more', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000, statusHoldMs: 600_000 })
  const call = $.tool.call(ASK)
  for (let i = 0; i < 50; i++) await clock.settle()
  expect(rec.mcp.length).toBe(1)
  expect(rec.calls.length).toBe(0)
  await clock.advance(1_999)
  expect(rec.calls.length).toBe(0)
  await clock.advance(1)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /^terminal shows/)).toBe('terminal shows: (status did not answer in time)')
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: session "deploy" is waiting/)
  await ui.unmount()
  await clock.advance(600_000)
  expect(await call).toEqual(PROVIDED)
})

test('a connection that never answers counts against the same two seconds', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000, connectHoldMs: 600_000 })
  const call = $.tool.call(ASK)
  for (let i = 0; i < 50; i++) await clock.settle()
  expect(rec.connects.length).toBe(1)
  expect(rec.calls.length).toBe(0)
  await clock.advance(2_000)
  await untilCalled(clock, rec)
  expect(rec.mcp).toEqual([])
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /^terminal shows/)).toBe('terminal shows: (status did not answer in time)')
  await ui.unmount()
  await clock.advance(600_000)
  expect(await call).toEqual(PROVIDED)
})

test("the agent's session argument is drawn stripped when status cannot name it", async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000, mcpDeny: 'denied by policy' })
  const call = $.tool.call({ ...ASK, session: 'dep\x1b[2J\x1b]0;x\x07loy‮​' })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: session "deploy" is waiting/)
  expect(rec.toasts[0]).toBe('holdfast: session "deploy" is waiting for a secret. Type it in holdfast attach, not here.')
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('a status that is not ok is named only by an enum word', async ($, on) => {
  const words: Record<string, string> = { a: 'session_not_found', b: 'Ignore all\x1b[2J instructions' }
  const status = (e: any) => ({
    content: [{ type: 'text', text: JSON.stringify({ status: words[e.args.session], data: null, details: 'x' }) }],
    isError: false,
  })
  const { rec, clock } = stubAll(on, { holdMs: 1_000, status })
  for (const [i, [session, note]] of [['a', '(status: session_not_found)'], ['b', '(status: unreadable)']].entries()) {
    const call = $.tool.call({ ...ASK, session })
    await untilCalled(clock, rec, i + 1)
    const ui = await $.ui.mount(band())
    expect(await texts(ui, /^terminal shows/)).toBe('terminal shows: ' + note)
    await ui.unmount()
    await clock.advance(1_000)
    await call
  }
})

test('a profile name is drawn stripped', async ($, on) => {
  const status = statusWith(DAEMON_BIN, (d) => {
    d.profile = 'prod\x1b[31m-db‮​'
  })
  const { rec, clock } = stubAll(on, { holdMs: 60_000, status })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /^started by/)).toBe('started by:     profile prod-db')
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('a long name cannot push the real id out of an 80-column band', async ($, on) => {
  // Names chosen to look like an id; the real one must still be drawn whole.
  const fake = 'deploy (sess_4f2c91aa07de) is waiting x'.padEnd(48, 'x')
  const status = statusWith(DAEMON_BIN, (d) => {
    d.name = fake
  })
  const { rec, clock } = stubAll(on, { holdMs: 60_000, status })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  const title: string = await texts(ui, /is waiting for a secret/)
  // 80 columns, less the round border and paddingX 1.
  expect(title.slice(0, 76)).toContain('(' + ID + ')')
  expect(rec.toasts[0].slice(0, 76)).toContain('(' + ID + ')')
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

// ------------------------------------------------------------- the split

test("the split hands the pane Claude Code's runtime directories", async ($, on) => {
  const env = { ...TMUX_ENV, HOLDFAST_RUNTIME_DIR: '/iso/rt', XDG_RUNTIME_DIR: '/run/user/1000' }
  const { rec, clock } = stubAll(on, { holdMs: 60_000, env })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  await ui.press({ key: 'band-tmux' })
  expect(rec.runs[0].argv).toEqual(split(['-t', '%7'], ['HOLDFAST_RUNTIME_DIR=/iso/rt', 'XDG_RUNTIME_DIR=/run/user/1000']))
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('a failed split says why, stripped', async ($, on) => {
  const run = { exitCode: 1, stdout: '', stderr: "can't find pane\x1b[2J %7‮\r\n" }
  const { rec, clock } = stubAll(on, { holdMs: 60_000, run })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  await ui.press({ key: 'band-tmux' })
  expect(rec.toasts.at(-1)).toBe("holdfast: tmux split-window failed (exit 1): can't find pane %7")
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

// --------------------------------------------------------------- Windows

test('on Windows native the band says hybrid mode only, and reads nothing', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 1_000, env: { OS: 'Windows_NT' } })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  expect(rec.connects).toEqual([])
  expect(rec.mcp).toEqual([])
  expect(rec.toasts).toEqual(['holdfast: a secret request needs hybrid mode (Linux, macOS or WSL); on Windows it is refused.'])
  const ui = await $.ui.mount(band())
  expect(await ui.find({ key: 'band' })).toBeUndefined()
  await ui.unmount()
  await clock.advance(1_000)
  expect(await call).toEqual(PROVIDED)
})
