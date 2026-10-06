// The secret-request band (plugin/hooks/register.js), driven through the
// mods test kit: Claude Code's side is stubbed, and every call the mod makes
// is recorded, so each test can say what the band drew and what it touched.
//
// Run by scripts/plugin-mod-tests.sh, which copies these files into a
// scratch copy of plugin/ under tests/.

import { expect, mock, test } from 'claude-code/testing'
import {
  attachCommand,
  clean,
  drawnName,
  identify,
  learn,
  outcomeWords,
  shellQuote,
  timeLeft,
  tmuxArgv,
  validSessionId,
  validTarget,
} from '../hooks/register.js'
import { AT_SHELL_PROMPT_TEXT, LIST_TEXT, PROVIDED_TEXT, START_TEXT, STATUS_TEXT, TIMEOUT_TEXT } from './fixtures.ts'

const TOOL = 'mcp__plugin_holdfast_holdfast__request_secret_input'
const START = 'mcp__plugin_holdfast_holdfast__start_session'
const LIST = 'mcp__plugin_holdfast_holdfast__list_sessions'
const STATUS = 'mcp__plugin_holdfast_holdfast__status'
const SERVER = 'plugin:holdfast:holdfast'
// The ids the fixtures report: `deploy` as start_session and list_sessions
// saw it, `old` exited in that list, and `deploy` as status saw it.
const ID = 'sess_8e2dc40db93c'
const OLD_ID = 'sess_c5a2c8e3dd58'
const STATUS_ID = 'sess_0f8fb4eb7af1'
const PATH_BIN = '/opt/holdfast/bin/holdfast'
const TMUX_ENV = { TMUX: '/tmp/tmux-1000/default,4242,0', TMUX_PANE: '%7' }
const ENV = { ...TMUX_ENV, PATH: '/usr/local/bin:/opt/holdfast/bin:/usr/bin' }
// What $.fs.stat and `test -x` find: `exec` is a file that runs.
const FILES: Record<string, 'exec' | 'file' | 'dir'> = { [PATH_BIN]: 'exec' }
const ASK = { tool: TOOL, session: 'deploy', prompt_text: 'sudo password for deploy', timeout_secs: 120 }
const START_DEPLOY = { tool: START, command: 'bash', name: 'deploy' }
const as = (text: string) => ({ result: text, text })
const PROVIDED = as(PROVIDED_TEXT)
const RLO = String.fromCodePoint(0x202e)
const ZWSP = String.fromCodePoint(0x200b)
// What the tmux split runs under `sh -c`, with the binary as $0 and the
// target as $1: pinned here, so a change to it is a change in review.
const SPLIT_SCRIPT =
  '"$0" attach --keep-size "$1" || { s=$?; [ "$s" = 64 ] && printf \'\\nThis holdfast predates attach --keep-size: update it, or run attach without the flag, which resizes the session to this pane.\\n\'; ' +
  'printf \'\\nholdfast attach exited %s. Press Enter to close this pane.\\n\' "$s"; read -r _; }'
const split = (target: string[], env: string[], binary = PATH_BIN, to = ID) => [
  'tmux', 'split-window', '-d', '-h', ...target, '--', '/usr/bin/env', ...env, '/bin/sh', '-c', SPLIT_SCRIPT, binary, to,
]
// The executable check, as the mod must run it: no PATH lookup, the path an
// argument no shell parses.
const isCheck = (argv: string[]) => argv[0] === '/bin/sh' && argv[2] === 'test -x "$1"'

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
  files?: Record<string, 'exec' | 'file' | 'dir'>
  surfaces?: string[]
  result?: unknown
  answers?: Record<string, unknown>
  approveMs?: number
  holdMs?: number
  surfacesHoldMs?: number
  envDeny?: string
  noProcess?: boolean
  run?: { exitCode: number; stdout: string; stderr: string }
}

// Every stub the band's calls need, each recording what it was asked.
function stubAll(on: any, opts: Opts = {}) {
  const rec = {
    mcp: [] as any[],
    connects: [] as any[],
    env: [] as string[],
    stats: [] as string[],
    checks: [] as any[],
    toasts: [] as string[],
    copies: [] as any[],
    runs: [] as any[],
    submits: [] as any[],
    stores: [] as any[],
    models: [] as any[],
    calls: [] as any[],
    decisions: [] as any[],
  }
  const env = opts.env ?? ENV
  const files = opts.files ?? FILES
  const answers: Record<string, unknown> = { [START]: as(START_TEXT), [LIST]: as(LIST_TEXT), [STATUS]: as(STATUS_TEXT), ...opts.answers }
  const clock = mock.clock(on, { now: 1_000_000 })
  on('env.get', ($: any, e: any) => {
    rec.env.push(e.name)
    return opts.envDeny ? { deny: opts.envDeny } : { value: env[e.name] }
  })
  on('fs.stat', ($: any, e: any) => {
    rec.stats.push(e.path)
    const kind = files[e.path]
    if (!kind) return { deny: 'ENOENT: no such file or directory' }
    return { value: { kind: kind === 'dir' ? 'dir' : 'file', size: 1, mtimeMs: 0, isLink: false } }
  })
  on('session.surfaces', async () => {
    if (opts.surfacesHoldMs) await clock.sleep(opts.surfacesHoldMs)
    return { value: opts.surfaces ?? ['terminal'] }
  })
  // The band calls neither of these; they answer, and record, so a call
  // that crept back in is seen rather than skipped.
  on('mcp.connect', ($: any, e: any) => {
    rec.connects.push(e)
    return { value: { isConnected: true, server: SERVER } }
  })
  on('mcp.call', ($: any, e: any) => {
    rec.mcp.push(e)
    return { value: { content: [{ type: 'text', text: STATUS_TEXT }], isError: false } }
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
    if (opts.noProcess) return { deny: 'no $.process on this surface' }
    if (isCheck(e.argv)) {
      rec.checks.push(e)
      return { value: { exitCode: files[e.argv[4]] === 'exec' ? 0 : 1, stdout: '', stderr: '' } }
    }
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
    rec.decisions.push(e)
    return { decision: 'ask' }
  })
  // Stands in for Claude Code's permission dialog, up for approveMs, and
  // then the daemon: the secret request blocks until the test moves the
  // clock past holdMs, as request_secret_input blocks on a human.
  on('tool.call', async ($: any, e: any) => {
    rec.calls.push(e)
    if (e.tool !== TOOL) return answers[e.tool] ?? as('{}')
    if (opts.approveMs) await clock.sleep(opts.approveMs)
    if (opts.holdMs) await clock.sleep(opts.holdMs)
    return opts.result ?? PROVIDED
  })
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['drawn by Claude Code'] }))
  return { rec, clock }
}

async function settle(clock: any, n = 60) {
  for (let i = 0; i < n; i++) await clock.settle()
}

// Lets the hook pass the agent's call on, and the band finish drawing.
async function untilCalled(clock: any, rec: any, n = 1) {
  const asked = () => rec.calls.filter((c: any) => c.tool === TOOL).length
  for (let i = 0; i < 200 && asked() < n; i++) await clock.settle()
  expect(asked()).toBe(n)
  await settle(clock)
}

const texts = async (ui: any, re: RegExp) => (await ui.find({ type: 'Text', text: re }))?.children?.[0]

// ---------------------------------------------------------------- helpers

test('an attach target is an id, or a name attach takes as it stands; nothing else builds a command', () => {
  expect(validSessionId(ID)).toBe(ID)
  for (const bad of ['sess_0F8FB4EB7AF1', 'sess_0f8fb4eb7af', 'sess_0f8fb4eb7af1a', 'sess_0f8fb4eb7af1\n', 'sess_0f8fb4eb7afg', 'deploy', '']) {
    expect(validSessionId(bad)).toBe(null)
  }
  expect(validSessionId(42)).toBe(null)
  for (const good of [ID, 'deploy', 'db-prod.2', 'A_b', '9lives', 'x'.repeat(64)]) {
    expect(validTarget(good)).toBe(good)
    expect(attachCommand(PATH_BIN, good)).toBe("'" + PATH_BIN + "' attach --keep-size '" + good + "'")
  }
  // A flag, a space, a quote, a separator, a non-ASCII letter, a leading
  // dot, too long: none of these is handed to attach.
  for (const bad of ['-x', '--keep-size', 'dep loy', "dep'loy", 'deploy;rm', 'a/b', 'd\u00e9ploy', '.hidden', 'x'.repeat(65), '', 7]) {
    expect(validTarget(bad)).toBe(null)
    expect(attachCommand(PATH_BIN, bad)).toBe(null)
  }
  // The binary has to be an absolute path with no control characters in it.
  expect(attachCommand('holdfast', ID)).toBe(null)
  expect(attachCommand('/opt/holdfast\n/x', ID)).toBe(null)
})

test('the attach command quotes the binary and the target for a shell', () => {
  expect(shellQuote("it's")).toBe("'it'\\''s'")
  expect(attachCommand("/opt/hold fast/it's/holdfast", ID)).toBe("'/opt/hold fast/it'\\''s/holdfast' attach --keep-size '" + ID + "'")
})

test('the tmux split passes the binary and the target as arguments, never through a shell', () => {
  expect(tmuxArgv(PATH_BIN, ID, '%7')).toEqual(split(['-t', '%7'], []))
  expect(tmuxArgv(PATH_BIN, 'deploy', '%7')).toEqual(split(['-t', '%7'], [], PATH_BIN, 'deploy'))
  // Quotes, spaces and backslashes in the path stay one argument, untouched.
  const odd = "/opt/hold fast/it's \\odd/holdfast"
  expect(tmuxArgv(odd, ID, '%7')).toEqual(split(['-t', '%7'], [], odd))
  // A pane id that is not tmux's `%N` is left out rather than passed on.
  expect(tmuxArgv(PATH_BIN, ID, '%7; rm')).toEqual(split([], []))
  expect(tmuxArgv(PATH_BIN, ID, undefined)).toEqual(split([], []))
  // Claude Code's runtime directories go to the pane, each only as a path.
  expect(tmuxArgv(PATH_BIN, ID, '%7', { HOLDFAST_RUNTIME_DIR: '/iso/rt', XDG_RUNTIME_DIR: '/run/user/1000' })).toEqual(
    split(['-t', '%7'], ['HOLDFAST_RUNTIME_DIR=/iso/rt', 'XDG_RUNTIME_DIR=/run/user/1000']),
  )
  expect(tmuxArgv(PATH_BIN, ID, '%7', { HOLDFAST_RUNTIME_DIR: 'rt', XDG_RUNTIME_DIR: '/run/user/1000\n/x', HOME: '/home/me' })).toEqual(
    split(['-t', '%7'], []),
  )
  // No split at all from a target or a binary that is not what it must be.
  expect(tmuxArgv(PATH_BIN, "sess_0f8fb4eb7af1'; touch /tmp/pwned; '", '%7')).toBe(null)
  expect(tmuxArgv(PATH_BIN, '-x', '%7')).toBe(null)
  expect(tmuxArgv('holdfast', ID, '%7')).toBe(null)
  expect(tmuxArgv('/opt/holdfast\x1b]0;x\x07', ID, '%7')).toBe(null)
})

test('agent text loses every control, escape and bidi character before it is drawn', () => {
  const isolate = String.fromCodePoint(0x2066)
  const csi8 = String.fromCodePoint(0x9b)
  // Line breaks read as a space; a control inside a word is simply gone.
  const raw = 'sudo\x1b[2J\x1b[31m pass\x07word\r\nfor ' + RLO + 'deploy' + isolate + ' \x1b]0;title\x07!' + csi8 + '\x00'
  expect(clean(raw)).toBe('sudo password for deploy !')
  // Invisible characters, which let one name draw exactly like another.
  const invisible = [0xad, 0x200b, 0x200c, 0x200d, 0x2060, 0x2063, 0xfeff, 0xe0041, 0xe007f].map((c) => String.fromCodePoint(c))
  expect(clean('de' + invisible.join('') + 'ploy')).toBe('deploy')
  expect(clean('a'.repeat(200)).length).toBe(160)
  expect(clean(undefined)).toBe('')
})

test('a name is drawn with nothing in it that reads as an id', () => {
  const CYRILLIC_A = String.fromCodePoint(0x430)
  for (const [name, drawn] of [
    ['use sess_aaaaaaaaaaaa', 'use sess_\u2026'],
    ['x-sess_0f8fb4eb7af1-y', 'x-sess_\u2026'],
    ['SESS_AAAAAAAAAAAA now', 'sess_\u2026 now'],
    ['(sess_aaaaaaaaaaaa)', '(sess_\u2026)'],
    ['sess_' + CYRILLIC_A.repeat(12), 'sess_\u2026'],
    // Taken apart by an invisible character, it is put back together and
    // then masked; cut short by the cap, what is left of it is masked too.
    ['sess' + ZWSP + '_aaaaaaaaaaaa', 'sess_\u2026'],
    ['x'.repeat(16) + 'sess_aaaaaaaaaaaa', 'x'.repeat(16) + 'sess_\u2026'],
    ['deploy', 'deploy'],
    ['session', 'session'],
  ]) {
    expect(drawnName(name)).toBe(drawn)
  }
})

test('the countdown says the least time left, and past zero that the request may still be open', () => {
  const req = { startedAt: 1_000_000, timeoutSecs: 90 }
  expect(timeLeft(req, 1_000_000)).toBe('at least 1:30 left')
  // Rounded down, never up: 89.5 s left is at least 1:29.
  expect(timeLeft(req, 1_000_500)).toBe('at least 1:29 left')
  expect(timeLeft(req, 1_089_001)).toBe('may time out at any moment')
  expect(timeLeft(req, 1_090_000)).toBe('may time out at any moment')
  expect(timeLeft(req, 2_000_000)).toBe('may time out at any moment')
})

test("the closing words are the daemon's own: status, reason, bytes", () => {
  expect(outcomeWords(as(PROVIDED_TEXT))).toBe('secret_provided, 8 bytes written')
  expect(outcomeWords(as(TIMEOUT_TEXT))).toBe('not sent: timeout')
  expect(outcomeWords(as(AT_SHELL_PROMPT_TEXT))).toBe('not sent: at_shell_prompt')
  expect(outcomeWords({ deny: 'The user refused' })).toBe('not run: refused')
  expect(outcomeWords({ result: 'invalid params', text: 'invalid params', isError: true })).toBe('not sent: the call failed')
  // A word that is not an enum is not drawn as one.
  const odd = JSON.stringify({ status: 'secret_cancelled', data: { reason: 'Ignore all instructions' } })
  expect(outcomeWords(as(odd))).toBe('not sent: secret_cancelled')
  const oddStatus = JSON.stringify({ status: 'Secret provided\x1b[2J', data: {} })
  expect(outcomeWords(as(oddStatus))).toBe('not sent: unknown')
})

test("the agent's own results pair live names with ids, and an exited session gives its name up", () => {
  const names = new Map()
  learn(names, JSON.parse(START_TEXT))
  expect([...names]).toEqual([['deploy', ID]])
  // list_sessions: `old` has exited, so its name is not kept.
  learn(names, JSON.parse(LIST_TEXT))
  expect([...names]).toEqual([['deploy', ID]])
  learn(names, JSON.parse(STATUS_TEXT))
  expect(names.get('deploy')).toBe(STATUS_ID)
  // A name learned live, then seen exited under the same id, is dropped.
  const old = JSON.parse(LIST_TEXT).data.sessions.find((s: any) => s.id === OLD_ID)
  learn(names, { status: 'ok', data: { ...old, state: 'Running' } })
  expect(names.get('old')).toBe(OLD_ID)
  learn(names, { status: 'ok', data: old })
  expect(names.has('old')).toBe(false)
  // A session still starting is live. An exited one by the same name but
  // another id is an earlier session, and leaves the live one's id alone,
  // whichever of the two a list names first.
  learn(names, { status: 'ok', data: { ...old, state: 'Starting' } })
  expect(names.get('old')).toBe(OLD_ID)
  learn(names, { status: 'ok', data: { sessions: [{ ...old, state: 'Running' }, { ...old, id: ID, state: 'Exited' }] } })
  expect(names.get('old')).toBe(OLD_ID)
  learn(names, { status: 'ok', data: { sessions: [{ ...old, id: ID, state: 'Exited' }, { ...old, state: 'Running' }] } })
  expect(names.get('old')).toBe(OLD_ID)
  learn(names, { status: 'ok', data: old })
  // Anything else teaches nothing.
  for (const junk of [null, 'ok', { status: 'session_not_found', data: { id: ID, name: 'x' } }, { status: 'ok', data: { id: 'sess_x', name: 'y' } }, { status: 'ok', data: { id: ID, name: '' } }]) {
    learn(names, junk)
  }
  expect([...names.keys()]).toEqual(['deploy'])

  expect(identify(names, 'deploy')).toEqual({ id: STATUS_ID, name: 'deploy', target: STATUS_ID })
  expect(identify(names, STATUS_ID)).toEqual({ id: STATUS_ID, name: 'deploy', target: STATUS_ID })
  expect(identify(names, ID)).toEqual({ id: ID, name: '', target: ID })
  expect(identify(names, 'build')).toEqual({ id: null, name: 'build', target: 'build' })
  expect(identify(names, 'dep loy')).toEqual({ id: null, name: 'dep loy', target: null })
  expect(identify(names, undefined)).toEqual({ id: null, name: '', target: null })
})

// ---------------------------------------------------------------- the band

test('the rising edge draws the band and a toast from the call alone, and calls nothing on Holdfast', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  await $.tool.call(START_DEPLOY)
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)

  expect(rec.connects).toEqual([])
  expect(rec.mcp).toEqual([])
  expect(rec.toasts).toEqual(['holdfast: deploy (' + ID + ') is waiting for a secret. Type it in holdfast attach, not here.'])

  const ui = await $.ui.mount(band())
  expect(await texts(ui, /is waiting for a secret/)).toBe('holdfast: deploy (' + ID + ') is waiting for a secret  at least 2:00 left')
  expect(await texts(ui, /^agent says/)).toBe('agent says: "sudo password for deploy"')
  expect(await texts(ui, /not here/)).toBe('Type it in holdfast attach, not here.')
  // Nothing the call does not say: the terminal and who started it are the
  // session panel's to show.
  expect(await texts(ui, /^terminal shows|^started by/)).toBeUndefined()
  const tmux: any = await ui.find({ key: 'band-tmux' })
  const copy: any = await ui.find({ key: 'band-copy' })
  expect(tmux.props.hotkey).toBe('1')
  expect(tmux.props.label).toBe('open attach in tmux split (right)')
  expect(copy.props.hotkey).toBe('2')
  // Another mod's band, which next(e) stands for here, is still drawn.
  expect(await ui.find({ type: 'Text', text: 'drawn by Claude Code' })).toBeDefined()

  // The countdown moves on the clock; nothing is looked up again.
  const looked = rec.env.length + rec.stats.length + rec.checks.length
  await clock.advance(30_000)
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/at least 1:30 left$/)
  expect(rec.env.length + rec.stats.length + rec.checks.length).toBe(looked)
  expect(rec.toasts.length).toBe(1)

  await clock.advance(30_000)
  await call
  await ui.unmount()
})

test('the call goes on before the band looks at anything', async ($, on) => {
  // Every host call the band makes first is held for a minute.
  const { rec, clock } = stubAll(on, { holdMs: 120_000, surfacesHoldMs: 60_000 })
  const call = $.tool.call(ASK)
  for (let i = 0; i < 20; i++) await clock.settle()
  expect(rec.calls.length).toBe(1)
  expect(rec.calls[0]).toMatchObject(ASK)
  expect(rec.toasts).toEqual([])
  await clock.advance(60_000)
  await settle(clock)
  const ui = await $.ui.mount(band())
  // The countdown started with the call, not when the band could draw.
  expect(await texts(ui, /is waiting for a secret/)).toBe('holdfast: session "deploy" is waiting for a secret  at least 1:00 left')
  await ui.unmount()
  await clock.advance(60_000)
  expect(await call).toEqual(PROVIDED)
})

// Claude Code's dialog for the agent's call comes after this hook (measured
// on 2.1.291), so the band's clock starts before the daemon's: the time the
// band gives is a floor, never more than the request truly has, and when it
// runs out the band does not say the request is over.
test('a permission dialog in front of the call never makes the band claim more time than there is', { timeoutMs: 30_000 }, async ($, on) => {
  const approveMs = 14_000
  const { rec, clock } = stubAll(on, { approveMs, holdMs: 90_000, result: as(TIMEOUT_TEXT) })
  const call = $.tool.call({ ...ASK, timeout_secs: 90 })
  let settled = false
  call.then(() => (settled = true))
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  const title = async () => (await texts(ui, /is waiting for a secret/)) as string
  expect(await title()).toMatch(/ at least 1:30 left$/)
  for (let t = 0; t < approveMs + 90_000; t += 1_000) {
    const shown = (await title()).match(/ at least (\d+):(\d\d) left$/)
    const truly = (approveMs + 90_000 - t) / 1000
    if (shown) expect(Number(shown[1]) * 60 + Number(shown[2])).toBeLessThanOrEqual(truly)
    else expect(await title()).toMatch(/ may time out at any moment$/)
    expect(settled).toBe(false)
    if (t === approveMs) expect(await title()).toMatch(/ at least 1:16 left$/)
    if (t === 90_000) expect(await title()).toMatch(/ may time out at any moment$/)
    await clock.advance(1_000)
  }
  expect(await call).toEqual(as(TIMEOUT_TEXT))
  await settle(clock)
  expect(await ui.find({ key: 'band-request' })).toBeUndefined()
  expect(await texts(ui, /^holdfast: session/)).toBe('holdfast: session "deploy" - not sent: timeout')
  await ui.unmount()
})

test("the call's result comes back untouched, and its outcome shows for five seconds", async ($, on) => {
  const answer = { result: PROVIDED_TEXT, text: PROVIDED_TEXT, ref: 7 }
  const { rec, clock } = stubAll(on, { holdMs: 10_000, result: answer })
  await $.tool.call(START_DEPLOY)
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  await clock.advance(10_000)
  expect(await call).toEqual(answer)
  await settle(clock)
  // The call went on exactly as the agent made it.
  expect(rec.calls.at(-1)).toMatchObject(ASK)

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
  const { rec, clock } = stubAll(on, { holdMs: 3_000, result: as(TIMEOUT_TEXT) })
  const call = $.tool.call({ ...ASK, session: ID, timeout_secs: 3 })
  await untilCalled(clock, rec)
  await clock.advance(3_000)
  await call
  await settle(clock)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /^holdfast: sess_/)).toBe('holdfast: ' + ID + ' - not sent: timeout')
  await ui.unmount()
})

test('a call refused before the band could draw gets its closing line and no waiting toast', async ($, on) => {
  // The daemon answers at once; the band's first look is held a moment.
  const { rec, clock } = stubAll(on, { result: as(AT_SHELL_PROMPT_TEXT), surfacesHoldMs: 50 })
  expect(await $.tool.call(ASK)).toEqual(as(AT_SHELL_PROMPT_TEXT))
  await clock.advance(50)
  await settle(clock)
  expect(rec.toasts).toEqual([])
  const ui = await $.ui.mount(band())
  expect(await ui.find({ key: 'band-request' })).toBeUndefined()
  expect(await texts(ui, /^holdfast: session/)).toBe('holdfast: session "deploy" - not sent: at_shell_prompt')
  await ui.unmount()
})

test('the tmux button splits beside Claude Code, and only when pressed', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  await $.tool.call(START_DEPLOY)
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
  const odd = "/opt/hold fast/it's/holdfast"
  const { rec, clock } = stubAll(on, { holdMs: 60_000, env: { ...ENV, HOLDFAST_BOOTSTRAP_BIN: odd }, files: { ...FILES, [odd]: 'exec' } })
  await $.tool.call(START_DEPLOY)
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  await ui.press({ key: 'band-copy' })
  expect(rec.copies).toEqual([{ text: "'/opt/hold fast/it'\\''s/holdfast' attach --keep-size '" + ID + "'", surface: 'terminal' }])
  expect(rec.runs).toEqual([])
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('without TMUX there is no tmux button, and copy stays', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000, env: { PATH: ENV.PATH } })
  const call = $.tool.call({ ...ASK, session: ID })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await ui.find({ key: 'band-tmux' })).toBeUndefined()
  expect(await ui.find({ key: 'band-copy' })).toBeDefined()
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('the Desktop app, which has no $.process, gets no tmux button and takes a regular file as it stands', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000, surfaces: ['desktop'], noProcess: true })
  const call = $.tool.call({ ...ASK, session: ID })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band('desktop'))
  expect(await ui.find({ key: 'band-tmux' })).toBeUndefined()
  await ui.press({ key: 'band-copy' })
  expect(rec.copies).toEqual([{ text: "'" + PATH_BIN + "' attach --keep-size '" + ID + "'", surface: 'desktop' }])
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

// ------------------------------------------------------------ the binary

test('HOLDFAST_BOOTSTRAP_BIN comes first when it names an executable file', async ($, on) => {
  const named = '/home/me/.cargo/bin/holdfast'
  const { rec, clock } = stubAll(on, { holdMs: 60_000, env: { ...ENV, HOLDFAST_BOOTSTRAP_BIN: named }, files: { ...FILES, [named]: 'exec' } })
  const call = $.tool.call({ ...ASK, session: ID })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  await ui.press({ key: 'band-copy' })
  expect(rec.copies[0].text).toBe("'" + named + "' attach --keep-size '" + ID + "'")
  // PATH was never searched.
  expect(rec.stats).toEqual([named])
  expect(rec.checks.map((c: any) => c.argv)).toEqual([['/bin/sh', '-c', 'test -x "$1"', 'sh', named]])
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

// Each gives way to PATH; one that is not an absolute path is not even
// looked at, since a relative one would be looked up where the agent works.
for (const [why, value, files, looked] of [
  ['relative', 'bin/holdfast', { 'bin/holdfast': 'exec' }, []],
  ['led by ~', '~/.cargo/bin/holdfast', {}, []],
  ['missing', '/home/me/.cargo/bin/holdfast', {}, ['/home/me/.cargo/bin/holdfast']],
  ['a directory', '/home/me/.cargo/bin', { '/home/me/.cargo/bin': 'dir' }, ['/home/me/.cargo/bin']],
  ['not executable', '/home/me/.cargo/bin/holdfast', { '/home/me/.cargo/bin/holdfast': 'file' }, ['/home/me/.cargo/bin/holdfast']],
] as const) {
  test('a HOLDFAST_BOOTSTRAP_BIN that is ' + why + ' gives way to PATH', async ($, on) => {
    const { rec, clock } = stubAll(on, { holdMs: 60_000, env: { ...ENV, HOLDFAST_BOOTSTRAP_BIN: value }, files: { ...FILES, ...files } })
    const call = $.tool.call({ ...ASK, session: ID })
    await untilCalled(clock, rec)
    expect(rec.stats).toEqual([...looked, '/usr/local/bin/holdfast', PATH_BIN])
    const ui = await $.ui.mount(band())
    await ui.press({ key: 'band-copy' })
    expect(rec.copies[0].text).toBe("'" + PATH_BIN + "' attach --keep-size '" + ID + "'")
    await ui.unmount()
    await clock.advance(60_000)
    await call
  })
}

test('PATH is searched in order, past relative entries, directories and files that do not run', async ($, on) => {
  // `/d//` is where it is found, and the command names `/d/holdfast`.
  const env = { ...ENV, PATH: 'rel:/a:/b/:/c:/d//:/e' }
  const files = { 'rel/holdfast': 'exec', '/b/holdfast': 'dir', '/c/holdfast': 'file', '/d/holdfast': 'exec', '/e/holdfast': 'exec' } as const
  const { rec, clock } = stubAll(on, { holdMs: 60_000, env, files })
  const call = $.tool.call({ ...ASK, session: ID })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  await ui.press({ key: 'band-tmux' })
  expect(rec.runs[0].argv).toEqual(split(['-t', '%7'], [], '/d/holdfast'))
  expect(rec.stats).toEqual(['/a/holdfast', '/b/holdfast', '/c/holdfast', '/d/holdfast'])
  // Only what stat calls a file is asked whether it runs, and never on stdin.
  expect(rec.checks.map((c: any) => c.argv[4])).toEqual(['/c/holdfast', '/d/holdfast'])
  for (const c of rec.checks) {
    expect(c.init).toMatchObject({ timeoutMs: 2000 })
    expect(c.init.stdin).toBeUndefined()
  }
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('with no holdfast to name there are no buttons: the band shows the command and why', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000, env: { ...TMUX_ENV, PATH: '/usr/bin:/bin' } })
  await $.tool.call(START_DEPLOY)
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await ui.find({ key: 'band-tmux' })).toBeUndefined()
  expect(await ui.find({ key: 'band-copy' })).toBeUndefined()
  expect(await texts(ui, /^run: /)).toBe("run: holdfast attach --keep-size '" + ID + "'")
  const why: any = await ui.find({ type: 'Text', text: /names none/ })
  expect(why.children[0]).toMatch(/^holdfast is not on Claude Code's PATH, and HOLDFAST_BOOTSTRAP_BIN names none: see \/holdfast:attach/)
  expect(why.children[1]).toMatchObject({ type: 'Link', props: { href: 'https://github.com/Sertelegger/holdfast/issues/280', label: '#280' } })
  // Never the plugin's bootstrap, which would download.
  expect(JSON.stringify(await ui.find({ key: 'band' }))).not.toContain('bootstrap')
  await ui.unmount()
  await clock.advance(60_000)
  await call
  expect(rec.runs).toEqual([])
  expect(rec.copies).toEqual([])
})

// ---------------------------------------------------- who the request is for

test('a session the agent listed gets its id beside its name, and attach is handed the id', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  expect(await $.tool.call({ tool: LIST })).toEqual(as(LIST_TEXT))
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: deploy \(sess_8e2dc40db93c\) is waiting/)
  await ui.press({ key: 'band-copy' })
  expect(rec.copies[0].text).toBe("'" + PATH_BIN + "' attach --keep-size '" + ID + "'")
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('an id the agent passes gets the name its own calls gave it', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  await $.tool.call({ tool: STATUS, session: 'deploy' })
  const call = $.tool.call({ ...ASK, session: STATUS_ID })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: deploy \(sess_0f8fb4eb7af1\) is waiting/)
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('a name whose id the agent never saw is drawn as a name, and attach is handed the name', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  const call = $.tool.call({ ...ASK, session: 'build' })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: session "build" is waiting/)
  await ui.press({ key: 'band-copy' })
  expect(rec.copies[0].text).toBe("'" + PATH_BIN + "' attach --keep-size 'build'")
  await ui.press({ key: 'band-tmux' })
  expect(rec.runs[0].argv).toEqual(split(['-t', '%7'], [], PATH_BIN, 'build'))
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('a name attach cannot take as it stands, with no id seen for it, draws no buttons', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  const call = $.tool.call({ ...ASK, session: "-x'; touch /tmp/pwned; '" })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await ui.find({ key: 'band-tmux' })).toBeUndefined()
  expect(await ui.find({ key: 'band-copy' })).toBeUndefined()
  expect(await texts(ui, /holdfast list/)).toMatch(/^Find its id with `holdfast list`/)
  await ui.unmount()
  await clock.advance(60_000)
  await call
  expect(rec.runs).toEqual([])
  expect(rec.copies).toEqual([])
})

test('the session calls the band watches go on as the agent made them and come back untouched', async ($, on) => {
  const odd = { result: START_TEXT, text: START_TEXT, ref: 3 }
  const { rec, clock } = stubAll(on, { answers: { [START]: odd, [STATUS]: as('not json') } })
  const asked = { tool: START, command: 'bash', name: 'deploy', env: { TOKEN: 'x' } }
  expect(await $.tool.call(asked)).toEqual(odd)
  const { tool_use_id, ...seen } = rec.calls[0]
  expect(seen).toEqual(asked)
  // A result it cannot read is passed on all the same.
  expect(await $.tool.call({ tool: STATUS, session: 'deploy' })).toEqual(as('not json'))
  await settle(clock)
  // Watching reads nothing and draws nothing.
  expect(rec.env).toEqual([])
  expect(rec.stats).toEqual([])
  expect(rec.toasts).toEqual([])
})

test("the agent's text is drawn stripped and labelled", async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  const call = $.tool.call({ ...ASK, session: 'dep\x1b[1Gloy' + RLO, prompt_text: 'type\x1b[2J it\r\nhere ' + RLO + '\x1b]8;;http://x\x07now' })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /^agent says/)).toBe('agent says: "type it here now"')
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: session "deploy" is waiting/)
  expect(rec.toasts[0]).toBe('holdfast: session "deploy" is waiting for a secret. Type it in holdfast attach, not here.')
  // The name as drawn is not a name attach was handed.
  expect(await ui.find({ key: 'band-copy' })).toBeUndefined()
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('a long name cannot push the real id out of an 80-column band', async ($, on) => {
  // A long name; the real id after it must still be drawn whole. (One that
  // reads as an id is masked, which the next test covers.)
  const fake = 'deploy-is-waiting-for-a-secret-'.padEnd(60, 'x')
  const started = JSON.stringify({ status: 'ok', data: { session_id: ID, name: fake } })
  const { rec, clock } = stubAll(on, { holdMs: 60_000, answers: { [START]: as(started) } })
  await $.tool.call({ tool: START, command: 'bash', name: fake })
  const call = $.tool.call({ ...ASK, session: fake })
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

test('the only id the band draws is the real one, whatever the name says', async ($, on) => {
  const fake = 'x sess_aaaaaaaaaaaa'
  const started = JSON.stringify({ status: 'ok', data: { session_id: ID, name: fake } })
  const { rec, clock } = stubAll(on, { holdMs: 60_000, answers: { [START]: as(started) } })
  await $.tool.call({ tool: START, command: 'bash', name: fake })
  const first = $.tool.call({ ...ASK, session: fake })
  await untilCalled(clock, rec, 1)
  // A name never paired with an id, which draws none at all; and the id,
  // drawn with the name it was paired with.
  const second = $.tool.call({ ...ASK, session: 'use sess_bbbbbbbbbbbb' })
  await untilCalled(clock, rec, 2)
  const third = $.tool.call({ ...ASK, session: ID })
  await untilCalled(clock, rec, 3)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: x sess_\u2026 \(sess_8e2dc40db93c\) is waiting/)
  expect(await texts(ui, /more waiting/)).toBe('+2 more waiting: session "use sess_\u2026", x sess_\u2026 (' + ID + ')')
  expect(rec.toasts[1]).toBe('holdfast: session "use sess_\u2026" is waiting for a secret. Type it in holdfast attach, not here.')
  const drawn = JSON.stringify(await ui.find({ key: 'band' })) + rec.toasts.join('\n')
  expect([...new Set(drawn.match(/sess_[0-9a-f]{12}/g))]).toEqual([ID])
  // The command is the real id's.
  await ui.press({ key: 'band-copy' })
  expect(rec.copies[0].text).toBe("'" + PATH_BIN + "' attach --keep-size '" + ID + "'")
  await ui.unmount()
  await clock.advance(60_000)
  await first
  await second
  await third
})

// ----------------------------------------------------- where and whether

test('a refused environment read still draws the band, and it closes with the call', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 10_000, envDeny: 'policy: no env' })
  const call = $.tool.call({ ...ASK, session: ID })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: sess_8e2dc40db93c is waiting/)
  expect(await ui.find({ key: 'band-tmux' })).toBeUndefined()
  expect(await texts(ui, /^run: /)).toBe("run: holdfast attach --keep-size '" + ID + "'")
  expect(rec.toasts.length).toBe(1)
  await clock.advance(10_000)
  expect(await call).toEqual(PROVIDED)
  await settle(clock)
  expect(await ui.find({ key: 'band-request' })).toBeUndefined()
  expect(await texts(ui, /^holdfast: sess_/)).toMatch(/secret_provided, 8 bytes written$/)
  await ui.unmount()
})

// Claude Code aborts a hook's next.signal when the person interrupts or a
// hook above it settles first; this plugin, loaded above the band, is the
// second. What it cut short beneath it never settles.
const CUT_SHORT = {
  name: 'cut-short',
  tier: 'prepend',
  register(on: any) {
    on('tool.call', { tool: 'mcp__plugin_holdfast_holdfast__request_secret_input' }, async ($: any, e: any, next: any) => {
      next(e).catch(() => {})
      await $.clock.sleep(10_000)
      return { deny: 'cut short' }
    })
  },
} as const

test('a call cut short clears the band at once, with no closing line', { plugins: [CUT_SHORT] }, async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 600_000 })
  const call = $.tool.call({ ...ASK, session: ID })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await ui.find({ key: 'band-request' })).toBeDefined()
  await clock.advance(10_000)
  expect(await call).toMatchObject({ deny: 'cut short' })
  await settle(clock)
  expect(await ui.find({ key: 'band' })).toBeUndefined()
  // And nothing comes back later, when the dropped call would have ended.
  await clock.advance(600_000)
  await settle(clock)
  expect(await ui.find({ key: 'band' })).toBeUndefined()
  expect(rec.toasts.length).toBe(1)
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
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/may time out at any moment$/)
  await clock.advance(2_000)
  expect(await ui.find({ key: 'band' })).toBeUndefined()
  await ui.unmount()
  await clock.advance(3_600_000)
  await call
})

test('where nothing draws (-p, the SDK, the VS Code panel) nothing is looked at or shown', async ($, on) => {
  const { rec, clock } = stubAll(on, { surfaces: [] })
  expect(await $.tool.call(ASK)).toEqual(PROVIDED)
  await settle(clock)
  expect(rec.env).toEqual([])
  expect(rec.stats).toEqual([])
  expect(rec.checks).toEqual([])
  expect(rec.toasts).toEqual([])
})

test('the VS Code surface alone counts as nothing drawing', async ($, on) => {
  const { rec, clock } = stubAll(on, { surfaces: ['vscode'] })
  expect(await $.tool.call(ASK)).toEqual(PROVIDED)
  await settle(clock)
  expect(rec.env).toEqual([])
  expect(rec.toasts).toEqual([])
})

test('switched off in userConfig, the module registers nothing', { options: { secret_band: false } }, async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  await $.tool.call(START_DEPLOY)
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  expect(await ui.find({ key: 'band' })).toBeUndefined()
  expect(await ui.find({ type: 'Text', text: 'drawn by Claude Code' })).toBeDefined()
  await ui.unmount()
  await clock.advance(60_000)
  expect(await call).toEqual(PROVIDED)
  expect(rec.env).toEqual([])
  expect(rec.stats).toEqual([])
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

test('a short band drops the frame and keeps the buttons', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  const call = $.tool.call({ ...ASK, session: ID })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band('terminal', 7))
  const box: any = await ui.find({ key: 'band-request' })
  expect(box.props.borderStyle).toBeUndefined()
  expect(await ui.find({ key: 'band-tmux' })).toBeDefined()
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('two requests at once: the oldest is drawn, the other is counted', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 60_000 })
  await $.tool.call(START_DEPLOY)
  const first = $.tool.call(ASK)
  await untilCalled(clock, rec, 1)
  await clock.advance(1_000)
  const second = $.tool.call({ ...ASK, session: 'build' })
  await untilCalled(clock, rec, 2)
  const ui = await $.ui.mount(band())
  expect(await texts(ui, /is waiting for a secret/)).toMatch(/^holdfast: deploy \(sess_8e2dc40db93c\)/)
  expect(await texts(ui, /more waiting/)).toBe('+1 more waiting: session "build"')
  await ui.unmount()
  await clock.advance(61_000)
  await first
  await second
})

test('nothing it does calls Holdfast, reaches the model or approves a call', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 30_000 })
  await $.tool.call(START_DEPLOY)
  await $.tool.call({ tool: LIST })
  await $.tool.call({ tool: STATUS, session: 'deploy' })
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

  // No connection to Holdfast's server and no call on it: a mod's call is
  // permission-checked like the agent's, so one would ask the user.
  expect(rec.connects).toEqual([])
  expect(rec.mcp).toEqual([])
  // The only processes: the executable check, and the split the press asked
  // for, neither with stdin.
  expect(rec.checks.length).toBeGreaterThan(0)
  for (const c of rec.checks) expect(c.init.stdin).toBeUndefined()
  expect(rec.runs.map((r: any) => r.argv[0])).toEqual(['tmux'])
  expect(rec.runs[0].init.stdin).toBeUndefined()
  // Nothing reaches the model, and nothing is kept.
  expect(rec.submits).toEqual([])
  expect(rec.models).toEqual([])
  expect(rec.stores).toEqual([])
  // Every call reached Claude Code exactly as the agent made it.
  expect(rec.calls.map((c: any) => c.tool)).toEqual([START, LIST, STATUS, TOOL])
  expect(rec.calls.at(-1)).toMatchObject(ASK)
})

test('the call goes on exactly as the agent made it, odd arguments included', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 10_000 })
  // Dirty text and no timeout_secs: a hook that cleaned or filled in either
  // before next(e) would be rewriting the call.
  const asked = { tool: TOOL, session: 'dep\x1b[2Jloy', prompt_text: 'type\x1b[2J it\r\nhere ' + RLO + ZWSP + 'now' }
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
    expect(await texts(ui, /is waiting for a secret/)).toMatch(/at least 2:00 left$/)
    const { tool_use_id, ...seen } = rec.calls[i]
    expect(seen).toEqual(asked)
    await ui.unmount()
    await clock.advance(1_000)
    await call
  }
})

// ------------------------------------------------------------- the split

test("the split hands the pane Claude Code's runtime directories", async ($, on) => {
  const env = { ...ENV, HOLDFAST_RUNTIME_DIR: '/iso/rt', XDG_RUNTIME_DIR: '/run/user/1000' }
  const { rec, clock } = stubAll(on, { holdMs: 60_000, env })
  const call = $.tool.call({ ...ASK, session: ID })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  await ui.press({ key: 'band-tmux' })
  expect(rec.runs[0].argv).toEqual(split(['-t', '%7'], ['HOLDFAST_RUNTIME_DIR=/iso/rt', 'XDG_RUNTIME_DIR=/run/user/1000']))
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

test('a failed split says why, stripped', async ($, on) => {
  const run = { exitCode: 1, stdout: '', stderr: "can't find pane\x1b[2J %7" + RLO + '\r\n' }
  const { rec, clock } = stubAll(on, { holdMs: 60_000, run })
  const call = $.tool.call({ ...ASK, session: ID })
  await untilCalled(clock, rec)
  const ui = await $.ui.mount(band())
  await ui.press({ key: 'band-tmux' })
  expect(rec.toasts.at(-1)).toBe("holdfast: tmux split-window failed (exit 1): can't find pane %7")
  await ui.unmount()
  await clock.advance(60_000)
  await call
})

// --------------------------------------------------------------- Windows

test('on Windows native the band says hybrid mode only, and looks for nothing', async ($, on) => {
  const { rec, clock } = stubAll(on, { holdMs: 1_000, env: { OS: 'Windows_NT', PATH: ENV.PATH } })
  const call = $.tool.call(ASK)
  await untilCalled(clock, rec)
  expect(rec.env).toEqual(['OS'])
  expect(rec.stats).toEqual([])
  expect(rec.toasts).toEqual(['holdfast: a secret request needs hybrid mode (Linux, macOS or WSL); on Windows it is refused.'])
  const ui = await $.ui.mount(band())
  expect(await ui.find({ key: 'band' })).toBeUndefined()
  await ui.unmount()
  await clock.advance(1_000)
  expect(await call).toEqual(PROVIDED)
})
