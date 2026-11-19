import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const article = 'https://web.shuiwujia.com/pc/detail?id=fixture&type=article#section'
const external = 'https://web.shuiwujia.com.example.test/pc/detail?id=fixture'
const storageKey = 'waterbuddy-portal-token'

async function run() {
  if (process.versions.electron) return verify()
  const home = mkdtempSync(path.join(tmpdir(), 'waterplus-browser-portal-'))
  const env = { ...process.env, BROWSER_PORTAL_HOME: home }
  delete env.ELECTRON_RUN_AS_NODE
  try {
    const child = spawn(require('electron'), [fileURLToPath(import.meta.url)], { env, stdio: 'inherit', windowsHide: true })
    const timeout = setTimeout(() => child.kill(), 20_000)
    try {
      const [code, signal] = await once(child, 'exit')
      assert.equal(code, 0, `Electron preview fixture exited with ${signal ?? code}`)
    } finally { clearTimeout(timeout) }
  } finally { rmSync(home, { recursive: true, force: true }) }
}

async function verify() {
  const { app, session, webContents } = require('electron')
  const { Factory } = require('../../assets/runtime/factory.cjs')
  const { Protocols } = require('../../assets/runtime/protocol.cjs')
  const { Webviews } = require('../../assets/runtime/webview.cjs')
  const { Windows } = require('../../assets/runtime/window.cjs')
  const { Environment } = require('../../assets/runtime/environment.cjs')
  const { Policies } = require('../../assets/runtime/policy.cjs')
  const { Downloads } = require('../../assets/runtime/downloads.cjs')
  const { createCommands } = require('../../assets/runtime/commands.cjs')
  Protocols.registerPrivileged(['tauri'])
  app.setPath('userData', process.env.BROWSER_PORTAL_HOME)
  await app.whenReady()
  let signedIn = true
  const requests = []
  const server = createServer((request, response) => {
    if (request.url === '/launch') { response.writeHead(303, { location: '/', 'set-cookie': 'core=synthetic' }).end(); return }
    if (request.url === '/api/waterbuddy/portal/token') {
      requests.push({ method: request.method, guard: request.headers['x-waterbuddy-portal'], cookie: request.headers.cookie })
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ token: signedIn ? 'fixture-platform-token' : '' }))
      return
    }
    if (request.url === '/api/waterbuddy/logout') { signedIn = false; response.writeHead(200).end('{}'); return }
    response.writeHead(200, { 'content-type': 'text/html' }).end('<!doctype html><title>Core fixture</title>')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  try {
    const core = `http://127.0.0.1:${server.address().port}`
    const webviews = new Webviews(), windows = new Windows(), popups = new Map()
    const transport = { closed: false, send(event, params) {
      if (event === 'webview.navigationRequested') policies.answerNavigation(params.id, true)
      if (event === 'protocol.request') protocols.answer(params.id, {
        status: 200, headers: { 'content-type': 'text/html' }, body: Buffer.from('<title>Desktop shell</title>').toString('base64'),
      })
    }, request() { return { action: 'deny' } } }
    const policies = new Policies({ transport, downloads: new Downloads(), webviews, windows, popups })
    const protocols = new Protocols({ policies, transport })
    protocols.register('tauri')
    const factory = new Factory({ webviews, windows, popups, policies, protocols, transport, environment: new Environment(webviews) })
    const commands = createCommands({ webviews, windows, protocols, factory, policies })
    const hosted = await commands['webHost.authenticate']({ url: core + '/launch' })
    let nextId = 0
    async function openCore() {
      const windowId = ++nextId
      const webviewId = ++nextId
      factory.createWindow({
        windowId, window: { visible: false },
        webview: { webviewId, url: 'tauri://localhost/', browserHost: true, authenticatedWebHostSession: true, policy: { navigation: true } },
      })
      const { contents } = webviews.get(webviewId)
      await once(contents, 'did-finish-load')
      commands['webHost.bind']({ webviewId, hostId: hosted.id })
      await contents.loadURL(hosted.documentUrl)
      return { webviewId, contents }
    }
    const { webviewId, contents } = await openCore()
    async function openPreview(name, url) {
      const reservation = factory.acquireBrowserGuest(webviewId, name)
      const previewSession = session.fromPartition(reservation.partition)
      previewSession.protocol.handle('https', request => {
        assert.equal(new URL(request.url).searchParams.has('waterbuddy_token'), false)
        assert.equal(request.headers.has('authorization'), false)
        return new Response(`<script>window.tokenAtStart = sessionStorage.getItem(${JSON.stringify(storageKey)})</script>`, { headers: { 'content-type': 'text/html' } })
      })
      const spec = JSON.stringify(reservation)
      const id = await contents.executeJavaScript(`new Promise((resolve, reject) => {
        const spec = ${spec};
        const view = document.createElement('webview');
        view.partition = spec.partition;
        view.src = 'about:blank#' + spec.lease;
        view.addEventListener('dom-ready', () => resolve(view.getWebContentsId()), { once: true });
        view.addEventListener('did-fail-load', event => reject(new Error(event.errorDescription)), { once: true });
        document.body.append(view);
      })`)
      const guest = webContents.fromId(id)
      if (guest.isLoading()) await once(guest, 'did-stop-loading')
      await guest.loadURL(url)
      return guest
    }
    const guest = await openPreview('article', article)
    assert.equal(guest.getURL(), article)
    assert.deepEqual(requests, [{ method: 'POST', guard: '1', cookie: 'core=synthetic' }])
    assert.equal(await guest.executeJavaScript('window.tokenAtStart'), 'fixture-platform-token')
    const other = await openPreview('external', external)
    assert.equal(await other.executeJavaScript('window.tokenAtStart'), null)
    assert.equal(requests.length, 1)
    const logoutWindow = await openCore()
    const closed = once(guest, 'destroyed')
    const logoutStatus = await logoutWindow.contents.executeJavaScript('fetch("/api/waterbuddy/logout", { method: "POST" }).then(response => response.status)')
    assert.equal(logoutStatus, 200)
    await closed
    assert.equal(other.isDestroyed(), false)
    const anonymous = await openPreview('anonymous', article)
    assert.equal(await anonymous.executeJavaScript('window.tokenAtStart'), null)
    assert.equal(requests.length, 2)
    console.log('WaterPlus preview login, isolation and logout: PASS')
    app.exit(0)
  } catch (error) {
    console.error(error)
    app.exit(1)
  } finally { server.close() }
}

void run().catch(error => { console.error(error); process.exitCode = 1 })
