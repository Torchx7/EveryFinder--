const { app, BrowserWindow, ipcMain, shell, safeStorage, dialog } = require('electron');
const crypto = require('crypto');
const fs = require('fs');
const { spawn, execSync } = require('child_process');
const path = require('path');
const os = require('os');

let win = null;
let sh = null;
const isWin = process.platform === 'win32';

function send(d) {
  if (win && !win.isDestroyed()) win.webContents.send('term:data', d);
}

function startShell() {
  if (sh) return;
  if (isWin) {
    sh = spawn('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '-'], {
      cwd: os.homedir(), windowsHide: true
    });
    sh.stdin.write('[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n');
  } else {
    sh = spawn(process.env.SHELL || '/bin/bash', [], {
      cwd: os.homedir(), detached: true, env: { ...process.env, TERM: 'dumb' }
    });
  }
  const me = sh;
  me.stdout.on('data', d => send(d.toString()));
  me.stderr.on('data', d => send(d.toString()));
  me.on('error', e => send('[shell error] ' + e.message + '\n'));
  me.on('exit', () => { if (sh === me) sh = null; });
  send('Shell started in ' + os.homedir() + '\n');
}

function stopShell() {
  if (!sh) return;
  const me = sh;
  sh = null;
  try {
    if (isWin) execSync('taskkill /pid ' + me.pid + ' /T /F', { stdio: 'ignore' });
    else process.kill(-me.pid, 'SIGKILL');
  } catch (_) { try { me.kill('SIGKILL'); } catch (__) {} }
}


// ---- API lookups (keys stay in this process, encrypted on disk) ----
const SERVICES = ['shodan', 'virustotal', 'urlscan', 'abuseipdb'];
const keyFile = () => path.join(app.getPath('userData'), 'keys.json');
function readKeys() { try { return JSON.parse(fs.readFileSync(keyFile(), 'utf8')); } catch (_) { return {}; } }
function getKey(svc) {
  const k = readKeys();
  try { return k[svc] ? safeStorage.decryptString(Buffer.from(k[svc], 'base64')) : ''; } catch (_) { return ''; }
}
ipcMain.handle('keys:status', () => {
  const k = readKeys(), o = {};
  SERVICES.forEach(s => { o[s] = !!k[s]; });
  o.canEncrypt = safeStorage.isEncryptionAvailable();
  return o;
});
ipcMain.handle('keys:set', (_, svc, key) => {
  if (!SERVICES.includes(svc) || typeof key !== 'string') return { ok: false, error: 'Bad request' };
  if (!safeStorage.isEncryptionAvailable()) return { ok: false, error: 'Secure storage is not available on this system' };
  const k = readKeys();
  if (key.trim()) k[svc] = safeStorage.encryptString(key.trim()).toString('base64');
  else delete k[svc];
  fs.writeFileSync(keyFile(), JSON.stringify(k));
  return { ok: true };
});

const isIp = t => /^(\d{1,3}\.){3}\d{1,3}$/.test(t);
const isDomain = t => /^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(t);
async function jget(url, headers) {
  const r = await fetch(url, { headers: headers || {}, signal: AbortSignal.timeout(25000) });
  const txt = await r.text();
  let j = null;
  try { j = JSON.parse(txt); } catch (_) {}
  if (!r.ok) {
    const e = j && j.error ? (typeof j.error === 'string' ? j.error : (j.error.message || '')) : '';
    throw new Error('HTTP ' + r.status + (e ? ': ' + e : ''));
  }
  return j;
}
ipcMain.handle('api:run', async (_, svc, target) => {
  try {
    if (typeof target !== 'string' || target.length > 300) throw new Error('Invalid target');
    const t = target.trim();
    const enc = encodeURIComponent;
    if (svc === 'shodan') {
      if (!isIp(t)) throw new Error('Shodan needs an IP address');
      const key = getKey('shodan'); if (!key) throw new Error('Add a Shodan API key first');
      const j = await jget('https://api.shodan.io/shodan/host/' + enc(t) + '?key=' + enc(key));
      return { ok: true, data: { ip: j.ip_str, org: j.org, isp: j.isp, country: j.country_name, os: j.os, ports: j.ports, hostnames: j.hostnames, vulns: Object.keys(j.vulns || {}), last_update: j.last_update } };
    }
    if (svc === 'virustotal') {
      const key = getKey('virustotal'); if (!key) throw new Error('Add a VirusTotal API key first');
      let ep;
      if (isIp(t)) ep = 'ip_addresses/' + enc(t);
      else if (isDomain(t)) ep = 'domains/' + enc(t);
      else if (/^https?:\/\/\S+$/i.test(t)) ep = 'urls/' + Buffer.from(t).toString('base64url');
      else throw new Error('VirusTotal needs a domain, IP or URL');
      const j = await jget('https://www.virustotal.com/api/v3/' + ep, { 'x-apikey': key });
      const a = (j.data && j.data.attributes) || {};
      return { ok: true, data: { target: t, stats: a.last_analysis_stats, reputation: a.reputation, categories: a.categories, registrar: a.registrar, created: a.creation_date ? new Date(a.creation_date * 1000).toISOString() : undefined, country: a.country, as_owner: a.as_owner } };
    }
    if (svc === 'urlscan') {
      if (!isDomain(t)) throw new Error('URLScan needs a domain');
      const key = getKey('urlscan');
      const j = await jget('https://urlscan.io/api/v1/search/?size=10&q=' + enc('domain:' + t), key ? { 'API-Key': key } : {});
      return { ok: true, data: { total: j.total, results: (j.results || []).map(r => ({ url: r.page && r.page.url, ip: r.page && r.page.ip, time: r.task && r.task.time, report: r.result })) } };
    }
    if (svc === 'abuseipdb') {
      if (!isIp(t)) throw new Error('AbuseIPDB needs an IP address');
      const key = getKey('abuseipdb'); if (!key) throw new Error('Add an AbuseIPDB API key first');
      const j = await jget('https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=' + enc(t), { Key: key, Accept: 'application/json' });
      const d = j.data || {};
      return { ok: true, data: { ip: d.ipAddress, abuseConfidenceScore: d.abuseConfidenceScore, totalReports: d.totalReports, lastReportedAt: d.lastReportedAt, country: d.countryCode, isp: d.isp, usageType: d.usageType, domain: d.domain } };
    }
    if (svc === 'crtsh') {
      if (!isDomain(t)) throw new Error('crt.sh needs a domain');
      const j = await jget('https://crt.sh/?output=json&q=' + enc('%.' + t));
      const names = new Set();
      (j || []).forEach(r => String(r.name_value || '').split('\n').forEach(n => names.add(n.trim().toLowerCase())));
      const list = Array.from(names).sort();
      return { ok: true, data: { count: list.length, names: list.slice(0, 200) } };
    }
    throw new Error('Unknown service');
  } catch (e) {
    return { ok: false, error: e.message || 'Request failed' };
  }
});

ipcMain.on('term:start', () => startShell());
ipcMain.on('term:write', (_, cmd) => {
  if (typeof cmd !== 'string') return;
  startShell();
  sh.stdin.write(cmd + '\n');
});
ipcMain.on('term:stop', () => { stopShell(); startShell(); });

// ---- Self-updating screen file (index.html) from a GitHub repo ----
// Change UPDATE_BASE if your repo name or branch is different.
const UPDATE_BASE = 'https://raw.githubusercontent.com/Torchx7/EveryFinder--/main/';
const BUNDLED_UI_VERSION = 1;
const updDir = () => path.join(app.getPath('userData'), 'updates');
const sha256 = buf => crypto.createHash('sha256').update(buf).digest('hex');

function localUi() {
  // Use a previously downloaded copy only if it is newer than the built-in one and its hash still matches.
  try {
    const meta = JSON.parse(fs.readFileSync(path.join(updDir(), 'version.json'), 'utf8'));
    const file = path.join(updDir(), 'index.html');
    if (Number(meta.version) > BUNDLED_UI_VERSION && sha256(fs.readFileSync(file)) === meta.sha256) {
      return { file, version: Number(meta.version) };
    }
  } catch (_) {}
  return { file: path.join(__dirname, 'renderer', 'index.html'), version: BUNDLED_UI_VERSION };
}

async function fetchBuf(url) {
  const r = await fetch(url + '?t=' + Date.now(), { cache: 'no-store', signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return Buffer.from(await r.arrayBuffer());
}

async function checkUpdate() {
  try {
    const cur = localUi().version;
    const remote = JSON.parse((await fetchBuf(UPDATE_BASE + 'version.json')).toString('utf8'));
    const rv = Number(remote.version);
    if (!(rv > cur) || typeof remote.sha256 !== 'string') return;
    const raw = await fetchBuf(UPDATE_BASE + 'renderer/index.html');
    const buf = Buffer.from(raw.toString('utf8').replace(/\r\n/g, '\n'));
    if (buf.length > 5 * 1024 * 1024) throw new Error('Update too large');
    if (sha256(buf) !== remote.sha256.toLowerCase()) throw new Error('Update failed its integrity check');
    if (!buf.toString('utf8').includes('<title>EveryFinder')) throw new Error('Unexpected update file');
    fs.mkdirSync(updDir(), { recursive: true });
    const tmp = path.join(updDir(), 'index.html.tmp');
    fs.writeFileSync(tmp, buf);
    fs.renameSync(tmp, path.join(updDir(), 'index.html'));
    fs.writeFileSync(path.join(updDir(), 'version.json'), JSON.stringify({ version: rv, sha256: remote.sha256.toLowerCase() }));
    if (win && !win.isDestroyed()) {
      const r = await dialog.showMessageBox(win, {
        type: 'info', buttons: ['Reload now', 'Later'], defaultId: 0,
        message: 'An EveryFinder update (version ' + rv + ') was downloaded.',
        detail: 'Reload to start using it. Your notes and case findings are kept.'
      });
      if (r.response === 0 && !win.isDestroyed()) win.loadFile(path.join(updDir(), 'index.html'));
    }
  } catch (_) { /* offline or no update: keep using the current copy */ }
}

function createWindow() {
  win = new BrowserWindow({
    width: 1200, height: 860, backgroundColor: '#0b1830', title: 'EveryFinder', icon: path.join(__dirname, 'build', 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: true
    }
  });
  win.setMenuBarVisibility(false);
  win.loadFile(localUi().file);
  win.webContents.once('did-finish-load', () => setTimeout(checkUpdate, 3000));
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e, url) => {
    if (!url.startsWith('file://')) {
      e.preventDefault();
      if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    }
  });
}

const FW_HOSTS = ['osintframework.com', 'www.osintframework.com'];
app.on('web-contents-created', (_, contents) => {
  contents.on('will-attach-webview', (e, webPreferences, params) => {
    delete webPreferences.preload;
    webPreferences.nodeIntegration = false;
    webPreferences.contextIsolation = true;
    let host = '';
    try { host = new URL(params.src).hostname; } catch (_) {}
    if (!FW_HOSTS.includes(host)) e.preventDefault();
  });
  if (contents.getType() === 'webview') {
    contents.setWindowOpenHandler(({ url }) => {
      if (/^https?:\/\//i.test(url)) shell.openExternal(url);
      return { action: 'deny' };
    });
    contents.on('will-navigate', (e, url) => {
      try {
        if (!FW_HOSTS.includes(new URL(url).hostname)) { e.preventDefault(); shell.openExternal(url); }
      } catch (_) { e.preventDefault(); }
    });
  }
});

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { stopShell(); app.quit(); });
app.on('before-quit', stopShell);
