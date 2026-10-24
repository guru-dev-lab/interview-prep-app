// Mac self-update (owner, 24 Oct: "FIX first"). Electron's Mac updater (Squirrel.Mac, used by electron-updater) only
// installs SIGNED apps, and xHire is ad-hoc signed (no Apple Developer ID), so a Mac never updated: every version had to
// be reinstalled by hand. This does it without Squirrel:
//   1. read latest-mac.yml from the newest GitHub release (the same file electron-builder publishes),
//   2. if it is newer, download the .zip for this Mac's chip and check its sha512 + size against that file,
//   3. unpack it (ditto) and check the unpacked app really is that version,
//   4. when the app quits (or "restart to update"), a small detached script waits for xHire to exit, moves the old app
//      aside, moves the new one into its place, and only then deletes the old one (on failure the old one is put back).
// Every step logs a result line; a failed step leaves the installed app untouched. No Node or Electron APIs beyond
// https/fs/crypto/child_process, so test/mac-updater.js runs it in plain Node against a local feed.
const https = require('https'), http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { execFile, spawn } = require('child_process');

const FEED = 'https://github.com/guru-dev-lab/interview-prep-app/releases/latest/download/latest-mac.yml';

// latest-mac.yml → { version, files: [{ url, sha512, size }] }. Only the keys electron-builder writes.
function parseFeed(text) {
  const t = String(text || '');
  const v = /^version:\s*['"]?([^'"\s]+)/m.exec(t);
  const files = []; const re = /-\s+url:\s*(\S+)\s*\n\s+sha512:\s*(\S+)\s*\n\s+size:\s*(\d+)/g; let m;
  while ((m = re.exec(t))) files.push({ url: m[1], sha512: m[2], size: Number(m[3]) });
  return { version: v ? v[1] : '', files };
}
// "1.1.10" > "1.1.9"; anything unparseable is never newer
function isNewer(a, b) {
  const pa = String(a || '').split('.').map(Number), pb = String(b || '').split('.').map(Number);
  if (pa.some(isNaN) || pb.some(isNaN)) return false;
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const x = pa[i] || 0, y = pb[i] || 0; if (x !== y) return x > y; }
  return false;
}
// The zip for this chip: electron-builder names them Xhire-<v>-arm64-mac.zip (Apple silicon) and Xhire-<v>-mac.zip (Intel)
function pickZip(files, arch) {
  const zips = (files || []).filter(f => /\.zip$/i.test(f.url));
  return arch === 'arm64' ? zips.find(f => /arm64/i.test(f.url)) || null : zips.find(f => !/arm64/i.test(f.url)) || null;
}
function plistVersion(appPath) {
  try { const p = fs.readFileSync(path.join(appPath, 'Contents', 'Info.plist'), 'utf8'); const m = /<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/.exec(p); return m ? m[1].trim() : ''; } catch (e) { return ''; }
}

function fetchTo(url, dest, redirects = 6) { // follows GitHub's redirects to its file store; dest = null → returns the body
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('http://') ? http : https;
    const req = lib.get(url, { headers: { 'User-Agent': 'xhire-mac-updater' } }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume(); if (!redirects) return reject(new Error('too many redirects'));
        return resolve(fetchTo(new URL(res.headers.location, url).toString(), dest, redirects - 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error('HTTP ' + res.statusCode + ' for ' + url)); }
      if (!dest) { const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve(Buffer.concat(chunks))); res.on('error', reject); return; }
      const hash = crypto.createHash('sha512'); let size = 0; const out = fs.createWriteStream(dest);
      res.on('data', c => { hash.update(c); size += c.length; });
      res.pipe(out); out.on('finish', () => resolve({ sha512: hash.digest('base64'), size })); out.on('error', reject); res.on('error', reject);
    });
    req.setTimeout(120000, () => req.destroy(new Error('timed out')));
    req.on('error', reject);
  });
}

function createMacUpdater({ currentVersion, workDir, arch = process.arch, log = console.log, feedUrl = FEED, onAvailable, onDownloaded }) {
  let busy = false, ready = null, installing = false;
  async function check() {
    if (busy || ready) return ready ? { state: 'ready', version: ready.version } : { state: 'busy' };
    busy = true;
    try {
      const feed = parseFeed((await fetchTo(feedUrl, null)).toString('utf8'));
      if (!feed.version) { log('[Update] Mac: the release feed has no version'); return { state: 'error' }; }
      if (!isNewer(feed.version, currentVersion)) { log('[Update] Mac: up to date (' + currentVersion + ')'); return { state: 'current' }; }
      const zip = pickZip(feed.files, arch);
      if (!zip) { log('[Update] Mac: v' + feed.version + ' is out but the release has no Mac zip for ' + arch); return { state: 'nozip', version: feed.version }; }
      log('[Update] Mac: v' + feed.version + ' available, downloading ' + zip.url);
      if (onAvailable) onAvailable(feed.version);
      const dir = path.join(workDir, 'mac-update'); fs.rmSync(dir, { recursive: true, force: true }); fs.mkdirSync(dir, { recursive: true });
      const file = path.join(dir, 'update.zip');
      const got = await fetchTo(new URL(zip.url, feedUrl).toString(), file);
      if (got.sha512 !== zip.sha512 || got.size !== zip.size) { fs.rmSync(dir, { recursive: true, force: true }); log('[Update] Mac: download did not match the release (sha512/size), discarded'); return { state: 'badfile' }; }
      const out = path.join(dir, 'unpacked');
      await new Promise((res, rej) => execFile('/usr/bin/ditto', ['-x', '-k', file, out], e => e ? rej(e) : res()));
      const appName = fs.readdirSync(out).find(n => /\.app$/.test(n));
      const appPath = appName && path.join(out, appName);
      if (!appPath || plistVersion(appPath) !== feed.version) { fs.rmSync(dir, { recursive: true, force: true }); log('[Update] Mac: the unpacked app is not v' + feed.version + ', discarded'); return { state: 'badapp' }; }
      fs.rmSync(file, { force: true });
      ready = { version: feed.version, appPath };
      log('[Update] Mac: v' + feed.version + ' ready, installs when xHire quits');
      if (onDownloaded) onDownloaded(feed.version);
      return { state: 'ready', version: feed.version };
    } catch (e) { log('[Update] Mac: check failed: ' + e.message); return { state: 'error', error: e.message }; }
    finally { busy = false; }
  }
  // bundlePath = the installed Xhire.app. Returns true when the swap script was started.
  function install({ bundlePath, pid, relaunch }) {
    if (!ready || installing) return false;
    if (!bundlePath || !/\.app$/.test(bundlePath)) { log('[Update] Mac: not running from an .app, skip install (' + bundlePath + ')'); return false; }
    try { fs.accessSync(path.dirname(bundlePath), fs.constants.W_OK); } catch (e) { log('[Update] Mac: cannot write to ' + path.dirname(bundlePath) + ', reinstall by hand'); return false; }
    installing = true;
    const script = path.join(path.dirname(ready.appPath), '..', 'swap.sh'), logFile = path.join(path.dirname(ready.appPath), '..', 'swap.log');
    fs.writeFileSync(script, [
      '#!/bin/sh',
      'PID="$1"; NEW="$2"; OLD="$3"; RELAUNCH="$4"; LOG="$5"; BAK="$OLD.old-update"',
      'i=0; while kill -0 "$PID" 2>/dev/null && [ $i -lt 150 ]; do sleep 0.2; i=$((i+1)); done',
      'rm -rf "$BAK"',
      'if mv "$OLD" "$BAK" && mv "$NEW" "$OLD"; then',
      '  xattr -dr com.apple.quarantine "$OLD" 2>/dev/null; rm -rf "$BAK"; echo "installed $(date)" >> "$LOG"',
      'else',
      '  if [ -d "$BAK" ] && [ ! -d "$OLD" ]; then mv "$BAK" "$OLD"; fi; echo "failed, kept the old app $(date)" >> "$LOG"',
      'fi',
      'if [ "$RELAUNCH" = "1" ]; then open "$OLD"; fi',
    ].join('\n') + '\n', { mode: 0o755 });
    spawn('/bin/sh', [script, String(pid), ready.appPath, bundlePath, relaunch ? '1' : '0', logFile], { detached: true, stdio: 'ignore' }).unref();
    log('[Update] Mac: installing v' + ready.version + ' when xHire exits' + (relaunch ? ', then reopening it' : ''));
    return true;
  }
  return { check, install, get ready() { return ready; } };
}

module.exports = { createMacUpdater, parseFeed, isNewer, pickZip, plistVersion, FEED };
