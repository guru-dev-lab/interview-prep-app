// Mac self-update (electron/mac-updater.js), end to end in plain Node on THIS Mac: a local feed served like GitHub
// (with a redirect), fake app bundles in a temp folder. Proves: newer version found, zip checked, unpacked, swapped in
// after the app exits; a tampered zip, a wrong version, a dmg-only release and a failed swap all leave the app untouched.
const fs = require('fs'), path = require('path'), os = require('os'), http = require('http'), crypto = require('crypto');
const { execFileSync, spawn } = require('child_process');
const U = require('../electron/mac-updater');
let pass = 0, fail = 0;
const check = (ok, label, detail) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + label + (!ok && detail !== undefined ? '\n     ' + String(detail).slice(0, 400) : '')); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---- pure parts
const real117 = `version: 1.1.7
files:
  - url: Xhire-1.1.7-arm64.dmg
    sha512: KRAYfIwdXi6Tdy/tDBnvD4F/Fs1orFf1MAEw9opeVhTRy0qP87XlAvLGtxYWVfFoOHXiHU+6GxuRQ8AVtiEB1A==
    size: 95605139
  - url: Xhire-1.1.7.dmg
    sha512: AQOdJIy6LETSjC8HPHS5aKTR3EdaBYujtB+Ae66XsEHxoKkmpTYDY6BknJzpqyg5RgroM9x80Hhsh9lESRbsfA==
    size: 101630908
path: Xhire-1.1.7-arm64.dmg
releaseDate: '2026-10-24T07:59:27.463Z'
`;
const f117 = U.parseFeed(real117);
check(f117.version === '1.1.7' && f117.files.length === 2 && f117.files[0].size === 95605139, 'reads the real 1.1.7 release feed', JSON.stringify(f117));
check(U.pickZip(f117.files, 'arm64') === null, 'a dmg-only release has no zip to install');
const zf = [{ url: 'Xhire-1.1.8-arm64-mac.zip' }, { url: 'Xhire-1.1.8-mac.zip' }, { url: 'Xhire-1.1.8.dmg' }];
check(U.pickZip(zf, 'arm64').url === 'Xhire-1.1.8-arm64-mac.zip' && U.pickZip(zf, 'x64').url === 'Xhire-1.1.8-mac.zip', 'picks the zip for the chip (Apple silicon / Intel)');
check(U.isNewer('1.1.8', '1.1.7') && U.isNewer('1.1.10', '1.1.9') && !U.isNewer('1.1.7', '1.1.7') && !U.isNewer('1.1.6', '1.1.7') && !U.isNewer('x', '1.0.0'), 'version compare');

if (process.platform !== 'darwin') { console.log(`(not a Mac: skipped the install run) ${fail ? fail + ' FAILED' : 'ALL PASS'} (${pass})`); process.exit(fail ? 1 : 0); }

(async () => {
  const T = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-macupd-'));
  const plist = v => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>CFBundleShortVersionString</key>\n<string>${v}</string></dict></plist>\n`;
  const makeApp = (dir, v, mark) => { fs.mkdirSync(path.join(dir, 'Xhire.app', 'Contents', 'MacOS'), { recursive: true }); fs.writeFileSync(path.join(dir, 'Xhire.app', 'Contents', 'Info.plist'), plist(v)); fs.writeFileSync(path.join(dir, 'Xhire.app', 'Contents', 'MacOS', 'Xhire'), mark); };
  const feedDir = path.join(T, 'feed'); fs.mkdirSync(feedDir);
  const zipOf = (v, name) => { const src = path.join(T, 'build-' + v); makeApp(src, v, 'NEW ' + v); execFileSync('/usr/bin/ditto', ['-c', '-k', '--keepParent', path.join(src, 'Xhire.app'), path.join(feedDir, name)]); const b = fs.readFileSync(path.join(feedDir, name)); return { url: name, sha512: crypto.createHash('sha512').update(b).digest('base64'), size: b.length }; };
  const z = zipOf('1.1.9', 'Xhire-1.1.9-arm64-mac.zip');
  const zWrongVer = zipOf('1.0.0', 'Xhire-wrong-arm64-mac.zip');
  const yml = (v, files) => 'version: ' + v + '\nfiles:\n' + files.map(f => `  - url: ${f.url}\n    sha512: ${f.sha512}\n    size: ${f.size}\n`).join('') + 'path: x\n';
  const feeds = {
    good: yml('1.1.9', [z, { url: 'Xhire-1.1.9-arm64.dmg', sha512: 'x', size: 1 }]),
    tampered: yml('1.1.9', [{ ...z, sha512: z.sha512.replace(/^./, c => c === 'A' ? 'B' : 'A') }]),
    wrongver: yml('1.1.9', [{ ...zWrongVer, url: zWrongVer.url }]),
    current: yml('1.1.8', [z]),
    dmgonly: real117.replace('1.1.7', '1.1.9'),
  };
  const srv = http.createServer((req, res) => {
    const m = /^\/(\w+)\/releases\/latest\/download\/latest-mac\.yml$/.exec(req.url);
    if (m) { res.writeHead(302, { Location: '/files/' + m[1] + '.yml' }); return res.end(); } // GitHub answers with a redirect too
    const f = /^\/files\/(\w+)\.yml$/.exec(req.url); if (f && feeds[f[1]]) { res.writeHead(200); return res.end(feeds[f[1]]); }
    const name = decodeURIComponent(req.url.replace(/^\/(\w+)\/releases\/latest\/download\//, '').replace(/^\/files\//, ''));
    const p = path.join(feedDir, path.basename(name)); if (fs.existsSync(p)) { res.writeHead(200); return fs.createReadStream(p).pipe(res); }
    res.writeHead(404); res.end();
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const apps = path.join(T, 'Applications'); makeApp(apps, '1.1.8', 'OLD 1.1.8');
  const installed = path.join(apps, 'Xhire.app');
  const logs = [];
  const signed = []; const fakeSign = async p => { signed.push(p); }; // the fake bundles hold no real program to sign; real signing is proven below
  const mk = (feed, work) => U.createMacUpdater({ currentVersion: '1.1.8', workDir: path.join(T, work), arch: 'arm64', log: l => logs.push(l), sign: fakeSign, feedUrl: base + '/' + feed + '/releases/latest/download/latest-mac.yml' });

  let r = await mk('current', 'w0').check();
  check(r.state === 'current', 'same version: nothing to do', JSON.stringify(r));
  r = await mk('dmgonly', 'w1').check();
  check(r.state === 'nozip', 'a release without a Mac zip is reported, nothing downloaded', JSON.stringify(r));
  r = await mk('tampered', 'w2').check();
  check(r.state === 'badfile' && !fs.existsSync(path.join(T, 'w2', 'mac-update')), 'a download that does not match the release is thrown away', JSON.stringify(r));
  r = await mk('wrongver', 'w3').check();
  check(r.state === 'badapp', 'an unpacked app of the wrong version is thrown away', JSON.stringify(r));
  check(U.plistVersion(installed) === '1.1.8', 'after all of those the installed app is untouched');

  // the real path: found, downloaded, checked, unpacked, swapped after the app exits
  let seen = [];
  const up = U.createMacUpdater({ currentVersion: '1.1.8', workDir: path.join(T, 'w4'), arch: 'arm64', log: l => logs.push(l), sign: fakeSign, feedUrl: base + '/good/releases/latest/download/latest-mac.yml', onAvailable: v => seen.push('available ' + v), onDownloaded: v => seen.push('downloaded ' + v) });
  r = await up.check();
  check(r.state === 'ready' && up.ready && up.ready.version === '1.1.9' && seen.join(',') === 'available 1.1.9,downloaded 1.1.9', 'newer version found, downloaded, checked and unpacked; the page is told both times', JSON.stringify([r, seen]));
  check(signed.length === 1 && /unpacked\/Xhire\.app$/.test(signed[0]), 'the unpacked app is signed before it is offered', JSON.stringify(signed));
  check((await up.check()).state === 'ready', 'checking again while one is ready does not download twice');
  const bad = await U.createMacUpdater({ currentVersion: '1.1.8', workDir: path.join(T, 'w6'), arch: 'arm64', log: l => logs.push(l), sign: async () => { throw new Error('invalid signature'); }, feedUrl: base + '/good/releases/latest/download/latest-mac.yml' }).check();
  check(bad.state === 'badsign' && !fs.existsSync(path.join(T, 'w6', 'mac-update')), 'an app that does not sign and verify is thrown away', JSON.stringify(bad));
  check(up.install({ bundlePath: path.join(T, 'not-an-app'), pid: process.pid }) === false, 'never installs over something that is not an .app');
  const fakeApp = spawn('/bin/sleep', ['1']); // stands in for xHire: the swap waits for it to exit
  check(up.install({ bundlePath: installed, pid: fakeApp.pid, relaunch: false }) === true, 'install starts the swap');
  await sleep(500);
  check(U.plistVersion(installed) === '1.1.8', 'nothing is swapped while the app is still running');
  await sleep(2500);
  check(U.plistVersion(installed) === '1.1.9' && fs.readFileSync(path.join(installed, 'Contents', 'MacOS', 'Xhire'), 'utf8') === 'NEW 1.1.9', 'after it exits, the new version is in place', U.plistVersion(installed));
  check(!fs.existsSync(installed + '.old-update'), 'the old copy is cleaned up');
  check(up.install({ bundlePath: installed, pid: process.pid }) === false, 'install runs once');

  // a swap that fails half way puts the old app back
  const up2 = U.createMacUpdater({ currentVersion: '1.1.9', workDir: path.join(T, 'w5'), arch: 'arm64', log: l => logs.push(l), sign: fakeSign, feedUrl: base + '/good/releases/latest/download/latest-mac.yml' });
  feeds.good = yml('1.2.0', [zipOf('1.2.0', 'Xhire-1.2.0-arm64-mac.zip')]);
  r = await up2.check();
  fs.rmSync(up2.ready.appPath, { recursive: true, force: true }); // the new app vanishes before the swap
  const fake2 = spawn('/bin/sleep', ['0.3']);
  up2.install({ bundlePath: installed, pid: fake2.pid, relaunch: false });
  await sleep(2000);
  check(U.plistVersion(installed) === '1.1.9' && !fs.existsSync(installed + '.old-update'), 'a failed swap puts the old app back where it was', U.plistVersion(installed));
  const swapLog = fs.readFileSync(path.join(T, 'w5', 'mac-update', 'swap.log'), 'utf8');
  check(/failed, kept the old app/.test(swapLog), 'and says so in its log', swapLog);
  check(logs.every(l => /^\[Update\] Mac: /.test(l)), 'every step logs one [Update] Mac line');

  srv.close(); fs.rmSync(T, { recursive: true, force: true });
  console.log(fail ? `${fail} FAILED, ${pass} passed` : `ALL PASS (mac updater, ${pass} checks)`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
