// Global Shortcut Mode (owner, 13 Oct) — main-process logic with a stand-in globalShortcut, plus the wiring through
// main.js → preload.js → canvas.html. Two keys: Cmd+Enter = Screen Assist, Cmd+Option+Enter = Snap (co-pilot camera).
// Free — no Electron, no model, no DB. Run: node test/global-shortcut.js
const assert = require('assert');
const fs = require('fs'), path = require('path');
const { createGlobalShortcut, ACCELERATOR, SHORTCUTS } = require(path.join(__dirname, '..', 'electron', 'global-shortcut.js'));
let n = 0; const ok = (c, m) => { n++; assert(c, m); };
const ASSIST = 'CommandOrControl+Enter', SNAP = 'CommandOrControl+Alt+Enter';

// stand-in for Electron's globalShortcut: one holder per accelerator, like the OS
function fakeGS(opts) {
  opts = opts || {};
  const held = new Map(); const calls = { register: 0, unregister: 0 };
  return {
    calls, held,
    register(acc, fn) { calls.register++; if (opts.throws) throw new Error(opts.throws); if ((opts.taken || []).includes(acc) || held.has(acc)) return false; held.set(acc, fn); return true; },
    unregister(acc) { calls.unregister++; held.delete(acc); },
    isRegistered(acc) { return held.has(acc); },
    press(acc) { const fn = held.get(acc); if (fn) fn(); return !!fn; }
  };
}

ok(ACCELERATOR === ASSIST, 'Assist: Cmd+Enter on Mac, Ctrl+Enter on Windows');
ok(SHORTCUTS.some(s => s.accelerator === SNAP && s.action === 'snap'), 'Snap: Cmd+Option+Enter (Ctrl+Alt+Enter)');

// ---- default OFF: nothing held until the page asks
let gs = fakeGS(), fired = [];
let s = createGlobalShortcut({ globalShortcut: gs, onFire: a => fired.push(a) });
ok(!s.status().on && gs.calls.register === 0, 'starts off, registers nothing');

// ---- ON: both registered once, each press runs its own action
let st = s.set(true);
ok(st.on && !st.error && st.keys['screen-assist'] && st.keys.snap, 'ON registers both keys');
ok(gs.isRegistered(ASSIST) && gs.isRegistered(SNAP), 'both held by the system');
gs.press(ASSIST); gs.press(SNAP);
ok(fired.join(',') === 'screen-assist,snap', 'each key runs its own action');
s.set(true); s.set(true);
ok(gs.calls.register === 2, 'turning ON again never registers twice');

// ---- OFF: both released at once
st = s.set(false);
ok(!st.on && !gs.isRegistered(ASSIST) && !gs.isRegistered(SNAP), 'OFF releases both immediately');
ok(!gs.press(ASSIST) && !gs.press(SNAP) && fired.length === 2, 'after OFF a press does nothing');
const un = gs.calls.unregister; s.set(false);
ok(gs.calls.unregister === un, 'OFF twice is harmless');

// ---- page load / quit drop them; ON again works
s.set(true); s.disable('page load');
ok(!gs.isRegistered(ASSIST) && !gs.isRegistered(SNAP) && !s.status().on, 'disable (page load / quit) releases both');
ok(s.set(true).on, 'can be turned on again after a release');

// ---- failures are reported, never thrown; one taken key does not cost the other
gs = fakeGS({ taken: [SNAP] });
s = createGlobalShortcut({ globalShortcut: gs, onFire: () => {} });
st = s.set(true);
ok(st.on && st.keys['screen-assist'] && !st.keys.snap && /Alt\+Enter taken by another app/.test(st.error), 'Snap taken → Assist still on, reason named');
gs = fakeGS({ taken: [ASSIST, SNAP] });
s = createGlobalShortcut({ globalShortcut: gs, onFire: () => {} });
st = s.set(true);
ok(!st.on && /taken by another app/.test(st.error), 'both taken → off + reason');
gs = fakeGS({ throws: 'conversion failed' });
s = createGlobalShortcut({ globalShortcut: gs, onFire: () => {} });
st = s.set(true);
ok(!st.on && /conversion failed/.test(st.error), 'register throwing → off + its message, no crash');

// ---- wiring: main process sends a message only (never raises the window), preload exposes it, page uses it
const main = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const preload = fs.readFileSync(path.join(__dirname, '..', 'electron', 'preload.js'), 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'electron', 'package.json'), 'utf8'));
const canvas = fs.readFileSync(path.join(__dirname, '..', 'public', 'canvas.html'), 'utf8');
const fire = (main.match(/onFire:\s*\(action\)\s*=>\s*\{[^\n]*\}/) || [''])[0];
ok(/webContents\.send\('global-shortcut', action\)/.test(fire), 'a press sends its action to the page');
ok(!/show\(|focus\(|moveTop\(/.test(fire), 'a press never shows or focuses the window');
ok(/ipcMain\.handle\('set-global-shortcut'/.test(main), 'main: set-global-shortcut handler');
ok(/app\.on\('will-quit'[\s\S]{0,120}globalCmdEnter\.disable[\s\S]{0,60}unregisterAll/.test(main), 'main: released on quit');
ok(/did-start-navigation[\s\S]{0,400}globalCmdEnter\.disable\('page load'\)/.test(main), 'main: released on every page load');
ok(pkg.build.files.includes('global-shortcut.js'), 'desktop build ships global-shortcut.js');
ok(/setGlobalShortcut:[^\n]*'set-global-shortcut'/.test(preload) && /onGlobalShortcut:[^\n]*'global-shortcut'/.test(preload), 'preload exposes both');
ok(/id="s-global-shortcut"[^>]*onchange="toggleGlobalShortcut\(this\.checked\)"/.test(canvas), 'Settings toggle wired');
ok(/id="row-global-shortcut" style="display:none"/.test(canvas) && /getElementById\('row-global-shortcut'\)[\s\S]{0,60}display = ''/.test(canvas), 'toggle shows in the desktop app only');
ok(/saveSetting\('globalShortcut', on\)/.test(canvas) && /toggleGlobalShortcut\(!!loadSetting\('globalShortcut'\)\)/.test(canvas), 'saved, and re-applied on launch (default off)');
ok(/action === 'screen-assist'\) screenAssist\(\)/.test(canvas) && /action === 'snap'\) snapShortcut\(\)/.test(canvas), 'global keys run screenAssist() / snapShortcut()');
ok(/function snapShortcut\(\) \{\s*if \(!copilotActive\)[^\n]*\n\s*copilotCapture\(\);/.test(canvas), 'Snap = the camera button\'s copilotCapture(), co-pilot mode only');
// in-page keys: Cmd+Option+Enter is checked BEFORE plain Cmd+Enter (it would match that too)
const kd = canvas.slice(canvas.indexOf('// ===== KEYBOARD SHORTCUTS ====='), canvas.indexOf('function quitApp()'));
const iSnap = kd.indexOf("e.altKey && e.key === 'Enter'"), iAssist = kd.indexOf("screenAssist();");
ok(iSnap > 0 && iAssist > iSnap && /e\.altKey && e\.key === 'Enter'\) \{\s*e\.preventDefault\(\);\s*snapShortcut\(\);/.test(kd), 'in-page Cmd+Option+Enter → Snap, checked first');
ok(/\(e\.metaKey \|\| e\.ctrlKey\) && e\.key === 'Enter'\) \{\s*e\.preventDefault\(\);\s*screenAssist\(\);/.test(kd), 'in-page Cmd+Enter unchanged');

console.log('global-shortcut: ' + n + ' checks passed');
