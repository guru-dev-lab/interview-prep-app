// Global Shortcut Mode (owner, 13 Oct) — main-process logic with a stand-in globalShortcut, plus the wiring through
// main.js → preload.js → canvas.html. Free — no Electron, no model, no DB. Run: node test/global-shortcut.js
const assert = require('assert');
const fs = require('fs'), path = require('path');
const { createGlobalShortcut, ACCELERATOR } = require(path.join(__dirname, '..', 'electron', 'global-shortcut.js'));
let n = 0; const ok = (c, m) => { n++; assert(c, m); };

// stand-in for Electron's globalShortcut: one holder per accelerator, like the OS
function fakeGS(opts) {
  const held = new Map(); const calls = { register: 0, unregister: 0 };
  return {
    calls, held,
    register(acc, fn) { calls.register++; if (opts && opts.throws) throw new Error(opts.throws); if ((opts && opts.taken) || held.has(acc)) return false; held.set(acc, fn); return true; },
    unregister(acc) { calls.unregister++; held.delete(acc); },
    isRegistered(acc) { return held.has(acc); },
    press(acc) { const fn = held.get(acc); if (fn) fn(); return !!fn; }
  };
}

// ---- default OFF: nothing held until the page asks
let gs = fakeGS(), fired = 0;
let s = createGlobalShortcut({ globalShortcut: gs, onFire: () => fired++ });
ok(!s.status().on && gs.calls.register === 0, 'starts off, registers nothing');
ok(ACCELERATOR === 'CommandOrControl+Enter', 'Cmd+Enter on Mac, Ctrl+Enter on Windows');

// ---- ON: registered once, a press anywhere runs the action
let st = s.set(true);
ok(st.on && !st.error && gs.isRegistered(ACCELERATOR), 'ON registers the system shortcut');
ok(gs.press(ACCELERATOR) && fired === 1, 'a press runs the existing action');
s.set(true); s.set(true);
ok(gs.calls.register === 1, 'turning ON again never registers twice');

// ---- OFF: released at once, the press no longer reaches us
st = s.set(false);
ok(!st.on && !gs.isRegistered(ACCELERATOR) && gs.calls.unregister === 1, 'OFF releases it immediately');
ok(!gs.press(ACCELERATOR) && fired === 1, 'after OFF a press does nothing');
s.set(false);
ok(gs.calls.unregister === 1, 'OFF twice is harmless');

// ---- page load / quit drop it; ON again works
s.set(true); s.disable('page load');
ok(!gs.isRegistered(ACCELERATOR) && !s.status().on, 'disable (page load / quit) releases it');
ok(s.set(true).on, 'can be turned on again after a release');

// ---- failures are reported, never thrown
gs = fakeGS({ taken: true });
s = createGlobalShortcut({ globalShortcut: gs, onFire: () => {} });
st = s.set(true);
ok(!st.on && /taken by another app/.test(st.error), 'keys held by another app → off + reason');
gs = fakeGS({ throws: 'conversion failed' });
s = createGlobalShortcut({ globalShortcut: gs, onFire: () => {} });
st = s.set(true);
ok(!st.on && /conversion failed/.test(st.error), 'register throwing → off + its message, no crash');

// ---- wiring: main process sends a message only (never raises the window), preload exposes it, page uses it
const main = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const preload = fs.readFileSync(path.join(__dirname, '..', 'electron', 'preload.js'), 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'electron', 'package.json'), 'utf8'));
const canvas = fs.readFileSync(path.join(__dirname, '..', 'public', 'canvas.html'), 'utf8');
const fire = (main.match(/onFire:\s*\(\)\s*=>\s*\{[^\n]*\}/) || [''])[0];
ok(/webContents\.send\('global-shortcut', 'screen-assist'\)/.test(fire), 'shortcut sends screen-assist to the page');
ok(!/show\(|focus\(|moveTop\(/.test(fire), 'shortcut never shows or focuses the window');
ok(/ipcMain\.handle\('set-global-shortcut'/.test(main), 'main: set-global-shortcut handler');
ok(/app\.on\('will-quit'[\s\S]{0,120}globalCmdEnter\.disable[\s\S]{0,60}unregisterAll/.test(main), 'main: released on quit');
ok(/did-start-navigation[\s\S]{0,400}globalCmdEnter\.disable\('page load'\)/.test(main), 'main: released on every page load');
ok(pkg.build.files.includes('global-shortcut.js'), 'desktop build ships global-shortcut.js');
ok(/setGlobalShortcut:[^\n]*'set-global-shortcut'/.test(preload) && /onGlobalShortcut:[^\n]*'global-shortcut'/.test(preload), 'preload exposes both');
ok(/id="s-global-shortcut"[^>]*onchange="toggleGlobalShortcut\(this\.checked\)"/.test(canvas), 'Settings toggle wired');
ok(/id="row-global-shortcut" style="display:none"/.test(canvas) && /getElementById\('row-global-shortcut'\)[\s\S]{0,60}display = ''/.test(canvas), 'toggle shows in the desktop app only');
ok(/saveSetting\('globalShortcut', on\)/.test(canvas) && /toggleGlobalShortcut\(!!loadSetting\('globalShortcut'\)\)/.test(canvas), 'saved, and re-applied on launch (default off)');
ok(/onGlobalShortcut\(function\(action\) \{ if \(action === 'screen-assist' && globalShortcutOn\) screenAssist\(\); \}\)/.test(canvas), 'shortcut runs the same screenAssist()');
ok(/\(e\.metaKey \|\| e\.ctrlKey\) && e\.key === 'Enter'\) \{\s*e\.preventDefault\(\);\s*screenAssist\(\);/.test(canvas), 'in-page Cmd+Enter unchanged');

console.log('global-shortcut: ' + n + ' checks passed');
