// GLOBAL SHORTCUT MODE (owner, 13 Oct): the overlay's shortcuts work from any app, without clicking into the overlay.
//   Cmd+Enter (Ctrl+Enter on Windows)              → Screen Assist (screenAssist())
//   Cmd+Option+Enter (Ctrl+Alt+Enter on Windows)   → Snap = the co-pilot camera (copilotCapture())
// A press only tells the page which action to run — the same functions the in-page keys and buttons call. It never
// shows, raises or focuses the window.
// The page owns the ON/OFF setting (saved with the other settings) and asks for it on every load; any page load
// first drops the shortcuts, so they are never held while no page is there to answer them.
// Pure: Electron's globalShortcut is passed in, so test/global-shortcut.js proves it without Electron.

const SHORTCUTS = [
  { accelerator: 'CommandOrControl+Enter', action: 'screen-assist' },
  { accelerator: 'CommandOrControl+Alt+Enter', action: 'snap' },
];
const ACCELERATOR = SHORTCUTS[0].accelerator;

function createGlobalShortcut({ globalShortcut, onFire, log }) {
  const _log = log || (() => {});
  const held = new Set(); // accelerators that are ours right now

  function status(errors) {
    const keys = {};
    for (const s of SHORTCUTS) keys[s.action] = held.has(s.accelerator);
    const out = { on: held.size > 0, accelerator: ACCELERATOR, keys };
    if (errors && errors.length) out.error = errors.join('; ');
    return out;
  }

  function enable() {
    const errors = [];
    for (const s of SHORTCUTS) {
      if (held.has(s.accelerator) && globalShortcut.isRegistered(s.accelerator)) continue; // never registered twice
      let okReg = false, error = '';
      try { okReg = globalShortcut.register(s.accelerator, () => { _log('[Shortcut] global', s.accelerator, '→', s.action); onFire(s.action); }); }
      catch (e) { error = (e && e.message) || String(e); }
      // register() returns false when another app already holds the keys (the OS gives no reason)
      if (!okReg && !error) error = 'taken by another app';
      if (okReg) held.add(s.accelerator); else { held.delete(s.accelerator); errors.push(s.accelerator + ' ' + error); }
      _log('[Shortcut] global', s.accelerator, okReg ? 'registered' : 'NOT registered: ' + error);
    }
    return status(errors);
  }

  function disable(why) {
    if (!held.size) return status();
    for (const acc of held) {
      try { globalShortcut.unregister(acc); } catch (e) { _log('[Shortcut] unregister failed:', acc, e && e.message); }
    }
    held.clear();
    _log('[Shortcut] global shortcuts released' + (why ? ' (' + why + ')' : ''));
    return status();
  }

  function set(want) { return want ? enable() : disable('setting off'); }

  return { set, enable, disable, status: () => status(), ACCELERATOR, SHORTCUTS };
}

module.exports = { createGlobalShortcut, ACCELERATOR, SHORTCUTS };
