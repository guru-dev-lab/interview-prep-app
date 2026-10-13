// GLOBAL SHORTCUT MODE (owner, 13 Oct): Cmd+Enter (Ctrl+Enter on Windows) runs Screen Assist from any app, without
// clicking into the overlay. The shortcut only tells the page to run its own Screen Assist — the same function the
// in-page Cmd+Enter and the camera button call. It never shows, raises or focuses the window.
// The page owns the ON/OFF setting (saved with the other settings) and asks for it on every load; any page load
// first drops the shortcut, so it is never held while no page is there to answer it.
// Pure: Electron's globalShortcut is passed in, so test/global-shortcut.js proves it without Electron.

const ACCELERATOR = 'CommandOrControl+Enter';

function createGlobalShortcut({ globalShortcut, onFire, log }) {
  const _log = log || (() => {});
  let on = false; // the shortcut is ours right now

  function status(extra) {
    return Object.assign({ on, accelerator: ACCELERATOR }, extra || {});
  }

  function enable() {
    if (on && globalShortcut.isRegistered(ACCELERATOR)) return status(); // never registered twice
    let okReg = false, error = '';
    try { okReg = globalShortcut.register(ACCELERATOR, () => { _log('[Shortcut] global Cmd+Enter → screen assist'); onFire(); }); }
    catch (e) { error = (e && e.message) || String(e); }
    // register() returns false when another app already holds the keys (the OS gives no reason)
    if (!okReg && !error) error = 'taken by another app';
    on = !!okReg;
    _log('[Shortcut] global', ACCELERATOR, on ? 'registered' : 'NOT registered: ' + error);
    return on ? status() : status({ error });
  }

  function disable(why) {
    if (!on) return status();
    try { globalShortcut.unregister(ACCELERATOR); } catch (e) { _log('[Shortcut] unregister failed:', e && e.message); }
    on = false;
    _log('[Shortcut] global', ACCELERATOR, 'released' + (why ? ' (' + why + ')' : ''));
    return status();
  }

  function set(want) { return want ? enable() : disable('setting off'); }

  return { set, enable, disable, status: () => status(), ACCELERATOR };
}

module.exports = { createGlobalShortcut, ACCELERATOR };
