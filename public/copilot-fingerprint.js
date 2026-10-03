// Screen fingerprint — ONE copy shared by the browser (canvas.html <script>) and node tests.
// A frame is reduced to a tiny grayscale thumbnail (32×18); two thumbnails differ when enough pixels moved.
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.CopilotFingerprint = api; // always set the global too (a page may have a `module` object)
})(typeof self !== 'undefined' ? self : (typeof window !== 'undefined' ? window : this), function () {
  // Tuned 3 Oct against the owner's real case: the captured frame is his whole display and the shared page is only
  // ~1/3 of it. Measured on the 8-page pack at that size — 32×18/Δ24: closest pages 0.87% apart (missed under a 3%
  // bar); 64×36/Δ12: closest pages 2.4% apart, same-page noise (menu-bar clock) 0. Bar 1%.
  var W = 64, H = 36;
  var PIXEL_DELTA = 12;     // one pixel counts as moved when its gray value shifts by more than this (0–255)
  var CHANGED_SHARE = 0.01; // the frame counts as changed when more than 1% of pixels moved

  function fingerprintChanged(prev, next) {
    if (!next) return false;
    if (!prev || prev.length !== next.length) return true;
    var moved = 0;
    for (var i = 0; i < next.length; i++) if (Math.abs(next[i] - prev[i]) > PIXEL_DELTA) moved++;
    return moved / next.length > CHANGED_SHARE;
  }

  // Which earlier capture (if any) is this frame? prints = [{ key, print }]; returns the key or null.
  function matchPrint(prints, print) {
    for (var i = (prints || []).length - 1; i >= 0; i--) if (!fingerprintChanged(prints[i].print, print)) return prints[i].key;
    return null;
  }

  // Auto-capture: true when this frame is a NEW page (matches no earlier capture) and has held still since the last
  // check — a scroll or page transition is never captured mid-way. The caller registers the print once it sends it.
  function stableNewScreen(state, print, prints) {
    if (matchPrint(prints, print)) { state.prev = null; return false; }
    var stable = !!(state.prev && !fingerprintChanged(state.prev, print));
    state.prev = print;
    return stable;
  }

  // Browser only: draw the video/canvas source into a 32×18 canvas and return its gray values.
  function fingerprintFrom(source) {
    var c = document.createElement('canvas'); c.width = W; c.height = H;
    var ctx = c.getContext('2d'); ctx.drawImage(source, 0, 0, W, H);
    var d = ctx.getImageData(0, 0, W, H).data, out = new Array(W * H);
    for (var i = 0; i < out.length; i++) out[i] = (d[i * 4] * 299 + d[i * 4 + 1] * 587 + d[i * 4 + 2] * 114) / 1000;
    return out;
  }

  return { fingerprintChanged: fingerprintChanged, matchPrint: matchPrint, stableNewScreen: stableNewScreen, fingerprintFrom: fingerprintFrom, W: W, H: H };
});
