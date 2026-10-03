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

  var NEW_PAGE_REGION = 0.09; // the changed pixels must spread over ≥ 9% of the frame to be a NEW PAGE (measured 3 Oct:
                              // page→page regions 11–34%; hover 2.2%, tooltip 0.7%, popup 7.4%, cursor 0 — all "same page")

  // How much moved, and how widely: share of pixels moved, and the bounding box of those pixels as a share of the frame.
  function changedRegion(prev, next) {
    if (!prev || !next || prev.length !== next.length) return { share: 1, bbox: 1 };
    var moved = 0, minx = W, maxx = -1, miny = H, maxy = -1;
    for (var i = 0; i < next.length; i++) if (Math.abs(next[i] - prev[i]) > PIXEL_DELTA) {
      moved++; var x = i % W, y = (i / W) | 0;
      if (x < minx) minx = x; if (x > maxx) maxx = x; if (y < miny) miny = y; if (y > maxy) maxy = y;
    }
    return { share: moved / next.length, bbox: maxx < 0 ? 0 : ((maxx - minx + 1) * (maxy - miny + 1)) / (W * H) };
  }

  // Anything moved at all (stability between two checks: a hover appearing counts as movement — wait for it to settle)
  function fingerprintChanged(prev, next) {
    if (!next) return false;
    if (!prev || prev.length !== next.length) return true;
    return changedRegion(prev, next).share > CHANGED_SHARE;
  }

  // A different page: enough moved AND spread across the content, not a hover / tooltip / popup / cursor
  function isNewPage(prev, next) {
    if (!next) return false;
    if (!prev || prev.length !== next.length) return true;
    var r = changedRegion(prev, next);
    return r.share > CHANGED_SHARE && r.bbox >= NEW_PAGE_REGION;
  }

  // Which earlier capture (if any) is this frame? prints = [{ key, print }]; returns the key or null.
  function matchPrint(prints, print) {
    for (var i = (prints || []).length - 1; i >= 0; i--) if (!isNewPage(prints[i].print, print)) return prints[i].key;
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

  return { fingerprintChanged: fingerprintChanged, changedRegion: changedRegion, isNewPage: isNewPage, matchPrint: matchPrint, stableNewScreen: stableNewScreen, fingerprintFrom: fingerprintFrom, W: W, H: H };
});
