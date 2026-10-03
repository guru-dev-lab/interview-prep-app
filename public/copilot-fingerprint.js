// Screen fingerprint — ONE copy shared by the browser (canvas.html <script>) and node tests.
// A frame is reduced to a tiny grayscale thumbnail (32×18); two thumbnails differ when enough pixels moved.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.CopilotFingerprint = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  var W = 32, H = 18;
  var PIXEL_DELTA = 24;     // one pixel counts as moved when its gray value shifts by more than this (0–255)
  var CHANGED_SHARE = 0.03; // the frame counts as changed when more than 3% of pixels moved

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

  // Browser only: draw the video/canvas source into a 32×18 canvas and return its gray values.
  function fingerprintFrom(source) {
    var c = document.createElement('canvas'); c.width = W; c.height = H;
    var ctx = c.getContext('2d'); ctx.drawImage(source, 0, 0, W, H);
    var d = ctx.getImageData(0, 0, W, H).data, out = new Array(W * H);
    for (var i = 0; i < out.length; i++) out[i] = (d[i * 4] * 299 + d[i * 4 + 1] * 587 + d[i * 4 + 2] * 114) / 1000;
    return out;
  }

  return { fingerprintChanged: fingerprintChanged, matchPrint: matchPrint, fingerprintFrom: fingerprintFrom, W: W, H: H };
});
