// Overlay wiring for the meeting co-pilot (public/canvas.html) — source-level checks, free.
// Each check names the behaviour the page must have; a regression removes the line and the check fails.
const assert = require('assert');
const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'public', 'canvas.html'), 'utf8');
let n = 0; const ok = (c, m) => { n++; assert(c, m); };

ok(/<script src="\/copilot-fingerprint\.js"><\/script>/.test(src), 'page loads the shared screen fingerprint (one copy for browser + tests)');
ok(/id="copilot-history"/.test(src) && /type="checkbox"/.test(src.slice(src.indexOf('id="copilot-float"'), src.indexOf('id="copilot-float"') + 1500)), 'History checkbox sits on the co-pilot pill');
ok(/saveSetting\('copilotHistory'/.test(src) && /loadSetting\('copilotHistory'\)/.test(src), 'History choice is saved and restored');
ok(/type: 'update_settings', copilot: /.test(src), 'mode + history go to the server over the live socket');
ok(!/copilotOnTranscript\(/.test(src) && !/COPILOT_AUTO_DELAY/.test(src), 'the 3-second speech buffer is gone');
ok(/if \(copilotActive && msg\.text\) copilotSend\(\{ ask: msg\.text \}\)/.test(src.slice(src.indexOf("msg.type === 'question_detected'"), src.indexOf("msg.type === 'question_detected'") + 700)), 'a detected question in co-pilot mode fires co-pilot with the question');
ok(/copilot_start/.test(src) && /copilot_delta/.test(src) && /copilot_done/.test(src), 'cards render from the streamed start/delta/done messages');
ok(!/copilot_step/.test(src) && !/copilotPendingLocal/.test(src), 'old one-shot card path removed (no double cards)');
ok(/CopilotFingerprint\.fingerprintFrom\(/.test(src) && /copilotPrints\.push\(/.test(src), 'frame is fingerprinted; a new screen is remembered and sent');
ok(/screenChanged:/.test(src) && /pressed:/.test(src) && /ask:/.test(src), 'request carries ask / pressed / screenChanged');
ok(!/copilot\/reset/.test(src), 'no per-switch reset call (the call log is per call)');
ok(/CopilotFingerprint\.matchPrint\(/.test(src) && /screenKey:/.test(src), 'camera press reuses a screen captured earlier in the call (screenKey)');
ok(/var SOLID = '[^']*\.copilot-float\.show/.test(src), 'the co-pilot pill is a SOLID element (clickable through the click-through overlay)');
ok(/\.copilot-float[^\n]*-webkit-app-region:no-drag/.test(src) || /\.copilot-float,[^\n]*\{-webkit-app-region:no-drag/.test(src), 'the pill is no-drag (a click is a click, not a window drag)');
ok(!/^\.copilot-float\{[^\n]*blur\(60px\)/m.test(src), 'the pill is not a 60px blur glass (owner: blurry)');
ok(/var held = [^\n]*e\.buttons/.test(src) && /var want = !solid && !held/.test(src), 'click-through never switches on while a mouse button is held (resize/drag stuck with the mouse, 3 Oct)');
ok(/addEventListener\('mouseup', function\(e\) \{ lastEvt = e;/.test(src), 'mouse-up re-evaluates click-through so a finished drag releases cleanly');
ok(src.indexOf('id="copilot-float"') > src.indexOf('class="feed-wrap"'), 'the pill comes AFTER the feed in the DOM (Electron drag regions win by DOM order; a pill before the feed gets its clicks eaten as a window drag)');
ok(/captureError:/.test(src) && /frame\.error/.test(src), 'a failed capture reports WHY to the server (never a silent no-image)');
ok(/copilot-screen-chip/.test(src) && /msg\.screen/.test(src), 'each card shows what happened to the screen: captured / same page / none');
ok(/lastCaptureCanvas/.test(src) && /CopilotFingerprint\.fingerprintFrom\(lastCaptureCanvas\)/.test(src) && !/new Image\(\); img\.src = image/.test(src), 'fingerprint reads the capture canvas, never an image (captureFrame returns raw base64, so an <img> was always broken — 3 Oct live log)');
ok(/if \(ev\.buttons === 0\) return onUp\(\)/.test(src), 'corner resize ends on the first move with no button held (lost mouse-up)');
ok(/if \(isDragging && e\.buttons === 0\) \{ isDragging = false; return; \}/.test(src), 'toolbar drag ends on the first move with no button held');
ok(/function copilotWatchTick/.test(src) && /copilotActive && copilotHistory && electronLive/.test(src), 'auto-capture watcher runs only in co-pilot mode with History on, while live');
ok(/CopilotFingerprint\.stableNewScreen\(/.test(src) && /auto: true/.test(src), 'a settled new page is sent with auto: true (read in the background, no answer card)');
ok(/msg\.type === 'copilot_captured'/.test(src) && /Page captured/.test(src), 'a captured page shows a short toast');
ok(/id="copilot-count"/.test(src) && /function copilotNoteCapture/.test(src) && /copilotNoteCapture\(\)/.test(src.slice(src.indexOf("msg.type === 'copilot_captured'"), src.indexOf("msg.type === 'copilot_captured'") + 200)), 'the pill counts captured pages and flashes on each new one (owner: "only then I would be sure to move on")');
{ const cam = src.slice(src.indexOf('async function copilotCapture()'), src.indexOf('async function copilotCaptureNow('));
  ok(/copilotCaptureNow\(false\)/.test(cam) && !/copilotSend\(/.test(cam) && !/pressed: true/.test(cam) && /capture: !auto/.test(src), 'camera = capture only (never an answer); Assist/typed/heard question answer'); }
ok(/type: 'copilot_watch'/.test(src) && /watchStats/.test(src), 'the auto-capture watcher reports its health to the server (ticks, stable, errors)');
ok(/COPILOT_WATCH_MS = 1500/.test(src), 'watcher ticks every 1.5 s (owner: slow when changing pages)');
ok(/function captureFrame\(stream, maxW\)/.test(src) && /captureFrame\(stream, COPILOT_CAPTURE_W\)/.test(src) && /COPILOT_CAPTURE_W = 1568/.test(src), 'co-pilot captures at 1568 wide (the most the model uses), other callers unchanged');
console.log('ALL PASS (meeting co-pilot overlay wiring, ' + n + ' checks)');
