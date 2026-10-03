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
ok(/id="copilot-count"/.test(src) && /function copilotNoteCapture/.test(src) && /copilotNoteCapture\(\)/.test(src.slice(src.indexOf("msg.type === 'copilot_captured'"), src.indexOf("msg.type === 'copilot_captured'") + 400)), 'the pill counts captured pages and flashes on each new one (owner: "only then I would be sure to move on")');
{ const cam = src.slice(src.indexOf('async function copilotCapture()'), src.indexOf('async function copilotCaptureNow('));
  ok(/copilotCaptureNow\(false\)/.test(cam) && !/copilotSend\(/.test(cam) && !/pressed: true/.test(cam) && /capture: !auto/.test(src), 'camera = capture only (never an answer); Assist/typed/heard question answer'); }
ok(/type: 'copilot_watch'/.test(src) && /watchStats/.test(src), 'the auto-capture watcher reports its health to the server (ticks, stable, errors)');
ok(/COPILOT_WATCH_MS = 1000/.test(src), 'watcher ticks every second (a page settles in ~2 s)');
ok(/function captureFrame\(stream, maxW\)/.test(src) && /captureFrame\(stream, COPILOT_CAPTURE_W\)/.test(src) && /COPILOT_CAPTURE_W = 1568/.test(src), 'co-pilot captures at 1568 wide (the most the model uses), other callers unchanged');
{ const cap = src.slice(src.indexOf('async function copilotCaptureNow('), src.indexOf('async function copilotCaptureNow(') + 2600);
  ok(/copilotPendingKeys/.test(cap) && cap.indexOf('copilotNoteCapture(') < cap.indexOf("fetch('/api/sessions/' + SESSION_ID + '/copilot'"), 'the counter moves the moment the frame is grabbed (owner leaves the page on seeing it), before the read');
  ok(/copilotPendingKeys\.delete\(/.test(cap) && /copilotUnnoteCapture\(\)/.test(cap), 'a refused/unchanged capture takes the count back'); }
ok(/msg\.type === 'copilot_captured'[^\n]*copilotPendingKeys\.has\(msg\.key\)/.test(src), 'the read confirmation does not double-count the sender\'s own capture');
ok(/id="copilot-count"[^>]*onclick="toggleCaptureList\(\)"/.test(src) && /function toggleCaptureList/.test(src), 'clicking the counter opens the list of captured pages');
ok(/\/copilot\/screens/.test(src) && /copilot-capture-list/.test(src) && /not read yet/.test(src), 'the list shows each capture: thumbnail, time, read or not, first line');
ok(/function captureThumb\(/.test(src) && /CopilotFingerprint\.W/.test(src), 'thumbnails are drawn from the local fingerprints (no image download)');
{ const cap = src.slice(src.indexOf('async function copilotCaptureNow('), src.indexOf('async function copilotCaptureNow(') + 2600);
  ok(!/Already captured this page/.test(cap) && /Captured again/.test(cap), 'camera always takes again (no "already captured" refusal); only auto skips known pages'); }
ok(/id="copilot-pause"/.test(src) && /function toggleCopilotPause/.test(src) && /copilotAutoPaused/.test(src), 'play/pause on the pill: the owner tells the watcher when to stop and continue');
ok(/copilotActive && copilotHistory && electronLive && !copilotAutoPaused/.test(src), 'paused = the watcher captures nothing');
{ const cs = src.slice(src.indexOf('function copilotCardStart('), src.indexOf('function copilotCardStart(') + 1200);
  ok(!/copilotNoteCapture\(/.test(cs), 'the counter counts collected pages only (camera + auto), never an Assist frame'); }
ok(/paused: copilotAutoPaused/.test(src), 'the watcher reports paused in its health line');
ok(/function styleCopilotCard\(/.test(src) && /cp-q/.test(src) && /cp-a/.test(src) && /styleCopilotCard\(c\.el\)/.test(src), 'co-pilot cards style the question line and the Answer line so he can scan and speak');
ok(/cp-block/.test(src) && /function styleCopilotCard\([\s\S]{0,1800}cp-block/.test(src), 'each question + answer is wrapped in its own card inside the co-pilot answer');
ok(/nextElementSibling/.test(src.slice(src.indexOf('function styleCopilotCard('), src.indexOf('function styleCopilotCard(') + 1800)), 'the line right after a question line is the result line (label or not)');
ok(/\.sh-kw\{color:#569CD6/.test(src) && !/#FF6188/.test(src) && /body\.light-mode \.sh-kw\{color:#0000FF/.test(src), 'code blocks use the VS Code Dark+ / Light+ palettes (owner: the red is straining)');
{ // the question-line matcher must accept the shapes the model actually writes (3 Oct: "Part 9 — Q1 — …" broke the cards)
  const m = src.match(/var QLINE = (\/.*?\/i);/); ok(!!m, 'QLINE regex is declared in one place');
  const QLINE = m ? eval(m[1]) : /$^/;
  ['Page 7 — Question 1 — Dallas cost', 'Part 9 — Q1 — Why is INV-1043 disputed?', 'Question 2: best carrier', 'Q3 — Dallas pallets', 'Screen 8 — Question — cheapest carrier', 'Page 8 — Question — cheapest'].forEach(t => ok(QLINE.test(t), 'matches: ' + t));
  ['Quarterly numbers look fine', 'Answer: $14,426', '140 pallets × $92'].forEach(t => ok(!QLINE.test(t), 'does not match: ' + t));
  ok(/QLINE\.test\(t\)/.test(src.slice(src.indexOf('function styleCopilotCard('), src.indexOf('function styleCopilotCard(') + 900)), 'styleCopilotCard uses QLINE'); }
console.log('ALL PASS (meeting co-pilot overlay wiring, ' + n + ' checks)');
