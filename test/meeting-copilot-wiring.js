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
ok(/COPILOT_WATCH_MS = 700/.test(src), 'watcher ticks every 0.7 s (a page settles in ~1.4 s — Part 2 was scrolled past in under 2 s, 3 Oct)');
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
{ // "Page # should not be part.. it can be a tag header" (3 Oct 11:48)
  const m = src.match(/var QSPLIT = (\/.*?\/i);/); ok(!!m, 'QSPLIT regex declared once');
  const QSPLIT = m ? eval(m[1]) : /$^/;
  const r = 'Page 7 — Question 1 — Dallas cost'.match(QSPLIT); ok(!!r && /^Page 7$/i.test(r[1]) && /^Question 1 — Dallas cost$/.test(r[2]), 'page prefix splits off: tag "Page 7", title "Question 1 — Dallas cost"');
  const r2 = 'Part 9 — Q1 — Why disputed?'.match(QSPLIT); ok(!!r2 && /^Part 9$/i.test(r2[1]) && /^Q1 — Why disputed\?$/.test(r2[2]), 'part prefix too');
  ok(!('Question 2: best carrier'.match(QSPLIT)), 'no prefix → no split');
  ok(/cp-tag/.test(src) && /class="cp-tag"/.test(src.slice(src.indexOf('function styleCopilotCard('), src.indexOf('function styleCopilotCard(') + 2500)), 'the card renders the page as a small tag'); }
{ const cap = src.slice(src.indexOf('async function copilotCaptureNow('), src.indexOf('async function copilotCaptureNow(') + 3200);
  ok(/setStealth\(true\)/.test(cap) && cap.indexOf('setStealth(true)') < cap.indexOf('captureFrame(stream, COPILOT_CAPTURE_W)'), 'the overlay is hidden from the frame before every capture (3 Oct: a 57 KB Part 3 capture had the panel over the table)');
  ok(/copilotPrints = copilotPrints\.filter/.test(cap), 'a refused or failed capture forgets the print so the page is retried (3 Oct: "Go Live first" refusals left pages marked known)'); }
{ const sc = src.slice(src.indexOf('function styleCopilotCard('), src.indexOf('function styleCopilotCard(') + 3000);
  ok(/star-inline/.test(sc) && /insertBefore\(res, /.test(sc) && !/RESULT\\b/.test(sc), 'the Result line is found by its RESULT chip element (the chip runs into the next word, so a word-boundary match never fired), and lifted to the top'); }
ok(/\.sc-card-a pre\{background:#1E1E1E;/.test(src) && /font:400 12\.5px/.test(src.slice(src.indexOf('.sc-card-a pre{'), src.indexOf('.sc-card-a pre{') + 400)), 'code blocks: solid VS Code background, bigger monospace (owner: make the code part more visible)');
ok(!/code-open-btn/.test(src) && !/openCodeInBrowser/.test(src) && !/\/api\/code-view/.test(src), 'no Open-in-browser button (owner: "Not open in chrome", 3 Oct)');
ok(!/\.sc-card-a pre code\{[^}]*font-size:11px/.test(src) && /\.code-content\{flex:1;color:#D4D4D4\}/.test(src) && /\.sh-kw\{color:#569CD6;font-weight:600\}/.test(src), 'code text: no 11px pin, VS Code base colour, bold keywords (owner: not the same colouring as the sample)');
ok(/codeSz = Math\.max\(11, canvasFontSize\)/.test(src), 'code size follows the font setting one-to-one, never smaller');
ok(/var copilotHistory = loadSetting\('copilotHistory'\) !== false;/.test(src), 'Hist defaults ON in co-pilot mode (owner, 3 Oct); a saved off stays off');
ok(/sendCopilotSettings\(\);/.test(src.slice(src.indexOf("type: 'update_settings', maxLines: settingsMaxLines, followUps"), src.indexOf("type: 'update_settings', maxLines: settingsMaxLines, followUps") + 300)), 'co-pilot flags are re-sent on every live connect, so toggling before Go Live still works');
ok(/electronLive = true; copilotWatchSync\(\);/.test(src), 'the watcher starts the moment the call goes live if co-pilot is already on');
ok(/function deleteCapture\(/.test(src) && /method: 'DELETE'/.test(src) && /cap-del/.test(src), 'each capture in the list has an × that deletes it (owner, 3 Oct)');
ok(/copilotPrints = copilotPrints\.filter\(function \(x\) \{ return x\.key !== key; \}\)/.test(src.slice(src.indexOf('function deleteCapture('), src.indexOf('function deleteCapture(') + 1200)) && /copilotUnnoteCapture\(\)/.test(src.slice(src.indexOf('function deleteCapture('), src.indexOf('function deleteCapture(') + 1200)), 'a deleted capture leaves the counter and the known-pages memory, so it can be retaken');
{ const cf = src.slice(src.indexOf('function captureFrame(stream, maxW)'), src.indexOf('function captureFrame(stream, maxW)') + 2600);
  ok(/CopilotFingerprint\.overlayRect\(/.test(cf) && /overlay, ignore/.test(cf) && cf.indexOf('overlayRect(') < cf.indexOf('lastFrameSig = frameSignature(canvas)'), 'the overlay masks its own rectangle in the frame before the fingerprint and the stored image (co-pilot captures)'); }
console.log('ALL PASS (meeting co-pilot overlay wiring, ' + n + ' checks)');
