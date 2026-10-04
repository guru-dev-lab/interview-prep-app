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
ok(/var held = [^\n]*e\.buttons/.test(src) && /return !solid && !held/.test(src), 'click-through never switches on while a mouse button is held (resize/drag stuck with the mouse, 3 Oct)');
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
ok(/function captureFrame\(stream, maxW, opts\)/.test(src) && /captureFrame\(stream, COPILOT_CAPTURE_W/.test(src) && /COPILOT_CAPTURE_W = 1568/.test(src), 'co-pilot captures at 1568 wide (the most the model uses), other callers unchanged');
{ const cap = src.slice(src.indexOf('async function copilotCaptureNow('), src.indexOf('async function copilotCaptureNow(') + 9000);
  ok(/copilotPendingKeys/.test(cap) && cap.indexOf('copilotNoteCapture(') < cap.indexOf("fetch('/api/sessions/' + SESSION_ID + '/copilot'"), 'the counter moves the moment the frame is grabbed (owner leaves the page on seeing it), before the read');
  ok(/copilotPendingKeys\.delete\(/.test(cap) && /copilotUnnoteCapture\(\)/.test(cap), 'a refused/unchanged capture takes the count back'); }
ok(/msg\.type === 'copilot_captured'[^\n]*copilotPendingKeys\.has\(msg\.key\)/.test(src), 'the read confirmation does not double-count the sender\'s own capture');
ok(/id="copilot-count"[^>]*onclick="toggleCaptureList\(\)"/.test(src) && /function toggleCaptureList/.test(src), 'clicking the counter opens the list of captured pages');
ok(/\/copilot\/screens/.test(src) && /copilot-capture-list/.test(src) && /not read yet/.test(src), 'the list shows each capture: thumbnail, time, read or not, first line');
ok(/function captureThumb\(/.test(src) && /CopilotFingerprint\.W/.test(src), 'thumbnails are drawn from the local fingerprints (no image download)');
{ const cap = src.slice(src.indexOf('async function copilotCaptureNow('), src.indexOf('async function copilotCaptureNow(') + 9000);
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
{ const cap = src.slice(src.indexOf('async function copilotCaptureNow('), src.indexOf('async function copilotCaptureNow(') + 9000);
  ok(/setStealth\(true\)/.test(cap) && cap.indexOf('setStealth(true)') < cap.indexOf('captureFrame(stream, COPILOT_CAPTURE_W'), 'the overlay is hidden from the frame before every capture (3 Oct: a 57 KB Part 3 capture had the panel over the table)');
  ok(/copilotPrints = copilotPrints\.filter/.test(cap), 'a refused or failed capture forgets the print so the page is retried (3 Oct: "Go Live first" refusals left pages marked known)'); }
{ const sc = src.slice(src.indexOf('function styleCopilotCard('), src.indexOf('function styleCopilotCard(') + 3000);
  ok(/star-inline/.test(sc) && /insertBefore\(res, /.test(sc) && !/RESULT\\b/.test(sc), 'the Result line is found by its RESULT chip element (the chip runs into the next word, so a word-boundary match never fired), and lifted to the top'); }
ok(/\.sc-card-a pre\{background:#1E1E1E;/.test(src) && /font:400 13\.5px/.test(src.slice(src.indexOf('.sc-card-a pre{'), src.indexOf('.sc-card-a pre{') + 400)), 'code blocks: solid VS Code background, bigger monospace (owner: make the code part more visible; 13.5px since 4 Oct)');
ok(!/code-open-btn/.test(src) && !/openCodeInBrowser/.test(src) && !/\/api\/code-view/.test(src), 'no Open-in-browser button (owner: "Not open in chrome", 3 Oct)');
ok(!/\.sc-card-a pre code\{[^}]*font-size:11px/.test(src) && /\.code-content\{flex:1;color:#D4D4D4\}/.test(src) && /\.sh-kw\{color:#569CD6;font-weight:600\}/.test(src), 'code text: no 11px pin, VS Code base colour, bold keywords (owner: not the same colouring as the sample)');
ok(/codeSz = Math\.max\(11, canvasFontSize\)/.test(src), 'code size follows the font setting one-to-one, never smaller');
ok(/var copilotHistory = loadSetting\('copilotHistory'\) !== false;/.test(src), 'Hist defaults ON in co-pilot mode (owner, 3 Oct); a saved off stays off');
ok(/sendCopilotSettings\(\);/.test(src.slice(src.indexOf("type: 'update_settings', maxLines: settingsMaxLines, followUps"), src.indexOf("type: 'update_settings', maxLines: settingsMaxLines, followUps") + 300)), 'co-pilot flags are re-sent on every live connect, so toggling before Go Live still works');
ok(/electronLive = true; copilotWatchSync\(\);/.test(src), 'the watcher starts the moment the call goes live if co-pilot is already on');
ok(/function deleteCapture\(/.test(src) && /method: 'DELETE'/.test(src) && /cap-del/.test(src), 'each capture in the list has an × that deletes it (owner, 3 Oct)');
ok(/copilotPrints = copilotPrints\.filter\(function \(x\) \{ return x\.key !== key; \}\)/.test(src.slice(src.indexOf('function deleteCapture('), src.indexOf('function deleteCapture(') + 1200)) && /copilotUnnoteCapture\(\)/.test(src.slice(src.indexOf('function deleteCapture('), src.indexOf('function deleteCapture(') + 1200)), 'a deleted capture leaves the counter and the known-pages memory, so it can be retaken');
{ const cf = src.slice(src.indexOf('function captureFrame(stream, maxW'), src.indexOf('function captureFrame(stream, maxW') + 4200);
  ok(/CopilotFingerprint\.overlayRect\(/.test(cf) && /overlay, ignore/.test(cf) && cf.indexOf('overlayRect(') < cf.indexOf('lastFrameSig = frameSignature(canvas)'), 'the overlay masks its own rectangle in the frame before the fingerprint and the stored image (co-pilot captures)'); }
ok(/lastMaskRect = r/.test(src) && /mask: lastMaskRect/.test(src), 'every co-pilot capture reports the mask rectangle it painted (or none), so the log says what happened');
ok(!/screen\.availLeft/.test(src.slice(src.indexOf('function captureFrame(stream, maxW)'), src.indexOf('function captureFrame(stream, maxW)') + 2600)), 'no work-area offset: the frame is the full display, window coords are display coords');
ok(/cap-preview/.test(src) && /lastCaptureCanvas/.test(src.slice(src.indexOf('async function toggleCaptureList('), src.indexOf('async function toggleCaptureList(') + 2600)), 'the capture list shows a real preview of the last frame sent (owner: "still there" — a 64px thumbnail cannot settle it)');
ok(/copilotWinOrigin = \{ x: e\.screenX - e\.clientX, y: e\.screenY - e\.clientY \}/.test(src), 'the window origin comes from mouse events (window.screenX is stale in this Electron build: log showed 2184,80 420x650 after moves)');
{ const cf = src.slice(src.indexOf('function captureFrame(stream, maxW'), src.indexOf('function captureFrame(stream, maxW') + 4200);
  ok(/overlayRect\(w, h, screen\.width, screen\.height, copilotWinOrigin\.x, copilotWinOrigin\.y, document\.documentElement\.clientWidth, document\.documentElement\.clientHeight\)/.test(cf), 'the mask uses the true origin and the live content size'); }
{ const cap = src.slice(src.indexOf('async function copilotCaptureNow('), src.indexOf('async function copilotCaptureNow(') + 9000);
  ok(/setOpacity\(0\.2\)/.test(cap) && /setOpacity\(1\)/.test(cap) && /captureFrame\(stream, COPILOT_CAPTURE_W, blinked \? \{ noMask: true \} : undefined\)/.test(cap), 'a camera press blinks the panel away and grabs the full page underneath (owner, 3 Oct: "it will not block what is behind?")');
  ok(!/if \(auto\)[\s\S]{0,400}setOpacity\(0\)/.test(cap) || /!auto/.test(cap.slice(0, cap.indexOf('setOpacity(0)'))), 'auto captures never blink'); }
ok(/function captureFrame\(stream, maxW, opts\)/.test(src) && /opts && opts\.noMask/.test(src), 'captureFrame can skip the mask when the panel is already out of the frame');
{ const cap = src.slice(src.indexOf('async function copilotCaptureNow('), src.indexOf('async function copilotCaptureNow(') + 9000);
  ok(/electronAPI\.captureDisplay\(COPILOT_CAPTURE_W\)/.test(cap) && cap.indexOf('captureDisplay(') < cap.indexOf('getScreenStream()'), 'co-pilot captures through the desktop app (screenshot backend, honours the eye) when the app offers it, else the old path');
  ok(/function frameFromShot\(/.test(src) && /data:image\/jpeg;base64,/.test(src.slice(src.indexOf('function frameFromShot('), src.indexOf('function frameFromShot(') + 900)), 'the app shot is loaded as a proper data URL into the capture canvas (no mask needed: the overlay is not in it)'); }
const main = require('fs').readFileSync(require('path').join(__dirname, '..', 'electron', 'main.js'), 'utf8');
const pre = require('fs').readFileSync(require('path').join(__dirname, '..', 'electron', 'preload.js'), 'utf8');
ok(/ipcMain\.handle\('capture-display'/.test(main) && /desktopCapturer\.getSources\(\{ types: \['screen'\], thumbnailSize/.test(main) && /ipcMain\.handle\('get-bounds'/.test(main), 'desktop app: capture-display via desktopCapturer thumbnails + get-bounds');
ok(/captureDisplay: \(maxW\) => ipcRenderer\.invoke\('capture-display', maxW\)/.test(pre) && /getBounds: \(\) => ipcRenderer\.invoke\('get-bounds'\)/.test(pre), 'preload exposes captureDisplay + getBounds');
ok(/"version": "1\.1\.4"/.test(require('fs').readFileSync(require('path').join(__dirname, '..', 'electron', 'package.json'), 'utf8')), 'desktop version 1.1.4');
ok(/\/\\d\/\.test\(sp\[1\]\)/.test(src.slice(src.indexOf('function styleCopilotCard('), src.indexOf('function styleCopilotCard(') + 1600)), 'a page tag with no number is not shown (single-page test showed an empty PAGE chip)');

// ---- SAY button in co-pilot mode (owner, 3 Oct): one brain — the server pulls what they just asked from the call, the overlay
// answers it through the co-pilot door with résumé + bank; a press on an already-answered ask jumps to that card
const srv = require('fs').readFileSync(require('path').join(__dirname, '..', 'server.js'), 'utf8');
const sayH = srv.slice(srv.indexOf("msg.type === 'what_should_i_say'"), srv.indexOf("msg.type === 'what_should_i_say'") + 6000);
ok(/if \(ws\._copilotMode\)/.test(sayH) && /type: 'copilot_say'/.test(sayH), 'Say in co-pilot mode routes to the co-pilot (copilot_say), never the QA jump/bank path');
ok(/_copilotAskTs/.test(sayH) && /_copilotAskTs/.test(srv.slice(srv.indexOf('question routed to co-pilot'), srv.indexOf('question routed to co-pilot') + 400)), 'what counts as "just asked" starts after the last co-pilot ask (heard or say)');
const ep = srv.slice(srv.indexOf("app.post('/api/sessions/:id/copilot'"), srv.indexOf("app.post('/api/sessions/:id/copilot'") + 9000);
ok(/const say = !!req\.body\.say/.test(ep) && /say,/.test(ep.slice(ep.indexOf('buildCopilotPrompt('), ep.indexOf('buildCopilotPrompt(') + 400)), 'endpoint passes say into the prompt');
ok(/FROM questions WHERE session_id = \$1 AND answer != ''/.test(ep) && /bank,/.test(ep.slice(ep.indexOf('buildCopilotPrompt('), ep.indexOf('buildCopilotPrompt(') + 400)), 'endpoint loads the Q&A bank and passes it to the prompt');
ok(/maxTokensFor\(mode, say\)/.test(ep), 'say gets the larger token room in regular mode');
ok(/type: 'copilot_start', cardId, ask, mode, say,/.test(ep), 'copilot_start tells the overlay this card is a Say');
const sayC = src.slice(src.indexOf("msg.type === 'copilot_say'"), src.indexOf("msg.type === 'copilot_say'") + 300);
ok(/copilotSay\(msg\.text\)/.test(sayC), 'overlay handles copilot_say');
const sayF = src.slice(src.indexOf('function copilotSay('), src.indexOf('function copilotSay(') + 1400);
ok(/copilotSend\(\{ ask: /.test(sayF) && /say: true/.test(sayF) && /pressed: true/.test(sayF), 'copilotSay goes through the one co-pilot door as a say press');
ok(/90000/.test(sayF) && /scrollIntoView/.test(sayF), 'same ask already answered in the last 90 s: jump to that card, no second call');
ok(/say: !!opts\.say/.test(src.slice(src.indexOf('async function copilotSend('), src.indexOf('async function copilotSend(') + 900)), 'request body carries say');
ok(/copilotLastAsk = \{/.test(src.slice(src.indexOf('function copilotCardStart('), src.indexOf('function copilotCardStart(') + 1800)), 'the last co-pilot ask is remembered when its card starts');
ok(/say \? ' · say'/.test(src.slice(src.indexOf('function copilotCardStart('), src.indexOf('function copilotCardStart(') + 1800)), 'a Say card is tagged as such');


// ---- "sometimes not moveable" (owner, 4 Oct): the window flipped to solid one animation frame + one IPC after the pointer
// reached the toolbar; a grab inside that gap went to the app behind. Now: near a solid part = solid, and the flip to solid
// is immediate.
const ct = src.slice(src.indexOf('function clickThroughTransparentParts()'), src.indexOf('function clickThroughTransparentParts()') + 3200);
ok(/var SOLID_MARGIN = (2[4-9]|[3-9]\d);/.test(ct), 'a margin of 24px+ around every solid part counts as solid (window goes solid before the pointer arrives)');
ok(/function nearSolid\(/.test(ct) && /getBoundingClientRect\(\)/.test(ct) && /SOLID_MARGIN/.test(ct.slice(ct.indexOf('function nearSolid('))), 'nearSolid measures the real boxes of the solid parts, grown by the margin');
ok(/var solid = .*nearSolid\(/.test(ct), 'the solid decision uses the margin');
ok(/if \(!want && through !== false\) \{ through = false; api\.setClickThrough\(false\); return; \}/.test(ct.slice(ct.indexOf("addEventListener('mousemove'"))), 'flip TO solid happens synchronously in the mousemove handler, never deferred to the next frame');


// ---- text in a fence is read, not coded (owner, 4 Oct: a CFO prompt rendered as 12.5px SQL-coloured code, "hard to read and small")
const fenceRe = src.slice(src.indexOf('for (var i = 0; i < lines.length; i++) {', src.indexOf('function formatAnswer(')), src.indexOf('function formatAnswer(') + 6000);
ok(/var fence = line\.trim\(\)\.match\(\/\^```\\s\*\(\[\\w\+#\.-\]\*\)\/\)/.test(fenceRe), 'the fence language tag is captured (it used to be thrown away)');
ok(/buildCodeBlock\(codeLines, codeLang\)/.test(fenceRe), 'the block builder is told the language');
ok(/var TEXT_LANGS = /.test(src) && /'text'/.test(src.slice(src.indexOf('var TEXT_LANGS = '), src.indexOf('var TEXT_LANGS = ') + 200)) && /'prompt'/.test(src.slice(src.indexOf('var TEXT_LANGS = '), src.indexOf('var TEXT_LANGS = ') + 200)), 'text/prompt/email/markdown fences are text, not code');
const lp = src.slice(src.indexOf('function looksLikeProse('), src.indexOf('function looksLikeProse(') + 1600);
ok(lp.length > 100, 'a prose detector exists for untagged fences');
const looksLikeProse = new Function(lp.slice(0, lp.indexOf('\n}\n') + 3) + '\nreturn looksLikeProse;')();
ok(looksLikeProse(["Our same-store sales growth really dropped off in the back half compared to the first half, and the board is going to want to know why and what we're doing about it. Can you dig into the POS data, promotions calendar, staffing schedules, and whatever competitor openings we have on file, and tell me where we should focus our corrective action going into next quarter?"]) === true, 'the CFO prompt from the screenshot is prose');
ok(looksLikeProse(["SELECT carrier, invoice_id, billed_amt - contracted_amt AS overage", "FROM carrier_invoices", "WHERE billed_amt > contracted_amt;"]) === false, 'SQL is code');
ok(looksLikeProse(["def overage(rows):", "    return [r for r in rows if r['billed'] > r['contracted']]"]) === false, 'Python is code');
ok(looksLikeProse(["=XLOOKUP(A2, Sheet2!A:A, Sheet2!C:C)"]) === false, 'a formula is code');
ok(looksLikeProse(["Hi Priya, thanks for flagging T-9012. We breached the four-hour rule, so I've paged the on-call manager and I'll have the availability sheet to you by Wednesday noon."]) === true, 'an email is prose');
const bcb = src.slice(src.indexOf('function buildCodeBlock('), src.indexOf('function buildCodeBlock(') + 1500);
ok(/TEXT_LANGS/.test(bcb) && /looksLikeProse\(lines\)/.test(bcb) && /buildTextBlock\(lines\)/.test(bcb), 'tagged text, or untagged prose, is rendered as a text block');
ok(/<pre class="text-block">/.test(src) && /TEXT TO USE/.test(src) && /<code class="text-content">/.test(src), 'the text block keeps the copy button (copy reads the <code> inside the <pre>)');
ok(/\.sc-card-a pre\{[^}]*font:400 13\.5px\/1\.7/.test(src), 'code is 13.5px (was 12.5)');
ok(/\.code-ln\{[^}]*font:400 11px/.test(src), 'line numbers 11px (was 10)');
ok(/\.sc-card-a pre\.text-block\{[^}]*font:400 13\.5px\/1\.7 -apple-system/.test(src) && /border-left:3px solid/.test(src.slice(src.indexOf('.sc-card-a pre.text-block{'), src.indexOf('.sc-card-a pre.text-block{') + 500)), 'text block: reading font, 13.5px, accent rail');
ok(/body\.light-mode \.sc-card-a pre\.text-block\{/.test(src), 'text block has a light-mode style');


// ---- what he TYPES is an order, never something to judge (owner, 4 Oct: Q&A typed question answered "No question on screen
// yet"; co-pilot typed ask answered "that's just test text, not a real question")
const sq = src.slice(src.indexOf('function sendQuestion()'), src.indexOf('function sendQuestion()') + 1600);
ok(/copilotSend\(\{ ask: text, typed: true \}\)/.test(sq), 'a typed ask reaches the co-pilot flagged as typed');
ok(/typed: !!opts\.typed/.test(src.slice(src.indexOf('async function copilotSend('), src.indexOf('async function copilotSend(') + 900)), 'request body carries typed');
const srv2 = require('fs').readFileSync(require('path').join(__dirname, '..', 'server.js'), 'utf8');
const ep2 = srv2.slice(srv2.indexOf("app.post('/api/sessions/:id/copilot'"), srv2.indexOf("app.post('/api/sessions/:id/copilot'") + 9000);
ok(/const typed = !!req\.body\.typed/.test(ep2) && /typed,/.test(ep2.slice(ep2.indexOf('buildCopilotPrompt('), ep2.indexOf('buildCopilotPrompt(') + 400)), 'endpoint passes typed into the prompt');
const sa = srv2.slice(srv2.indexOf("const { image, auto, instruction } = req.body;"), srv2.indexOf("const { image, auto, instruction } = req.body;") + 4000);
ok(/const noItem = !instruction && \(question === 'NONE' \|\| !suggestion\)/.test(sa), 'screen assist: a typed instruction can never come back as "no question on screen"');
ok(/const questionText = noItem \? 'Screen' : \(instruction \|\| question\)/.test(sa) || /questionText = instruction \|\|/.test(sa), 'the card is titled with what he typed');
ok(/THE CANDIDATE TYPED \(this IS the question to answer; the screen is context[^']*never answer QUESTION: NONE/.test(sa), 'the screen prompt is told the typed text is the question');
ok(/if \(instruction && !suggestion\) suggestion = String\(reply \|\| ''\)\.trim\(\)/.test(sa), 'a typed question never gets an empty answer (the raw reply stands in)');


// ---- every screen capture is overlay-free (owner, 4 Oct: the Q&A screen reader read the overlay's OWN card as the question
// on screen, and the co-pilot described the Q&A card's SQL as "on screen"). Only the co-pilot camera used the app capture.
const gs = src.slice(src.indexOf('async function grabScreen('), src.indexOf('async function grabScreen(') + 1400);
ok(gs.length > 100 && /electronAPI\.captureDisplay\(/.test(gs) && /frameFromShot\(shot\)/.test(gs) && /captureFrame\(stream, maxW, opts\)/.test(gs), 'one door: grabScreen prefers the app capture (no overlay, honours the eye) and falls back to the page stream');
const direct = (src.match(/captureFrame\((screenStream|stream)\)/g) || []).length;
ok(direct === 0, 'no caller grabs the raw page stream any more (found ' + direct + ')');
ok(/grabScreen\(1280\)\.then\(function\(b64\) \{ return sendScreenCapture\(b64, \{ instruction: text \}\); \}\)/.test(src), 'typed-with-screen (Q&A) uses grabScreen');
ok((src.match(/await grabScreen\(1280, \{ stream: stream \}\)/g) || []).length >= 2 && /await grabScreen\(1280, \{ stream: screenStream \}\)/.test(src), 'Assist button, Record first shot and Record loop use grabScreen');
ok(/await grabScreen\(COPILOT_CAPTURE_W, \{ stream: stream \}\)/.test(src.slice(src.indexOf('async function copilotFrame('), src.indexOf('async function copilotFrame(') + 900)), 'co-pilot Assist frame uses grabScreen');
// ---- a typed Q&A question is the candidate's own order (owner, 4 Oct: "I can't write an essay. That question doesn't match…")
const srv3 = require('fs').readFileSync(require('path').join(__dirname, '..', 'server.js'), 'utf8');
const cq = srv3.slice(srv3.indexOf("msg.type === 'canvas_question'"), srv3.indexOf("msg.type === 'canvas_question'") + 1500);
ok(/rebuildIdx, true, true, \{ typed: true \}\)/.test(cq), 'the typed question is flagged typed on its way to the writer');
ok(/^async function fastMatchAndRespond\(.*skipClean, extraOpts\)/m.test(srv3), 'fastMatchAndRespond carries extra writer options');
const fm = srv3.slice(srv3.indexOf('async function fastMatchAndRespond('), srv3.indexOf('async function fastMatchAndRespond(') + 9000);
ok((fm.match(/generateLiveAnswer\([^)]*Object\.assign\(\{\}, extraOpts/g) || []).length >= 3, 'every writer call inside it passes the flag through (bank, fresh, regen)');
const gl = srv3.slice(srv3.indexOf('async function generateLiveAnswer('), srv3.indexOf('async function generateLiveAnswer(') + 12000);
ok(/const typedBlock = opts\.typed \? /.test(gl) && /TYPED BY THE CANDIDATE/.test(gl) && /never declined/i.test(gl), 'the writer is told a typed line is an order: do it in full, never decline or redirect');
ok(/opts\.typed \? 'QUESTION \(typed by the candidate — do exactly this\):' : 'QUESTION \(detected from speech/.test(gl), 'the question label says typed, not "detected from speech"');

console.log('ALL PASS (meeting co-pilot overlay wiring, ' + n + ' checks)');
