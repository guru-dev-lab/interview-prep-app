// Unit tests for the meeting co-pilot logic (lib/meeting-copilot.js) and the shared screen fingerprint
// (public/copilot-fingerprint.js). Free — no model, no DB. Run: node test/meeting-copilot.js
const assert = require('assert');
const path = require('path');
const mc = require(path.join(__dirname, '..', 'lib', 'meeting-copilot.js'));
const fp = require(path.join(__dirname, '..', 'public', 'copilot-fingerprint.js'));

let n = 0; const ok = (c, m) => { n++; assert(c, m); };
const row = (kind, text, ts, meta) => ({ kind, text, ts, meta: meta || {} });

// ---- rows → regular-mode selection: last 6 voice lines, last ask, last seen, last said
{
  const rows = [];
  for (let i = 1; i <= 9; i++) rows.push(row(i % 2 ? 'asker' : 'you', 'line ' + i, i));
  rows.push(row('seen', 'old table', 2), row('seen', 'new table', 7), row('said', 'earlier card', 5), row('said', 'latest card', 8));
  rows.push(row('asker', 'what does row 12 mean?', 10, { ask: true }));
  rows.push(row('document', 'ref doc', 1));
  const sel = mc.selectRegularRows(rows);
  const voice = sel.filter(r => r.kind === 'asker' || r.kind === 'you');
  ok(voice.length === 6, 'regular keeps 6 voice rows, got ' + voice.length);
  ok(voice[voice.length - 1].text === 'what does row 12 mean?', 'newest voice row kept');
  ok(!voice.some(r => r.text === 'line 1' || r.text === 'line 2' || r.text === 'line 3'), 'oldest voice rows dropped');
  ok(sel.filter(r => r.kind === 'seen').length === 1 && sel.find(r => r.kind === 'seen').text === 'new table', 'only the latest seen');
  ok(sel.filter(r => r.kind === 'said').length === 1 && sel.find(r => r.kind === 'said').text === 'latest card', 'only the latest said');
  ok(!sel.some(r => r.kind === 'document'), 'documents are not voice rows (they ride in via session docs)');
  for (let i = 1; i < sel.length; i++) ok(sel[i - 1].ts <= sel[i].ts, 'selection is in time order');
}

// ---- prompt text: regular vs smart
{
  const rows = [];
  for (let i = 1; i <= 30; i++) rows.push(row(i % 2 ? 'asker' : 'you', (i % 2 ? 'them says ' : 'I said ') + i, i));
  rows.push(row('seen', 'Sales table, row 12 at -18%', 31));
  const base = { session: { role: 'Data Analyst', company: 'Acme' }, docs: 'Q3 plan notes', ask: 'what does row 12 mean?', screenChanged: false };
  const regular = mc.buildCopilotPrompt(Object.assign({ mode: 'regular', rows }, base));
  ok(/You: I said 30/.test(regular), 'regular carries his own latest line labelled You');
  ok(/Them: them says 29/.test(regular), 'regular labels their lines Them');
  ok(!/I said 2\b/.test(regular), 'regular drops old lines (last few only)');
  ok(/Sales table, row 12/.test(regular), 'regular reuses the latest seen summary when the screen did not change');
  ok(/Q3 plan notes/.test(regular), 'documents ride in');
  ok(!/BRIDGES|RESUME|Candidate:|Interviewer:/.test(regular), 'no interview-era context');
  ok(/what does row 12 mean\?/.test(regular), 'the ask is in the prompt');

  const smart = mc.buildCopilotPrompt(Object.assign({ mode: 'smart', rows, digest: 'DIGEST: they want the reclass explained' }, base));
  ok(/DIGEST: they want the reclass explained/.test(smart), 'smart carries the digest');
  ok(/I said 2\b/.test(smart) && /I said 30\b/.test(smart), 'smart carries a short call whole, word for word (sized by characters, not rows)');
  ok(mc.modelFor('regular') === 'haiku' && mc.modelFor('smart') === 'sonnet', 'model by mode');
}

// ---- press with nothing asked = panic rule, and screen-changed wording
{
  const p = mc.buildCopilotPrompt({ mode: 'regular', rows: [], session: {}, ask: '', pressed: true, screenChanged: true });
  ok(/pressed/i.test(p) && /there IS something to answer/i.test(p), 'a press tells the model there is something to answer');
}

// ---- compaction budget (smart mode only, new rows only, 3 min apart)
{
  const now = 1_000_000;
  ok(!mc.shouldCompact({ lastAt: 0, lastCount: 0 }, { now, rowCount: 10, historyOn: false }), 'never when history is off');
  ok(!mc.shouldCompact({ lastAt: 0, lastCount: 10 }, { now, rowCount: 10, historyOn: true }), 'never without new rows');
  ok(!mc.shouldCompact({ lastAt: now - 60_000, lastCount: 5 }, { now, rowCount: 10, historyOn: true }), 'not within 3 minutes');
  ok(mc.shouldCompact({ lastAt: now - 181_000, lastCount: 5 }, { now, rowCount: 10, historyOn: true }), 'yes after 3 minutes with new rows');
  ok(mc.shouldCompact({ lastAt: 0, lastCount: 0 }, { now, rowCount: 3, historyOn: true }), 'first compaction runs as soon as there are rows');
}

// ---- live-only writer guard
{
  const calls = [];
  const record = mc.makeRecorder({ query: (sql, params) => { calls.push({ sql, params }); return Promise.resolve({ rows: [] }); } });
  return_ = record('sess-1', null, 'asker', 'hello', {});
  ok(return_ === false && calls.length === 0, 'no call id (not live) → nothing written');
  ok(record('sess-1', 'call-1', 'asker', '', {}) === false && calls.length === 0, 'empty text → nothing written');
  ok(record('sess-1', 'call-1', 'bogus', 'x', {}) === false && calls.length === 0, 'unknown kind → nothing written');
  ok(record('sess-1', 'call-1', 'you', 'I said this', {}) !== false && calls.length === 1, 'live + text → one insert');
  ok(/INSERT INTO call_events/.test(calls[0].sql) && calls[0].params.includes('you'), 'insert goes to call_events with the kind');
}

// ---- screen fingerprint: same frame = unchanged; a moved table = changed
{
  const a = new Array(32 * 18).fill(100);
  const b = a.slice(); b[5] = 104; // tiny noise
  const c = a.map((v, i) => (i % 32 > 20 ? 200 : v)); // a third of the frame changed
  ok(!fp.fingerprintChanged(a, b), 'small noise is not a change');
  ok(fp.fingerprintChanged(a, c), 'a real screen change is detected');
  ok(fp.fingerprintChanged(null, a), 'first frame always counts as changed');
}

console.log('ALL PASS (meeting co-pilot logic, ' + n + ' checks)');

// ---- (added after the keep-alive run showed two slips) no screen yet → say so; a press never gets "nothing new"
{
  const noSeen = mc.buildCopilotPrompt({ mode: 'regular', rows: [row('asker', 'hi', 1)], session: {}, ask: 'sum sales by region', screenChanged: false });
  assert(/No screen has been captured yet/i.test(noSeen) && !/use the latest "Screen shown earlier"/.test(noSeen), 'without any seen row the prompt says no screen yet (not "use the summary above")');
  const withSeen = mc.buildCopilotPrompt({ mode: 'regular', rows: [row('seen', 'a table', 1)], session: {}, ask: 'x', screenChanged: false });
  assert(/use the latest "Screen shown earlier"/.test(withSeen), 'with a seen row the prompt points at it');
  const pressed = mc.buildCopilotPrompt({ mode: 'regular', rows: [], session: {}, ask: '', pressed: true, screenChanged: false });
  assert(/never answer "nothing new"/i.test(pressed), 'a press forbids the nothing-new escape');
  assert(/a press( or a typed line)? always gets a real answer/i.test(mc.MEETING_PROMPT), 'system prompt limits "nothing new" to un-pressed, un-typed turns');
  console.log('ALL PASS (prompt slips: no-screen wording, press never "nothing new")');
}

// ---- camera press: a screen captured EARLIER in the call is reused (match any earlier print, not just the last)
{
  const a = new Array(32 * 18).fill(90), b = a.map((v, i) => (i % 32 > 16 ? 220 : v)), c = a.map((v, i) => (i < 200 ? 10 : v));
  const prints = [{ key: 'scr-1', print: a }, { key: 'scr-2', print: b }];
  assert(fp.matchPrint(prints, a.slice()) === 'scr-1', 'first page again → its key');
  assert(fp.matchPrint(prints, b.map(v => v + 3)) === 'scr-2', 'second page with noise → its key');
  assert(fp.matchPrint(prints, c) === null, 'a new page → null');
  assert(fp.matchPrint([], a) === null, 'nothing captured yet → null');
}

// ---- prompt: a reused screen points at THAT capture's text; smart mode carries every screen shown in full
{
  const rows = [row('seen', 'PAGE 2: volumes table …', 1, { key: 'scr-1' }), row('seen', 'PAGE 3: rate card …', 2, { key: 'scr-2' }), row('asker', 'hi', 3)];
  const p = mc.buildCopilotPrompt({ mode: 'regular', rows, session: {}, ask: 'dallas volume?', screenChanged: false, seenKey: 'scr-1' });
  assert(/captured earlier on this call/i.test(p) && /PAGE 2: volumes table/.test(p), 'reused screen → that capture, named as earlier');
  assert(!/use the latest "Screen shown earlier"/.test(p), 'not the generic latest-summary line');
  const smart = mc.buildCopilotPrompt({ mode: 'smart', rows, session: {}, ask: 'q', screenChanged: false, digest: 'D' });
  assert(/SCREENS SHOWN THIS CALL/.test(smart) && /PAGE 2: volumes table/.test(smart) && /PAGE 3: rate card/.test(smart), 'smart lists every screen shown');
  const reg = mc.buildCopilotPrompt({ mode: 'regular', rows, session: {}, ask: 'q', screenChanged: false });
  assert(!/SCREENS SHOWN THIS CALL/.test(reg), 'regular does not');
  assert(typeof mc.TRANSCRIBE_PROMPT === 'string' && /table/i.test(mc.TRANSCRIBE_PROMPT), 'a transcription prompt exists for smart-mode screen notes');
  console.log('ALL PASS (earlier-screen reuse + smart screens section)');
}

// ---- smartest mode rules (owner, 3 Oct): exact tool how-to, puzzles decoded literally, earlier slips corrected; room to finish
{
  const P = mc.MEETING_PROMPT;
  assert(/exact function|exact formula/i.test(P) && /what it does/i.test(P), 'tool questions → the exact function/formula to type + one plain line on what it does');
  assert(/no jargon/i.test(P), 'no jargon unless the jargon is the answer');
  assert(/decode each picture literally/i.test(P) && /options given/i.test(P), 'puzzles: literal decode, matched against the options given');
  assert(/earlier co-pilot answer/i.test(P) && /correct it/i.test(P), 'a wrong earlier co-pilot answer is corrected, not carried');
  assert(mc.maxTokensFor('regular') >= 700 && mc.maxTokensFor('smart') >= 1200, 'room to finish a multi-step calculation (page 8 was cut off at 500)');
  assert(mc.modelFor('smart') === 'sonnet' && typeof mc.requestExtrasFor === 'function', 'per-mode request extras (thinking/effort) come from one place');
  console.log('ALL PASS (smartest-mode rules)');
}

// ---- the fingerprint file must expose window.CopilotFingerprint even where `module` exists (Electron renderer with
// node integration: 3 Oct the overlay captured nothing — the UMD check saw `module` and never set the global)
{
  const src = require('fs').readFileSync(path.join(__dirname, '..', 'public', 'copilot-fingerprint.js'), 'utf8');
  const fakeWindow = {}; const fakeModule = { exports: {} };
  new Function('module', 'self', 'window', src)(fakeModule, fakeWindow, fakeWindow);
  assert(fakeWindow.CopilotFingerprint && typeof fakeWindow.CopilotFingerprint.matchPrint === 'function', 'global set even when module exists');
  assert(fakeModule.exports && typeof fakeModule.exports.matchPrint === 'function', 'module export still set');
  console.log('ALL PASS (fingerprint global under Electron)');
}

// ---- auto-capture (History on): a NEW page that has settled for two checks is captured once; scrolling/transitions and
// pages already captured are not
{
  const a = new Array(32 * 18).fill(50), b = a.map((v, i) => (i % 32 > 10 ? 220 : v));
  const prints = [{ key: 'scr-1', print: a }];
  const st = {};
  assert(fp.stableNewScreen(st, b, prints) === false, 'first sight of a new page: not yet (unstable)');
  assert(fp.stableNewScreen(st, b, prints) === true, 'same new page on the next check: capture');
  assert(fp.stableNewScreen(st, b, prints) === true, 'still new until the caller registers it');
  assert(fp.stableNewScreen(st, a, prints) === false, 'a page already captured: never');
  assert(fp.stableNewScreen(st, a.map(v => v + 2), prints) === false, 'same page with noise: never');
  const c = a.map((v, i) => (i < 300 ? 200 : v));
  assert(fp.stableNewScreen(st, c, prints) === false && fp.stableNewScreen(st, b, prints) === false, 'flipping between pages resets stability');
  console.log('ALL PASS (auto-capture stability)');
}

// ---- the overlay sends raw base64 (no data-URL prefix): the server must sniff the real type, never assume JPEG
{
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]).toString('base64');
  const jpg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0]).toString('base64');
  const webp = Buffer.from('RIFF\u0000\u0000\u0000\u0000WEBPVP8 ', 'binary').toString('base64');
  assert.deepStrictEqual(mc.sniffImage(png), { mediaType: 'image/png', data: png }, 'raw PNG');
  assert.deepStrictEqual(mc.sniffImage(jpg), { mediaType: 'image/jpeg', data: jpg }, 'raw JPEG');
  assert.strictEqual(mc.sniffImage(webp).mediaType, 'image/webp', 'raw WEBP');
  assert.deepStrictEqual(mc.sniffImage('data:image/png;base64,' + png), { mediaType: 'image/png', data: png }, 'data URL stripped + typed');
  assert.strictEqual(mc.sniffImage('data:image/jpeg;base64,' + png).mediaType, 'image/png', 'bytes beat a wrong data-URL label');
  assert.strictEqual(mc.sniffImage('').data, '', 'empty stays empty');
  console.log('ALL PASS (image type sniffing)');
}

// ---- measured 3 Oct (owner's display: the pack page is ~1/3 of the captured frame): at 32×18/Δ24 the two closest
// pages differed on 0.87% of pixels (< the 3% bar → "already captured" on every page); at 64×36/Δ12 the closest pair
// is 2.4% and same-page noise (menu-bar clock tick) is 0. Bar is 1%.
{
  assert(fp.W === 64 && fp.H === 36, 'thumbnail is 64×36');
  const base = new Array(64 * 36).fill(120);
  const twoPct = base.map((v, i) => (i < Math.round(64 * 36 * 0.024) ? v + 40 : v));
  const halfPct = base.map((v, i) => (i < Math.round(64 * 36 * 0.005) ? v + 40 : v));
  const faint = base.map((v, i) => (i < Math.round(64 * 36 * 0.3) ? v + 10 : v)); // 30% of pixels moved by 10 → below the delta → noise
  assert(fp.fingerprintChanged(base, twoPct), '2.4% moved → a different page');
  assert(!fp.fingerprintChanged(base, halfPct), '0.5% moved → same page');
  assert(!fp.fingerprintChanged(base, faint), 'a faint shift everywhere is noise');
  console.log('ALL PASS (fingerprint tuned to a page inside a larger frame)');
}

// ---- accuracy (owner's run 3 Oct: answer used 80 pallets / $1,000 minimum — page said 60 / $5,000)
{
  assert(mc.SMART_SCREENS_CHARS >= 24000, 'smart mode keeps far more screen text (was 9k)');
  const r = (k, t, ts) => ({ kind: 'seen', text: t, ts, meta: { key: k } });
  const rows = [r('a', 'PAGE 2 Monthly volumes: Dallas 140, Atlanta 60, Denver 95, Columbus 210. Note: holiday spike excluded.', 1),
                r('b', 'PAGE 2 Monthly volumes: Dallas 140, Atlanta 60, Denver 95, Columbus 210. Note: holiday spike excluded', 2), // same page, re-captured after a hover
                r('c', 'PAGE 3 Rate card: Blue Arrow 92, Redline 88, Summit 97; minimums $5,000 / $4,500 / $4,800', 3)];
  const kept = mc.dedupeScreens(rows);
  assert(kept.length === 2 && kept[0].meta.key === 'a' && kept[1].meta.key === 'c', 'near-duplicate screens are dropped, first capture kept');
  const p = mc.buildCopilotPrompt({ mode: 'smart', rows, session: {}, ask: 'Atlanta cheapest?', screenChanged: false });
  assert((p.match(/PAGE 2 Monthly volumes/g) || []).length === 1, 'the prompt carries each distinct screen once');
  assert(/name the screen/i.test(mc.MEETING_PROMPT) && /which page you still need/i.test(mc.MEETING_PROMPT), 'every number names its screen; a missing page is named, never invented');
  console.log('ALL PASS (accuracy: dedupe, bigger screen budget, cite-the-screen rule)');
}

// ---- owner 3 Oct: "we can upgrade the model a little bit.. haiku just be too dumb" → page reading on Sonnet, thinking off
{
  assert(mc.transcribeModelFor('smart') === 'sonnet' && mc.transcribeModelFor('regular') === 'sonnet', 'page transcripts on Sonnet in both modes');
  assert(mc.transcribeExtras() && mc.transcribeExtras().thinking && mc.transcribeExtras().thinking.type === 'disabled', 'thinking off for transcription (speed)');
  console.log('ALL PASS (transcription model)');
}

// ---- transcripts are of the CONTENT, not the browser chrome (owner's live run: "Browser tab shows claude.ai, bookmarks bar…")
assert(/ignore browser tabs|ignore the browser/i.test(mc.TRANSCRIBE_PROMPT) && /menu bar/i.test(mc.TRANSCRIBE_PROMPT), 'transcription skips tabs, bookmarks, menu bars, docks');
console.log('ALL PASS (transcribe content only)');

// ---- owner 3 Oct: "when answering, it must use the structure.. like question #1 or whatever it saw"
assert(/same labels/i.test(mc.MEETING_PROMPT) && /Question 1/.test(mc.MEETING_PROMPT) && /same order/i.test(mc.MEETING_PROMPT), 'answers mirror the structure on the page: same labels, same order, one block each');
console.log('ALL PASS (answer mirrors page structure)');

// ---- owner 3 Oct: "if answer is code then use code editor.. exact and style" → always a fenced block with the language
assert(/```/.test(mc.MEETING_PROMPT) && /fenced code block/i.test(mc.MEETING_PROMPT) && /language/i.test(mc.MEETING_PROMPT) && /ready to paste/i.test(mc.MEETING_PROMPT), 'code/formula/SQL answers come as a fenced block with the language, complete, ready to paste');
console.log('ALL PASS (code answers fenced)');

// ---- 3 Oct 09:59, owner: the region rule missed his pages (watcher: 1 captured, 83 "known") → back to the share rule:
// any real movement (≥1% of pixels) is a new page; a duplicate costs one read at assist, a missed page costs the answer.
{
  const W = fp.W, H = fp.H, base = new Array(W * H).fill(100);
  const band = base.map((v, i) => (((i / W) | 0) === 10 && (i % W) > 2 && (i % W) < 60 ? v + 60 : v));
  assert(fp.matchPrint([{ key: 'a', print: base }], band) === null, 'a visible change on the page is a new capture (owner: never miss a page)');
  assert(fp.matchPrint([{ key: 'a', print: base }], base.map(v => v + 3)) === 'a', 'noise below the pixel delta is the same page');
  assert(typeof fp.isNewPage === 'undefined', 'the region rule is removed (one rule, one place)');
  console.log('ALL PASS (share rule restored)');
}
// ---- 3 Oct 09:59: answer cut mid-sentence at 727 chars — adaptive thinking shares the output cap (first words 7.9 s)
assert(mc.maxTokensFor('smart') >= 4000, 'History mode cap leaves room for thinking + the answer');
console.log('ALL PASS (smart cap)');

// ---- owner 3 Oct: "the question on page 7 should be answered and NEEDS TO ADD number of question and what asked"
assert(/Question 1 — <what was asked>/.test(mc.MEETING_PROMPT) && /every question on the page/i.test(mc.MEETING_PROMPT), 'numbered questions: each block carries its number and what was asked, every question answered');
console.log('ALL PASS (question number + wording in each block)');

// ---- 3 Oct 10:07: Assist on the cover page answered page 8 only and ignored page 7's three questions
{
  const p = mc.buildCopilotPrompt({ mode: 'smart', rows: [], session: {}, ask: '', pressed: true, screenChanged: true, digest: '' });
  assert(/every question found across the captured screens/i.test(p) && /Page 7 — Question 1 — <what was asked>/.test(p) && /already answered/i.test(p), 'a press with nothing typed answers every open question across the captured pages, grouped by page, numbered with its wording');
  console.log('ALL PASS (press answers all open questions)');
}

// ---- owner 3 Oct 10:45: "question formatting is not good enough… see it faster and answer" → answer first, working after
assert(/Result: <the result in one short line/.test(mc.MEETING_PROMPT) && /working/i.test(mc.MEETING_PROMPT) && /\*\*Page 7 — Question 1 — <what was asked>\*\*/.test(mc.MEETING_PROMPT), 'each block: bold question line, the working, then "Result:" (the card lifts it to the top)');
console.log('ALL PASS (answer-first blocks)');

// ---- 3 Oct 11:18 listening test: 37 voice rows at the first Assist, no digest yet → only the last 20 rows went in; the
// first 40 s (revenue, headcount, dates) were stored but never handed over. Raw rows are sized by characters now.
{
  const rows = []; for (let i = 1; i <= 40; i++) rows.push(row(i % 2 ? 'asker' : 'you', 'line number ' + i + ' of the update', i));
  const p = mc.buildCopilotPrompt({ mode: 'smart', rows, session: {}, ask: 'q', screenChanged: false });
  assert(/line number 1 of the update/.test(p) && /line number 40 of the update/.test(p), 'a short call goes in whole (all 40 rows)');
  const big = []; for (let i = 1; i <= 400; i++) big.push(row('asker', 'row ' + i + ' ' + 'x'.repeat(80), i));
  const q = mc.buildCopilotPrompt({ mode: 'smart', rows: big, session: {}, ask: 'q', screenChanged: false });
  assert(!/\brow 1 x/.test(q) && /\brow 400 x/.test(q) && q.length < 40000, 'a long call keeps the newest ~16k chars word for word');
  assert(mc.SMART_RAW_CHARS >= 16000 && typeof mc.rawCharsOf === 'function', 'budget and measurer exported (the server compacts first when the raw part overflows and no digest exists)');
  console.log('ALL PASS (raw transcript by characters)');
}

// ---- 3 Oct 11:37: the SQL used EXTRACT(DAY FROM date - date) — fails on Postgres (date - date is an integer) — and
// multiplied by a percent column without saying whether it holds 2 or 0.02 → code must run as written, assumptions stated
assert(/run as written/i.test(mc.MEETING_PROMPT) && /date - date/i.test(mc.MEETING_PROMPT) && /state the assumption/i.test(mc.MEETING_PROMPT), 'code must run as written on the stated engine; types/units respected; assumptions stated in the plain line');
console.log('ALL PASS (code runs as written)');

// ---- 3 Oct 11:39, owner: a meeting may or may not relate to the selected session → the session line is a hint, not a frame
{
  const p = mc.buildCopilotPrompt({ mode: 'regular', rows: [], session: { role: 'Data Analyst', company: 'Acme' }, ask: 'x', screenChanged: true });
  assert(/only if this call is clearly about that job/i.test(p) && /otherwise ignore it/i.test(p), 'session role/company used only when the call is about that job');
  const q = mc.buildCopilotPrompt({ mode: 'regular', rows: [], session: {}, ask: 'x', screenChanged: true });
  assert(!/THIS PERSON/.test(q), 'no session line at all when the session has no role/company');
  console.log('ALL PASS (session is a hint)');
}

// ---- 3 Oct 11:41, owner: "it has to use session, sometimes it can be about the session" → résumé, JD and earlier-call
// notes ride along, used only when the call is about that job
{
  const p = mc.buildCopilotPrompt({ mode: 'regular', rows: [], session: { role: 'Data Analyst', company: 'Acme', resume: 'RESUME TEXT HERE', jd: 'JD TEXT HERE' }, priorMemory: 'EARLIER CALLS NOTES', ask: 'x', screenChanged: true });
  assert(/SESSION MATERIAL/.test(p) && /RESUME TEXT HERE/.test(p) && /JD TEXT HERE/.test(p) && /EARLIER CALLS NOTES/.test(p), 'résumé, JD and earlier-call notes ride along');
  assert(/(use|used) ?(it|them|this)? ?only if this call is clearly about that job/i.test(p), 'under the same rule: only when the call is about that job');
  const big = mc.buildCopilotPrompt({ mode: 'regular', rows: [], session: { resume: 'r'.repeat(20000), jd: 'j'.repeat(20000) }, ask: 'x', screenChanged: true });
  assert(big.length < 20000, 'session material is capped');
  const none = mc.buildCopilotPrompt({ mode: 'regular', rows: [], session: {}, ask: 'x', screenChanged: true });
  assert(!/SESSION MATERIAL/.test(none), 'no block when the session has nothing');
  console.log('ALL PASS (session material rides along, gated)');
}

// ---- 3 Oct 11:47: on the 9-page + 2-min-briefing context the answer took 29.8 s to first word and was cut at Q5
// (1358 chars): adaptive thinking at medium ballooned and shared the cap. Effort low; cap no longer competes.
assert(mc.requestExtrasFor('smart').thinking.type === 'disabled' && !mc.requestExtrasFor('smart').output_config, 'History mode: thinking OFF (measured 3 Oct on the 10-question battery: 10/10 either way; thinking blew first words to 13–30 s on his real context)');
assert(mc.maxTokensFor('smart') >= 8000, 'cap leaves room for thinking + a ten-question answer');
console.log('ALL PASS (thinking off, cap 8000)');

// ---- 3 Oct 12:04: with thinking off the model committed to the result before the arithmetic (Q6 corrected itself
// mid-card, Q3 went wrong) → working first, "Result:" as the LAST line of each block; the card lifts it to the top
assert(/Result: <the result in one short line/.test(mc.MEETING_PROMPT) && /last line of the block/i.test(mc.MEETING_PROMPT) && !/Answer: <the result/.test(mc.MEETING_PROMPT), 'each block: question, working lines, then Result: as the last line');
console.log('ALL PASS (work first, result last)');

// ---- 3 Oct 13:19: Part 2 (invoice table) was never captured; the model filled Q2/Q9 from EARLIER-CALL notes with a wrong
// date and cited a screen it did not have → earlier calls never stand in for a page missing from THIS call
assert(/never take a table, a figure or a date from earlier-call notes/i.test(mc.MEETING_PROMPT) && /not among the screens shown this call/i.test(mc.MEETING_PROMPT), 'a page missing from this call is reported missing, never filled from earlier-call notes');
console.log('ALL PASS (missing page is missing)');

// ---- 3 Oct 15:36: the capture thumbnail showed the overlay's own shape even with the eye on — content protection does
// not hide the window from the app's own grab. The overlay masks its own rectangle in every frame it stores/fingerprints.
{
  // frame 1568×980 of a 2560×1600 (CSS px) display; overlay at CSS (1800, 300) size 700×1100 → scaled by 1568/2560
  const r = fp.overlayRect(1568, 980, 2560, 1600, 1800, 300, 700, 1100);
  assert(Math.round(r.x) === 1103 && Math.round(r.y) === 184 && Math.round(r.w) === 429 && Math.round(r.h) === 674, 'overlay rect is scaled into frame pixels: ' + JSON.stringify(r));
  const c = fp.overlayRect(1568, 980, 2560, 1600, 2400, 1500, 700, 1100);
  assert(c.x + c.w <= 1568 && c.y + c.h <= 980, 'clamped to the frame');
  assert(fp.overlayRect(1568, 980, 2560, 1600, -900, 0, 700, 1100) === null, 'an overlay on another display (off this frame) masks nothing');
  console.log('ALL PASS (overlay rect in frame)');
}
// ---- SAY (owner, 3 Oct): the Say button answers what they JUST asked of this person; questions about the person come from
// résumé + Q&A bank whatever the call is about; technical asks get approach → exact code/steps → trade-off
{
  const base = { mode: 'smart', rows: [], session: { role: 'Data Analyst', company: 'Acme', resume: 'RESUME TEXT' }, bank: 'Q: tell me about yourself\nA: I am a data analyst with 5 years…', screenChanged: false };
  const say = mc.buildCopilotPrompt(Object.assign({}, base, { ask: 'have you done this before?', say: true, pressed: true }));
  ok(/Q&A BANK/.test(say) && /I am a data analyst with 5 years/.test(say), 'the Q&A bank rides along with the session material');
  ok(/THEY JUST ASKED/.test(say) && /have you done this before\?/.test(say), 'say mode names what they just asked');
  ok(/about THIS PERSON/i.test(say) && /RESUME and Q&A BANK/.test(say), 'questions about the person always use résumé + bank (no job gate)');
  ok(/trade-off/i.test(say) && /Approach/.test(say), 'technical say: approach → exact code/steps → trade-off');
  ok(/every part of the ask/i.test(say), 'technical say covers every part of the ask inside the code (flags AND per-carrier totals, not a note)');
  const plain = mc.buildCopilotPrompt(Object.assign({}, base, { ask: 'what does row 12 mean?' }));
  ok(!/THEY JUST ASKED/.test(plain), 'a heard/typed question is not labelled as a Say press');
  ok(/about THIS PERSON/i.test(plain), 'the person rule holds for heard questions too (tell me about yourself heard on the call)');
  const empty = mc.buildCopilotPrompt(Object.assign({}, base, { ask: '', say: true, pressed: true }));
  ok(/THEY JUST ASKED/.test(empty) && /latest thing they said/i.test(empty), 'say with nothing caught: answer the latest thing they said that needs a reply');
  ok(!/PRESSED the co-pilot button with nothing typed/.test(empty), 'say never turns into the all-pages Assist sweep');
  ok(mc.maxTokensFor('regular', true) >= 1500 && mc.maxTokensFor('regular') === 700, 'say in regular mode has room for code (1500+), plain regular stays 700');
  ok(mc.maxTokensFor('smart', true) === mc.maxTokensFor('smart'), 'smart cap unchanged by say');
}


// ---- prose is never fenced as code (owner, 4 Oct): text to paste is tagged ```text; what is said aloud is never fenced
{
  const P = mc.MEETING_PROMPT;
  ok(/```text/.test(P), 'the prompt names the ```text fence for prose to paste (a prompt, an email, a memo)');
  ok(/never (put|fence) .*(spoken|said out loud|Say lines)/i.test(P) || /Say lines are never fenced/i.test(P), 'spoken lines are never fenced');
  ok(/code fence (always )?carries its language/i.test(P) || /with the language/i.test(P), 'a code fence carries its language');
  console.log('ALL PASS (prose fenced as text, never as code)');
}

// ---- a typed ask is this person's own instruction (owner, 4 Oct): do it; never judge it as "not a real meeting question"
{
  const base = { mode: 'smart', rows: [], session: { role: 'Data Analyst' }, screenChanged: false };
  const t = mc.buildCopilotPrompt(Object.assign({}, base, { ask: 'write an essay for me real fast about anything', typed: true }));
  ok(/THIS PERSON TYPED/.test(t) && /do exactly this/i.test(t) && /write an essay for me real fast about anything/.test(t), 'typed ask is labelled as their own instruction, to be done');
  ok(!/JUST ASKED \/ NOTED/.test(t), 'a typed ask is not presented as something heard on the call');
  const h = mc.buildCopilotPrompt(Object.assign({}, base, { ask: 'what does row 12 mean?' }));
  ok(/JUST ASKED \/ NOTED/.test(h) && !/THIS PERSON TYPED/.test(h), 'a heard ask keeps its own label');
  ok(/Asked: nothing new[^\n]*never[^\n]*(typed|TYPED)/i.test(mc.MEETING_PROMPT) || /never on a typed/i.test(mc.MEETING_PROMPT), '"nothing new" is forbidden on a typed instruction too');
  console.log('ALL PASS (typed = an order)');
}
