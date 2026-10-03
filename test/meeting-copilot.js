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
  ok(/I said 12\b/.test(smart) && !/I said 10\b/.test(smart), 'smart carries the raw last 20 rows, not more');
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
  assert(/a press always gets a real answer/i.test(mc.MEETING_PROMPT), 'system prompt limits "nothing new" to un-pressed turns');
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
