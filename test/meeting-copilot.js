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
