// Session memory across sittings (owner 23 Nov: "i want the session to always remember what it has been discussed or hear
// or answered or screenshorted or noted all together to get better and give correct answers").
// Sitting 1 = a long work call: five key facts said EARLY, then ~110 lines of other talk, answers and a shared table
// (rows written the way the live call writes them). It ends → the carry. Sitting 2 asks for all of it back.
// Usage: DATABASE_URL=<local> node test/session-memory-e2e.js http://localhost:3999 <server log path>
require('dotenv').config();
const fs = require('fs');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const BASE = process.argv[2] || 'http://localhost:3999';
const LOG = process.argv[3];
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
if (!LOG || !fs.existsSync(LOG)) { console.error('Pass the server log path'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const sleep = ms => new Promise(r => setTimeout(r, ms));
let pass = 0, fail = 0;
const check = (ok, label, detail) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + label + (detail && !ok ? '\n     ' + String(detail).replace(/\n/g, '\n     ').slice(0, 1500) : '')); };
const logSince = mark => fs.readFileSync(LOG).subarray(mark).toString('utf8');

const EARLY = [
  ['asker', 'Before we start, remember our fiscal year starts on the first of April, so Q1 is April to June.'],
  ['you', 'Got it, April start.'],
  ['asker', 'And all revenue on this dashboard has to be in GBP, not dollars.'],
  ['asker', 'Dana Whitfield signs off on anything that goes to the board, so she sees it first.'],
  ['you', 'Okay, Dana reviews before the board.'],
  ['asker', 'We agreed last week to build it on vw_customer_360, not the old finance ledger.'],
  ['asker', 'First draft is due on the 14th of December.'],
];
const TOPICS = ['the colour of the region bars', 'whether to show a trend line', 'the filter for product family', 'tooltip wording', 'the font size on the KPI tiles', 'sorting the table by margin', 'a drill-down from region to store', 'how to label returns', 'the refresh schedule', 'mobile layout', 'whether to hide zero rows', 'the legend position'];
function filler(n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const t = TOPICS[i % TOPICS.length];
    out.push(i % 3 === 2 ? ['you', `For ${t}, I think option ${1 + (i % 4)} is cleaner, I can mock it up.`] : ['asker', `Next on my list is ${t}. Version ${i} looked a bit busy to me, what do you think about simplifying it?`]);
  }
  return out;
}

(async () => {
  const email = 'assessment-e2e@local.test';
  let u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Assess Tester','premium') RETURNING *", [email])).rows[0];
  await pool.query("UPDATE users SET plan='premium', is_admin=false WHERE id=$1", [u.id]);
  await pool.query("DELETE FROM sessions WHERE user_id=$1 AND kind='assessment'", [u.id]); // local test user only
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const api = async (method, p, body) => { const r = await fetch(BASE + p, { method, headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: body ? JSON.stringify(body) : undefined }); let j = {}; try { j = await r.json(); } catch (e) {} return { r, j }; };
  const live = async sid => {
    const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
    await new Promise(r => ws.on('open', r));
    ws.send(JSON.stringify({ type: 'start', token, sessionId: sid, mode: 'full', platform: 'electron', dualStream: true }));
    await sleep(1500);
    ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: true }));
    await sleep(300);
    return ws;
  };
  const sid = (await api('POST', '/api/assessments')).j.id;

  // ---- sitting 1 ----
  let ws = await live(sid);
  const call1 = (await pool.query('SELECT id FROM live_transcripts WHERE session_id=$1 ORDER BY started_at DESC LIMIT 1', [sid])).rows[0].id;
  const lines = EARLY.concat(filler(110));
  const t0 = Date.now() - 40 * 60 * 1000; // a 40-minute call
  let i = 0;
  for (const [kind, text] of lines) await pool.query('INSERT INTO call_events (session_id, call_id, ts, kind, text, meta) VALUES ($1,$2,$3,$4,$5,$6)', [sid, call1, new Date(t0 + (i++) * 20000), kind, text, '{}']);
  await pool.query('INSERT INTO call_events (session_id, call_id, ts, kind, text, meta) VALUES ($1,$2,$3,$4,$5,$6)', [sid, call1, new Date(t0 + 600000), 'seen', 'TYPE: DATA\nPlan vs actual by region: Northeast plan 1,240 actual 1,302 (+5%); Southeast 980 / 1,011 (+3%); Midwest 1,150 / 943 (-18%).', JSON.stringify({ key: 'scr-mem-1' })]);
  await pool.query('INSERT INTO call_events (session_id, call_id, ts, kind, text, meta) VALUES ($1,$2,$3,$4,$5,$6)', [sid, call1, new Date(t0 + 900000), 'said', 'Midwest is the only big miss, down 18 percent against plan.', JSON.stringify({ ask: 'which region missed plan', answered: ['Which region missed plan'] })]);
  const mark1 = fs.statSync(LOG).size;
  ws.send(JSON.stringify({ type: 'stop' })); ws.close();
  let carried = null; const tw = Date.now();
  while (Date.now() - tw < 120000) { const m = logSince(mark1).match(/\[Assessment\] sitting \S+ carried in \d+ms \((\d+) chars/); if (m) { carried = +m[1]; break; } await sleep(1000); }
  check(carried > 0, `sitting 1 carried (${carried} chars)`);
  const mem = ((await pool.query('SELECT memory FROM live_transcripts WHERE id=$1', [call1])).rows[0] || {}).memory || '';

  // ---- sitting 2: ask for it all back ----
  ws = await live(sid);
  const res = await api('POST', `/api/sessions/${sid}/copilot`, { ask: 'Remind me from our earlier call: when does their fiscal year start, what currency do they want, who signs off before the board, which view did we agree to build on, when is the first draft due, and which region missed plan?', typed: true });
  const ans = res.j.answer || '';
  const facts = { 'April start': /April/i.test(ans), 'GBP': /GBP|pounds?/i.test(ans), 'Dana signs off': /Dana/i.test(ans), 'vw_customer_360': /vw_customer_360/.test(ans), '14 December': /14(th)?\s*(of\s*)?Dec|Dec(ember)?\s*14/i.test(ans), 'Midwest -18%': /Midwest/.test(ans) };
  for (const [f, ok] of Object.entries(facts)) check(ok, 'sitting 2 remembers: ' + f, ok ? '' : 'MEMORY:\n' + mem + '\n\nANSWER:\n' + ans);
  ws.send(JSON.stringify({ type: 'stop' })); ws.close(); await sleep(500);

  console.log(`\n${fail ? 'FAILED' : 'ALL PASS'} (session memory e2e, ${pass} pass, ${fail} fail)`);
  await pool.end(); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
