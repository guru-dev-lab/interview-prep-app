// Multi-page pack (test/fixtures/meeting-pack): instructions, tables, a picture puzzle, a chart, then memos pages later
// whose questions need the earlier pages. History (smart) mode on. Also proves the camera rule: a page shown again is
// reused (screenKey), not re-sent. Usage: node test/meeting-pack-e2e.js [http://localhost:3999] <server log path>
require('dotenv').config();
const fs = require('fs'), path = require('path');
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
const check = (ok, label, detail) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + label + (detail && !ok ? '\n     ' + String(detail).replace(/\n/g, '\n     ').slice(0, 900) : '')); };
const logSince = mark => fs.readFileSync(LOG, 'utf8').slice(mark);
const page = n => 'data:image/png;base64,' + fs.readFileSync(path.join(__dirname, 'fixtures/meeting-pack/p' + n + '.png')).toString('base64');

(async () => {
  const email = 'screen-e2e@local.test';
  let u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Screen Tester','pro') RETURNING *", [email])).rows[0];
  let s = (await pool.query('SELECT id FROM sessions WHERE user_id=$1 LIMIT 1', [u.id])).rows[0];
  if (!s) s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1,'Northwind Logistics','Logistics Analyst','Analyst.') RETURNING id", [u.id])).rows[0];
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'pro', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const copilot = async (label, body) => {
    const t0 = Date.now();
    const r = await fetch(BASE + '/api/sessions/' + s.id + '/copilot', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify(body) });
    let j = {}; try { j = await r.json(); } catch (e) {}
    console.log(`  · ${label} → ${r.status} in ${Date.now() - t0}ms\n    ${(j.answer || j.error || '').replace(/\n/g, '\n    ').slice(0, 700)}`);
    return j.answer || '';
  };
  const seenRows = async () => (await pool.query("SELECT text, meta FROM call_events WHERE session_id=$1 AND kind='seen' AND ts > NOW() - interval '3 minutes' ORDER BY ts", [s.id])).rows;

  const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: true }));
  await sleep(300);

  // 1. Walk pages 2–6 with the camera (each a new screen)
  for (const n of [2, 3, 4, 5, 6]) {
    const a = await copilot('page ' + n + ' (camera)', { pressed: true, image: page(n), screenChanged: true, screenKey: 'scr-p' + n });
    check(/^Asked:/m.test(a) && /^On screen:/m.test(a), 'page ' + n + ' answered in shape', a);
  }
  // transcriptions land in the background
  let full = [];
  for (let i = 0; i < 30 && full.length < 5; i++) { await sleep(1000); full = (await seenRows()).filter(r => r.meta && r.meta.full); }
  check(full.length >= 5, 'smart mode transcribed every page in full (' + full.length + '/5)', JSON.stringify(full.map(r => r.text.slice(0, 60))));
  const p4 = full.find(r => r.meta.key === 'scr-p4');
  check(p4 && /blue/i.test(p4.text) && /arrow/i.test(p4.text) && /truck|lorry/i.test(p4.text), 'puzzle page transcription names blue, arrow, truck', p4 && p4.text);

  // 2. Camera on page 2 AGAIN → reused, not re-sent
  let mark = fs.readFileSync(LOG, 'utf8').length;
  let a = await copilot('page 2 again (reuse)', { ask: 'What is the Chicago to Dallas monthly pallet volume?', screenChanged: false, screenKey: 'scr-p2' });
  check(/reusing earlier screen scr-p2/.test(logSince(mark)), 'server reuses the earlier capture of page 2', logSince(mark).slice(-300));
  check(/\b140\b/.test(a), 'answer reads 140 pallets from the reused page', a);

  // 3. Memo page 7: questions that need pages 2, 3, 4, 5, 6
  a = await copilot('page 7 Q1', { ask: 'Priya: using the carrier from the puzzle, what is the monthly cost of the Chicago to Dallas lane at the page-2 volume, including the fuel surcharge?', image: page(7), screenChanged: true, screenKey: 'scr-p7' });
  check(/blue arrow/i.test(a), 'Q1 decodes the puzzle → Blue Arrow', a);
  check(/14,?42[56]/.test(a), 'Q1 cost: 140 × $92 = 12,880 + 12% = $14,426', a);
  a = await copilot('page 7 Q2', { ask: 'Which carrier has the best on-time on the chart, and is it the same one as the puzzle?', screenChanged: false, screenKey: 'scr-p7' });
  check(/blue arrow/i.test(a) && /96/.test(a) && /\b(yes|same)\b/i.test(a), 'Q2: Blue Arrow 96%, same as the puzzle', a);
  a = await copilot('page 7 Q3', { ask: 'With the Q1 growth rule, how many pallets per month does Dallas become?', screenChanged: false, screenKey: 'scr-p7' });
  check(/\b168\b/.test(a), 'Q3: 140 × 1.2 = 168', a);

  // 4. Memo page 8: minimum charges + surcharge across carriers
  a = await copilot('page 8', { ask: 'Priya: for Chicago to Atlanta, which carrier is cheapest per month once minimum charges and the surcharge apply, and what is that monthly cost?', image: page(8), screenChanged: true, screenKey: 'scr-p8' });
  check(/redline/i.test(a), 'page 8: Redline is cheapest (60×70=4,200 → min 4,500 → +8%)', a);
  check(/4,?860/.test(a), 'page 8: $4,860', a);

  ws.send(JSON.stringify({ type: 'stop' })); await sleep(500); ws.close(); await pool.end();
  console.log(`\n${fail ? 'FAILED' : 'ALL PASS'} (${pass} pass, ${fail} fail)`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
