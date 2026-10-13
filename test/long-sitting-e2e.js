// Long sitting, smarter pull-back (13 Oct): the pack's real pages + 30 filler pages push them to index lines; vague asks
// must still be answered from the right page. LOCAL server only. Usage: node test/long-sitting-e2e.js <base> <server log>
require('dotenv').config();
const fs = require('fs');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const BASE = process.argv[2] || 'http://localhost:3999', LOG = process.argv[3];
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const sleep = ms => new Promise(r => setTimeout(r, ms));
let pass = 0, fail = 0;
const check = (ok, label, detail) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + label + (detail && !ok ? '\n     ' + String(detail).replace(/\n/g, '\n     ').slice(0, 700) : '')); };
const logSince = mark => fs.readFileSync(LOG).subarray(mark).toString('utf8');
const PAGES = {
  p2: 'TYPE: DATA\nNorthwind Logistics — Q4 Freight Review pack\nPage 2 of 8\nMonthly volumes by lane (Q4 average)\nLane | Pallets / month | Avg weight (lb) | Current carrier\nChicago → Dallas | 140 | 1,180 | Redline\nChicago → Atlanta | 60 | 1,050 | Summit\nChicago → Denver | 95 | 1,320 | Blue Arrow\nChicago → Columbus | 210 | 900 | Redline',
  p3: 'TYPE: DATA\nNorthwind Logistics — Q4 Freight Review pack\nPage 3 of 8\nRate card — $ per pallet (linehaul)\nLane: Chicago → Dallas, Blue Arrow: 92, Redline: 88, Summit: 97\nLane: Chicago → Atlanta, Blue Arrow: 75, Redline: 70, Summit: 68\nLane: Chicago → Denver, Blue Arrow: 104, Redline: 110, Summit: 99\nLane: Chicago → Columbus, Blue Arrow: 41, Redline: 39, Summit: 44\nMinimum monthly charge per lane\nCarrier: Blue Arrow, Minimum / lane / month: $5,000, Accessorial (liftgate): $35 / stop\nCarrier: Redline, Minimum / lane / month: $4,500, Accessorial (liftgate): $40 / stop\nCarrier: Summit, Minimum / lane / month: $4,800, Accessorial (liftgate): $30 / stop',
  p5: 'TYPE: INFO\nNorthwind Logistics — Q4 Freight Review pack\nPage 5 of 8\nFuel surcharge and assumptions\nFuel surcharge: applied to the monthly lane cost after the minimum charge is applied.\n- Rate above $80 per pallet → 12% surcharge\n- Rate $80 or below → 8% surcharge\nGrowth: the Dallas lane grows 20% in Q1; all other lanes flat.',
  p6: 'TYPE: DATA\nNorthwind Logistics — Q4 Freight Review pack\nPage 6 of 8\nOn-time delivery, Q4 (% of shipments)\nChart (bar chart):\n- Blue Arrow: 96%\n- Redline: 91%\n- Summit: 88%',
};
const w = i => String.fromCharCode(97 + i % 26) + String.fromCharCode(97 + Math.floor(i / 26) % 26) + 'ex';

(async () => {
  const email = 'screen-e2e@local.test';
  let u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Screen Tester','pro') RETURNING *", [email])).rows[0];
  // a FRESH session every run: no earlier-call notes can answer for a page (13 Oct: a run passed off old notes)
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1,'Long Sitting Test','Analyst','Analyst.') RETURNING id", [u.id])).rows[0];
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'pro', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: true }));
  await sleep(300);
  const callId = (await pool.query('SELECT id FROM live_transcripts WHERE session_id=$1 ORDER BY started_at DESC LIMIT 1', [s.id])).rows[0].id;
  let t = Date.now() - 3600 * 1000;
  const put = (key, text) => pool.query("INSERT INTO call_events (session_id, call_id, kind, text, meta, ts) VALUES ($1,$2,'seen',$3,$4, to_timestamp($5 / 1000.0))", [s.id, callId, text, JSON.stringify({ key, full: true }), t += 60000]);
  for (const k of ['p2', 'p3', 'p5', 'p6']) await put('scr-' + k, PAGES[k]);
  for (let i = 0; i < 30; i++) await put('scr-f' + i, 'TYPE: DATA\nWarehouse sheet ' + [0, 1, 2, 3, 4, 5, 6, 7].map(k => w(i * 11 + k)).join(' ') + '\n' + ('bin ' + w(i) + ' qty 5 shelf 12\n').repeat(60));
  await put('scr-now', 'TYPE: QUESTION\nWarehouse review — final page\nAnswer the questions from the call.');
  const ask = async (q) => {
    const mark = fs.statSync(LOG).size;
    const r = await fetch(BASE + '/api/sessions/' + s.id + '/copilot', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify({ ask: q, screenKey: 'scr-now' }) });
    const j = await r.json().catch(() => ({}));
    const log = logSince(mark);
    console.log('  · ' + q + '\n    ' + String(j.answer || j.error).replace(/\n/g, ' ⏎ ').slice(0, 420) + '\n    ' + ((log.match(/\[Co-pilot\] pull router[^\n]*/) || ['(no router call)'])[0]) + '\n    ' + ((log.match(/\[Usage\] copilot-answer[^\n]*/) || [''])[0]));
    return { a: j.answer || '', log };
  };
  let x = await ask('Which carrier had the best on-time on that chart we looked at earlier?');
  check(/blue arrow/i.test(x.a) && /96/.test(x.a), '"that chart" → Blue Arrow 96%', x.a);
  x = await ask('What did Summit charge per pallet for Denver on the rate card?');
  check(/\b99\b/.test(x.a), '"the rate card" → Summit Denver $99', x.a);
  x = await ask('With the growth rule, how many pallets a month does Dallas become?');
  check(/\b168\b/.test(x.a), 'growth rule + Dallas volume → 168', x.a);
  x = await ask('How much was the extra fee when the truck needed help unloading?');
  check(/liftgate/i.test(x.a) && /\$?(35|40|30)\b/.test(x.a), 'no shared words → router finds the liftgate fee', x.a);
  check(/pull router[^\n]*PAGES:\s*[\d]/.test(x.log), 'that one went through the router', x.log.match(/pull router[^\n]*/));

  ws.send(JSON.stringify({ type: 'stop' })); await sleep(300); ws.close(); await pool.end();
  console.log(`\n${fail ? 'FAILED' : 'ALL PASS'} (${pass} pass, ${fail} fail)`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
