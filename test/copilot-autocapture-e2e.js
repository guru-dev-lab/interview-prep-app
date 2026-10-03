// Auto-capture (History on): a new page sent with auto:true is read and stored, no answer card; the same page again is
// unchanged; with History off it is ignored. Usage: node test/copilot-autocapture-e2e.js [http://localhost:3999] <server log>
require('dotenv').config();
const fs = require('fs'), path = require('path');
const { Pool } = require('pg'); const jwt = require('jsonwebtoken'); const WebSocket = require('ws');
const BASE = process.argv[2] || 'http://localhost:3999', LOG = process.argv[3];
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
if (!LOG || !fs.existsSync(LOG)) { console.error('Pass the server log path'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const sleep = ms => new Promise(r => setTimeout(r, ms));
let pass = 0, fail = 0;
const check = (ok, label, detail) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + label + (detail && !ok ? '\n     ' + String(detail).slice(0, 600) : '')); };
(async () => {
  const email = 'screen-e2e@local.test';
  const u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  const s = (await pool.query('SELECT id FROM sessions WHERE user_id=$1 LIMIT 1', [u.id])).rows[0];
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'pro', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const raw = fs.readFileSync(path.join(__dirname, 'fixtures/meeting-pack/p3.png')).toString('base64'); // raw base64, as the overlay sends it
  const post = async body => { const r = await fetch(BASE + '/api/sessions/' + s.id + '/copilot', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify(body) }); return { status: r.status, j: await r.json() }; };
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const got = [];
  ws.on('message', d => { try { got.push(JSON.parse(d)); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true })); await sleep(1500);
  ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: false })); await sleep(200);
  const before = (await pool.query("SELECT count(*)::int n FROM call_events WHERE session_id=$1 AND kind='said'", [s.id])).rows[0].n;
  let r = await post({ auto: true, image: raw, screenKey: 'auto-p3' });
  check(r.status === 200 && r.j.ignored, 'History off → auto capture ignored', JSON.stringify(r.j));
  ws.send(JSON.stringify({ type: 'update_settings', copilotHistory: true })); await sleep(200);
  const mark = fs.readFileSync(LOG, 'utf8').length;
  r = await post({ auto: true, image: raw, screenKey: 'auto-p3' });
  check(r.status === 200 && r.j.captured && r.j.chars > 200, 'History on → page read and stored', JSON.stringify(r.j));
  const seen = (await pool.query("SELECT text, meta FROM call_events WHERE session_id=$1 AND kind='seen' AND meta->>'key'='auto-p3'", [s.id])).rows;
  check(seen.length === 1 && seen[0].meta.auto === true && /Blue Arrow/.test(seen[0].text) && /4,?500/.test(seen[0].text), 'seen row carries the full page (rate card names + minimums)', seen[0] && seen[0].text.slice(0, 200));
  const after = (await pool.query("SELECT count(*)::int n FROM call_events WHERE session_id=$1 AND kind='said'", [s.id])).rows[0].n;
  check(after === before && !got.some(m => m.type === 'copilot_start'), 'no answer card for an auto capture');
  check(got.some(m => m.type === 'copilot_captured' && m.key === 'auto-p3'), 'overlay told: copilot_captured', got.map(m => m.type).join(','));
  check(/auto-captured page auto-p3/.test(fs.readFileSync(LOG, 'utf8').slice(mark)), 'logged');
  r = await post({ auto: true, image: raw, screenKey: 'auto-p3' });
  check(r.status === 200 && r.j.unchanged, 'same page again → unchanged (no second read)', JSON.stringify(r.j));
  ws.send(JSON.stringify({ type: 'stop' })); await sleep(300); ws.close(); await pool.end();
  console.log(`\n${fail ? 'FAILED' : 'ALL PASS'} (${pass} pass, ${fail} fail)`); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
