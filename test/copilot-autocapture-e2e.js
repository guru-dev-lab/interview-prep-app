// Collect-then-assist (owner, 3 Oct): captures (auto or camera) and listening are data collection — NO model call.
// At Assist time the pages not yet read are read once each, then the answer uses them. Usage:
//   node test/copilot-autocapture-e2e.js [http://localhost:3999] <server log path>
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
const logSince = m => fs.readFileSync(LOG, 'utf8').slice(m);
(async () => {
  const email = 'screen-e2e@local.test';
  const u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  const s = (await pool.query('SELECT id FROM sessions WHERE user_id=$1 LIMIT 1', [u.id])).rows[0];
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'pro', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const raw = n => fs.readFileSync(path.join(__dirname, 'fixtures/meeting-pack/p' + n + '.png')).toString('base64');
  const post = async body => { const r = await fetch(BASE + '/api/sessions/' + s.id + '/copilot', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify(body) }); return { status: r.status, j: await r.json() }; };
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const got = [];
  ws.on('message', d => { try { got.push(JSON.parse(d)); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true })); await sleep(1500);
  ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: true })); await sleep(200);
  const callId = (await pool.query('SELECT id FROM live_transcripts WHERE session_id=$1 ORDER BY started_at DESC LIMIT 1', [s.id])).rows[0].id;
  const screens = async () => (await pool.query("SELECT key, (image IS NOT NULL) AS has_image, (transcript IS NOT NULL) AS has_text FROM call_screens WHERE call_id=$1 ORDER BY ts", [callId])).rows;
  const seenRows = async () => (await pool.query("SELECT meta->>'key' k, text FROM call_events WHERE call_id=$1 AND kind='seen' ORDER BY ts", [callId])).rows;

  // 1. Auto capture (page 3) and camera capture (page 2): stored, NOT read, no model call
  let mark = fs.readFileSync(LOG, 'utf8').length;
  let r = await post({ auto: true, image: raw(3), screenKey: 'auto-p3' });
  check(r.status === 200 && r.j.captured && r.j.stored, 'auto capture stored', JSON.stringify(r.j));
  r = await post({ capture: true, image: raw(2), screenKey: 'cam-p2' });
  check(r.status === 200 && r.j.captured && r.j.stored, 'camera capture stored (any mode)', JSON.stringify(r.j));
  await sleep(300);
  let sc = await screens();
  check(sc.length === 2 && sc.every(x => x.has_image && !x.has_text), 'both screens hold the image and no transcript yet', JSON.stringify(sc));
  check((await seenRows()).length === 0, 'no seen rows yet (nothing read)');
  check(!/transcribed|claude-sonnet|claude-haiku/.test(logSince(mark)), 'no model call on capture', logSince(mark).slice(-400));
  check(got.filter(m => m.type === 'copilot_captured').length === 2 && !got.some(m => m.type === 'copilot_start'), 'overlay told twice, no card');
  r = await post({ auto: true, image: raw(3), screenKey: 'auto-p3' });
  check(r.status === 200 && r.j.unchanged, 'same page again → unchanged');

  // 2. Assist: pending pages read once each, then the answer uses them
  mark = fs.readFileSync(LOG, 'utf8').length;
  r = await post({ ask: 'Priya: for Chicago to Atlanta which carrier is cheapest per month after minimums and the 8% surcharge, and the cost?', pressed: true });
  check(r.status === 200 && /redline/i.test(r.j.answer || '') && /4,?860/.test(r.j.answer || ''), 'assist answers from the captured pages (Redline $4,860)', r.j.answer);
  check(/read 2 pending screens at assist/.test(logSince(mark)), 'pending screens read at assist time, once', logSince(mark).slice(-500));
  sc = await screens();
  check(sc.length === 2 && sc.every(x => x.has_text), 'transcripts now stored', JSON.stringify(sc));
  const seen = await seenRows();
  check(seen.length === 2 && seen.some(x => /4,?500/.test(x.text)) && seen.some(x => /\b60\b/.test(x.text)), 'seen rows carry the pages (minimums, volumes)', JSON.stringify(seen.map(x => x.text.slice(0, 80))));
  // 2b. The capture list endpoint: every stored screen of this call, read state + first line
  const lr = await fetch(BASE + '/api/sessions/' + s.id + '/copilot/screens', { headers: { Authorization: 'Bearer ' + token } });
  const lj = await lr.json();
  check(lr.ok && Array.isArray(lj.screens) && lj.screens.length === 2 && lj.screens.every(x => x.read && x.head && x.ts && x.key), 'capture list lists both screens as read with a first line', JSON.stringify(lj).slice(0, 300));
  // 3. A second assist reads nothing again
  mark = fs.readFileSync(LOG, 'utf8').length;
  r = await post({ ask: 'And the Dallas volume?', pressed: true });
  check(r.status === 200 && /\b140\b/.test(r.j.answer || ''), 'second assist answers (140)', r.j.answer);
  check(!/read \d+ pending screens/.test(logSince(mark)), 'nothing re-read');

  // 4. Stop → images dropped, transcripts kept
  ws.send(JSON.stringify({ type: 'stop' })); await sleep(800);
  sc = await screens();
  check(sc.length === 2 && sc.every(x => !x.has_image && x.has_text), 'after stop: images dropped, transcripts kept', JSON.stringify(sc));
  ws.close(); await pool.end();
  console.log(`\n${fail ? 'FAILED' : 'ALL PASS'} (${pass} pass, ${fail} fail)`); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
