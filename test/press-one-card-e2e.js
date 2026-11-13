// ONE CARD PER ASK (live 12 Nov, Tableau walkthrough): Assist was pressed while the interviewer was still asking, and every
// ask got two cards — the press's and the heard ask's. Lines below are the real ones from that call, pressed at the same
// moments. Real server + real Deepgram + real models, co-pilot mode on (the overlay's parts mimicked as in the rehearsal).
// Usage: node test/press-one-card-e2e.js [baseUrl]   (LOCAL DATABASE_URL; server with MUSTHAVE_PREBUILD=0)
require('dotenv').config();
const { execFileSync } = require('child_process'); const fs = require('fs'), os = require('os'), path = require('path');
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3997';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL }); const sleep = ms => new Promise(r => setTimeout(r, ms));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-p1-'));
const speech = (t, v) => { const a = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), w = a.replace('.aiff', '.wav'); execFileSync('say', ['-v', v, '-o', a, t]); execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', a, w]); return fs.readFileSync(w).slice(44); };
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
const SHOT = 'data:image/png;base64,' + fs.readFileSync(path.join(__dirname, 'fixtures/screens/tableau-superstore.png')).toString('base64');

// [name, lines spoken in order (PRESS = Assist between lines), press timing, expect]
//  'mid'   = Assist while the last line is still being spoken (1.2 s before its end)
//  'after' = Assist 3 s after the heard ask's card started
//  'alone' = Assist after 10 s of quiet (a normal press: must still make its card)
const CASES = [
  ['pressed mid-question (16:45:27 on the call)', ['Perfect. One more question to demonstrate. Can you create a hierarchy, like, using category, sub category, and product name, if they wanted to see all in this dashboard? Where you can basically drill down, or drill up.'], 'mid', { starts: 1, dup: false }],
  ['pressed 3 s after the card (16:48:16 on the call)', ['So let\'s say a business user comes back and asks you to enhance this dashboard. He is really having issues navigating it. What do you think? How can you enhance this one?'], 'after', { starts: 1, dup: true }],
  ['pressed on "Perfect." before the question (16:52:57 on the call)', ['Perfect.', 'PRESS', 'Can you tell me a bit, go in detail, about the data validation or QC, like how you do that?'], 'between', { starts: 1, dup: false, about: /validat|QC|quality/i }],
  ['a normal press after quiet still makes its card', [], 'alone', { starts: 1, dup: false }],
];

(async () => {
  const email = 'rehearsal@local.test';
  let u = (await pool.query('SELECT id FROM users WHERE email = $1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1, 'RH', 'pro') RETURNING id", [email])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1, 'Honest Health', 'BI Analyst', 'BI Analyst: Tableau and Power BI dashboards, SQL, Snowflake.') RETURNING id", [u.id])).rows[0];
  const token = jwt.sign({ userId: u.id, name: 'RH', email, plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const post = body => fetch(`${BASE}/api/sessions/${s.id}/copilot`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify(body) }).then(r => r.json()).catch(e => ({ error: String(e) }));
  let shared = false; const frame = () => shared ? {} : (shared = true, { image: SHOT, screenChanged: true, screenKey: 'scr-tableau' });
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const got = [];
  ws.on('message', d => { try { const m = JSON.parse(d); m._t = Date.now();
    if (/copilot_(start|done|dup)|question_detected/.test(m.type)) got.push(m);
    if (m.type === 'question_detected' && m.source === 'copilot') post({ ask: m.text, ...frame() }); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500); ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: false })); await sleep(500);
  let pressRes = null; const press = () => post({ ask: '', pressed: true, ...frame() }).then(r => { pressRes = r; });
  // stream audio; `at` (ms before the end) fires a callback once while the words are still going out
  const audio = async (buf, at, fn) => { const end = buf.length; let fired = false;
    for (let o = 0; o < end; o += 3200) { if (fn && !fired && (end - o) / 32 <= at) { fired = true; fn(); }
      ws.send(Buffer.concat([Buffer.from([1]), buf.slice(o, o + 3200)])); ws.send(Buffer.concat([Buffer.from([2]), silence(100)])); await sleep(100); } };
  let fail = 0;
  for (const [name, lines, when, want] of CASES) {
    const i0 = got.length; pressRes = null; const t0 = Date.now();
    if (when === 'alone') { await audio(silence(10000)); press(); }
    const bufs = lines.map(l => l === 'PRESS' ? null : speech(l, 'Samantha')); // made up front: a sync TTS between lines held the press back ~1 s
    for (const b of bufs) {
      if (!b) { press(); continue; }
      await audio(b, when === 'mid' ? 1200 : 0, when === 'mid' ? press : null);
    }
    if (when === 'after') { for (let k = 0; k < 150 && !got.slice(i0).some(m => m.type === 'copilot_start'); k++) await audio(silence(100)); await audio(silence(3000)); press(); }
    for (let k = 0; k < 40 && !(got.slice(i0).some(m => m.type === 'copilot_done') && pressRes); k++) await audio(silence(500));
    await audio(silence(4000)); // a late second card would land here
    const here = got.slice(i0), starts = here.filter(m => m.type === 'copilot_start'), done = here.filter(m => m.type === 'copilot_done').pop();
    const checks = [[`${want.starts} card (got ${starts.length})`, starts.length === want.starts], ['press answered (' + JSON.stringify(pressRes) + ')', !!pressRes && !pressRes.error],
      [want.dup ? 'press went to the card (copilot_dup)' : 'no jump needed', want.dup ? here.some(m => m.type === 'copilot_dup') : true]];
    if (want.about) checks.push(['the card answers the ask that followed', !!done && want.about.test(done.answer || '')]);
    console.log(`\n${name}  (${((Date.now() - t0) / 1000).toFixed(0)} s)`); for (const [l, ok] of checks) { console.log(`   ${ok ? 'PASS' : 'FAIL'} ${l}`); if (!ok) fail++; }
    for (const m of starts) console.log('     card:', (m.ask || '(press)').slice(0, 90));
  }
  ws.close(); await pool.end();
  console.log(fail ? `\n${fail} FAILED` : '\nALL PASS (one card per ask)'); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
