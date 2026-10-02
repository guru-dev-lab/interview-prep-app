// Co-pilot use keeps the live connection open; typed co-pilot text is the candidate's, not the interviewer's;
// web "Switch Tab" re-opens the interviewer stream through the ONE handler (the one with the echo check).
// Usage: node test/copilot-switchtab-e2e.js [http://localhost:3999] <server log path>
//   (LOCAL DATABASE_URL only; server with IDLE_TIMEOUT_MS=20000 MUSTHAVE_PREBUILD=0)
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
const check = (ok, label, detail) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + label + (detail && !ok ? '\n     ' + String(detail).replace(/\n/g, '\n     ') : '')); };

(async () => {
  // Reuse ONE local test user + session (test spend rule)
  const email = 'screen-e2e@local.test';
  let u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Screen Tester','pro') RETURNING *", [email])).rows[0];
  let s = (await pool.query('SELECT id FROM sessions WHERE user_id=$1 LIMIT 1', [u.id])).rows[0];
  if (!s) s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1,'Acme Analytics','Data Analyst','Data analyst, 4 years. SQL, Power BI, Excel, Python. Built sales dashboards at Northwind.') RETURNING id", [u.id])).rows[0];
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'pro', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });

  const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
  let wsClosed = false;
  ws.on('close', () => { wsClosed = true; });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'web', dualStream: true }));
  await sleep(1500);
  // measured after start — live start inserts the must-have questions on its own
  const bankBefore = (await pool.query('SELECT count(*)::int n FROM questions WHERE session_id=$1', [s.id])).rows[0].n;

  // 1. Co-pilot only (no audio, no screen-assist) for 26 s on a 20 s idle limit → the connection stays live
  const shot = 'data:image/png;base64,' + fs.readFileSync(require('path').join(__dirname, 'fixtures/screens/mcq.png')).toString('base64');
  const copilot = async (transcript, mode, image) => {
    const r = await fetch(BASE + '/api/sessions/' + s.id + '/copilot', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
      body: JSON.stringify({ transcript, mode, image })
    });
    const j = await r.json();
    console.log(`  · copilot ${mode} → ${r.status} | ${(j.answer || j.error || '').replace(/\n/g, ' ').slice(0, 110)}`);
    return { r, j };
  };
  const typed = 'I opened the pivot table, now sum sales by region';
  let res = await copilot(typed, 'typed');
  check(res.r.ok && res.j.answer, 'typed co-pilot step answered', JSON.stringify(res.j));
  check(!/interviewer (just )?(said|asked)/i.test(res.j.answer || ''), 'typed text is not treated as the interviewer speaking', res.j.answer);
  for (let t = 0; t < 2; t++) { await sleep(9000); await copilot('', 'check', shot); }
  await sleep(8000);
  check(!wsClosed, 'co-pilot use keeps the live connection open past the idle limit');

  // 2. Switch Tab → stream closed; next Ch1 packet re-opens it through the one handler (lazy setup)
  const mark = fs.readFileSync(LOG, 'utf8').length;
  ws.send(JSON.stringify({ type: 'switch_tab' }));
  await sleep(500);
  const pcm = Buffer.alloc(3201); pcm[0] = 1; // channel 1 + 1600 samples of silence
  for (let i = 0; i < 5; i++) { ws.send(pcm); await sleep(100); }
  await sleep(1500);
  const after = fs.readFileSync(LOG, 'utf8').slice(mark);
  check(/Switching tab/.test(after), 'switch_tab received');
  check(/Opening interviewer stream \(lazy\)/.test(after), 'new tab audio opens through _setupInterviewerDG (echo-checked handler)', after.slice(0, 800));

  // 3. Co-pilot never writes to the question bank
  const bankAfter = (await pool.query('SELECT count(*)::int n FROM questions WHERE session_id=$1', [s.id])).rows[0].n;
  check(bankAfter === bankBefore, `question bank unchanged (${bankBefore} → ${bankAfter})`);

  ws.close(); await pool.end();
  console.log(`\n${fail ? 'FAILED' : 'ALL PASS'} (${pass} pass, ${fail} fail)`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
