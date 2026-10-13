// Desktop Assessment, end to end on a LOCAL server (real routes, real WS, real models — kept small: 2 screens, 3 presses).
// Usage: DATABASE_URL=<local> node test/assessment-e2e.js http://localhost:3999 <server log path>
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
const logSince = mark => fs.readFileSync(LOG).subarray(mark).toString('utf8'); // mark is a byte offset (statSync.size)
const waitLog = async (mark, re, ms) => { const t = Date.now(); while (Date.now() - t < ms) { const m = logSince(mark).match(re); if (m) return m; await sleep(500); } return null; };
const img = f => fs.readFileSync(path.join(__dirname, 'fixtures/screens', f)).toString('base64');

(async () => {
  const email = 'assessment-e2e@local.test';
  let u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Assess Tester','pro') RETURNING *", [email])).rows[0];
  await pool.query("DELETE FROM sessions WHERE user_id=$1 AND kind='assessment'", [u.id]); // local test user only
  if (!(await pool.query("SELECT 1 FROM sessions WHERE user_id=$1 AND coalesce(kind,'interview')<>'assessment'", [u.id])).rows.length)
    await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1,'Acme','Data Analyst','RESUME-MARKER: 5 years SQL at Acme.')", [u.id]);
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'pro', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
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

  // 1. first open: nothing yet → start new; a second Start reuses the blank
  let { j } = await api('GET', '/api/assessments');
  check(j.allowed === true && Array.isArray(j.items) && j.items.length === 0, 'first open: allowed, no history', JSON.stringify(j));
  const a1 = (await api('POST', '/api/assessments')).j;
  const a1b = (await api('POST', '/api/assessments')).j;
  check(a1.id && a1b.id === a1.id && a1b.reused, 'a blank assessment is reused, not piled up', JSON.stringify([a1, a1b]));
  const sess = (await api('GET', '/api/sessions')).j;
  check(Array.isArray(sess) && !sess.some(s => s.id === a1.id), 'assessment not in the company session list');
  const row = (await pool.query('SELECT kind, company, resume FROM sessions WHERE id=$1', [a1.id])).rows[0];
  check(row.kind === 'assessment' && row.company === '' && /RESUME-MARKER/.test(row.resume), 'not tied to a company; his résumé rides along', JSON.stringify(row));

  // 2. sitting 1: instructions page + a question page captured, one press answers it, stop → carry + title lock
  let mark = fs.statSync(LOG).size;
  let ws = await live(a1.id);
  check(!!(await waitLog(mark, /\[Assessment\] sitting \S+ starts from nothing \(first sitting\)/, 8000)), 'first sitting starts from nothing');
  for (const [k, f] of [['scr-e2e-ins', 'instructions.png'], ['scr-e2e-mcq', 'mcq.png']])
    await api('POST', '/api/sessions/' + a1.id + '/copilot', { capture: true, image: img(f), screenKey: k });
  let res = await api('POST', '/api/sessions/' + a1.id + '/copilot', { pressed: true, screenKey: 'scr-e2e-mcq' });
  console.log('  · press 1:', String(res.j.answer || res.j.error).replace(/\n/g, ' ⏎ ').slice(0, 300));
  check(/HAVING/i.test(res.j.answer || ''), 'press answers the question on the captured page (HAVING)');
  mark = fs.statSync(LOG).size;
  ws.send(JSON.stringify({ type: 'stop' }));
  const carried = await waitLog(mark, /\[Assessment\] sitting \S+ carried in (\d+)ms \((\d+) chars[^\n]*/, 60000);
  console.log('  · ' + (carried ? carried[0] : 'no carry line'));
  check(!!carried, 'stop carries the sitting');
  check(carried && /title locked: "/.test(carried[0]), 'first carry locks the title');
  ws.close(); await sleep(500);
  j = (await api('GET', '/api/assessments')).j;
  const item = (j.items || [])[0] || {};
  console.log('  · list:', JSON.stringify(j.items));
  check(item.id === a1.id && item.title && !/^(online )?assessment$/i.test(item.title) && item.carried, 'history shows it by its title, carried');
  check(/talentcheck|sql/i.test(item.title || ''), 'title names what it is (TalentCheck / SQL)', item.title);
  const t1 = item.title;

  // 3. a new one is a NEW id now (the first has content); the first keeps its title
  const a2 = (await api('POST', '/api/assessments')).j;
  check(a2.id && a2.id !== a1.id && !a2.reused, 'Start new after real use → a new assessment');

  // 4. continue the first: the new sitting starts from the carry; the same page pressed again is not redone
  mark = fs.statSync(LOG).size;
  ws = await live(a1.id);
  check(!!(await waitLog(mark, /\[Assessment\] sitting \S+ starts from the carry \(\d+ chars\)/, 15000)), 'continue starts from the carry');
  await api('POST', '/api/sessions/' + a1.id + '/copilot', { capture: true, image: img('mcq.png'), screenKey: 'scr-e2e-mcq2' });
  res = await api('POST', '/api/sessions/' + a1.id + '/copilot', { pressed: true, screenKey: 'scr-e2e-mcq2' });
  console.log('  · press 2 (same page, new sitting):', String(res.j.answer || res.j.error).replace(/\n/g, ' ⏎ ').slice(0, 400));
  check(/nothing open|already answered|stands|answered earlier/i.test(res.j.answer || ''), 'same question in the next sitting is not answered again');
  res = await api('POST', '/api/sessions/' + a1.id + '/copilot', { ask: 'what have I done so far in this assessment and where did I stop?', typed: true });
  console.log('  · typed recap:', String(res.j.answer || res.j.error).replace(/\n/g, ' ⏎ ').slice(0, 400));
  check(/HAVING|question 4/i.test(res.j.answer || ''), 'continuation knows what was done');
  mark = fs.statSync(LOG).size;
  ws.send(JSON.stringify({ type: 'stop' })); ws.close();
  const c2 = await waitLog(mark, /\[Assessment\] sitting \S+ carried[^\n]*/, 60000);
  check(c2 && !/title locked/.test(c2[0]), 'second carry does not change the locked title');
  const t2 = (await pool.query('SELECT title FROM sessions WHERE id=$1', [a1.id])).rows[0].title;
  check(t2 === t1, 'title stays locked', t1 + ' → ' + t2);

  console.log(`\n${fail ? 'FAILED' : 'ALL PASS'} (${pass} pass, ${fail} fail)`);
  await pool.end(); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
