// Screen assist on ANY assessment, through the real route (owner, 2 Oct): suggest, don't dump; stay quiet when nothing
// new is on screen; real coding gets a real working answer; behavioral items get a decisive good-faith pick.
// Usage: node test/screen-assist-e2e.js [http://localhost:3999]   (LOCAL DATABASE_URL only; server with IDLE_TIMEOUT_MS=6000)
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');

const BASE = process.argv[2] || 'http://localhost:3999';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const shot = name => 'data:image/png;base64,' + fs.readFileSync(path.join(__dirname, 'fixtures/screens', name + '.png')).toString('base64');

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

  // A live connection, like the desktop app's, to prove screen use keeps it open
  const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
  let wsClosed = false, cards = 0;
  ws.on('close', () => { wsClosed = true; });
  ws.on('message', m => { try { if (JSON.parse(m).type === 'screen_assist') cards++; } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));

  const post = async (name, body) => {
    const t0 = Date.now();
    const r = await fetch(BASE + '/api/sessions/' + s.id + '/screen-assist', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
      body: JSON.stringify({ image: shot(name), ...body })
    });
    const j = await r.json();
    console.log(`  · ${name} ${body.auto ? 'auto' : 'pressed'} → ${r.status} in ${Date.now() - t0}ms ${j.unchanged ? '(quiet: ' + j.reason + ')' : '| ' + (j.questionText || '').slice(0, 70)}`);
    if (j.answer) console.log('    ' + j.answer.replace(/\n/g, '\n    '));
    return j;
  };

  // 1. Instructions page on Record → quiet (no item)
  let j = await post('instructions', { auto: true });
  check(j.unchanged && j.reason === 'no_item', 'instructions page: no card');

  // 2. Multiple choice → short suggestion with the right option
  j = await post('mcq', { auto: true });
  check(!j.unchanged && /suggested:?\**\s*B\b/i.test(j.answer), 'MCQ: suggests B (HAVING)', j.answer);
  check(j.answer && j.answer.split('\n').filter(l => l.trim()).length <= 3, 'MCQ: short (≤3 lines)', j.answer);

  // 3. Same item again on Record → quiet
  j = await post('mcq', { auto: true });
  check(j.unchanged && j.reason === 'same_item', 'same MCQ again: no new card');

  // 4. Same item, PRESSED with a typed instruction → always answers
  j = await post('mcq', { instruction: 'just the answer' });
  check(!j.unchanged && /\bB\b/.test(j.answer || ''), 'pressed + typed "just the answer": answers', j.answer);

  // 5. Numerical → $200,000 (B)
  j = await post('numerical', { auto: true });
  check(!j.unchanged && /200,?000|\bB\b/.test(j.answer || ''), 'numerical: $200,000', j.answer);

  // 6. Real coding → a working function that passes the examples + edge cases
  j = await post('coding', { auto: true });
  const code = ((j.answer || '').match(/```(?:javascript|js)?\s*\n([\s\S]*?)```/) || [])[1] || '';
  let codeOk = false, why = '';
  try {
    const fn = new Function(code + '\nreturn secondLargest;')();
    const cases = [[[3, 1, 4, 4, 2], 3], [[7, 7], null], [[-2, -5], -5], [[], null], [[5], null], [[1, 2, 3, 3], 2]];
    const bad = cases.filter(([inp, out]) => fn(inp.slice()) !== out);
    codeOk = !bad.length; why = bad.map(([i, o]) => JSON.stringify(i) + ' → ' + fn(i.slice()) + ' (want ' + o + ')').join('; ');
  } catch (e) { why = e.message; }
  check(codeOk, 'coding: real working solution passes 6 cases', why || j.answer);

  // 7. Situational judgement → decisive good-faith pick: Most A, Least D (or B/C), no hedging
  j = await post('sjt', { auto: true });
  check(!j.unchanged && /most\W+A\b/i.test(j.answer || '') && /least\W+[BCD]\b/i.test(j.answer || ''), 'SJT: Most A, Least B/C/D', j.answer);
  check(!/it depends|unsure|cannot determine/i.test(j.answer || ''), 'SJT: no hedging', j.answer);

  // 8. Personality → one decisive option
  j = await post('personality', { auto: true });
  check(!j.unchanged && /suggested:?\**\s*(strongly agree|agree|neutral|disagree|strongly disagree)/i.test(j.answer || '') && !/it depends|unsure/i.test(j.answer), 'personality: one decisive option', j.answer);

  // 9. Nothing from the screen saved into the question bank (live start adds must-haves on its own — not counted)
  const screenRows = Number((await pool.query("SELECT count(*) FROM questions WHERE session_id=$1 AND text LIKE '[Screen Assist]%'", [s.id])).rows[0].count);
  check(screenRows === 0, 'question bank: no screen rows', screenRows + ' screen rows');

  // 10. Live connection still open: server ran with a short idle timeout, screen use must keep it alive
  check(!wsClosed, 'live connection stayed open while the screen was in use (IDLE_TIMEOUT_MS=' + (process.env.IDLE_TIMEOUT_MS || 'unset') + ')');
  check(cards >= 6, 'cards reached the live connection (' + cards + ')');

  ws.close(); await pool.end();
  console.log(`\n${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
