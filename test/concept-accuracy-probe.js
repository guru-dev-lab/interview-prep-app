// Concept accuracy probe (13 Nov: "blue and green pills" after "dimension vs measure" came back as dimension/measure 3 of 4 runs): N asks on a local server, prints each card's Say + PASS/FAIL. Usage: node run.js <base> <N> <out>
require('dotenv').config();
const R = p => require(p);
const fs = require('fs'); const WebSocket = R('ws'); const jwt = R('jsonwebtoken'); const { Pool } = R('pg');
const BASE = process.argv[2], N = +process.argv[3] || 3, OUT = process.argv[4];
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL)) process.exit(2);
const pool = new Pool({ connectionString: process.env.DATABASE_URL }); const sleep = ms => new Promise(r => setTimeout(r, ms));
const SHOT = 'data:image/png;base64,' + fs.readFileSync(require('path').join(__dirname, 'fixtures/screens/tableau-superstore.png')).toString('base64');
// [ask, pass test] — the pills one twice as often: it is the one that failed
const ASKS = [
  ["What's the difference between a dimension and a measure?", a => /qualitative|categor/i.test(a) && /quantitative|numer|aggregat/i.test(a)],
  ['And what do the blue and green pills mean?', a => /discrete/i.test(a) && /continuous/i.test(a) && !/blue( pills)?[^.\n]{0,12}\b(are|=|means?)\s+(the\s+)?dimensions?\b/i.test(a) && !/answered earlier/i.test(a)],
];
(async () => {
  const u = (await pool.query("SELECT id FROM users WHERE email = 'rehearsal@local.test'")).rows[0];
  const token = jwt.sign({ userId: u.id, name: 'RH', email: 'rehearsal@local.test', plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const log = []; let pass = 0, n = 0;
  for (let run = 0; run < N; run++) {
    const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1, 'Honest Health', 'BI Analyst', 'BI Analyst: Tableau and Power BI dashboards, SQL.') RETURNING id", [u.id])).rows[0];
    const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const done = [];
    ws.on('message', d => { try { const m = JSON.parse(d); if (m.type === 'copilot_done') done.push(m); } catch (e) {} });
    await new Promise(r => ws.on('open', r));
    ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
    await sleep(1200); ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: false })); await sleep(400);
    let first = true;
    for (const [ask, ok] of ASKS) {
      const k = done.length;
      await fetch(`${BASE}/api/sessions/${s.id}/copilot`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify({ ask, ...(first ? { image: SHOT, screenChanged: true, screenKey: 'scr-t' } : {}) }) });
      first = false;
      for (let i = 0; i < 60 && done.length === k; i++) await sleep(500);
      const a = (done[k] || {}).answer || ''; const good = ok(a); n++; if (good) pass++;
      console.log(`run ${run} ${good ? 'PASS' : 'FAIL'} — ${ask}`);
      log.push(`### run ${run} ${good ? 'PASS' : 'FAIL'} — ${ask}\n${a}\n`);
    }
    ws.close();
  }
  fs.writeFileSync(OUT, log.join('\n')); console.log(`${pass}/${n} pass`); await pool.end(); process.exit(0);
})();
