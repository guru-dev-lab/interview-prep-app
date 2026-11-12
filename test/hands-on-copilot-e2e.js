// Hands-on tool walkthrough (owner, 12 Nov: a Tableau Public walkthrough with Superstore — "it can be any tool tomorrow",
// nothing hard-coded). Real copilot route + real models: a heard build ask gets a build recipe (Build / places / Calc /
// Steps / Talk track / Next) from the model's own knowledge of the tool and the public dataset.
// Labels may come bare or bold: the overlay bolds them (canvas.html cpLabels).
// Usage: node test/hands-on-copilot-e2e.js [baseUrl] [regular|smart]   (LOCAL DATABASE_URL; server with MUSTHAVE_PREBUILD=0)
require('dotenv').config();
const fs = require('fs'); const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3997', MODE = process.argv[3] || 'regular';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL }); const sleep = ms => new Promise(r => setTimeout(r, ms));
const has = (a, re) => re.test(a);
const SHOT = 'data:image/png;base64,' + fs.readFileSync(require('path').join(__dirname, 'fixtures/screens/tableau-superstore.png')).toString('base64');
const CASES = [
  ['You have Tableau Public open with the Superstore data. Can you show me which sub-categories are losing money?', a => [
    ['Build line', has(a, /\*\*Build:\*\*/)], ['numbered Steps', has(a, /\*\*Steps:\*\*[\s\S]*\n\s*1[.)]/)], ['Superstore fields named', has(a, /`Sub-Category`/) && has(a, /Profit/)],
    ['Tableau places (Rows/Columns/Marks)', has(a, /\*\*(Rows|Columns|Marks)/)], ['Talk track', has(a, /^(\*\*)?Talk track:/m)], ['Next idea', has(a, /^(\*\*)?Next:/m)]]],
  ["Let's calculate the profit ratio and show it by region.", a => [
    ['Calc fenced (a code box with copy)', has(a, /```(formula|tableau|text|sql)[\s\S]*SUM\(\[Profit\]\)\s*\/\s*SUM\(\[Sales\]\)[\s\S]*```/)], ['Region used', has(a, /`Region`/)], ['numbered Steps', has(a, /\n\s*1[.)]/)]]],
  ["How would you tell the story of what's driving the losses in this data?", a => [
    ['three beats', (a.match(/\*\*(Beat|1|2|3|What|Where|Why|So what)/gi) || []).length >= 2 || (a.match(/\((what|where|why)\)/gi) || []).length >= 2 || (a.match(/\b(what|where|why)\b\s*[:)]/gi) || []).length >= 2 || /what.{0,25}(losing|happening)[\s\S]*where[\s\S]*why/i.test(a) || /what('s| is) happening[\s\S]*why/i.test(a)],
    ['discount named as a driver to look at', has(a, /discount/i)], ['dashboard or story points', has(a, /dashboard|story point/i)], ['Talk track', has(a, /^(\*\*)?Talk track:/m)]]],
  ['Different tool now. In Power BI with the AdventureWorks sample, how would you show sales by month with a year over year comparison?', a => [
    ['Build line', has(a, /\*\*Build:\*\*/)], ['Power BI places (axis / values / legend / visual)', has(a, /X-axis|Y-axis|Values|Legend|line chart/i)], ['DAX measure fenced', has(a, /```(dax|text|formula)[\s\S]*(SAMEPERIODLASTYEAR|DATEADD|CALCULATE)[\s\S]*```/)]]],
  // ON-SCREEN DATA AS SUPPORT (owner, 12 Nov: "use audio and maybe on screen details as supportive data"): his Tableau screen
  // (fixture: Profit by Sub-Category, the newer Superstore field names, a YEAR filter left on) rides with the heard ask.
  ['Okay, I can see your screen now. Which states are driving the losses on Tables?', a => [
    ['reads the screen: Tables -17,725', has(a, /-?17,?725/)], ['field name as shown on screen: `State/Province`', has(a, /State\/Province/)],
    ['notices the YEAR(Order Date) filter left on', has(a, /YEAR\(Order Date\)|year filter|filter.{0,40}year/i)], ['numbered Steps', has(a, /\n\s*1[.)]/)]], SHOT],
  ["What's the story in this chart right now?", a => [
    ['cites the top on screen (Copiers 55,618)', has(a, /Copiers/) && has(a, /55,?618/)], ['cites the losers on screen', has(a, /Tables/) && has(a, /Bookcases/)]], SHOT],
];
(async () => {
  const email = 'hands-on@local.test';
  let u = (await pool.query('SELECT id FROM users WHERE email = $1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1, 'HO', 'pro') RETURNING id", [email])).rows[0];
  let s = (await pool.query('SELECT id FROM sessions WHERE user_id = $1 LIMIT 1', [u.id])).rows[0];
  if (!s) s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1, 'Polaris Project', 'Data Analyst', 'Data Analyst, R&L Carriers. SQL, Python, Power BI, Tableau.') RETURNING id", [u.id])).rows[0];
  const token = jwt.sign({ userId: u.id, name: 'HO', email, plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const done = [];
  ws.on('message', d => { try { const m = JSON.parse(d); if (m.type === 'copilot_done') done.push(m.answer); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(2000);
  ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: MODE === 'smart' }));
  await sleep(500);
  const out = []; let fail = 0;
  for (const [ask, checks, image] of CASES) {
    const n = done.length, t0 = Date.now();
    const r = await fetch(`${BASE}/api/sessions/${s.id}/copilot`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify(image ? { ask, image } : { ask }) });
    if (!r.ok) { console.log('FAIL route', r.status, await r.text()); fail++; continue; }
    while (done.length === n && Date.now() - t0 < 60000) await sleep(200);
    const a = done[n] || '';
    console.log(`\n### [${MODE}] ${ask}  (${((Date.now() - t0) / 1000).toFixed(1)} s)\n${a}`);
    for (const [lbl, ok] of checks(a)) { console.log(`  ${ok ? 'PASS' : 'FAIL'} ${lbl}`); if (!ok) fail++; }
    out.push({ ask, answer: a });
  }
  fs.writeFileSync(process.env.HANDS_ON_OUT || `/tmp/hands-on-${MODE}.json`, JSON.stringify(out, null, 1));
  ws.close(); await pool.end();
  console.log(fail ? `\n${fail} FAILED` : '\nALL PASS'); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
