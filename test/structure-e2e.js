// Live answer STRUCTURE test: real server + real Claude through the live path (start → typed question → answer).
// Checks the output contract from the LIVE ANSWER COMPOSER for each question type and a range of styles.
// Usage: node test/structure-e2e.js [baseUrl]     (LOCAL DATABASE_URL only)
require('dotenv').config();
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3997';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const RESUME = `Ridwan Akanbi — Data Analyst, R&L Carriers (Mar 2022–present). Freight & operations reporting.
- Build SQL and Power BI reporting on freight shipments, terminals and claims.
- Reconciled legacy AS/400 tables with newer SQL Server marts after numbers didn't match; fixed a field-mapping issue.
- Automated weekly terminal KPI pack (Excel → Power BI), saving ops managers ~6 hours/week.
Skills: SQL, Power BI, Excel, Python.`;
async function ask(q, style) {
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Str','pro') RETURNING id", ['str-' + Date.now() + Math.random() + '@local.test'])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd, answer_style) VALUES ($1,'Keystone Freight','Senior Data Analyst',$2,'Senior Data Analyst — SQL, Power BI, logistics reporting.',$3) RETURNING id", [u.id, RESUME, style])).rows[0];
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); let answer = '';
  ws.on('message', d => { try { const m = JSON.parse(d); if (m.type === 'live_answer' && m.answer) answer = m.answer; } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token: jwt.sign({ userId: u.id, name: 'Str', email: 'x', plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' }), sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  ws.send(JSON.stringify({ type: 'canvas_question', text: q }));
  for (let i = 0; i < 250 && !answer; i++) await sleep(100);
  ws.close(); return answer;
}
const L = a => a.split('\n').filter(Boolean);
const bullets = a => L(a).filter(l => l.startsWith('• '));
const has = (a, re) => L(a).some(l => re.test(l));
const CASES = [
  ['general, no history → answer only, no employer', 'What is the difference between WHERE and HAVING?', 'conversational', a => [
    ['2–4 bullet lines', bullets(a).length >= 2 && bullets(a).length <= 4], ['no ↳ employer line', !has(a, /^↳/)], ['no ▸ heading', !has(a, /^▸/)], ['no employer named', !/R&L/.test(a)]]],
  ['code → code block first, then why', 'Write a SQL query to get the second highest salary in each department.', 'conversational', a => [
    ['first line opens code block', /^```/.test(L(a)[0])], ['1–2 bullet lines after code', bullets(a).length >= 1 && bullets(a).length <= 2], ['no ▸ heading', !has(a, /^▸/)]]],
  ['story → ▸ At <employer> heading + story lines', 'Tell me about a time you had to fix data that did not match.', 'conversational', a => [
    ['first line ▸ At R&L', /^▸ At R&L/i.test(L(a)[0])], ['3–5 bullet lines', bullets(a).length >= 3 && bullets(a).length <= 5], ['no ↳ line', !has(a, /^↳/)]]],
  ['pitch → who → proof → why, no separate employer line', 'Tell me a bit about yourself.', 'conversational', a => [
    ['3–5 bullet lines', bullets(a).length >= 3 && bullets(a).length <= 5], ['no ↳ line', !has(a, /^↳/)], ['no ▸ heading', !has(a, /^▸/)]]],
  ['STAR style on a story → labels', 'Tell me about a time you had to fix data that did not match.', 'star', a => [
    ['▸ heading first', /^▸/.test(L(a)[0])], ['Situation/Action/Result labels', has(a, /^Situation:/) && has(a, /^Action:/) && has(a, /^Result:/)]]],
  ['STAR style on a general question → plain lines (labels only for stories)', 'What is the difference between WHERE and HAVING?', 'star', a => [
    ['no STAR labels', !has(a, /^(Situation|Action|Result):/)], ['bullets', bullets(a).length >= 1]]],
  ['Executive style → at most 2 answer lines', 'How do you prioritize competing deadlines?', 'executive', a => [
    ['≤ 2 bullet lines', bullets(a).length >= 1 && bullets(a).length <= 2]]],
  ['Keyword style → short cues, same layout', 'How do you prioritize competing deadlines?', 'keywords', a => [
    ['every line ≤ 8 words', bullets(a).every(l => l.replace(/^• /, '').split(/\s+/).length <= 8)], ['bullets', bullets(a).length >= 1]]],
];
// Switching style DURING a live call must apply to the next answer (real PUT route the app uses).
async function midCallSwitch() {
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Sw','pro') RETURNING id", ['sw-' + Date.now() + '@local.test'])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, answer_style) VALUES ($1,'Keystone Freight','Senior Data Analyst',$2,'conversational') RETURNING id", [u.id, RESUME])).rows[0];
  const token = jwt.sign({ userId: u.id, name: 'Sw', email: 'x', plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const answers = [];
  ws.on('message', d => { try { const m = JSON.parse(d); if (m.type === 'live_answer' && m.answer) answers.push(m.answer); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  const r = await fetch(BASE + '/api/sessions/' + s.id + '/answer-style', { method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify({ style: 'keywords' }) });
  ws.send(JSON.stringify({ type: 'canvas_question', text: 'How do you prioritize competing deadlines?' }));
  for (let i = 0; i < 250 && !answers.length; i++) await sleep(100);
  ws.close();
  const a = answers[0] || '';
  const ok = r.ok && a && bullets(a).every(l => l.replace(/^• /, '').split(/\s+/).length <= 8);
  console.log(`\n### style switched mid-call → next answer uses it  [conversational → keywords]\n  PUT ${r.status}\n  ${(a || '(no answer)').split('\n').join('\n  ')}\n  RESULT: ${ok ? 'PASS' : 'FAIL'}`);
  return ok;
}

(async () => {
  let fails = 0;
  if (!process.env.ONLY || 'switch'.includes(process.env.ONLY) || process.env.ONLY === 'switch') { if (!(await midCallSwitch())) fails++; }
  for (const [name, q, style, checks] of CASES) {
    if (process.env.ONLY && !name.includes(process.env.ONLY)) continue;
    const a = await ask(q, style);
    const res = a ? checks(a) : [['answer arrived', false]];
    const bad = res.filter(([, ok]) => !ok);
    if (bad.length) fails++;
    console.log(`\n### ${name}  [${style}]\n  Q: ${q}\n  ${(a || '(no answer)').split('\n').join('\n  ')}\n  ${res.map(([n, ok]) => (ok ? '✓ ' : '✗ ') + n).join('   ')}\n  RESULT: ${bad.length ? 'FAIL' : 'PASS'}`);
  }
  await pool.end(); console.log(`\n${fails ? fails + ' FAILED' : 'ALL PASS'}`); process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
