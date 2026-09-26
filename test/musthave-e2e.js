// Must-have questions (incl. influence & pushback) are in every session's bank with answers ready, and real-world
// wordings of them hit the prepared answer instantly. Real server + real Claude. Usage: node test/musthave-e2e.js [baseUrl]
require('dotenv').config();
const fs = require('fs'), path = require('path');
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3997';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const INFLUENCE = ['How do you convince executives to use a report, tool, or recommendation you built?', 'How do you get buy-in when stakeholders are not sold on your idea?',
  'Tell me about a time someone pushed back on your recommendation. How did you handle it?', 'What do you do when leadership disagrees with what your data or analysis shows?',
  'How do you get people to actually adopt something new you built?', 'Tell me about a time you influenced a decision without having authority.',
  'How do you handle a stakeholder who keeps changing requirements?', 'Tell me about a time you had to say no to a stakeholder.'];
const key = t => t.toLowerCase().replace(/[^a-z]/g, '');
async function user(plan) {
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'MH',$2) RETURNING id", ['mh-' + Date.now() + Math.random() + '@local.test', plan])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1,'Keystone Logistics','Senior Data Analyst',$2,$3) RETURNING id",
    [u.id, fs.readFileSync(path.join(__dirname, 'fixtures', 'resume.txt'), 'utf8'), fs.readFileSync(path.join(__dirname, 'fixtures', 'jd.txt'), 'utf8')])).rows[0];
  return { token: jwt.sign({ userId: u.id, name: 'MH', email: 'x', plan }, process.env.JWT_SECRET, { expiresIn: '1h' }), sessionId: s.id };
}
async function bankState(sessionId) {
  const rows = (await pool.query('SELECT text, answer, starred FROM questions WHERE session_id = $1', [sessionId])).rows;
  const inf = rows.filter(r => INFLUENCE.some(q => key(q) === key(r.text)));
  return { present: inf.length, answered: inf.filter(r => r.answer && r.answer.length > 20).length, starred: inf.filter(r => r.starred).length };
}
(async () => {
  let fails = 0; const check = (name, ok, detail) => { if (!ok) fails++; console.log(`  ${ok ? '✓' : '✗'} ${name}${detail ? '  — ' + detail : ''}`); };

  console.log('\n### PAID user — fresh session, go live');
  const a = await user('pro');
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const got = [];
  ws.on('message', d => { try { const m = JSON.parse(d); if (['match', 'new_question', 'live_answer'].includes(m.type)) got.push({ t: Date.now(), m }); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token: a.token, sessionId: a.sessionId, mode: 'full', platform: 'electron', dualStream: true }));
  let st; const t0 = Date.now();
  for (let i = 0; i < 120; i++) { await sleep(1000); st = await bankState(a.sessionId); if (st.answered === INFLUENCE.length) break; }
  check('8 influence questions in the bank, starred', st.present === 8 && st.starred === 8, JSON.stringify(st));
  check('all 8 answered before any is asked', st.answered === 8, `ready in ${Math.round((Date.now() - t0) / 1000)} s`);
  await sleep(1500); // let the live call reload its bank
  for (const q of ['How do you convince people when they are not buying your idea?', 'What do you do when your boss pushes back on your analysis?', 'How would you get executives to actually use your dashboard?']) {
    const from = got.length, t1 = Date.now();
    ws.send(JSON.stringify({ type: 'canvas_question', text: q }));
    for (let i = 0; i < 100 && !got.slice(from).some(e => (e.m.type === 'match' || e.m.type === 'live_answer') && e.m.answer); i++) await sleep(100);
    const first = got.slice(from).find(e => (e.m.type === 'match' || e.m.type === 'live_answer') && e.m.answer);
    const hit = first && first.m.type === 'match' && INFLUENCE.some(b => key(b) === key(first.m.questionText || ''));
    check(`"${q}" → prepared answer`, hit, first ? `${first.m.type}: "${first.m.questionText}" in ${first.t - t1} ms` : 'nothing');
    await sleep(4000);
  }
  // Not in the bank → must NOT be forced onto a bank question (meaning match + AI check stay strict on subject)
  { const from = got.length; ws.send(JSON.stringify({ type: 'canvas_question', text: 'What is the difference between WHERE and HAVING in SQL?' }));
    for (let i = 0; i < 100 && !got.slice(from).some(e => (e.m.type === 'match' || e.m.type === 'live_answer') && e.m.answer); i++) await sleep(100);
    const first = got.slice(from).find(e => (e.m.type === 'match' || e.m.type === 'live_answer') && e.m.answer);
    check('unrelated question is not forced onto a bank answer', first && first.m.type !== 'match', first ? `${first.m.type}: "${first.m.questionText}"` : 'nothing'); }
  ws.close();

  console.log('\n### FREE user — questions added, answers NOT auto-generated (plan limit)');
  const b = await user('free');
  const ws2 = new WebSocket(BASE.replace(/^http/, 'ws'));
  await new Promise(r => ws2.on('open', r));
  ws2.send(JSON.stringify({ type: 'start', token: b.token, sessionId: b.sessionId, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(15000); const st2 = await bankState(b.sessionId); ws2.close();
  check('8 influence questions present', st2.present === 8, JSON.stringify(st2));
  check('no auto-generated answers', st2.answered === 0);

  await pool.end(); console.log(`\n${fails ? fails + ' FAILED' : 'ALL PASS'}`); process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
