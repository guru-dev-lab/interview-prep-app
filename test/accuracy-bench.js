// Technical accuracy + delay of live answers. Sends each question as a typed question through the real live path
// (start → canvas_question → answer), grades correctness with the strongest model, and times first words / full.
// Usage: node test/accuracy-bench.js <baseUrl>     (LOCAL DATABASE_URL only)
require('dotenv').config();
const https = require('https'); const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3999';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const QUESTIONS = [
  'In Snowflake, how do you find which queries are the slowest?',
  'Write a SQL query to get the second highest salary in each department.',
  'How would you remove duplicate rows in SQL but keep the most recent one?',
  'How do you calculate a 7-day rolling average in SQL?',
  'What is the difference between WHERE and HAVING?',
  'In Snowflake, what is a clustering key and when would you use one?',
  'In Power BI, what is the difference between a calculated column and a measure?',
  'What does the CALCULATE function do in DAX?',
  'In Excel, what is the difference between VLOOKUP and XLOOKUP?',
  'How would you find customers who ordered in January but not in February, in SQL?',
];
async function ask(q) {
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Acc','pro') RETURNING id", ['acc-' + Date.now() + Math.random() + '@local.test'])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1,'Keystone','Data Analyst','Data Analyst, R&L Carriers. SQL, Snowflake, Power BI, Excel, Python.','Data Analyst — SQL, Snowflake, Power BI.') RETURNING id", [u.id])).rows[0];
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); let first = 0, done = 0, answer = '', t0 = 0;
  ws.on('message', d => { try { const m = JSON.parse(d);
    if (m.type === 'live_answer_delta' && m.chunk && !first) first = Date.now() - t0;
    if (m.type === 'live_answer' && m.answer) { answer = m.answer; done = Date.now() - t0; if (!first) first = done; }
  } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token: jwt.sign({ userId: u.id, name: 'Acc', email: 'x', plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' }), sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500); t0 = Date.now();
  ws.send(JSON.stringify({ type: 'canvas_question', text: q }));
  for (let i = 0; i < 300 && !done; i++) await sleep(100);
  ws.close(); return { q, first, done, answer };
}
function grade(q, a) {
  const sys = 'You are a strict senior data engineer grading an interview answer for technical correctness. Reply ONLY JSON: {"correct":0-2,"errors":"list every factual or syntax error, or none"}. 2 = fully correct; 1 = mostly right but has an error or misleading claim; 0 = wrong, or uses a function/command/feature that does not exist.';
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ model: process.env.MODEL_OPUS || 'claude-opus-4-8', max_tokens: 3000, system: sys, messages: [{ role: 'user', content: `QUESTION: ${q}\n\nANSWER:\n${a}` }] });
    const req = https.request({ hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' } }, res => {
      let d = ''; res.on('data', c => d += c); res.on('end', () => { try { const t = JSON.parse(d).content.filter(c => c.type === 'text').map(c => c.text).join(''); resolve(JSON.parse(t.slice(t.indexOf('{'), t.lastIndexOf('}') + 1))); } catch (e) { reject(new Error('grade parse: ' + d.slice(0, 300))); } });
    }); req.on('error', reject); req.write(body); req.end();
  });
}
(async () => {
  let score = 0; const firsts = [], dones = [];
  for (const q of QUESTIONS) {
    const r = await ask(q);
    const g = r.answer ? await grade(q, r.answer) : { correct: 0, errors: 'NO ANSWER' };
    score += g.correct; if (r.first) firsts.push(r.first); if (r.done) dones.push(r.done);
    console.log(`[${g.correct}/2] ${q}\n      first ${r.first} ms, full ${r.done} ms${g.correct < 2 ? '\n      errors: ' + g.errors : ''}`);
  }
  const med = xs => xs.sort((a, b) => a - b)[Math.floor((xs.length - 1) / 2)];
  console.log(`\nACCURACY ${score}/${QUESTIONS.length * 2}   median first words ${med(firsts)} ms   median full ${med(dones)} ms   (${BASE})`);
  await pool.end();
})().catch(e => { console.error(e); process.exit(1); });
