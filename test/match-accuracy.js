// Bank-matching accuracy through the real live path: paraphrases must hit the prepared answer, neighbouring topics
// must NOT. Each asked N times (the AI check isn't deterministic). Usage: node test/match-accuracy.js [baseUrl] [N]
require('dotenv').config();
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3997', N = +(process.argv[3] || 5);
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL }); const sleep = ms => new Promise(r => setTimeout(r, ms));
const BANK = ['What do you do when leadership disagrees with what your data or analysis shows?', 'How do you get buy-in when stakeholders are not sold on your idea?',
  'How do you convince executives to use a report, tool, or recommendation you built?', 'How do you approach query performance tuning?',
  'Walk us through your experience with logistics or supply chain data.', 'Explain the difference between a LEFT JOIN and an INNER JOIN.',
  'Tell me about a time you influenced a decision without having authority.', 'What are your salary expectations?'];
const CASES = [
  ['What do you do when your manager pushes back on your analysis?', BANK[0]],
  ['How do you convince people when they are not buying your idea?', BANK[1]],
  ['How would you get executives to actually use your dashboard?', BANK[2]],
  ['How would you approach speeding up slow queries?', BANK[3]],
  ["What's your experience with demand forecasting?", null],
  ['What is the difference between WHERE and HAVING?', null],
  ['Tell me about a time you led a project from start to finish.', null],
  ['How do you prioritize competing deadlines?', null],
];
(async () => {
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'MA','free') RETURNING id", ['ma-' + Date.now() + '-' + Math.random().toString(36).slice(2) + '@local.test'])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1,'Keystone','Analyst','Data Analyst at R&L Carriers since Mar 2022.') RETURNING id", [u.id])).rows[0];
  for (const q of BANK) await pool.query('INSERT INTO questions (session_id, text, answer) VALUES ($1,$2,$3)', [s.id, q, 'PREPARED: ' + q]);
  const token = jwt.sign({ userId: u.id, name: 'MA', email: 'x', plan: 'free' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  let hits = 0, needHits = 0, falses = 0, needNone = 0; const rows = [];
  for (const [asked, want] of CASES) {
    let ok = 0;
    for (let i = 0; i < N; i++) {
      const ws = new WebSocket(BASE.replace(/^http/, 'ws')); let first = null;
      ws.on('message', d => { try { const m = JSON.parse(d); if (!first && (m.type === 'match' || m.type === 'new_question')) first = m; } catch (e) {} });
      await new Promise(r => ws.on('open', r));
      ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
      await sleep(1200); ws.send(JSON.stringify({ type: 'canvas_question', text: asked }));
      for (let k = 0; k < 60 && !first; k++) await sleep(100);
      ws.close(); await sleep(300);
      const got = first && first.type === 'match' ? first.questionText : null;
      const good = want ? got === want : !got || !BANK.includes(got) || got === null;
      if (want) { needHits++; if (got === want) hits++; } else { needNone++; if (got && BANK.includes(got)) falses++; }
      if (good) ok++; else rows.push(`   ✗ "${asked}" → ${got ? '"' + got + '"' : 'new answer'}`);
    }
    console.log(`${ok === N ? '✓' : '✗'} ${ok}/${N}  "${asked}" ${want ? '→ prepared' : '→ no bank match'}`);
  }
  if (rows.length) console.log(rows.join('\n'));
  console.log(`\nparaphrase hit rate ${hits}/${needHits}   false matches ${falses}/${needNone}`);
  await pool.end(); process.exit(hits === needHits && falses === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
