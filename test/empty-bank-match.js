// node test/empty-bank-match.js   (local server on :3999 + LOCAL DATABASE_URL)
// Real route (manual_match → fastMatchAndRespond): a question that matches a bank row with NO answer yet must be answered
// as asked (its own card), and the empty bank row must not be filled with an answer to a different question.
const R = process.argv[2] || require('path').join(__dirname, '..'); require(R + '/node_modules/dotenv').config({ path: R + '/.env' });
const WebSocket = require(R + '/node_modules/ws'), jwt = require(R + '/node_modules/jsonwebtoken'), { Pool } = require(R + '/node_modules/pg');
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const u = (await pool.query("INSERT INTO users (email,name,plan) VALUES ($1,'EB','premium') RETURNING *", ['eb-' + Date.now() + '@local.test'])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id,company,role,resume) VALUES ($1,'WEX','Business Intelligence Analyst II','BI analyst. SQL, Power BI, Excel, Python, Alteryx. Built scheduled and ad hoc reports for finance.') RETURNING *", [u.id])).rows[0];
  const empty = (await pool.query("INSERT INTO questions (session_id,text,answer) VALUES ($1,'Walk me through your experience creating both scheduled and ad hoc reports.',NULL) RETURNING id", [s.id])).rows[0].id;
  await pool.query("INSERT INTO questions (session_id,text,answer) VALUES ($1,'Tell me about yourself.','I am a BI analyst...'),($1,'Why do you want this role?','Because...')", [s.id]);
  const token = jwt.sign({ userId: u.id, name: u.name, email: u.email, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const ws = new WebSocket('ws://localhost:3999'), got = [];
  ws.on('message', d => { try { got.push(JSON.parse(d)); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(2500);
  const asked = 'So you were talking about the ad hoc report tools. What did you say you use for the ad hoc reporting?';
  ws.send(JSON.stringify({ type: 'manual_match', text: asked }));
  await sleep(9000);
  const card = got.find(m => ['match', 'new_question'].includes(m.type));
  const ans = [...got].reverse().find(m => m.type === 'live_answer');
  const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) process.exitCode = 1; };
  ok(card && card.type === 'new_question' && /tools|ad hoc/i.test(card.questionText) && !/^walk me through/i.test(card.questionText), `card is what was asked (got ${card && card.type}: "${card && card.questionText}")`);
  ok(ans && ans.answer && ans.answer.length < 900, `answer is about the tools, short (${ans ? ans.answer.length : 0} chars): ${ans ? ans.answer.slice(0, 120).replace(/\n/g, ' ') : ''}`);
  const row = (await pool.query('SELECT answer FROM questions WHERE id = $1', [empty])).rows[0];
  ok(!row.answer, 'empty bank row not filled with an answer to a different question');
  ws.close(); await pool.end();
})();
