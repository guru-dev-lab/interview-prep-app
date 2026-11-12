// Story answers (owner 12 Nov: "#4 is very important ... positive and good amount of story behind it and positive story
// and the start and every hook must be there"). Through the real WebSocket path: a story question gets a hook opening,
// a full positive story (stakes → what he did → the turn → the result), and every part the interviewer asked answered.
// Reuses ONE local user + session, no Answer Note (spend rule). Usage: node test/story-quality.js [baseUrl] [startIndex]
require('dotenv').config();
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3997';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL }); const sleep = ms => new Promise(r => setTimeout(r, ms));
const RESUME = `Data Analyst, R&L Carriers (Mar 2022 to present)
- Merged 14 regional carrier feeds into one Snowflake table with a Python cleaning step; weekly report prep fell from 9 hours to 40 minutes.
- Ran a regression and a before/after comparison on on-time delivery for a new routing program; found a 6% on-time gain, controlled for season and region.
- Built Power BI dashboards used by 40 regional managers.
- Worked with the operations lead to agree one definition of "late shipment" after two teams reported different numbers.
Reporting Analyst, Midwest Health Clinics (2019 to 2022)
- Automated monthly patient-visit reporting in SQL and Excel for 12 clinics; delivered a state audit report 3 days early.
Skills: SQL, Python (pandas, statsmodels), Snowflake, Power BI, Excel.`;
const L = a => a.split('\n').filter(Boolean), body = a => L(a).filter(l => !/^▸/.test(l));
const NEGATIVE = /\b(blame|their fault|incompetent|lazy|refused to|frustrat|annoy|hated|terrible|disaster|failed miserably)\b/i;
// [question, parts that must each be answered: [label, regex]]
const CASES = [
  ["That's wonderful, thank you so much. And could you describe a time when you've applied statistical analysis or specific research methods to investigate a program related question, to help a program identify trends or assess outcomes. Again, kind of how did you determine which analytical methods were appropriate? What did your findings reveal, and then how did you account for any limitations in that data?",
    [['the methods + how chosen', /\b(chose|picked|because|so I|fit|right method|regression|before.and.after)\b/i], ['what the findings revealed', /\b(found|finding|showed|revealed)\b|6%/i], ['the limitations', /\b(limitation|season|region|control|caveat|bias|small sample)\b/i]]],
  ['Tell me about a time you disagreed with a coworker. How did you handle it and what happened?',
    [['how he handled it', /\b(sat down|met|talked|asked|listened|walked|together)\b/i], ['what happened', /\b(agreed|one definition|now|since|result|relationship)\b/i]]],
  ['Walk us through a time where you had to deliver something important under a tight deadline.', []],
];
const run = process.argv[3] ? CASES.slice(+process.argv[3]) : CASES;
(async () => {
  const email = 'story-quality@local.test';
  let u = (await pool.query('SELECT id FROM users WHERE email = $1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1, 'SQ', 'pro') RETURNING id", [email])).rows[0];
  let s = (await pool.query('SELECT id FROM sessions WHERE user_id = $1 LIMIT 1', [u.id])).rows[0];
  if (!s) s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1, 'Polaris Project', 'Program Data Analyst', $2, 'Analyze program outcomes with county partners; statistical analysis; dashboards.') RETURNING id", [u.id, RESUME])).rows[0];
  await pool.query('DELETE FROM questions WHERE session_id = $1', [s.id]);
  const token = jwt.sign({ userId: u.id, name: 'SQ', email, plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const answers = new Map(); let lastQ = null;
  ws.on('message', d => { try { const m = JSON.parse(d); if (m.type === 'new_question') lastQ = m.questionId; if (m.type === 'live_answer' && m.answer) answers.set(m.questionId, m.answer); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(2500);
  let fail = 0;
  for (const [asked, parts] of run) {
    const before = lastQ; ws.send(JSON.stringify({ type: 'canvas_question', text: asked }));
    const t0 = Date.now(); while (Date.now() - t0 < 40000 && (lastQ === before || !answers.has(lastQ))) await sleep(300);
    await sleep(2000);
    const a = answers.get(lastQ) || '', b = body(a);
    const checks = [
      ['▸ heading first', /^▸/.test(L(a)[0] || '')],
      ['hook start (the win or the stakes up front, not flat background)', /\d|\b(best|proud|favorite|favourite|biggest|turned|proved|proving|saved|win|cut|early|stakes|at stake|had to|deadline|confusion|problem)\b/i.test(b[0] || '')],
      ['a full story (hook + 6 lines)', b.length >= 7],
      ['positive (no blame or negative words)', !NEGATIVE.test(a)],
      ['ends on the result', /\d|\b(result|now|since|saved|cut|fell|gain|early|trust|trusted|aligned|agreed|meant|gave|helped|decision|expand|standard)\b/i.test(b[b.length - 1] || '')],
      ...parts.map(([lbl, re]) => ['answers: ' + lbl, b.some(l => re.test(l))]),
    ];
    console.log(`\n### ${asked.slice(0, 90)}\n${a.split('\n').map(l => '    ' + l).join('\n')}`);
    for (const [lbl, ok] of checks) { console.log(`  ${ok ? 'PASS' : 'FAIL'} ${lbl}`); if (!ok) fail++; }
  }
  ws.close(); await pool.end();
  console.log(fail ? `\n${fail} FAILED` : '\nALL PASS'); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
