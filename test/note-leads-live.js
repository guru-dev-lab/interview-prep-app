// The Answer Note leads the live answer (owner 11 Nov: "XHIRE GIVING BEST ANSWER OR MAYBE EVEN CLOSE TO NOTE, NOTE WOULD BE
// EXPANSION AND BIGGER PICTURE"). Through the real WebSocket path: a question that IS a note question (asked in other
// words) gets an answer built from the note's own story and numbers; a different question never borrows them.
// Reuses ONE local user + session (test spend rule). Usage: node test/note-leads-live.js [baseUrl]   (LOCAL DATABASE_URL only)
// Run the server with MUSTHAVE_PREBUILD=0 (semantic matching on, like prod).
require('dotenv').config();
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3997';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL }); const sleep = ms => new Promise(r => setTimeout(r, ms));

const RESUME = 'Data Analyst, R&L Carriers (Mar 2022 to present). SQL, Python, Snowflake, Power BI. Built reporting for regional operations.';
const NOTE = [
  { name: 'Cleaning messy data', q: 'Tell me about a time you cleaned and combined messy data from several sources',
    a: 'At R&L Carriers I merged 14 regional carrier feeds that all used different date formats and codes.\nI built one Python cleaning step that standardized them into a single Snowflake table.\nWeekly report prep went from 9 hours to 40 minutes.' },
  { name: 'First 90 days', q: 'What would you do in your first 90 days?',
    a: 'First 30 days I would run a listening tour with all 6 county partners.\nBy day 60 I would map every data source and its owner.\nBy day 90 I would ship one trusted outcomes dashboard.' },
];
// [asked, must contain one of, must contain none of]
const CASES = [
  ["Could you walk us through a time where you've cleaned, standardized or combined complex datasets?", [/\b14\b/, /40 minutes/i, /9 hours/i], []],
  ['If you were going to join us in this role, what would your priorities be for the first ninety days?', [/\b6 county|six county|listening tour/i], []],
  ['What principles guide you when you work with sensitive data about real people?', [], [/\b14\b/, /40 minutes/i, /listening tour/i]],
  // worded like a note question, asks something else: must not borrow its plan
  ['What would you do in your first week if our main data warehouse went down?', [], [/listening tour/i, /\b6 county|six county/i, /day 60|day 90/i]],
];
if (process.argv[3]) CASES.splice(0, CASES.length, ...CASES.slice(+process.argv[3])); // run from case N only (spend)

(async () => {
  // one reused user + job + note
  const email = 'note-leads@local.test';
  let u = (await pool.query('SELECT id FROM users WHERE email = $1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1, 'NL', 'pro') RETURNING id", [email])).rows[0];
  let s = (await pool.query('SELECT id FROM sessions WHERE user_id = $1 LIMIT 1', [u.id])).rows[0];
  if (!s) s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1, 'Polaris Project', 'Data Analyst', $2, 'Combine data from county partners; build outcome dashboards.') RETURNING id", [u.id, RESUME])).rows[0];
  await pool.query('DELETE FROM questions WHERE session_id = $1', [s.id]); // no bank answers: the note is the only prepared source
  let n = (await pool.query('SELECT id FROM answer_notes WHERE user_id = $1', [u.id])).rows[0];
  if (!n) n = (await pool.query("INSERT INTO answer_notes (user_id, settings) VALUES ($1, '{\"seeded\":true,\"seedVersion\":99}') RETURNING id", [u.id])).rows[0];
  await pool.query('DELETE FROM answer_note_groups WHERE note_id = $1', [n.id]);
  for (const [k, x] of NOTE.entries()) {
    const g = (await pool.query("INSERT INTO answer_note_groups (note_id, name, section, sort_order, scope, job_ids) VALUES ($1, $2, 'Role', $3, 'job', $4::uuid[]) RETURNING id", [n.id, x.name, k, [s.id]])).rows[0];
    const it = (await pool.query('INSERT INTO answer_note_items (note_id, group_id, question, sort_order) VALUES ($1, $2, $3, 0) RETURNING id', [n.id, g.id, x.q])).rows[0];
    await pool.query('INSERT INTO answer_note_job_answers (item_id, session_id, answer_html) VALUES ($1, $2, $3)', [it.id, s.id, x.a.split('\n').map(l => '<p>' + l + '</p>').join('')]);
  }

  const token = jwt.sign({ userId: u.id, name: 'NL', email, plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
  const answers = new Map(); let lastQ = null;
  ws.on('message', d => { try { const m = JSON.parse(d); if (m.type === 'new_question') lastQ = m.questionId; if (m.type === 'live_answer' && m.answer) answers.set(m.questionId, m.answer); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(2500);

  let fail = 0;
  for (const [asked, must, mustNot] of CASES) {
    const before = lastQ; ws.send(JSON.stringify({ type: 'canvas_question', text: asked }));
    const t0 = Date.now(); while (Date.now() - t0 < 30000 && (lastQ === before || !answers.has(lastQ))) await sleep(300);
    await sleep(1500); // the final whole answer
    const a = answers.get(lastQ) || '';
    const okMust = !must.length || must.some(r => r.test(a)), okNot = !mustNot.some(r => r.test(a)), ok = !!a && okMust && okNot;
    if (!ok) fail++;
    console.log(`${ok ? 'PASS' : 'FAIL'} ${asked.slice(0, 70)}\n${a.split('\n').map(l => '    ' + l).join('\n') || '    (no answer)'}`);
  }
  ws.close(); await pool.end();
  console.log(fail ? `${fail} FAILED` : 'ALL PASS (note leads the live answer)');
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
