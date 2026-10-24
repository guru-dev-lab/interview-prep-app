// Answer Note call memory, end to end on a LOCAL server (real routes, real DB; ONE model call: the call notes).
// Usage: DATABASE_URL=<local> node test/answer-note-calls-e2e.js http://localhost:3998
require('dotenv').config();
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const BASE = process.argv[2] || 'http://localhost:3998';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
let pass = 0, fail = 0;
const check = (ok, label, detail) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + label + (detail && !ok ? '\n     ' + String(detail).slice(0, 900) : '')); };

(async () => {
  const email = 'note-calls@local.test';
  let u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Calls Tester','premium') RETURNING *", [email])).rows[0];
  await pool.query('DELETE FROM answer_notes WHERE user_id=$1', [u.id]); // local test user only
  await pool.query('DELETE FROM sessions WHERE user_id=$1', [u.id]);
  const sess = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1,'Globex','Analytics Lead','Senior BI Analyst at Acme. Power BI, SQL.','Lead BI.') RETURNING id", [u.id])).rows[0];
  const t0 = Date.parse('2026-10-20T17:00:00Z');
  const L = (s, text, you) => ({ text: (you ? '[You] ' : '') + text, ts: t0 + s * 1000, isUser: !!you, isEcho: false });
  const transcript = [
    L(0, "Hi, I'm Dana, I lead the data platform team here at Globex. We're five analysts and we're moving everything into Microsoft Fabric this quarter."),
    L(10, "Thanks Dana, great to meet you.", true),
    L(20, "So first, how do you prioritize when you have three stakeholders all saying their report is the most urgent?"),
    L(40, "I rank by business impact and the deadline that really matters, then I agree the order with the managers in one short call.", true),
    L(70, "Okay. Which Microsoft Fabric components have you personally implemented?"),
    L(90, "I've built dataflows and a lakehouse in Fabric, and published semantic models from it.", true),
    L(120, "Our biggest pain right now is that finance and operations report different revenue numbers. How would you find out why?"),
    L(140, "I'd trace both numbers back to the source tables and compare the filters and definitions step by step.", true),
    L(170, "Great. Next round will be with our VP, Marcus, and it's more about stakeholder management."),
    L(180, "Sounds good, thank you.", true),
  ];
  const call = (await pool.query("INSERT INTO live_transcripts (session_id, user_id, transcript, started_at, ended_at, stage, interviewer_name) VALUES ($1,$2,$3,to_timestamp($4/1000.0),to_timestamp($5/1000.0),'Hiring manager','Dana') RETURNING id",
    [sess.id, u.id, JSON.stringify(transcript), t0, t0 + 25 * 60000])).rows[0];
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const api = async (method, p, body) => { const r = await fetch(BASE + p, { method, headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: body ? JSON.stringify(body) : undefined }); let j = {}; try { j = await r.json(); } catch (e) {} return { r, j }; };

  check((await fetch(BASE + '/api/note/calls')).status === 401, 'calls list needs a login');
  let list = (await api('GET', '/api/note/calls?sessionId=' + sess.id)).j;
  check(list.session && list.session.company === 'Globex' && list.calls.length === 1 && list.calls[0].lines === 10 && list.calls[0].report === null && list.calls[0].interviewer === 'Dana', 'the job\'s calls are listed, no notes yet', JSON.stringify(list));
  const convo = (await api('GET', '/api/note/calls/' + call.id)).j;
  check(convo.lines.length === 10 && convo.lines[0].who === 'them' && convo.lines[1].who === 'you' && !/^\[You\]/.test(convo.lines[1].text), 'the conversation comes back as Them / You, no [You] tags', JSON.stringify(convo.lines.slice(0, 2)));

  await api('GET', '/api/note'); // his note exists before the call notes are made, so they can say which note question each one is
  // the call notes (one model call)
  const t1 = Date.now();
  const rep = await api('POST', '/api/sessions/' + sess.id + '/transcripts/' + call.id + '/report');
  const R = rep.j.report || {};
  console.log('   notes made in ' + (Date.now() - t1) + ' ms');
  check(rep.r.status === 200 && Array.isArray(R.noteQuestions) && R.noteQuestions.length >= 3, 'notes split out the questions they asked', JSON.stringify(R).slice(0, 800));
  const qs = (R.noteQuestions || []).map(q => q.question).join(' | ');
  check(/prioriti/i.test(qs) && /fabric/i.test(qs) && /revenue|numbers|different/i.test(qs), 'the three real questions are there', qs);
  check(!/hear me|great to meet/i.test(qs), 'small talk is not a question', qs);
  check((R.noteQuestions || []).every(q => q.title && q.title.split(/\s+/).length <= 6 && Array.isArray(q.ways) && q.ways.length <= 3), 'each has a short title and at most 3 rewordings', JSON.stringify(R.noteQuestions));
  check(Array.isArray(R.likelyNext) && R.likelyNext.length >= 1 && R.likelyNext.length <= 5, 'likely next questions (1 to 5)', JSON.stringify(R.likelyNext));
  check(Array.isArray(R.aboutThem) && /Dana|Fabric|five|Marcus|revenue/i.test(R.aboutThem.join(' ')), 'what they shared about themselves is kept', JSON.stringify(R.aboutThem));
  check(Array.isArray(R.candidateSaid) && /lakehouse|dataflow|impact|trace/i.test(R.candidateSaid.join(' ')) && !/biggest pain/i.test(R.candidateSaid.join(' ')), 'what YOU said is kept, never their words', JSON.stringify(R.candidateSaid));
  list = (await api('GET', '/api/note/calls?sessionId=' + sess.id)).j;
  check(list.calls[0].report && Array.isArray(list.calls[0].report.noteQuestions), 'the notes are saved with the call');

  const pq = (R.noteQuestions || []).find(q => /prioriti/i.test(q.question));
  check(pq && pq.sameAs && pq.sameAs.name === 'Prioritizing', 'the notes know the prioritize question IS "Prioritizing" in the note', JSON.stringify(pq));
  // add the questions to the note: the prioritize one is already in the seed, the others are new
  const add = await api('POST', '/api/note/from-call', { questions: R.noteQuestions, section: 'From calls: Globex' });
  check(add.r.status === 200 && add.j.skipped.some(s => /prioriti/i.test(s.question)), 'a question already in the note is skipped and named', JSON.stringify(add.j.skipped));
  check(add.j.added.length >= 1 && add.j.added.every(g => g.section === 'From calls: Globex' && g.items.length >= 1 && g.items.length <= 4), 'new ones are added under "From calls: Globex", at most 3 other ways each', JSON.stringify(add.j.added.map(g => [g.name, g.items.length])));
  const again = await api('POST', '/api/note/from-call', { questions: R.noteQuestions, section: 'From calls: Globex' });
  check(again.j.added.length === 0 && again.j.skipped.length === R.noteQuestions.length, 'adding the same call again adds nothing', JSON.stringify(again.j));
  const tree = (await api('GET', '/api/note')).j;
  check(tree.groups.filter(g => g.section === 'From calls: Globex').length === add.j.added.length, 'they are in the note');
  const other = await fetch(BASE + '/api/note/calls/' + call.id, { headers: { Authorization: 'Bearer ' + jwt.sign({ userId: '00000000-0000-0000-0000-000000000000' }, process.env.JWT_SECRET) } });
  check(other.status === 404 || other.status === 401 || other.status === 403, "someone else cannot read this call", other.status);

  console.log(fail ? `${fail} FAILED, ${pass} passed` : `ALL PASS (answer note calls e2e, ${pass} checks, 1 model call)`);
  await pool.end(); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
