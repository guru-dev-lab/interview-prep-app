// Other-voice test (real server, real Deepgram + Claude). Owner's run 26 Sep 16:34: practising against a mock-interview
// VIDEO, the call audio carried the host AND the video's own candidate; the answer broke character:
// "I need to stop and clarify: the conversation transcript provided does not match the candidate I'm supposed to be coaching".
// Checks: the answer to the interviewer's question is the OWNER speaking from HIS resume, and nothing that talks to the
// user is ever sent to the screen (not even one streamed chunk).
// Usage: node test/other-voice-e2e.js [http://localhost:3999]   (LOCAL DATABASE_URL only)
require('dotenv').config();
const { execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3999';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-ov-'));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
function speech(text, voice) {
  const aiff = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), wav = aiff.replace('.aiff', '.wav');
  execFileSync('say', ['-v', voice, '-o', aiff, text]); execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', aiff, wav]);
  const b = fs.readFileSync(wav); return b.slice(b.indexOf('data') + 8);
}
const RESUME = `Ridwan Akanbi — Lead Business Intelligence Analyst, 10+ years.
R&L Carriers (2019–present): terminal KPI dashboards in Tableau and Power BI, SQL Server and Snowflake pipelines, freight claims reporting.
Wells Fargo (2014–2019): data engineering for loan reporting, SQL, ETL.
Skills: Tableau, Power BI, SQL, Snowflake, Python.`;
// Ch1 = the video: host (Samantha) and the video's own candidate (Daniel) — both come through call audio
const VIDEO = [
  ['Samantha', "Arman, why don't you start by telling us a little bit about yourself."],
  ['Daniel', "Sure. I studied economics and public policy, I did tax credit analysis for a while, organized campaigns, and most recently I worked at Calvert College, California's first online community college, doing enrollment analysis. Now I'm interviewing for the analyst role at Stripe."],
  // prod 21:33 UTC: the other candidate's last words and the host's question arrived as ONE utterance
  ['Daniel+Samantha', "What we did at Calvert College was really exciting. And when you talk about your role, can you just talk a little bit about some of the projects you are working on? And then also talk to me about the tech stack you were using."],
];
const OUT_OF_CHARACTER = /the candidate|transcript|supposed to|prep materials|does(n't| not) match|clarify|i can('|no)t answer|different (person|candidate)|resume provided/i;
const HIS = /R&L|Wells Fargo|Tableau|Power BI|Snowflake|SQL|terminal|freight|claims/i;
const THEIRS = /Calvert|tax credit|public policy|economics|enrollment|community college/i;

(async () => {
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Ridwan Akanbi','pro') RETURNING id", ['ov-' + Date.now() + '@local.test'])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1,'Cambium Learning Group','Lead Analyst / BI Product Manager',$2,'Lead Analyst — BI, SQL, Snowflake, dashboards.') RETURNING id", [u.id, RESUME])).rows[0];
  const token = jwt.sign({ userId: u.id, name: 'Ridwan Akanbi', email: 'x', plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const msgs = [];
  ws.on('message', d => { try { msgs.push(JSON.parse(d)); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(2500);
  let ch1 = [silence(400)];
  for (const [v, l] of VIDEO) ch1.push(speech(l, v === 'Daniel+Samantha' ? 'Samantha' : v), silence(v === 'Daniel+Samantha' ? 400 : 2200));
  ch1 = Buffer.concat([...ch1, silence(3000)]); const ch2 = Buffer.alloc(ch1.length);
  for (let o = 0; o < ch1.length; o += 3200) { ws.send(Buffer.concat([Buffer.from([1]), ch1.slice(o, o + 3200)])); ws.send(Buffer.concat([Buffer.from([2]), ch2.slice(o, o + 3200)])); await sleep(100); }
  await sleep(3000);
  ws.send(JSON.stringify({ type: 'what_should_i_say' })); // owner pressed What should I say for that question
  await sleep(18000);
  ws.send(JSON.stringify({ type: 'stop' })); await sleep(1500); ws.close();

  const fails = [];
  // 1. nothing out of character ever SENT (streamed chunks rebuilt per card, plus final answers)
  const streamed = {};
  msgs.filter(m => m.type === 'live_answer_delta').forEach(m => { streamed[m.questionId] = (streamed[m.questionId] || '') + (m.chunk || ''); });
  Object.values(streamed).forEach(t => { if (OUT_OF_CHARACTER.test(t)) fails.push('streamed to screen: ' + t.slice(0, 90)); });
  // a card is gone only if it was dropped and NOT answered again afterwards
  const dropped = new Set(); msgs.forEach(m => { if (m.type === 'drop_card') dropped.add(m.questionId); else if ((m.type === 'live_answer' || m.type === 'match') && m.answer) dropped.delete(m.questionId); });
  const realDropped = msgs.filter(m => m.type === 'drop_card').length;
  if (realDropped) fails.push(`${realDropped} card(s) dropped — every line in this video after the intro asks something`);
  const finals = new Map(); msgs.filter(m => m.type === 'live_answer' || m.type === 'match').forEach(m => finals.set(m.questionId, m));
  const shown = [...finals.values()].filter(m => !dropped.has(m.questionId));
  shown.forEach(m => { if (OUT_OF_CHARACTER.test(m.answer || '')) fails.push('final answer out of character: ' + m.answer.slice(0, 90)); });
  // 2. the interviewer's question got an in-character answer from HIS resume
  const card = shown.find(m => /project|tech stack/i.test(m.questionText || ''));
  console.log('cards:'); shown.forEach(m => console.log(`  • ${m.questionText}\n    ${String(m.answer || '').replace(/\n/g, ' / ').slice(0, 160)}`));
  if (!card) fails.push('the projects / tech stack question has no answer on screen');
  else {
    if (!HIS.test(card.answer)) fails.push('answer is not from his resume');
    if (THEIRS.test(card.answer)) fails.push("answer uses the video candidate's background");
  }
  console.log(fails.length ? 'RESULT: FAIL\n- ' + fails.join('\n- ') : 'RESULT: PASS');
  await pool.end(); process.exit(fails.length ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
