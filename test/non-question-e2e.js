// Non-question test (real server, real Deepgram + Claude). Owner's run 26 Sep: a mock-interview VIDEO's host intro
// ("…an analyst role at Stripe. Which is a pretty cool company. So I'll be jumping back and forth…") became a card
// whose "answer" asked the user for the full question. Speaks that intro + a line that slips past the rules,
// then a real question, and checks: no intro card stays on screen, nothing talks to the user, the real one is answered.
// Usage: node test/non-question-e2e.js [http://localhost:3999]   (LOCAL DATABASE_URL only)
require('dotenv').config();
const { execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3999';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-nq-'));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
function speech(text) {
  const aiff = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), wav = aiff.replace('.aiff', '.wav');
  execFileSync('say', ['-v', 'Samantha', '-o', aiff, text]); execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', aiff, wav]);
  const b = fs.readFileSync(wav); return b.slice(b.indexOf('data') + 8);
}
const INTRO = [
  "So, how it's gonna work? Pretty much, I'll be jumping back and forth between Arman's resume slash LinkedIn, which he has graciously volunteered, and the job description for an analyst role at Stripe. Which is a pretty cool company. So I'll be jumping back and forth, and I created custom questions based on Arman's background.",
  'Where to find me after this: my YouTube channel is linked below in the description.',
];
const REAL = 'Tell me about a time you had to clean up really messy data.';
const META_RE = /could you (please )?(provide|clarify|share)|full question|appears to be incomplete|need to clarify/i;

(async () => {
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Test User','pro') RETURNING id", ['nq-' + Date.now() + '@local.test'])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1,'Stripe','Data Analyst','Data Analyst at Northwind Retail 2021-present. SQL, Python, Tableau. Cleaned 2M CRM records.','Data Analyst — SQL, dashboards, payments data.') RETURNING id", [u.id])).rows[0];
  const token = jwt.sign({ userId: u.id, name: 'Test User', email: 'x', plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const msgs = [];
  ws.on('message', d => { try { msgs.push(JSON.parse(d)); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(2500);
  let ch1 = [silence(400)];
  for (const l of [...INTRO, REAL]) ch1.push(speech(l), silence(2500));
  ch1 = Buffer.concat([...ch1, silence(3000)]); const ch2 = Buffer.alloc(ch1.length);
  for (let o = 0; o < ch1.length; o += 3200) { ws.send(Buffer.concat([Buffer.from([1]), ch1.slice(o, o + 3200)])); ws.send(Buffer.concat([Buffer.from([2]), ch2.slice(o, o + 3200)])); await sleep(100); }
  await sleep(15000);
  ws.send(JSON.stringify({ type: 'stop' })); await sleep(1500); ws.close();

  // What stays on screen: every card that got a final answer and was not dropped afterwards
  const dropped = new Set(msgs.filter(m => m.type === 'drop_card').map(m => m.questionId));
  const cards = new Map();
  for (const m of msgs) if (m.type === 'live_answer' || m.type === 'match') cards.set(m.questionId, m);
  const onScreen = [...cards.values()].filter(m => !dropped.has(m.questionId));
  console.log('cards on screen:'); onScreen.forEach(m => console.log(`  • ${m.questionText}\n    ${String(m.answer || '').split('\n')[0].slice(0, 110)}`));
  console.log(`dropped as not-a-question: ${dropped.size}`);
  const fails = [];
  // The 'Which is a pretty cool company' intro must never become a card (detection rule). A stray line like 'Where to
  // find me after this?' may get a card now (the writer no longer skips — it dropped real questions), but never a meta reply.
  const introCards = onScreen.filter(m => /pretty cool company|jumping back and forth|custom questions/i.test(m.questionText || ''));
  if (introCards.length) fails.push('intro stayed on screen as a card: ' + introCards.map(m => `"${m.questionText}"`).join(', '));
  const meta = onScreen.filter(m => META_RE.test(m.answer || ''));
  if (meta.length) fails.push('an answer talked to the user: ' + meta.map(m => m.answer.slice(0, 80)).join(' | '));
  const flashed = msgs.filter(m => m.type === 'live_answer_delta' && /NOT_A_QUESTION|NOT_A|NOT_/.test(m.chunk || ''));
  if (flashed.length) fails.push('the NOT_A_QUESTION signal was streamed to the screen');
  const real = onScreen.find(m => /clean up/i.test(m.questionText || '') && (m.answer || '').length > 40);
  if (!real) fails.push('the real question was not answered');
  console.log(fails.length ? 'RESULT: FAIL\n- ' + fails.join('\n- ') : 'RESULT: PASS');
  await pool.end(); process.exit(fails.length ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
