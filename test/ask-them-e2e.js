// "Questions to ask them" test (real server, real Deepgram + Claude). Speaks a two-call interview into ONE session,
// then presses the "?" button at the end of call 2 — the way the owner uses it — and checks the owner's rule:
//   questions come from what the INTERVIEWERS said (this call + earlier calls), never from the candidate's own
//   statements, never repeat what was already asked/answered, and sound like a real person talking.
// Usage: node test/ask-them-e2e.js [http://localhost:3999]   (LOCAL DATABASE_URL only)
require('dotenv').config();
const { execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path'), https = require('https');
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3999';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-ask-'));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
function speech(text, voice) {
  const aiff = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), wav = aiff.replace('.aiff', '.wav');
  execFileSync('say', ['-v', voice, '-o', aiff, text]); execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', aiff, wav]);
  const b = fs.readFileSync(wav); return b.slice(b.indexOf('data') + 8);
}
const RESUME = `Jordan Lee — Data Analyst, Northwind Retail (2021–present). Sales & CRM analytics for 120 retail stores.
- Built a customer churn model in Python; automated the Tableau dashboard refresh.
- Mentored two junior analysts. Skills: SQL, Snowflake, Python, Tableau, Excel.`;

// strings = interviewer (Ch1), { you } = candidate mic (Ch2)
const CALL1 = [
  "Thanks for joining. I'm the hiring manager. We're a regional freight company, and last quarter we moved our carrier scorecards out of Excel and into Snowflake.",
  { you: 'Nice to meet you. At Northwind I built a customer churn model in Python and I automated our Tableau refresh, so I am comfortable with that kind of move.' },
  "The biggest headache right now is that the on-time delivery numbers never match between finance and operations.",
  { you: 'I have mentored two junior analysts and I like cleaning up definitions like that.' },
];
// A real call: company talk only at the start, then their questions + the candidate's long answers, then the
// candidate's own question, their answer, and the candidate's closing statement.
const CALL2 = [
  "Hi, I run the analytics team you'd be joining. We're about to take over the Kansas City cross-dock reporting, and leadership wants a single weekly margin view by lane before peak season in October.",
  'Tell me about a time you had to clean up really messy data.',
  { you: 'At Northwind our customer data was a mess, so I rebuilt the churn model inputs in Python and deduplicated about two million CRM records before the Tableau dashboards refreshed.' },
  'How do you handle a stakeholder who keeps changing the requirements?',
  { you: 'I write down what they asked for in plain words, I show them a quick Tableau mockup early, and I mentor my junior analysts to do the same.' },
  { you: 'Can I ask how big the team is today?' },
  "Sure, it's four analysts right now.",
  { you: 'Thank you so much, I really enjoyed this. I think my churn modeling and Tableau work would really help here.' },
];

async function call(auth, lines, { askAtEnd = false } = {}) {
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); let questions = null, err = null;
  ws.on('message', d => { try { const m = JSON.parse(d); if (m.type === 'followup_questions_result') questions = m.questions; if (m.type === 'error') err = m.message; } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token: auth.token, sessionId: auth.sessionId, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(3000); // earlier-call memory loads here
  let ch1 = [silence(400)], ch2 = [silence(400)];
  for (const l of lines) {
    if (typeof l === 'string') { const a = speech(l, 'Samantha'); ch1.push(a, silence(1600)); ch2.push(silence(a.length / 32 + 1600)); }
    else { const a = speech(l.you, 'Daniel'); ch2.push(a, silence(1600)); ch1.push(silence(a.length / 32 + 1600)); }
  }
  ch1 = Buffer.concat([...ch1, silence(2500)]); ch2 = Buffer.concat([...ch2, silence(2500)]);
  const len = Math.max(ch1.length, ch2.length), pad = b => Buffer.concat([b, Buffer.alloc(len - b.length)]); ch1 = pad(ch1); ch2 = pad(ch2);
  for (let o = 0; o < len; o += 3200) { ws.send(Buffer.concat([Buffer.from([1]), ch1.slice(o, o + 3200)])); ws.send(Buffer.concat([Buffer.from([2]), ch2.slice(o, o + 3200)])); await sleep(100); }
  await sleep(6000);
  let ms = 0;
  if (askAtEnd) {
    const t0 = Date.now(); ws.send(JSON.stringify({ type: 'followup_questions' }));
    while (!questions && !err && Date.now() - t0 < 30000) await sleep(200);
    ms = Date.now() - t0;
  }
  ws.send(JSON.stringify({ type: 'stop' })); await sleep(2500); ws.close();
  return { questions, err, ms };
}

function judge(qs) {
  const sys = 'You grade questions a job candidate would ask the interviewer at the end of an interview. Reply with ONLY JSON: {"natural":[0-2 per question],"why":"one short sentence"}. natural: 2 = a real person would say this out loud as written; 1 = usable but stiff; 0 = fake, scripted, flattering or templated.';
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ model: process.env.MODEL_SONNET || 'claude-sonnet-5', max_tokens: 2000, system: sys, messages: [{ role: 'user', content: qs }] });
    const req = https.request({ hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' } }, res => {
      let d = ''; res.on('data', c => d += c); res.on('end', () => { try { const t = JSON.parse(d).content.filter(c => c.type === 'text').map(c => c.text).join(''); resolve(JSON.parse(t.slice(t.indexOf('{'), t.lastIndexOf('}') + 1))); } catch (e) { reject(new Error('judge parse: ' + d.slice(-300))); } });
    }); req.on('error', reject); req.write(body); req.end();
  });
}

(async () => {
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Jordan Lee','pro') RETURNING id", ['ask-' + Date.now() + '@local.test'])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1,'Keystone Freight','Senior Data Analyst',$2,'Senior Data Analyst — Snowflake, SQL, carrier performance and margin reporting for freight operations.') RETURNING id", [u.id, RESUME])).rows[0];
  const auth = { token: jwt.sign({ userId: u.id, name: 'Jordan Lee', email: 'x', plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' }), sessionId: s.id };

  console.log('call 1 (hiring manager)…'); await call(auth, CALL1);
  console.log('call 2 (team lead) + press "?" at the end…'); const r = await call(auth, CALL2, { askAtEnd: true });
  if (!r.questions) { console.log('NO QUESTIONS', r.err || 'timeout'); process.exit(1); }
  console.log(`\n(${r.ms} ms)\n${r.questions}\n`);

  const qs = r.questions.split('\n').map(l => l.replace(/^\d+[.)]\s*/, '').trim()).filter(Boolean);
  const CANDIDATE_ONLY = /\b(churn|tableau|northwind|mentor\w*|junior|retail|crm)\b/i;               // only the candidate said these
  const THEIRS = /\b(scorecards?|on-time|finance|operations|kansas city|cross-dock|margin|lanes?|peak|carriers?|snowflake)\b/i; // only interviewers said these
  const TEMPLATE = /^(you mentioned|you said|earlier you|i noticed|given that|as someone who)|\b(synergy|leverage|culture of excellence|fast-paced|sounds exciting)\b/i;
  const REPEAT = /\b(how (big|many people)|team size|how large is the team)\b/i;
  const fails = [];
  if (qs.length !== 4) fails.push(`expected 4 questions, got ${qs.length}`);
  qs.forEach(q => {
    if (CANDIDATE_ONLY.test(q)) fails.push(`uses the candidate's own statement: "${q}"`);
    if (TEMPLATE.test(q)) fails.push(`templated/fake wording: "${q}"`);
    if (REPEAT.test(q)) fails.push(`repeats a question already asked: "${q}"`);
    if (q.split(/\s+/).length > 26) fails.push(`too long: "${q}"`);
  });
  const grounded = qs.filter(q => THEIRS.test(q)).length;
  if (grounded < 3) fails.push(`only ${grounded}/4 built on what the interviewers said`);
  const fromEarlierCall = qs.some(q => /\b(scorecards?|on-time|finance|operations|carriers?)\b/i.test(q));
  if (!fromEarlierCall) fails.push('nothing from the earlier call (hiring manager) was used');
  let j = null; try { j = await judge(qs.join('\n')); } catch (e) { fails.push('judge failed: ' + e.message); }
  if (j && !Array.isArray(j.natural)) j.natural = typeof j.natural === 'object' && j.natural ? Object.values(j.natural).map(Number) : [Number(j.natural)];
  if (j) { const nat = j.natural.reduce((a, b) => a + b, 0) / j.natural.length; console.log(`natural ${j.natural.join(' ')} — ${j.why}`); if (j.natural.some(n => n === 0) || nat < 1.5) fails.push(`not natural enough (${j.natural.join(',')})`); }
  console.log(`built on interviewers: ${grounded}/4 | earlier call used: ${fromEarlierCall}`);
  console.log(fails.length ? 'RESULT: FAIL\n- ' + fails.join('\n- ') : 'RESULT: PASS');
  await pool.end(); process.exit(fails.length ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
