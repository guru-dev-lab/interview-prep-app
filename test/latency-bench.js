// Answer delay as the candidate feels it: interviewer STOPS talking → first answer words on screen → full answer.
// Real audio, real Deepgram + Claude. Usage: node test/latency-bench.js <baseUrl> [reps]   (LOCAL DATABASE_URL only)
require('dotenv').config();
const { execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3999', REPS = +(process.argv[3] || 2);
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-lat-'));
const sleep = ms => new Promise(r => setTimeout(r, ms)), silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
const cache = {};
function speech(text, voice) {
  const k = voice + text; if (cache[k]) return cache[k];
  const aiff = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), wav = aiff.replace('.aiff', '.wav');
  execFileSync('say', ['-v', voice, '-o', aiff, text]); execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', aiff, wav]);
  const b = fs.readFileSync(wav); return (cache[k] = b.slice(b.indexOf('data') + 8));
}
async function seed() {
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Lat','pro') RETURNING id", ['lat-' + Date.now() + Math.random() + '@local.test'])).rows[0];
  // LAT_REALISTIC=1: real-size resume + JD + 8 prepared answers (~2.5k tokens), like a real session
  const big = process.env.LAT_REALISTIC === '1';
  const resume = big ? fs.readFileSync(path.join(__dirname, 'fixtures', 'resume.txt'), 'utf8') : 'Data Analyst, Northwind Retail. Snowflake, dbt, SQL, Power BI. Cut weekly sales report from 4h to 20 min.';
  const jd = big ? fs.readFileSync(path.join(__dirname, 'fixtures', 'jd.txt'), 'utf8') : 'Senior Data Analyst — Snowflake, SQL, forecasting.';
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1,'Keystone Logistics','Senior Data Analyst',$2,$3) RETURNING id", [u.id, resume, jd])).rows[0];
  await pool.query('INSERT INTO questions (session_id, text, answer) VALUES ($1,$2,$3)', [s.id, 'How do you approach query performance tuning?', 'I start with the query profile, fix the heaviest scans and joins first, and add clustering on the columns we filter by most.']);
  if (big) for (const [q, a] of JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'bank.json'), 'utf8'))) await pool.query('INSERT INTO questions (session_id, text, answer) VALUES ($1,$2,$3)', [s.id, q, a]);
  return { token: jwt.sign({ userId: u.id, name: 'Lat', email: 'x', plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' }), sessionId: s.id };
}
async function run(lines, question) {
  const a = await seed(); const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const ev = [];
  ws.on('message', d => { try { const m = JSON.parse(d); if (['match', 'new_question', 'live_answer_delta', 'live_answer'].includes(m.type)) ev.push({ t: Date.now(), m }); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token: a.token, sessionId: a.sessionId, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  let ch1 = [silence(400)], ch2 = [silence(400)];
  for (const l of lines) {
    if (typeof l === 'string') { const x = speech(l, 'Samantha'); ch1.push(x, silence(1400)); ch2.push(silence(x.length / 32 + 1400)); }
    else { const x = speech(l.you, 'Daniel'); ch2.push(x, silence(1400)); ch1.push(silence(x.length / 32 + 1400)); }
  }
  const q = speech(question, 'Samantha');
  const qEnd = Buffer.concat(ch1).length + q.length; // byte offset where the interviewer stops talking
  ch1.push(q, silence(9000)); ch2.push(silence(q.length / 32 + 9000));
  ch1 = Buffer.concat(ch1); ch2 = Buffer.concat(ch2);
  let tStop = 0;
  for (let o = 0; o < ch1.length; o += 3200) {
    ws.send(Buffer.concat([Buffer.from([1]), ch1.slice(o, o + 3200)])); ws.send(Buffer.concat([Buffer.from([2]), ch2.slice(o, o + 3200)]));
    if (!tStop && o + 3200 >= qEnd) tStop = Date.now();
    await sleep(100);
  }
  await sleep(4000); ws.close();
  const after = ev.filter(e => e.t >= tStop - 500);
  const first = after.find(e => (e.m.type === 'live_answer_delta' && e.m.chunk) || ((e.m.type === 'match' || e.m.type === 'live_answer') && e.m.answer));
  const done = [...after].reverse().find(e => e.m.type === 'live_answer' || (e.m.type === 'match' && e.m.answer));
  return { first: first ? first.t - tStop : null, done: done ? done.t - tStop : null, kind: first ? first.m.type : '-' };
}
const HISTORY = ['Do you have experience with Snowflake?', { you: 'Yes, I use Snowflake every day, about three years, mostly sales reporting pipelines.' },
  'Great. Here we use Snowflake to forecast demand for forty warehouses, and our shipment queries got slow.', { you: 'Got it.' },
  'We are a hybrid team of six analysts.', 'We present to operations leadership monthly.', { you: 'Sounds great.' }];
(async () => {
  const cases = [
    ['new question, no history', [], 'How would you speed up a slow query in our environment?'],
    ['new question, with history', HISTORY, 'How would you speed up a slow query in our environment?'],
    ['prepared answer, with history', HISTORY, 'How do you approach query performance tuning?'],
  ];
  const out = [];
  for (const [name, lines, q] of cases.filter(c => !process.env.ONLY || c[0].includes(process.env.ONLY))) for (let i = 0; i < REPS; i++) { const r = await run(lines, q); out.push({ name, ...r }); console.log(`${name} #${i + 1}: first words ${r.first ?? '—'} ms, full ${r.done ?? '—'} ms (${r.kind})`); }
  const med = xs => { xs = xs.filter(x => x != null).sort((a, b) => a - b); return xs.length ? xs[Math.floor((xs.length - 1) / 2)] : null; };
  console.log('\nSUMMARY ' + BASE);
  for (const [name] of cases.filter(c => !process.env.ONLY || c[0].includes(process.env.ONLY))) { const rs = out.filter(o => o.name === name); console.log(`  ${name.padEnd(32)} first words ${String(med(rs.map(r => r.first))).padStart(5)} ms   full answer ${String(med(rs.map(r => r.done))).padStart(5)} ms`); }
  await pool.end(); fs.rmSync(tmp, { recursive: true, force: true });
})().catch(e => { console.error(e); process.exit(1); });
