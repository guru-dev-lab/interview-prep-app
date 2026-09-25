// End-to-end live test: real server, real Deepgram, real Haiku. Speaks questions with macOS `say`,
// streams them as Electron does (channel byte 1 + 16k PCM), and records what the screen would receive.
// Usage: node test/live-e2e.js [http://localhost:3999]   (needs a LOCAL DATABASE_URL in .env — never prod)
require('dotenv').config();
const { execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const BASE = process.argv[2] || 'http://localhost:3999';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-e2e-'));

function speech(text, voice) {
  const aiff = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), wav = aiff.replace('.aiff', '.wav');
  execFileSync('say', ['-v', voice || 'Samantha', '-o', aiff, text]);
  execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', aiff, wav]);
  const b = fs.readFileSync(wav); const i = b.indexOf('data'); return b.slice(i + 8);
}
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function seed() {
  const email = 'e2e-' + Date.now() + '@local.test';
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'E2E Tester','pro') RETURNING *", [email])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1,'Acme Analytics','Data Analyst','Data analyst, 4 years. SQL, Power BI, Excel, Python. Built sales dashboards at Northwind.') RETURNING id", [u.id])).rows[0];
  for (const [t, a] of [['Tell me about yourself', 'I am a data analyst with 4 years of experience...'], ['Why do you want this role?', 'Because Acme builds analytics products I use...']])
    await pool.query('INSERT INTO questions (session_id, text, answer) VALUES ($1,$2,$3)', [s.id, t, a]);
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'pro', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  return { token, sessionId: s.id };
}

// One scenario = fresh live connection; speak lines on channel 1, optionally click "What should I say", collect screen events.
async function scenario(name, { lines, click, waitMs = 9000 }) {
  const { token, sessionId } = await seed();
  const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
  const got = [];
  ws.on('message', d => { try { const m = JSON.parse(d); if (m.type !== 'transcript' && m.type !== 'live_answer_delta' && m.type !== 'user_transcript') got.push(m); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  const pcm = Buffer.concat([silence(500), ...lines.flatMap(l => [speech(l), silence(700)]), silence(2500)]);
  for (let o = 0; o < pcm.length; o += 3200) { // 100 ms packets, real time
    ws.send(Buffer.concat([Buffer.from([1]), pcm.slice(o, o + 3200)]));
    await sleep(100);
  }
  if (click) { await sleep(1000); got.push({ type: '— CLICK what_should_i_say —' }); ws.send(JSON.stringify({ type: 'what_should_i_say' })); }
  await sleep(waitMs);
  ws.close();
  // For a click, only what arrives AFTER the click counts — auto-detect must not mask a dead button.
  const from = click ? got.findIndex(m => m.type === '— CLICK what_should_i_say —') : 0;
  const seen = got.slice(from);
  const detected = seen.find(m => m.type === 'question_detected');
  const card = seen.find(m => ['match', 'new_question', 'live_answer'].includes(m.type));
  const errs = seen.filter(m => m.type === 'error').map(m => m.message);
  console.log(`\n### ${name}`);
  console.log('  detected :', detected ? `${detected.source}: "${detected.text}"` : '— none —');
  console.log('  card     :', card ? `${card.type}: "${card.questionText}"` : '— NOTHING ON SCREEN —');
  if (errs.length) console.log('  errors   :', errs.join(' | '));
  return { detected: !!detected, card: !!card, errs };
}

(async () => {
  const cases = [
    ['AUTO  "Please describe…"', { lines: ['Please describe your experience with Power BI.'] }],
    ['AUTO  "Talk me through…"', { lines: ['Talk me through your approach to cleaning messy data.'] }],
    ['AUTO  "In your current role…"', { lines: ['In your current role, what reporting tools do you use most?'] }],
    ['CLICK "Share an example…"', { lines: ['Share an example of a time you handled a difficult stakeholder.'], click: true }],
    ['CLICK "Please describe…"', { lines: ['Please describe your experience with Power BI.'], click: true }],
    ['NONE  candidate answering', { lines: ['I built a sales dashboard in Power BI for the regional team, and it cut reporting time by twenty percent.'], expectNone: true }],
    ['NONE  small talk', { lines: ['Hi, how are you doing today?', 'Can you hear me okay?'], expectNone: true }],
    ['CLICK nothing asked yet', { lines: [], click: true, waitMs: 5000 }],
  ];
  const only = process.env.ONLY; let fails = 0;
  for (const [n, c] of cases) {
    if (only && !n.includes(only)) continue;
    const r = await scenario(n, c);
    const ok = c.expectNone ? !r.card : c.lines.length ? r.card : r.errs.length > 0; // spoken question → card; candidate/small talk → no card; nothing spoken → a visible reason
    if (!ok) fails++; console.log('  RESULT   :', ok ? 'PASS' : 'FAIL');
  }
  await pool.end(); fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${fails ? fails + ' FAILED' : 'ALL PASS'}`); process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
