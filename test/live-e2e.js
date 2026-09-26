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
async function scenario(name, { lines, click, waitMs = 9000, expectText }) {
  const { token, sessionId } = await seed();
  const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
  const got = [];
  ws.on('message', d => { try { const m = JSON.parse(d); m._t = Date.now(); if (m.type !== 'transcript' && m.type !== 'user_transcript') got.push(m); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  // Build both channels. Interviewer lines (strings) → Ch1 only. Your lines ({ you }) → Ch2 (mic) AND a quieter,
  // 200 ms-late copy on Ch1 — your voice leaking into the call audio (no headphones), the hard case.
  let ch1 = [silence(500)], ch2 = [silence(500)];
  for (const l of lines) {
    if (l && l.bleed) { // interviewer from your speakers leaks into your mic (no headphones): Ch1 clean, Ch2 quieter 40 ms late
      const a = speech(l.bleed), leak = Buffer.alloc(a.length);
      for (let i = 0; i < a.length; i += 2) leak.writeInt16LE(Math.round(a.readInt16LE(i) * 0.35), i);
      ch1.push(a, silence(740)); ch2.push(silence(40), leak, silence(700));
    }
    else if (typeof l === 'string') { const a = speech(l); ch1.push(a, silence(700)); ch2.push(silence(a.length / 32), silence(700)); }
    else {
      const a = speech(l.you, 'Daniel'), echo = Buffer.alloc(a.length);
      for (let i = 0; i < a.length; i += 2) echo.writeInt16LE(Math.round(a.readInt16LE(i) * 0.5), i);
      ch2.push(a, silence(900)); ch1.push(silence(200), echo, silence(700));
    }
  }
  ch1 = Buffer.concat([...ch1, silence(2500)]); ch2 = Buffer.concat([...ch2, silence(2500)]);
  const len = Math.max(ch1.length, ch2.length);
  const pad = b => Buffer.concat([b, Buffer.alloc(len - b.length)]);
  ch1 = pad(ch1); ch2 = pad(ch2);
  for (let o = 0; o < len; o += 3200) { // 100 ms packets per channel, real time
    ws.send(Buffer.concat([Buffer.from([1]), ch1.slice(o, o + 3200)]));
    ws.send(Buffer.concat([Buffer.from([2]), ch2.slice(o, o + 3200)]));
    await sleep(100);
  }
  if (click) { await sleep(1000); got.push({ type: '— CLICK what_should_i_say —', _t: Date.now() }); ws.send(JSON.stringify({ type: 'what_should_i_say' })); }
  await sleep(waitMs);
  ws.close();
  // For a click, only what arrives AFTER the click counts — auto-detect must not mask a dead button.
  const from = click ? got.findIndex(m => m.type === '— CLICK what_should_i_say —') : 0;
  const seen = got.slice(from);
  const detected = seen.find(m => m.type === 'question_detected');
  const cardsAfter = seen.filter(m => ['match', 'new_question', 'live_answer'].includes(m.type));
  const card = (click && expectText) ? (cardsAfter.find(m => expectText.test(m.questionText || '')) || cardsAfter[0]) : cardsAfter[0];
  const errs = seen.filter(m => m.type === 'error').map(m => m.message);
  console.log(`\n### ${name}`);
  console.log('  detected :', detected ? `${detected.source}: "${detected.text}"` : '— none —');
  console.log('  card     :', card ? `${card.type}: "${card.questionText}"` : '— NOTHING ON SCREEN —');
  if (errs.length) console.log('  errors   :', errs.join(' | '));
  // Instant jump check: first answer-bearing event after the click is a 'match' within 800 ms, and no new card/rewrite.
  let jump = null;
  if (click) {
    const clickT = seen[0] && seen[0]._t, after = seen.slice(1);
    const first = after.find(m => ['match', 'new_question', 'live_answer'].includes(m.type));
    const newCards = after.filter(m => m.type === 'new_question').length;
    const clickedIds = new Set(after.filter(m => m.type === 'match').map(m => m.questionId));
    const rewrites = after.filter(m => m.type === 'live_answer_delta' && clickedIds.has(m.questionId) && m._t > clickT + 900).length;
    jump = { ok: !!first && first.type === 'match' && first._t - clickT < 800 && newCards === 0 && rewrites === 0, ms: first ? first._t - clickT : null, newCards, rewrites };
    console.log(`  jump     : ${first ? first.type + ' in ' + jump.ms + ' ms' : 'nothing'}, new cards after click ${newCards}, rewrites ${rewrites}`);
  }
  return { detected: !!detected, card: !!card, cardText: card ? (card.questionText || '') : '', errs, jump };
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
    ['YOU   answering (echo leaks)', { lines: [{ you: 'Yeah, so in my last role I built the sales dashboards in Power BI, and it cut reporting time by twenty percent.' }], expectNone: true }],
    ['YOU   asking them a question (echo)', { lines: [{ you: 'Great, so what does the team structure look like for this role?' }], expectNone: true }],
    ['YOU   asking, filler lead-in (echo)', { lines: [{ you: 'Okay. How do you measure success in the first ninety days?' }], expectNone: true }],
    ['YOU   rhetorical mid-answer (echo)', { lines: [{ you: 'And why did that matter? Because the finance team needed numbers by Monday.' }], expectNone: true }],
    ['CLICK after only YOU spoke', { lines: [{ you: 'Great, so what does the team structure look like for this role?' }], click: true, expectNone: true, waitMs: 7000 }],
    ['CLICK them, then YOU answer', { lines: ['Talk me through how you would clean a messy sales dataset.', { you: 'Sure. So first I would check for duplicates. Why? Because duplicates inflate revenue.' }], click: true, expectText: /messy|clean/i }],
    ['BLEED interviewer leaks into mic', { lines: [{ bleed: 'Please describe your experience with Power BI.' }] }],
    ['BLEED interviewer leaks, wh- question', { lines: [{ bleed: 'How would you handle a missed deadline on a client report?' }] }],
    ['CLICK after the app already answered → instant jump, no rewrite', { lines: ['How would you handle a missed deadline on a client report?'], click: true, expectJump: true, waitMs: 6000 }],
    ['PANIC "Your thoughts on dbt." → answers it', { lines: ['Your thoughts on dbt.'], click: true, expectText: /dbt/i }],
    ['PANIC statement "So you have been using Power BI…" → answers it', { lines: ['So you have been using Power BI for a while.'], click: true, expectText: /power bi/i }],
    ['PANIC problem "We struggle with data quality…" → answers it', { lines: ['We have been struggling with data quality in our warehouse feeds.'], click: true, expectText: /data quality|quality/i }],
    ['PANIC new ask after an old answer → answers the NEW one', { lines: ['How would you handle a missed deadline on a client report?', 'Your thoughts on dbt.'], click: true, expectText: /dbt/i }],
    ['CLICK nothing asked yet', { lines: [], click: true, waitMs: 5000 }],
  ];
  const only = process.env.ONLY; let fails = 0;
  for (const [n, c] of cases) {
    if (only && !n.includes(only)) continue;
    const r = await scenario(n, c);
    const ok = c.expectJump ? (r.jump && r.jump.ok) : c.expectNone ? !r.card : c.expectText ? r.card && c.expectText.test(r.cardText) : c.lines.length ? r.card : r.errs.length > 0; // spoken question → card; candidate/small talk → no card; nothing spoken → a visible reason
    if (!ok) fails++; console.log('  RESULT   :', ok ? 'PASS' : 'FAIL');
  }
  await pool.end(); fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${fails ? fails + ' FAILED' : 'ALL PASS'}`); process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
