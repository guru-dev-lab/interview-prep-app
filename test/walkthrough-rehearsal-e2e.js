// Big walkthrough rehearsal (owner, 12 Nov: "bigger test with voice and you typing too.. or using voice only with different
// ones and ill ask to assist.. lot of scenario questions, direct questions and all"). Real server + real Deepgram + real
// models, co-pilot mode on, the Tableau screen fixture shared. Interviewer lines are spoken with macOS `say` in several
// voices on the call channel. Four ways in, like on the call:
//   heard  — they say it, nobody presses: a card must come on its own (the overlay's question_detected → copilotSend part)
//   say    — they say it, he presses Say
//   assist — they say something that is not a clean question, he presses Assist
//   typed  — he types an instruction
// Small talk must NOT make a card. Every card is written to OUT for a read by hand (facts, field names).
// Usage: node test/walkthrough-rehearsal-e2e.js [baseUrl] [start step]   (LOCAL DATABASE_URL; server with MUSTHAVE_PREBUILD=0)
require('dotenv').config();
const { execFileSync } = require('child_process'); const fs = require('fs'), os = require('os'), path = require('path');
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3997', FROM = +(process.argv[3] || 0);
const OUT = process.env.REHEARSAL_OUT || path.join(os.tmpdir(), 'walkthrough-rehearsal.md');
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL }); const sleep = ms => new Promise(r => setTimeout(r, ms));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-wr-'));
const speech = (t, v) => { const a = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), w = a.replace('.aiff', '.wav'); execFileSync('say', ['-v', v, '-o', a, t]); execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', a, w]); const b = fs.readFileSync(w); return b.slice(b.indexOf('data') + 8); };
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
const SHOT = 'data:image/png;base64,' + fs.readFileSync(path.join(__dirname, 'fixtures/screens/tableau-superstore.png')).toString('base64');

const noCode = a => a.replace(/```[\s\S]*?```/g, '');
const steps = a => (a.match(/^\s*\d+[.)]\s/gm) || []).length;
// what a good card looks like, per kind
const KIND = {
  build: a => [['Do + numbered steps', /^(\*\*)?Do:/m.test(a) && steps(a) >= 1], ['at most 5 steps', !/^\s*6[.)]/m.test(a)], ['skim length', noCode(a).length <= 1150], ['no Build / Look for', !/^(\*\*)?(Build|Look for):/m.test(a)]],
  story: a => [['three beats', /what is happening/i.test(a) && /where and why/i.test(a) && /what to do/i.test(a)], ['skim length', noCode(a).length <= 1400]],
  concept: a => [['answers in Say lines', /^Say:/m.test(a) && noCode(a).split('\n').filter(l => l.trim()).length >= 3], ['skim length', noCode(a).length <= 1150]],
  open: a => [['an answer', /^(Say:|(\*\*)?(Do|Say it):)/m.test(a)], ['skim length', noCode(a).length <= 1400]],
  about: a => [['spoken answer', /^Say:/m.test(a)], ['no build steps', !/^(\*\*)?Do:/m.test(a)]],
};
const V = ['Samantha', 'Daniel', 'Karen', 'Moira', 'Rishi', 'Tessa'];
// [how, what is said / typed, kind, extra check]
const STEPS = [
  ['heard', 'Hi, can you hear me okay? Give me one second, my camera is acting up.', 'none'],
  ['heard', "Great. So you've got Tableau Public open with the Superstore data. Can you walk me through what's in the data pane?", 'concept'],
  ['heard', "Let's start simple. Build me a bar chart of sales by category.", 'build', a => [['Sales and Category named', /`Sales`|SUM\(Sales\)/.test(a) && /`Category`/.test(a)]]],
  ['heard', 'Now break that down by sub-category and sort it from highest to lowest.', 'build', a => [['Sub-Category', /Sub-Category/.test(a)]]],
  ['heard', 'Which sub-categories are losing money?', 'build', a => [['reads losers off the screen (Tables, Bookcases, Supplies) or checks', /Tables/.test(a) || /negative|go negative/i.test(a)]]],
  ['say', 'Okay, and how would you highlight just the ones that lose money so they jump out?', 'build', a => [['colour or calc on Profit', /Color|colour|IF .*Profit|SUM\(\[Profit\]\)\s*<\s*0/i.test(a)]]],
  ['heard', "Let's filter this down to just the West region.", 'build', a => [['Region filter', /Region/.test(a) && /West/.test(a)]]],
  ['heard', 'Can you create a calculated field for profit ratio?', 'build', a => [['profit ratio formula', /SUM\(\[Profit\]\)\s*\/\s*SUM\(\[Sales\]\)/.test(a)]]],
  ['typed', 'how do I format profit ratio as a percentage', 'build', a => [['Format / Percentage', /percent/i.test(a) && /format|default properties|number format/i.test(a)]]],
  ['heard', 'Show me sales and profit by state on a map.', 'build', a => [['State/Province as on screen', /State\/Province/.test(a)]]],
  ['heard', 'How would you show the trend of sales over time, by month?', 'build', a => [['Order Date by month', /Order Date/.test(a) && /month/i.test(a)]]],
  ['heard', 'Can you add a reference line for the average?', 'build', a => [['Analytics pane / Reference Line', /Analytics|Reference Line|Average Line/i.test(a)]]],
  ['heard', "What's the difference between a dimension and a measure?", 'concept'],
  ['heard', 'And what do the blue and green pills mean?', 'concept', a => [['discrete / continuous (not dimension / measure)', /discrete/i.test(a) && /continuous/i.test(a)]]],
  ['say', 'Who are our top ten customers by sales?', 'build', a => [['Top N filter on Customer Name', /Customer Name/.test(a) && /Top|10/i.test(a)]]],
  ['heard', 'Is there a relationship between discount and profit? How would you check that?', 'build', a => [['scatter of Discount vs Profit', /Discount/.test(a) && /scatter|Columns|Rows/i.test(a)]]],
  ['typed', 'year over year growth calc', 'build', a => [['table calc / LOOKUP / percent difference', /Percent Difference|LOOKUP|YoY|year over year|Quick Table Calculation/i.test(a)]]],
  ['heard', 'Have you used LOD expressions? Show me average sales per customer with one.', 'build', a => [['FIXED LOD', /\{\s*FIXED\s*\[Customer (Name|ID)\]/i.test(a)]]],
  ['heard', 'Now put the map and the bar chart together on a dashboard, and make clicking a state filter the bars.', 'build', a => [['Dashboard + filter action', /Dashboard/i.test(a) && /(Use as Filter|Actions|filter action)/i.test(a)]]],
  ['assist', "So, the regional managers keep telling us the Central numbers just don't look right to them.", 'open'],
  ['heard', 'How would you tell the story of what is driving the losses in this data?', 'story', a => [['discount named', /discount/i.test(a)]]],
  ['heard', 'Hmm, okay. Sorry, let me just pull up my notes here.', 'none'],
  ['heard', 'Tell me a little bit about yourself and your background.', 'about'],
  ['say', 'Tell me about a time an insight you found changed a decision.', 'about'],
  ['typed', 'give me a good title for this chart', 'concept'],
  ['heard', 'Do you have any questions for me?', 'about'],
];

(async () => {
  const email = 'rehearsal@local.test';
  let u = (await pool.query('SELECT id FROM users WHERE email = $1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1, 'RH', 'pro') RETURNING id", [email])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1, 'Polaris Project', 'Data Analyst', 'Data Analyst, R&L Carriers (2021–now): built Power BI and Tableau dashboards for freight lanes; SQL, Python. Found that 12% of lanes lost money after fuel surcharges, which changed carrier pricing.') RETURNING id", [u.id])).rows[0]; // a fresh session each run
  const token = jwt.sign({ userId: u.id, name: 'RH', email, plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '2h' });
  const post = body => fetch(`${BASE}/api/sessions/${s.id}/copilot`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify(body) }).then(r => r.json()).catch(e => ({ error: String(e) }));
  let shared = false; // the overlay sends the screen with the first turn, then only when it changes
  const frame = () => shared ? {} : (shared = true, { image: SHOT, screenChanged: true, screenKey: 'scr-tableau' });
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const got = [];
  let waitingFirst = false; // first words of the card just started
  ws.on('message', d => { try { const m = JSON.parse(d); m._t = Date.now();
    if (m.type === 'copilot_delta') { if (waitingFirst) { waitingFirst = false; got.push({ type: 'first_delta', _t: m._t }); } return; }
    if (m.type === 'copilot_start') waitingFirst = true;
    if (/copilot|question_detected/.test(m.type)) got.push(m);
    // the overlay's parts (canvas.html): a heard question → copilotSend({ ask }); Say → the server's pick comes back as copilot_say
    if (m.type === 'question_detected' && m.source === 'copilot') post({ ask: m.text, ...frame() });
    if (m.type === 'copilot_say') post({ ask: m.text || '', say: true, pressed: true, ...frame() }); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: false }));
  await sleep(500);
  const audio = async (buf, until) => { for (let o = 0; o < buf.length; o += 3200) { ws.send(Buffer.concat([Buffer.from([1]), buf.slice(o, o + 3200)])); ws.send(Buffer.concat([Buffer.from([2]), silence(100)])); await sleep(100); if (until && until()) return; } };
  const report = [`# Walkthrough rehearsal — ${new Date().toISOString()}\n`]; let fail = 0, n = 0;
  for (const [how, text, kind, extra] of STEPS.slice(FROM)) {
    n++; const i0 = got.length, t0 = Date.now(), voice = V[n % V.length];
    const doneHere = () => got.slice(i0).some(m => m.type === 'copilot_done');
    if (how === 'typed') { await audio(silence(800)); post({ ask: text, typed: true, ...frame() }); }
    else {
      await audio(speech(text, voice));
      if (how === 'say') { await audio(silence(1500)); ws.send(JSON.stringify({ type: 'what_should_i_say' })); } // the Say button, as the overlay sends it
      if (how === 'assist') { await audio(silence(1500)); post({ ask: '', pressed: true, ...frame() }); }
    }
    // keep the call audio flowing (silence) while the card comes; a no-card step waits long enough for a wrong card to show
    await audio(silence(kind === 'none' ? 9000 : 30000), kind === 'none' ? null : () => doneHere() && Date.now() - t0 > 4000);
    await audio(silence(1500)); // a late second card for the same ask would land here
    const here = got.slice(i0), starts = here.filter(m => m.type === 'copilot_start'), dones = here.filter(m => m.type === 'copilot_done');
    const first = here.find(m => m.type === 'first_delta'), a = dones.length ? dones[dones.length - 1].answer || '' : '';
    const sec = x => x ? ((x._t - t0) / 1000).toFixed(1) + ' s' : '—';
    const checks = kind === 'none' ? [['no card for small talk', starts.length === 0]]
      : [['a card came', dones.length >= 1], ['one card, not two', starts.length <= 1], ...(a ? KIND[kind](a) : []), ...(a && extra ? extra(a) : [])];
    const bad = checks.filter(c => !c[1]); fail += bad.length;
    console.log(`\n[${FROM + n - 1}] ${how.padEnd(6)} ${voice.padEnd(8)} ${kind.padEnd(7)} first ${sec(first)} done ${sec(dones[0])}  "${text}"`);
    for (const [l, ok] of checks) console.log(`   ${ok ? 'PASS' : 'FAIL'} ${l}`);
    report.push(`## [${FROM + n - 1}] ${how} — "${text}"\n_${kind} · first words ${sec(first)} · card done ${sec(dones[0])} · ${bad.length ? 'FAIL: ' + bad.map(c => c[0]).join(', ') : 'pass'}_\n` + (here.filter(m => m.type === 'question_detected').map(m => `heard: "${m.text}"`).join('\n') || '') + '\n\n' + (dones.map(d => d.answer).join('\n\n---\n\n') || '(no card)') + '\n');
    fs.writeFileSync(OUT, report.join('\n'));
  }
  ws.close(); await pool.end();
  console.log(`\nCards written to ${OUT}`);
  console.log(fail ? `${fail} FAILED` : 'ALL PASS'); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
