// FULL MOCK INTERVIEW — two calls (hiring manager, then her boss) played as real audio through the real server, the
// way the desktop app streams them. Scores every interviewer question (detected once, right question, speed, layout,
// judged quality) and checks that the candidate's own speech and small talk never produce a card.
// Usage: node test/mock-interview.js [baseUrl] [mode]   mode = clean | echo | noise   (LOCAL DATABASE_URL only)
require('dotenv').config();
const { execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path'), https = require('https');
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const stringSimilarity = require('string-similarity');
const BASE = process.argv[2] || 'http://localhost:3997', MODE = process.argv[3] || 'clean';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-mock-'));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const VOICES = { sarah: 'Samantha', david: 'Reed (English (US))', me: 'Daniel' };
function speech(text, voice) {
  const aiff = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), wav = aiff.replace('.aiff', '.wav');
  execFileSync('say', ['-v', voice, '-o', aiff, text]); execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', aiff, wav]);
  const b = fs.readFileSync(wav); return b.slice(b.indexOf('data') + 8);
}
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
const scaled = (buf, g) => { const o = Buffer.alloc(buf.length); for (let i = 0; i < buf.length; i += 2) o.writeInt16LE(Math.max(-32768, Math.min(32767, Math.round(buf.readInt16LE(i) * g))), i); return o; };

const EXP_FACTS = (() => { const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8'); const i = src.indexOf('const _MONTHS'), j = src.indexOf('// ONE answer generator for prepared (bank) answers'); return new Function(src.slice(i, j) + '\nreturn experienceFacts;')(); })()(`Ridwan Akanbi — Data Analyst, R&L Carriers (Mar 2022–present).\nJunior Data Analyst — Midwest Health Clinics (2020–2022)`);
const JD = fs.readFileSync(path.join(__dirname, 'fixtures', 'jd.txt'), 'utf8');
const RESUME = `Ridwan Akanbi — Data Analyst, R&L Carriers (Mar 2022–present). Freight & operations reporting.
- Build SQL and Power BI reporting on freight shipments, terminals and claims for 30 terminal managers.
- Reconciled legacy AS/400 tables with newer SQL Server marts after totals didn't match; found and fixed a field-mapping issue.
- Automated the weekly terminal KPI pack (Excel → Power BI), saving ops managers ~6 hours a week.
- Rewrote slow claims-report SQL (indexes, pre-aggregated tables): refresh went from 45 minutes to 6 minutes.
- Got regional directors to adopt a new on-time-delivery dashboard by piloting it with one region first; usage grew to all 8 regions.
Junior Data Analyst — Midwest Health Clinics (2020–2022): weekly operational reports in SQL Server and Excel.
Skills: SQL, Power BI (DAX), Excel, Python, SQL Server. B.S. Information Systems.`;

// Script. I = interviewer (expect: 'none' | { shape, bank?, about }), Y = candidate (must never make a card).
const CALL1 = [
  { who: 'sarah', t: 'Hi, thanks for joining. Can you hear me okay?', expect: 'none' },
  { who: 'me', t: 'Yes, I can hear you fine. Thanks for having me.' },
  { who: 'sarah', t: "Great. I'm Sarah, I manage the analytics team here at Keystone.", expect: 'none' },
  { who: 'sarah', t: 'So to start, tell me a little about yourself.', expect: { shape: 'pitch', about: 'tell me about yourself' } },
  { who: 'me', t: "Sure. I'm a data analyst at R and L Carriers, where I build freight and operations reporting in SQL and Power BI." },
  { who: 'sarah', t: "Okay. So we have forty warehouses, and our shipment queries in Snowflake have gotten really slow. How would you approach speeding them up?", expect: { shape: 'general', about: 'speeding up their slow Snowflake shipment queries' } },
  { who: 'me', t: 'I would start by looking at the query plan and seeing where the time goes.' },
  { who: 'sarah', t: 'Makes sense.', expect: 'none' },
  { who: 'sarah', t: 'I really like people who dig in before escalating. Tell me about a time you had to fix data that did not match.', expect: { shape: 'story', about: 'a time fixing data that did not match' } },
  { who: 'me', t: 'So our old AS 400 totals did not match the new SQL Server reports. Why did it matter? Because the terminal managers were getting two different numbers.' },
  { who: 'sarah', t: 'Write me a quick SQL query to get the top three customers by revenue in each region.', expect: { shape: 'code', about: 'SQL top 3 customers by revenue per region' } },
  { who: 'sarah', t: 'How do you get executives to actually use a dashboard you built?', expect: { shape: 'general', bank: 'How do you convince executives to use a report, tool, or recommendation you built?', about: 'getting executives to use a dashboard' } },
  { who: 'me', t: 'I usually pilot it with one team first and show them it saves time.' },
  { who: 'sarah', t: "What's the difference between a left join and an inner join?", expect: { shape: 'general', about: 'left join vs inner join' } },
  { who: 'me', t: 'Can I ask what the team structure looks like?' },
  { who: 'sarah', t: "Sure. We're six analysts, hybrid, based in Chicago.", expect: 'none' },
  { who: 'me', t: 'That sounds great, thank you.' },
];
const CALL2 = [
  { who: 'david', t: "Hi, I'm David, Sarah's boss. We're a small team, and we care a lot about people who can work independently.", expect: 'none' },
  { who: 'me', t: 'Nice to meet you, David.' },
  { who: 'david', t: 'How do you handle it when you get stuck on something?', expect: { shape: 'general', about: 'handling getting stuck (they value independence; Sarah: dig in before escalating)' } },
  { who: 'me', t: 'I try to trace the problem myself first, and then I ask with specifics.' },
  { who: 'david', t: 'What do you do when your manager pushes back on your analysis?', expect: { shape: 'general', bank: 'What do you do when leadership disagrees with what your data or analysis shows?', about: 'manager pushing back on your analysis' } },
  { who: 'david', t: "In Power BI, what's the difference between a calculated column and a measure?", expect: { shape: 'general', about: 'Power BI calculated column vs measure' } },
  { who: 'me', t: 'A measure is calculated at query time.' },
  { who: 'david', t: 'Why are you looking to leave your current job?', expect: { shape: 'pitch', about: 'why leaving current job' } },
  { who: 'david', t: "What's your experience with demand forecasting?", expect: { shape: 'general', about: 'experience with demand forecasting (their team forecasts demand by warehouse)' } },
  { who: 'me', t: 'I have done some trend analysis on shipment volumes.' },
  { who: 'david', t: 'Alright, that is all the time we have. Thanks for coming in.', expect: 'none' },
];

async function seed() {
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Ridwan Akanbi','pro') RETURNING id", ['mock-' + Date.now() + '@local.test'])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1,'Keystone Logistics','Senior Data Analyst',$2,$3) RETURNING id",
    [u.id, RESUME, JD])).rows[0];
  return { token: jwt.sign({ userId: u.id, name: 'Ridwan Akanbi', email: 'x', plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '2h' }), sessionId: s.id };
}

// Build both channels for one call, per MODE; returns buffers + byte ranges of every line.
function buildCall(lines) {
  let ch1 = [silence(600)], ch2 = [silence(600)], at = 600 * 32; const spans = [];
  for (const l of lines) {
    const a = speech(l.t, VOICES[l.who]); const len = a.length;
    const gapAfter = l.who === 'me' ? 1200 : (l.expect && l.expect !== 'none' ? 3200 : 1400); // time for the answer to show
    if (l.who === 'me') {
      ch2.push(a, silence(gapAfter));
      ch1.push(MODE === 'echo' ? Buffer.concat([silence(200), scaled(a, 0.5)]).slice(0, len) : silence(len / 32), silence(gapAfter));
    } else {
      ch1.push(a, silence(gapAfter));
      ch2.push(MODE === 'echo' ? Buffer.concat([silence(40), scaled(a, 0.35)]).slice(0, len) : silence(len / 32), silence(gapAfter));
    }
    spans.push({ start: at, end: at + len }); at += len + gapAfter * 32;
  }
  const pad = [silence(4000)]; ch1 = Buffer.concat([...ch1, ...pad]); ch2 = Buffer.concat([...ch2, ...pad]);
  if (MODE === 'noise') for (const b of [ch1, ch2]) for (let i = 0; i < b.length; i += 2) b.writeInt16LE(Math.max(-32768, Math.min(32767, b.readInt16LE(i) + Math.round((Math.random() - 0.5) * 900))), i);
  return { ch1, ch2, spans };
}

async function runCall(auth, lines, clicks) {
  const { ch1, ch2, spans } = buildCall(lines);
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const ev = [];
  ws.on('message', d => { try { const m = JSON.parse(d); if (!['transcript', 'user_transcript', 'interviewer_final', 'status', 'follow_up_predictions'].includes(m.type)) ev.push({ t: Date.now(), m }); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token: auth.token, sessionId: auth.sessionId, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(2000);
  const times = spans.map(() => ({})); const t0 = Date.now();
  for (let o = 0; o < ch1.length; o += 3200) {
    ws.send(Buffer.concat([Buffer.from([1]), ch1.slice(o, o + 3200)])); ws.send(Buffer.concat([Buffer.from([2]), ch2.slice(o, o + 3200)]));
    const now = Date.now();
    spans.forEach((s, i) => { if (!times[i].start && o + 3200 >= s.start) times[i].start = now; if (!times[i].end && o + 3200 >= s.end) times[i].end = now; });
    for (const c of clicks) if (!c.sent && times[c.after] && times[c.after].end && now - times[c.after].end > c.delay) { c.sent = now; ev.push({ t: now, m: { type: '— CLICK —', after: c.after } }); ws.send(JSON.stringify({ type: 'what_should_i_say' })); }
    await sleep(100);
  }
  await sleep(6000); ws.send(JSON.stringify({ type: 'stop' })); await sleep(2000); ws.close();
  return { ev, times, t0 };
}

// Group events into cards (one per questionId) and attribute each card to the line that caused it.
function score(lines, run) {
  const cards = new Map();
  for (const { t, m } of run.ev) {
    if (!m.questionId || !['new_question', 'match', 'live_answer_delta', 'live_answer'].includes(m.type)) continue;
    const c = cards.get(m.questionId) || { id: m.questionId, first: t, firstWords: null, q: m.questionText, answer: '', types: new Set(), grew: false, seq: [] };
    c.types.add(m.type); if (!c.seq.length || c.seq[c.seq.length - 1] !== m.type) c.seq.push(m.type); if (m.questionText) c.q = m.questionText;
    if (!c.firstWords && ((m.type === 'live_answer_delta' && m.chunk) || (m.answer && m.answer.length))) c.firstWords = t;
    if (m.type === 'live_answer' && m.answer) { c.answer = m.answer; if (m.grew) c.grew = true; }
    if (m.type === 'match' && m.answer && !c.answer) c.answer = m.answer;
    cards.set(m.questionId, c);
  }
  const lineAt = t => { let k = -1; run.times.forEach((x, i) => { if (x.start && x.start <= t) k = i; }); return k; };
  const perLine = lines.map(() => []); const problems = [];
  for (const c of cards.values()) {
    let k = lineAt(c.first);
    // a late card belongs to the last interviewer line if the candidate only just started talking
    while (k > 0 && lines[k].who === 'me' && c.first - run.times[k - 1].end < 7000) k--;
    const ownVoice = lines.some(l => l.who === 'me' && stringSimilarity.compareTwoStrings((c.q || '').toLowerCase(), l.t.toLowerCase()) > 0.5);
    if (ownVoice) problems.push(`OWN-VOICE card: "${c.q}"`);
    if (k < 0 || lines[k].who === 'me') { if (!ownVoice) problems.push(`STRAY card (after candidate speech): "${c.q}"`); continue; }
    if (lines[k].expect === 'none') { problems.push(`FALSE card on small talk "${lines[k].t}": "${c.q}"`); continue; }
    perLine[k].push(c);
  }
  return { cards, perLine, problems };
}

function shapeOK(shape, a) {
  const L = a.split('\n').filter(Boolean), b = L.filter(l => l.startsWith('• '));
  if (shape === 'code') return /^```/.test(L[0] || '');
  if (shape === 'story') return /^▸ /.test(L[0] || '') && b.length + L.filter(l => /^(Situation|Action|Result):/.test(l)).length >= 3;
  if (shape === 'pitch') return b.length >= 3 && !L.some(l => /^[↳▸]/.test(l));
  return b.length >= 2 && !L.some(l => /^▸/.test(l));
}
function judge(context, q, a) {
  const sys = 'You grade a live interview-copilot answer shown to a candidate mid-interview. Reply ONLY JSON: {"correct":0-2,"answers_it":0-2,"uses_history":0-2,"own_facts":0-2,"own_words":0-2,"why":"one short sentence"}.';
  const user = `TODAY: ${new Date().toISOString().slice(0, 10)}\n${EXP_FACTS}\n\nCANDIDATE RESUME:\n${RESUME}\n\nJOB DESCRIPTION (the candidate may reference it):\n${JD}\n\nWHAT WAS SAID EARLIER IN THIS INTERVIEW PROCESS:\n${context}\n\nQUESTION: ${q}\nANSWER SHOWN:\n${a}\n\nScore 0-2 each:
correct = factually/technically correct (0 if any wrong fact, bad syntax, or non-existent feature).
answers_it = directly answers THIS question (0 if it answers a different question).
uses_history = uses what was said earlier where it matters (their situation, values, the candidate's earlier claims); give 2 if nothing earlier is relevant.
own_facts = examples and facts about the candidate come from the resume/earlier answers; facts about the company may come from the job description or the interview; nothing invented (employers, numbers, years).
own_words = does not parrot the interviewers' phrasing or say "you mentioned".`;
  return new Promise((resolve) => {
    const body = JSON.stringify({ model: process.env.MODEL_OPUS || 'claude-opus-4-8', max_tokens: 3000, system: sys, messages: [{ role: 'user', content: user }] });
    const req = https.request({ hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' } }, res => {
      let d = ''; res.on('data', c => d += c); res.on('end', () => { try { const t = JSON.parse(d).content.filter(c => c.type === 'text').map(c => c.text).join(''); resolve(JSON.parse(t.slice(t.indexOf('{'), t.lastIndexOf('}') + 1))); } catch (e) { resolve(null); } });
    }); req.on('error', () => resolve(null)); req.write(body); req.end();
  });
}

(async () => {
  const auth = await seed();
  // The candidate prepares the session ahead of time: must-have answers (incl. influence & pushback) get ready.
  { const w = new WebSocket(BASE.replace(/^http/, 'ws')); await new Promise(r => w.on('open', r));
    w.send(JSON.stringify({ type: 'start', token: auth.token, sessionId: auth.sessionId, mode: 'full', platform: 'electron', dualStream: true }));
    for (let i = 0; i < 90; i++) { await sleep(1000); const r = await pool.query("SELECT count(*) FILTER (WHERE answer <> '') a, count(*) n FROM questions WHERE session_id = $1", [auth.sessionId]); if (+r.rows[0].n >= 20 && +r.rows[0].a >= 20) break; }
    w.close(); await pool.query('DELETE FROM live_transcripts WHERE session_id = $1', [auth.sessionId]); await sleep(1500); }

  const report = []; let totalQ = 0, detected = 0, dup = 0, layout = 0, bankHits = 0, bankQ = 0, judged = 0, goodAns = 0; const lat = []; const problems = [];
  const history = [];
  for (const [label, lines, clicks] of [['CALL 1 — Sarah (hiring manager)', CALL1, [{ after: 12, delay: 1500 }]], ['CALL 2 — David (her boss)', CALL2, []]]) {
    const run = await runCall(auth, lines, clicks);
    const sc = score(lines, run); problems.push(...sc.problems.map(p => `${label.split(' —')[0]}: ${p}`));
    report.push(`\n=== ${label}  [${MODE}]`);
    for (let k = 0; k < lines.length; k++) {
      const l = lines[k];
      if (l.who !== 'me') history.push(`${l.who === 'sarah' ? 'Sarah (hiring manager)' : 'David (her boss)'}: ${l.t}`); else history.push(`Candidate: ${l.t}`);
      if (!l.expect || l.expect === 'none') continue;
      totalQ++;
      const cs = sc.perLine[k].filter(c => !c.grew || sc.perLine[k].length === 1);
      const clickDup = clicks.some(c => { let j = c.after; while (j > 0 && lines[j].who === 'me') j--; return j === k; }) ? 1 : 0;
      if (!cs.length) { report.push(`✗ MISSED  "${l.t}"`); continue; }
      detected++; if (cs.length > 1 + clickDup) dup++;
      const c = cs[0]; const fw = c.firstWords ? c.firstWords - run.times[k].end : null; if (fw !== null) lat.push(fw);
      const okShape = shapeOK(l.expect.shape, c.answer || ''); if (okShape) layout++;
      let bankNote = ''; if (l.expect.bank) { bankQ++; const hit = stringSimilarity.compareTwoStrings((c.q || '').toLowerCase(), l.expect.bank.toLowerCase()) > 0.8; /* matched OR upgraded onto the prepared question */ if (hit) bankHits++; bankNote = hit ? ' prepared✓' : ' prepared✗'; }
      const g = c.answer ? await judge(history.slice(0, -1).join('\n'), l.t, c.answer) : null;
      let gNote = 'no answer';
      if (g) { judged++; const ok = g.correct === 2 && g.answers_it === 2 && g.uses_history >= 1 && g.own_facts >= 1 && g.own_words >= 1; if (ok) goodAns++; gNote = `${ok ? 'GOOD' : 'WEAK'} c${g.correct} a${g.answers_it} h${g.uses_history} f${g.own_facts} w${g.own_words} — ${g.why}`; }
      report.push(`${okShape ? '✓' : '✗'} ${String(fw ?? '—').padStart(5)} ms  ${cs.length > 1 + clickDup ? 'DUP ' : ''}[${l.expect.shape}]${bankNote}  "${l.t}"\n      card: "${c.q}"  (${cs.length} card(s): ${cs.map(x => x.seq.join('>')).join(' | ')})\n      ${(c.answer || '').split('\n').join('\n      ')}\n      judge: ${gNote}`);
    }
  }
  const med = xs => xs.length ? xs.slice().sort((a, b) => a - b)[Math.floor((xs.length - 1) / 2)] : null;
  const p90 = xs => xs.length ? xs.slice().sort((a, b) => a - b)[Math.floor(xs.length * 0.9) - (xs.length * 0.9 % 1 === 0 ? 1 : 0)] : null;
  console.log(report.join('\n'));
  console.log(`\n==================== SCORECARD [${MODE}] ====================`);
  console.log(`questions detected   ${detected}/${totalQ}`);
  console.log(`duplicates           ${dup}`);
  console.log(`wrong cards          ${problems.length}${problems.length ? '\n  - ' + problems.join('\n  - ') : ''}`);
  console.log(`right layout         ${layout}/${detected}`);
  console.log(`prepared answer hit  ${bankHits}/${bankQ}`);
  console.log(`judged GOOD          ${goodAns}/${judged}`);
  console.log(`first words          median ${med(lat)} ms, p90 ${p90(lat)} ms, worst ${lat.length ? Math.max(...lat) : '—'} ms`);
  const pass = detected === totalQ && dup === 0 && problems.length === 0 && layout === detected && bankHits === bankQ && goodAns >= Math.ceil(judged * 0.85);
  console.log(pass ? 'RESULT: PASS' : 'RESULT: FAIL');
  await pool.end(); fs.rmSync(tmp, { recursive: true, force: true }); process.exit(pass ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
