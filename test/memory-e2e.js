// Session-memory test (real server, real Deepgram + Claude). Speaks a multi-call interview into ONE session and
// grades the live answers with a judge model against the owner's rule:
//   use what was said (mine + interviewer, this call and earlier calls) → consistent with MY claims, aligned to
//   THEIR use case, but grounded in MY experience/domain and never in their words.
// Usage: node test/memory-e2e.js [http://localhost:3999]   (LOCAL DATABASE_URL only)
require('dotenv').config();
const { execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path'), https = require('https');
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3999';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-mem-'));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
function speech(text, voice) {
  const aiff = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), wav = aiff.replace('.aiff', '.wav');
  execFileSync('say', ['-v', voice, '-o', aiff, text]); execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', aiff, wav]);
  const b = fs.readFileSync(wav); return b.slice(b.indexOf('data') + 8);
}
const RESUME = `Jordan Lee — Data Analyst, Northwind Retail (2021–present). Sales & CRM analytics for 120 retail stores.
- Built daily Snowflake + dbt pipelines for sales and CRM data; Power BI dashboards for regional sales managers.
- Cut weekly sales-report refresh from 4 hours to 20 minutes by rewriting SQL and clustering large fact tables.
- Cleaned Salesforce CRM data (dedup, standardization) for 2M customer records.
Skills: SQL, Snowflake, dbt, Power BI, Python, Excel.`;
async function seed(sc = {}) {
  const resume = sc.resume || RESUME, company = sc.company || 'Keystone Logistics', role = sc.role || 'Senior Data Analyst';
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Jordan Lee','pro') RETURNING id", ['mem-' + Date.now() + '@local.test'])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1,$3,$4,$2,'Senior Data Analyst — Snowflake, SQL, forecasting, logistics operations analytics.') RETURNING id", [u.id, resume, company, role])).rows[0];
  if (!sc.resume) await pool.query('INSERT INTO questions (session_id, text, answer) VALUES ($1,$2,$3)', [s.id, 'Tell me about your Snowflake experience',
    'I have used Snowflake for about three years.\nI build pipelines and write SQL for reporting.\nI am comfortable with warehouses, roles, and performance tuning.']);
  return { token: jwt.sign({ userId: u.id, name: 'Jordan Lee', email: 'x', plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' }), sessionId: s.id };
}
// One call = one live connection. Lines: strings = interviewer (Ch1), { you } = candidate mic (Ch2, headphones).
async function call(auth, lines, { waitMs = 12000 } = {}) {
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const got = [];
  ws.on('message', d => { try { const m = JSON.parse(d); if (['live_answer', 'match', 'new_question'].includes(m.type)) got.push(m); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token: auth.token, sessionId: auth.sessionId, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  let ch1 = [silence(400)], ch2 = [silence(400)];
  for (const l of lines) {
    if (typeof l === 'string') { const a = speech(l, 'Samantha'); ch1.push(a, silence(1600)); ch2.push(silence(a.length / 32 + 1600)); }
    else { const a = speech(l.you, 'Daniel'); ch2.push(a, silence(1600)); ch1.push(silence(a.length / 32 + 1600)); }
  }
  ch1 = Buffer.concat([...ch1, silence(2500)]); ch2 = Buffer.concat([...ch2, silence(2500)]);
  const len = Math.max(ch1.length, ch2.length), pad = b => Buffer.concat([b, Buffer.alloc(len - b.length)]); ch1 = pad(ch1); ch2 = pad(ch2);
  for (let o = 0; o < len; o += 3200) { ws.send(Buffer.concat([Buffer.from([1]), ch1.slice(o, o + 3200)])); ws.send(Buffer.concat([Buffer.from([2]), ch2.slice(o, o + 3200)])); await sleep(100); }
  await sleep(waitMs);
  ws.send(JSON.stringify({ type: 'stop' })); await sleep(1500); ws.close();
  // The answer on screen for the LAST question = latest answer-bearing message
  const last = [...got].reverse().find(m => (m.type === 'live_answer' || m.type === 'match') && m.answer);
  return last ? { q: last.questionText, a: last.answer, kind: last.type } : null;
}
function judge(context, shown, sc = {}) {
  const sys = 'You grade a live interview-copilot answer. Reply with ONLY JSON: one integer 0-2 per criterion named below (use exactly those names as keys) plus "why":"one short sentence".';
  const user = `TODAY: ${new Date().toISOString().slice(0, 10)} (use it to check years of experience).\n\nWHAT WAS SAID EARLIER IN THIS INTERVIEW SESSION:\n${context}\n\nCANDIDATE RESUME:\n${sc.resume || RESUME}\n\nQUESTION NOW: ${shown.q}\nANSWER SHOWN TO CANDIDATE:\n${shown.a}\n\nScore 0-2 each:${sc.rubric || `
consistent = builds on what the CANDIDATE already said (daily Snowflake use, ~3 years, sales/CRM pipelines). 2 = clearly builds on it; 1 = compatible but ignores it; 0 = contradicts it.
aligned = connects to the INTERVIEWER's stated situation (demand forecasting across warehouses, slow queries on shipment tables). 2 = explicitly ties the answer to their situation; 1 = only generically relevant; 0 = unrelated.
grounded = the proof/examples come from the CANDIDATE's own experience/domain (retail sales/CRM at Northwind, e.g. the 4h→20min report). 2 = uses a concrete example from their own work; 1 = generic, no example; 0 = claims the candidate did the company's logistics/forecasting work.
own_words = does NOT parrot the interviewer. 2 = own phrasing; 1 = borrows a phrase; 0 = copies their sentences.`}`;
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ model: process.env.MODEL_SONNET || 'claude-sonnet-5', max_tokens: 3000, system: sys, messages: [{ role: 'user', content: user }] });
    const req = https.request({ hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' } }, res => {
      let d = ''; res.on('data', c => d += c); res.on('end', () => { try { const t = JSON.parse(d).content.filter(c => c.type === 'text').map(c => c.text).join(''); resolve(JSON.parse(t.slice(t.indexOf('{'), t.lastIndexOf('}') + 1))); } catch (e) { reject(new Error('judge parse: stop=' + ((()=>{try{return JSON.parse(d).stop_reason}catch(_){return '?'}})()) + ' ' + d.slice(-300))); } });
    }); req.on('error', reject); req.write(body); req.end();
  });
}
var keptFail = false;
(async () => {
  const CONTEXT = `Interviewer: Do you have experience with Snowflake?
Candidate: Yes, I use Snowflake every day, about three years now, mostly building sales reporting pipelines and cleaning CRM data.
Interviewer: Great. Here we use Snowflake to forecast demand for our forty warehouses, and our queries over the shipment tables have gotten really slow.`;
  const call1 = ['Do you have experience with Snowflake?',
    { you: 'Yes, I use Snowflake every day, about three years now, mostly building sales reporting pipelines and cleaning CRM data.' },
    'Great. Here we use Snowflake to forecast demand for our forty warehouses, and our queries over the shipment tables have gotten really slow.',
    { you: 'Got it, that makes sense.' }];
  const filler = ['Let me tell you a little about the team.', 'We are a hybrid team of six analysts.', 'Most of us are based in Chicago.',
    { you: 'That sounds great.' }, 'We do planning every two weeks.', 'And we present to operations leadership monthly.', { you: 'Okay, nice.' }];
  const cases = [
    ['SAME CALL, 7 lines later', async a => call(a, [...call1, ...filler, 'How would you speed up a slow query in our environment?'])],
    ['NEXT CALL, open question', async a => { await call(a, call1, { waitMs: 6000 }); await sleep(4000);
      // Regression: a finished call must be KEPT (it was deleted as "empty") and get its notes for the next call
      const r = (await pool.query('SELECT jsonb_array_length(transcript) n, memory FROM live_transcripts WHERE session_id = $1', [a.sessionId])).rows;
      const kept = r.find(x => x.n > 0);
      console.log(`\n### FINISHED CALL KEPT\n  rows=${r.length} lines=${kept ? kept.n : 0} notes=${kept && kept.memory ? kept.memory.length + ' chars' : 'none'}\n  RESULT: ${kept && kept.memory ? 'PASS' : 'FAIL'}`);
      if (!(kept && kept.memory)) keptFail = true;
      return call(a, ['Thanks for joining again.', 'How would you speed up a slow query in our environment?']); }],
    ['NEXT CALL, bank question', async a => { await call(a, call1, { waitMs: 6000 }); return call(a, ['Thanks for joining again.', 'Tell me about your Snowflake experience.']); }],
  ];
  const RL_RESUME = `Ridwan Akanbi — Data Analyst, R&L Carriers (Mar 2022–present). Freight & operations reporting.
- Build SQL and Power BI reporting on freight shipments, terminals and claims.
- Reconcile data across legacy AS/400 tables and newer SQL Server marts.
- Automated weekly terminal KPI pack (Excel → Power BI), saving ops managers ~6 hours/week.
Skills: SQL, Power BI, Excel, Python.`;
  const RL_CONTEXT = `Earlier call — Sarah (hiring manager): "I really like someone who can dig in when they hit a problem, instead of escalating right away." and "Honestly our data environment is messy, it can be hard to find things."
Next call — David (Sarah's boss) introduces: "We're a small team, and we care a lot about ownership, people who can work independently."`;
  const RL_RUBRIC = `
concern = shows the qualities these interviewers said they value (digs in / investigates before escalating; ownership; works independently in a messy, hard-to-navigate data environment). 2 = the answer clearly demonstrates them; 1 = hints; 0 = ignores.
own_env = makes the point through the CANDIDATE's OWN workplace (R&L, its data/tables/reporting) — e.g. their own environment is also messy so they dig first. 2 = concrete, in their own workplace; 1 = generic; 0 = none, or claims they worked at the interviewer's company.
facts = keeps resume facts true (employer, role, dates, tools). 2 = fully; 1 = minor stretch; 0 = contradicts or invents employers/titles/degrees.
own_words = does NOT parrot the interviewers (no "you mentioned", no copying "dig in", "hard to find things" verbatim). 2 = own phrasing; 1 = borrows a phrase; 0 = copies their sentences.`;
  const RL = { resume: RL_RESUME, company: 'Keystone Freight', role: 'Senior Data Analyst', rubric: RL_RUBRIC,
    call1: ['Hi, I am Sarah, the hiring manager for this role.', 'I really like someone who can dig in when they hit a problem, instead of escalating right away.',
      { you: 'That makes sense, I like to understand a problem before I raise it.' }, 'Honestly our data environment is messy, it can be hard to find things.', { you: 'Got it.' }] };
  cases.push(['OTHER INTERVIEWER, stuck question', async a => { await call(a, RL.call1, { waitMs: 5000 }); await sleep(4000);
    return call(a, ['Hi, I am David, Sarah\'s boss.', "We're a small team, and we care a lot about ownership, people who can work independently.", 'How do you handle it when you get stuck on something?']); }, RL]);
  cases.push(['OTHER INTERVIEWER, tell me about yourself', async a => { await call(a, RL.call1, { waitMs: 5000 }); await sleep(4000);
    return call(a, ['Hi, I am David, Sarah\'s boss.', "We're a small team, and we care a lot about ownership, people who can work independently.", 'So tell me a bit about yourself.']); }, RL]);
  let fails = 0;
  for (const [name, run, sc] of cases) {
    if (process.env.ONLY && !name.includes(process.env.ONLY)) continue;
    const shown = await run(await seed(sc || {}));
    console.log(`\n### ${name}`);
    if (!shown) { fails++; console.log('  NO ANSWER ON SCREEN — FAIL'); continue; }
    console.log(`  Q: ${shown.q}  [${shown.kind}]\n  A: ${shown.a.replace(/\n/g, '\n     ')}`);
    const g = await judge(sc ? RL_CONTEXT : CONTEXT, shown, sc || {});
    const keys = Object.keys(g).filter(k => k !== 'why'); const sum = keys.reduce((t, k) => t + g[k], 0);
    const ok = sc ? (g.concern === 2 && g.own_env >= 1 && g.facts === 2 && g.own_words >= 1)       // their concern, through MY workplace
                  : (g.aligned === 2 && g.grounded === 2 && g.consistent >= 1 && g.own_words >= 1); // their use case, through MY experience
    if (!ok) fails++;
    console.log(`  judge: ${keys.map(k => k + '=' + g[k]).join(' ')} (${sum}/${keys.length * 2}) — ${g.why}\n  RESULT: ${ok ? 'PASS' : 'FAIL'}`);
  }
  if (keptFail) fails++;
  await pool.end(); fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${fails ? fails + ' FAILED' : 'ALL PASS'}`); process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
