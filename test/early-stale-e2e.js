// Live call 21 Oct (regular panel): answers came before the question was finished, the rest of the question made a NEW
// card, statements got answer cards, and a new question showed an old card ("stale"). Real server + real Deepgram + Haiku,
// spoken with macOS `say`, streamed like Electron. ONE seeded session for the whole run (spend rule).
// Usage: node test/early-stale-e2e.js [http://localhost:3999]   (LOCAL DATABASE_URL only; server with MUSTHAVE_PREBUILD=0)
require('dotenv').config();
const { execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const BASE = process.argv[2] || 'http://localhost:3999';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-es-'));
const speech = (text, voice) => {
  const aiff = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), wav = aiff.replace('.aiff', '.wav');
  execFileSync('say', ['-v', voice || 'Samantha', '-o', aiff, text]);
  execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', aiff, wav]);
  const b = fs.readFileSync(wav); const i = b.indexOf('data'); return b.slice(i + 8);
};
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function seed() {
  const email = 'e2e-es-' + Date.now() + '@local.test';
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'E2E Tester','pro') RETURNING *", [email])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1,'Acme Analytics','Data Analyst','Data analyst, 4 years. SQL, Power BI, Excel, Python. Built sales dashboards at Northwind.') RETURNING id", [u.id])).rows[0];
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'pro', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  return { token, sessionId: s.id };
}

// lines: interviewer string | { you } (candidate mic) | { pause: ms } (interviewer silent mid-turn, replaces the 700 ms gap)
async function scenario(sess, name, { lines, click, clickAt, waitMs = 9000 }) {
  const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
  const got = [];
  ws.on('message', d => { try { const m = JSON.parse(d); m._t = Date.now(); if (!/transcript/.test(m.type)) got.push(m); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token: sess.token, sessionId: sess.sessionId, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  const ch1 = [silence(500)], ch2 = [silence(500)];
  let lastAskEnd = 0, lastAskStart = 0; // byte offsets of the interviewer's LAST line
  let pressByte = null, pressEnd = null; // { ask, pressAt }: press Say part-way through THAT line
  const len1 = () => ch1.reduce((n, b) => n + b.length, 0);
  for (const l of lines) {
    if (typeof l === 'string' || l.ask) { const a = speech(l.ask || l); lastAskStart = len1(); ch1.push(a); lastAskEnd = len1(); if (l.pressAt) { pressByte = lastAskStart + Math.round(a.length * l.pressAt); pressEnd = lastAskEnd; } ch1.push(silence(700)); ch2.push(silence(a.length / 32 + 700)); }
    else if (l.pause) { ch1.pop(); ch2.pop(); ch1.push(silence(l.pause)); ch2.push(silence(l.pause)); }
    else { const a = speech(l.you, 'Daniel'); ch2.push(a, silence(900)); ch1.push(silence(a.length / 32 + 900)); }
  }
  let c1 = Buffer.concat([...ch1, silence(2500)]), c2 = Buffer.concat(ch2);
  const len = Math.max(c1.length, c2.length);
  c1 = Buffer.concat([c1, Buffer.alloc(len - c1.length)]); c2 = Buffer.concat([c2, Buffer.alloc(len - c2.length)]);
  const t0 = Date.now();
  // clickAt: press Say part-way through the interviewer's last line (0.6 = 60% of it spoken) — they are still talking.
  const clickByte = pressByte !== null ? pressByte : clickAt ? lastAskStart + Math.round((lastAskEnd - lastAskStart) * clickAt) : null;
  for (let o = 0; o < len; o += 3200) {
    if (clickByte !== null && o >= clickByte && !got.some(m => m.type === 'CLICK')) { got.push({ type: 'CLICK', _t: Date.now() }); ws.send(JSON.stringify({ type: 'what_should_i_say' })); }
    ws.send(Buffer.concat([Buffer.from([1]), c1.slice(o, o + 3200)]));
    ws.send(Buffer.concat([Buffer.from([2]), c2.slice(o, o + 3200)]));
    await sleep(100);
  }
  const askEndT = t0 + ((pressEnd !== null ? pressEnd : lastAskEnd) / 32000) * 1000; // end of the line pressed in (else the last line)
  if (click && !clickAt && pressByte === null) { got.push({ type: 'CLICK', _t: Date.now() }); ws.send(JSON.stringify({ type: 'what_should_i_say' })); }
  await sleep(waitMs);
  ws.close();
  const detected = got.filter(m => m.type === 'question_detected');
  const ids = [...new Set(got.filter(m => ['new_question', 'match', 'live_answer'].includes(m.type)).map(m => m.questionId))];
  console.log(`\n### ${name}`);
  for (const m of got.filter(m => ['question_detected', 'new_question', 'match', 'CLICK'].includes(m.type)))
    console.log(`  ${String(m._t - askEndT).padStart(6)} ms  ${m.type.padEnd(17)} ${m.source || ''} "${(m.text || m.questionText || '').slice(0, 90)}"`);
  return { got, detected, ids, askEndT };
}

(async () => {
  const sess = await seed();
  const fails = [];
  const check = (ok, what) => { console.log(`  ${ok ? 'PASS' : 'FAIL'} ${what}`); if (!ok) fails.push(what); };

  let r;
  const only = (process.env.ONLY || '').split(',').filter(Boolean), run = n => !only.length || only.includes(String(n)); // ONLY=6,8 → just those (spend rule)
  if (run(1)) {
  // 1. Deepgram cuts the question in two; the first half must not get a card, the whole question gets ONE card.
  r = await scenario(sess, 'SPLIT question (11:10 Power BI)', { lines: ['So when it comes to Power BI, right,', { pause: 1100 }, 'can you share a project where you built Power BI solutions, and how you structured it?'] });
  check(r.ids.length === 1, `one card, not ${r.ids.length}`);
  check(r.detected.length && r.detected.every(d => d._t >= r.askEndT), 'nothing answered before the question finished');
  check(r.detected.length && /share|project/i.test(r.detected[0].text), 'the card is the full question');
  }

  if (run(2)) {
  // 2. Statements and an announced question: no card at all.
  r = await scenario(sess, 'STATEMENTS (11:02, 11:22)', { lines: ['Build datasets, helping them build dashboards, helping them really automate a lot of the manual tasks that they do. Right?', 'I know we are running close to the thirty minute mark. I do have one question I wanted to ask you.'], waitMs: 7000 });
  check(r.ids.length === 0, `no card for statements (got ${r.ids.length})`);
  }

  if (run(3)) {
  // 3. One turn with a follow-up tag → one card.
  r = await scenario(sess, 'ONE TURN, follow-up tag (11:19)', { lines: ['How do you handle conflicting priorities?', { pause: 400 }, 'Right? Just give me an example of how you handled it when two regions both said theirs was the most urgent.'], click: true });
  check(r.ids.length === 1, `one card, not ${r.ids.length}`);
  check(r.detected.filter(d => d.source !== 'manual').every(d => d._t >= r.askEndT), 'nothing answered before the turn finished');
  const ci3 = r.got.findIndex(m => m.type === 'CLICK'), after3 = r.got.slice(ci3 + 1).filter(m => ['match', 'new_question'].includes(m.type));
  check(after3.length && after3.every(m => m.type === 'match' && m.questionId === r.ids[0]), 'Say on the updated card stays on it');
  }

  if (run(4)) {
  // 4. Stale: after the candidate answered card 1, a related NEW question must get its own answer, not card 1.
  r = await scenario(await seed(), 'STALE re-use (11:19:59)', { lines: ['Have you come across situations where several teams sent you conflicting priorities, and how did you solve them?', { you: 'Yes. At Northwind I ranked the requests by business impact and agreed the order with each manager, then I shared the plan every Monday.' }, 'Okay. When the APAC team says their project is the most urgent, how would you decide what to build first?'], waitMs: 11000 });
  check(r.ids.length === 2, `two different cards (got ${r.ids.length})`);
  const lastQ = r.detected[r.detected.length - 1];
  check(lastQ && /decide|build first/i.test(lastQ.text) && lastQ._t >= r.askEndT, `the new question is answered whole, after it finished (got "${lastQ ? lastQ.text.slice(0, 60) : 'none'}")`);
  check(!r.got.some(m => m.type === 'match' && /conflicting priorities/i.test(m.questionText || '') && m._t > r.askEndT - 6000), 'the new question did not re-show the old priorities card');
  }

  if (run(5)) {
  // 5. Say after the interviewer moved on with something that is not shaped like a question (no auto card): the press
  //    must answer THAT, not jump back to the old card (11:16–11:23 presses).
  r = await scenario(sess, 'SAY after they moved on', { lines: ['How would you handle a missed deadline on a client report?', { you: 'I would tell the client early and agree a new date with them.' }, 'We have been struggling with data quality in our warehouse feeds lately.'], click: true, waitMs: 9000 });
  const ci = r.got.findIndex(m => m.type === 'CLICK');
  const firstAfter = r.got.slice(ci + 1).find(m => ['match', 'new_question', 'live_answer'].includes(m.type));
  check(!firstAfter || !/deadline/i.test(firstAfter.questionText || ''), `Say did not bring back the old deadline card (first: "${firstAfter ? (firstAfter.questionText || '').slice(0, 50) : 'nothing'}")`);
  check(r.got.slice(ci + 1).some(m => ['match', 'new_question', 'live_answer'].includes(m.type) && /quality|warehouse/i.test(m.questionText || '')), 'the data-quality point is answered');
  }

  if (run(6)) {
  // 6. Say when the latest question is already answered and nothing new was asked — even a long answer later (> 90 s):
  //    stay on that card, nothing rewritten, no second card.
  r = await scenario(await seed(), 'SAY, already answered, long answer', { lines: ['How would you handle a missed deadline on a client report?', { you: 'I would tell the client early and agree a new date with them.' }, { pause: 95000 }], click: true, waitMs: 8000 });
  const cardIds = [...new Set(r.got.filter(m => m.type === 'new_question').map(m => m.questionId))];
  const ci6 = r.got.findIndex(m => m.type === 'CLICK');
  const after6 = r.got.slice(ci6 + 1).filter(m => ['match', 'new_question', 'live_answer', 'question_detected'].includes(m.type));
  check(cardIds.length === 1, `one card before the press (got ${cardIds.length})`);
  check(after6.length && after6[0].type === 'match' && after6[0].questionId === cardIds[0], `Say stayed on the answered card (first: ${after6[0] ? after6[0].type : 'nothing'})`);
  check(!after6.some(m => m.type === 'new_question' || (m.type === 'live_answer' && m.questionId === cardIds[0])), 'nothing rewritten, no new card');
  }

  if (run(7)) {
  // 7. The card is updated after it appeared (second part of the question a moment later), then Say: stay on that card.
  r = await scenario(await seed(), 'SAY on a card updated after it appeared', { lines: ['Tell me about a dashboard you built for a sales team?', { pause: 2500 }, 'And what tools did you use for it, and who used it every week?'], click: true, waitMs: 9000 });
  const ci7 = r.got.findIndex(m => m.type === 'CLICK');
  const cards7 = [...new Set(r.got.slice(0, ci7).filter(m => m.type === 'new_question').map(m => m.questionId))];
  const after7 = r.got.slice(ci7 + 1).filter(m => ['match', 'new_question'].includes(m.type));
  check(cards7.length === 1, `the second part updated the first card, no second card (got ${cards7.length})`);
  check(after7.length && after7.every(m => m.type === 'match' && m.questionId === cards7[cards7.length - 1]), `Say stayed on the latest card (cards before press: ${cards7.length})`);
  check(!r.got.slice(ci7 + 1).some(m => m.type === 'question_detected' && m.source === 'manual' && r.got.slice(ci7 + 1).some(x => x.type === 'new_question')), 'no new card from the press');
  }

  // 8–12. Say pressed WHILE the interviewer is still asking (owner, 23 Oct: "I detect the question and can not wait"). The press
  //    answers at once from what was said so far; when they finish, the automatic side adds the rest to the SAME card
  //    (lines on screen stay, 1–2 added). The ending ("…on their phones?") is not spoken at the press, so it must arrive by growing.
  const DASH = 'Can you walk me through how you would build a dashboard that tracks weekly sales by region, and how you would make it work for managers who open it on their phones?';
  const OLD = ['How would you handle a missed deadline on a client report?', { you: 'I would tell the client early and agree a new date with them.' }];
  const midPress = (r, label, { topic = /dashboard|sales/i, windowMs = Infinity, early = false } = {}) => {
    const ci = r.got.findIndex(m => m.type === 'CLICK');
    const post = r.got.slice(ci + 1).filter(m => ['match', 'new_question', 'live_answer'].includes(m.type) && m._t < r.askEndT + windowMs);
    const ids = [...new Set(post.map(m => m.questionId))];
    const first = post[0];
    const firstAns = post.filter(m => m.type === 'live_answer' && !m.grew && m.answer)[0];
    const grown = post.filter(m => m.type === 'live_answer' && m.grew).pop();
    const askEnd = r.askEndT, pressT = r.got[ci]._t;
    console.log(`  timing: press ${Math.round(askEnd - pressT)} ms before they finished; card ${first ? first._t - pressT : '-'} ms after press; answer ${firstAns ? firstAns._t - pressT : '-'} ms after press; grew ${grown ? Math.round(grown._t - askEnd) + ' ms after they finished' : 'never'}`);
    check(first && first._t < askEnd, `${label}: answered while they were still asking (proactive)`);
    check(first && !/deadline/i.test(first.questionText || '') && (early || topic.test(first.questionText || '')), `${label}: the card is the question being asked, not the old card (got "${first ? (first.questionText || '').slice(0, 60) : 'nothing'}")`);
    check(ids.length === 1, `${label}: one card only (got ${ids.length})`);
    check(!!grown, `${label}: when they finished, the rest was added to that card`);
    check(grown && firstAns && grown.answer.startsWith(firstAns.answer.trim().slice(0, 120)), `${label}: lines already on screen stayed the same`);
    check(grown && /phone|mobile/i.test(grown.answer), `${label}: the added part answers the end of the question (phones)`);
    check(grown && topic.test(grown.questionText || '') && /phone/i.test(grown.questionText || ''), `${label}: the card's title is now the whole question (got "${grown ? (grown.questionText || '').slice(-50) : 'none'}")`);
    return { ids, grown };
  };

  if (run(8)) { // pressed 60% in, an older answered card on screen
    r = await scenario(await seed(), 'SAY pressed mid-question (60%)', { lines: [...OLD, DASH], clickAt: 0.6, waitMs: 15000 });
    midPress(r, '60%');
  }
  if (run(9)) { // pressed early — only "Can you walk me through how you would build a dashboard" heard
    r = await scenario(await seed(), 'SAY pressed early (35%)', { lines: [...OLD, DASH], clickAt: 0.35, waitMs: 15000 });
    midPress(r, '35%', { early: true }); // only "…how you would build a" heard — the title may be half until they finish
  }
  if (run(10)) { // pressed near the end — they finish while the press is still reading the question
    r = await scenario(await seed(), 'SAY pressed near the end (92%)', { lines: [...OLD, DASH], clickAt: 0.92, waitMs: 15000 });
    const ci = r.got.findIndex(m => m.type === 'CLICK');
    const post = r.got.slice(ci + 1).filter(m => ['match', 'new_question', 'live_answer'].includes(m.type));
    const ids = [...new Set(post.map(m => m.questionId))];
    const last = post.filter(m => m.type === 'live_answer' && m.answer).pop();
    check(post[0] && !/deadline/i.test(post[0].questionText || ''), `92%: not the old card (got "${post[0] ? (post[0].questionText || '').slice(0, 60) : 'nothing'}")`);
    check(ids.length === 1, `92%: one card only (got ${ids.length})`);
    check(last && /phone|mobile/i.test(last.answer), '92%: the answer covers the whole question (phones)');
  }
  if (run(13)) { // pressed the moment they finish — before the automatic side answers it: still ONE card, the whole question
    r = await scenario(await seed(), 'SAY pressed as they finish', { lines: [...OLD, DASH], clickAt: 0.995, waitMs: 15000 });
    const ci = r.got.findIndex(m => m.type === 'CLICK');
    const post = r.got.slice(ci + 1).filter(m => ['match', 'new_question', 'live_answer'].includes(m.type));
    const ids = [...new Set(post.map(m => m.questionId))];
    const last = post.filter(m => m.type === 'live_answer' && m.answer).pop();
    check(post[0] && !/deadline/i.test(post[0].questionText || ''), `as they finish: not the old card (got "${post[0] ? (post[0].questionText || '').slice(0, 60) : 'nothing'}")`);
    check(ids.length === 1, `as they finish: one card only (got ${ids.length})`);
    check(last && /phone|mobile/i.test(last.answer), 'as they finish: the answer covers the whole question (phones)');
  }
  if (run(11)) { // first question of the call — no card on screen yet
    r = await scenario(await seed(), 'SAY pressed mid-question, first question of the call', { lines: [DASH], clickAt: 0.6, waitMs: 15000 });
    midPress(r, 'first question');
  }
  if (run(12)) { // press mid-question, card grows; the candidate answers; then a NEW question → its own card, not grown into the press card
    r = await scenario(await seed(), 'SAY mid-question, then a new question later', { lines: [...OLD, { ask: DASH, pressAt: 0.6 }, { you: 'I would build it in Power BI with one page per region and a mobile layout for the managers.' }, 'Okay. How do you make sure the numbers on it are correct before the managers see them?'], waitMs: 12000 });
    const { ids } = midPress(r, 'then new question', { windowMs: 6000 });
    const lastQ = r.got.filter(m => m.type === 'new_question').pop();
    check(lastQ && !ids.includes(lastQ.questionId) && /correct|numbers|accura/i.test(lastQ.questionText || ''), `the later question got its own card (got "${lastQ ? (lastQ.questionText || '').slice(0, 60) : 'none'}")`);
  }

  await pool.end();
  console.log(fails.length ? `\n${fails.length} FAILED` : '\nALL PASS');
  process.exit(fails.length ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
