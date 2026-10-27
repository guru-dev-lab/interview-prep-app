// STRESS: the whole live path under a big bank of real-shaped interview moments, several voices, demo screens,
// several calls at once, every press timed. Real server + real Deepgram + real models; audio streamed like Electron
// (channel 1 = the call, channel 2 = his mic; his voice also leaks into the call, like no headphones).
// The overlay is emulated exactly: question_detected (co-pilot) → POST ask; copilot_say → POST say+pressed.
//
//   node test/stress-e2e.js [http://localhost:3999] [--all | --n 12] [--group ask,mid] [--only ask-03] [--par 3]
//   default: 12 moments picked across every group (spend rule); --all = the whole bank.
// Budgets (ms) can be changed with env: AUTO_CARD, AUTO_WORDS, SAY_CARD, SAY_WORDS, CP_CARD, CP_WORDS.
// LOCAL DATABASE_URL only. Server: MUSTHAVE_PREBUILD=0. Voices: test/stress/voice.js (ElevenLabs, cached).
require('dotenv').config();
const fs = require('fs'), path = require('path');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { SCENARIOS, PREPARED } = require('./stress/bank');
const voice = require('./stress/voice');

const args = process.argv.slice(2);
const BASE = args.find(a => /^https?:/.test(a)) || 'http://localhost:3999';
const opt = n => { const i = args.indexOf('--' + n); return i < 0 ? null : (args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : true); };
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const B = { // what he sees, in ms
  AUTO_CARD: +process.env.AUTO_CARD || 4500,  // they finish asking → the card is on screen
  AUTO_WORDS: +process.env.AUTO_WORDS || 7000, // they finish asking → first words of the answer
  SAY_CARD: +process.env.SAY_CARD || 1500,    // Say pressed → a card
  SAY_WORDS: +process.env.SAY_WORDS || 5000,  // Say pressed → first words
  CP_CARD: +process.env.CP_CARD || 1500,      // co-pilot Say → the card
  CP_WORDS: +process.env.CP_WORDS || 4500,    // co-pilot Say → first words
};
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const scale = (a, k) => { const o = Buffer.alloc(a.length); for (let i = 0; i < a.length; i += 2) o.writeInt16LE(Math.round(a.readInt16LE(i) * k), i); return o; };
const CARD = ['new_question', 'match', 'live_answer'];
const hasWords = m => (m.type === 'live_answer_delta' && m.chunk) || ((m.type === 'live_answer' || m.type === 'match') && m.answer);

// ---- pick what to run ----
let pick = SCENARIOS;
if (opt('group')) pick = pick.filter(s => String(opt('group')).split(',').includes(s.group));
if (opt('only')) pick = pick.filter(s => String(opt('only')).split(',').includes(s.id));
if (!opt('all') && !opt('only')) { // a spread: round-robin across groups
  const n = +opt('n') || 12, byG = {}; for (const s of pick) (byG[s.group] = byG[s.group] || []).push(s);
  const seed = +(process.env.SEED || Date.now() % 1000); for (const g in byG) byG[g] = byG[g].map((s, i) => [((i + 1) * 7919 + seed) % 1009, s]).sort((a, b) => a[0] - b[0]).map(x => x[1]);
  const out = []; for (let i = 0; out.length < Math.min(n, pick.length); i++) for (const g in byG) if (byG[g][i] && out.length < n) out.push(byG[g][i]);
  pick = out;
}
const PAR = Math.max(1, +opt('par') || 3);

async function seed(tag) {
  const email = 'stress-' + tag + '-' + Date.now() + '@local.test';
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Stress Tester','premium') RETURNING *", [email])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1,'Northwind Logistics','Senior BI Developer','Senior BI developer, 6 years. SQL Server, Power BI, DAX, Python, dbt, Azure, Fabric. Built sales and finance reporting at Contoso; row level security for 300 managers; automated month-end reconciliation.') RETURNING id", [u.id])).rows[0];
  for (const [t, a] of PREPARED) await pool.query('INSERT INTO questions (session_id, text, answer) VALUES ($1,$2,$3)', [s.id, t, a]);
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '2h' });
  return { token, sessionId: s.id };
}

async function run(sess, sc) {
  const cp = sc.group === 'copilot';
  const post = async body => { const t = Date.now(); const r = await fetch(BASE + '/api/sessions/' + sess.sessionId + '/copilot', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + sess.token }, body: JSON.stringify(body) }); const j = await r.json().catch(() => ({})); return { status: r.status, j, ms: Date.now() - t }; };
  const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
  const got = [], posts = [];
  let lastAsk = null; // the overlay's own "already answered this" memory (90 s)
  ws.on('message', d => {
    let m; try { m = JSON.parse(d); } catch (e) { return; } if (/transcript/.test(m.type)) return;
    m._t = Date.now(); got.push(m);
    if (!cp) return;
    if (m.type === 'question_detected' && m.text) posts.push(post({ ask: m.text }).then(r => ({ kind: 'heard', ...r })));
    if (m.type === 'copilot_say') {
      const norm = String(m.text || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
      if (norm && lastAsk && lastAsk === norm) { got.push({ type: 'SAY_ALREADY', _t: Date.now() }); return; }
      lastAsk = norm; posts.push(post({ ask: m.text || '', say: true, pressed: true }).then(r => ({ kind: 'say', ...r })));
    }
  });
  await new Promise((r, j) => { ws.on('open', r); ws.on('error', j); });
  ws.send(JSON.stringify({ type: 'start', token: sess.token, sessionId: sess.sessionId, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  if (cp) {
    ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: true })); await sleep(300);
    for (const [i, n] of (sc.screens || []).entries()) await post({ auto: true, image: fs.readFileSync(path.join(__dirname, 'stress/screens', n + '.png')).toString('base64'), screenKey: 'st-' + sc.id + '-' + i + '-' + Date.now() });
  }
  // build both channels
  const ch1 = [silence(500)], ch2 = [silence(500)]; const len1 = () => ch1.reduce((n, b) => n + b.length, 0);
  let askStart = 0, askEnd = 0, pressByte = null;
  for (const l of sc.lines) {
    if (typeof l === 'string' || l.ask || l.t) {
      const a = await voice.pcm(l.t ? l.v : sc.voice, l.ask || l.t || l); askStart = len1(); ch1.push(a); askEnd = len1();
      if (l.pressAt) pressByte = askStart + Math.round(a.length * l.pressAt);
      ch1.push(silence(700)); ch2.push(silence(a.length / 32 + 700));
    } else if (l.pause) { ch1.pop(); ch2.pop(); ch1.push(silence(l.pause)); ch2.push(silence(l.pause)); }
    else if (l.you) { const a = await voice.pcm('you', l.you); ch2.push(a, silence(900)); ch1.push(silence(200), scale(a, 0.5), silence(700)); }
  }
  let c1 = Buffer.concat([...ch1, silence(2500)]), c2 = Buffer.concat(ch2);
  const len = Math.max(c1.length, c2.length);
  c1 = Buffer.concat([c1, Buffer.alloc(len - c1.length)]); c2 = Buffer.concat([c2, Buffer.alloc(len - c2.length)]);
  const t0 = Date.now(); let pressT = null;
  const press = () => { pressT = Date.now(); got.push({ type: 'PRESS', _t: pressT }); ws.send(JSON.stringify({ type: 'what_should_i_say' })); };
  for (let o = 0; o < len; o += 3200) {
    if (pressByte !== null && o >= pressByte && !pressT) press();
    ws.send(Buffer.concat([Buffer.from([1]), c1.slice(o, o + 3200)]));
    ws.send(Buffer.concat([Buffer.from([2]), c2.slice(o, o + 3200)]));
    await sleep(100);
  }
  const askEndT = Math.round(t0 + (askEnd / 32000) * 1000); // the moment the last interviewer line finished
  if (!pressT && (sc.press === 'after' || cp)) { await sleep(300); press(); }
  // wait: until the co-pilot answer is done, else a fixed listen window
  const until = Date.now() + (cp ? 30000 : sc.group === 'mid' ? 15000 : 9000);
  while (Date.now() < until) { if (cp && got.some(m => m.type === 'copilot_done' && m._t > pressT)) break; await sleep(250); }
  const res = await Promise.all(posts); await sleep(cp ? 500 : 0); ws.close();
  return { got, askEndT, pressT, posts: res };
}

// ---- judge one moment: { pass, why[], ms{} } ----
function judge(sc, r) {
  const why = [], ms = {}; const fail = w => why.push(w); const e = sc.expect;
  const { got, askEndT, pressT } = r;
  const cards = got.filter(m => CARD.includes(m.type));
  const ids = [...new Set(cards.map(m => m.questionId))];
  const after = t => got.filter(m => m._t >= t);
  const firstCard = list => list.find(m => CARD.includes(m.type));
  const firstWords = list => list.find(hasWords);
  const growsOnly = id => { // APP-WIDE: what he may be reading only grows, it is never swapped
    const texts = got.filter(m => m.type === 'live_answer' && m.questionId === id && m.answer).map(m => m.answer.trim());
    for (let i = 1; i < texts.length; i++) if (!texts[i].startsWith(texts[i - 1].slice(0, 120))) return false; return true;
  };
  const errs = got.filter(m => m.type === 'error').map(m => m.message); if (errs.length) fail('error shown: ' + errs[0]);
  if (sc.group === 'ask' || sc.group === 'split') {
    const c = firstCard(got), w = firstWords(got);
    if (c) ms.card = c._t - askEndT; if (w) ms.words = w._t - askEndT;
    if (ids.length !== 1) fail(`one card expected, got ${ids.length}`);
    if (!c) fail('no card');
    else if (!e.topic.test(c.questionText || '')) fail(`card is not the question: "${(c.questionText || '').slice(0, 70)}"`);
    if (got.some(m => m.type === 'question_detected' && m._t < askEndT - 250)) fail('answered before they finished');
    if (c && ms.card > B.AUTO_CARD) fail(`card late: ${ms.card} ms`);
    if (w && ms.words > B.AUTO_WORDS) fail(`first words late: ${ms.words} ms`);
    if (c && !w) fail('card but no answer words');
    if (ids[0] && !growsOnly(ids[0])) fail('answer text was swapped (must only grow)');
  } else if (sc.group === 'match') {
    const c = firstCard(got); if (c) ms.card = c._t - askEndT;
    if (!c) fail('no card'); else if (!(c.type === 'match' && e.card.test(c.questionText || ''))) fail(`wrong card: ${c.type} "${(c.questionText || '').slice(0, 60)}"`);
    if (c && ms.card > B.AUTO_CARD) fail(`card late: ${ms.card} ms`);
  } else if (sc.group === 'none') {
    if (cards.length) fail(`a card appeared: "${(cards[0].questionText || '').slice(0, 70)}"`);
  } else if (sc.group === 'mid') {
    const post = after(pressT).filter(m => CARD.includes(m.type)), c = post[0], w = firstWords(after(pressT));
    if (c) ms.card = c._t - pressT; if (w) ms.words = w._t - pressT;
    const pids = [...new Set(post.map(m => m.questionId))];
    const firstAns = post.find(m => m.type === 'live_answer' && !m.grew && m.answer), grown = post.filter(m => m.type === 'live_answer' && m.grew).pop();
    if (!c) fail('Say pressed mid-question: nothing'); else if (!e.topic.test(c.questionText || '')) fail(`card is not this question: "${(c.questionText || '').slice(0, 60)}"`);
    if (pids.length !== 1) fail(`one card expected, got ${pids.length}`);
    if (sc.lines[0].pressAt < 0.9) {
      if (c && c._t >= askEndT) fail('no answer until they finished (should start at the press)');
      if (!grown) fail('the rest of the question was never added'); else {
        if (!e.end.test(grown.answer)) fail('the added part does not answer the end of the question');
        if (firstAns && !grown.answer.startsWith(firstAns.answer.trim().slice(0, 120))) fail('lines on screen changed (must only grow)');
      }
    } else { const last = post.filter(m => m.type === 'live_answer' && m.answer).pop(); if (!last || !e.end.test(last.answer)) fail('the answer misses the end of the question'); }
    if (c && ms.card > B.SAY_CARD) fail(`card late after press: ${ms.card} ms`);
    if (w && ms.words > B.SAY_WORDS) fail(`first words late after press: ${ms.words} ms`);
  } else if (sc.group === 'say') {
    const post = after(pressT), c = firstCard(post), w = firstWords(post);
    if (c) ms.card = c._t - pressT; if (w) ms.words = w._t - pressT;
    if (!c) fail('Say did nothing');
    else if (e.old && e.old.test(c.questionText || '')) fail('Say brought back the OLD card');
    if (!post.some(m => CARD.includes(m.type) && e.topic.test(m.questionText || ''))) fail('Say did not answer the latest thing they said');
    if (c && ms.card > B.SAY_CARD) fail(`card late after press: ${ms.card} ms`);
    if (w && ms.words > B.SAY_WORDS) fail(`first words late after press: ${ms.words} ms`);
  } else if (sc.group === 'stale') {
    const last = got.filter(m => m.type === 'new_question').pop();
    if (ids.length < 2) fail(`the new question needs its own card (cards: ${ids.length})`);
    if (!last || !e.topic.test(last.questionText || '')) fail(`latest card is not the new question: "${last ? (last.questionText || '').slice(0, 60) : 'none'}"`);
    if (got.some(m => m.type === 'match' && e.old.test(m.questionText || '') && m._t > askEndT - 6000)) fail('the old card came back');
    const c = last && got.find(m => m.questionId === last.questionId); if (c) ms.card = c._t - askEndT;
    if (c && ms.card > B.AUTO_CARD) fail(`card late: ${ms.card} ms`);
  } else if (sc.group === 'copilot') {
    const say = got.find(m => m.type === 'copilot_say' && m._t >= pressT), sp = r.posts.find(p => p.kind === 'say');
    const already = got.some(m => m.type === 'SAY_ALREADY');
    const st = got.find(m => m.type === 'copilot_start' && m._t >= pressT), d = got.find(m => m.type === 'copilot_delta' && m._t >= pressT);
    const heard = r.posts.find(p => p.kind === 'heard'); // the question was already being answered by itself when he pressed
    if (say) ms.say = say._t - pressT; if (st) ms.card = st._t - pressT; if (d) ms.words = d._t - pressT;
    if (!say) fail('Say got no reply from the server');
    else if (!e.say.test(say.text || '')) fail(`Say did not use their last question: "${(say.text || '').slice(0, 80)}"`);
    const ans = (sp && sp.j && sp.j.answer) || (heard && heard.j && heard.j.answer) || '';
    if (!already && !st && !heard) fail('no answer card');
    if (!already && st && ms.card > B.CP_CARD) fail(`card late: ${ms.card} ms`);
    if (!already && d && ms.words > B.CP_WORDS) fail(`first words late: ${ms.words} ms`);
    if (!ans) fail('empty answer' + (sp && sp.j && sp.j.error ? ': ' + sp.j.error : ''));
    else if (!e.want.test(ans)) fail('answer missed the screen: ' + ans.replace(/\s+/g, ' ').slice(0, 100));
    if (sp && sp.status !== 200) fail('HTTP ' + sp.status);
  }
  return { pass: !why.length, why, ms };
}

const pct = (a, p) => { if (!a.length) return '-'; const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };

(async () => {
  console.log(`STRESS: ${pick.length} moments (${[...new Set(pick.map(s => s.group))].join(', ')}), ${PAR} calls at once, server ${BASE}`);
  console.log(`budgets: card ${B.AUTO_CARD} / words ${B.AUTO_WORDS} after they finish; Say card ${B.SAY_CARD} / words ${B.SAY_WORDS}; co-pilot ${B.CP_CARD} / ${B.CP_WORDS}`);
  const queue = [...pick], results = [];
  const worker = async w => {
    const sess = await seed('w' + w);
    while (queue.length) {
      const sc = queue.shift();
      try {
        // copilot and match moments get a fresh session so an earlier moment cannot answer for them
        const r = await run(sc.group === 'copilot' || sc.group === 'match' ? await seed('w' + w + sc.id) : sess, sc);
        const j = judge(sc, r); results.push({ id: sc.id, group: sc.group, ...j });
        console.log(`${j.pass ? 'PASS' : 'FAIL'} ${sc.id.padEnd(11)} ${Object.entries(j.ms).map(([k, v]) => k + ' ' + v + 'ms').join('  ').padEnd(38)} ${j.why.join(' | ')}`);
      } catch (e) { results.push({ id: sc.id, group: sc.group, pass: false, why: ['crashed: ' + e.message], ms: {} }); console.log(`FAIL ${sc.id} crashed: ${e.message}`); }
    }
  };
  await Promise.all(Array.from({ length: PAR }, (_, i) => worker(i + 1)));
  // summary
  console.log('\n== by group');
  for (const g of [...new Set(results.map(r => r.group))]) { const rs = results.filter(r => r.group === g); console.log(`  ${g.padEnd(8)} ${rs.filter(r => r.pass).length}/${rs.length}`); }
  console.log('== timing (ms): p50 / p95 / max');
  for (const [label, gs, k] of [['card after they finish', ['ask', 'split', 'match', 'stale'], 'card'], ['first words after they finish', ['ask', 'split'], 'words'],
    ['Say → card', ['say', 'mid'], 'card'], ['Say → first words', ['say', 'mid'], 'words'], ['co-pilot Say → card', ['copilot'], 'card'], ['co-pilot Say → first words', ['copilot'], 'words']]) {
    const v = results.filter(r => gs.includes(r.group) && r.ms[k] != null).map(r => r.ms[k]);
    if (v.length) console.log(`  ${label.padEnd(30)} ${pct(v, 0.5)} / ${pct(v, 0.95)} / ${Math.max(...v)}   (${v.length})`);
  }
  if (voice.used.mac) console.log(`note: ${voice.used.mac} lines used the Mac voice (no saved ElevenLabs audio; run node test/stress/voice.js --build)`);
  fs.writeFileSync(path.join(__dirname, 'stress/last-run.json'), JSON.stringify({ when: new Date().toISOString(), base: BASE, budgets: B, results }, null, 2));
  const fails = results.filter(r => !r.pass).length;
  console.log(fails ? `\n${fails} FAILED of ${results.length}` : `\nALL PASS (${results.length})`);
  await pool.end(); process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
