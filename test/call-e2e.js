// REAL CALLS: whole interviews as ONE continuous call (owner, 27 Oct: "we pause after each question.. nooo"). Every turn is
// spoken by ElevenLabs v4 (cached), turns run back to back with natural gaps and cut-ins, the candidate answers at length on
// his mic (and leaks into the call audio when the call says laptop speakers). Streamed in real time, like Electron.
// Each interviewer turn is scored: caught, the card IS that question, the prepared card for a reworded one, no card for small
// talk / pitch / setups, Say presses answer the question being asked, and no jump back to an older card.
//
//   node test/call-e2e.js [http://localhost:3999] [--only call-1] [--export]
//   --export also writes the whole call as test/stress/audio/calls/<id>.m4a (to play out loud into the desktop app)
// LOCAL DATABASE_URL only. Run the server like production (semantic matching on), MUSTHAVE_PREBUILD=0.
require('dotenv').config();
const { execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { CALLS } = require('./stress/calls');
const { PREPARED } = require('./stress/bank');
const voice = require('./stress/voice');

const args = process.argv.slice(2);
const BASE = args.find(a => /^https?:/.test(a)) || 'http://localhost:3999';
const opt = n => { const i = args.indexOf('--' + n); return i < 0 ? null : (args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : true); };
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const MODEL = 'eleven_v4';
const CARD_MS = +process.env.CALL_CARD_MS || 4500; // they finish asking → the card is on screen
const SAY_MS = +process.env.CALL_SAY_MS || 1500;   // Say pressed → a card
const CARD = ['new_question', 'match', 'live_answer'];
const sleep = ms => new Promise(r => setTimeout(r, ms));
const B = ms => Math.round(16 * ms) * 2; // ms → bytes (16 kHz, 16-bit mono)

async function seed(tag) {
  const email = 'call-' + tag + '-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6) + '@local.test';
  const u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Call Tester','premium') RETURNING *", [email])).rows[0];
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1,'Northwind Logistics','Senior BI Developer','Senior BI developer, 6 years. SQL Server, Power BI, DAX, Python, dbt, Azure, Fabric. Contoso: sales and finance reporting; row level security for 300 managers; automated month-end reconciliation (2 days → 2 hours).') RETURNING id", [u.id])).rows[0];
  for (const [t, a] of PREPARED) await pool.query('INSERT INTO questions (session_id, text, answer) VALUES ($1,$2,$3)', [s.id, t, a]);
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '2h' });
  return { token, sessionId: s.id };
}

// Lay the call out on one timeline: ch1 = the call (interviewers, + his voice leaking when echo), ch2 = his mic.
async function build(call) {
  const turns = []; let cursor = 600, prev = null;
  for (const [i, tr] of call.turns.entries()) {
    const slot = tr.s === 'you' ? 'you' : call.voices[tr.s];
    const pcm = await voice.pcm(slot, tr.t, MODEL);
    const durMs = pcm.length / 32;
    // natural gaps, no fixed pause: answer after a question ~0.5–1.1 s, same speaker going on ~0.3 s, a reply ~0.4–0.9 s
    const natural = !prev ? 0 : prev.s === tr.s ? 300 : tr.s === 'you' ? 500 + (i * 211) % 600 : 400 + (i * 137) % 500;
    const start = Math.max(0, (prev ? prev.end : cursor) + (tr.gap != null ? tr.gap : natural));
    const t = { ...tr, i, slot, pcm, start, end: start + durMs };
    turns.push(t); prev = t;
  }
  const total = Math.ceil(Math.max(...turns.map(t => t.end)) + 9000);
  const ch1 = Buffer.alloc(B(total)), ch2 = Buffer.alloc(B(total));
  const mix = (dst, src, atMs, gain = 1) => { const o = B(atMs); for (let k = 0; k + 1 < src.length && o + k + 1 < dst.length; k += 2) { const v = dst.readInt16LE(o + k) + Math.round(src.readInt16LE(k) * gain); dst.writeInt16LE(Math.max(-32768, Math.min(32767, v)), o + k); } };
  // --speakers = his real setup (owner 27 Oct: "i normally just use the speaker"): the interviewer comes out of the laptop
  // speakers into his mic, louder than the captured call audio, and the mic hears it FIRST (the Mac captures its own output
  // late) — live log 27 Oct: mic led by 8–379 ms, mic 1.5× louder. Zoom never plays his own voice back: his turns are mic only.
  const speakers = !!opt('speakers');
  for (const t of turns) {
    if (t.s === 'you') { mix(ch2, t.pcm, t.start); if (call.echo && !speakers) mix(ch1, t.pcm, t.start + 500, 0.35); /* far-end echo: ~0.5 s late, quiet */ }
    else if (speakers) { mix(ch2, t.pcm, t.start, 1.5); mix(ch1, t.pcm, t.start + 50 + (t.i * 97) % 300); }
    else mix(ch1, t.pcm, t.start);
  }
  return { turns, ch1, ch2, total };
}

function exportCall(call, ch1, ch2) {
  const dir = path.join(__dirname, 'stress/audio/calls'); fs.mkdirSync(dir, { recursive: true });
  const both = Buffer.alloc(ch1.length);
  for (let k = 0; k < both.length; k += 2) both.writeInt16LE(Math.max(-32768, Math.min(32767, ch1.readInt16LE(k) + ch2.readInt16LE(k))), k);
  const hdr = Buffer.alloc(44); hdr.write('RIFF', 0); hdr.writeUInt32LE(36 + both.length, 4); hdr.write('WAVEfmt ', 8); hdr.writeUInt32LE(16, 16); hdr.writeUInt16LE(1, 20); hdr.writeUInt16LE(1, 22); hdr.writeUInt32LE(16000, 24); hdr.writeUInt32LE(32000, 28); hdr.writeUInt16LE(2, 32); hdr.writeUInt16LE(16, 34); hdr.write('data', 36); hdr.writeUInt32LE(both.length, 40);
  const wav = path.join(os.tmpdir(), call.id + '.wav'), out = path.join(dir, call.id + '.m4a');
  fs.writeFileSync(wav, Buffer.concat([hdr, both])); execFileSync('afconvert', ['-f', 'm4af', '-d', 'aac', wav, out]); fs.rmSync(wav);
  return out;
}

async function play(call) {
  const { turns, ch1, ch2, total } = await build(call);
  if (opt('export')) console.log('  exported:', exportCall(call, ch1, ch2));
  const sess = await seed(call.id);
  const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
  const got = [];
  const mics = []; // his mic lines as the server judged them (bleed = the interviewer heard through his mic)
  ws.on('message', d => { try { const m = JSON.parse(d); if (m.type === 'user_transcript') { m._t = Date.now(); mics.push(m); } if (/transcript/.test(m.type)) return; m._t = Date.now(); got.push(m); } catch (e) {} });
  await new Promise((r, j) => { ws.on('open', r); ws.on('error', j); });
  ws.send(JSON.stringify({ type: 'start', token: sess.token, sessionId: sess.sessionId, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  const presses = turns.filter(t => t.press != null).map(t => ({ t, at: t.press === 'after' ? t.end + 300 : t.start + (t.end - t.start) * t.press }));
  const t0 = Date.now();
  for (let o = 0; o < ch1.length; o += 3200) {
    const nowMs = o / 32;
    for (const p of presses) if (!p.sent && nowMs >= p.at) { p.sent = Date.now(); got.push({ type: 'PRESS', _t: p.sent, turn: p.t.i }); ws.send(JSON.stringify({ type: 'what_should_i_say' })); }
    ws.send(Buffer.concat([Buffer.from([1]), ch1.slice(o, o + 3200)]));
    ws.send(Buffer.concat([Buffer.from([2]), ch2.slice(o, o + 3200)]));
    const due = t0 + (o + 3200) / 32; const wait = due - Date.now(); if (wait > 0) await sleep(wait); // real time, no drift
  }
  ws.close();
  const wall = ms => t0 + ms; // audio time → wall clock
  for (const t of turns) { t.startT = wall(t.start); t.endT = wall(t.end); }
  for (const p of presses) p.t.pressT = p.sent;
  return { turns, got, total, mics };
}

function score(call, { turns, got }) {
  const asks = turns.filter(t => t.s !== 'you' && (t.q || t.card));
  const cardEvts = got.filter(m => CARD.includes(m.type));
  const firstSeen = new Map(); for (const m of cardEvts) if (!firstSeen.has(m.questionId)) firstSeen.set(m.questionId, m);
  const res = [];
  for (const t of turns) {
    if (t.s === 'you' || !(t.q || t.card || t.none)) continue;
    const why = [], ms = {}; const fail = w => why.push(w);
    const nextAsk = asks.find(a => a.i > t.i);
    const until = Math.min(nextAsk ? nextAsk.endT : Infinity, t.endT + 12000);
    const inWin = cardEvts.filter(m => m._t >= t.startT && m._t <= until);
    if (t.q || t.card) {
      const want = t.q || t.card;
      const hit = inWin.find(m => want.test(m.questionText || ''));
      if (!hit) fail(`missed: ${inWin.length ? 'cards were "' + [...new Set(inWin.map(m => (m.questionText || '').slice(0, 50)))].join('", "') + '"' : 'no card'}`);
      else {
        // the same interviewer carrying straight on ("…priorities? Right? Just give me an example…") is one turn: the card
        // comes when they stop
        let end = t.endT; for (let k = t.i + 1; k < turns.length && turns[k].s === t.s && !turns[k].q && !turns[k].none && turns[k].start - turns[k - 1].end <= 600; k++) end = turns[k].endT;
        ms.card = Math.round(hit._t - end);
        if (t.card && hit.type !== 'match') fail('fresh answer, not the prepared card');
        if (!t.pressT && ms.card > CARD_MS) fail(`late: ${ms.card} ms`);
      }
      if (t.pressT) {
        const after = got.filter(m => m._t >= t.pressT && CARD.includes(m.type)), c = after[0];
        if (c) ms.say = c._t - t.pressT;
        if (!c) fail('Say did nothing');
        else if (!want.test(c.questionText || '') && !(t.press !== 'after' && c._t < t.endT)) fail(`Say showed "${(c.questionText || '').slice(0, 50)}"`);
        if (c && ms.say > SAY_MS) fail(`Say slow: ${ms.say} ms`);
      }
      // an answer for THIS question appearing before they finished, when nobody pressed, is the "answered early" bug
      if (!t.pressT) { const early = got.find(m => m.type === 'question_detected' && m._t >= t.startT && m._t < t.endT - 300); if (early) fail(`answered before they finished: "${(early.text || '').slice(0, 50)}"`); }
    } else if (t.none) {
      const fresh = [...firstSeen.values()].filter(m => m._t >= t.startT && m._t <= t.endT + 4000);
      if (fresh.length) fail(`card for small talk: "${(fresh[0].questionText || '').slice(0, 60)}"`);
    }
    // stale: after this turn starts, a JUMP (match) to a card of an EARLIER asked question that is not this one
    const older = asks.filter(a => a.i < t.i && a.q && !(t.q && t.q.source === a.q.source));
    const stale = got.find(m => m.type === 'match' && m._t >= t.startT + 500 && m._t <= t.endT + 4000 && !(t.q && t.q.test(m.questionText || '')) && older.some(a => a.q.test(m.questionText || '')) && !got.some(p => p.type === 'PRESS' && Math.abs(p._t - m._t) < 300));
    if (stale) fail(`jumped back to an older card: "${(stale.questionText || '').slice(0, 50)}"`);
    res.push({ i: t.i, s: t.s, kind: t.q ? 'ask' : t.card ? 'prepared' : 'none', text: t.t.replace(/\[[^\]]+\]\s*/g, ''), pass: !why.length, why, ms });
  }
  return res;
}

const pct = (a, p) => { const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };

(async () => {
  const pick = CALLS.filter(c => !opt('only') || String(opt('only')).split(',').includes(c.id));
  console.log(`REAL CALLS: ${pick.length} continuous interview(s), ElevenLabs ${MODEL}, server ${BASE}`);
  const out = [];
  await Promise.all(pick.map(async call => { // the calls run side by side, like several users at once
    const r = await play(call); const res = score(call, r);
    // the note greys the lines HE said: a mic line taken as his while only the interviewer was talking greys the wrong lines
    const youSpans = r.turns.filter(t => t.s === 'you').map(t => [t.startT - 500, t.endT + 2500]);
    const wrongMine = r.mics.filter(m => !m.bleed && !youSpans.some(([a, b]) => m._t >= a && m._t <= b));
    const lostMine = r.mics.filter(m => m.bleed && youSpans.some(([a, b]) => m._t >= a + 500 && m._t <= b - 2000)); // his own words marked as the interviewer
    out.push({ call, res, mins: (r.total / 60000).toFixed(1), wrongMine: wrongMine.map(m => m.text.slice(0, 60)), lostMine: lostMine.map(m => m.text.slice(0, 60)), micMine: r.mics.filter(m => !m.bleed).length });
  }));
  let fails = 0; const cardMs = [], sayMs = [];
  for (const { call, res, mins } of out) {
    console.log(`\n### ${call.id} — ${call.title} (${mins} min)`);
    const o = out.find(x => x.call === call); console.log(`  mic lines taken as HIS while only the interviewer spoke: ${o.wrongMine.length}${o.wrongMine.length ? ' — "' + o.wrongMine.join('" | "') + '"' : ''}`);
    console.log(`  his own lines taken as the interviewer: ${o.lostMine.length}${o.lostMine.length ? ' — "' + o.lostMine.join('" | "') + '"' : ''}`);
    for (const r of res) {
      if (!r.pass) fails++; if (r.ms.card != null && r.kind !== 'none') cardMs.push(r.ms.card); if (r.ms.say != null) sayMs.push(r.ms.say);
      console.log(`  ${r.pass ? 'PASS' : 'FAIL'} #${String(r.i).padStart(2)} ${r.kind.padEnd(8)} ${Object.entries(r.ms).map(([k, v]) => k + ' ' + v + 'ms').join(' ').padEnd(24)} "${r.text.slice(0, 70)}"${r.why.length ? '\n         → ' + r.why.join(' | ') : ''}`);
    }
  }
  const all = out.flatMap(o => o.res);
  console.log('\n== summary');
  for (const k of ['ask', 'prepared', 'none']) { const rs = all.filter(r => r.kind === k); if (rs.length) console.log(`  ${k.padEnd(9)} ${rs.filter(r => r.pass).length}/${rs.length}`); }
  if (cardMs.length) console.log(`  card after they finish: p50 ${pct(cardMs, 0.5)} / p95 ${pct(cardMs, 0.95)} / max ${Math.max(...cardMs)} ms`);
  if (sayMs.length) console.log(`  Say → card:             p50 ${pct(sayMs, 0.5)} / max ${Math.max(...sayMs)} ms`);
  fs.writeFileSync(path.join(__dirname, 'stress/last-call-run.json'), JSON.stringify({ when: new Date().toISOString(), calls: out.map(o => ({ id: o.call.id, turns: o.res })) }, null, 2));
  console.log(fails ? `\n${fails} FAILED of ${all.length}` : `\nALL PASS (${all.length})`);
  await pool.end(); process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
