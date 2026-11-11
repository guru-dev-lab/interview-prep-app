// Live call 10 Nov: one long 4-part question, SAY pressed early and again while they were still asking → THREE cards in
// 20 s (the first half, a sub-part, then the whole question again as its own card). One question = one card.
// Real server + real Deepgram + Haiku, spoken with macOS `say`, streamed like Electron. Reuses the note-leads local user.
// Usage: node test/say-twice-e2e.js [baseUrl]   (LOCAL DATABASE_URL only; server with MUSTHAVE_PREBUILD=0)
require('dotenv').config();
const { execFileSync } = require('child_process'); const fs = require('fs'), os = require('os'), path = require('path');
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3997';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL }); const sleep = ms => new Promise(r => setTimeout(r, ms));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-st-'));
const speech = t => { const a = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), w = a.replace('.aiff', '.wav'); execFileSync('say', ['-v', 'Samantha', '-o', a, t]); execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', a, w]); const b = fs.readFileSync(w); return b.slice(b.indexOf('data') + 8); };
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
// [line, press SAY at this fraction of it (or null)]
const PARTS = [
  ["That's wonderful, thank you so much. And could you describe a time when you've applied statistical analysis or specific research methods to investigate a program related question,", 0.75],
  ['to help a program identify trends or assess outcomes.', null],
  ['Again, kind of how did you determine which analytical methods were appropriate?', null],
  ['What did your findings reveal, and then how did you account for any limitations in that data?', 0.5],
];
(async () => {
  const u = (await pool.query("SELECT * FROM users WHERE email = 'note-leads@local.test'")).rows[0];
  if (!u) { console.error('Run test/note-leads-live.js once first (it makes the reused local user)'); process.exit(2); }
  const s = (await pool.query('SELECT id FROM sessions WHERE user_id = $1 LIMIT 1', [u.id])).rows[0];
  await pool.query('DELETE FROM questions WHERE session_id = $1', [s.id]); // no cards from an earlier run to match
  const token = jwt.sign({ userId: u.id, name: 'NL', email: u.email, plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const got = []; const t0 = Date.now();
  ws.on('message', d => { try { const m = JSON.parse(d); if (!/transcript/.test(m.type)) { m._t = Date.now() - t0; got.push(m); } } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  const chunks = [silence(500)], presses = [];
  let n = chunks[0].length;
  for (const [line, at] of PARTS) { const a = speech(line); if (at !== null) presses.push(n + Math.round(a.length * at)); chunks.push(a, silence(650)); n += a.length + silence(650).length; }
  const c1 = Buffer.concat([...chunks, silence(12000)]);
  for (let o = 0; o < c1.length; o += 3200) {
    if (presses.length && o >= presses[0]) { presses.shift(); got.push({ type: 'PRESS', _t: Date.now() - t0 }); ws.send(JSON.stringify({ type: 'what_should_i_say' })); }
    ws.send(Buffer.concat([Buffer.from([1]), c1.slice(o, o + 3200)]));
    ws.send(Buffer.concat([Buffer.from([2]), silence(100).slice(0, Math.min(3200, c1.length - o))]));
    await sleep(100);
  }
  await sleep(4000); ws.close();
  for (const m of got.filter(m => ['PRESS', 'new_question', 'match', 'question_title'].includes(m.type))) console.log(`  ${String(m._t).padStart(6)} ms  ${m.type.padEnd(15)} ${(m.questionText || '').slice(0, 100)}`);
  const cards = [...new Set(got.filter(m => m.type === 'new_question' || m.type === 'match').map(m => m.questionId))];
  const last = [...got].reverse().find(m => m.type === 'live_answer' && m.answer);
  console.log('  final answer:\n' + String(last ? last.answer : '(none)').split('\n').map(l => '    ' + l).join('\n'));
  const ok = cards.length === 1;
  console.log(ok ? 'PASS one question = one card' : `FAIL ${cards.length} cards for one question`);
  await pool.end(); process.exit(ok ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
