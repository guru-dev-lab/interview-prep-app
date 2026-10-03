// Meeting co-pilot end to end: real server, real Deepgram, real Haiku/Sonnet, ONE reused local session.
// Proves: live-only call log written from the real audio path (you + them), co-pilot mode routes a detected
// question to co-pilot (no Q&A card), regular answer in the Asked/On screen/Say shape citing the table, no-image
// turn reuses the last screen summary, smart mode compacts and stays consistent with what YOU said.
// Usage: node test/meeting-copilot-e2e.js [http://localhost:3999] <server log path>
//   (LOCAL DATABASE_URL only; server with MUSTHAVE_PREBUILD=0 SEMANTIC_MATCH=0)
require('dotenv').config();
const fs = require('fs'), os = require('os'), path = require('path');
const { execFileSync } = require('child_process');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');

const BASE = process.argv[2] || 'http://localhost:3999';
const LOG = process.argv[3];
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
if (!LOG || !fs.existsSync(LOG)) { console.error('Pass the server log path'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-mc-'));
function speech(text, voice) {
  const aiff = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), wav = aiff.replace('.aiff', '.wav');
  execFileSync('say', ['-v', voice || 'Samantha', '-o', aiff, text]);
  execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', aiff, wav]);
  const b = fs.readFileSync(wav); const i = b.indexOf('data'); return b.slice(i + 8);
}
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
let pass = 0, fail = 0;
const check = (ok, label, detail) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + label + (detail && !ok ? '\n     ' + String(detail).replace(/\n/g, '\n     ').slice(0, 900) : '')); };
const logSince = mark => fs.readFileSync(LOG, 'utf8').slice(mark);

(async () => {
  const email = 'screen-e2e@local.test';
  let u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Screen Tester','pro') RETURNING *", [email])).rows[0];
  let s = (await pool.query('SELECT id FROM sessions WHERE user_id=$1 LIMIT 1', [u.id])).rows[0];
  if (!s) s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1,'Acme Analytics','Data Analyst','Data analyst.') RETURNING id", [u.id])).rows[0];
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'pro', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const shot = 'data:image/png;base64,' + fs.readFileSync(path.join(__dirname, 'fixtures/screens/meeting-table.png')).toString('base64');
  const rowsNow = async () => (await pool.query('SELECT kind, text, ts FROM call_events WHERE session_id=$1 ORDER BY ts', [s.id])).rows;
  const copilot = async body => {
    const r = await fetch(BASE + '/api/sessions/' + s.id + '/copilot', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify(body) });
    let j = {}; try { j = await r.json(); } catch (e) {}
    console.log(`  · copilot ${JSON.stringify(Object.assign({}, body, { image: body.image ? '<img>' : null })).slice(0, 90)} → ${r.status} | ${(j.answer || j.error || '').replace(/\n/g, ' ⏎ ').slice(0, 160)}`);
    return { r, j };
  };

  // 0. Not live → refused, nothing logged
  const before = (await rowsNow()).length;
  let res = await copilot({ ask: 'what does row 12 mean?', image: shot });
  check(res.r.status === 409, 'not live → co-pilot refuses (409)', res.r.status + ' ' + JSON.stringify(res.j));
  check((await rowsNow()).length === before, 'not live → no call_events written');

  // 1. Go live in co-pilot mode (history off); YOU say something, THEY ask about the table
  const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
  const got = [];
  ws.on('message', d => { try { const m = JSON.parse(d); m._t = Date.now(); if (m.type !== 'transcript' && m.type !== 'user_transcript') got.push(m); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: false }));
  const liveFrom = (await rowsNow()).length;
  const lines = [{ you: 'I already told finance the reclass posts next week, so the Midwest number will recover.' },
                 'Can you walk us through what row twelve means in this table?'];
  let ch1 = [silence(500)], ch2 = [silence(500)];
  for (const l of lines) {
    if (typeof l === 'string') { const a = speech(l); ch1.push(a, silence(700)); ch2.push(silence(a.length / 32), silence(700)); }
    else { const a = speech(l.you, 'Daniel'), echo = Buffer.alloc(a.length); for (let i = 0; i < a.length; i += 2) echo.writeInt16LE(Math.round(a.readInt16LE(i) * 0.5), i); ch2.push(a, silence(900)); ch1.push(silence(200), echo, silence(700)); }
  }
  ch1 = Buffer.concat([...ch1, silence(2500)]); ch2 = Buffer.concat([...ch2, silence(2500)]);
  const len = Math.max(ch1.length, ch2.length), pad = b => Buffer.concat([b, Buffer.alloc(len - b.length)]);
  ch1 = pad(ch1); ch2 = pad(ch2);
  for (let o = 0; o < len; o += 3200) { ws.send(Buffer.concat([Buffer.from([1]), ch1.slice(o, o + 3200)])); ws.send(Buffer.concat([Buffer.from([2]), ch2.slice(o, o + 3200)])); await sleep(100); }
  await sleep(6000);
  let rows = (await rowsNow()).slice(liveFrom);
  console.log('  call_events:', rows.map(r => r.kind + ':"' + r.text.slice(0, 50) + '"').join(' | '));
  check(rows.some(r => r.kind === 'you' && /finance|reclass|next week/i.test(r.text)), 'YOU line logged from the mic path');
  check(rows.some(r => r.kind === 'asker' && /row twelve|row 12/i.test(r.text)), 'THEIR line logged from the call path');
  const detected = got.find(m => m.type === 'question_detected');
  check(!!detected, 'question door fired', JSON.stringify(got.map(m => m.type)));
  check(!got.some(m => ['match', 'new_question', 'live_answer'].includes(m.type)), 'co-pilot mode: no Q&A card for the detected question', got.map(m => m.type).join(','));

  // 2. Regular: the client answers the detected ask with a fresh screen
  let mark = fs.readFileSync(LOG, 'utf8').length;
  res = await copilot({ ask: detected ? detected.text : lines[1], image: shot, screenChanged: true });
  check(res.r.ok && /^Asked:/m.test(res.j.answer || '') && /^On screen:/m.test(res.j.answer || '') && /^Say:/m.test(res.j.answer || ''), 'regular answer has the Asked / On screen / Say shape', res.j.answer);
  check(/-?18|943|reclass|Midwest/i.test(res.j.answer || ''), 'regular answer cites the table', res.j.answer);
  check(/haiku/i.test(logSince(mark)), 'regular mode runs on Haiku', logSince(mark).slice(-600));
  const stream = got.filter(m => /^copilot_(start|delta|done)$/.test(m.type));
  check(stream.some(m => m.type === 'copilot_start') && stream.filter(m => m.type === 'copilot_delta').length >= 2 && stream.some(m => m.type === 'copilot_done'), 'card streams (start, deltas, done)', stream.map(m => m.type).join(','));
  rows = (await rowsNow()).slice(liveFrom);
  check(rows.some(r => r.kind === 'seen') && rows.some(r => r.kind === 'said'), 'screen summary + answer logged (seen, said)', rows.map(r => r.kind).join(','));

  // 3. Same screen, pressed, no ask → text-only turn reusing the last screen summary
  mark = fs.readFileSync(LOG, 'utf8').length;
  res = await copilot({ pressed: true, screenChanged: false });
  check(res.r.ok && /^Asked:/m.test(res.j.answer || ''), 'press with unchanged screen still answers in shape', res.j.answer);
  check(/no image/i.test(logSince(mark)), 'server logs the text-only turn', logSince(mark).slice(-400));

  // 4. Smart (history on): consistent with what YOU said; digest compacted
  ws.send(JSON.stringify({ type: 'update_settings', copilotHistory: true }));
  await sleep(300);
  mark = fs.readFileSync(LOG, 'utf8').length;
  res = await copilot({ ask: 'Priya asks what you already told finance about the Midwest number and when it recovers', screenChanged: false });
  check(res.r.ok && /next week|reclass/i.test(res.j.answer || ''), 'smart answer stays consistent with the YOU line', res.j.answer);
  check(/sonnet/i.test(logSince(mark)), 'smart mode runs on Sonnet', logSince(mark).slice(-600));
  await sleep(6000);
  rows = (await rowsNow()).slice(liveFrom);
  check(rows.some(r => r.kind === 'digest'), 'digest row written (compaction ran)', rows.map(r => r.kind).join(','));
  check(/\[Co-pilot\] digest/i.test(logSince(mark)), 'compaction logged', logSince(mark).slice(-400));

  // 5. Stop → nothing more is logged or answered
  ws.send(JSON.stringify({ type: 'stop' })); await sleep(1500);
  const after = (await rowsNow()).length;
  res = await copilot({ ask: 'anything?', image: shot });
  check(res.r.status === 409 && (await rowsNow()).length === after, 'after stop → refused, nothing logged');

  ws.close(); await pool.end();
  console.log(`\n${fail ? 'FAILED' : 'ALL PASS'} (${pass} pass, ${fail} fail)`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
