// Hands-on asks HEARD from the interviewer fire a co-pilot card on their own (owner, 12 Nov: "I want it to coach and very
// active"). Real server + real Deepgram, spoken with macOS `say` on the interviewer channel, co-pilot mode on, nobody presses.
// Usage: node test/hands-on-heard-e2e.js [baseUrl]   (LOCAL DATABASE_URL; reuses the hands-on local user)
require('dotenv').config();
const { execFileSync } = require('child_process'); const fs = require('fs'), os = require('os'), path = require('path');
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3997';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL }); const sleep = ms => new Promise(r => setTimeout(r, ms));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-ho-'));
const speech = t => { const a = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), w = a.replace('.aiff', '.wav'); execFileSync('say', ['-v', 'Samantha', '-o', a, t]); execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', a, w]); const b = fs.readFileSync(w); return b.slice(b.indexOf('data') + 8); };
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
const LINES = [
  "Okay, so you have Tableau Public open with the Superstore data. Let's look at which sub-categories are losing money.",
  'Great. Now go ahead and filter that to just the West region.',
];
(async () => {
  const u = (await pool.query("SELECT id FROM users WHERE email = 'hands-on@local.test'")).rows[0];
  if (!u) { console.error('Run test/hands-on-copilot-e2e.js once first'); process.exit(2); }
  const s = (await pool.query('SELECT id FROM sessions WHERE user_id = $1 LIMIT 1', [u.id])).rows[0];
  const token = jwt.sign({ userId: u.id, name: 'HO', email: 'hands-on@local.test', plan: 'pro' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const got = [];
  // the overlay's part (canvas.html: question_detected from co-pilot → copilotSend({ ask })) — no press, nothing typed
  const overlayAsk = ask => fetch(`${BASE}/api/sessions/${s.id}/copilot`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify({ ask }) }).catch(() => {});
  ws.on('message', d => { try { const m = JSON.parse(d); if (/copilot|question_detected/.test(m.type) && m.type !== 'copilot_delta') got.push(m); if (m.type === 'question_detected' && m.source === 'copilot') overlayAsk(m.text); } catch (e) {} });
  await new Promise(r => ws.on('open', r));
  ws.send(JSON.stringify({ type: 'start', token, sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
  await sleep(1500);
  ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: false }));
  await sleep(500);
  for (const line of LINES) {
    const c1 = Buffer.concat([speech(line), silence(9000)]);
    for (let o = 0; o < c1.length; o += 3200) { ws.send(Buffer.concat([Buffer.from([1]), c1.slice(o, o + 3200)])); ws.send(Buffer.concat([Buffer.from([2]), silence(100)])); await sleep(100); }
  }
  await sleep(8000); ws.close();
  for (const m of got) console.log(' ', m.type.padEnd(18), (m.text || m.ask || (m.answer || '').replace(/\n/g, ' ⏎ ')).slice(0, 230));
  const starts = got.filter(m => m.type === 'copilot_start');
  const ok1 = starts.some(m => /sub-?categor/i.test(m.ask)), ok2 = starts.some(m => /west/i.test(m.ask));
  const dones = got.filter(m => m.type === 'copilot_done'), recipe = dones.filter(m => /(Do|Steps):/.test(m.answer)).length;
  console.log(`${ok1 ? 'PASS' : 'FAIL'} heard "Let's look at … losing money" → card on its own`);
  console.log(`${ok2 ? 'PASS' : 'FAIL'} heard "go ahead and filter … West" → card on its own`);
  console.log(`${recipe >= 2 ? 'PASS' : 'FAIL'} both cards are build recipes with Steps (${recipe})`);
  await pool.end(); process.exit(ok1 && ok2 && recipe >= 2 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
