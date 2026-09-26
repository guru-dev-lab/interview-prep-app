// Multi-part questions stay ONE card (answer covers both parts); different back-to-back questions get TWO cards.
// Real audio → real server. Usage: node test/followup-e2e.js [baseUrl] [reps]   (LOCAL DATABASE_URL only)
require('dotenv').config();
const { execFileSync } = require('child_process'); const fs = require('fs'), os = require('os'), path = require('path'), https = require('https');
const WebSocket = require('ws'); const jwt = require('jsonwebtoken'); const { Pool } = require('pg');
const BASE = process.argv[2] || 'http://localhost:3997', REPS = +(process.argv[3] || 2);
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL }); const sleep = ms => new Promise(r => setTimeout(r, ms));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xhire-fu-'));
function speech(t) { const a = path.join(tmp, Math.random().toString(36).slice(2) + '.aiff'), w = a.replace('.aiff', '.wav'); execFileSync('say', ['-v', 'Samantha', '-o', a, t]); execFileSync('afconvert', ['-f', 'WAVE', '-d', 'LEI16@16000', '-c', '1', a, w]); const b = fs.readFileSync(w); return b.slice(b.indexOf('data') + 8); }
const silence = ms => Buffer.alloc(Math.round(16 * ms) * 2);
function bothParts(q1, q2, answer) {
  const body = JSON.stringify({ model: process.env.MODEL_SONNET || 'claude-sonnet-5', max_tokens: 2000, system: 'Reply ONLY JSON {"both":true|false}.', messages: [{ role: 'user', content: `Part 1: ${q1}\nPart 2: ${q2}\n\nANSWER:\n${answer}\n\nDoes the answer address BOTH parts?` }] });
  return new Promise(res => { const r = https.request({ hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' } }, x => { let d = ''; x.on('data', c => d += c); x.on('end', () => { try { const t = JSON.parse(d).content.filter(c => c.type === 'text').map(c => c.text).join(''); res(JSON.parse(t.slice(t.indexOf('{'), t.lastIndexOf('}') + 1)).both === true); } catch (e) { res(false); } }); }); r.write(body); r.end(); });
}
const CASES = [
  { name: 'two-part join question → ONE card, both parts', parts: ["What's the difference between an inner join and a left join?", 'How would you approach this problem?'], cards: 1 },
  { name: '"And what if…" follow-up → ONE card, both parts', parts: ['How do you handle a stakeholder who keeps changing requirements?', "And what if they're a senior executive?"], cards: 1 },
  { name: 'two different questions back to back → TWO cards', parts: ['What is a primary key in a database?', 'How do you prioritize competing deadlines?'], cards: 2 },
];
(async () => {
  let fails = 0;
  for (const c of CASES) for (let r = 0; r < REPS; r++) {
    const u = (await pool.query("INSERT INTO users (email,name,plan) VALUES ($1,'FU','free') RETURNING id", ['fu-' + Date.now() + Math.random() + '@local.test'])).rows[0];
    const s = (await pool.query("INSERT INTO sessions (user_id,company,role,resume) VALUES ($1,'Keystone','Data Analyst','Data Analyst at R&L Carriers (Mar 2022–present). SQL, Power BI.') RETURNING id", [u.id])).rows[0];
    const ws = new WebSocket(BASE.replace(/^http/, 'ws')); const cards = new Map();
    ws.on('message', d => { try { const m = JSON.parse(d); if (m.questionId && ['new_question', 'match', 'live_answer'].includes(m.type)) { const x = cards.get(m.questionId) || { versions: [] }; if (m.answer) { x.answer = m.answer; x.versions.push(m.answer); } cards.set(m.questionId, x); } } catch (e) {} });
    await new Promise(r2 => ws.on('open', r2));
    ws.send(JSON.stringify({ type: 'start', token: jwt.sign({ userId: u.id, name: 'FU', email: 'x', plan: 'free' }, process.env.JWT_SECRET), sessionId: s.id, mode: 'full', platform: 'electron', dualStream: true }));
    await sleep(1500);
    const a = Buffer.concat([silence(400), speech(c.parts[0]), silence(900), speech(c.parts[1]), silence(9000)]);
    for (let o = 0; o < a.length; o += 3200) { ws.send(Buffer.concat([Buffer.from([1]), a.slice(o, o + 3200)])); ws.send(Buffer.concat([Buffer.from([2]), silence(100).slice(0, Math.min(3200, a.length - o))])); await sleep(100); }
    await sleep(3000); ws.close();
    const n = cards.size; let ok = n === c.cards; let note = `${n} card(s)`;
    if (ok && c.cards === 1) {
      const card = [...cards.values()][0]; const ans = card.answer || '';
      const both = await bothParts(c.parts[0], c.parts[1], ans); ok = both; note += both ? ', covers both parts' : ', MISSES a part';
      // owner's rule: the follow-up is APPENDED — every line of the first complete answer stays, unchanged and in order
      const first = (card.versions[0] || '').split('\n').filter(l => l.startsWith('• ')); const fin = ans.split('\n').filter(l => l.startsWith('• '));
      const kept = first.length > 0 && first.every((l, i) => fin[i] === l) && fin.length > first.length;
      if (!kept) ok = false; note += kept ? `, first ${first.length} lines kept + ${fin.length - first.length} added` : ', first answer was REWRITTEN (lines changed)';
    }
    if (!ok) fails++;
    console.log(`${ok ? '✓' : '✗'} ${c.name}  — ${note}`);
  }
  await pool.end(); fs.rmSync(tmp, { recursive: true, force: true }); console.log(fails ? `${fails} FAILED` : 'ALL PASS'); process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
