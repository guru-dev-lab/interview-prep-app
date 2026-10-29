// Real note page: coach lines are kept per topic (owner 28 Oct), said ones tick, a finished topic is tidied into a card,
// and history survives a reload. Local server :3999.
const X = '/Users/rba-home/Documents/Claude/xhire';
require(X + '/node_modules/dotenv').config({ path: X + '/.env' });
const { chromium } = require('/Users/rba-home/.local/node/lib/node_modules/@playwright/mcp/node_modules/playwright');
const { Pool } = require(X + '/node_modules/pg'); const jwt = require(X + '/node_modules/jsonwebtoken');
let pass = 0, fail = 0; const check = (ok, l, d) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + l + (ok || d === undefined ? '' : '  ' + d)); };
const B = 'http://localhost:3999', SHOT = process.argv[2] || '/tmp/coach-hist.png';
(async () => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const u = (await pool.query("SELECT * FROM users WHERE email='note-calls@local.test'")).rows[0];
  const RES = 'Alex Doe. Senior BI Developer, 8 years at Contoso. Built Power BI dashboards for 2,000+ users across 14 hospitals, SQL Server and Snowflake pipelines, cut month-end reporting from 5 days to 1.';
  const s = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1,'Northwind','BI Analyst II',$2,'BI Analyst: Power BI, SQL, finance dashboards, automation.') RETURNING *", [u.id, RES])).rows[0];
  await pool.query("UPDATE answer_notes SET settings = jsonb_set(settings, '{jobsBuilt}', coalesce(settings->'jobsBuilt', '[]'::jsonb) || to_jsonb($2::text)) WHERE user_id = $1", [u.id, s.id]);
  const token = jwt.sign({ userId: u.id, name: u.name, email: u.email, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  await fetch(B + '/api/note/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify({ autoGenerate: false, autoSwitch: false, coach: true }) });
  const br = await chromium.launch({ channel: 'chrome' }); const ctx = await br.newContext({ viewport: { width: 1250, height: 900 } });
  const p = await ctx.newPage(); const errs = []; p.on('pageerror', e => errs.push(e.message));
  try {
    await p.goto(B + '/note?token=' + token + '&session=' + s.id); await p.waitForTimeout(2000);
    const x = await ctx.newPage(); await x.goto(B + '/download');
    const send = (type, text) => x.evaluate(([type, text]) => new BroadcastChannel('xhire-note').postMessage({ type, text }), [type, text]);
    const hist = () => p.evaluate(() => coachTopics.map(t => ({ title: t.title, lines: t.lines.map(l => (l.said ? '[SAID] ' : '') + l.t), tidy: t.tidy })));
    const waitFor = async (fn, ms) => { for (let i = 0; i < ms / 250; i++) { const v = await fn(); if (v) return v; await p.waitForTimeout(250); } return null; };
    await send('question', 'So tell me, why are you looking to leave Contoso right now?');
    const h1 = await waitFor(async () => { const h = await hist(); return h.length && h[0].lines.length ? h : null; }, 12000);
    check(!!h1, 'a coach line is kept under its question', JSON.stringify(h1));
    console.log('   topic 1:', JSON.stringify(h1 && h1[0].lines));
    const line = h1 && h1[0].lines[0];
    if (line) await send('said', line.replace(/^\[SAID\] /, ''));
    const h2 = (await waitFor(async () => { const h = await hist(); return h[0].lines.some(l => l.startsWith('[SAID]')) ? h : null; }, 5000)) || await hist(); check(h2[0].lines.some(l => l.startsWith('[SAID]')), 'what he said ticks the line as said');
    await send('them', 'Yeah, we hear that a lot. Honestly the team here is great, we just moved everything to Fabric and it has been a ride.');
    await p.waitForTimeout(7000);
    await send('question', 'How do you prioritize when every request is marked urgent?');
    const h3 = await waitFor(async () => { const h = await hist(); const t1 = h.find(t => /leave Contoso/.test(t.title)); return h.length >= 2 && t1 && t1.tidy ? h : null; }, 20000);
    check(!!h3, 'the finished topic is tidied into a card when the next starts', JSON.stringify(await hist()));
    if (h3) {
      for (const t of h3) console.log('   ' + t.title + ' | raw: ' + JSON.stringify(t.lines) + '\n     tidy: ' + JSON.stringify(t.tidy));
      const t1 = h3.find(t => t.tidy);
      check(t1.tidy.points.length >= 1 && t1.tidy.points.length <= 4, '1-4 ready lines');
      check(t1.tidy.points.some(q => q.said), 'the line he said stays marked as said');
    }
    for (const t of await hist()) { const L = t.lines.map(l => l.replace(/^\[SAID\] /, '')); check(new Set(L).size === L.length, 'no line twice in "' + t.title.slice(0, 30) + '"'); }
    await p.evaluate(() => { if (!coachHistOpen) $('chist-btn').click(); });
    await p.waitForTimeout(400); await p.screenshot({ path: SHOT });
    const shown = await p.evaluate(() => ({ vis: getComputedStyle($('chist')).display, n: $('chist-list').querySelectorAll('.ch-t').length, now: !!$('chist-list').querySelector('.now'), btn: $('chist-btn').textContent }));
    check(shown.vis !== 'none' && shown.n >= 2 && shown.now, 'history shows under the page, newest first with "Now"', JSON.stringify(shown));
    const n0 = (await hist()).length; await p.reload(); await p.waitForTimeout(2500);
    check((await hist()).length === n0, 'history is still there after the note reloads');
    check(!errs.length, 'no page errors', errs.join(' | '));
  } finally { await br.close(); await pool.end(); console.log(fail ? `${fail} FAILED of ${pass + fail}` : `ALL PASS (${pass})`); }
})();
