// 23 Nov owner asks, in real Chrome against a LOCAL server:
//  1. the Answer Note no longer opens by itself (only after a quick restart of the SAME session; never a new assessment)
//  2. turning the eye (invisible mode) OFF asks first — from the eye and from Settings; turning it ON never asks
//  3. the + on the co-pilot bar is labelled "Info"
//  4. New session from the desktop launcher: same routes as the website, so the website lists it at once
// Usage: node test/desktop-polish-ui.js http://localhost:3999 <screenshot dir> [--skip-build]
const X = require('path').join(__dirname, '..');
require(X + '/node_modules/dotenv').config({ path: X + '/.env' });
const { chromium } = require('/Users/rba-home/.local/node/lib/node_modules/@playwright/mcp/node_modules/playwright');
const { Pool } = require(X + '/node_modules/pg'); const jwt = require(X + '/node_modules/jsonwebtoken');
const B = process.argv[2] || 'http://localhost:3999', OUT = process.argv[3] || '/tmp', SKIP_BUILD = process.argv.includes('--skip-build');
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
let pass = 0, fail = 0; const check = (ok, l, d) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + l + (!ok && d ? '\n     ' + d : '')); };

// a stand-in for the desktop bridge: every call is recorded and does nothing
const BRIDGE = `(() => { window.__calls = []; const fixed = { isElectron: true, isWindows: false };
  window.electronAPI = new Proxy({}, { get: (_, k) => k in fixed ? fixed[k] : (...a) => { window.__calls.push([String(k), a]); return Promise.resolve(null); } }); })();`;

(async () => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const email = 'assessment-e2e@local.test';
  const u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  let base = (await pool.query("SELECT id, company FROM sessions WHERE user_id=$1 AND coalesce(kind,'interview')<>'assessment' AND coalesce(resume,'')<>'' ORDER BY created_at DESC LIMIT 1", [u.id])).rows[0];
  if (!base) base = (await pool.query("INSERT INTO sessions (user_id, company, role, resume) VALUES ($1,'Acme','Data Analyst','RESUME-MARKER: 5 years SQL at Acme. Built dashboards in Tableau and Power BI.') RETURNING id, company", [u.id])).rows[0];
  const SID = base.id;
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const br = await chromium.launch({ channel: 'chrome' });

  // ---- 1. the note ----
  const notePage = async (want, seenAgoMs, extra) => {
    const ctx = await br.newContext({ viewport: { width: 1100, height: 800 } });
    await ctx.addInitScript(BRIDGE);
    await ctx.addInitScript(([w, s]) => { if (!sessionStorage.getItem('seeded')) { sessionStorage.setItem('seeded', '1'); localStorage.setItem('xhire_note_want', w); localStorage.setItem('xhire_overlay_seen_at', String(Date.now() - s)); } }, [want, seenAgoMs]);
    const p = await ctx.newPage();
    await p.goto(B + '/canvas?token=' + token + '&session=' + SID + '&electron=1' + (extra || '')); await p.waitForTimeout(2200);
    const opened = await p.evaluate(() => window.__calls.filter(c => c[0] === 'openNote').length);
    const flag = await p.evaluate(() => localStorage.getItem('xhire_note_want'));
    await ctx.close(); return { opened, flag };
  };
  let r = await notePage('1', 5000);
  check(r.opened === 0 && r.flag === '0', 'old sticky flag ("open last time") → note stays closed, flag cleared', JSON.stringify(r));
  r = await notePage(JSON.stringify({ s: 'some-other-session', at: Date.now() }), 5000);
  check(r.opened === 0, 'note was open in ANOTHER session → stays closed', JSON.stringify(r));
  r = await notePage(JSON.stringify({ s: SID, at: Date.now() }), 60 * 60 * 1000);
  check(r.opened === 0, 'same session but the app was closed an hour ago → stays closed', JSON.stringify(r));
  r = await notePage(JSON.stringify({ s: SID, at: Date.now() }), 60 * 1000, '&assessment=new');
  check(r.opened === 0, 'a NEW assessment never opens the note', JSON.stringify(r));
  r = await notePage(JSON.stringify({ s: SID, at: Date.now() }), 60 * 1000);
  check(r.opened === 1, 'restart in the middle of the SAME session (1 min ago) → note comes back (26 Oct case)', JSON.stringify(r));

  // ---- 2 + 3. eye asks first; + is labelled ----
  const ctx = await br.newContext({ viewport: { width: 1100, height: 800 } }); await ctx.addInitScript(BRIDGE);
  const p = await ctx.newPage(); const errs = []; p.on('pageerror', e => errs.push(e.message));
  await p.goto(B + '/canvas?token=' + token + '&session=' + SID + '&electron=1'); await p.waitForTimeout(2000);
  const stealthCalls = () => p.evaluate(() => window.__calls.filter(c => c[0] === 'setStealth').map(c => c[1][0]));
  const before = (await stealthCalls()).length;
  await p.click('#btn-stealth'); await p.waitForTimeout(200);
  check(await p.isVisible('#stealth-ask') && await p.evaluate(() => stealthOn === true) && (await stealthCalls()).length === before, 'eye click: asks first, still invisible');
  await p.screenshot({ path: OUT + '/eye-ask.png' });
  await p.click('#stealth-ask-no'); await p.waitForTimeout(150);
  check(!(await p.isVisible('#stealth-ask')) && await p.evaluate(() => stealthOn === true) && (await stealthCalls()).length === before, '"No, keep it hidden" → nothing changes');
  await p.click('#btn-stealth'); await p.waitForTimeout(150); await p.keyboard.press('Escape'); await p.waitForTimeout(150);
  check(!(await p.isVisible('#stealth-ask')) && await p.evaluate(() => stealthOn === true), 'Esc = keep hidden');
  await p.click('#btn-stealth'); await p.waitForTimeout(150); await p.click('#stealth-ask-yes'); await p.waitForTimeout(150);
  let sc = await stealthCalls();
  check(await p.evaluate(() => stealthOn === false) && sc[sc.length - 1] === false, '"Yes, turn it off" → off', JSON.stringify(sc));
  await p.click('#btn-stealth'); await p.waitForTimeout(150);
  sc = await stealthCalls();
  check(!(await p.isVisible('#stealth-ask')) && await p.evaluate(() => stealthOn === true) && sc[sc.length - 1] === true, 'turning it back ON never asks');
  await p.evaluate(() => toggleStealthFromSettings(false)); await p.waitForTimeout(150);
  check(await p.isVisible('#stealth-ask'), 'Settings switch off asks too');
  await p.click('#stealth-ask-no'); await p.waitForTimeout(150);
  check(await p.evaluate(() => stealthOn === true && $('s-stealth').checked === true), 'Settings "No" puts the switch back on');
  const lbl = await p.$eval('#btn-copilot-gear', el => el.textContent.replace(/\s+/g, ''));
  check(lbl === '+Info', 'the + on the co-pilot bar says Info', lbl);
  check(!errs.length, 'no page errors (canvas)', errs.join(' | '));
  await ctx.close();

  // ---- 4. New session from the launcher ----
  const lc = await br.newContext({ viewport: { width: 420, height: 720 } });
  await lc.addInitScript(([t, id]) => { localStorage.setItem('xhire_token', t); localStorage.setItem('xhire_uid', id); }, [token, u.id]);
  const L = await lc.newPage(); const lerrs = []; L.on('pageerror', e => lerrs.push(e.message));
  await L.goto(B + '/launcher'); await L.waitForTimeout(2500);
  check(await L.isVisible('.ns-new'), 'launcher session list has "+ New session"');
  await L.click('.ns-new'); await L.waitForTimeout(1200);
  const st = await L.textContent('#ns-res-state');
  check(/Using your résumé from/.test(st), 'New session reuses the last résumé', st);
  await L.click('#ns-build'); await L.waitForTimeout(300);
  check(/Paste the job description/.test(await L.textContent('#ns-error')), 'Create with no JD → plain message');
  await L.screenshot({ path: OUT + '/new-session.png' });
  if (!SKIP_BUILD) {
    const n0 = (await pool.query("SELECT count(*)::int n FROM sessions WHERE user_id=$1 AND coalesce(kind,'interview')<>'assessment'", [u.id])).rows[0].n;
    await L.fill('#ns-jd', 'Northwind Health is hiring a Senior Data Analyst.\nYou will build SQL pipelines and Power BI dashboards for hospital operations, partner with finance on KPIs, and present findings to leadership.\nRequirements: 4+ years SQL, Power BI or Tableau, stakeholder communication.');
    const nav = L.waitForURL(/\/canvas\?/, { timeout: 180000 }).then(() => true).catch(() => false);
    await L.click('#ns-build');
    const went = await nav;
    const newId = (L.url().match(/session=([0-9a-f-]{36})/) || [])[1];
    check(went && newId, 'Create → session made and opened in the overlay', L.url());
    const row = newId && (await pool.query('SELECT company, role, resume, jd FROM sessions WHERE id=$1', [newId])).rows[0];
    const baseRes = (await pool.query('SELECT resume FROM sessions WHERE id=$1', [SID])).rows[0].resume;
    check(row && row.resume === baseRes && /Northwind/.test(row.jd), 'saved with the reused résumé + the JD', JSON.stringify(row && { company: row.company, role: row.role }));
    const web = await (await fetch(B + '/api/sessions', { headers: { Authorization: 'Bearer ' + token } })).json();
    check(Array.isArray(web) && web.some(x => x.id === newId && x.questionCount > 0), 'the website list has it, with questions built (synced)', JSON.stringify((web || []).find(x => x.id === newId)));
    const n1 = (await pool.query("SELECT count(*)::int n FROM sessions WHERE user_id=$1 AND coalesce(kind,'interview')<>'assessment'", [u.id])).rows[0].n;
    check(n1 === n0 + 1, 'exactly one session added', n0 + ' → ' + n1);
  }
  check(!lerrs.length, 'no page errors (launcher)', lerrs.join(' | '));
  await br.close(); await pool.end();
  console.log(`\n${fail ? 'FAILED' : 'ALL PASS'} (desktop polish ui, ${pass} pass, ${fail} fail)`); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
