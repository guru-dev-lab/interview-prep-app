// Rename an assessment from the desktop launcher (owner 23 Nov), real Chrome + LOCAL server, desktop bridge stubbed.
// Usage: node test/assessment-rename-ui.js http://localhost:3999 <screenshot dir>
const X = require('path').join(__dirname, '..');
require(X + '/node_modules/dotenv').config({ path: X + '/.env' });
const { chromium } = require('/Users/rba-home/.local/node/lib/node_modules/@playwright/mcp/node_modules/playwright');
const { Pool } = require(X + '/node_modules/pg'); const jwt = require(X + '/node_modules/jsonwebtoken');
const B = process.argv[2] || 'http://localhost:3999', OUT = process.argv[3] || '/tmp';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
let pass = 0, fail = 0; const check = (ok, l, d) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + l + (!ok && d ? '\n     ' + d : '')); };
const BRIDGE = `(() => { window.__calls = []; const fixed = { isElectron: true, isWindows: false, getServerUrl: () => Promise.resolve(location.origin) };
  window.electronAPI = new Proxy({}, { get: (_, k) => k in fixed ? fixed[k] : (...a) => { window.__calls.push([String(k), a]); return Promise.resolve(null); } }); })();`;

(async () => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const email = 'assessment-e2e@local.test';
  const u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  await pool.query("DELETE FROM sessions WHERE user_id=$1 AND kind='assessment'", [u.id]); // local test user only
  const mk = async (title, ago) => { const s = (await pool.query("INSERT INTO sessions (user_id, kind, title, created_at) VALUES ($1,'assessment',$2, NOW() - ($3 || ' minutes')::interval) RETURNING id", [u.id, title, String(ago)])).rows[0]; await pool.query("INSERT INTO session_knowledge (session_id, title, body) VALUES ($1,'note','some info')", [s.id]); return s.id; };
  const older = await mk('Old SQL Check', 60), newest = await mk('', 5); // newest is untitled: the list shows its first item's title
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const H = { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token };

  // API rules
  let r = await fetch(`${B}/api/assessments/${newest}`, { method: 'PATCH', headers: H, body: JSON.stringify({ title: '   ' }) });
  check(r.status === 400, 'empty name refused');
  const company = (await pool.query("SELECT id FROM sessions WHERE user_id=$1 AND coalesce(kind,'interview')<>'assessment' LIMIT 1", [u.id])).rows[0];
  if (company) { r = await fetch(`${B}/api/assessments/${company.id}`, { method: 'PATCH', headers: H, body: JSON.stringify({ title: 'x' }) }); check(r.status === 404, 'a company session cannot be renamed here (404)'); }
  let o = (await pool.query("SELECT * FROM users WHERE email='pro-gate@local.test'")).rows[0];
  const oT = jwt.sign({ userId: o.id, name: o.name, email: o.email, isAdmin: false, plan: 'pro', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  r = await fetch(`${B}/api/assessments/${newest}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + oT }, body: JSON.stringify({ title: 'hijack' }) });
  check(r.status === 404, "another account cannot rename it (404)");

  // launcher UI
  const br = await chromium.launch({ channel: 'chrome' }); const ctx = await br.newContext({ viewport: { width: 420, height: 720 } });
  await ctx.addInitScript(BRIDGE);
  await ctx.addInitScript(([t, id]) => { localStorage.setItem('xhire_token', t); localStorage.setItem('xhire_uid', id); }, [token, u.id]);
  const L = await ctx.newPage(); const errs = []; L.on('pageerror', e => errs.push(e.message));
  await L.goto(B + '/launcher'); await L.waitForTimeout(2500);
  await L.click('#as-card'); await L.waitForTimeout(1000);
  check(await L.isVisible('#as-last .as-ed') && await L.isVisible('#as-hist .as-ed'), 'a rename pencil on the last one and on history rows');
  await L.click('#as-last .as-ed'); await L.waitForTimeout(200);
  check(await L.isVisible('#as-last .as-name') && await L.evaluate(() => document.activeElement.classList.contains('as-name')), 'pencil → name box, ready to type');
  await L.fill('#as-last .as-name', 'Encompass loan view — practice'); await L.screenshot({ path: OUT + '/rename.png' });
  await L.keyboard.press('Enter'); await L.waitForTimeout(800);
  check((await L.textContent('#as-last .as-t')).trim() === 'Encompass loan view — practice', 'Enter saves: the card shows the new name');
  check((await pool.query('SELECT title FROM sessions WHERE id=$1', [newest])).rows[0].title === 'Encompass loan view — practice', 'saved on the server');
  check(!(await L.evaluate(() => window.__calls.some(c => c[0] === 'loadCanvas'))), 'renaming did not open the assessment');
  await L.click('#as-hist .as-ed'); await L.waitForTimeout(200);
  await L.fill('#as-hist .as-name', 'should not save'); await L.keyboard.press('Escape'); await L.waitForTimeout(300);
  check((await pool.query('SELECT title FROM sessions WHERE id=$1', [older])).rows[0].title === 'Old SQL Check' && /Old SQL Check/.test(await L.textContent('#as-hist')), 'Esc keeps the old name');
  await L.reload(); await L.waitForTimeout(2500); await L.click('#as-card'); await L.waitForTimeout(1000);
  check((await L.textContent('#as-last .as-t')).trim() === 'Encompass loan view — practice', 'still renamed after reopening');
  // the auto-title never overwrites a name he chose (the carry names only an empty title — same clause as server.js)
  const lockedSql = (await pool.query("UPDATE sessions SET title = 'AUTO TITLE' WHERE id = $1 AND coalesce(title, '') = '' RETURNING id", [newest])).rowCount;
  check(lockedSql === 0, "the carry's title rule (only when empty) leaves his name alone");
  check(!errs.length, 'no page errors', errs.join(' | '));
  await br.close(); await pool.end();
  console.log(`\n${fail ? 'FAILED' : 'ALL PASS'} (assessment rename ui, ${pass} pass, ${fail} fail)`); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
