// Add info (23 Nov) — the real page in real Chrome against a LOCAL server: open the +, type + Add, see it listed and kept
// after a reload, open a preview. Run AFTER test/add-info-e2e.js (it uses that session, which has 2 items left).
// Usage: node test/add-info-ui.js http://localhost:3999 <screenshot dir>
const X = require('path').join(__dirname, '..');
require(X + '/node_modules/dotenv').config({ path: X + '/.env' });
const { chromium } = require('/Users/rba-home/.local/node/lib/node_modules/@playwright/mcp/node_modules/playwright');
const { Pool } = require(X + '/node_modules/pg'); const jwt = require(X + '/node_modules/jsonwebtoken');
const B = process.argv[2] || 'http://localhost:3999', OUT = process.argv[3] || '/tmp';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
let pass = 0, fail = 0; const check = (ok, l, d) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + l + (!ok && d ? '\n     ' + d : '')); };

(async () => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const u = (await pool.query("SELECT * FROM users WHERE email='assessment-e2e@local.test'")).rows[0];
  const s = (await pool.query("SELECT s.id FROM sessions s WHERE s.user_id=$1 AND EXISTS (SELECT 1 FROM session_knowledge k WHERE k.session_id=s.id) ORDER BY s.created_at LIMIT 1", [u.id])).rows[0];
  const before = (await pool.query('SELECT count(*)::int n FROM session_knowledge WHERE session_id=$1', [s.id])).rows[0].n;
  const token = jwt.sign({ userId: u.id, name: u.name, email: u.email, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const br = await chromium.launch({ channel: 'chrome' }); const ctx = await br.newContext({ viewport: { width: 1000, height: 820 } });
  const p = await ctx.newPage(); const errs = []; p.on('pageerror', e => errs.push(e.message));
  await p.goto(B + '/canvas?token=' + token + '&session=' + s.id); await p.waitForTimeout(2500);
  check(await p.$eval('#btn-copilot-gear', el => el.classList.contains('has-data') && el.getAttribute('data-tip') === 'Add info'), 'the + shows this session has info');
  await p.evaluate(() => showCopilotGear()); await p.waitForTimeout(800);
  check(await p.$eval('#copilot-files-list', el => (el.textContent.match(/Added \((\d+)\)/) || [])[1]) === String(before), `opens with the ${before} saved items`);
  await p.screenshot({ path: OUT + '/add-info-open.png' });
  await p.fill('#info-text', 'Stakeholder: Dana (finance). She wants revenue in thousands, rounded.');
  await p.click('#info-add-btn'); await p.waitForTimeout(1500);
  const status = await p.$eval('#copilot-gear-status', el => el.textContent);
  check(/^Added "Stakeholder: Dana/.test(status) && await p.$eval('#info-text', el => el.value === ''), 'Add saves it, clears the box, says so', status);
  await p.reload(); await p.waitForTimeout(2500);
  await p.evaluate(() => showCopilotGear()); await p.waitForTimeout(800);
  const after = await p.$eval('#copilot-files-list', el => el.textContent);
  check(after.includes('Added (' + (before + 1) + ')') && after.includes('Stakeholder: Dana'), 'still there after a reload', after.slice(0, 200));
  await p.click('.info-item .file-name >> nth=0'); await p.waitForTimeout(300);
  check(await p.$eval('.info-preview', el => /fin\.sales_ledger_q3/.test(el.textContent)), 'clicking a name shows what was added');
  await p.screenshot({ path: OUT + '/add-info-preview.png' });
  check(!errs.length, 'no page errors', errs.join(' | '));
  await pool.query("DELETE FROM session_knowledge WHERE session_id=$1 AND title LIKE 'Stakeholder: Dana%'", [s.id]); // test row only
  await br.close(); await pool.end();
  console.log(`\n${fail ? 'FAILED' : 'ALL PASS'} (add info ui, ${pass} pass, ${fail} fail)`); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
