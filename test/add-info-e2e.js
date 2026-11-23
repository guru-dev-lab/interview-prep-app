// Add info (23 Nov), end to end on a LOCAL server: real routes, real DB, real models (kept small: 1 picture read, 2 answers).
// Owner: "somewhere i can add file, text … use it to help in answering … continue to use it as long as i am still using that session".
// Usage: DATABASE_URL=<local> node test/add-info-e2e.js http://localhost:3999 <server log path>
require('dotenv').config();
const fs = require('fs'), path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const BASE = process.argv[2] || 'http://localhost:3999';
const LOG = process.argv[3];
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
if (!LOG || !fs.existsSync(LOG)) { console.error('Pass the server log path'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const sleep = ms => new Promise(r => setTimeout(r, ms));
let pass = 0, fail = 0;
const check = (ok, label, detail) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + label + (detail && !ok ? '\n     ' + String(detail).replace(/\n/g, '\n     ').slice(0, 1200) : '')); };
const logSince = mark => fs.readFileSync(LOG).subarray(mark).toString('utf8');

(async () => {
  const email = 'assessment-e2e@local.test'; // reuse the assessment test account (one account, no fresh ones)
  let u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Assess Tester','premium') RETURNING *", [email])).rows[0];
  await pool.query("UPDATE users SET plan='premium', is_admin=false WHERE id=$1", [u.id]);
  await pool.query("DELETE FROM sessions WHERE user_id=$1 AND kind='assessment'", [u.id]); // local test user only
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const H = { Authorization: 'Bearer ' + token };
  const api = async (method, p, body) => { const r = await fetch(BASE + p, { method, headers: Object.assign({ 'Content-Type': 'application/json' }, H), body: body ? JSON.stringify(body) : undefined }); let j = {}; try { j = await r.json(); } catch (e) {} return { r, j }; };
  const upload = async (sid, name, buf, type) => { const fd = new FormData(); fd.append('file', new Blob([buf], { type }), name); const r = await fetch(BASE + '/api/sessions/' + sid + '/info', { method: 'POST', headers: H, body: fd }); return { r, j: await r.json().catch(() => ({})) }; };
  const live = async sid => {
    const ws = new WebSocket(BASE.replace(/^http/, 'ws'));
    await new Promise(r => ws.on('open', r));
    ws.send(JSON.stringify({ type: 'start', token, sessionId: sid, mode: 'full', platform: 'electron', dualStream: true }));
    await sleep(1500);
    ws.send(JSON.stringify({ type: 'update_settings', copilot: true, copilotHistory: true }));
    await sleep(300);
    return ws;
  };

  // 1. a new assessment starts empty
  const a = (await api('POST', '/api/assessments')).j;
  const sid = a.id;
  let g = await api('GET', `/api/sessions/${sid}/info`);
  check(g.r.status === 200 && Array.isArray(g.j.items) && g.j.items.length === 0, 'new session: nothing added yet', JSON.stringify(g.j));

  // 2. add text (his existing query), a file (table + fields), a picture (a table on a screenshot)
  const QUERY = 'SELECT region_code, SUM(net_rev_usd) AS total_rev\nFROM fin.sales_ledger_q3\nGROUP BY region_code';
  let t = await api('POST', `/api/sessions/${sid}/info`, { text: QUERY });
  check(t.r.status === 200 && t.j.item && t.j.item.title === 'Query — fin.sales_ledger_q3' && t.j.item.body === QUERY, 'text added, titled from its table', JSON.stringify(t.j));
  const FIELDS = 'Table fin.sales_ledger_q3\n- region_code (text)\n- net_rev_usd (numeric)\n- order_cnt (int) = number of orders on the row\n- booked_dt (date)';
  let f = await upload(sid, 'ledger-fields.txt', Buffer.from(FIELDS), 'text/plain');
  check(f.r.status === 200 && f.j.item && f.j.item.title === 'ledger-fields.txt' && /order_cnt/.test(f.j.item.body) && f.j.item.source === 'file', 'file added and read', JSON.stringify(f.j));
  const mark0 = fs.statSync(LOG).size;
  let p = await upload(sid, 'plan-vs-actual.png', fs.readFileSync(path.join(__dirname, 'fixtures/screens/meeting-table.png')), 'image/png');
  check(p.r.status === 200 && p.j.item && p.j.item.source === 'image' && /Midwest/.test(p.j.item.body) && /943/.test(p.j.item.body) && /-18%/.test(p.j.item.body), 'picture read into exact text (Midwest 943 -18%)', JSON.stringify(p.j).slice(0, 800));
  check(/\[Info\] read picture plan-vs-actual\.png in \d+ms/.test(logSince(mark0)), 'picture read logged');
  let empty = await api('POST', `/api/sessions/${sid}/info`, { text: '   ' });
  check(empty.r.status === 400 && /type or paste/i.test(empty.j.error || ''), 'empty text refused with a plain message', JSON.stringify(empty.j));

  // 3. it is kept: a fresh read (= reload / restart) has all three, in order
  g = await api('GET', `/api/sessions/${sid}/info`);
  check(g.j.items && g.j.items.length === 3 && g.j.items[0].source === 'text' && g.j.items[2].source === 'image', 'kept on the server: 3 items after a fresh read', JSON.stringify(g.j).slice(0, 400));

  // 4. an assessment with only added info is listed (titled from its first item) and a New never reuses it as blank
  const list = (await api('GET', '/api/assessments')).j;
  const it = (list.items || []).find(x => x.id === sid);
  check(it && it.title === 'Query — fin.sales_ledger_q3', 'launcher lists it, titled from the first item', JSON.stringify(list).slice(0, 400));
  const b = (await api('POST', '/api/assessments')).j;
  check(b.id && b.id !== sid, 'a New assessment is a different one (not reused as blank)', JSON.stringify(b));

  // 5. someone else cannot see or remove it
  let o = (await pool.query("SELECT * FROM users WHERE email='pro-gate@local.test'")).rows[0];
  if (!o) o = (await pool.query("INSERT INTO users (email, name, plan) VALUES ('pro-gate@local.test','pro gate','pro') RETURNING *")).rows[0];
  const oH = { Authorization: 'Bearer ' + jwt.sign({ userId: o.id, name: o.name, email: o.email, isAdmin: false, plan: 'pro', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' }) };
  const og = await fetch(`${BASE}/api/sessions/${sid}/info`, { headers: oH });
  const od = await fetch(`${BASE}/api/sessions/${sid}/info/${g.j.items[0].id}`, { method: 'DELETE', headers: oH });
  check(og.status === 404 && od.status === 404, 'another account: 404 on read and remove', og.status + ' ' + od.status);

  // 6. a live ask in this session builds on HIS query with HIS names
  let ws = await live(sid);
  let mark = fs.statSync(LOG).size;
  let res = await api('POST', `/api/sessions/${sid}/copilot`, { ask: 'They want my query to also show the number of orders per region, only for bookings from September on. What do I change?', typed: true });
  const ans = res.j.answer || '';
  check(/fin\.sales_ledger_q3/.test(ans) && /order_cnt/.test(ans) && /booked_dt/.test(ans) && /region_code/.test(ans), 'answer extends HIS query with HIS table and fields', ans);
  check(/\[Info\] co-pilot call carries 3 added item\(s\)/.test(logSince(mark)), 'co-pilot call carried the 3 items (log)');
  check(!/\bITEM\s*\d/i.test(ans), 'card names it, never "ITEM 1"', ans);
  ws.send(JSON.stringify({ type: 'stop' })); ws.close(); await sleep(1500);

  // 7. next sitting (continue): still there, still used — the picture's numbers too
  ws = await live(sid);
  mark = fs.statSync(LOG).size;
  res = await api('POST', `/api/sessions/${sid}/copilot`, { ask: 'Which region missed plan and by how much?', typed: true });
  const ans2 = res.j.answer || '';
  check(/Midwest/.test(ans2) && /18\s?%|207/.test(ans2), 'next sitting uses the picture they added (Midwest -18%)', ans2);
  check(/\[Info\] co-pilot call carries 3 added item\(s\)/.test(logSince(mark)), 'next sitting carried them (log)');
  check(!/\bITEM\s*\d/i.test(ans2), 'card names it, never "ITEM 3"', ans2);
  ws.send(JSON.stringify({ type: 'stop' })); ws.close(); await sleep(500);

  // 8. remove one → gone from the list
  const rm = await api('DELETE', `/api/sessions/${sid}/info/${g.j.items[2].id}`);
  g = await api('GET', `/api/sessions/${sid}/info`);
  check(rm.r.status === 200 && g.j.items.length === 2 && !g.j.items.some(x => x.source === 'image'), 'remove takes it out', JSON.stringify(rm.j) + ' ' + g.j.items.length);

  // 9. (23 Nov) a BIG SQL view with NO file extension: accepted whole (no limit), titled from the SQL, compacted once,
  //    and an answer about a column near its END uses the exact lines; binary files get a plain refusal
  const cols = Array.from({ length: 1750 }, (_, i) => `      , ISNULL(f.metric_${String(i).padStart(4, '0')}_amount, 0) * fx.rate_to_usd AS kpi_${String(i).padStart(4, '0')}_usd`);
  cols.splice(1700, 0, "      , CASE WHEN o.churn_flag = 'Y' AND DATEDIFF(day, o.last_order_dt, GETDATE()) > 90 THEN 'At risk' ELSE 'Active' END AS customer_health_status");
  const BIG = 'USE [SalesDW]\r\nGO\r\n/****** Object:  View [dbo].[vw_customer_360] ******/\r\nCREATE VIEW [dbo].[vw_customer_360] AS\r\nSELECT c.customer_id\r\n' + cols.join('\r\n') + '\r\nFROM dbo.fact_customer_month f\r\nJOIN dbo.dim_customer c ON c.customer_id = f.customer_id\r\nJOIN dbo.orders_summary o ON o.customer_id = c.customer_id\r\nJOIN dbo.fx_rates fx ON fx.currency = f.currency\r\nGO\r\n';
  let bigUp = await upload(sid, 'downloaded-file-1795047840', Buffer.from(BIG), 'application/octet-stream');
  check(bigUp.r.status === 200 && bigUp.j.item && bigUp.j.item.title === 'View — dbo.vw_customer_360' && bigUp.j.item.chars > 120000 && bigUp.j.item.ready === false, `big view, no extension: added whole (${bigUp.j.item && bigUp.j.item.chars} chars), titled from the SQL, short version on its way`, JSON.stringify(bigUp.j).slice(0, 300));
  let ready = false; const tR = Date.now();
  while (Date.now() - tR < 180000) { const gl = await api('GET', `/api/sessions/${sid}/info`); const it = (gl.j.items || []).find(x => x.id === (bigUp.j.item || {}).id); if (it && it.ready) { ready = true; break; } await sleep(4000); }
  const short = (await pool.query('SELECT length(compact) n FROM session_knowledge WHERE id=$1', [(bigUp.j.item || {}).id])).rows[0];
  check(ready && short && short.n > 200 && short.n < 30000, `short version written once (${short && short.n} chars for ${bigUp.j.item && bigUp.j.item.chars})`, JSON.stringify(short));
  const bin = await upload(sid, 'data.bin', Buffer.from([0, 1, 2, 3, 0, 255, 7]), 'application/octet-stream');
  check(bin.r.status === 400 && /Can't read data\.bin/.test(bin.j.error || ''), 'a binary file gets a plain refusal', JSON.stringify(bin.j));
  ws = await live(sid);
  mark = fs.statSync(LOG).size;
  res = await api('POST', `/api/sessions/${sid}/copilot`, { ask: 'In my customer 360 view, how is customer_health_status worked out? They want the at-risk cut-off moved to 60 days.', typed: true });
  const ans3 = res.j.answer || '';
  check(/churn_flag/.test(ans3) && /last_order_dt/.test(ans3) && /\b60\b/.test(ans3), 'answer about a column near the END of the big view uses its exact line', ans3);
  const ln = (logSince(mark).match(/\[Info\] co-pilot call carries .*?(\d+) chars of exact parts/) || [])[1];
  check(+ln > 0 && +ln <= 12000, `only the matching exact parts rode with the question (${ln} chars, not the whole view)`);
  mark = fs.statSync(LOG).size;
  res = await api('POST', `/api/sessions/${sid}/copilot`, { ask: 'Which tables does the customer 360 view join, and on what keys?', typed: true });
  const ans4 = res.j.answer || '';
  check(/fact_customer_month/.test(ans4) && /dim_customer/.test(ans4) && /orders_summary/.test(ans4) && /fx_rates/.test(ans4), 'join question answered from the short version + parts', ans4);
  const cr = (logSince(mark).match(/\[Cache\] \S+ input=\d+ cached_read=(\d+)/) || [])[1];
  check(+cr > 1000, `second answer re-read the info from cache (cached_read=${cr})`);
  ws.send(JSON.stringify({ type: 'stop' })); ws.close(); await sleep(500);

  console.log(`\n${fail ? 'FAILED' : 'ALL PASS'} (add info e2e, ${pass} pass, ${fail} fail)`);
  await pool.end(); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
