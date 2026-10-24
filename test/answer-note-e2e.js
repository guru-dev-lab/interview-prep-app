// Answer Note, end to end on a LOCAL server (real routes, real DB; the model is called TWICE — one write, one "shorter").
// Usage: DATABASE_URL=<local> node test/answer-note-e2e.js http://localhost:3998
require('dotenv').config();
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const BASE = process.argv[2] || 'http://localhost:3998';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
let pass = 0, fail = 0;
const check = (ok, label, detail) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + label + (detail && !ok ? '\n     ' + String(detail).replace(/\n/g, '\n     ').slice(0, 900) : '')); };

(async () => {
  const email = 'note-e2e@local.test';
  let u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  if (!u) u = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Note Tester','premium') RETURNING *", [email])).rows[0];
  await pool.query('DELETE FROM answer_notes WHERE user_id=$1', [u.id]); // local test user only: a fresh first open every run
  await pool.query('DELETE FROM sessions WHERE user_id=$1', [u.id]);
  const resume = 'RESUME-MARKER\nSenior BI Analyst, Acme Logistics (Mar 2021 – present)\n- Built the Power BI shipment dashboard used by 40 executives; cut weekly report refresh from 4 hours to 20 minutes.\n- SQL (Snowflake), DAX, Python.\nData Analyst, Midwest Health Clinics (2018 – 2021)\n- Patient-flow reports for 12 clinics.';
  const sess = (await pool.query("INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1,'Globex','Analytics Lead',$2,'Lead BI for ops; Power BI, SQL.') RETURNING id", [u.id, resume])).rows[0];
  const token = jwt.sign({ userId: u.id, name: u.name, email, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const api = async (method, p, body) => { const r = await fetch(BASE + p, { method, headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: body ? JSON.stringify(body) : undefined }); let j = {}; try { j = await r.json(); } catch (e) {} return { r, j }; };

  // 0. auth at the door
  const anon = await fetch(BASE + '/api/note');
  check(anon.status === 401, 'no token → 401');
  const page = await fetch(BASE + '/note');
  check(page.status === 200 && /Answer Note/.test(await page.text()) && /no-store/.test(page.headers.get('cache-control') || ''), 'GET /note serves the page, no-store');

  // 1. first open seeds the mined groups
  let { j } = await api('GET', '/api/note');
  const nItems = j.groups.reduce((n, g) => n + g.items.length, 0);
  check(j.id && j.groups.length === 18 && nItems === 94, 'first open: 18 groups, 94 variations seeded', JSON.stringify([j.groups.length, nItems]));
  check(j.groups[0].name === 'Tell me about yourself' && j.groups[0].items[0].question === 'Tell me about yourself.' && j.groups[0].items[0].version === 0, 'seed order kept, answers empty');
  const again = (await api('GET', '/api/note')).j;
  check(again.id === j.id && again.groups.length === 18, 'second open: same note, not seeded twice');
  const g0 = j.groups[0], item = g0.items[0];

  // 2. manual save with history + stale write refused
  let r1 = await api('PUT', '/api/note/items/' + item.id, { answer_html: '<ul><li>My own words</li></ul>', key_points: 'own words', baseVersion: 0 });
  check(r1.r.status === 200 && r1.j.version === 1 && r1.j.versions.length === 0 && r1.j.answer_html === '<ul><li>My own words</li></ul>', 'manual save: version 1', JSON.stringify(r1.j));
  let r2 = await api('PUT', '/api/note/items/' + item.id, { answer_html: '<p>From a stale window</p>', baseVersion: 0 });
  check(r2.r.status === 409 && r2.j.item && r2.j.item.answer_html.includes('My own words'), 'stale save → 409 with the live row, nothing overwritten', r2.r.status + ' ' + JSON.stringify(r2.j).slice(0, 200));
  let r3 = await api('PUT', '/api/note/items/' + item.id, { answer_html: '<p onclick="x()">Edit two</p><script>bad()</script>', baseVersion: 1 });
  check(r3.r.status === 200 && r3.j.version === 2 && r3.j.answer_html === '<p>Edit two</p>' && r3.j.versions.length === 1 && r3.j.versions[0].preview === 'My own words', 'second save: sanitised, first text kept in history', JSON.stringify(r3.j));
  let rq = await api('PUT', '/api/note/items/' + item.id, { question: 'Tell me about yourself (renamed).' });
  check(rq.r.status === 200 && rq.j.question === 'Tell me about yourself (renamed).' && rq.j.version === 2, 'rename a variation: no content version');

  // 3. AI write (one call) — pushes the manual text into history; the answer is the candidate speaking, from the résumé
  const t0 = Date.now();
  let gen = await api('POST', '/api/note/items/' + item.id + '/generate', { mode: 'regenerate', sessionId: sess.id });
  const genMs = Date.now() - t0;
  const plain = String(gen.j.answer_html || '').replace(/<[^>]+>/g, ' ');
  check(gen.r.status === 200 && gen.j.version === 3 && /<li>/.test(gen.j.answer_html) && plain.length > 60, 'AI write: list answer, version 3 (' + genMs + ' ms)', JSON.stringify(gen.j).slice(0, 400));
  check(gen.j.versions.length === 2 && gen.j.versions[1].preview === 'Edit two' && gen.j.versions[1].by === 'you', 'AI write kept the manual edit in history', JSON.stringify(gen.j.versions));
  check(gen.j.key_points && gen.j.key_points.length > 3 && gen.j.key_points.split(/\s+/).length <= 16, 'KEY line present and short', gen.j.key_points);
  check(/\bI\b|\bI'm\b|\bmy\b/i.test(plain) && !/the candidate|resume/i.test(plain), 'first person, never talks about "the candidate"', plain.slice(0, 300));
  check(/Acme|Power BI|dashboard|Snowflake|SQL|20 minutes|4 hours|40 executives|Midwest|analyst/i.test(plain), 'uses facts from the résumé', plain.slice(0, 300));
  check(gen.j.job && gen.j.job.id === sess.id, 'written for the chosen session');
  const aiText = plain;

  // 4. "Shorter" (second and last model call) keeps the AI version in history; Undo = restore
  let sh = await api('POST', '/api/note/items/' + item.id + '/generate', { mode: 'shorter', sessionId: sess.id });
  const shPlain = String(sh.j.answer_html || '').replace(/<[^>]+>/g, ' ');
  const lines = h => (h.match(/<li>/g) || []).length;
  check(sh.r.status === 200 && sh.j.version === 4 && sh.j.versions.length === 3 && sh.j.versions[2].by === 'ai' && sh.j.versions[2].label === 'Regenerated', 'Shorter: version 4, the full AI answer kept', JSON.stringify(sh.j.versions));
  check(lines(sh.j.answer_html) <= Math.max(2, lines(gen.j.answer_html)) && shPlain.length < aiText.length + 40, 'Shorter is not longer (' + lines(gen.j.answer_html) + ' → ' + lines(sh.j.answer_html) + ' lines)', aiText.length + ' → ' + shPlain.length);
  const undo = await api('POST', '/api/note/items/' + item.id + '/restore', { versionId: sh.j.versions[2].id });
  check(undo.r.status === 200 && undo.j.version === 5 && undo.j.answer_html === gen.j.answer_html && undo.j.versions.length === 4, 'Undo restores the full AI answer; the short one stays in history', JSON.stringify(undo.j).slice(0, 300));
  const bad = await api('POST', '/api/note/items/' + item.id + '/restore', { versionId: 'nope' });
  check(bad.r.status === 404, 'restore of a missing version → 404');
  const noInstr = await api('POST', '/api/note/items/' + item.id + '/generate', { mode: 'custom', instruction: '' });
  check(noInstr.r.status === 400, 'custom change with no instruction → 400 (no model call)');

  // 5. groups and variations: add, rename, colour, pin, reorder, delete
  const ng = (await api('POST', '/api/note/groups', { name: 'My extra group' })).j;
  check(ng.id && ng.name === 'My extra group' && ng.sort_order === 18, 'add group at the end', JSON.stringify(ng));
  const ren = (await api('PUT', '/api/note/groups/' + ng.id, { name: 'Renamed group', color: '#2563eb', pinned: true })).j;
  check(ren.name === 'Renamed group' && ren.color === '#2563eb' && ren.pinned === true, 'rename, colour, pin a group');
  let tree = (await api('GET', '/api/note')).j;
  check(tree.groups[0].id === ng.id, 'pinned group comes first');
  const ids = tree.groups.map(g => g.id);
  const ord = (await api('PUT', '/api/note/groups/order', { ids: [ids[2], ids[1], 'not-an-id'].concat(ids.slice(3)) })).j;
  check(ord.ids.length === ids.length && ord.ids[0] === ids[2] && ord.ids[1] === ids[1] && ord.ids.includes(ids[0]), 'reorder groups: bad id ignored, nothing lost', JSON.stringify(ord.ids.slice(0, 3)));
  const ni = (await api('POST', '/api/note/groups/' + ng.id + '/items', { question: 'A brand new way to ask' })).j;
  check(ni.id && ni.question === 'A brand new way to ask' && ni.group_id === ng.id, 'add a variation');
  const ni2 = (await api('POST', '/api/note/groups/' + ng.id + '/items', { question: 'Second one' })).j;
  const iord = (await api('PUT', '/api/note/groups/' + ng.id + '/items/order', { ids: [ni2.id, ni.id] })).j;
  check(iord.ids.join() === [ni2.id, ni.id].join(), 'reorder variations');
  tree = (await api('GET', '/api/note')).j;
  const gg = tree.groups.find(g => g.id === ng.id);
  check(gg.items[0].id === ni2.id && gg.items[1].id === ni.id, 'order persisted');
  const di = await api('DELETE', '/api/note/items/' + ni2.id);
  const dg = await api('DELETE', '/api/note/groups/' + ng.id);
  tree = (await api('GET', '/api/note')).j;
  check(di.j.removed && dg.j.removed && !tree.groups.some(g => g.id === ng.id) && tree.groups.length === 18, 'delete a variation and a group (its items go with it)');
  const other = (await pool.query("SELECT i.id FROM answer_note_items i JOIN answer_notes n ON n.id=i.note_id WHERE n.user_id<>$1 LIMIT 1", [u.id])).rows[0];
  if (other) { const x = await api('PUT', '/api/note/items/' + other.id, { answer_html: 'x', baseVersion: 0 }); check(x.r.status === 404, "another user's item → 404"); }
  else check(true, "another user's item → 404 (no other note locally, skipped)");

  // 6. settings
  const st = (await api('PUT', '/api/note/settings', { bg: '#101820', theme: 'light', sessionId: sess.id, hacker: 'no' })).j;
  check(st.settings.bg === '#101820' && st.settings.theme === 'light' && st.settings.sessionId === sess.id && st.settings.hacker === undefined && st.settings.seeded === true, 'settings: allow-listed keys merge, seeded flag kept', JSON.stringify(st.settings));

  // 7. no résumé anywhere → a clear refusal, no model call
  const u2e = 'note-noresume@local.test';
  let u2 = (await pool.query('SELECT * FROM users WHERE email=$1', [u2e])).rows[0];
  if (!u2) u2 = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'No Resume','premium') RETURNING *", [u2e])).rows[0];
  await pool.query('DELETE FROM sessions WHERE user_id=$1', [u2.id]);
  const t2 = jwt.sign({ userId: u2.id, name: u2.name, email: u2e, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const n2 = await (await fetch(BASE + '/api/note', { headers: { Authorization: 'Bearer ' + t2 } })).json();
  const g2 = await fetch(BASE + '/api/note/items/' + n2.groups[0].items[0].id + '/generate', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + t2 }, body: '{"mode":"regenerate"}' });
  check(g2.status === 400 && /résumé/.test((await g2.json()).error), 'no résumé → 400 "Add your résumé to a session first"');

  console.log(fail ? `${fail} FAILED, ${pass} passed` : `ALL PASS (answer note e2e, ${pass} checks, 2 model calls)`);
  await pool.end(); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
