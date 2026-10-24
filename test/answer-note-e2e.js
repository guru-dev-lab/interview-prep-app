// Answer Note, end to end on a LOCAL server (real routes, real DB; the model is called TWICE — one write, one "shorter").
// Usage: DATABASE_URL=<local> node test/answer-note-e2e.js http://localhost:3998
require('dotenv').config();
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const BASE = process.argv[2] || 'http://localhost:3998';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const answerNote = require('../lib/answer-note');
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
  check(j.id && j.groups.length === 48 && nItems === 192, 'first open: 48 questions, 192 wordings seeded', JSON.stringify([j.groups.length, nItems]));
  check(j.groups[0].name === 'About me' && j.groups[0].section === 'About you' && j.groups[0].items[0].question === 'Tell me about yourself.' && j.groups[0].items[0].version === 0, 'seed order kept: short title, section, full question first, answers empty');
  check(j.settings.seedVersion === 3, 'a fresh note is born on the current seed (v3, never upgraded again)');
  const cap = await api('POST', '/api/note/groups/' + j.groups[0].id + '/items', { question: 'A fifth wording' });
  check(cap.r.status === 400 && /at most 3/.test(cap.j.error || ''), 'a question already holding 3 other ways refuses a 4th', cap.r.status + ' ' + JSON.stringify(cap.j));
  const again = (await api('GET', '/api/note')).j;
  check(again.id === j.id && again.groups.length === 48, 'second open: same note, not seeded twice');
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
  check(ng.id && ng.name === 'My extra group' && ng.sort_order === 48, 'add group at the end', JSON.stringify(ng));
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
  check(di.j.removed && dg.j.removed && !tree.groups.some(g => g.id === ng.id) && tree.groups.length === 48, 'delete a variation and a group (its items go with it)');
  const other = (await pool.query("SELECT i.id FROM answer_note_items i JOIN answer_notes n ON n.id=i.note_id WHERE n.user_id<>$1 LIMIT 1", [u.id])).rows[0];
  if (other) { const x = await api('PUT', '/api/note/items/' + other.id, { answer_html: 'x', baseVersion: 0 }); check(x.r.status === 404, "another user's item → 404"); }
  else check(true, "another user's item → 404 (no other note locally, skipped)");

  // 6. settings
  const st = (await api('PUT', '/api/note/settings', { bg: '#101820', theme: 'light', sessionId: sess.id, hacker: 'no' })).j;
  check(st.settings.bg === '#101820' && st.settings.theme === 'light' && st.settings.sessionId === sess.id && st.settings.hacker === undefined && st.settings.seeded === true, 'settings: allow-listed keys merge, seeded flag kept', JSON.stringify(st.settings));

  // 6b. a note seeded with v1 moves to v2 once, through the real route, and keeps everything he wrote
  const u3e = 'note-upgrade@local.test';
  let u3 = (await pool.query('SELECT * FROM users WHERE email=$1', [u3e])).rows[0];
  if (!u3) u3 = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'Upgrade Tester','premium') RETURNING *", [u3e])).rows[0];
  await pool.query('DELETE FROM answer_notes WHERE user_id=$1', [u3.id]); // local test user only
  const n3 = (await pool.query(`INSERT INTO answer_notes (user_id, settings) VALUES ($1, '{"seeded": true, "theme": "dark"}') RETURNING id`, [u3.id])).rows[0];
  const mkG = async (name, so, qs) => { const g = (await pool.query('INSERT INTO answer_note_groups (note_id, name, sort_order) VALUES ($1,$2,$3) RETURNING id', [n3.id, name, so])).rows[0]; const ids = []; for (let k = 0; k < qs.length; k++) ids.push((await pool.query('INSERT INTO answer_note_items (note_id, group_id, question, sort_order) VALUES ($1,$2,$3,$4) RETURNING id', [n3.id, g.id, qs[k], k])).rows[0].id); return { id: g.id, ids }; };
  const pri = await mkG('Prioritising', 3, ['How do you prioritise?', 'How do you handle conflicting priorities?', 'You have two or three projects coming at once. How do you handle it?', 'How do you prioritise across a global team and multiple regions?', 'How do you handle tight deadlines and pressure?']);
  await pool.query("UPDATE answer_note_items SET answer_html = '<ul><li>MY-OWN-ANSWER</li></ul>', version = 1 WHERE id = $1", [pri.ids[3]]);
  const mine = await mkG('My own group', 0, ['My own question']);
  const t3 = jwt.sign({ userId: u3.id, name: u3.name, email: u3e, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const get3 = async () => (await fetch(BASE + '/api/note', { headers: { Authorization: 'Bearer ' + t3 } })).json();
  const up = await get3();
  const upPri = up.groups.find(g => g.id === pri.id);
  const kept = upPri && upPri.items.find(i => i.id === pri.ids[3]);
  check(up.settings.seedVersion === 3 && up.settings.theme === 'dark', 'v1 note upgraded once, his settings kept', JSON.stringify(up.settings));
  check(upPri && upPri.name === 'Prioritizing' && upPri.section === 'How you work' && upPri.items[0].question === 'How do you prioritize when everything is urgent?', 'v1 group renamed to the short title, full question first', JSON.stringify(upPri && upPri.items.map(i => i.question)));
  check(kept && /MY-OWN-ANSWER/.test(kept.answer_html) && kept.question === 'How do you prioritise across a global team and multiple regions?', 'his written answer survived with its own question');
  check(upPri && upPri.items.length === 4, 'the group now holds 4 wordings', upPri && upPri.items.length);
  check(up.groups.length === 49 && up.groups.some(g => g.id === mine.id && g.name === 'My own group'), 'the missing seed questions were added, his own group left alone', up.groups.length);
  const up2 = await get3();
  check(up2.groups.length === 49 && up2.groups.reduce((n, g) => n + g.items.length, 0) === up.groups.reduce((n, g) => n + g.items.length, 0), 'opening again changes nothing (runs once)');

  // 6c. a note made on seed v2 (like his) gets the Agentic AI questions once, right after its AI section, nothing else touched
  const u4e = 'note-v2@local.test';
  let u4 = (await pool.query('SELECT * FROM users WHERE email=$1', [u4e])).rows[0];
  if (!u4) u4 = (await pool.query("INSERT INTO users (email, name, plan) VALUES ($1,'V2 Tester','premium') RETURNING *", [u4e])).rows[0];
  await pool.query('DELETE FROM answer_notes WHERE user_id=$1', [u4.id]); // local test user only
  const n4 = (await pool.query(`INSERT INTO answer_notes (user_id, settings) VALUES ($1, '{"seeded": true, "seedVersion": 2}') RETURNING id`, [u4.id])).rows[0];
  const v2seed = answerNote.seedRows().filter(g => !(answerNote.SEED.groups.find(s => s.title === g.name) || {}).since);
  for (let i = 0; i < v2seed.length; i++) { const g = (await pool.query('INSERT INTO answer_note_groups (note_id, name, section, sort_order) VALUES ($1,$2,$3,$4) RETURNING id', [n4.id, v2seed[i].name, v2seed[i].section, i])).rows[0]; for (const it of v2seed[i].items) await pool.query('INSERT INTO answer_note_items (note_id, group_id, question, sort_order) VALUES ($1,$2,$3,$4)', [n4.id, g.id, it.question, it.sort_order]); }
  const before4 = (await pool.query("SELECT id FROM answer_note_items WHERE note_id = $1 AND question = 'What tools, platforms and databases have you used?'", [n4.id])).rows[0];
  await pool.query("UPDATE answer_note_items SET answer_html = '<p>MY-TOOLS-ANSWER</p>', version = 1 WHERE id = $1", [before4.id]);
  const t4 = jwt.sign({ userId: u4.id, name: u4.name, email: u4e, isAdmin: false, plan: 'premium', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const get4 = async () => (await fetch(BASE + '/api/note', { headers: { Authorization: 'Bearer ' + t4 } })).json();
  const v3 = await get4();
  const names = v3.groups.map(g => g.name);
  const ai = names.indexOf('My tools');
  check(v3.settings.seedVersion === 3 && v3.groups.length === 48, 'v2 note: moved to v3, 5 questions added', v3.groups.length);
  check(JSON.stringify(names.slice(ai + 1, ai + 6)) === JSON.stringify(['Agentic AI at work', 'Building an AI agent', 'Keeping agents in check', 'Agent vs chatbot', 'Agents for this team']) && v3.groups.slice(ai + 1, ai + 6).every(g => g.section === 'AI and tools' && g.items.length === 4), 'they sit right after "My tools" in the AI section, with their 3 other ways', JSON.stringify(names.slice(ai - 1, ai + 7)));
  check(names[ai + 6] === 'Great teamwork' && names[0] === 'About me', 'the questions after them just move down');
  check(/MY-TOOLS-ANSWER/.test(v3.groups[ai].items[0].answer_html), 'his written answers are untouched');
  check((await get4()).groups.length === 48, 'opening again adds nothing');

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
