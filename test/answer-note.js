// Unit test: Answer Note logic (lib/answer-note.js + public/note-match.js) — seed, version history (no silent
// overwrite), restore, search, reorder, HTML safety, writer-reply parsing, live-question matching. No DB, no model.
const N = require('../lib/answer-note');
let pass = 0, fail = 0;
const check = (ok, label, detail) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + label + (!ok && detail !== undefined ? '\n     ' + String(detail).slice(0, 300) : '')); };

// Seed (v2, owner 24 Oct): every distinct question its own line, a short title, the full question, at most 3 other ways
const rows = N.seedRows();
const nItems = rows.reduce((n, g) => n + g.items.length, 0);
check(rows.length === 43 && nItems === 172, 'seed: 43 questions, 172 wordings', rows.length + ' ' + nItems);
check(rows.every(g => g.items.length >= 1 && g.items.length <= N.MAX_WAYS + 1), 'seed: every question has at most ' + N.MAX_WAYS + ' other ways');
check(rows[0].name === 'About me' && rows[0].section === 'About you' && rows[0].items[0].question === 'Tell me about yourself.', 'seed: short title, section, full question first');
check(rows.every(g => g.name.length <= 40 && g.section), 'seed: every title is short and sits in a section', rows.filter(g => g.name.length > 40 || !g.section).map(g => g.name).join(' | '));
check(rows.every((g, i) => g.sort_order === i && g.items.every((it, j) => it.sort_order === j)), 'seed: sort orders set');
check(rows.some(g => /won't budge/.test(g.items[0].question)) && rows.some(g => /prioritize/.test(g.items[0].question)), 'seed: the two the owner remembers are in');
check(!/\u2014/.test(JSON.stringify(N.SEED)), 'seed: no em dashes');
const allQ = rows.flatMap(g => g.items.map(i => i.question.toLowerCase()));
check(new Set(allQ).size === allQ.length, 'seed: no wording appears twice');

// v1 -> v2 upgrade: nothing he wrote is lost; only empty seeded rows are renamed, reused or removed
const v1 = [
  { id: 'g1', name: 'Prioritising', sort_order: 3, items: [
    { id: 'a', question: 'How do you prioritise?', sort_order: 0 },
    { id: 'b', question: 'How do you handle conflicting priorities?', sort_order: 1, answer_html: '<ul><li>my answer</li></ul>' },
    { id: 'c', question: 'You have two or three projects coming at once. How do you handle it?', sort_order: 2 },
    { id: 'd', question: 'How do you prioritise across a global team and multiple regions?', sort_order: 3, versions: [{ id: 'v' }] },
    { id: 'e', question: 'How do you handle tight deadlines and pressure?', sort_order: 4, key_points: 'my key' },
  ] },
  { id: 'g2', name: 'Salary', sort_order: 15, items: [{ id: 's1', question: 'What are your salary expectations?', sort_order: 0 }, { id: 's2', question: 'x', sort_order: 1 }] },
  { id: 'g9', name: 'My own group', sort_order: 1, items: [{ id: 'm1', question: 'Mine', sort_order: 0 }] },
];
const ops = N.upgradePlan(v1);
const byId = id => ops.filter(o => o.id === id);
const del = new Set(ops.filter(o => o.op === 'deleteEmptyItem').map(o => o.id));
check(!del.has('b') && !del.has('d') && !del.has('e'), 'upgrade: an answer, a KEY or any history is never deleted', JSON.stringify([...del]));
check(byId('b').every(o => o.question === undefined) && byId('d').every(o => o.question === undefined), 'upgrade: his answered rows keep their own question');
check(byId('g1')[0].name === 'Prioritizing' && byId('g1')[0].section === 'How you work', 'upgrade: group gets the short title and section');
const g1Rows = ops.filter(o => (o.op === 'updateItem' && ['a', 'b', 'c', 'd', 'e'].includes(o.id)) || (o.op === 'insertItem' && o.group_id === 'g1'));
check(g1Rows.length === 4 && g1Rows.find(o => o.sort_order === 0).question === 'How do you prioritize when everything is urgent?', 'upgrade: 4 wordings, the full question first', JSON.stringify(g1Rows));
check(del.has('c') && del.size === 1, 'upgrade: only the empty extra row goes', JSON.stringify([...del]));
check(byId('s1')[0].question === 'What are your salary expectations?' && byId('s2')[0].question === 'What are you looking for in pay?' && ops.filter(o => o.op === 'insertItem' && o.group_id === 'g2').length === 2, 'upgrade: empty rows are reused, the rest inserted');
check(ops.some(o => o.op === 'insertGroup' && o.name === "Why I'm leaving") && ops.filter(o => o.op === 'insertGroup').length === 43 - 2, 'upgrade: questions not in the old note are added', ops.filter(o => o.op === 'insertGroup').length);
check(byId('g9').length === 1 && byId('g9')[0].sort_order === 43 && byId('g9')[0].name === undefined, 'upgrade: his own group is left alone, moved below the seed');
const tooMany = N.upgradePlan([{ id: 'g', name: 'SQL', items: ['p', 'q', 'r', 's', 't'].map((x, i) => ({ id: x, question: 'q' + x, sort_order: i, answer_html: 'a' })) }]);
check(tooMany.filter(o => o.op === 'deleteEmptyItem').length === 0 && tooMany.filter(o => o.op === 'updateItem' && 'pqrst'.includes(o.id)).length === 5, 'upgrade: more answered rows than the cap all stay');

// Version history — ONE door, nothing overwritten silently
let item = { answer_html: '', key_points: '', version: 0, versions: [] };
let r = N.applyChange(item, { answer_html: '<ul><li>First draft</li></ul>', key_points: 'first', baseVersion: 0 }, { by: 'ai', label: 'Regenerated' });
check(r.changed && r.version === 1 && r.versions.length === 0, 'first write: no version kept for an empty answer', JSON.stringify(r));
Object.assign(item, r);
r = N.applyChange(item, { answer_html: '<ul><li>My own edit</li></ul>', baseVersion: 1 }, { by: 'you' });
check(r.changed && r.version === 2 && r.versions.length === 1 && r.versions[0].html.includes('First draft') && r.versions[0].by === 'ai', 'manual edit keeps the AI draft in history', JSON.stringify(r.versions));
Object.assign(item, r);
let conflict = null;
try { N.applyChange(item, { answer_html: '<p>AI result from a stale read</p>', baseVersion: 1 }, { by: 'ai' }); } catch (e) { conflict = e; }
check(conflict && conflict.code === 'CONFLICT' && item.answer_html.includes('My own edit'), 'stale write is refused (409), the manual edit stands', conflict && conflict.message);
r = N.applyChange(item, { answer_html: '<ul><li>Shorter AI</li></ul>', key_points: 'short' }, { by: 'ai', label: 'Shorter' }); // AI edits carry no baseVersion: history keeps the manual text
check(r.changed && r.versions.length === 2 && r.versions[1].html.includes('My own edit') && r.versions[1].by === 'you', 'AI edit pushes the manual edit into history first');
Object.assign(item, r);
r = N.applyChange(item, { answer_html: item.answer_html, key_points: item.key_points, baseVersion: item.version }, { by: 'you' });
check(!r.changed && r.version === item.version, 'same content: no new version');
const undo = N.restoreVersion(item, item.versions[1].id);
check(undo.answer_html.includes('My own edit') && undo.version === item.version + 1 && undo.versions.length === 3 && undo.versions[2].html.includes('Shorter AI'), 'restore brings the manual edit back and keeps the AI one');
let gone = null; try { N.restoreVersion(item, 'nope'); } catch (e) { gone = e; }
check(gone && gone.code === 'NOT_FOUND', 'restoring a missing version is refused');
let big = { answer_html: 'v0', key_points: '', version: 0, versions: [] };
for (let i = 1; i <= N.MAX_VERSIONS + 5; i++) big = Object.assign(big, N.applyChange(big, { answer_html: 'v' + i }, { by: 'you' }));
check(big.versions.length === N.MAX_VERSIONS && big.versions[0].html === 'v5', 'history is capped at ' + N.MAX_VERSIONS + ', oldest dropped', big.versions.length + ' ' + big.versions[0].html);

// HTML safety
const dirty = '<p onclick="x()">hi</p><script>alert(1)</script><a href="javascript:evil()">l</a><span style="color:red">ok</span><img src=x onerror=alert(1)>';
const clean = N.sanitizeHtml(dirty);
check(!/script|onclick|onerror|javascript:|<img/i.test(clean) && /<span style="color:red">ok<\/span>/.test(clean) && /<a>l<\/a>/.test(clean), 'sanitize: scripts, handlers, bad links and images stripped; formatting kept', clean);
check(N.htmlToText('<ul><li>One</li><li>Two &amp; three</li></ul><p>Four</p>') === 'One\nTwo & three\nFour', 'htmlToText: lines and entities', N.htmlToText('<ul><li>One</li><li>Two &amp; three</li></ul><p>Four</p>'));

// Writer reply → answer + key points, live layout → editor HTML
const gen = N.parseGenerated('• I lead with the number.\n• Then the how.\n↳ At Acme — cut refresh from 4 hours to 20 minutes.\nKEY: lead with the 4h to 20min cut');
check(gen.keyPoints === 'lead with the 4h to 20min cut' && !/KEY/.test(gen.answer) && gen.answer.split('\n').length === 3, 'parseGenerated splits KEY off', JSON.stringify(gen));
const html = N.answerToHtml(gen.answer);
check(html === '<ul><li>I lead with the number.</li><li>Then the how.</li></ul><p class="emp">At Acme — cut refresh from 4 hours to 20 minutes.</p>', 'answerToHtml: bullets → list, ↳ → proof line', html);
check(N.answerToHtml('▸ At Acme\n• Situation: x\n```sql\nSELECT 1\n```') === '<h3>At Acme</h3><ul><li>Situation: x</li></ul><pre>SELECT 1</pre>', 'answerToHtml: heading and code', N.answerToHtml('▸ At Acme\n• Situation: x\n```sql\nSELECT 1\n```'));

// Change instructions
check(N.changeInstruction('shorter').includes('half the lines') && N.changeInstruction('custom', ' make it about Power BI ') === 'make it about Power BI' && N.changeInstruction('regenerate') === '', 'AI modes map to one instruction each');
check(N.changeLabel('custom', 'make it about Power BI') === 'AI: make it about Power BI' && N.changeLabel('natural') === 'Made it sound like me', 'history labels per mode');

// Search
const groups = [
  { id: 'g1', name: 'SQL', items: [{ id: 'a', question: 'What is a window function?', answer_html: '<p>ROW_NUMBER over a partition</p>', key_points: '' }, { id: 'b', question: 'Inner vs left join', answer_html: '', key_points: 'keeps all left rows' }] },
  { id: 'g2', name: 'Salary', items: [{ id: 'c', question: 'What are your salary expectations?', answer_html: '', key_points: '' }] },
];
check(N.searchNote(groups, '').length === 2, 'search: empty query returns everything');
let s = N.searchNote(groups, 'partition');
check(s.length === 1 && s[0].items.length === 1 && s[0].items[0].id === 'a', 'search: matches answer text', JSON.stringify(s));
s = N.searchNote(groups, 'left rows');
check(s.length === 1 && s[0].items[0].id === 'b', 'search: matches key points, every word must hit', JSON.stringify(s));
s = N.searchNote(groups, 'sql');
check(s.length === 1 && s[0].items.length === 2, 'search: a group name hit keeps all its variations');
check(N.searchNote(groups, 'zzz').length === 0, 'search: no hit → nothing');

// Reorder
check(N.reorderIds(['a', 'b', 'c'], ['c', 'a']).join() === 'c,a,b' && N.reorderIds(['a', 'b'], ['x', 'b', 'b']).join() === 'b,a', 'reorder: only existing ids, nothing lost');
check(N.sortGroups([{ id: 1, sort_order: 2 }, { id: 2, sort_order: 0 }, { id: 3, sort_order: 1, pinned: true }]).map(g => g.id).join() === '3,2,1', 'pinned groups first, then saved order');

// Live question → closest variation (paraphrases from his real interviews)
const seedGroups = N.seedRows().map((g, i) => ({ id: 'g' + i, name: g.name, items: g.items.map((it, j) => ({ id: 'g' + i + 'i' + j, question: it.question })) }));
const cases = [
  ['So how do you prioritize when you have a lot of competing things coming at you?', 'Prioritizing'],
  ['How do you convince an executive who just will not budge?', "Exec who won't budge"],
  ["What's the difference between a left join and an inner join?", 'Inner vs left join'],
  ['Could you tell us a bit about yourself?', 'About me'],
  ['What are you expecting salary wise?', 'Salary'],
  ['How do you validate the report before leadership sees it?', 'Checking a report'],
  ["What's your biggest weakness?", 'Weakness'],
  ['Why should we hire you over the other candidates?', 'Why hire me'],
];
for (const [heard, groupName] of cases) {
  const m = N.closest(seedGroups, heard);
  const g = m && seedGroups.find(x => x.id === m.groupId);
  check(g && g.name === groupName, 'match: "' + heard.slice(0, 50) + '" → ' + groupName, (g && g.name) + ' ' + (m && m.score.toFixed(2)) + ' ' + (m && m.question));
}
check(N.closest(seedGroups, 'okay great, can you hear me fine?') === null, 'match: small talk matches nothing', JSON.stringify(N.closest(seedGroups, 'okay great, can you hear me fine?')));

console.log(fail ? `${fail} FAILED, ${pass} passed` : `ALL PASS (answer note, ${pass} checks)`);
process.exit(fail ? 1 : 0);
