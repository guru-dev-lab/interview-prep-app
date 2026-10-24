// Answer Note (owner, 23 Oct) — pure logic (no DB, no model). server.js wires it; test/answer-note.js proves it.
// A desktop note he reads from DURING a live interview: left side = the full questions, each with up to 3 other
// ways interviewers phrase it, each one = his answer (AI-written from his résumé, then his
// own edits). Rules that live here: seeding from data/note-seed.json, the version history (an AI edit never silently
// overwrites a manual edit), search, the change instructions per AI button, parsing the writer's reply, HTML safety.
const SEED = require('../data/note-seed.json');
const NoteMatch = require('../public/note-match');

const MAX_VERSIONS = 20; // per answer; oldest dropped

const MAX_WAYS = 3; // owner 24 Oct: a question plus at most 3 other ways it gets asked (so at most 4 items per group)

// First open: the mined questions, in order. Group name = a short title (bold on the left), section = the heading it
// sits under; its items = the full question first (shown under the title), then the other ways it gets asked.
// Returns plain rows for the server's INSERT loop.
function seedQuestions(g) { return [g.question].concat(g.ways || []).filter(Boolean).slice(0, MAX_WAYS + 1).map(q => String(q).trim().slice(0, 500)); }
function seedTitle(g) { return String(g.title || g.question).trim().slice(0, 160); }
function seedRows(seed) {
  const groups = ((seed || SEED).groups || []).filter(g => g && g.question);
  return groups.map((g, gi) => ({
    name: seedTitle(g), section: String(g.section || '').slice(0, 80), sort_order: gi,
    items: seedQuestions(g).map((q, qi) => ({ question: q, sort_order: qi })),
  }));
}

// A note seeded with v1 (short group names, up to 8 phrasings each) moves to v2 ONCE. Nothing he wrote is lost:
// an item with an answer, a KEY or any history is never deleted and keeps its own question; only EMPTY seeded rows are
// renamed, reused or removed. A group he renamed or added himself is left alone (it just moves below the seed).
// Questions added to the seed after a note was made (seed "since": N > the note's seedVersion) go into that note once:
// each right after the last question of its section (or at the end), skipped if the note already has it (same title or
// the same wording). Nothing else in the note moves except what sits below the new ones.
// groups: [{ id, name, section, sort_order, items: [{ question }] }] → [{ name, section, items, after }] where `after` is
// the sort_order to insert after (the server shifts everything below by one, then inserts).
function additionsPlan(groups, fromVersion, seed) {
  const S = ((seed || SEED).groups || []).filter(g => g && g.question && (g.since || 0) > (fromVersion || 0));
  const norm = q => String(q || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const have = (groups || []).map(g => ({ section: g.section || '', sort_order: g.sort_order || 0, name: norm(g.name), qs: (g.items || []).map(i => norm(i.question)) }));
  const out = [];
  let end = have.reduce((m, g) => Math.max(m, g.sort_order), -1);
  for (const s of S) {
    if (have.some(g => g.name === norm(seedTitle(s)) || g.qs.includes(norm(s.question)))) continue;
    const inSec = have.filter(g => g.section === (s.section || ''));
    const after = inSec.length ? Math.max(...inSec.map(g => g.sort_order)) : end;
    out.push({ name: seedTitle(s), section: String(s.section || '').slice(0, 80), items: seedQuestions(s), after });
    have.forEach(g => { if (g.sort_order > after) g.sort_order++; });   // what the server's shift does
    have.push({ section: s.section || '', sort_order: after + 1, name: norm(seedTitle(s)), qs: [norm(s.question)] });
    end = Math.max(end + 1, after + 1);
  }
  return out;
}

// groups: [{ id, name, sort_order, items: [{ id, question, answer_html, key_points, versions }] }] → a list of ops.
function upgradePlan(groups, seed) {
  const S = ((seed || SEED).groups || []).filter(g => g && g.question);
  const has = it => !!(String(it.answer_html || '').trim() || String(it.key_points || '').trim() || (it.versions || []).length);
  const norm = q => String(q || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const ops = []; const used = new Set();
  S.forEach((s, i) => {
    const g = (groups || []).find(x => !used.has(x.id) && s.was && x.name === s.was);
    const targets = seedQuestions(s);
    const section = String(s.section || '').slice(0, 80);
    if (!g) { ops.push({ op: 'insertGroup', name: seedTitle(s), section, sort_order: i, items: targets }); return; }
    used.add(g.id);
    ops.push({ op: 'updateGroup', id: g.id, name: seedTitle(s), section, sort_order: i });
    const items = (g.items || []).slice().sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0));
    const kept = items.filter(has), empty = items.filter(it => !has(it));
    const taken = new Set();
    let slots = targets.map(t => { const m = kept.find(k => !taken.has(k.id) && norm(k.question) === norm(t)); if (m) taken.add(m.id); return m ? { id: m.id } : { question: t }; });
    const extra = kept.filter(k => !taken.has(k.id)).map(k => ({ id: k.id }));
    slots = [slots[0]].concat(extra, slots.slice(1));
    for (let j = slots.length - 1; j > 0 && slots.length > MAX_WAYS + 1; j--) if (!slots[j].id) slots.splice(j, 1); // drop empty placeholders, never his answers
    const spare = empty.slice();
    slots.forEach((sl, j) => {
      if (sl.id) { ops.push({ op: 'updateItem', id: sl.id, sort_order: j }); return; }
      const row = spare.shift();
      if (row) ops.push({ op: 'updateItem', id: row.id, question: sl.question, sort_order: j });
      else ops.push({ op: 'insertItem', group_id: g.id, question: sl.question, sort_order: j });
    });
    spare.forEach(row => ops.push({ op: 'deleteEmptyItem', id: row.id }));
  });
  (groups || []).filter(g => !used.has(g.id)).sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0))
    .forEach((g, k) => ops.push({ op: 'updateGroup', id: g.id, sort_order: S.length + k }));
  return ops;
}

// ---- HTML safety: the answer is stored as the editor's HTML (his formatting). Only formatting tags survive;
// scripts, handlers and javascript: links never do. Applied at the route door on every write.
const ALLOWED_TAGS = /^(b|strong|i|em|u|s|strike|p|div|br|ul|ol|li|h1|h2|h3|h4|span|font|pre|code|blockquote|a|sup|sub|mark|hr|table|thead|tbody|tr|th|td|img)$/i;
// an image is only a pasted picture (data:image) or an https link; anything else (javascript:, data:text/html) is dropped
const SAFE_IMG = /^(data:image\/(png|jpeg|gif|webp);base64,[a-z0-9+\/=]+|https:\/\/[^\s"'<>]+)$/i;
function sanitizeHtml(html) {
  let s = String(html || '');
  s = s.replace(/<!--[\s\S]*?-->/g, '');
  s = s.replace(/<(script|style|iframe|object|embed|form|input|textarea|button|meta|link)\b[\s\S]*?(<\/\1\s*>|$)/gi, '');
  s = s.replace(/<\/?([a-z0-9]+)([^>]*)>/gi, (m, tag, attrs) => {
    if (!ALLOWED_TAGS.test(tag)) return '';
    if (m.startsWith('</')) return `</${tag.toLowerCase()}>`;
    const kept = [];
    const re = /([a-z-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s"'>]+)/gi; let a;
    while ((a = re.exec(attrs || ''))) {
      const name = a[1].toLowerCase(), val = a[2].replace(/^["']|["']$/g, '');
      if (/^on/.test(name)) continue;
      if (name === 'href' && !/^(https?:|mailto:)/i.test(val.trim())) continue;
      if (name === 'src' && !(tag.toLowerCase() === 'img' && SAFE_IMG.test(val.trim()))) continue;
      if (!/^(style|class|href|color|size|face|align|src|alt|colspan|rowspan|width)$/.test(name)) continue;
      if (name === 'style' && /expression|javascript:|url\(/i.test(val)) continue;
      kept.push(`${name}="${val.replace(/"/g, '&quot;')}"`);
    }
    if (tag.toLowerCase() === 'img' && !kept.some(k => k.startsWith('src='))) return ''; // an image with no safe source is dropped whole
    return `<${tag.toLowerCase()}${kept.length ? ' ' + kept.join(' ') : ''}>`;
  });
  return s;
}

const htmlToText = NoteMatch.htmlToText; // one copy, shared with the page (public/note-match.js)
function escapeHtml(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

// The writer's live layout ("• line", "▸ At X" heading, "↳ At X — proof", ```code```) → editor HTML the user can
// then format. Bullets become a real list so Shorter / reorder / copy keep working on lines.
function answerToHtml(text) {
  const lines = String(text || '').replace(/\r/g, '').split('\n');
  const out = []; let list = []; let inCode = false; let code = [];
  const flush = () => { if (list.length) { out.push('<ul>' + list.map(l => `<li>${escapeHtml(l)}</li>`).join('') + '</ul>'); list = []; } };
  for (const raw of lines) {
    const t = raw.trim();
    if (/^```/.test(t)) { if (inCode) { out.push(`<pre>${escapeHtml(code.join('\n'))}</pre>`); code = []; inCode = false; } else { flush(); inCode = true; } continue; }
    if (inCode) { code.push(raw); continue; }
    if (!t) continue;
    if (/^▸/.test(t)) { flush(); out.push(`<h3>${escapeHtml(t.replace(/^▸\s*/, ''))}</h3>`); continue; }
    if (/^↳/.test(t)) { flush(); out.push(`<p class="emp">${escapeHtml(t.replace(/^↳\s*/, ''))}</p>`); continue; }
    if (/^(Situation|Task|Action|Result)\s*:/i.test(t)) { list.push(t); continue; }
    list.push(t.replace(/^[•\-*]\s+/, ''));
  }
  if (inCode) out.push(`<pre>${escapeHtml(code.join('\n'))}</pre>`);
  flush();
  return out.join('');
}

// The writer ends with "KEY: <one glance line>" — split it off the answer.
function parseGenerated(text) {
  const lines = String(text || '').replace(/\r/g, '').split('\n');
  let keyPoints = '';
  const body = [];
  for (const l of lines) {
    const m = l.match(/^\s*[•\-*]?\s*KEY(?: POINTS?)?\s*:\s*(.+)$/i);
    if (m && !keyPoints) { keyPoints = m[1].trim().slice(0, 160); continue; }
    body.push(l);
  }
  return { answer: body.join('\n').trim(), keyPoints };
}

// ---- Version history. ONE door for every content change (manual save, AI result, restore). The current content
// goes into `versions` BEFORE it is replaced, so nothing is ever lost; `version` is the row's change counter.
// A write that carries baseVersion from an older read is a CONFLICT (someone or the AI changed it since) — the route
// answers 409 with the live row and the user decides; nothing is overwritten silently.
function applyChange(item, next, who) {
  const cur = { answer_html: item.answer_html || '', key_points: item.key_points || '', version: item.version || 0, versions: Array.isArray(item.versions) ? item.versions : [] };
  if (next.baseVersion !== undefined && next.baseVersion !== null && Number(next.baseVersion) !== cur.version) {
    const err = new Error('This answer changed since you opened it'); err.code = 'CONFLICT'; throw err;
  }
  const answer_html = next.answer_html !== undefined ? sanitizeHtml(next.answer_html) : cur.answer_html;
  const key_points = next.key_points !== undefined ? String(next.key_points || '').slice(0, 160) : cur.key_points;
  if (answer_html === cur.answer_html && key_points === cur.key_points) return { changed: false, answer_html, key_points, version: cur.version, versions: cur.versions };
  const versions = cur.versions.slice();
  if (cur.answer_html || cur.key_points) { // an empty answer has nothing worth keeping
    versions.push({ id: `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`, ts: new Date().toISOString(), by: item.edited_by || 'you', label: item.edit_label || '', html: cur.answer_html, keyPoints: cur.key_points, version: cur.version });
    while (versions.length > MAX_VERSIONS) versions.shift();
  }
  return { changed: true, answer_html, key_points, version: cur.version + 1, versions, edited_by: who.by || 'you', edit_label: who.label || '' };
}
function restoreVersion(item, versionId) {
  const v = (item.versions || []).find(x => x.id === versionId);
  if (!v) { const err = new Error('That version is gone'); err.code = 'NOT_FOUND'; throw err; }
  return applyChange(item, { answer_html: v.html, key_points: v.keyPoints }, { by: 'restore', label: 'Restored ' + (v.by === 'ai' ? 'an AI version' : 'your version') });
}

// ---- AI buttons → the change the writer is asked for. One place; the page only sends the mode.
const MODES = {
  regenerate: { label: 'Regenerated', instruction: '' },
  shorter: { label: 'Shorter', instruction: 'Rewrite the CURRENT ANSWER shorter: at most half the lines (never fewer than 2), keep the facts and the strongest real number, drop the rest.' },
  number: { label: 'Added a number', instruction: 'Rewrite the CURRENT ANSWER keeping its lines, and work in ONE real number or one concrete example from the résumé or Q&A bank where it fits best. Never invent a number — if there is no real number for this question, add the most concrete real detail there is instead.' },
  natural: { label: 'Made it sound like me', instruction: 'Rewrite the CURRENT ANSWER so it sounds like the candidate actually talking: contractions, everyday words, shorter sentences, no polish or buzzwords. Same facts, same number of lines or fewer.' },
  custom: { label: 'Changed as asked', instruction: '' },
  rich: { label: 'Study note', instruction: '' }, // its own writer (server.js generateStudyNote): HTML with tables and a diagram
};
function changeInstruction(mode, custom) {
  const m = MODES[mode] || MODES.regenerate;
  if (mode === 'custom') return String(custom || '').trim().slice(0, 600);
  return m.instruction;
}
function changeLabel(mode, custom) { return mode === 'custom' ? ('AI: ' + String(custom || '').trim().slice(0, 60)) : (MODES[mode] || MODES.regenerate).label; }

const searchNote = NoteMatch.searchNote; // shared with the page

// ---- Order: a reorder request may only permute the ids that exist (a stale or foreign id is ignored, nothing lost).
function reorderIds(existingIds, requestedIds) {
  const have = new Set(existingIds);
  const out = []; const seen = new Set();
  for (const id of requestedIds || []) if (have.has(id) && !seen.has(id)) { out.push(id); seen.add(id); }
  for (const id of existingIds) if (!seen.has(id)) out.push(id);
  return out;
}

const sortGroups = NoteMatch.sortGroups; // shared with the page

// ---- Questions from a call → new note questions. A question already in the note is skipped and named, never added
// twice: the call notes say which note question it IS (sameAs, decided by the writer: wording alone cannot tell), and a
// near-identical wording (the same call added again, or twice in one batch) is caught here too. Each one: short title + the full question + up to
// MAX_WAYS rewordings. Strings only; anything else is dropped.
const SAME_QUESTION = NoteMatch.SAME_QUESTION;
function questionsToAdd(groups, questions) {
  const clean = v => String(v || '').replace(/\s+/g, ' ').replace(/\u2014/g, ', ').trim();
  const pool = (groups || []).map(g => ({ id: g.id, name: g.name, items: (g.items || []).map(i => ({ id: i.id, question: i.question })) }));
  const add = [], skipped = [];
  for (const q of Array.isArray(questions) ? questions.slice(0, 40) : []) {
    const question = clean(q && q.question).slice(0, 500);
    if (question.length < 8) continue;
    const same = q.sameAs && q.sameAs.id && pool.find(x => x.id === q.sameAs.id);
    if (same) { skipped.push({ question, inNote: same.name }); continue; }
    const hit = NoteMatch.closest(pool, question, SAME_QUESTION);
    if (hit) { const g = pool.find(x => x.id === hit.groupId); skipped.push({ question, inNote: g ? g.name : hit.question }); continue; }
    const ways = (Array.isArray(q.ways) ? q.ways : []).map(w => clean(w).slice(0, 500)).filter(w => w.length >= 8 && w.toLowerCase() !== question.toLowerCase()).slice(0, MAX_WAYS);
    const title = (clean(q.title) || question).slice(0, 60);
    const items = [question].concat(ways);
    add.push({ title, items });
    pool.push({ id: 'new' + add.length, name: title, items: items.map((x, k) => ({ id: 'new' + add.length + '-' + k, question: x })) });
  }
  return { add, skipped };
}

module.exports = { SEED, MAX_WAYS, seedRows, upgradePlan, additionsPlan, questionsToAdd, sanitizeHtml, htmlToText, answerToHtml, parseGenerated, applyChange, restoreVersion, MODES, changeInstruction, changeLabel, searchNote, reorderIds, sortGroups, closest: NoteMatch.closest, MAX_VERSIONS };
