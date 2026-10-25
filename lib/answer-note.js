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

// ---- Detailed answers (owner, 24 Oct: "some questions required good details... that human and slow word for word
// start"). Only the SHAPE of the example he showed is used here: the journey, proof, one real example, the bridge to
// this job, how they work with people, and a close aimed at the company. Never its wording (owner: "never use that original"). The seed marks which questions need it ("detail")
// and which path they follow; everything else stays short bullets.
const DETAIL_ARCS = {
  intro: `1. Who I am: my title, my years, and the journey through my employers in order, one short line each.
2. My core strength: the skill this job needs most, a certification if the resume has one, and two real numbers that prove it.
3. One recent, concrete example from my work, specific enough to picture: what I built, how, and what it changed.
4. What I am doing now that is newest or most in demand for this job: a tool or platform the job description asks for that the resume shows.
5. The bridge: the part of this job I most want to grow in, with proof from an earlier role.
6. How I work with people: I ask what decision they are trying to make. One short real example where what was asked and what was needed differed (only if the resume or Q&A bank has one; otherwise describe the habit plainly).
7. Close: one line that sums up who I am, then what this company does and what I would give their team from day one.`,
  role: `1. What this role is really about, in my words: the top needs of the job description.
2. Why it fits where my career has been going: my journey in two lines.
3. Two proofs I can do the core of it, with real numbers.
4. The part that excites me most and why, tied to something I have done.
5. Close: what I would bring to the team in the first months.`,
  company: `1. What the company does and who it serves, only as the job description says it. Never invent news, numbers or facts about the company.
2. What this team seems to be working on, read from the job description.
3. Why that matters to me, tied to my own work.
4. Close: how my experience plugs straight into it.`,
  hire: `1. One line: the problem they are hiring for, and that I have solved it before.
2. Three reasons, one short paragraph each: a strength this job needs, then the real proof (employer, what I did, the number).
3. Close: what working with me looks like from day one.`,
  story: `1. The situation: where I was, who was involved, what was at stake.
2. The problem, in one clear line.
3. What I did, step by step, in the first person: specific actions and how I talked to people.
4. The result, with a real number if the resume or Q&A bank has one.
5. What I learned, or what I do differently now.
Use one real situation from the resume or Q&A bank. If none fits exactly, use the closest real experience and tell it honestly.`,
  walk: `1. The ask: who needed it and what decision it supported.
2. The data: the sources and what was messy about them.
3. The build: the model or pipeline, the key design choices and why, the tools by name.
4. The checks: how I made sure the numbers were right.
5. The rollout: how people started using it.
6. The result, with a real number.
Use one real project from the resume or Q&A bank.`,
};
const DETAIL_BY_TITLE = {};
SEED.groups.forEach(g => { if (g.detail && DETAIL_ARCS[g.detail]) { DETAIL_BY_TITLE[g.title.toLowerCase()] = g.detail; if (g.was) DETAIL_BY_TITLE[String(g.was).toLowerCase()] = g.detail; } });
function detailFor(groupName) { return DETAIL_BY_TITLE[String(groupName || '').trim().toLowerCase()] || ''; }
// ---- The best way to answer (owner, 24 Oct: "make the app smartest to pick best way to answer"). Every question, not
// only the seed's, gets a form: short spoken lines, a detailed spoken path (DETAIL_ARCS), or "explain" (the study
// note: table + flow diagram). The seed's own marks win; anything else is decided once by the fast model.
const FORMS = ['short', 'intro', 'role', 'company', 'hire', 'story', 'walk', 'explain'];
// Every line he may read out must be the words themselves (see dropStageTalk).
const READ_ALOUD = 'Every line is exactly what they say, ready to read out word for word in a fast interview: never a line about saying it ("I would say", "I\'ll say", "I\'ll mention", "Mention that", "Talk about"); start straight with the words. Short sentences, easy to read at a glance.';
// Live coach (owner 24 Oct): "whats best to say based on the meeting.. especially when they asked question and there is
// something they might be looking for.. should be on the Note like subtitle and goes and come when need". One line on
// what they are really testing, one line to say that shows it. Nothing when the question is plain (no lecture: the
// old "also hit" points were dropped for lecturing instead of saying what to say).
const COACH_PROMPT = `You coach a job candidate live, during the call, one line at a time. You get what the interviewer said leading up to now, their question, and, once the candidate has started answering, what the candidate has said so far.
Reply with exactly two lines:
WANT: <at most 10 words: what they are really after, or why this line now>
SAY: <the very next thing to say out loud, first person, each sentence at most 14 words. Usually ONE sentence. At most two: the second only when the first is thanks or something nice about them, or when the second is a written resume number that proves the first. Never a third, never filler>
or the single word NONE.
What SAY is (owner: "just what I should say or add to what I am actually saying... even it means throwing in jokes, or greeting, or thanking them before going into my details"):
- Before the answer (nothing said yet): the best way to open. Be human first when it fits: thank them for the question or for explaining; when they spent time describing their company, team, product or the role, say something specific and genuinely nice about what they just said, before any of your own details; a greeting at the start of the call; a light, friendly line or small joke when the mood is relaxed. When none of that fits, the strongest first line of the answer.
- While the candidate is answering: the one thing to add next that they have not said and that the interviewer is looking for (a real number, an example, a tie back to what the job needs). NONE if they already covered it.
Rules: facts about the candidate come only from the resume and Q&A bank: never invent a number, tool, employer, title, event or detail of what happened, and add nothing to a fact (name it as written). The resume and bank are the source of facts about the candidate's past, never of the method: for a technical how-would-you or design question, SAY names the exact technique, feature or pattern a senior expert would name for that problem (the term the interviewer listens for), even when an earlier bank answer describes it more loosely. Anything nice about the company uses only what the interviewer actually said. ${READ_ALOUD} Simple sentences, no semicolons.
Questions about how they work, fit, a gap, a concern or a choice always have something behind it (fully remote: can you work on your own and keep people in the loop; why are you leaving: are you running from something, will you stay). Always NONE for a start date, notice period, salary, pay, location or schedule (only the candidate can answer those, never guess them), a yes/no fact, a sound check, or not a question. Small talk (how is your day, how are you) gets a short warm reply only at the very start of the call, otherwise NONE.
No em dashes.`;
const FORM_GUIDE = `Pick the best way to answer this interview question in a prepared note the candidate reads from during the call. Reply with ONE word:
short: 3 or 4 short spoken lines. For logistics (salary, start date, notice, location, schedule), yes/no, a simple preference, one fact or a single definition, why they are leaving (best kept brief and positive), a weakness.
intro: tell me about yourself, walk me through your background, introduce yourself.
role: why this role, why this job, what they want next in their career.
company: about the EMPLOYER itself: what do you know about us, what do you think we do, what stands out about our company.
hire: why should we hire them, what sets them apart, their strengths or biggest strength (including what a manager or colleague would say their strength is).
story: asks for a real past situation: tell me about a time, give an example of when, describe a situation, how did you handle a specific case.
walk: asks them to walk through a specific thing they built or ran, end to end.
explain: the answer is a method with a clear order or ranking that a table or a step diagram makes easy to follow: a technical how, what or design question (a process, an architecture, how something works, a comparison of two approaches), or a question about HOW THEY WORK in general where the answer is their steps or their order of priority (how do you prioritize, what is your process when, how do you check or look into something). Not for an opinion or a style (leadership style, how AI is changing your work), a list of tools, or a single past situation.
Just the word.`;
function parseCoach(raw) {
  const line = k => ((String(raw || '').match(new RegExp('^\\s*' + k + '\\s*:\\s*(.+)$', 'im')) || [])[1] || '');
  const j = { want: line('WANT'), say: line('SAY') };
  // "role-level security" is not a thing; the model slips into it for row-level security
  const clean = (t, n) => dropStageTalk(String(t || '').replace(/\s*\u2014\s*/g, ', ').replace(/\brole[- ]level security\b/gi, 'row-level security').replace(/\s+/g, ' ').trim()).slice(0, n);
  const want = clean(j.want, 90);
  // Owner 24 Oct: "i want to see how multi line would be". Up to 2 sentences, one line each; each line is one breath.
  // (3 were measured: the model filled the third with invented detail and took 2 to 3 s.)
  const breath = t => {
    if (t.split(/\s+/).length > 16) t = t.replace(/,\s+(so|which|and|because|where)\s.*$/i, '.'); // loses its trailing ", so I'm..."
    if (t.split(/\s+/).length > 18) { // still long: end it at the first comma that leaves a full thought (6+ words)
      const w = t.split(/\s+/), k = w.findIndex((x, i) => i >= 5 && /,$/.test(x));
      if (k > 0) t = w.slice(0, k + 1).join(' ').replace(/,$/, '.');
    }
    return t;
  };
  // sentences split on . ! ? followed by a capital letter or a digit (so "e.g." or "3.5" never breaks a line)
  const lines = clean(j.say, 400).split(/(?<=[.!?])\s+(?=[A-Z0-9"'])/).map(t => breath(t.trim())).filter(Boolean).slice(0, 2);
  const say = lines.join(' ');
  // The model sometimes labels a plain question instead of answering NONE: nothing is shown then.
  const plain = t => /^none\b|\b(not a real (question|test)|small talk|sound check|plain question|no hidden)/i.test(t);
  return want && say && !plain(want) && !plain(say) ? { want, say, lines } : null;
}
function parseForm(raw) { const m = String(raw || '').toLowerCase().match(/\b(short|intro|role|company|hire|story|walk|explain)\b/); return m ? m[1] : 'short'; }
const FORM_LABEL = { short: 'Written short', intro: 'Written as a spoken intro', role: 'Written as a spoken answer', company: 'Written as a spoken answer', hire: 'Written as a spoken answer', story: 'Written as a spoken story', walk: 'Written as a walk-through', explain: 'Written as a study note' };

// Spoken paragraphs (blank-line separated) → <p> per paragraph; a stray bullet or heading mark is dropped.
function paragraphsToHtml(text) {
  return String(text || '').replace(/\r/g, '').split(/\n\s*\n/).map(p => p.split('\n').map(l => l.trim().replace(/^([•\-*]|#+)\s+/, '')).filter(Boolean).join(' '))
    .filter(Boolean).map(p => `<p>${escapeHtml(p)}</p>`).join('');
}

// Owner 24 Oct: "some people would just utter before the capture in a very fast pace interview" — he reads lines out as
// they are, so a line that TELLS him what to say ("I'll say this happened at R&L", "I would say my strength is",
// "Mention that...") comes out of his mouth word for word. Strip the stage words; the line keeps what to say.
const STAGE_TALK = /(^|<(?:li|p|td)>|[.!?]\s+)((?:[•\-*]\s*)?)(?:(?:I'd|I would|I'll|I will|I might|I'd probably|I would probably)\s+(?:say|mention|add|note|point out|start by saying|open with|lead with saying)|(?:Say|Mention|Note|Add|Point out|Explain)(?=\s+that\b))(?:\s+that)?[,:]?\s+(\w)/gm;
function dropStageTalk(text) {
  return String(text || '').replace(STAGE_TALK, (m, pre, bullet, ch) => pre + bullet + ch.toUpperCase());
}
// The writer ends with "KEY: <one glance line>" — split it off the answer.
function parseGenerated(text) {
  const lines = String(text || '').replace(/\r/g, '').replace(/\s*—\s*/g, ', ').split('\n'); // no em dashes in anything he reads (one place for every note writer)
  let keyPoints = '';
  const body = [];
  for (const l of lines) {
    const m = l.match(/^\s*[•\-*]?\s*KEY(?: POINTS?)?\s*:\s*(.+)$/i);
    if (m && !keyPoints) { keyPoints = m[1].trim().slice(0, 160); continue; }
    body.push(l);
  }
  return { answer: dropStageTalk(body.join('\n').trim()), keyPoints };
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

// Per job (owner 25 Oct): "Answer must be for that job except for some which are for the experience.. cos app can be
// used for someone interviewing for something that's not even data analyst at all". Two rules live here:
// 1. scope: a 'you' question (his own past, the same in every interview) keeps ONE answer; every other question keeps
//    one answer PER JOB. The app decides from the title; he can flip it (group.scope set).
// 2. role sections: questions about one kind of work (the seed's data sections, questions from one job's calls, the
//    ones built from a job description) show only for the jobs they were linked to (group.job_ids); the rest show for every job.
const YOU_TITLES = new Set(["why i'm leaving", 'what i want next', 'prioritizing', 'deadlines and pressure', 'great teamwork', 'a difficult person',
  'my work was challenged', 'leadership style', 'back to hands-on work', 'strengths', 'weakness', 'start date', 'other offers']);
const ROLE_SECTIONS = new Set(['dashboards and power bi', 'sql and pipelines', 'getting the numbers right']);
function scopeOf(g) { return g && (g.scope === 'you' || g.scope === 'job') ? g.scope : YOU_TITLES.has(String((g && g.name) || '').trim().toLowerCase()) ? 'you' : 'job'; }
function isRoleSection(section) { return ROLE_SECTIONS.has(String(section || '').trim().toLowerCase()) || /^from calls: /i.test(String(section || '')); }
function visibleFor(g, sessionId) { return !Array.isArray(g.job_ids) || (!!sessionId && g.job_ids.includes(sessionId)); }
// One call per job, the first time the note opens for it: which of his role questions this job would ask, and the
// questions this kind of job asks that he has none for yet.
const JOB_BUILD_PROMPT = `You prepare a candidate's interview note for ONE job. Read the job below.
Part 1: from the numbered ROLE QUESTIONS (written for other jobs), list the numbers an interviewer for THIS job would really ask. Only ones that fit this job's actual work; none is fine.
Part 2: add the questions an interviewer for THIS job is most likely to ask about the work itself (its skills, tools, daily situations, the hard parts of this kind of role) that neither the role questions you kept nor the GENERAL QUESTIONS already cover. 6 to 12, fewer if the job says little. Not general ones (about me, strengths, teamwork, salary): those are already in the note.
Group them under 1 to 3 short section names in plain words for this kind of work (e.g. "Patient care", "Selling and pipeline"). Each: a 2 to 5 word title, the question as an interviewer says it, and up to 3 other ways it gets asked.
Reply with JSON only: {"keep":[numbers],"add":[{"section":"...","title":"...","question":"...","ways":["..."]}]}`;
function parseJobBuild(raw, candidateCount) {
  let j = null; try { j = JSON.parse((String(raw || '').match(/\{[\s\S]*\}/) || [''])[0]); } catch (e) {}
  if (!j || (!Array.isArray(j.keep) && !Array.isArray(j.add))) return { ok: false, keep: [], add: [] }; // unreadable: the job is not marked done
  const keep = [...new Set((Array.isArray(j.keep) ? j.keep : []).map(n => parseInt(n, 10)).filter(n => n >= 1 && n <= candidateCount))];
  const add = (Array.isArray(j.add) ? j.add : []).map(a => ({
    section: String((a && a.section) || '').replace(/\s+/g, ' ').trim().slice(0, 60),
    title: String((a && a.title) || '').replace(/\s+/g, ' ').trim().slice(0, 60),
    question: String((a && a.question) || '').replace(/\s+/g, ' ').trim().slice(0, 300),
    ways: (Array.isArray(a && a.ways) ? a.ways : []).map(w => String(w || '').replace(/\s+/g, ' ').trim().slice(0, 300)).filter(Boolean).slice(0, MAX_WAYS),
  })).filter(a => a.section && a.question && !/^(new questions|from calls)/i.test(a.section)).slice(0, 12);
  return { ok: true, keep, add };
}

// Owner 25 Oct: "AI and agentic ai questions ... light but positive ... some good automation flow i can say i have used
// it for.. sounds real and heavy to ears". ONE rule for every writer (live, note, detailed).
const AI_RULE = `AI AND AGENTIC AI QUESTIONS (companies take these seriously): light, positive and confident. Never say "I haven't", "not yet", "to be honest/straight", never apologise or say it is not the AI answer they want. Answer with ONE concrete automation flow in plain steps: what kicks it off, what the AI or agent does, how a person checks it, what it saves. Build it on the candidate's REAL work from the resume (their real tasks, data, reports and users). If the resume, Q&A bank or earlier answers show AI or automation use, tell that as their own story with its real facts. If not, tell the flow confidently as how they put AI to work on that real task: no invented results, numbers, dates or product names (say "an AI assistant", "an agent"). Open with the flow itself, never with what was not done. Never credit AI with a real result the resume does not tie to AI (a number from other work stays with that work). This rule wins over any rule or step about telling missing experience honestly.`;

// Owner 25 Oct: "Your questions" (his questions for them) sit last, just before New questions. groups come in their
// saved order; everything else keeps it. Returns every id in the new order.
const YOUR_QUESTIONS = 'Your questions', NEW_QUESTIONS = 'New questions';
function yourQuestionsLast(groups) {
  const sec = g => String((g && g.section) || '');
  const rest = (groups || []).filter(g => sec(g) !== YOUR_QUESTIONS && sec(g) !== NEW_QUESTIONS);
  return rest.concat(groups.filter(g => sec(g) === YOUR_QUESTIONS), groups.filter(g => sec(g) === NEW_QUESTIONS)).map(g => g.id);
}

module.exports = { AI_RULE, YOUR_QUESTIONS, yourQuestionsLast, moveSection: NoteMatch.moveSection, scopeOf, isRoleSection, visibleFor, JOB_BUILD_PROMPT, parseJobBuild, SEED, MAX_WAYS, DETAIL_ARCS, detailFor, paragraphsToHtml, FORMS, FORM_GUIDE, parseForm, FORM_LABEL, seedRows, upgradePlan, additionsPlan, questionsToAdd, sanitizeHtml, htmlToText, answerToHtml, parseGenerated, dropStageTalk, READ_ALOUD, COACH_PROMPT, parseCoach, applyChange, restoreVersion, MODES, changeInstruction, changeLabel, searchNote, reorderIds, sortGroups, closest: NoteMatch.closest, MAX_VERSIONS };
