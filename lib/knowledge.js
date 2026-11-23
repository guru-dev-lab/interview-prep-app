// Add info (owner, 23 Nov 2026) — pure logic (no DB, no model). server.js wires it; test/knowledge.js proves it.
// He gives a session what it should know — an existing query, a table and its fields, steps, a doc, a screenshot — and
// every co-pilot suggestion in that session builds on it, for as long as he keeps using the session (saved in the DB,
// so a reload, a new sitting or an app restart keeps them). The old ⚙ Files lived only in the open window.
//
// 23 Nov (2), owner: "should not have limit but the session should be able to compact and make things simple and not
// consume big cost using it". So: NO size cap on what he adds — the whole thing is kept. A LONG item (over COMPACT_OVER)
// is compacted ONCE when added (a short version with every name exact); every answer carries the short versions (cached)
// plus only the EXACT parts of the full text that match the question (picked by words, no model call, not cached).

const COMPACT_OVER = 12000;          // longer than this → compacted once; shorter → carried whole
const COMPACTS_PROMPT_CHARS = 80000; // all carried items together (short versions + short items), newest kept first
const DETAIL_CHARS = 12000;          // exact parts of long items picked for ONE question
const CHUNK_CHARS = 2500;
const NOT_READY_HEAD = 8000;         // a long item whose short version is still being written: its start meanwhile

// A plain title from what he gave: a real file name (with an extension), else what the content is (the SQL object it
// creates, the table a query reads), else its first real line. "downloaded-file-1795047840" tells him nothing.
function makeTitle(text, fileName) {
  const f = String(fileName || '').trim();
  if (f && /\.[a-z0-9]{1,5}$/i.test(f)) return f.slice(0, 120);
  const t = String(text || '');
  const obj = t.match(/\bcreate\s+(?:or\s+(?:alter|replace)\s+)?(view|table|procedure|proc|function)\s+([\w.\[\]"`]+)/i);
  if (obj) { const kind = { proc: 'Procedure' }[obj[1].toLowerCase()] || obj[1][0].toUpperCase() + obj[1].slice(1).toLowerCase(); return (kind + ' — ' + obj[2].replace(/[\[\]"`]/g, '')).slice(0, 120); }
  if (/^\s*(with\s+\w+\s+as\s*\(|select\b|insert\b|update\b|create\b|alter\b)/i.test(t)) {
    const from = t.match(/\b(?:from|into|update|table)\s+([\w.\[\]"`]+)/i);
    return ('Query' + (from ? ' — ' + from[1].replace(/[\[\]"`]/g, '') : '')).slice(0, 120);
  }
  const line = t.split('\n').map(s => s.trim()).find(s => s.length > 0) || 'Info';
  return line.length > 60 ? line.slice(0, 57).trimEnd() + '…' : line;
}

// Tidy only — nothing he gave is cut.
function cleanBody(text) {
  return String(text || '').replace(/\r\n?/g, '\n').replace(/\u0000/g, '').replace(/[ \t]+$/gm, '').replace(/\n{3,}/g, '\n\n').trim();
}

// What a file really is, from its bytes (a name may have no extension at all: "downloaded-file-1795047840" was a SQL view).
function sniffFile(buf, name) {
  const b = buf || Buffer.alloc(0);
  const head = b.subarray(0, 12).toString('latin1');
  if (head.startsWith('%PDF')) return 'pdf';
  if (b[0] === 0x89 && head.slice(1, 4) === 'PNG') return 'image';
  if (b[0] === 0xFF && b[1] === 0xD8) return 'image';
  if (head.startsWith('GIF8') || (head.startsWith('RIFF') && head.slice(8, 12) === 'WEBP')) return 'image';
  if (head.startsWith('PK')) return /\.docx?$/i.test(name || '') || b.includes('word/') ? 'docx' : 'binary';
  if (head.startsWith('\xD0\xCF\x11\xE0')) return /\.doc$/i.test(name || '') ? 'docx' : 'binary'; // old Office file
  const sample = b.subarray(0, 8000);
  let odd = 0;
  for (const c of sample) { if (c === 0) return 'binary'; if (c < 9 || (c > 13 && c < 32)) odd++; }
  return sample.length && odd / sample.length > 0.1 ? 'binary' : 'text';
}

const needsCompact = body => String(body || '').length > COMPACT_OVER;

// The short version of a long item, written ONCE when it is added.
const COMPACT_PROMPT = `Make a compact reference of the material below so a live co-pilot can answer questions about it WITHOUT the full text (the exact passages are looked up separately when a question needs them).
- Keep every name EXACTLY as written: databases, schemas, tables, views, columns, aliases, CTEs, parameters, files, sections, people, products.
- SQL / code: what it creates or does (object name + type); every source table/view with its alias and how they join (keys, join type); the filters (WHERE / HAVING) and grouping; each CTE/subquery by name and what it does; then the OUTPUT COLUMNS, one line each "name ← where it comes from / the calculation in brief". Group similar columns on one line when there are very many.
- Documents / notes / data: the facts, numbers, definitions, rules, steps and decisions, in the material's own words where it matters.
No commentary, no advice, nothing that is not in the material. Plain text. As short as possible while keeping every name; max ~2,500 words.`;

// The block every co-pilot call carries (stable → cached). Short items whole, long ones by their short version.
// Oldest first (the order he added them); over the budget, the OLDEST are dropped first.
function buildKnowledgeBlock(items, extra) {
  const list = (items || []).filter(n => n && String(n.body || '').trim());
  const extraText = String(extra || '').trim();
  if (!list.length && !extraText) return '';
  let budget = COMPACTS_PROMPT_CHARS;
  const kept = [];
  for (let i = list.length - 1; i >= 0; i--) { // newest first while budgeting
    const n = list[i], body = String(n.body).trim();
    let head, text;
    if (!needsCompact(body)) { head = `--- ${n.title} ---`; text = body; }
    else if (n.compact && String(n.compact).trim()) { head = `--- ${n.title} (long, ${body.length} characters: SHORT VERSION — the exact parts that match each question come with the question) ---`; text = String(n.compact).trim(); }
    else { head = `--- ${n.title} (long, ${body.length} characters: its START while the short version is written — the exact parts that match each question come with the question) ---`; text = body.slice(0, NOT_READY_HEAD); }
    if (text.length > budget) continue;
    budget -= text.length;
    kept.unshift(head + '\n' + text);
  }
  if (extraText) kept.push(extraText);
  return kept.join('\n\n');
}

// Words a question/talk points at: names split on _ . [ ] too ("net_rev_usd" → net_rev_usd, net, rev, usd).
const STOP = new Set('the and for with that this from what which where when how can you your our are was were will would should could does did has have had not but all any its into than then them they their there here about also just only more most some such very like make show give tell want need use using used get got let lets please okay yeah so do is it be to of in on at by an or if as we he she me my i a'.split(' '));
function termsOf(text) {
  const out = new Set();
  for (const raw of String(text || '').toLowerCase().match(/[a-z0-9_.\[\]]{3,}/g) || []) {
    const w = raw.replace(/[\[\]]/g, '').replace(/^\.+|\.+$/g, '');
    if (w.length >= 3 && !STOP.has(w)) out.add(w);
    for (const p of w.split(/[._]/)) if (p.length >= 3 && !STOP.has(p)) out.add(p);
  }
  return out;
}

// For ONE question: the parts of the long items' FULL text that match its words (whole lines, in file order). Free.
function pickDetail(items, query, maxChars) {
  const max = maxChars || DETAIL_CHARS;
  const q = termsOf(query);
  if (!q.size) return '';
  const cands = [];
  for (const n of items || []) {
    const body = String(n.body || '');
    if (!needsCompact(body)) continue; // short items ride whole already
    const lines = body.split('\n'); let cur = [], len = 0, idx = 0;
    const flush = () => {
      if (!cur.length) return;
      const text = cur.join('\n'), lc = text.toLowerCase(); let score = 0;
      for (const t of q) if (lc.includes(t)) score += t.length >= 6 ? 2 : 1;
      if (score) cands.push({ title: n.title, idx, text, score });
      idx++; cur = []; len = 0;
    };
    for (const l of lines) { cur.push(l); len += l.length + 1; if (len >= CHUNK_CHARS) flush(); }
    flush();
  }
  if (!cands.length) return '';
  const chosen = []; let used = 0;
  for (const c of cands.slice().sort((a, b) => b.score - a.score)) { if (used + c.text.length > max) continue; chosen.push(c); used += c.text.length; }
  const byTitle = {};
  for (const c of chosen.sort((a, b) => a.idx - b.idx)) (byTitle[c.title] = byTitle[c.title] || []).push(c.text);
  return Object.keys(byTitle).map(t => `--- exact parts of ${t} that match this question ---\n` + byTitle[t].join('\n…\n')).join('\n\n');
}

// How the info is used. ONE place (lib/meeting-copilot.js puts this ahead of the items).
const KNOWLEDGE_RULE = 'INFO THEY ADDED — files and text this person gave you so you help them better in this session: their own queries, tables and fields, steps, docs. Treat it as true and current. '
  + 'Whenever the talk or the screen touches anything here, build on it: use the exact table, field, query, file and step names as written; when they are asked to change or extend something, change THEIR query/steps (show the changed version) instead of writing a new one; never contradict it. When you mention one, call it by what it is ("your query", "the ledger fields", "the plan vs actual table"), never by a number or as an item. '
  + 'A long one is given as a SHORT VERSION; when a question needs exact lines, the matching EXACT PARTS of it come with the question — use those word for word. '
  + 'Be supportive and simple: the easiest way first, plain words, short steps they can follow while talking.';

// A screenshot he adds is read ONCE into text (its exact content) so every later call can use it cheaply.
const IMAGE_READ_PROMPT = `Write out EVERYTHING in this image as plain text, exactly as shown, so someone who cannot see it has all of it.
- A table or grid: a markdown table with every column name and every visible row, values exact.
- A database / schema / field list: each table name, then each field with its type and notes if shown.
- Code or a query: the code verbatim in a fenced block.
- A form, dashboard or app screen: each label with its value, in reading order; name the app if it is shown.
- Anything else: the text in reading order.
No commentary, no summary, nothing that is not in the image.`;

module.exports = { COMPACT_OVER, COMPACTS_PROMPT_CHARS, DETAIL_CHARS, makeTitle, cleanBody, sniffFile, needsCompact, COMPACT_PROMPT, buildKnowledgeBlock, termsOf, pickDetail, KNOWLEDGE_RULE, IMAGE_READ_PROMPT };
