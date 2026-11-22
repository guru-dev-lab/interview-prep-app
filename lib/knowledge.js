// Add info (owner, 23 Nov 2026) — pure logic (no DB, no model). server.js wires it; test/knowledge.js proves it.
// He gives a session what it should know — an existing query, a table and its fields, steps, a doc, a screenshot — and
// every co-pilot suggestion in that session builds on it, for as long as he keeps using the session (saved in the DB,
// so a reload, a new sitting or an app restart keeps them). The old ⚙ Files lived only in the open window.

const ITEM_MAX_CHARS = 30000;   // one item (a long doc is cut, never refused)
const ITEMS_MAX = 30;           // items per session
const KNOWLEDGE_PROMPT_CHARS = 60000; // all items together in one co-pilot call (newest kept whole first if over)

// A plain title from what he gave: the file name, else the first real line, else what it looks like.
function makeTitle(text, fileName) {
  const f = String(fileName || '').trim();
  if (f) return f.slice(0, 120);
  const t = String(text || '');
  if (/^\s*(with\s+\w+\s+as\s*\(|select\b|insert\b|update\b|create\b|alter\b)/i.test(t)) {
    const from = t.match(/\b(?:from|into|update|table)\s+([\w.\[\]"`]+)/i);
    return ('Query' + (from ? ' — ' + from[1].replace(/[\[\]"`]/g, '') : '')).slice(0, 120);
  }
  const line = t.split('\n').map(s => s.trim()).find(s => s.length > 0) || 'Info';
  return line.length > 60 ? line.slice(0, 57).trimEnd() + '…' : line;
}

function cleanBody(text) {
  return String(text || '').replace(/\r\n/g, '\n').replace(/\u0000/g, '').trim().slice(0, ITEM_MAX_CHARS);
}

// The block every co-pilot call carries. Oldest first (the order he added them); if the whole set is over the budget the
// OLDEST items are cut down first — what he added last is most likely what this meeting is about.
function buildKnowledgeBlock(notes, extra) {
  const list = (notes || []).filter(n => n && String(n.body || '').trim());
  const extraText = String(extra || '').trim();
  if (!list.length && !extraText) return '';
  let budget = KNOWLEDGE_PROMPT_CHARS;
  const kept = [];
  for (let i = list.length - 1; i >= 0; i--) { // newest first while budgeting
    const body = String(list[i].body).trim();
    const room = Math.max(0, budget);
    const b = body.length <= room ? body : (room > 400 ? body.slice(0, room) + '\n…(cut)' : '');
    budget -= b.length;
    kept.unshift({ title: String(list[i].title || 'Info'), body: b });
  }
  const parts = kept.filter(k => k.body).map(k => `--- ${k.title} ---\n${k.body}`); // no numbers: a card once said "their ITEM 1 query"
  if (extraText) parts.push(extraText);
  return parts.join('\n\n');
}

// How the info is used. ONE place (lib/meeting-copilot.js puts this ahead of the notes).
const KNOWLEDGE_RULE = 'INFO THEY ADDED — files and text this person gave you so you help them better in this session: their own queries, tables and fields, steps, docs. Treat it as true and current. '
  + 'Whenever the talk or the screen touches anything here, build on it: use the exact table, field, query, file and step names as written; when they are asked to change or extend something, change THEIR query/steps (show the changed version) instead of writing a new one; never contradict it. When you mention one, call it by what it is ("your query", "the ledger fields", "the plan vs actual table"), never by a number or as an item. '
  + 'Be supportive and simple: the easiest way first, plain words, short steps they can follow while talking.';

// A screenshot he adds is read ONCE into text (its exact content) so every later call can use it cheaply.
const IMAGE_READ_PROMPT = `Write out EVERYTHING in this image as plain text, exactly as shown, so someone who cannot see it has all of it.
- A table or grid: a markdown table with every column name and every visible row, values exact.
- A database / schema / field list: each table name, then each field with its type and notes if shown.
- Code or a query: the code verbatim in a fenced block.
- A form, dashboard or app screen: each label with its value, in reading order; name the app if it is shown.
- Anything else: the text in reading order.
No commentary, no summary, nothing that is not in the image.`;

module.exports = { ITEM_MAX_CHARS, ITEMS_MAX, KNOWLEDGE_PROMPT_CHARS, makeTitle, cleanBody, buildKnowledgeBlock, KNOWLEDGE_RULE, IMAGE_READ_PROMPT };
