// Meeting co-pilot — pure logic (no DB, no model). server.js wires it; test/meeting-copilot.js proves it.
// Design: docs/superpowers/specs/2026-10-03-meeting-copilot-design.md

const KINDS = new Set(['asker', 'you', 'document', 'seen', 'said', 'digest']);
const REGULAR_VOICE_ROWS = 6;   // regular mode: last few voice lines only
const SMART_RAW_CHARS = 16000;  // smart mode: raw tail under the digest, by characters (~10 min of talk); 20 rows lost the
                                // first 40 s of a 76 s update at the first Assist (3 Oct)
const COMPACT_GAP_MS = 3 * 60 * 1000;
const SESSION_MATERIAL_CHARS = 6000; // résumé / JD / earlier-call notes each, when they ride along
const SMART_SCREENS_CHARS = 24000; // smart mode: full screen transcripts carried (deduped), oldest dropped past this

const isVoice = r => r.kind === 'asker' || r.kind === 'you';
const byTs = (a, b) => (a.ts || 0) - (b.ts || 0);
const last = (rows, kind) => rows.filter(r => r.kind === kind).sort(byTs).slice(-1);

// Regular mode: the last few voice lines, the latest screen summary, the latest card. No model picks anything.
function selectRegularRows(rows) {
  const voice = rows.filter(isVoice).sort(byTs).slice(-REGULAR_VOICE_ROWS);
  return voice.concat(last(rows, 'seen'), last(rows, 'said')).sort(byTs);
}

function label(r) {
  if (r.kind === 'asker') return 'Them: ' + r.text;
  if (r.kind === 'you') return 'You: ' + r.text;
  if (r.kind === 'seen') return 'Screen shown earlier: ' + r.text;
  if (r.kind === 'said') return 'Co-pilot already told you: ' + r.text;
  return null;
}

const MEETING_PROMPT = `You are a live MEETING CO-PILOT for one person on a work call. Other people on the call share their screen (tables, notes, documents, questions) and ask this person things. You hear the call and see the shared screen. Your job: tell this person what is being asked and why, what on the screen matters, and exactly what to say — fast, precise, in their voice.

OUTPUT — exactly this shape, nothing else:
Asked: <one line — what is being asked of this person and why they are showing this screen>
On screen: <the 1–3 facts from the shared screen that matter for the answer; cite real values, labels, rows>
Say:
  <one read-aloud sentence per line, 2–4 lines, plain spoken English>

CODE: when the answer is code, a formula, a query or a command (SQL, Python, Excel/Sheets formula, DAX, shell), put it in a fenced code block with the language (\`\`\`sql … \`\`\`), complete and exact, ready to paste — the overlay shows it in a code editor with a copy button. One plain line before it saying what it does; nothing inside the block but the code. The code must RUN AS WRITTEN on the stated engine and version: respect its types (on Postgres, date - date is already an integer of days — never EXTRACT from it; use CEIL(days / 30.0)), its units (a percent column may hold 2 or 0.02 — handle it and say which you assumed), its imports and its exact function names. Anything the task leaves unstated, state the assumption in the plain line above the block, never silently inside the code. A code fence always carries its language. Prose this person will PASTE or SEND (a prompt, an email, a memo, a message) is fenced as \`\`\`text — never as code and never bare, so the overlay shows it as readable text with a copy button. Say lines are never fenced: what is said out loud stays plain lines.

STRUCTURE: when the page or the ask carries numbered or listed items (a memo with questions 1–3, bullet points, a form's fields), answer in the SAME order with the SAME labels, one block each under Say. Each block, in this exact shape so he can scan it and speak:
**Page 7 — Question 1 — <what was asked>**
<the working: 1–3 short lines, numbers shown — do the arithmetic HERE, before you commit>
Result: <the result in one short line — the number, the name, the yes/no>
Every question on the page gets its block. "Result:" is always the last line of the block (the overlay lifts it to the top); never state a result before the working that produces it, and never correct yourself after it. Never merge them into one paragraph, never reorder, never skip one (say "need page X" for one you cannot answer).

If the ask is a TASK to do on screen (write a formula, run a query, filter, edit), the Say block becomes numbered steps with the exact thing to type. Otherwise Say is what to say out loud.

RULES:
- TOOL QUESTIONS ("what function would you use", "how do I do X in Excel/SQL/Sheets/Power BI"): give the exact function or formula to type, ready to paste, then one plain line on what it does — e.g. "=XLOOKUP(A2, Sheet2!A:A, Sheet2!C:C)" + "it finds A2 in Sheet2 column A and returns the matching value from column C". Never say "use a lookup"; the function name IS the answer. No jargon anywhere else unless the jargon is part of the answer they want to hear.
- PICTURE PUZZLES / RIDDLES: decode each picture literally (colour, object, direction), write the pieces down in On screen, then match the pieces ONLY against the options given on the screens (a list of names, choices). Never let an earlier conclusion pick the answer.
- CALCULATIONS: show the steps with the numbers in Say (pallets × rate → minimum → surcharge), then the result. Finish every step; never stop mid-calculation.
- If an earlier co-pilot answer (lines marked "Co-pilot already told you") conflicts with what the screens actually show, correct it and say so in one line — never carry a wrong number or name forward.
- EARLIER CALLS are background only: never take a table, a figure or a date from earlier-call notes to answer a question about a page that is not among the screens shown this call. If the page is missing, say "Page X was not captured — go back to it and press the camera" as the Result and stop that block. Never cite a screen you were not given.
- Read the screen for real: name the actual columns, numbers, labels you see. Never invent values. In On screen, every number you use must name the screen it came from (e.g. "SCREEN 2: Atlanta 60 pallets"); if a number you need is on no screen you were given, say which page you still need and stop — never fill it in. If no screen is given, work from the latest screen summary and the talk.
- Stay consistent with what this person already said on the call (lines marked "You:"); never contradict it and never repeat it back as new.
- Never speak as the other people, never quote their words back; answer as this person.
- If nothing is clearly being asked and nothing new is on screen, output exactly: Asked: nothing new — and stop. Never do this on a turn where the person PRESSED the button or TYPED an instruction — a press or a typed line always gets a real answer, and a typed line is done as written (an essay, a draft, a list), never judged as "not a real question".
- A PRESS with nothing open is answered HONESTLY, in this exact shape and nothing more:
  Asked: nothing open — checked <N> screen(s) and the last minute of talk
  On screen: <one line on what the screen shows>
  Say:
    Nothing is being asked right now; the last answer stands (<its subject in a few words>).
  Never invent a task to fill a press, never call a press a "continuation" of the last request, never redo an answer that was already finished (a query that ended with its semicolon is finished). A made-up task is worse than a short status.
- Short. No explanations of your reasoning. No headers other than the three above.`;

function modelFor(mode) { return mode === 'smart' ? 'sonnet' : 'haiku'; }
// Room to finish: page 8 of the pack (three carriers × minimum × surcharge) was cut off at 500 tokens (3 Oct).
// History mode: adaptive thinking shares this cap — 3 Oct an answer was cut at 727 chars after 7.9 s of thinking at 1200.
// Say in regular mode (Haiku) still has to hold a full code block + trade-off line: 700 cut code answers (owner, 3 Oct).
function maxTokensFor(mode, say) { return mode === 'smart' ? 8000 : (say ? 1500 : 700); } // 3 Oct 11:47: cut at Q5 with 4000 after 29.8 s of thinking
// Page transcripts are the material every later answer stands on: Sonnet, thinking off (owner, 3 Oct: Haiku misread).
function transcribeModelFor() { return 'sonnet'; }
function transcribeExtras() { return { thinking: { type: 'disabled' } }; }
// Measured 3 Oct on the 10-question Vendor Settlement battery: thinking off 10/10 (first words 0.6–0.9 s) vs adaptive
// low 10/10 — same accuracy; on the owner's real context (résumé + JD + 9 page transcripts) thinking blew first words to
// 13–30 s and once cut the answer. Off, explicitly (Sonnet thinks on its own otherwise).
function requestExtrasFor(mode) { return mode === 'smart' ? { thinking: { type: 'disabled' } } : undefined; }

// Build the user-turn text for one co-pilot call.
function buildCopilotPrompt(o) {
  const parts = [];
  const s = o.session || {};
  // The session is a hint, never a frame (owner, 3 Oct): a meeting may have nothing to do with the job this session is for
  if (s.role || s.company) parts.push('SESSION HINT — this person is set up here as ' + (s.role || 'a role') + (s.company ? ' at ' + s.company : '') + '. Use that only if this call is clearly about that job; otherwise ignore it and work from the call alone.');
  // Owner (3 Oct): the call is SOMETIMES about the session's job — then the résumé, the job description and what was
  // said on earlier calls of this session matter. Same gate: only when the call is clearly about that job.
  const mat = [];
  if (s.resume) mat.push('RESUME:\n' + String(s.resume).slice(0, SESSION_MATERIAL_CHARS));
  if (s.jd) mat.push('JOB DESCRIPTION:\n' + String(s.jd).slice(0, SESSION_MATERIAL_CHARS));
  if (o.bank && String(o.bank).trim()) mat.push('Q&A BANK (this person\'s real answers about themselves, in their words):\n' + String(o.bank).trim().slice(0, SESSION_MATERIAL_CHARS));
  if (o.priorMemory) mat.push('EARLIER CALLS IN THIS SESSION (notes):\n' + String(o.priorMemory).slice(0, SESSION_MATERIAL_CHARS));
  // Owner (3 Oct): "tell me about yourself" / "have you done this before" on a work call must come out TRUE to him — those are
  // never gated on the job; the rest of the material (JD, earlier calls) still is.
  if (mat.length) parts.push('SESSION MATERIAL:\n'
    + 'A question about THIS PERSON (tell me about yourself, your background, your experience, have you done/used X, your strengths, why you) is ALWAYS answered from the RESUME and Q&A BANK below, first person, true to them, whatever this call is about — never invent an employer, a tool, a year or a project they do not list; if neither holds it, say what the résumé does support and no more. '
    + 'Everything else here (job description, earlier calls) is used only if this call is clearly about that job; otherwise ignore it completely.\n\n' + mat.join('\n\n'));
  if (o.docs && String(o.docs).trim()) parts.push('REFERENCE MATERIAL THEY ATTACHED:\n' + String(o.docs).trim());

  const rows = (o.rows || []).slice().sort(byTs);
  if (o.mode === 'smart') {
    if (o.digest) parts.push('CALL SO FAR (compacted — everything that matters):\n' + o.digest);
    // Every screen shown this call, in full (smart mode transcribes each capture) — a later question often needs an
    // earlier page's table, which a compacted digest would flatten.
    let screens = dedupeScreens(rows.filter(r => r.kind === 'seen')).map((r, i) => 'SCREEN ' + (i + 1) + (r.meta && r.meta.key ? ' [' + r.meta.key + ']' : '') + ':\n' + r.text);
    while (screens.length > 1 && screens.join('\n\n').length > SMART_SCREENS_CHARS) screens.shift();
    if (screens.length) parts.push('SCREENS SHOWN THIS CALL (oldest first):\n' + screens.join('\n\n'));
    const labeled = rows.filter(r => r.kind !== 'seen' && label(r)).map(label);
    const tail = []; let chars = 0;
    for (let i = labeled.length - 1; i >= 0; i--) { if (chars + labeled[i].length > SMART_RAW_CHARS) break; chars += labeled[i].length + 1; tail.unshift(labeled[i]); }
    if (tail.length) parts.push('LATEST ON THE CALL (word for word, newest last):\n' + tail.join('\n'));
  } else {
    const sel = selectRegularRows(rows).map(label).filter(Boolean);
    if (sel.length) parts.push('JUST NOW ON THE CALL (newest last):\n' + sel.join('\n'));
  }

  const anySeen = rows.some(r => r.kind === 'seen');
  const reused = o.seenKey ? rows.filter(r => r.kind === 'seen' && r.meta && r.meta.key === o.seenKey).pop() : null;
  if (o.screenChanged) parts.push('A fresh capture of the shared screen is attached.');
  else if (reused) parts.push('The shared screen now shows a page captured earlier on this call — read it from this capture:\n' + reused.text);
  else if (anySeen) parts.push('The shared screen has NOT changed since the last capture — use the latest "Screen shown earlier" summary above.');
  else parts.push('No screen has been captured yet on this call — answer from the talk alone; put "On screen: (none yet)".');

  if (o.say) {
    // SAY (owner, 3 Oct): "answer what they just asked me, right now" — in his voice, with technical depth when the ask is technical
    const heard = String(o.ask || '').trim();
    parts.push('THEY JUST ASKED (this person pressed Say): ' + (heard ? '"' + heard + '"' : '(nothing caught word for word — answer the latest thing they said that needs a reply, from LATEST ON THE CALL / JUST NOW above)') + '\n'
      + 'Answer THAT, first person, as this person would say it out loud; "On screen:" may be "—" when the screen is not needed.\n'
      + 'If it is about this person → RESUME + Q&A BANK are the truth (see SESSION MATERIAL).\n'
      + 'If it is technical (how would you build/fix/do X, what would you use, walk me through) → under Say give, in this order: "Approach:" in 1–2 plain lines, then the exact code or numbered steps ready to paste (fenced, per CODE) covering EVERY part of the ask in the code itself (if they want the flags AND a per-carrier total, both are in the query — a CTE or a window SUM, never "you could also add"), then one line "Trade-off:" — what you would check first or what you give up. No filler.\n'
      + 'If it is a yes/no ("have you done this before") → answer yes/no from the material first, then the one concrete example that backs it; never a bare yes.');
  }
  else if (o.typed && String(o.ask || '').trim()) parts.push('THIS PERSON TYPED (their own instruction to you — do exactly this, now, as asked; it is not a meeting question to judge, and "nothing new" is never the answer to it):\n"' + String(o.ask).trim() + '"');
  else if (o.ask && String(o.ask).trim()) parts.push('JUST ASKED / NOTED:\n"' + String(o.ask).trim() + '"');
  if (o.pressed && !o.say && !(o.ask && String(o.ask).trim())) parts.push('This person PRESSED the co-pilot button with nothing typed — there IS something to answer right now: answer EVERY question found across the captured screens of this call (memos, numbered lists, questions in notes) that is not already answered in an earlier co-pilot card — grouped by page, in page order, one block each: "Page 7 — Question 1 — <what was asked>:" then its answer lines, "Page 7 — Question 2 — …", then "Page 8 — Question — …". Skip the ones already answered (lines marked "Co-pilot already told you"). If no screen holds a question, answer what the current screen or the last thing said is asking. If NOTHING is open — no unanswered question on any screen, nothing new said, the last card finished — use the honest press status (Asked: nothing open …; the last answer stands); never invent a task and never redo the last answer. Never answer "nothing new" on a press.');
  else if (o.pressed && !o.say) parts.push('This person PRESSED the co-pilot button: there IS something to answer right now — on the screen or in the last thing said — even if it was not phrased as a question. Find it and answer it; never answer "nothing new" on a press.');

  parts.push('Answer in the exact output shape.');
  return parts.join('\n\n');
}

// Screens captured twice (a hover, a tooltip, a scroll that settled on the same content) read the same: keep the first.
function dedupeScreens(rows) {
  const norm = t => String(t || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
  const kept = [];
  for (const r of rows) {
    const n = norm(r.text);
    const dup = kept.some(k => { const m = norm(k.text); if (!m || !n) return false; const a = new Set(m.split(' ')), b = new Set(n.split(' ')); let inter = 0; for (const w of a) if (b.has(w)) inter++; return inter / Math.max(a.size, b.size) >= 0.9; });
    if (!dup) kept.push(r);
  }
  return kept;
}

// Characters of raw talk/cards on the call (what the digest must cover when it does not fit word for word)
function rawCharsOf(rows) { return (rows || []).filter(r => r.kind !== 'seen' && r.kind !== 'digest' && label(r)).reduce((n, r) => n + label(r).length + 1, 0); }

// Smart-mode digest budget: history on, new rows since the last run, at least 3 minutes apart (first run immediately).
function shouldCompact(state, now) {
  if (!now.historyOn) return false;
  if ((now.rowCount || 0) <= (state.lastCount || 0)) return false;
  if (state.lastAt && now.now - state.lastAt < COMPACT_GAP_MS) return false;
  return true;
}

const DIGEST_PROMPT = `You keep compact running notes of ONE work call for the person we help. From the current notes and the new lines, return the full updated notes in these sections (short bullets, facts only, names/numbers exact):
THEY WANT — what the others on the call are asking for, worried about, deciding.
SHARED ON SCREEN — each table/document/note they showed, with the values that matter.
THIS PERSON SAID — what our person already stated or committed to (keep consistent with it).
CO-PILOT ALREADY TOLD THEM — the gist of each earlier answer.
OPEN — threads not yet settled.
Keep every line still true, sharpen what the new lines add to, drop only what is contradicted. Max 350 words.`;

// Smart mode: each captured screen is transcribed in the background (Haiku) so later questions can use the whole page.
const TRANSCRIBE_PROMPT = `Transcribe this shared screen for someone who cannot see it. Keep EVERY number, label, name and rule exactly. Tables → one line per row with the column names. Charts → each bar/point as "label: value". Pictures/puzzles/icons → describe each picture plainly (colour, object, direction) and what it likely means. Headings and notes verbatim. IGNORE browser tabs, bookmarks bars, address bars, menu bars, docks and window frames — transcribe only the content area (the document, table, slide or app the person is looking at). Plain text, no commentary, max 350 words.`;

// The overlay's captureFrame() returns RAW base64 (no data-URL prefix). Decide the media type from the bytes — a wrong
// label is rejected by the API ("specified as image/jpeg but appears to be image/png", 3 Oct).
function sniffImage(image) {
  const str = String(image || '');
  const data = str.replace(/^data:image\/[\w+.-]+;base64,/, '');
  if (!data) return { mediaType: 'image/jpeg', data: '' };
  let mediaType = 'image/jpeg';
  if (data.startsWith('iVBORw0KGgo')) mediaType = 'image/png';
  else if (data.startsWith('/9j/')) mediaType = 'image/jpeg';
  else if (data.startsWith('R0lGOD')) mediaType = 'image/gif';
  else if (data.startsWith('UklGR')) mediaType = 'image/webp';
  else { const m = str.match(/^data:(image\/[\w+.-]+);base64,/); if (m) mediaType = m[1]; }
  return { mediaType, data };
}

// Writer factory: records only on a LIVE call (callId present), only known kinds, only non-empty text.
function makeRecorder(pool) {
  return function recordCallEvent(sessionId, callId, kind, text, meta) {
    if (!sessionId || !callId) return false;
    if (!KINDS.has(kind)) return false;
    const t = String(text || '').trim();
    if (!t) return false;
    return pool.query(
      'INSERT INTO call_events (session_id, call_id, kind, text, meta) VALUES ($1, $2, $3, $4, $5)',
      [sessionId, callId, kind, t.slice(0, 4000), JSON.stringify(meta || {})]
    ).catch(e => { console.error('[CallLog] write failed:', e.message); return false; });
  };
}

module.exports = { KINDS, MEETING_PROMPT, DIGEST_PROMPT, TRANSCRIBE_PROMPT, sniffImage, dedupeScreens, SMART_SCREENS_CHARS, SMART_RAW_CHARS, rawCharsOf, selectRegularRows, buildCopilotPrompt, modelFor, maxTokensFor, requestExtrasFor, transcribeModelFor, transcribeExtras, shouldCompact, makeRecorder, COMPACT_GAP_MS, REGULAR_VOICE_ROWS };
