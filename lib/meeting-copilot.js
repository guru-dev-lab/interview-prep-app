// Meeting co-pilot — pure logic (no DB, no model). server.js wires it; test/meeting-copilot.js proves it.
// Design: docs/superpowers/specs/2026-10-03-meeting-copilot-design.md

const KINDS = new Set(['asker', 'you', 'document', 'seen', 'said', 'digest']);
const REGULAR_VOICE_ROWS = 6;   // regular mode: last few voice lines only
const SMART_RAW_ROWS = 20;      // smart mode: raw tail under the digest
const COMPACT_GAP_MS = 3 * 60 * 1000;
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

If the ask is a TASK to do on screen (write a formula, run a query, filter, edit), the Say block becomes numbered steps with the exact thing to type. Otherwise Say is what to say out loud.

RULES:
- TOOL QUESTIONS ("what function would you use", "how do I do X in Excel/SQL/Sheets/Power BI"): give the exact function or formula to type, ready to paste, then one plain line on what it does — e.g. "=XLOOKUP(A2, Sheet2!A:A, Sheet2!C:C)" + "it finds A2 in Sheet2 column A and returns the matching value from column C". Never say "use a lookup"; the function name IS the answer. No jargon anywhere else unless the jargon is part of the answer they want to hear.
- PICTURE PUZZLES / RIDDLES: decode each picture literally (colour, object, direction), write the pieces down in On screen, then match the pieces ONLY against the options given on the screens (a list of names, choices). Never let an earlier conclusion pick the answer.
- CALCULATIONS: show the steps with the numbers in Say (pallets × rate → minimum → surcharge), then the result. Finish every step; never stop mid-calculation.
- If an earlier co-pilot answer (lines marked "Co-pilot already told you") conflicts with what the screens actually show, correct it and say so in one line — never carry a wrong number or name forward.
- Read the screen for real: name the actual columns, numbers, labels you see. Never invent values. In On screen, every number you use must name the screen it came from (e.g. "SCREEN 2: Atlanta 60 pallets"); if a number you need is on no screen you were given, say which page you still need and stop — never fill it in. If no screen is given, work from the latest screen summary and the talk.
- Stay consistent with what this person already said on the call (lines marked "You:"); never contradict it and never repeat it back as new.
- Never speak as the other people, never quote their words back; answer as this person.
- If nothing is clearly being asked and nothing new is on screen, output exactly: Asked: nothing new — and stop. Never do this on a turn where the person PRESSED the button — a press always gets a real answer.
- Short. No explanations of your reasoning. No headers other than the three above.`;

function modelFor(mode) { return mode === 'smart' ? 'sonnet' : 'haiku'; }
// Room to finish: page 8 of the pack (three carriers × minimum × surcharge) was cut off at 500 tokens (3 Oct).
function maxTokensFor(mode) { return mode === 'smart' ? 1200 : 700; }
// Smart mode: Sonnet with ADAPTIVE thinking at medium effort — measured 3 Oct on the puzzle page: 6/6 correct, first
// words 0.75–0.93 s (no slower than thinking disabled). Without any setting Sonnet thinks on its own: 4–8 s spikes.
// Page transcripts are the material every later answer stands on: Sonnet, thinking off (owner, 3 Oct: Haiku misread).
function transcribeModelFor() { return 'sonnet'; }
function transcribeExtras() { return { thinking: { type: 'disabled' } }; }
function requestExtrasFor(mode) { return mode === 'smart' ? { thinking: { type: 'adaptive' }, output_config: { effort: 'medium' } } : undefined; }

// Build the user-turn text for one co-pilot call.
function buildCopilotPrompt(o) {
  const parts = [];
  const s = o.session || {};
  parts.push('THIS PERSON: ' + (s.role || 'their role') + ' at ' + (s.company || 'their company'));
  if (o.docs && String(o.docs).trim()) parts.push('REFERENCE MATERIAL THEY ATTACHED:\n' + String(o.docs).trim());

  const rows = (o.rows || []).slice().sort(byTs);
  if (o.mode === 'smart') {
    if (o.digest) parts.push('CALL SO FAR (compacted — everything that matters):\n' + o.digest);
    // Every screen shown this call, in full (smart mode transcribes each capture) — a later question often needs an
    // earlier page's table, which a compacted digest would flatten.
    let screens = dedupeScreens(rows.filter(r => r.kind === 'seen')).map((r, i) => 'SCREEN ' + (i + 1) + (r.meta && r.meta.key ? ' [' + r.meta.key + ']' : '') + ':\n' + r.text);
    while (screens.length > 1 && screens.join('\n\n').length > SMART_SCREENS_CHARS) screens.shift();
    if (screens.length) parts.push('SCREENS SHOWN THIS CALL (oldest first):\n' + screens.join('\n\n'));
    const tail = rows.filter(r => r.kind !== 'seen' && label(r)).slice(-SMART_RAW_ROWS).map(label);
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

  if (o.ask && String(o.ask).trim()) parts.push('JUST ASKED / NOTED:\n"' + String(o.ask).trim() + '"');
  if (o.pressed) parts.push('This person PRESSED the co-pilot button: there IS something to answer right now — on the screen or in the last thing said — even if it was not phrased as a question. Find it and answer it; never answer "nothing new" on a press.');

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
const TRANSCRIBE_PROMPT = `Transcribe this shared screen for someone who cannot see it. Keep EVERY number, label, name and rule exactly. Tables → one line per row with the column names. Charts → each bar/point as "label: value". Pictures/puzzles/icons → describe each picture plainly (colour, object, direction) and what it likely means. Headings and notes verbatim. Plain text, no commentary, max 350 words.`;

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

module.exports = { KINDS, MEETING_PROMPT, DIGEST_PROMPT, TRANSCRIBE_PROMPT, sniffImage, dedupeScreens, SMART_SCREENS_CHARS, selectRegularRows, buildCopilotPrompt, modelFor, maxTokensFor, requestExtrasFor, transcribeModelFor, transcribeExtras, shouldCompact, makeRecorder, COMPACT_GAP_MS, REGULAR_VOICE_ROWS, SMART_RAW_ROWS };
