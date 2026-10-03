// Meeting co-pilot — pure logic (no DB, no model). server.js wires it; test/meeting-copilot.js proves it.
// Design: docs/superpowers/specs/2026-10-03-meeting-copilot-design.md

const KINDS = new Set(['asker', 'you', 'document', 'seen', 'said', 'digest']);
const REGULAR_VOICE_ROWS = 6;   // regular mode: last few voice lines only
const SMART_RAW_ROWS = 20;      // smart mode: raw tail under the digest
const COMPACT_GAP_MS = 3 * 60 * 1000;

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
- Read the screen for real: name the actual columns, numbers, labels you see. Never invent values. If no screen is given, work from the latest screen summary and the talk.
- Stay consistent with what this person already said on the call (lines marked "You:"); never contradict it and never repeat it back as new.
- Never speak as the other people, never quote their words back; answer as this person.
- If nothing is clearly being asked and nothing new is on screen, output exactly: Asked: nothing new — and stop.
- Short. No explanations of your reasoning. No headers other than the three above.`;

function modelFor(mode) { return mode === 'smart' ? 'sonnet' : 'haiku'; }

// Build the user-turn text for one co-pilot call.
function buildCopilotPrompt(o) {
  const parts = [];
  const s = o.session || {};
  parts.push('THIS PERSON: ' + (s.role || 'their role') + ' at ' + (s.company || 'their company'));
  if (o.docs && String(o.docs).trim()) parts.push('REFERENCE MATERIAL THEY ATTACHED:\n' + String(o.docs).trim());

  const rows = (o.rows || []).slice().sort(byTs);
  if (o.mode === 'smart') {
    if (o.digest) parts.push('CALL SO FAR (compacted — everything that matters):\n' + o.digest);
    const tail = rows.filter(r => label(r)).slice(-SMART_RAW_ROWS).map(label);
    if (tail.length) parts.push('LATEST ON THE CALL (word for word, newest last):\n' + tail.join('\n'));
  } else {
    const sel = selectRegularRows(rows).map(label).filter(Boolean);
    if (sel.length) parts.push('JUST NOW ON THE CALL (newest last):\n' + sel.join('\n'));
  }

  if (o.screenChanged) parts.push('A fresh capture of the shared screen is attached.');
  else parts.push('The shared screen has NOT changed since the last capture — use the latest "Screen shown earlier" summary above.');

  if (o.ask && String(o.ask).trim()) parts.push('JUST ASKED / NOTED:\n"' + String(o.ask).trim() + '"');
  else if (o.pressed) parts.push('This person PRESSED the co-pilot button: there IS something to answer right now — on the screen or in the last thing said — even if it was not phrased as a question. Find it and answer it.');

  parts.push('Answer in the exact output shape.');
  return parts.join('\n\n');
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

module.exports = { KINDS, MEETING_PROMPT, DIGEST_PROMPT, selectRegularRows, buildCopilotPrompt, modelFor, shouldCompact, makeRecorder, COMPACT_GAP_MS, REGULAR_VOICE_ROWS, SMART_RAW_ROWS };
