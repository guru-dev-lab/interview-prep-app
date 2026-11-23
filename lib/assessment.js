// Assessment (desktop only) — pure logic (no DB, no model). server.js wires it; test/assessment.js proves it.
// Owner, 13 Oct: an Assessment entry in the Electron app, not tied to any company. Each assessment keeps its own history;
// opening it again offers to CONTINUE the last one from a compacted carry of everything done so far; once there is
// content, the assessment is locked to a title taken from what it is about + the date/time it started.

// Who sees it. ONE place. Owner, 13 Oct: Admin, Premium and UAT Tester (plan 'test'). ASSESSMENT_PLANS (comma list)
// overrides the default without a deploy; "all" opens it to everyone. Admin accounts (is_admin) always see it.
const ASSESSMENT_DEFAULT_PLANS = ['admin', 'premium', 'test'];
function canUseAssessment(user, env) {
  const raw = String((env || {}).ASSESSMENT_PLANS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  if (raw.includes('all')) return true;
  const list = raw.length ? raw : ASSESSMENT_DEFAULT_PLANS;
  if (user && user.is_admin) return true;
  return list.includes(String((user && user.plan) || '').toLowerCase());
}

// 23 Nov, owner: "i want the session to always remember what it has been discussed or hear or answered or screenshorted or
// noted all together to get better and give correct answers". The carry used to see only the LAST 30 talk lines and was
// written as a test sheet: a 40-minute call lost every fact said early (fiscal year, currency, sign-off, deadline — 5/5
// forgotten in test/session-memory-e2e.js). Now it reads the whole sitting's talk and keeps FACTS & DECISIONS for good.
const CARRY_PROMPT = `You keep the MEMORY of ONE session a person works in with a live co-pilot: an online assessment (a test, an onboarding exam, a skills check) or work calls and meetings — sometimes both. These notes are ALL that a later sitting will know, so everything said, heard, shown on screen and answered that could matter later must be kept, letting the work continue exactly where it stopped, with no repeat and no contradiction.

Output exactly this shape:
TITLE: <3–8 words naming THIS session — the program/product/company/project it belongs to if known, then what it is about (e.g. "Project Vantage — Video Question Writing", "SQL Skills Check — Window Functions", "Northwind — Customer 360 Dashboard"). Never a generic title like "Assessment", "Meeting" or "Online Test".>
WHAT IT IS — 1–2 lines: who it is with / who runs it, what it is about, how it is judged if that is known.
FACTS & DECISIONS — every fact, number, date, deadline, name, owner, requirement, preference and agreement anyone stated (e.g. "fiscal year starts 1 April", "revenue in GBP", "Dana Whitfield signs off before the board", "build on vw_customer_360"), each on its own line, exact. NEVER drop one unless it was later changed (then keep the new one).
RULES & FORMAT — the rules that change an answer (time limits, attempts, required counts, what a correct answer must have, banned things), exact numbers. Omit when there are none.
THEY WANT / OPEN — what the others asked for, are worried about or still need; threads not settled.
DONE — one line per question/task already answered: "<page/question> — <what was asked> → <the answer given, exact>".
WHERE IT STOPPED — the last screen or question in progress and what is still open.
KEY MATERIAL — tables, figures, definitions, options or sample text a later question will need, values exact.

Repeated small talk or the same request said many times → one line. Facts only, from the material given; never invent a question, an answer, a fact or a rule. Keep EVERYTHING from the EARLIER NOTES that is still true (they are earlier sittings of the same session). Max 1,200 words.`;

// Material for one call's carry: earlier carry + this call's digest, screens (question/data whole, info pages short),
// every answered item, and the last of the talk. Bounded so the call stays cheap.
const TALK_CHARS = 60000, TALK_HEAD = 15000; // talk sent to the (once per sitting) memory writer
const MEMORY_CHARS = 12000; // memory carried into every answer of a later sitting (cached part)
function buildCarryInput(prevCarry, rows) {
  const parts = [];
  if (prevCarry) parts.push('EARLIER NOTES (from the sittings before this one):\n' + prevCarry);
  const r = (rows || []).slice().sort((a, b) => (a.ts || 0) - (b.ts || 0));
  const digest = r.filter(x => x.kind === 'digest').pop();
  if (digest) parts.push('RUNNING NOTES OF THIS SITTING:\n' + digest.text);
  const screens = []; let chars = 0;
  for (const s of r.filter(x => x.kind === 'seen').reverse()) { // newest first, so the bound drops the oldest
    const info = /^\s*TYPE:\s*INFO\b/i.test(s.text);
    const t = info ? String(s.text).replace(/\s+/g, ' ').slice(0, 300) : String(s.text).slice(0, 3000);
    if (chars + t.length > 14000) break;
    chars += t.length; screens.unshift(t);
  }
  if (screens.length) parts.push('SCREENS SEEN THIS SITTING (oldest first):\n' + screens.map((t, i) => 'SCREEN ' + (i + 1) + ':\n' + t).join('\n\n'));
  const said = r.filter(x => x.kind === 'said');
  if (said.length) parts.push('ANSWERS GIVEN THIS SITTING (oldest first):\n' + said.map(x => {
    const items = (x.meta && x.meta.answered) || [];
    return '- ' + (items.length ? items.join(' | ') + ' :: ' : '') + String(x.text).replace(/\s+/g, ' ').slice(0, 500);
  }).join('\n'));
  // ALL the talk of this sitting, oldest first (23 Nov: the last 30 lines lost every fact said early). A very long sitting
  // keeps its first part and its last part whole; the running notes above cover the middle.
  const talkLines = r.filter(x => x.kind === 'asker' || x.kind === 'you').map(x => (x.kind === 'you' ? 'You: ' : 'Heard: ') + x.text);
  let talk = talkLines.join('\n');
  if (talk.length > TALK_CHARS) talk = talk.slice(0, TALK_HEAD) + '\n… (middle of the talk: see RUNNING NOTES) …\n' + talk.slice(-(TALK_CHARS - TALK_HEAD));
  if (talk) parts.push('EVERYTHING SAID THIS SITTING (oldest first):\n' + talk);
  return parts.join('\n\n');
}

// Is there anything worth carrying? (an opened-then-closed sitting has nothing — it must not get a title). 23 Nov, owner:
// "not save unless there is transcribe or anything at all" — a real conversation counts (TALK_MIN_LINES lines), a stray
// word picked up by the mic does not.
const TALK_MIN_LINES = 5;
function hasMaterial(rows) {
  const r = rows || [];
  return r.some(x => x.kind === 'seen' || x.kind === 'said' || x.kind === 'digest') || r.filter(x => x.kind === 'asker' || x.kind === 'you').length >= TALK_MIN_LINES;
}

const GENERIC_TITLE_RE = /^(the )?(online |skills? |technical |coding )?(assessment|test|exam|quiz|evaluation)s?$/i;
function parseCarry(out) {
  const text = String(out || '').trim();
  const m = text.match(/^\s*TITLE:\s*(.+)$/mi);
  let title = m ? m[1].trim().replace(/^["'*]+|["'*.]+$/g, '').slice(0, 120) : '';
  if (GENERIC_TITLE_RE.test(title)) title = '';
  const notes = text.replace(/^\s*TITLE:.*$/mi, '').trim();
  return { title, notes };
}

module.exports = { ASSESSMENT_DEFAULT_PLANS, canUseAssessment, CARRY_PROMPT, buildCarryInput, hasMaterial, parseCarry, TALK_MIN_LINES, MEMORY_CHARS };
