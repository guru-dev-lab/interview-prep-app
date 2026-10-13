// Assessment (desktop only) — pure logic (no DB, no model). server.js wires it; test/assessment.js proves it.
// Owner, 13 Oct: an Assessment entry in the Electron app, not tied to any company. Each assessment keeps its own history;
// opening it again offers to CONTINUE the last one from a compacted carry of everything done so far; once there is
// content, the assessment is locked to a title taken from what it is about + the date/time it started.

// Who sees it. ONE place (owner: "only some profile type would see it but for now" everyone). ASSESSMENT_PLANS, when set
// (comma list, e.g. "pro,admin"), limits it to those plans; admins always see it.
function canUseAssessment(user, env) {
  const list = String((env || {}).ASSESSMENT_PLANS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  if (!list.length) return true;
  if (user && user.is_admin) return true;
  return list.includes(String((user && user.plan) || '').toLowerCase());
}

const CARRY_PROMPT = `You keep the carry-over notes for ONE online assessment a person is taking (a test, an onboarding exam, a skills check — screens with instructions and questions). These notes are all that a later sitting will know, so they must let the work continue exactly where it stopped, with no repeat and no contradiction.

Output exactly this shape:
TITLE: <3–8 words naming THIS assessment — the program/product/company it belongs to if shown, then what it tests (e.g. "Project Vantage — Video Question Writing", "SQL Skills Check — Window Functions"). Never a generic title like "Assessment" or "Online Test".>
WHAT IT IS — 1–2 lines: who runs it, what it tests, how it is scored.
RULES & FORMAT — the rules that change an answer (time limits, attempts, required counts, what a correct answer must have, banned things), exact numbers.
DONE — one line per question/task already answered: "<page/question> — <what was asked> → <the answer given, exact>".
WHERE IT STOPPED — the last screen or question in progress and what is still open.
KEY MATERIAL — tables, figures, definitions, options or sample text a later question will need, values exact.

Facts only, from the material given; never invent a question, an answer or a rule. Keep everything from the EARLIER NOTES that is still true. Max 450 words.`;

// Material for one call's carry: earlier carry + this call's digest, screens (question/data whole, info pages short),
// every answered item, and the last of the talk. Bounded so the call stays cheap.
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
  const talk = r.filter(x => x.kind === 'asker' || x.kind === 'you').slice(-30).map(x => (x.kind === 'you' ? 'You: ' : 'Heard: ') + x.text);
  if (talk.length) parts.push('LAST THINGS HEARD:\n' + talk.join('\n'));
  return parts.join('\n\n');
}

// Is there anything worth carrying? (an opened-then-closed sitting has nothing — it must not get a title)
function hasMaterial(rows) { return (rows || []).some(x => x.kind === 'seen' || x.kind === 'said' || x.kind === 'digest'); }

const GENERIC_TITLE_RE = /^(the )?(online |skills? |technical |coding )?(assessment|test|exam|quiz|evaluation)s?$/i;
function parseCarry(out) {
  const text = String(out || '').trim();
  const m = text.match(/^\s*TITLE:\s*(.+)$/mi);
  let title = m ? m[1].trim().replace(/^["'*]+|["'*.]+$/g, '').slice(0, 120) : '';
  if (GENERIC_TITLE_RE.test(title)) title = '';
  const notes = text.replace(/^\s*TITLE:.*$/mi, '').trim();
  return { title, notes };
}

module.exports = { canUseAssessment, CARRY_PROMPT, buildCarryInput, hasMaterial, parseCarry };
