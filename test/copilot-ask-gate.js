// Co-pilot heard-ask gate, repeat check, answered ledger, compaction (owner, 13 Oct). Free — no model, no DB.
// Lines are the real ones from his 12 Oct assessment (training video voice-over) and his 9 Oct work call.
const assert = require('assert');
const path = require('path');
const mc = require(path.join(__dirname, '..', 'lib', 'meeting-copilot.js'));
let n = 0; const ok = (c, m) => { n++; assert(c, m); };
const row = (kind, text, ts, meta) => ({ kind, text, ts, meta: meta || {} });

// ---- gate: the three voice-over lines that fired cards on 12 Oct are not asks
for (const q of [
  'Motion properties, which covers how motion changes, motion which tracks where motion goes, or symbolic and metaphorical',
  'When building options, ensure the correct answer is defensible',
  'Do you have at least',
  'Always filter your questions through this assigned category.',
]) ok(!mc.heardAskGate(q).ok, 'not an ask: ' + q);
// ---- gate: the real asks from his 9 Oct call still go through
for (const q of [
  'What do you want to do first, and can you walk me through the model?',
  'Can you give me the DAX needed to create a measure that would rank them?',
  'How would you adjust for that?',
  'Walk me through your process and approach there.',
  'Did you wanna declare a variable first maybe?',
  'Is there something here that you would use as a tiebreaker?',
]) ok(mc.heardAskGate(q).ok, 'an ask: ' + q);
// ---- gate: hands-on instructions in a tool are asks (12 Nov, Tableau walkthrough)
for (const q of [
  "Let's look at profit by region.",
  'Go ahead and drag Region onto columns.',
  'Now filter it to just the West region.',
  'Sort that from highest to lowest.',
]) ok(mc.heardAskGate(q).ok, 'a hands-on ask: ' + q);
// 12 Nov rehearsal: a lead-in word with its comma, and an instruction Deepgram closed before its last words, are still asks
for (const q of ['Great. Now break that down by sub-category.', 'Okay, put the map and the bar chart together on a dashboard.', 'Now break that down by subcategory and sort it from highest']) ok(mc.heardAskGate(q).ok, 'still an ask: ' + q);
for (const q of ['So what we usually do is', 'and then the numbers from the']) ok(!mc.heardAskGate(q).ok, 'a cut-off fragment is not: ' + q);
for (const q of ["What's the difference between a dimension and a measure?", 'Tell me a little bit about yourself and your background.', 'Do you have any questions for me?', 'What do the blue and green pills mean?', 'Now break that down by sub-category.']) ok(mc.judgeOverride(q, 'NOT: rhetorical question'), 'a direct ask goes through a wrong NOT: ' + q);
ok(mc.judgeOverride("Okay. So you have Tableau Public open with the Superstore data. Let's look at which sub-categories are losing money.", 'NOT: narration/instructions setting up a scenario for the person to follow.'), 'a real "let\'s look at" ask goes through a bare narration NOT');
ok(!mc.judgeOverride("Let's look at the data model next.", 'NOT: narration from a video tutorial'), 'a video voice-over stays NOT');
ok(!mc.judgeOverride('Do you have at least eight distractors? If so, you are ready to submit.', 'NOT: instructions or a checklist being read out'), 'a checklist read out stays NOT');
ok(!mc.judgeOverride('Hi, can you hear me okay? Give me one second.', 'NOT: small talk'), 'small talk stays NOT');
ok(!mc.judgeOverride('Hmm, okay. Sorry, let me just pull up my notes here.', 'NOT: small talk'), 'pulling up notes stays NOT');
ok(!mc.judgeOverride('Sarah, can you share the deck?', 'NOT: a question to someone else by name'), 'a question to someone else stays NOT');
ok(/ONE ask/.test(mc.HEARD_ASK_JUDGE) && /sense of the work on the call/.test(mc.HEARD_ASK_JUDGE), 'judge: a narrowing follow-up is one ask; words read in the call\'s sense');
ok(/HANDS-ON IN A TOOL/.test(mc.MEETING_PROMPT) && !/tableau|superstore/i.test(mc.MEETING_PROMPT.slice(mc.MEETING_PROMPT.indexOf('HANDS-ON'), mc.MEETING_PROMPT.indexOf('RULES:'))), 'hands-on rule is general: no tool or dataset hard-coded');
ok(/hands-on in a tool[\s\S]*never fenced/i.test(mc.buildCopilotPrompt({ mode: 'regular', rows: [], session: {}, ask: 'Show me sales by region.', say: true, pressed: true })), 'Say on a build ask uses the build recipe, steps not fenced');
ok(/HANDS-ON IN A TOOL shape/.test(mc.buildCopilotPrompt({ mode: 'regular', rows: [], session: {}, ask: 'Show me sales by region.' })), 'every turn carries the hands-on reminder');

// ---- repeat: the 9 Oct doubles are one question
ok(mc.sameAsk('What would you take into consideration for breaking those ties?', 'What would you take into consideration for breaking those ties?'), 'same words');
ok(mc.sameAsk('What is it that you\'re looking to measure?', 'What what is it that you\'re looking to measure?'), 'stutter is the same ask');
ok(!mc.sameAsk('Filter the superstore data in Tableau Public to show which subcategories are losing money in just the west region.', 'Which subcategories are losing money?'), 'a narrowing follow-up is a new ask (12 Nov)');
ok(mc.sameAsk('Okay so can you tell me which subcategories are losing money?', 'Which subcategories are losing money?'), 'a lead-in on the same ask is a repeat');
ok(!mc.sameAsk('How would you adjust for that?', 'Can you give me the DAX needed to create a measure that would rank them?'), 'different asks stay different');
const asked = [{ text: 'Is there something that you would do to ensure that you know the data is right?', cardId: 'copilot-1' }];
ok(mc.findAnsweredAsk('Is there something that you would do to ensure that you know the data is right?', asked).cardId === 'copilot-1', 'repeat points at the earlier card');
ok(!mc.findAnsweredAsk('How would you adjust for that?', asked), 'a new ask is not a repeat');

// ---- judge plumbing: only a clear NOT skips
ok(!mc.judgeSaysAsk('NOT: video voice-over checklist'), 'NOT skips');
ok(mc.judgeSaysAsk('ASK'), 'ASK answers');
ok(mc.judgeSaysAsk('') && mc.judgeSaysAsk('ASK (judge timed out)'), 'empty / timeout answers (a miss costs more)');
const jin = mc.buildHeardAskJudgeInput('Do you have at least eight distractors?', [row('asker', 'Run this final checklist.', 1), row('asker', 'Is there exactly one correct answer supported by evidence?', 2)]);
ok(/Run this final checklist/.test(jin) && /THE LINE TO JUDGE/.test(jin), 'judge sees the lines before it');

// ---- ledger: every block title survives, not just the first 600 chars
const press = 'Asked: answer the open questions on pages 3–4\nOn screen: SCREEN 3 …\nSay:\n**Page 3 — Question 1 — Which option is defensible?**\n' + 'x'.repeat(700) + '\nResult: B\n**Page 4 — Question 2 — Write a distractor**\nworking\nResult: done\n';
const items = mc.answeredItems(press);
ok(items.length === 3 && /Page 4 — Question 2/.test(items[2]), 'ledger keeps the block past 600 chars: ' + JSON.stringify(items));
ok(mc.answeredItems('Asked: nothing open — checked 3 screen(s)\nSay: …').length === 0, 'an honest status answered nothing');
const rows = [row('seen', 'TYPE: QUESTION\nQ1 Which option is defensible?', 1, { key: 'a' }), row('said', press.slice(0, 600), 2, { ask: '', answered: items, cardId: 'copilot-9' })];
const p = mc.buildCopilotPrompt({ mode: 'smart', rows, session: {}, pressed: true });
ok(/ALREADY ANSWERED ON THIS CALL[\s\S]*Page 4 — Question 2/.test(p), 'press prompt lists what was already answered');
ok(/\[CUT OFF\]/.test(p) && /scroll so the whole question shows/.test(p), 'press prompt skips cut-off questions and says scroll');

// ---- compaction: older INFO pages ride as first lines; question/data pages and the current page ride whole
const info = 'TYPE: INFO\n' + 'Welcome to Project Vantage onboarding. '.repeat(40);
const rows2 = [row('seen', info, 1, { key: 'i1' }), row('seen', 'TYPE: DATA\nRegion | Sales\nAtlanta | 60', 2, { key: 'd1' }), row('seen', 'TYPE: QUESTION\nQ5 pick one', 3, { key: 'q1' })];
const p2 = mc.buildCopilotPrompt({ mode: 'smart', rows: rows2, session: {}, pressed: true });
ok(/— info page, nothing to answer \(index line/.test(p2) && p2.split('Welcome to Project Vantage').length < 10, 'older info page compacted');
ok(/Atlanta \| 60/.test(p2) && /Q5 pick one/.test(p2), 'data and question pages whole');
ok(mc.screenType('no type line here') === 'DATA', 'old transcripts count as data (kept whole)');
// talk the digest covers is not repeated word for word
const talk = []; for (let i = 0; i < 40; i++) talk.push(row('asker', 'narration line ' + i, i));
const p3 = mc.buildCopilotPrompt({ mode: 'smart', rows: talk, digest: 'NOTES', digestUpTo: 35, session: {} });
ok(!/narration line 5\b/.test(p3) && /narration line 30/.test(p3) && /narration line 39/.test(p3), 'only post-digest talk (+6 overlap) rides raw');
const p4 = mc.buildCopilotPrompt({ mode: 'smart', rows: talk, session: {} });
ok(/narration line 0\b/.test(p4), 'no digest → all talk rides (nothing lost)');

console.log(`copilot-ask-gate: ${n} checks\nALL PASS (heard asks gated, repeats point at their card, ledger whole, compact non-questions)`);
