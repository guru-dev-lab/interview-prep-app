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

// ---- repeat: the 9 Oct doubles are one question
ok(mc.sameAsk('What would you take into consideration for breaking those ties?', 'What would you take into consideration for breaking those ties?'), 'same words');
ok(mc.sameAsk('What is it that you\'re looking to measure?', 'What what is it that you\'re looking to measure?'), 'stutter is the same ask');
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
ok(/\(info page, nothing to answer/.test(p2) && p2.split('Welcome to Project Vantage').length < 10, 'older info page compacted');
ok(/Atlanta \| 60/.test(p2) && /Q5 pick one/.test(p2), 'data and question pages whole');
ok(mc.screenType('no type line here') === 'DATA', 'old transcripts count as data (kept whole)');
// talk the digest covers is not repeated word for word
const talk = []; for (let i = 0; i < 40; i++) talk.push(row('asker', 'narration line ' + i, i));
const p3 = mc.buildCopilotPrompt({ mode: 'smart', rows: talk, digest: 'NOTES', digestUpTo: 35, session: {} });
ok(!/narration line 5\b/.test(p3) && /narration line 30/.test(p3) && /narration line 39/.test(p3), 'only post-digest talk (+6 overlap) rides raw');
const p4 = mc.buildCopilotPrompt({ mode: 'smart', rows: talk, session: {} });
ok(/narration line 0\b/.test(p4), 'no digest → all talk rides (nothing lost)');

console.log(`copilot-ask-gate: ${n} checks\nALL PASS (heard asks gated, repeats point at their card, ledger whole, compact non-questions)`);
