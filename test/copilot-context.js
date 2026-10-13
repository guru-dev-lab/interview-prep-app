// Co-pilot context tiers + cache order (owner, 13 Oct: smart, cheap, never lose data). Free — no model, no DB.
const assert = require('assert');
const path = require('path');
const mc = require(path.join(__dirname, '..', 'lib', 'meeting-copilot.js'));
let n = 0; const ok = (c, m) => { n++; assert(c, m); };
const seen = (key, text, ts) => ({ kind: 'seen', text, ts, meta: { key, full: true } });
const said = (answered, ts) => ({ kind: 'said', text: 'x', ts, meta: { answered, ask: '' } });

// the real page 5 of the pack, labelled INFO by the reader — it holds the rules
const P5 = 'TYPE: INFO\nPage 5 of 8\nFuel surcharge and assumptions\nRate above $80 per pallet → 12% surcharge\nRate $80 or below → 8% surcharge\nGrowth: the Dallas lane grows 20% in Q1';
const BARE = 'TYPE: INFO\nWelcome to the Northwind onboarding pack. Take your time and read each page carefully.';
const P7 = 'TYPE: QUESTION\nPage 7 of 8\nMemo from Priya\n1. Using the carrier from the puzzle, what is the monthly cost of the Chicago → Dallas lane at the page-2 volume, including the fuel surcharge?\n2. Which carrier has the best on-time on the chart, and is it the same one as the puzzle?';
ok(!mc.isBareInfo(P5), 'an INFO page with figures/rules is NOT compacted (13 Oct regression)');
ok(mc.isBareInfo(BARE), 'a figure-free welcome page is bare info');

const rows = [seen('a', BARE, 1), seen('p5', P5, 2), seen('p7', P7, 3), seen('p8', 'TYPE: QUESTION\nPage 8 of 8\nWhich carrier is cheapest for Atlanta?', 4)];
let b = mc.buildCopilotBlocks({ mode: 'smart', rows, session: {}, pressed: true });
const sc = b.screens.join('\n');
ok(/\[a\] — info page, nothing to answer \(index line/.test(sc), 'bare info → index line');
ok(/12% surcharge/.test(sc) && /grows 20%/.test(sc), 'rules page rides in full');
ok(/Memo from Priya/.test(sc), 'open question page rides in full');

// answered: both memo questions in the ledger → index line; one answered → still full
const both = rows.concat([said(['Page 7 — Question 1 — monthly cost of Chicago→Dallas with the puzzle carrier incl. fuel surcharge', 'Page 7 — Question 2 — best on-time carrier on the chart, same as the puzzle?'], 5)]);
b = mc.buildCopilotBlocks({ mode: 'smart', rows: both, session: {}, pressed: true });
ok(/\[p7\] — every question here is already answered \(index line/.test(b.screens.join('\n')), 'fully answered page → index line');
const one = rows.concat([said(['Page 7 — Question 1 — monthly cost of Chicago→Dallas with the puzzle carrier incl. fuel surcharge'], 5)]);
b = mc.buildCopilotBlocks({ mode: 'smart', rows: one, session: {}, pressed: true });
ok(/Memo from Priya/.test(b.screens.join('\n')), 'half-answered page stays in full');

// pull-in: an index page comes back in full when the question points at it
b = mc.buildCopilotBlocks({ mode: 'smart', rows: both, session: {}, ask: 'For the memo on page 7, which carrier was best on-time?' });
ok(/PULLED IN FULL FOR THIS QUESTION[\s\S]*Memo from Priya/.test(b.volatile.join('\n')), '"page 7" pulls the answered page back in full');
b = mc.buildCopilotBlocks({ mode: 'smart', rows: both, session: {}, ask: 'what fuel surcharge applies to Chicago Dallas monthly cost with the puzzle carrier' });
ok(/PULLED IN FULL[\s\S]*Memo from Priya/.test(b.volatile.join('\n')), 'shared names/numbers pull it back too');

// budget: 40 big data pages → none dropped, oldest become index lines, newest full
const big = []; for (let i = 0; i < 40; i++) big.push(seen('d' + i, 'TYPE: DATA\nPage ' + i + ' of 40\nTable ' + i + ': ' + ('Atlanta 60 pallets $70 ').repeat(60) + ' unique' + i, i));
b = mc.buildCopilotBlocks({ mode: 'smart', rows: big, session: {}, pressed: true });
const all = b.screens.join('\n');
ok(big.every(r => all.includes('[' + r.meta.key + ']')), 'every page is still listed (nothing dropped)');
ok(/\[d0\] — older page \(index line/.test(all) && /\[d39\]:\n/.test(all), 'oldest → index line, newest full');
ok(all.length < mc.SMART_SCREENS_CHARS + 40 * 400, 'screens stay inside the budget');
b = mc.buildCopilotBlocks({ mode: 'smart', rows: big, session: {}, ask: 'what is on page 3 of 40, table 3 unique3' });
ok(/PULLED IN FULL[\s\S]*unique3/.test(b.volatile.join('\n')), 'an old page is pulled back by page number');

// all-day call: > 60 index lines fold into a count line
const word = i => String.fromCharCode(97 + i % 26) + String.fromCharCode(97 + Math.floor(i / 26) % 26) + 'zed';
const day = []; for (let i = 0; i < 90; i++) day.push(seen('w' + i, 'TYPE: INFO\nIntro ' + [0, 1, 2, 3, 4, 5].map(k => word(i * 7 + k)).join(' '), i));
b = mc.buildCopilotBlocks({ mode: 'smart', rows: day.concat([seen('last', 'TYPE: QUESTION\nWhich one?', 99)]), session: {}, pressed: true });
ok(/earlier pages are stored but not listed/.test(b.screens.join('\n')), 'all-day call folds the oldest index lines');

// cache order: the ask never touches the cached part; a new page only appends
const r1 = rows.slice(0, 3), r2 = rows;
const x = mc.buildCopilotBlocks({ mode: 'smart', rows: r1, session: { resume: 'R' }, ask: 'first ask' });
const y = mc.buildCopilotBlocks({ mode: 'smart', rows: r1, session: { resume: 'R' }, ask: 'a different ask', typed: true });
ok(JSON.stringify(x.stable.concat(x.screens)) === JSON.stringify(y.stable.concat(y.screens)), 'different asks → identical cached part');
const z = mc.buildCopilotBlocks({ mode: 'smart', rows: r2, session: { resume: 'R' }, pressed: true });
ok(x.screens.slice(0, -1).every((t, i) => z.screens[i] === t), 'a new page appends; earlier page blocks unchanged');
ok(!/first ask/.test(x.stable.concat(x.screens).join('')), 'volatile text never in the cached part');
ok(mc.buildCopilotPrompt({ mode: 'smart', rows: r1, session: {}, ask: 'q?' }).includes('q?'), 'string form still has everything');

console.log(`copilot-context: ${n} checks\nALL PASS (nothing dropped, rules kept, answered pages indexed, pulled back on demand, cache order)`);
