// Unit test: isFollowUpOf — continuation words / pointing back (the embedding part is not loaded here → word rules only).
const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'server.js'), 'utf8');
const f = new Function('embedText', src.slice(src.indexOf('const FOLLOW_UP_SIMILARITY'), src.indexOf('// AI verification — send top candidates')) + ';return isFollowUpOf;')(async () => null);
const prev = "What's the difference between an inner join and a left join?";
const cases = [
  ['How would you approach this problem?', true], ['And when would you use each one?', true], ['Can you walk me through that?', true],
  ['What about when the tables are huge?', true], ["What if they're a senior executive?", true], ['How would you test it?', true],
  ['How do you prioritize competing deadlines?', false], ['How do you handle it when you get stuck on something?', false],
  ['In Power BI, what is the difference between a calculated column and a measure?', false], ['Why are you looking to leave your current job?', false],
];
(async () => { let fail = 0; for (const [q, want] of cases) { const got = await f(q, prev); if (got !== want) { fail++; console.log('FAIL', q, '→', got); } }
  console.log(fail ? `${fail} FAILED` : `ALL PASS (follow-up rules, ${cases.length} cases)`); process.exit(fail ? 1 : 0); })();
