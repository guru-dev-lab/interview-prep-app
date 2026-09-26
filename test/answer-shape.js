// Unit test for the LIVE ANSWER COMPOSER block in server.js: question-type classifier, output-contract normalizer,
// growth insertion, and that every style + shape composes a prompt. Evaluated straight from the source (no copies).
// Run: node test/answer-shape.js
const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'server.js'), 'utf8');
const block = src.slice(src.indexOf('// ===== LIVE ANSWER COMPOSER'), src.indexOf('// Generate answer for live question'));
const stylesBlock = src.slice(src.indexOf('const ANSWER_STYLES = {'), src.indexOf('\n};', src.indexOf('const ANSWER_STYLES = {')) + 3);
const pre = src.slice(src.indexOf('const ANSWER_PROMPT = `'), src.indexOf('// ============ ANSWER STYLE TEMPLATES'));
const memRules = src.slice(src.indexOf('const MEMORY_RULES = `'), src.indexOf('`;', src.indexOf('const MEMORY_RULES = `')) + 2);
const api = new Function(pre + stylesBlock + memRules + block + '\nreturn { classifyQuestionShape, normalizeLiveAnswer, appendToLiveAnswer, composeLiveSystemPrompt, liveLineCap, ANSWER_STYLES, LIVE_TONES };')();
let fail = 0; const eq = (name, got, want) => { if (JSON.stringify(got) !== JSON.stringify(want)) { fail++; console.log('FAIL', name, '\n  got :', JSON.stringify(got), '\n  want:', JSON.stringify(want)); } };

// 1) classifier
const SHAPES = {
  pitch: ['Tell me about yourself', 'So tell me a bit about yourself.', 'Why do you want this role?', 'Why are you leaving your current job?', "What's your greatest weakness?", 'Walk me through your resume'],
  story: ['Tell me about a time you handled messy data', 'Describe a situation where you disagreed with a manager', 'Give me an example of a time you missed a deadline', 'Have you ever dealt with a difficult stakeholder?', 'How did you handle a project that went off track?'],
  code: ['Write a SQL query to get the second highest salary in each department.', 'How would you remove duplicate rows in SQL but keep the most recent one?', 'How do you calculate a 7-day rolling average in SQL?', 'Write a DAX measure for year-over-year growth', 'How would you find customers who ordered in January but not in February, in SQL?'],
  general: ['What is the difference between WHERE and HAVING?', 'How would you speed up a slow query in our environment?', 'How do you handle it when you get stuck on something?', 'In Snowflake, what is a clustering key and when would you use one?', 'How do you prioritize competing deadlines?', "What's your experience with Snowflake?"],
};
for (const [want, qs] of Object.entries(SHAPES)) for (const q of qs) eq('shape: ' + q, api.classifyQuestionShape(q).shape, want);
eq('technical: clustering', api.classifyQuestionShape('What is a clustering key in Snowflake?').technical, true);
eq('not technical: stuck', api.classifyQuestionShape('How do you handle it when you get stuck?').technical, false);

// 2) normalizer — contract: bullets, one ↳ last, ▸ first (story only)
eq('bullets added', api.normalizeLiveAnswer('WHERE filters rows.\nHAVING filters groups.', 'general'), '• WHERE filters rows.\n• HAVING filters groups.');
eq('dash bullets → •', api.normalizeLiveAnswer('- one\n* two', 'general'), '• one\n• two');
eq('↳ moved last, only one kept', api.normalizeLiveAnswer('↳ At A — old\n• one\n↳ At R&L — keep\n• two', 'general'), '• one\n• two\n↳ At R&L — keep');
eq('▸ first for story', api.normalizeLiveAnswer('• it broke\n▸ At R&L\n• I fixed it', 'story'), '▸ At R&L\n• it broke\n• I fixed it');
eq('story drops ↳', api.normalizeLiveAnswer('▸ At R&L\n• it broke\n↳ At R&L — dup', 'story'), '▸ At R&L\n• it broke');
eq('code block kept verbatim', api.normalizeLiveAnswer('```sql\nSELECT *\n  FROM t;\n```\nDENSE_RANK keeps ties.', 'code'), '```sql\nSELECT *\n  FROM t;\n```\n• DENSE_RANK keeps ties.');
eq('unterminated code closed', api.normalizeLiveAnswer('```sql\nSELECT 1', 'code'), '```sql\nSELECT 1\n```');
eq('STAR labels kept', api.normalizeLiveAnswer('▸ At R&L\nSituation: x\nAction: y\nResult: z', 'story'), '▸ At R&L\nSituation: x\nAction: y\nResult: z');
eq('cap keeps first N lines', api.normalizeLiveAnswer('• a\n• b\n• c\n↳ At R&L — p', 'general', { cap: 2 }), '• a\n• b\n↳ At R&L — p');
eq('employer line stripped when not allowed', api.normalizeLiveAnswer('• a\n↳ At R&L — p', 'general', { employerLineAllowed: false }), '• a');
eq('executive cap 2', api.liveLineCap('executive', 0), 2);
eq('user setting stricter than style', api.liveLineCap('direct', 2), 2);
eq('no cap by default', api.liveLineCap('conversational', 0), 0);
eq('cue-only drops prose line', api.normalizeLiveAnswer('• Unblock ops first\n• When I am juggling many asks I start by checking what is on the critical path for operations', 'general', { cueOnly: true }), '• Unblock ops first');
eq('blank lines dropped', api.normalizeLiveAnswer('• a\n\n\n• b', 'general'), '• a\n• b');

// 3) growth goes above the employer line
eq('grow above ↳', api.appendToLiveAnswer('• one\n↳ At R&L — proof', 'Also two.', 'general'), '• one\n• Also two.\n↳ At R&L — proof');
eq('grow no ↳', api.appendToLiveAnswer('• one', '- two', 'general'), '• one\n• two');

// 4) every style × shape composes, tone included, layout included
{ const p = api.composeLiveSystemPrompt({ shape: 'general', technical: true, styleKey: 'conversational', maxLines: 0, voiceProfile: '', withConversation: false, questionText: 'What is the difference between WHERE and HAVING?' });
  if (!p.includes('NO employer line')) { fail++; console.log('FAIL no-history concept question should forbid employer line'); } }
{ const p = api.composeLiveSystemPrompt({ shape: 'general', technical: true, styleKey: 'conversational', maxLines: 0, voiceProfile: '', withConversation: false, questionText: "What's your experience with Snowflake?" });
  if (!p.includes('EMPLOYER LINE (optional')) { fail++; console.log('FAIL own-experience question should allow employer line'); } }
for (const style of Object.keys(api.ANSWER_STYLES)) for (const shape of ['general', 'code', 'story', 'pitch']) {
  const p = api.composeLiveSystemPrompt({ shape, technical: shape === 'code', styleKey: style, maxLines: 0, voiceProfile: '', withConversation: true, questionText: 'x' });
  if (!p.includes('LAYOUT — fixed') || !p.includes(api.LIVE_TONES[style]) || !p.includes('CONNECT TO WHAT WAS SAID')) { fail++; console.log('FAIL compose', style, shape); }
  if (style === 'star' && shape === 'story' && !p.includes('"Situation: …"')) { fail++; console.log('FAIL star labels not in story layout'); }
  if (style === 'keywords' && !/CUE/.test(p)) { fail++; console.log('FAIL keywords cue unit missing', shape); }
}
console.log(fail ? `${fail} FAILED` : `ALL PASS (classifier, contract, growth, ${Object.keys(api.ANSWER_STYLES).length} styles × 4 shapes)`);
process.exit(fail ? 1 : 0);
