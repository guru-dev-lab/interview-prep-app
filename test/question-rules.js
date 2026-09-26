// Unit test for the QUESTION RULES block in server.js (evaluated straight from the source — no copy).
// Run: node test/question-rules.js
const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'server.js'), 'utf8');
const block = src.slice(src.indexOf('// === QUESTION RULES'), src.indexOf('// === END QUESTION RULES'));
const isQuestion = new Function(block + '\nreturn isQuestion;')();

const QUESTIONS = [
  'Tell me about a time you led a project',
  'Share an example of a time you handled a difficult stakeholder',
  'In your current role, what reporting tools do you use',
  'A lot of our clients use Salesforce. How comfortable are you with it?',
  'The next thing I want to ask is how you prioritize competing deadlines',
  'Okay. So how would you handle a missed deadline?',
  'Great question, what does your ideal team look like?',
  "Let's talk about your SQL experience. What joins do you use most?",
  'Please describe your experience with Power BI',
  'Talk me through your approach to cleaning messy data',
  'Why do you want this role?',
  'Now, how do you handle conflict with a manager?',
  "What's your biggest weakness",
  "I'd love to hear how you handled your last product launch",
  'Walk me through your resume',
  'Can you explain the difference between a left join and an inner join',
  'Yeah so what made you leave your last job?',
  'Imagine the dashboard numbers are wrong on launch day. What do you do?',
  'Explain how you would design an ETL pipeline',
  'Have you ever worked with Snowflake or BigQuery?',
];
const NOT_QUESTIONS = [
  'I built a sales dashboard in Power BI for the regional team',
  'We used SQL and Python to clean the data every week',
  'So I think the main thing I learned was communication',
  'Yeah that makes sense',
  'What I did was rebuild the pipeline from scratch',
  'How are you doing today?',
  'Can you hear me okay?',
  'My last role was at Northwind as an analyst',
  'The result was a 20 percent drop in reporting time',
  'Okay great',
  'Do you have any questions for me?',
  'And then after that we moved the reports to Tableau',
  'Thanks so much for your time today',
];
// questionPartOf / cleanQuestionText live outside the block — grab them by name from the same source
function grab(name) { const i = src.indexOf('function ' + name + '('); let d = 0, j = src.indexOf('{', i); for (let k = j; k < src.length; k++) { if (src[k] === '{') d++; else if (src[k] === '}') { d--; if (!d) return src.slice(i, k + 1); } } }
const questionPartOf = new Function(block + grab('cleanQuestionText') + grab('questionPartOf') + '\nreturn questionPartOf;')();
let fail = 0;
for (const q of QUESTIONS) if (!isQuestion(q)) { fail++; console.log('MISSED question :', q); }
for (const q of NOT_QUESTIONS) if (isQuestion(q)) { fail++; console.log('FALSE question  :', q); }
// Fast route: clear interviewer questions come back (with their context), everything else → null (AI route decides)
const FAST = [
  ['How would you speed up a slow query in our environment?', 'How would you speed up a slow query in our environment?'],
  ['A lot of our clients use Salesforce. How comfortable are you with it?', 'A lot of our clients use Salesforce. How comfortable are you with it?'],
  ['Okay. So how would you handle a missed deadline?', 'How would you handle a missed deadline?'],
  ['I built the dashboards in Power BI for our regional team.', null],
  ['Thanks for joining again.', null],
  ['Great, so what does the team structure look like for this role?', 'What does the team structure look like for this role?'],
];
for (const [inp, want] of FAST) { const got = questionPartOf(inp); if ((got === null) !== (want === null) || (want && got.toLowerCase() !== want.toLowerCase())) { fail++; console.log('FAST ROUTE wrong:', inp, '→', got); } }
console.log(fail ? `${fail} FAILED` : `ALL PASS (${QUESTIONS.length} questions caught, ${NOT_QUESTIONS.length} non-questions rejected)`);
process.exit(fail ? 1 : 0);
