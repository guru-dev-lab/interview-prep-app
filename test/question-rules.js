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
let fail = 0;
for (const q of QUESTIONS) if (!isQuestion(q)) { fail++; console.log('MISSED question :', q); }
for (const q of NOT_QUESTIONS) if (isQuestion(q)) { fail++; console.log('FALSE question  :', q); }
console.log(fail ? `${fail} FAILED` : `ALL PASS (${QUESTIONS.length} questions caught, ${NOT_QUESTIONS.length} non-questions rejected)`);
process.exit(fail ? 1 : 0);
