// Unit test for the QUESTION RULES block in server.js (evaluated straight from the source — no copy).
// Run: node test/question-rules.js
const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'server.js'), 'utf8');
const block = src.slice(src.indexOf('// === QUESTION RULES'), src.indexOf('// === END QUESTION RULES'));
const isQuestion = new Function(block + '\nreturn isQuestion;')();

const QUESTIONS = [
  "I didn't catch any of the company names. So what companies did you work for?",
  "What have you done in the past with Snowflake?",
  'What you would do if the numbers did not match?',
  'Which is better here, a left join or an inner join?',
  'Which tool would you use for this dashboard',
  'Which of these metrics matters most to you and why?',
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
  // stress bank 27 Oct: the interviewer says what they want to know, words in between, no sentence break from Deepgram
  'So I suppose what I really want to understand is when a stakeholder tells you the numbers on your dashboard are wrong what is the very first thing you do?',
  "I'm trying to understand how you would set up the refresh schedule for this",
  "I guess what I'd really like to know is how you handle pushback from a director",
  // "how are you…" is only small talk as the greeting (stress bank 27 Oct)
  'How are you currently using AI or agentic tools in your day to day work, if at all?',
  'How are you handling the move to Fabric on your current team?',
  'Let me ask you, how do you handle a stakeholder who keeps changing requirements?',
  'Let me ask you about stakeholders. How do you keep a non technical executive engaged?',
  'Walk me through your resume',
  'Can you explain the difference between a left join and an inner join',
  'Yeah so what made you leave your last job?',
  'Imagine the dashboard numbers are wrong on launch day. What do you do?',
  'Suppose the totals do not match the finance system, how would you find out why?',
  "Let's say you are the only analyst on the team. Walk me through your first week.",
  'Imagine you have to explain churn to the board',
  'Explain how you would design an ETL pipeline',
  'Have you ever worked with Snowflake or BigQuery?',
  'Write me a quick SQL query to get the top three customers by revenue in each region.',
  'Can you write a DAX measure for year over year growth?',
  'Build me a simple model to forecast weekly demand.',
  // Live call 21 Oct — the real questions
  "When it comes to Power BI, can you share a certain project you've worked on where you have built Power BI solutions?",
  'How do you handle conflicting priorities?',
  'If you have, like, two or three projects coming to you, how would you handle that?',
  'Like, what are you looking for your next role? You mentioned',
  'Have you come across any issues like that in your role, right, and how have you solved them?',
  'Just give me maybe an example of how you handled that.',
];
const NOT_QUESTIONS = [
  // Host feedback, prod 26 Sep 23:15 — a clause about what the candidate did, not a question
  "But I also like that you said what you've done in the past. So",
  'How you handled that stakeholder was really strong.',
  // Mock-video host intro, 26 Sep — relative 'which' continuing the last sentence
  'Which is a pretty cool company.',
  "Which is a pretty cool company. So I'll be jumping back and forth, and I created custom questions based on",
  'Which was a really fun project for the whole team.',
  // the topic announced, the question still to come (stress bank 27 Oct: jumped to an OLD stakeholder card)
  'Let me ask you about stakeholders.',
  'Okay, let me ask you about your SQL background.',
  'I want to ask you about dbt.',
  // a scenario set up, the question still to come (stress bank 27 Oct: answered "Imagine you join us on Monday.")
  'So imagine you join us on Monday.',
  'Suppose the dashboard goes live next week and the data is in four different systems.',
  "Let's say you are the only analyst on the team,",
  // the candidate using the same words about his own work (27 Oct)
  'I really wanted to understand why the totals were off, so I compared both systems side by side.',
  'I was trying to understand how the old system mapped the regions, and it turned out one field was wrong.',
  'I built a sales dashboard in Power BI for the regional team',
  'We used SQL and Python to clean the data every week',
  'So I think the main thing I learned was communication',
  'Yeah that makes sense',
  'What I did was rebuild the pipeline from scratch',
  'How are you doing today?',
  'How are you feeling this morning?',
  'Okay, how are you today, all good?',
  'Can you hear me okay?',
  'My last role was at Northwind as an analyst',
  'The result was a 20 percent drop in reporting time',
  'Okay great',
  'Do you have any questions for me?',
  'And then after that we moved the reports to Tableau',
  'Thanks so much for your time today',
  'For joining. You hear me okay?',
  'Can you see me alright?',
  // Live call 21 Oct (regular panel) — every one of these got an answer card
  'Build datasets, helping them build dashboards, helping them really automate a lot of the manual task that they do. Right?',
  'So when when it comes to Power BI, right,',
  'Build reports that',
  '? Just give me maybe an example of how',
  "Report could serve multiple stakeholders. Right? You you know what I'm trying to say?",
  'I know we are kind of running close to the thirty minute mark. I do have one question I wanted to ask you.',
  'Up me and another manager. We report up to Tricia, who who is our manager.',
  "So that's, I think, what the culture is all about.",
  'Right? So the way it works is I report',
  'Does that make sense?',
];
// Deepgram cuts a sentence across lines; the second half starts lowercase. It is never a fresh question on its own.
const CONTINUATIONS = [
  "describe the culture. So far, it's been really good, really productive environment to work on.",
  'up me and another manager. We report up to Tricia, who who is our manager.',
];
// questionPartOf / cleanQuestionText live outside the block — grab them by name from the same source
function grab(name) { const i = src.indexOf('function ' + name + '('); let d = 0, j = src.indexOf('{', i); for (let k = j; k < src.length; k++) { if (src[k] === '{') d++; else if (src[k] === '}') { d--; if (!d) return src.slice(i, k + 1); } } }
const questionPartOf = new Function(block + grab('cleanQuestionText') + grab('questionPartOf') + '\nreturn questionPartOf;')();
let fail = 0;
for (const q of QUESTIONS) if (!isQuestion(q)) { fail++; console.log('MISSED question :', q); }
for (const q of NOT_QUESTIONS) if (isQuestion(q)) { fail++; console.log('FALSE question  :', q); }
for (const q of CONTINUATIONS) if (questionPartOf(q)) { fail++; console.log('CONTINUATION answered:', q); }
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
