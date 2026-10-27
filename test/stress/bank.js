// The stress bank: real-shaped interview moments, spoken in several voices (ElevenLabs, cached in ./audio).
// One entry = one live moment. Line kinds:
//   'text'                 interviewer (the scenario's voice)
//   { v, t }               another interviewer voice (panel)
//   { you }                the candidate on his mic (his voice also leaks into the call audio, like no headphones)
//   { pause: ms }          the interviewer stops mid-turn
//   { ask, pressAt }       interviewer line, and he presses Say part-way through it (0.6 = 60% spoken)
// Groups and what each must do:
//   ask      one card for the question, the card IS that question, not before they finished
//   split    the question comes in pieces with pauses: still ONE card, the whole question
//   match    a paraphrase of a prepared question: jumps to that prepared card
//   none     statements, small talk, company pitch, his own talking: NO card
//   mid      Say pressed while they are still asking: card at once, one card, grows with the rest
//   say      Say pressed after they moved on: answers the LATEST thing, never an old card
//   stale    an answered question, his answer, then a related new one: a new card, the old one never comes back
//   copilot  screens on, spoken question, Say: answers from the last question and the screens, on time
// Copilot screens live in ./screens (built by screens.js).

const PREPARED = [
  ['Tell me about yourself', 'I am a BI developer with six years in SQL, Power BI and Python, mostly sales and finance reporting.'],
  ['Why do you want this role?', 'Because the team is building the analytics platform I have been building towards, at a bigger scale.'],
  ['What is your greatest strength?', 'Turning a vague business question into a model people trust.'],
  ['Tell me about a time you failed', 'I shipped a forecast without a holdout test once; it drifted, I owned it and added backtesting.'],
  ['How do you prioritize competing requests?', 'By business impact and deadline, agreed openly with the requesters.'],
  ['Where do you see yourself in five years?', 'Leading a small analytics engineering team.'],
];

const S = [];
const add = (group, voice, lines, expect = {}, extra = {}) => S.push({ id: group + '-' + String(S.filter(s => s.group === group).length + 1).padStart(2, '0'), group, voice, lines, expect, ...extra });

// ---- ask: clean, long, rambling, technical, behavioural, with preambles ------------------------------------------
add('ask', 'us_m', ['Can you walk me through how you would design a star schema for a retail sales model, and how you would decide what goes in the fact table versus the dimensions?'], { topic: /star schema|fact|dimension/i });
add('ask', 'uk_f', ['So, I suppose what I really want to understand is, when a stakeholder tells you the numbers on your dashboard are wrong, what is the very first thing you do?'], { topic: /numbers|wrong|dashboard|stakeholder/i });
add('ask', 'au_m', ['How would you explain the difference between a left join and an inner join to someone in finance who has never written SQL?'], { topic: /join/i });
add('ask', 'us_f', ['What is your approach to incremental refresh in Power BI when the source table has about two hundred million rows?'], { topic: /incremental refresh|million rows/i });
add('ask', 'uk_m', ['Tell me about a time you had to push back on a senior leader because the analysis they wanted would have been misleading.'], { topic: /push back|senior|misleading|leadership disagrees/i });
add('ask', 'us_m2', ['How do you decide between using a calculated column and a measure in DAX?'], { topic: /calculated column|measure/i });
add('ask', 'us_f2', ['Okay, great. So, um, how do you go about testing a data pipeline before it goes to production, like what checks do you actually put in place?'], { topic: /test|pipeline|checks/i });
add('ask', 'uk_f', ['Describe a situation where the data you needed simply did not exist. What did you do?'], { topic: /data.*(not exist|did not exist)|did you do/i });
add('ask', 'us_m', ['How are you currently using AI or agentic tools in your day to day work, if at all?'], { topic: /\bAI\b|agentic/i });
add('ask', 'au_m', ['What would you do in your first ninety days in this role?'], { topic: /ninety days|90 days|first/i });
add('ask', 'us_f', ['How would you handle row level security for a report shared with three hundred regional managers?'], { topic: /row level security|RLS|regional managers/i });
add('ask', 'uk_m', ['If a query that used to run in ten seconds now takes eight minutes, walk me through how you would find out why.'], { topic: /query|eight minutes|slow|why/i });
add('ask', 'us_m2', ['Have you ever worked with slowly changing dimensions, and which type would you use for a customer address history?'], { topic: /slowly changing|SCD|address/i });
add('ask', 'us_f2', ['What does good data governance look like to you in a company our size, around two thousand people?'], { topic: /governance/i });
add('ask', 'uk_f', ['How do you make sure a dashboard actually gets used after you launch it?'], { topic: /dashboard.*used|adoption|launch/i });
add('ask', 'us_m', ['Explain window functions to me, and give me a case where you would use ROW_NUMBER instead of RANK.'], { topic: /window function|row_number|rank/i });
add('ask', 'au_m', ['How do you deal with a stakeholder who keeps changing the requirements halfway through a project?'], { topic: /changing.*requirements|requirements/i });
add('ask', 'us_f', ['Where should business logic live, in the database, in the semantic model, or in the report, and why?'], { topic: /business logic/i });
add('ask', 'uk_m', ['What is the most complex DAX measure you have written, and what made it complex?'], { topic: /complex.*DAX|DAX measure/i });
add('ask', 'us_m2', ['How would you reconcile two systems that report different revenue numbers for the same month?'], { topic: /reconcile|revenue/i });
add('ask', 'us_f2', ['Can you tell me how you would build a forecast for next quarter when we only have eighteen months of history?'], { topic: /forecast/i });
add('ask', 'uk_f', ['What is your experience with Microsoft Fabric, and would you recommend it over a traditional Azure setup?'], { topic: /fabric/i });
add('ask', 'us_m', ['Tell me about the biggest mistake you have made with data in production and how you found out about it.'], { topic: /mistake|production/i });
add('ask', 'au_m', ['How would you measure whether a new sales incentive program actually worked?'], { topic: /incentive|measure|worked/i });
add('ask', 'us_f', ['What is the difference between a data lake, a data warehouse, and a lakehouse, in your own words?'], { topic: /lake|warehouse|lakehouse/i });

// ---- split: pieces with pauses, one card, the whole question ----------------------------------------------------
add('split', 'us_m', ['So when it comes to Power BI, right,', { pause: 1100 }, 'can you share a project where you built a full solution, and how you structured it?'], { topic: /project|structured|solution/i });
add('split', 'uk_f', ['Let me ask you about stakeholders.', { pause: 1300 }, 'How do you keep a non technical executive engaged when the analysis is complicated?'], { topic: /executive|non technical|engaged/i });
add('split', 'au_m', ['Okay, thinking about data quality,', { pause: 1200 }, 'what would you put in place so bad data never reaches the board report?'], { topic: /bad data|board report|data quality/i });
add('split', 'us_f2', ['And on the technical side.', { pause: 900 }, 'How would you optimize a Power BI model that is three gigabytes and slow to refresh?'], { topic: /optimi[sz]e|gigabytes|slow/i });
add('split', 'uk_m', ['Right, so, the team uses dbt heavily,', { pause: 1400 }, 'how have you structured models in dbt, or how would you if you have not?'], { topic: /dbt/i });
add('split', 'us_m2', ['How do you handle conflicting priorities?', { pause: 400 }, 'Right? Just give me an example where two directors both said theirs was the most urgent.'], { topic: /priorit|urgent|directors/i, early: true }); // the first part is a whole question: answering it, then growing, is right
add('split', 'us_f', ['I want to understand your SQL depth.', { pause: 1000 }, 'Can you explain how you would find the second highest salary in each department?'], { topic: /second highest|salary|department/i });
add('split', 'uk_f', ['So imagine you join us on Monday,', { pause: 1200 }, 'and the CFO asks for a margin report by Friday, but the data is in four different systems. What do you do?'], { topic: /margin|CFO|four different systems|friday/i });

// ---- match: paraphrases of prepared questions ------------------------------------------------------------------
add('match', 'us_m', ['So to start us off, could you give me a quick walkthrough of your background?'], { card: /tell me about yourself/i });
add('match', 'uk_f', ['What draws you to this particular position with us?'], { card: /why do you want this role/i });
add('match', 'au_m', ['What would you say is the thing you are best at?'], { card: /greatest strength/i });
add('match', 'us_f2', ['Tell me about something that did not go well, a failure, and what you learned.'], { card: /time you failed/i });
add('match', 'us_m2', ['When everybody wants something from you at the same time, how do you decide what to do first?'], { card: /prioritize competing/i });
add('match', 'uk_m', ['Long term, what are your career goals, say five years out?'], { card: /five years|long.?term|career goals/i });

// ---- none: no card at all --------------------------------------------------------------------------------------
add('none', 'us_m', ['Hi, how are you doing today?', 'Can you hear me okay?'], {});
add('none', 'uk_f', ['So a little about us. We are a logistics company with about two thousand people, and the data team sits under finance. We moved to Fabric last year and we are still cleaning up a lot of legacy reports.'], {});
add('none', 'au_m', ['I know we are running close to the thirty minute mark. I do have one more question I wanted to ask you.'], {});
add('none', 'us_f', ['That makes a lot of sense. Yeah, we have seen the same thing with our regional teams, honestly.'], {});
add('none', 'us_m2', ['Build datasets, helping them build dashboards, helping them really automate a lot of the manual tasks that they do. Right?'], {});
add('none', 'us_f2', [{ you: 'Yeah, so in my last role I built the sales dashboards in Power BI, and it cut reporting time by about twenty percent.' }], {});
add('none', 'uk_m', [{ you: 'Great, so what does the team structure look like for this role?' }], {});
add('none', 'uk_f', ['Perfect. Let me just pull up my notes here, one second.', 'Okay, sorry about that, my screen froze.'], {});

// ---- mid: Say pressed while they are still asking --------------------------------------------------------------
const DASH = 'Can you walk me through how you would build a dashboard that tracks weekly sales by region, and how you would make it work for managers who open it on their phones?';
add('mid', 'us_m', [{ ask: DASH, pressAt: 0.6 }], { topic: /dashboard|sales/i, end: /phone|mobile/i });
add('mid', 'uk_f', [{ ask: 'How would you design the data model for a subscription business so that finance can see monthly recurring revenue, churn, and expansion revenue in one place?', pressAt: 0.5 }], { topic: /subscription|recurring|data model/i, end: /churn|expansion/i });
add('mid', 'au_m', [{ ask: 'Tell me about a time you automated a manual report, what tools you used, and how much time it saved the business every month?', pressAt: 0.55 }], { topic: /automat|manual report/i, end: /time|saved|hours/i });
add('mid', 'us_f2', [{ ask: DASH, pressAt: 0.92 }], { topic: /dashboard|sales/i, end: /phone|mobile/i });

// ---- say: pressed after they moved on ------------------------------------------------------------------------
add('say', 'us_m2', ['How would you handle a missed deadline on a client report?', { you: 'I would tell the client early and agree a new date with them.' }, 'We have been struggling with data quality in our warehouse feeds lately.'], { topic: /quality|warehouse/i, old: /deadline/i }, { press: 'after' });
add('say', 'uk_m', ['Your thoughts on dbt.'], { topic: /dbt/i }, { press: 'after' });
add('say', 'us_f', ['So you have been using Power BI for a while.'], { topic: /power bi/i }, { press: 'after' });
add('say', 'au_m', ['How do you usually model a date table in Power BI?', 'Okay, great.', 'And how would you test that the totals are right after a refresh?'], { topic: /test|totals|refresh/i, old: /date table/i }, { press: 'after' });

// ---- stale: a related new question must get its own card ---------------------------------------------------------
add('stale', 'us_m', ['Have you come across situations where several teams sent you conflicting priorities, and how did you solve them?', { you: 'Yes. At Northwind I ranked the requests by business impact and agreed the order with each manager, then I shared the plan every Monday.' }, 'Okay. When the APAC team says their project is the most urgent, how would you decide what to build first?'], { topic: /decide|build first|APAC/i, old: /conflicting priorities/i });
add('stale', 'uk_f', ['Have you ever implemented row level security in any of your Power BI datasets?', { you: 'Yes, I built a security table in SQL mapping manager emails to regions, then a role with a DAX filter on the user name.' }, 'Okay. So what would you say is your approach on the business logic? Where does it belong?'], { topic: /business logic|belong/i, old: /row level security/i });
add('stale', 'us_f2', ['How do you validate the numbers in a new report?', { you: 'I reconcile totals against the source system and get a finance owner to sign off on a sample.' }, 'And when the source system itself is wrong, what then?'], { topic: /source system|wrong/i, old: /validate the numbers/i });

// ---- copilot: screens + spoken question + Say ------------------------------------------------------------------
add('copilot', 'us_m', ['So what would you change in the code on your screen so it shows the correct percentage for each product?', 'Sales amount is a measure defined in the model itself, so you will not see it written here.'], { say: /^So what would you change in the code/i, want: /REMOVEFILTERS|DEFINE|MEASURE/i }, { screens: ['dax'] });
add('copilot', 'uk_f', ['Looking at the query on the screen, the share column shows one for every rep. How would you fix it?'], { say: /share column|fix it/i, want: /region_totals|JOIN|OVER\s*\(/i }, { screens: ['sql'] });
add('copilot', 'au_m', ['The notebook is throwing an error on line eight. What would you change?'], { say: /error on line eight|what would you change/i, want: /clean_amount/i }, { screens: ['py'] });
add('copilot', 'us_f', ['Take a minute to read the case on screen. How would you approach it, and what would you look at first?'], { say: /approach it/i, want: /.{80,}/s }, { screens: ['case'] });
add('copilot', 'us_m2', ['This chart is what the sales director sees every Monday. What would you change about it?'], { say: /what would you change/i, want: /.{80,}/s }, { screens: ['chart'] });
add('copilot', 'uk_m', ['So looking at the measures here, why is the year to date number wrong for March?'], { say: /year to date|march/i, want: /DATESYTD|TOTALYTD|date table|Date\]/i }, { screens: ['ytd'] });

module.exports = { SCENARIOS: S, PREPARED };
