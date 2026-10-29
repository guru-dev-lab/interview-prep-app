// Whole interviews as ONE continuous call (owner, 27 Oct: real calls do not pause after each question).
// ElevenLabs v4 speaks every turn (tags like [hesitates] shape the delivery, they are not spoken). Turns run back to back
// with natural gaps; `gap` (ms) overrides it — negative = the speaker cuts in before the last one finished.
// Turn fields:
//   s       who speaks: an interviewer voice key, or 'you' (the candidate, on his mic channel)
//   t       what they say
//   q       interviewer turns that ASK: the card must be this question (regex on the card's title)
//   card    a reworded prepared question: the card must be that prepared card (regex)
//   none    interviewer turns that must NOT make a new card (small talk, pitch, setup, announcement)
//   press   press Say: a fraction of this turn (0.6 = while still asking) or 'after'
// Every other interviewer turn (no q/card/none) is free: a card or not, it is not scored, but stale jumps still are.

const CALLS = [
  {
    id: 'call-1', title: 'Northwind Logistics — Senior BI Developer, hiring manager + senior analyst (headphones)',
    echo: false, voices: { hm: 'us_m', sa: 'uk_f' },
    turns: [
      { s: 'hm', t: "Hey, good morning! Can you hear me okay?", none: true },
      { s: 'you', t: "Good morning! Yes, I can hear you fine. Thanks for having me." },
      { s: 'hm', t: "Great, great. So, um, I'm Brian, I run the BI team here, and I've got Alice with me, she's one of our senior analysts. [laughs] She'll jump in with the hard ones.", none: true },
      { s: 'sa', t: "Hi! Nice to meet you.", none: true },
      { s: 'you', t: "Nice to meet you both." },
      { s: 'hm', t: "So a little about us. We're a logistics company, about two thousand people, and the data team sits under finance. We moved to Fabric last year and honestly we're still cleaning up a lot of, uh, legacy reports.", none: true },
      { s: 'you', t: "That makes sense. I've been through a migration like that, so I know how messy the legacy side can get." },
      { s: 'hm', t: "[warmly] Yeah. So, to start us off, could you just walk me through your background?", card: /tell me about yourself|walk me through your resume|background/i },
      { s: 'you', t: "Sure. I'm a BI developer with about six years in SQL Server, Power BI and Python. Right now I'm at Contoso, where I own the sales and finance reporting. I built the row level security for around three hundred regional managers, and I automated our month end reconciliation, which used to take the finance team two full days. Before that I was an analyst, so I still think about what the business actually does with the numbers." },
      { s: 'hm', t: "Nice. Okay. So, um, when it comes to Power BI, right,", gap: 400 },
      { s: 'hm', t: "how do you decide what goes in the model as a calculated column versus a measure?", gap: 1100, q: /calculated column|measure/i },
      { s: 'you', t: "So my rule is, if I need to slice or filter by it, it can be a column, ideally built upstream in SQL. If it's an aggregation that has to respond to the filter context, it's a measure. Columns cost memory on every row, so I keep them to a minimum on big fact tables." },
      { s: 'sa', t: "[curious] Can I jump in? What about, say, a margin percentage. Where does that one live?", q: /margin/i },
      { s: 'you', t: "That one is always a measure, because the ratio has to be computed after the sums, not row by row. If you average a row level margin column you get the wrong answer." },
      { s: 'hm', t: "Right, right. Okay. Let me ask you about stakeholders.", none: true },
      { s: 'hm', t: "When a director tells you the numbers on your dashboard are wrong, what's the very first thing you do?", gap: 600, q: /numbers|wrong|director|dashboard/i },
      { s: 'you', t: "First I don't argue, I ask which number and what they expected, because usually they're comparing to a different report or a different filter. Then I reconcile against the source, and I get back to them the same day with either a fix or an explanation in plain words." },
      { s: 'hm', t: "[thinking] Mm. And has that ever turned out to be your mistake?", q: /mistake/i },
      { s: 'you', t: "Yes, once. A currency conversion was applied twice on a regional page. I owned it, fixed it, and added a test that compares totals to the finance close every morning, so it can't happen silently again." },
      { s: 'sa', t: "So, I suppose what I really want to understand is, when the source system itself is wrong, um, what then?", q: /source system|wrong|what then/i },
      { s: 'you', t: "Then it's a data owner conversation. I flag it with evidence, show the impact in money, and agree who fixes it at the source. In the meantime I'll put a clear note on the report so nobody makes a decision on a number we know is off." },
      { s: 'hm', t: "Okay, cool. So imagine you join us on Monday,", none: true, gap: 500 },
      { s: 'hm', t: "and the CFO asks for a margin report by Friday, but the data is in, like, four different systems. What do you do?", gap: 900, q: /CFO|margin report|four different systems|friday/i, press: 0.6 },
      { s: 'you', t: "I'd start by agreeing the definition of margin with the CFO's team on day one, because that's where these projects fail. Then I'd land the four sources into one staging layer, reconcile the totals, and ship a simple first version by Thursday so there's time for questions." },
      { s: 'sa', t: "How are you currently using AI or, um, agentic tools in your day to day work, if at all?", q: /\bAI\b|agentic/i },
      { s: 'you', t: "I use it a lot for the boring parts. I have a small automation that reads the failed refresh alerts, pulls the error and the last change, and drafts the ticket with the likely cause. It saves me maybe three hours a week." },
      { s: 'sa', t: "Oh, nice. And how do you make sure it doesn't, you know, make things up?", q: /make things up|sure it|trust|wrong/i },
      { s: 'you', t: "It never acts on its own. It drafts, I review, and it only uses the logs and the change history I give it." },
      { s: 'hm', t: "Love that. Okay, um, we're running close to time. Do you have any questions for us?", none: true },
      { s: 'you', t: "Yes, actually. What does success look like for this role in the first six months?" },
      { s: 'hm', t: "Great question. Honestly, it's getting the finance pack off the old reports and onto Fabric, with numbers people trust.", none: true },
    ],
  },
  {
    id: 'call-2', title: 'Brightline Health — Data Analyst, recruiter screen then manager (laptop speakers, his voice leaks)',
    echo: true, voices: { rc: 'us_f', mg: 'au_m' },
    turns: [
      { s: 'rc', t: "Hi there! How are you doing today?", none: true },
      { s: 'you', t: "I'm doing well, thank you. How about you?" },
      { s: 'rc', t: "Good, good, busy morning. [laughs] Okay so this is just a quick screen and then Charlie, the hiring manager, is going to join us in a bit.", none: true },
      { s: 'rc', t: "So, what draws you to this particular position with us?", card: /why do you want this role|interested|position/i, press: 'after' },
      { s: 'you', t: "Mostly the mission and the data. Healthcare reporting has real consequences, and from the job description you're building out a proper analytics team, which is exactly the stage where I do my best work." },
      { s: 'rc', t: "Okay. And, um, what are you looking for in terms of salary?" }, // a card or not, both fine
      { s: 'you', t: "I'm flexible, and I'd like to understand the full package, but I'm targeting the range that was in the posting." },
      { s: 'rc', t: "Perfect. Oh, looks like Charlie just joined. Hi Charlie!", none: true },
      { s: 'mg', t: "G'day, sorry I'm late, back to back meetings. Okay, let's dive in.", none: true },
      { s: 'mg', t: "How do you handle conflicting priorities?", q: /priorit/i },
      { s: 'mg', t: "Right? Just give me an example where two directors both said theirs was the most urgent.", gap: 350 },
      { s: 'you', t: "Sure. At Contoso the sales director and the finance director both wanted their dashboard first. I put both requests on one page with the business impact and the effort, and asked them to agree the order together in fifteen minutes. Finance went first because of the month end close, and sales got a quick interim extract." },
      { s: 'mg', t: "Good. Okay, technical one. If a query that used to run in, like, ten seconds now takes eight minutes, walk me through how you'd find out why.", q: /query|eight minutes|slow|why/i },
      { s: 'you', t: "I'd look at what changed first, data volume, the plan, or the code. Then I compare the execution plans, look for scans where there used to be seeks, missing statistics, or a parameter sniffing issue." },
      { s: 'mg', t: "And if it's", gap: -800 },
      { s: 'mg', t: "sorry, if it's not the query at all, it's the warehouse being overloaded?", gap: 300, q: /overloaded|warehouse|not the query/i },
      { s: 'you', t: "Then it's workload management. I'd check what else runs at that time and move the heavy jobs or scale for that window." },
      { s: 'rc', t: "[softly] We have about ten minutes left, just so you know.", none: true },
      { s: 'mg', t: "Yep. So you've been using Power BI for a while.", press: 'after', q: /power bi/i },
      { s: 'you', t: "Yes, about six years, mostly sales and finance models, and the last two years a lot of performance and security work." },
      { s: 'mg', t: "Where should business logic live, in the database, in the semantic model, or in the report, and why?", q: /business logic/i, press: 0.5 },
      { s: 'you', t: "As low as it can. Shared definitions in the database or the semantic model, so every report gets the same number. The report layer is only for presentation." },
      { s: 'mg', t: "Okay. I think that's all from me. Thanks, this was great.", none: true },
    ],
  },
  {
    // Live 28 Oct (WEX recruiter, laptop speakers): he was still answering when she cut in with "Oh, absolutely…" and her
    // 20-second turn ended on a new question. The first 1.5 s of her line had his voice loud on the mic, so the whole line
    // was thrown away as "your echo"; two Say presses showed the old salary card.
    id: 'call-wex', title: 'WEX-style recruiter screen — salary talk, then she cuts in over his answer with a new question (laptop speakers)',
    echo: true, micGain: 3, voices: { rc: 'us_f' },
    turns: [
      { s: 'rc', t: "Perfect. And speaking of money, what's the salary range you're seeking?", q: /salary/i },
      { s: 'you', t: "I'm looking at around eighty five to ninety thousand, depending on the full package." },
      { s: 'rc', t: "Okay. So I'll be very upfront with you, because I never want to waste anyone's time. The range listed shows seventy one to eighty four, but what this role is budgeted for is seventy one to seventy two thousand. So we are quite a ways off. I'll share about the benefits too, medical, dental, vision. But even considering that, in all honesty, will that budget work for you?", q: /budget|work for you|salary/i },
      { s: 'you', t: "Honestly, money matters, but it's not everything. I care about the team, the culture, and the kind of problems I'd be solving. So I'd like to keep the conversation going and hear more about the bonus and the benefits before I decide anything." },
      { s: 'rc', gap: -2500, t: "Oh, absolutely. Absolutely. And like I said, I'll share some other information about bonus and things of that nature a little later in our conversation. But I'm glad you want to continue. So with that being said, tell me, in doing your research, what have you come to understand about us, who we are, and exactly what we do?", q: /understand|who we are|what we do|know about/i, press: 'after' },
      { s: 'you', t: "From what I've read, you're a payments and fintech company with fleet, travel and health benefits businesses." },
      { s: 'rc', t: "That's right. Great.", none: true },
    ],
  },
  {
    // Live 28 Oct: fast-route cards were titled with the chatter before the question ("You know, they know you know, like…",
    // "Me today. I'm just pulling your resume up…") and the note added those lines to New questions. A card's title must
    // START with the question itself (anchored regexes below).
    id: 'call-chatter', title: 'Recruiter who talks before every question (headphones)',
    echo: false, voices: { rc: 'us_f' },
    turns: [
      { s: 'rc', t: "Hi! Thanks for joining me today. I'm just pulling your resume up. I'm so sorry. Can you tell me how to pronounce your name?", q: /^(can you tell me )?how (do|to|would) (i |you )?pronounce/i },
      { s: 'you', t: "Sure, it's Ridwan. Rid, like get rid of, and then wan." },
      { s: 'rc', t: "Ridwan. Got it. Okay. So you know, they know, you know, like, they know who's requesting the trips, so that would be the other types of trips. Are you okay with the travel aspect of it?", q: /^(are )?you (okay|ok) with (the )?travel/i },
      { s: 'you', t: "Yes, travel is fine with me. Around fifteen percent works well." },
      { s: 'rc', t: "Perfect. And speaking of the team, I'll say they are a great group to learn from, right? What's important to you in a manager?", q: /^what('s| is) important to you (in|and) a manager/i },
      { s: 'you', t: "Clear priorities and honest feedback. I like a manager who tells me early when something isn't landing." },
    ],
  },
  {
    // Owner 28 Oct: "Ask them" = he asks THEM a question; their answer (with its own "you know what I mean?" style
    // questions) must not make cards until he presses SAY, which answers and turns catching back on.
    id: 'call-askthem', title: 'He asks them a question; they explain at length; then a real question with SAY (headphones)',
    echo: false, voices: { hm: 'us_m' },
    turns: [
      { s: 'hm', t: "So that's the role in a nutshell. What questions do you have for me?", q: /questions/i },
      { s: 'you', askThem: true, t: "Thanks. How is the data team set up today, and what does the first ninety days look like?" },
      { s: 'hm', t: "Great question. So we're about twelve people. Do you know how most teams split BI and engineering? We don't, honestly. Everyone builds end to end.", none: true },
      { s: 'hm', t: "And the first ninety days? Mostly learning the finance models. Why does that matter? Because finance is our biggest customer, and they are picky.", none: true },
      { s: 'you', t: "That makes sense, thank you." },
      { s: 'hm', t: "Okay, one more from me. How would you handle a stakeholder who keeps changing the requirements?", q: /stakeholder|requirements/i, press: 'after' },
      { s: 'you', t: "I'd write the agreed scope down and show the trade off of each change in time." },
      { s: 'hm', t: "And how do you keep a report fast when the data grows?", q: /fast|data grows|performance/i },
    ],
  },
  {
    // Live test 28 Oct: SAY pressed on "Okay. One more from me." before the question; the reader made one up from older talk
    // (an ad hoc reporting question) and the real question was grown onto that wrong card. The card must BE the question.
    id: 'call-early-say', title: 'SAY pressed on the lead-in, before the question is asked (headphones)',
    echo: false, voices: { rc: 'us_f' },
    turns: [
      { s: 'rc', t: "So you were talking about ad hoc reports earlier. What tools did you say you use for the ad hoc reporting?", q: /tools/i },
      { s: 'you', t: "Mostly Power BI and Excel, and SQL underneath for the data pulls." },
      { s: 'rc', t: "Great, thank you. Okay. One more from me.", press: 0.75 },
      { s: 'rc', gap: 1300, t: "How would you handle a stakeholder who keeps changing the requirements?", q: /^(one more from me\.? )?how would you handle a stakeholder/i },
      { s: 'you', t: "I'd write the agreed scope down and show the trade off of each change in time." },
    ],
  },
];

module.exports = { CALLS };
