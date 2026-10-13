// Desktop Assessment — pure logic + wiring (owner, 13 Oct). Free — no model, no DB. Run: node test/assessment.js
const assert = require('assert');
const fs = require('fs'), path = require('path');
const as = require(path.join(__dirname, '..', 'lib', 'assessment.js'));
const mc = require(path.join(__dirname, '..', 'lib', 'meeting-copilot.js'));
let n = 0; const ok = (c, m) => { n++; assert(c, m); };
const row = (kind, text, ts, meta) => ({ kind, text, ts, meta: meta || {} });

// ---- who sees it: everyone for now; ASSESSMENT_PLANS narrows it in one place
ok(as.canUseAssessment({ plan: 'free' }, {}), 'everyone for now');
ok(!as.canUseAssessment({ plan: 'free' }, { ASSESSMENT_PLANS: 'pro, team' }), 'plan list narrows it');
ok(as.canUseAssessment({ plan: 'Pro' }, { ASSESSMENT_PLANS: 'pro,team' }), 'plan match ignores case');
ok(as.canUseAssessment({ plan: 'free', is_admin: true }, { ASSESSMENT_PLANS: 'pro' }), 'admins always');

// ---- carry material: earlier carry, digest, screens (info short, questions whole), answers with their ledger, talk
const rows = [
  row('seen', 'TYPE: INFO\n' + 'Welcome to Project Vantage onboarding. '.repeat(30), 1),
  row('seen', 'TYPE: QUESTION\nQ3 Which option describes the motion change? A) speeds up B) slows to a stop', 2),
  row('said', 'Asked: Q3\nSay:\n**Page 3 — Question 3 — motion change**\nResult: B', 3, { answered: ['Page 3 — Question 3 — motion change'] }),
  row('digest', 'THEY WANT — video question writing', 4),
  row('asker', 'Remember, three honest attempts are allowed.', 5),
];
const inp = as.buildCarryInput('DONE — Q1 → A; Q2 → C', rows);
ok(/EARLIER NOTES[\s\S]*Q1 → A/.test(inp), 'earlier carry rides in (cumulative)');
ok(/RUNNING NOTES OF THIS SITTING:\nTHEY WANT/.test(inp), 'digest rides in');
ok(/Q3 Which option describes the motion change/.test(inp), 'question screen whole');
ok(inp.split('Welcome to Project Vantage').length < 12, 'info screen short');
ok(/Page 3 — Question 3 — motion change :: /.test(inp), 'answers carry their whole ledger');
ok(/Heard: Remember, three honest attempts/.test(inp), 'last talk rides in');
const big = []; for (let i = 0; i < 40; i++) big.push(row('seen', 'TYPE: DATA\n' + ('row ' + i + ' ').repeat(400), i));
const binp = as.buildCarryInput('', big);
ok(binp.length < 20000 && /row 39/.test(binp) && !/row 0 /.test(binp), 'bounded, keeps the newest screens');

// ---- nothing to carry → no title, no carry
ok(!as.hasMaterial([row('asker', 'hello', 1), row('you', 'hi', 2)]), 'talk alone is not material');
ok(as.hasMaterial([row('said', 'x', 1)]), 'an answer is material');

// ---- title parse + lock rules
const p = as.parseCarry('TITLE: "Project Vantage — Video Question Writing"\nWHAT IT IS — onboarding test\nDONE — Q3 → B');
ok(p.title === 'Project Vantage — Video Question Writing', 'title parsed: ' + p.title);
ok(/WHAT IT IS/.test(p.notes) && !/TITLE:/.test(p.notes), 'notes without the title line');
ok(as.parseCarry('TITLE: Online Assessment\nDONE — x').title === '', 'a generic title is refused (stays untitled until a real one)');
ok(as.parseCarry('no title here').title === '', 'missing title → empty');

// ---- co-pilot prompt: assessment frame + carry; carry is never gated like interview memory
const ap = mc.buildCopilotPrompt({ mode: 'smart', rows: [], session: { resume: 'R' }, assessment: true, priorMemory: 'DONE — Q3 → B\nWHERE IT STOPPED — Q4', pressed: true });
ok(/ASSESSMENT — this person is taking an online assessment/.test(ap), 'assessment frame');
ok(/THIS ASSESSMENT SO FAR[\s\S]*WHERE IT STOPPED — Q4/.test(ap), 'carry rides as the starting point');
ok(!/EARLIER CALLS IN THIS SESSION/.test(ap), 'not as gated interview memory');
const ip = mc.buildCopilotPrompt({ mode: 'smart', rows: [], session: { resume: 'R' }, priorMemory: 'old call', pressed: true });
ok(/EARLIER CALLS IN THIS SESSION/.test(ip) && !/ASSESSMENT —/.test(ip), 'interview sessions unchanged');

// ---- wiring
const srv = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'launcher.html'), 'utf8');
const canvas = fs.readFileSync(path.join(__dirname, '..', 'public', 'canvas.html'), 'utf8');
ok(/coalesce\(s\.kind, 'interview'\) <> 'assessment'/.test(srv), 'assessments never show in the company session list');
ok(/app\.get\('\/api\/assessments'/.test(srv) && /app\.post\('\/api\/assessments'/.test(srv), 'list + start routes');
ok(/AND coalesce\(title, ''\) = '' RETURNING id/.test(srv), 'title is written once (locked)');
ok(/if \(ws\._isAssessment && ws\._callId\) finishAssessmentCall/.test(srv.slice(srv.indexOf("msg.type === 'stop'"))), 'stop carries the sitting');
ok(/if \(ws\._isAssessment && ws\._callId\) finishAssessmentCall/.test(srv.slice(srv.indexOf("ws.on('close'"))), 'close carries the sitting');
ok(/loadAssessmentCarry\(sessionId, _memTid\)/.test(srv), 'a new sitting starts from the carry');
ok(/assessment: s\.rows\[0\]\.kind === 'assessment'/.test(srv), 'co-pilot knows it is an assessment');
const card = html.slice(html.indexOf('async function renderAssessmentCard'), html.indexOf('async function openAssessment'));
ok(/if \(!window\.electronAPI\) return;/.test(card), 'desktop only — never in a browser');
ok(/if \(!data\.allowed\) return;/.test(card), 'hidden when the profile type is not allowed');
ok(/if \(!assessments\.length\) return startNewAssessment\(\)/.test(html), 'no history → straight into a new one');
ok(/Continue last/.test(html) && /Start a new assessment/.test(html) && /id="as-hist"/.test(html), 'history → continue / new / list');
ok(/var ASSESSMENT = params\.get\('assessment'\)/.test(canvas) && /setMode\('copilot'\)/.test(canvas.slice(canvas.indexOf('var ASSESSMENT'), canvas.indexOf('var ASSESSMENT') + 600)), 'overlay opens in co-pilot');

console.log(`assessment: ${n} checks\nALL PASS (desktop-only entry, continue from carry, title locked once)`);
