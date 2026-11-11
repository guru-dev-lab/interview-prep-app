// Real note page, coach = ONE starter line (owner 11 Nov: "best response to start to what they just finished explaining or
// asked.. more like convo beginner"). The AI routes are faked here (no spend): this checks WHEN and HOW OFTEN the page asks
// for a line and what the strip shows. Live 10 Nov it asked 4-6 times per question and added "Add:" lines while he talked.
// Usage: node test/coach-opener-ui.js [baseUrl]   (local server, LOCAL DATABASE_URL; run test/note-leads-live.js once first)
const X = require('path').join(__dirname, '..');
require(X + '/node_modules/dotenv').config({ path: X + '/.env' });
const { chromium } = require('/Users/rba-home/.local/node/lib/node_modules/@playwright/mcp/node_modules/playwright');
const { Pool } = require(X + '/node_modules/pg'); const jwt = require(X + '/node_modules/jsonwebtoken');
const B = process.argv[2] || 'http://localhost:3997';
if (!/127\.0\.0\.1|localhost/.test(process.env.DATABASE_URL || '')) { console.error('Refusing: DATABASE_URL is not local'); process.exit(2); }
let pass = 0, fail = 0; const check = (ok, l, d) => { ok ? pass++ : fail++; console.log((ok ? 'PASS ' : 'FAIL ') + l + (ok || d === undefined ? '' : '  ' + d)); };
(async () => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const u = (await pool.query("SELECT * FROM users WHERE email = 'note-leads@local.test'")).rows[0];
  if (!u) { console.error('Run test/note-leads-live.js once first (it makes the reused local user)'); process.exit(2); }
  const s = (await pool.query('SELECT * FROM sessions WHERE user_id = $1 LIMIT 1', [u.id])).rows[0];
  await pool.query("UPDATE answer_notes SET settings = coalesce(settings, '{}'::jsonb) || jsonb_build_object('jobsBuilt', jsonb_build_array($2::text), 'autoGenerate', false, 'autoSwitch', false, 'coach', true) WHERE user_id = $1", [u.id, s.id]);
  const token = jwt.sign({ userId: u.id, name: u.name, email: u.email, isAdmin: false, plan: 'pro', suspended: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
  const br = await chromium.launch({ channel: 'chrome' }); const ctx = await br.newContext({ viewport: { width: 1250, height: 900 } });
  const p = await ctx.newPage(); const errs = []; p.on('pageerror', e => errs.push(e.message));
  const calls = []; let t0 = Date.now();
  await p.route('**/api/note/coach', r => { const b = JSON.parse(r.request().postData() || '{}'); calls.push({ at: Date.now() - t0, text: b.text, chat: !!b.chat, youSaid: b.youSaid || '' });
    r.fulfill({ contentType: 'application/json', body: JSON.stringify({ coach: { want: 'WANT-TEXT', say: 'Thanks for walking me through that.' } }) }); });
  await p.route('**/api/note/heard', r => r.fulfill({ contentType: 'application/json', body: '{"groupId":null}' }));
  await p.route('**/api/note/coach-tidy', r => r.fulfill({ contentType: 'application/json', body: '{"tidy":null}' }));
  await p.route('**/api/note/said', r => r.fulfill({ contentType: 'application/json', body: '{}' }));
  try {
    await p.goto(B + '/note?token=' + token + '&session=' + s.id); await p.waitForTimeout(2500);
    const x = await ctx.newPage(); await x.goto(B + '/download');
    const send = (type, text) => x.evaluate(([type, text]) => new BroadcastChannel('xhire-note').postMessage({ type, text }), [type, text]);
    const W = ms => p.waitForTimeout(ms);

    // 1) a long question: heard early, the rest keeps coming (the 10 Nov statistics question)
    t0 = Date.now(); calls.length = 0;
    await send('question', 'Could you describe a time when you have applied statistical analysis or research methods?'); await W(400);
    await send('them', 'to help a program identify trends or assess outcomes.'); await W(400);
    await send('them', 'What did your findings reveal, and how did you account for limitations?');
    const lastThem = Date.now() - t0;
    await W(2500);
    check(calls.length === 1, 'one starter line for the whole question', JSON.stringify(calls));
    check(calls[0] && calls[0].at >= lastThem + 500, 'asked for only after they stopped talking', calls[0] && `${calls[0].at}ms vs last words ${lastThem}ms`);
    check(calls[0] && /findings reveal/.test(calls[0].text), 'it reads the whole question, end included', calls[0] && calls[0].text);
    const strip = await p.evaluate(() => ({ shown: $('coach').classList.contains('show'), say: $('coach-say').textContent, wantVisible: getComputedStyle(document.querySelector('.coach .cw')).display !== 'none' }));
    check(strip.shown && /Thanks for walking/.test(strip.say), 'the strip shows the line to say', JSON.stringify(strip));
    check(!strip.wantVisible, 'no "They want" line on the strip', JSON.stringify(strip));

    // 2) he answers with pauses: no "Add:" lines
    await send('said', 'Sure. At my last role I looked at program outcome data.'); await W(3500);
    await send('said', 'I used a simple regression and compared before and after.'); await W(3500);
    check(calls.length === 1, 'nothing more while he answers (no Add lines)', JSON.stringify(calls.slice(1)));

    // 4) they explain at length (no question): one reaction when they finish, not one per pause
    await W(21000); // the question above is old now
    const dbg = () => p.evaluate(() => ({ coachNow: !!coachNow, done: $('coach').classList.contains('done'), chat: chatText, heard: heardText.slice(0, 30), heardAge: Date.now() - heardAt, said: saidText.length, follow: typeof follow !== 'undefined' && follow }));
    console.log('   before:', JSON.stringify(await dbg()));
    t0 = Date.now(); calls.length = 0;
    await send('them', 'So our Texas program is still relatively young compared to some of our other programs.'); await W(1500);
    await send('them', 'We have some data systems in place but others still need to be developed or strengthened.'); await W(1500);
    await send('them', 'We use a combination of tools from Excel to Airtable to Power BI and Salesforce.'); await W(4000);
    console.log('   after:', JSON.stringify(await dbg()));
    check(calls.length === 1 && calls[0].chat, 'one reaction after they finish explaining', JSON.stringify(calls));
    check(calls[0] && /Salesforce/.test(calls[0].text) && /relatively young/.test(calls[0].text), 'the reaction reads their whole explanation', calls[0] && calls[0].text);
    check(!errs.length, 'no page errors', errs.join(' | '));
  } finally { await br.close(); await pool.end(); console.log(fail ? `${fail} FAILED of ${pass + fail}` : `ALL PASS (${pass})`); process.exit(fail ? 1 : 0); }
})();
