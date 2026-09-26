# Handoff

## 26 Sep 2026 (later) — follow-ups grow on screen; ANTHROPIC CREDIT RAN OUT during testing (topped up by owner)
- Owner: a question + an immediate second part is ONE question; the answer must grow append-only (no rewrite, no new
  card). Built: isFollowUpOf + no-candidate-speech window → growLiveAnswer (queued if the first answer is still
  arriving); candidate speech judged by loudness; "same question found again" never grows/relabels; prepared answers
  shown in live layout (display only). The 15 s cooldown's job is now done by this merge (clear new questions not held).
- Last complete mock battery: 6/6 PASS (66/66 detected, 0 dup, 0 own-voice, prepared 12/12, two-part stays one card).
- ~08:00 the Anthropic account behind the PRODUCTION key hit "credit balance too low" from test volume; stopped all
  tests; owner topped up; verified with a 5-token call; no real user hit it (no prod log errors). RULE: testing needs its
  own capped key — never run batteries on the prod key again; state cost before any run.
- Reruns after top-up: musthave all pass, match 12/12 + 0 false, follow-up structure append-only 4/4 (judge strict on
  whether 1 appended line fully answers vague "approach this"), live-e2e pass.

## 26 Sep 2026 — full mock-interview testing + fixes (branch fix/mock-interview-findings → PR, NOT live until merged)
- New harness test/mock-interview.js: two full calls (HM Sarah, boss David), real audio via Deepgram, 11 questions +
  small talk + candidate speech; modes clean / echo (no headphones) / noise; scores detection, duplicates, wrong cards
  (incl. own-voice), layout, prepared-answer hits, first-word delay, Opus-judged quality. ~$0.9 per run (Opus judge
  ~$0.33 of it). Also test/match-accuracy.js, experience-facts.js, platform-traps.js.
- Found + fixed (all evidence-first): 15 s cooldown dropped back-to-back questions; "Write me a query…" not a
  question; split/cut questions (join rules, hold-while-talking, card upgrade to the full question with generation
  tickets); interviewer bleed misjudged as echo (loudness decides; loudness-only when mic words not back yet);
  "What should I say" fallback used raw transcript incl. [You]/[Echo] (OWN-VOICE hole, also live today); years of
  experience computed in code; platform traps (Snowflake indexes) guard for answers AND growth; employer business
  never rewritten; answer-only-this-question; Sonnet for story/pitch + prepared answers; callClaude/vision read text
  blocks anywhere (Sonnet 5 thinking-first replies were thrown away as "API error" — live bug for Sonnet callers);
  must-have answers reach a live call batch by batch; "…you hear me okay?" small talk.
- Last full battery (6 mock interviews under load + all suites): 5/6 perfect; all 66 questions detected, 0 duplicates,
  0 own-voice cards; live/structure/must-have/match all pass. Remaining: noise-only split question sometimes gets a
  fresh (correct) answer instead of the prepared one; story answers add narrative colour (hard facts stay true).
- Cost note: all testing uses the production Anthropic/Deepgram keys (copied to local .env). ~$37 on 26 Sep morning.

## 26 Sep 2026 — DEPLOYED
- PR #1 merged by owner (merge 85a7549) → Railway deployment 537aa0aa SUCCESS, live on xhire.app ~40 s after build.
- Startup log: "Database tables ready", "Running on 8080", "[Semantic] Model ready in 1412ms", no errors.
- Pages /, /canvas, /launcher, /download all 200. Memory 0.51 GB of 8 GB (was ~0.14 GB).
- Railway var ONNXRUNTIME_NODE_INSTALL=skip set (skips CUDA download in build).
- Rollback: Railway one-click to deployment 7bfad9b1 (commit 1116138), or tag known-good-2026-09-25-start.
- Next: watch first real interviews' logs ([AI Auto-Detect] (fast), [Semantic], [Cache], [Stream] NO text,
  [MustHave], [Memory]); open items listed in the 25 Sep blocks below (tenure calc, "your X experience" tie-in,
  web switch_tab echo gap, npm test script, GitHub token in tradingview-mcp/.env.github is dead — gh CLI now logged in).

## 25 Sep 2026 (night) — must-have influence questions + meaning-based matching (feat/must-have-influence, NOT live)
- Owner: "how do you convince executives to use your report", "how do you convince when they push back" get asked
  constantly → always in the bank, answers ready. Added 8 influence & pushback questions to MUST_HAVE (role-neutral).
- ensureMustHavesReady: inserts missing must-haves (starred) at build AND at live-call start (so existing sessions get
  them), prepares answers in the background with the SAME generator as Generate All (answerSessionQuestions,
  extracted from the generate-batch route); paid plans only (free plans cap answers in the web app). Live bank reloads.
- Found: bank matching was word-based only → paraphrases never matched. Added SEMANTIC MATCH: local embedding model
  (@huggingface/transformers, all-MiniLM-L6-v2) adds meaning-based candidates (~5 ms), Haiku verify still confirms
  (paraphrase counts as same question). Loads in background at boot; falls back to word matching. SEMANTIC_MATCH=0 off.
  Cost: +~185 MB RAM, ~480 MB node_modules, ~23 MB model download at boot.
- Fixed: a matched bank question with no answer yet left an empty card → now answered on the spot (fills the bank).
- Proof: test/musthave-e2e.js all pass (3 paraphrases → prepared answer in ~1.0–1.1 s; unrelated question not forced;
  free plan gets questions, no auto answers). structure 9/9, live 16/16, accuracy 19/20, memory 5/6.

## 25 Sep 2026 (late) — answer STRUCTURE + speed (feat/session-memory, NOT live)
- Owner's design: full read-aloud sentences, one per line; layout fixed by question type (general / code / story /
  pitch); the style picker changes WORDING only; employer on a separate dimmed "↳ At <Employer> — …" line, only when
  a real example helps (never on plain concept questions); story questions get a "▸ At <Employer>" heading.
- Built LIVE ANSWER COMPOSER (server.js, one block): classifyQuestionShape, liveLayout (style → STYLE_LAYOUT params:
  executive ≤2, direct ≤3, keywords = cues, star = S/A/R labels), LIVE_TONES for all 11 styles, output contract +
  normalizeLiveAnswer (enforces line cap, strips ↳ when not allowed, drops prose in cue style), growth inserts above ↳.
  Renderers: canvas formatAnswer, index rAns / formatCanvasAnswer / formatPopOutAnswer draw ↳ (dim) and ▸ (label).
- Bugs found+fixed on the way: (1) the style picker NEVER applied to live answers (answer_style not loaded into the
  call cache) — now loaded, and a mid-call switch reaches the running call; (2) Sonnet 5 "thinks" on its own → 1.3–3.3 s
  first-word spikes; thinking off for live answers (LIVE_THINKING=adaptive reverts) — accuracy 19/20 & 18/20 with it
  off vs 15/20 on; (3) empty answers can't reach the screen (retry once, else a visible error; stream logs why).
- Echo rule narrowed: their VALUE phrases are banned ("dig in", "ownership"), their concrete things (shipment tables,
  warehouses) are named on purpose. Aim note ("what they care about", from BRIDGES) sits next to the question.
- Speed: FAST route — a clear interviewer question fires immediately (skips 0.8 s wait + AI extraction), everything
  else takes the AI route; ONE door fireDetectedQuestion for both. FAST_DETECT=0 reverts. Prompt caching of session
  material (saves cost; no measurable speed change). PROMPT_CACHE=0 reverts.
- Final proof: unit all pass; structure 9/9; live-e2e 16/16; memory 8/10 (both misses 7/8); accuracy 18/20;
  delay (realistic session, interviewer stops → first words) ~0.95 s, prepared answer 0.78 s (live app ~1.5–1.9 s).
- Open: occasional tenure miscount ("3.5 yrs" for Mar 2022–now); "tell me about your X experience" sometimes skips
  the tie-in to their use; web switch_tab path lacks the echo check.

## 25 Sep 2026 (pm) — values/concerns across interviewers + technical accuracy (feat/session-memory, NOT live)
- Owner's 2nd example: HM said she likes people who dig in before escalating + their data is messy; next day her
  boss asked something close → answer should settle THEIR concern through HIS workplace (R&L is messy too, so he
  digs first), never in their words, hard facts unchanged.
- Built: notes now capture per-interviewer VALUES / CONCERNS / ENVIRONMENT / intro; BRIDGES computed in the
  background as the call runs (their concern → his own proof → how to say it), fed to every answer; relevance
  judged by the model (keyword gate missed "stuck" ↔ "dig in"); prepared answers adapted unless the model says
  KEEP (swapped in whole, not streamed over); SHOW-DON'T-ECHO + hard-facts rule; TODAY's date for years.
- Accuracy (test/accuracy-bench.js, 10 technical Qs, Opus-graded, 2 runs): Haiku 15/20 both, Sonnet 18/20 both,
  Opus 16/20. Technical questions now default to Sonnet (LIVE_TECH_MODEL=haiku reverts).
- Proof: memory-e2e 5 cases — last full run 9/10, his example 4/4 on final code. live-e2e 16/16, rules 20/20.
- Delay (final code): technical new question first words ~2.1–2.2 s (Sonnet; was ~1.5–1.9 s), full ~3.8–4.0 s;
  prepared answer still 1.65 s, adapted swap ~4.0 s.
- Open: answers still borrow a word like "dig in"/"messy" (own_words 1/2, never 0). Web switch_tab echo gap.

## 25 Sep 2026 — session memory on branch feat/session-memory (stacked on fix/question-detection; NOT live)
- Owner's rule: every answer uses everything said in the interview session (his claims + interviewer's
  explanations, this call AND earlier calls) — consistent with what he said, aligned to their use case, proof
  from HIS own experience/domain, never their words.
- Before: answers saw only the last 6 transcript lines; the "candidate's recent responses" block was dead
  (`ws._userRecentLines` never set); earlier calls unused; prepared bank answers shown verbatim.
- DATA-LOSS BUG FOUND + FIXED: post-call step JSON.parse'd the JSONB transcript (pg already returns an array)
  → 0 lines → EVERY finished call's transcript was DELETED as "empty"; post-call learning and the voice profile
  never ran. One reader now: `transcriptLines()`. Could not measure prod damage — a read-only prod count was
  blocked by permissions; owner can allow it.
- Built (SESSION MEMORY block in server.js, one place): `labelTranscript` (drops echo + interviewer bleed in
  the mic so their words are never "his"), per-call notes (`live_transcripts.memory`, ADD COLUMN only),
  earlier-call notes loaded at call start, long-call digest, `buildConversationContext` used by new answers,
  grow, and prepared answers (adapted on the same card when the topic came up; bank never overwritten).
  Proof line only when the topic already came up (overrides DIRECT MODE's no-stories rule for that answer).
- Proof: `node test/memory-e2e.js` (judge = Sonnet): before 0/3; after 3/3 twice + finished call kept.
  `test/live-e2e.js` 16/16 and question-rules still pass on this branch.
- Delay (`node test/latency-bench.js`, interviewer stops → first words, median of 3): live 1.54–1.89 s,
  fix#1 1.52–1.61 s, memory 1.63–1.76 s. Prepared answer: 1.7 s on all; adapted version replaces it ~3.3 s.
- Open: `ANALYZE TABLE` suggested for Snowflake (not a real command) — accuracy guard issue, not touched.

## 25 Sep 2026 — #1 fixed on branch fix/question-detection (NOT live yet)
- Bug: Electron sometimes missed a question, and "What should I say" did nothing.
- Cause (proven): `isQuestion()` threw away normal questions ("Please describe…", "Talk me through…", "Share an
  example…", "Okay. So how…", "In your role, what…"): 13 of 20 test questions. Auto-detect post-filter and the
  button both ran it, so both dropped silently. The canvas also hid server errors in the console.
- Fix: sentence-aware question rules in ONE block (`// === QUESTION RULES` in server.js); user-triggered
  requests (button / typed / clicked line) are never filtered and never end silently; canvas shows errors as
  toasts; auto-detect pre-filter uses the shared candidate rule; the user-speaking flag no longer leaks to a
  global (guard stays OFF by default, `USER_SPEECH_GUARD=1` turns it on).
- Proof: `node test/question-rules.js` (old code 14 fails → 0). `node test/live-e2e.js` = real server + real
  Deepgram + Haiku with spoken audio: old code fails 3 of 5 cases, new code passes all 8 (including no-card
  cases for candidate talk and small talk). Canvas toast checked in a real browser.
- Local test setup: embedded Postgres on :54329 (scratchpad), `.env` with PORT=3999 + local DATABASE_URL.
  live-e2e refuses to run against a non-local DB.
- Rollback: tag `known-good-2026-09-25-start`.
- Own-voice safety (owner's hard rule: never answer what HE says), commit 2:
  - "What should I say" read [You]/[Echo] lines too, so it answered his OWN question. Pre-existing in live code
    (reproduced on the live version side by side). Now uses `interviewerLines()` — the same rule as auto-detect.
  - Echo check was text-only, so the interviewer's question leaking from speakers into the mic got marked as
    "echo" and dropped (pre-existing race = another "missed question" cause). Now a shared server clock
    (`openDeepgramStream` timeline, first-word timestamp) decides who spoke first: any mic lead → it's the user;
    call audio clearly first → the interviewer. Measured: echo = mic first 50–245 ms; bleed = call first 83–163 ms.
  - live-e2e now has 16 cases incl. 5 own-voice/echo and 2 speaker-bleed cases. All pass.
- Open: web `switch_tab` path (index.html only) re-opens Ch1 without the echo check — not Electron; not touched.
- Next: owner's go to merge/deploy. Then "the massive one".

## 25 Sep 2026 — project set up
- Fresh clone of origin/main (1116138). CLAUDE.md written. Nothing changed in the app yet.
- Next: owner lists the craziest issues; reproduce each before fixing.
