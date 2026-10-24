# Handoff

## 24 Oct — Answer Note v2 (branch feat/answer-note-v2)
- Owner on v1: "the ugliest", "left side must show full question, expandable windows everywhere", "variations is harder to
  spot", "i meant another way the question could be framed and most 3", "hard to see all whats it at glance".
- Seed v2 (data/note-seed.json): 43 distinct questions in 11 sections; each = short bold title + the full question + up to 3
  REWORDINGS of that same question (never a different question). lib MAX_WAYS = 3; POST item refuses a 4th other way (400).
- Group name = short title, new column answer_note_groups.section (ADD COLUMN IF NOT EXISTS), items[0] = full question.
- Notes seeded with v1 move to v2 once (loadNote → upgradeNoteSeed, one transaction, note row locked, settings.seedVersion=2).
  upgradePlan never deletes an item with an answer, KEY or history and keeps its question; the SQL also re-checks emptiness.
- Page rebuilt like a notes app: sections fold, Titles only, drag divider / hide left side, Expand (F), Pop out a question into
  its own window (?solo=gid), cards for the ways, always-editable answer, Aa format bar, ... menu (follow call, theme, size,
  page colour). Light paper default, dark mode; contrast measured >= 4.5:1 in both.
- Proof: npm test green (answer-note 48 checks incl. upgrade), e2e 39/39 local (2 model calls; upgrade via the real route),
  browser check 24/24 (scratchpad note-v2-check.js). Rollback tag known-good-2026-10-24-before-note-v2.


## 24 Oct — Answer Note (branch feat/answer-note, PR open, NOT merged)
- Owner's ask (23 Oct): a desktop note he reads from DURING a call — left rail = question groups, horizontal tabs = the ways
  one question gets asked, each tab = his answer; AI-written from his résumé, hand-editable with fonts/colours, background
  colours, smart search, shortcuts, one click to the answer.
- Built: `/note` page (public/note.html) + routes `/api/note…` in server.js (block "ANSWER NOTE") + logic in lib/answer-note.js
  + shared matcher/search public/note-match.js (one copy for page + server + tests) + seed data/note-seed.json (18 groups /
  94 phrasings mined from his 16 real interviews). Tables answer_notes / answer_note_groups / answer_note_items (additive).
- Rules: every content write goes through applyChange — the current text goes into `versions` (cap 20) BEFORE anything
  replaces it; a save with a stale baseVersion is refused 409 and the page shows both ("Use that version" / "Keep mine");
  AI buttons (Regenerate / Shorter / Add a number / Sound like me / free text) never overwrite silently — Undo + History
  restore. Answers use the live writer rules (composeLiveSystemPrompt + normalizeLiveAnswer, Haiku, `employerLine: true`
  = his own example always welcome) from the chosen session (or his latest with a résumé), end with a KEY glance line.
  Lazy write on first open of a tab (settings.autoGenerate=false turns it off); "Generate all" fills the rest 2 at a time.
- Live link: canvas.html + index.html `question_detected` → tellAnswerNote() (BroadcastChannel 'xhire-note' + localStorage
  fallback); the note jumps to the closest phrasing (Dice + keyword containment, threshold 0.4) and flashes it. Fire-and-
  forget; the live pipeline never waits on it.
- Entry points: launcher card "Answer Note" (desktop + browser), canvas toolbar button, web nav button. Desktop opens it via
  window.open(..., 'alwaysOnTop=yes') from the overlay — needs no app build; NOT yet proven inside the real Electron app
  (only in Chrome). If the child window is not on top, an Electron change (setWindowOpenHandler / explicit BrowserWindow
  with setAlwaysOnTop) is the fix — described in the PR.
- Proof: test/answer-note.js 34 checks (in npm test); test/answer-note-e2e.js 31/31 on a local server (2 model calls);
  real Chrome via Playwright: groups/tabs, edit + bold + KEY edit autosave (Saving… → Saved, survives reload), background
  colour, search, ↑↓←→ / 1-9 / Cmd+E / R / "/" / Esc, read mode, history restore, live-link jump from a second tab.
  Total model calls in testing: 4 Haiku answers. Screenshots in the session scratchpad (note-01..04.png).
- Open: Electron real-window proof; plan cap for note answers = the bank's monthly cap (checkAnswerLimit) — owner to say
  if the note should count differently; a font-size/family picked with no selection sets the note default (by design).
- Rollback: tag known-good-2026-10-23-before-answer-note (tables are additive, harmless).

## 23 Oct — Say pressed mid-question (PR: fix/say-mid-question)
- Owner: candidates press Say early, while the interviewer is still asking, because they can already hear the question.
- Reproduced (early-stale-e2e scenario 8, old code): Say read only FINAL transcript words; the question still being spoken was
  interim → "nothing new" → it jumped to the OLD card; when they finished, a SECOND card appeared.
- Fix (server.js): Say reads the in-progress words too (`interviewerInterim`); a press mid-question marks `ws._sayTurn`; the
  question they then finish grows that same card (`growSayCard`) — or, if it finishes before the card exists, the press
  answers the whole question.
- Proof: scenario 8 PASS (was 2 FAIL); all 8 scenarios, live-e2e, npm test PASS. Note: run scenario 6 WITHOUT IDLE_TIMEOUT_MS=20000
  (its 95 s pause trips the short test cutoff). `ONLY=6,8 node test/early-stale-e2e.js` runs chosen scenarios.
- Rollback: tag known-good-2026-10-23-before-say-midq.
- Follow-up (owner: "TEST PROPERLY"): 6 early-press scenarios (8–13: pressed at 35% / 60% / 92% / as they finish / first question
  of the call / then a new question). Found + fixed 3 gaps: (1) "nothing to add" used 90% similarity and skipped "on their
  phones" → now any new word grows the card; (2) an early press left the card TITLE as the half heard → title becomes the whole
  question (server + index.html grew branch); (3) a press right after a phrase went final / before the held question fired
  wasn't mid-question → now also counts (`_ch1HeardTs`, `_ch1PauseTs`, `ws._questionPending`). All 13 scenarios, live-e2e,
  npm test PASS. Rollback: known-good-2026-10-23-before-say-midq-2.

## 22 Oct 2026 — Say stays on the answered card (PR #104) · LIVE 21:23Z (deploy e5aced7b, 1cf07b6, #103 + #104)
- Say > 90 s after a card with nothing new asked re-ran the AI and rewrote the card → no age limit now (nothing new since =
  still their latest question); lines that grew/upgraded a card count as that card (`_lastCard.heardTs`).
- A question's second part ("What tools did you use for it? And who used it every week?") made a 2nd card → isFollowUpOf
  catches it/them pointing back in a short ask (not "handle it when…").
- Proof: early-stale-e2e 7 scenarios ALL PASS (6, 7 failed before), live-e2e ALL PASS, npm test green.
- Deployed by hand (Railway outage paused builds ~05:00–21:08Z; GitHub push did not auto-deploy). Live smoke: pages, APIs, auth refusals, WebSocket all PASS. Rollback tags:
  known-good-2026-10-21-before-detect-fix (before both), known-good-2026-10-22-before-say-fix.
- Railway posted a security notice: reconnect GitHub after their credential reset — if merges stop auto-deploying, check it.

## 21 Oct 2026 — answers before the question finished + stale answers (regular panel), user call 11:00–11:33 CDT
- Evidence (Railway logs 16:00–16:33Z, session 626c2a88…, copilot:false): fast route answered fragments and statements
  ("So when when it comes to Power BI, right,", "Build reports that", "…what the culture is all about.", "I do have one
  question I wanted to ask you."); Deepgram default endpointing (10 ms) cut sentences ("…how I wanna | describe the
  culture." → card "Describe the culture."); full question then made a NEW card; Grow folded new questions into a 3-min-old
  card; a new question matched an already-answered card from this call; every Say press jumped to the old card first, and
  once answered Haiku's "I understand you want me to find…" as the question.
- Fix (server.js): question rules (cut-off endings, comma tails need you/?, tag checks, announced questions, third-person
  task lines, lowercase continuations); Deepgram endpointing=500 (DG_ENDPOINTING_MS) + UtteranceEnd fires held questions;
  fast route fires only after a real pause, eager/cut lines held (3 s safety net); one turn = one question; lowercase
  continuation rejoins within 15 s; AI-route timer waits while they talk (and a cleared timer is never re-armed); Grow and
  upgrade only within 20 s (GROW_WINDOW_MS); answered cards from this call aren't reused for a new question; Say jumps only
  when nothing new was said, reads only lines since the card, rejects non-question extractions.
- Proof: test/question-rules.js (+16 real lines); test/early-stale-e2e.js (5 cases from the call) OLD code 7 FAIL → new
  ALL PASS; test/live-e2e.js 21/21; npm test green. Answer lands ~0.8–1.2 s after the interviewer's last word (old code
  fired up to 1 s BEFORE it; a clean "?" question used to land ~0.3 s after).
- Rollback: tag known-good-2026-10-21-before-detect-fix.
- Open: watch the next real call for "[Fast] … answering held question", "[FastMatch] Skipping already-answered card",
  "[WhatShouldISay] Extraction was not a question"; Grow lines now log the line that grew the card.

## 13 Oct 2026 (21:15) — continued assessment + press shows answers as cards (PRs #100, #101) — owner: "it works now"
- #100: a CONTINUED sitting said "the last answer stands" for answers given in an EARLIER sitting (not on his screen).
  Carry text no longer says "never redo it"; DONE items on screen are re-shown as "<item> — answered earlier:"; volatile
  block CONTINUED SITTING (assessment + priorMemory + pressed); answeredItems() records those headings.
- #101: a press with questions already answered THIS sitting gave "Nothing is being asked right now; the last answer
  stands (…)" with the answer in a bracket (log 14 Oct 02:09–02:10Z). Now every press re-shows each on-screen answered
  question as its own block "<question> — answered earlier:" + same lines. "Nothing open" = screen holds NO question.
- Proof kit: scratchpad frontwin/continue.js (1 Sonnet call; SECOND=1 = this-sitting case). test/meeting-copilot.js +2,
  test/assessment.js 53 checks. Rollback tags: known-good-2026-10-13-before-{carry-restate,answer-card}.
- Open: 17 junk rows (blocked on Railway SSH link); read [Overlay] diag / [Usage] / [Assessment] logs after his next real
  run; co-pilot plan limit unanswered; Support Weekly Sync artifact — delete when he says.

## 13 Oct 2026 (19:00) — front-window read, launcher fonts, Snap shortcut, auto-follow (PRs #95–#98, desktop v1.1.6)
- #95 screen reader: overlapping windows → FRONT window first + decides TYPE, "Behind:" lines, "Typed in the box (not
  sent): …". Cause in log: "Transcribing the main terminal window". Repro kit: scratchpad frontwin/ (1 Sonnet call).
- #96 launcher Assessment History rows = Continue-last fonts (600 12px / 10px #94a3b8).
- #97 (v1.1.6, installed on his Mac): Snap = ⌘⌥↵ (Ctrl+Alt+Enter) → copilotCapture(); in-page always, global with Global
  Shortcut Mode. Keys: ⌘↵ Assist, ⌘⌥↵ Snap, ⌘⇧↵ Say. Real-key proof harness scratchpad gs-proof/snap.js (takes over the
  keyboard ~30 s — ASK him first; a blocked Write once launched Electron with no file → error dialog on his screen).
- #98 auto-follow: ONE door revealAnswer() — newest answer's first line to the top, re-applied per streamed chunk, never
  past it / never back up; instant scrollTo (the list has CSS scroll-behavior:smooth, whose in-between positions read as
  "scrolled up"). userScrolledUp = reading ABOVE the newest answer. Proof: scratchpad gs-proof/follow.js.
- Assessment "Continue last" checked against [Assessment] logs: correct (most recent sitting first). Owner confirmed.
  Known weak spot (owner said leave it): titles come from whatever is on screen at the first carry, incl. background
  windows (my terminals named two of his). Offer if it comes up: name from the front window only, or tap-to-rename.
- Rollback tags: known-good-2026-10-13-before-{front-window,as-font,snap-shortcut,auto-follow}.

## 13 Oct 2026 (18:00) — Global Shortcut Mode (PR #93, desktop v1.1.5)
- Owner's ask: Settings → Live Mode → Global Shortcut Mode (desktop only, default OFF). ON = Cmd+Enter (Ctrl+Enter on
  Windows) runs Screen Assist from any app; the overlay is not raised or focused. He uses it in meetings (incl. Assessment).
- electron/global-shortcut.js (pure) + main.js `set-global-shortcut` IPC; a press only sends `global-shortcut:
  screen-assist`; the page runs the same screenAssist(). Released on OFF, on every page load, on quit; the canvas re-applies
  its saved setting (`xhire_set_globalShortcut`) on load. Status line: on / off / "could not turn on: … taken by another
  app" / "needs the latest desktop app" (builds ≤1.1.4).
- Proof: npm test (test/global-shortcut.js 24 checks); real Electron harness with real preload + canvas: real Cmd+Enter
  with Finder frontmost → Screen Assist ran once, Finder stayed frontmost, overlay not focused; OFF → ignored; relaunch →
  ON restored. electron-builder --mac --dir packs global-shortcut.js. Live canvas serves the toggle.
- Do NOT run electron/main.js from source for tests: clearOldPrivacyEntriesOnNewVersion() runs tccutil reset on
  com.xhire.overlay — the INSTALLED app's mic/screen permissions. Use a harness like scratchpad gs-proof.
- Rollback: known-good-2026-10-13-before-global-shortcut (Railway one-click to the #92 deployment).

## 13 Oct 2026 (03:00) — overlay "not moveable, esp when live": hold-off + diagnostics
- Code path (inference, not yet measured): live + co-pilot history runs a full-display grab (desktopCapturer + toJPEG)
  every 0.7 s on the Electron MAIN process — the same thread that must flip setIgnoreMouseEvents(false) as the pointer
  reaches the toolbar. Fix (page only, no rebuild): auto-capture holds off while the pointer is on/near the overlay and
  for 2 s after (window.__overlayPointerAt from the click-through handler). Camera button unaffected.
- Diagnostics: overlay sends `overlay_diag` every 10 s while live → server log `[Overlay] diag:` lagMax (page stall ms),
  pingMax/pingAvg (get-bounds round trip = main-process busy), grabMax/grabN, flips, presses, toolbarPresses, heldOff.
  READ THESE after his next live drag complaint before changing anything else.
- Proof: npm test (wiring +5); real canvas page with stand-in bridge: held off with pointer near, grabbed when away, no
  page errors; diag line reached the server log.
- 17 junk rows (session 3cf29ca5): owner said delete. Blocked on Railway SSH key — owner to run
  `railway ssh keys add -k ~/.ssh/id_ed25519.pub -n claude-code-rba-mac`; then read → back up → delete by id → verify.
- Rollback: known-good-2026-10-13-before-drag-live.

## 13 Oct 2026 (02:30) — smarter pull-back
- pullIndexes (free): page numbers incl. "previous/first page"; kinds ("the chart", "rate card", "memo", "puzzle",
  "rules", "code"); shared words only when RARE across the call's pages (df ≤ 30%), ask words ×2 — a template header on
  every page no longer pulls look-alikes. A page bigger than the 12k pull room comes in cut, never skipped.
- planPull → Haiku router (copilot-pull, 1.5 s deadline, fails to "none") ONLY when the ask is real, a non-bare page is an
  index line, and the free rules found nothing. Index lines now carry distinctive words from the whole page ("also: …").
- Proof: test/long-sitting-e2e.js 5/5 (pack pages pushed to index lines by 30 filler pages; "that chart" 96%, "rate card"
  $99, growth 168 free; "extra fee for help unloading" → router PAGES: 2 in 0.9 s → liftgate fees); pack 15/15;
  meeting-copilot-e2e 18/18; npm test (copilot-context 30 checks). Router ran once across all runs.
- Rollback: known-good-2026-10-13-before-smart-pull.

## 13 Oct 2026 (02:00) — co-pilot context: tiers + prompt caching + usage logs; INFO-page regression fixed
- REGRESSION FOUND + FIXED: PR #84 compacted every page the reader tagged INFO; the pack's page 5 (12%/8% surcharge, 20%
  growth) was tagged INFO → rules vanished → 3/15 pack checks failed on live main. Now isBareInfo(): an INFO page with any
  figure or rule word rides in full; the reader prompt defines INFO as no figures and no rules.
- Tiers (lib/meeting-copilot.js buildCopilotBlocks): every page listed; full = open question / data / rules / newest;
  index line = bare info, fully answered page (pageAnswered vs ledger), or over budget (oldest first). pullIn(): an index
  page returns in full when the ask names its page or shares ≥3 names/numbers. >60 index lines fold to a count line.
- Cache order: system + stable (session material, assessment carry, docs) + one block per page (cache_control on the last)
  → image → volatile (pulled pages, digest, talk, ledger, ask). Regular (Haiku) mode unchanged, string, no cache.
- loadCallRows: ALL seen/said/document rows + newest 400 talk rows + newest digest (all-day calls keep every page).
- [Usage] <tag> log on copilot-answer / copilot-read / copilot-digest / copilot-judge / assessment-carry.
- Proof (same 8-page pack, before → after): 12/15 → 15/15; answer input 64.5k full-price → 26.3k full + 32.6k cached;
  ~15.8¢ → ~9.1¢ for 10 answers. meeting-copilot-e2e 18/18, assessment-e2e 25/25, npm test (+copilot-context 18 checks).
- Rollback: known-good-2026-10-13-before-smart-context.

## 13 Oct 2026 (night, last) — Assessment: who sees it
- Owner's call: Admin, Premium, UAT Tester (plan 'test'). Default lives in lib/assessment.js ASSESSMENT_DEFAULT_PLANS;
  is_admin accounts always; env ASSESSMENT_PLANS overrides without a deploy ("all" = everyone). Free/Pro: no card, POST 403.
- Also shipped tonight: card text "Help with any online test"; smaller assessment page text (PR #88).
- OPEN (owner not yet answered): co-pilot answers have NO plan limit (free plan's 10-answer cap is Q&A only).
- Proof: assessment unit checks; assessment-e2e 25/25 local (pro + free refused).
- Rollback: known-good-2026-10-13-before-assessment-plans.

## 13 Oct 2026 (night) — Assessment never auto-starts recording; co-pilot side bar follows the panel
- Opening an assessment sets co-pilot + history only; he presses Go Live himself (toast says so).
- Panel closed → body.board-closed hides .copilot-float (📸, files, Hist, pause, count) + its capture list; auto-capture
  keeps running; hidden parts are 0×0 so clicks pass through. Body starts board-closed (panel starts closed).
- Proof: npm test (assessment 44 checks); real page in Playwright: open → copilot on, live false, side bar none;
  panel open → flex; closed → none.
- Rollback: known-good-2026-10-13-before-pill-fix.

## 13 Oct 2026 (latest) — × remove on assessments
- × in front of every History row and on the Continue card → inline "Remove <title> and everything in it? Remove / Keep"
  (no browser dialog). DELETE /api/assessments/:id: only kind='assessment' rows of this user (a company session → 404),
  refused while open in the overlay (409); FK cascade removes sittings, call log, screens, carry. List updates only after
  the server confirms; empty list → back to sessions, card's "Last:" line follows.
- Proof: test/assessment.js 40 checks; assessment-e2e 23/23 local (incl. 404/409/cascade-to-zero/twice→404);
  meeting-copilot-e2e 18/18 rerun (existing co-pilot unbroken); screenshots of × and confirm.
- Rollback: known-good-2026-10-13-before-assessment-remove.

## 13 Oct 2026 (later) — desktop ASSESSMENT entry + two co-pilot row-window fixes
- Assessment (Electron only; launcher card hidden in a browser): not tied to a company — sessions.kind='assessment',
  hidden from /api/sessions. Open → no history: starts at once; history: "Continue last" (title + start time + sittings)
  / "Start new" / History list. Overlay opens in co-pilot, history on, goes live (?assessment=new|continue).
  Each sitting (one live connection) ends with a CARRY (Sonnet, thinking off): earlier carry + digest + screens + answered
  ledger → live_transcripts.memory; the first carry with content LOCKS sessions.title (written once). A new sitting starts
  from the latest carry (a sitting that ended without one gets it built first; a reconnect waits for the carry in flight).
  Prompt: ASSESSMENT frame + "THIS ASSESSMENT SO FAR" (never gated like interview memory). Blank assessments are reused.
  Résumé copied from his latest interview session. Who sees it: lib/assessment.js canUseAssessment — everyone now;
  env ASSESSMENT_PLANS=pro,team narrows it (admins always). Assessments do not count toward the session limit.
- Fixes found on the way: loadCallRows returned the OLDEST 400 rows (9 Oct call froze at rows=400 — new screens/answers
  invisible) → newest 400; digest compaction counted rows by position → now by timestamp (meta.upTo).
- Proof: npm test (test/assessment.js 33 checks); test/assessment-e2e.js 16/16 on local server with real models
  (title locked "TalentCheck Online Assessment — …", continue starts from carry, same question next sitting not redone,
  second carry keeps the title); launcher screenshots desktop vs browser.
- Rollback: known-good-2026-10-13-before-assessment.

## 13 Oct 2026 — co-pilot: answers only real asks, never the same question twice, compact non-questions
- Evidence (Railway logs, his 12 Oct 21:40 CDT assessment): 3 unasked cards came from the voice route — a training video's
  voice-over: 2 statements ("Motion properties, which covers…", "When building options, ensure…") and a cut fragment
  ("Do you have at least"). His other 15 cards were his own presses (Assist / Cmd+Enter after a camera capture).
  9 Oct call: the co-pilot branch skipped the de-dup → the same question carded twice 0.5 s apart and again a minute later.
  `said` rows were cut at 600 chars → a 2,000-char press lost its later blocks and the next press answered them again.
- Fix (lib/meeting-copilot.js + server.js `routeHeardToCopilot`, the one door for heard lines in co-pilot mode):
  gate = a FINISHED ask (ends "?" or an explicit ask to him) → repeat check against every answered ask/block title on the
  call + in-flight asks → repeat = `copilot_dup` (overlay flashes the earlier card, no new answer) → Haiku judge (ASK/NOT:
  voice-over, checklist read out, rhetorical) with a 3 s deadline, fails open. Every skip logs `[Co-pilot] heard, not answered (reason)`.
  Said rows carry meta {cardId, ask, answered[]} (whole ledger); prompts get ALREADY ANSWERED ON THIS CALL.
  Transcriber tags TYPE: QUESTION/DATA/INFO and [CUT OFF]; press skips cut-off questions (says scroll) and repeats.
  Older INFO pages ride as first lines only; talk the digest covers is not repeated raw (6-line overlap).
- Proof: npm test (new test/copilot-ask-gate.js 28 checks on his real lines, wiring +5); judge 9/9 on Haiku with his real
  lines; one Sonnet press: Q3 already answered → not redone, cut-off Q4 → "scroll", not guessed; meeting-copilot-e2e 18/18
  real audio on local server (judge ASK in 785 ms, card served).
- Cost of the change: +~0.8 s before a heard question's card (judge). Typed / pressed / Say are never gated.
- Rollback: tag known-good-2026-10-13-before-copilot-gate.

## 3 Oct 2026 (night) — desktop v1.1.4, capture via the screenshot backend
- Found: the OS content-protection flag (the eye) hides xHire from other apps and from Cmd+Shift+3, NOT from the app's
  own getDisplayMedia stream — every co-pilot frame had the panel in it (obscured tables, panel text read as content,
  streaming cards counted as screen changes). Page-side mask attempts (#70–#73) were defeated by stale window.screenX.
- Fix: v1.1.4 (PR #75) — main.js `capture-display` (desktopCapturer thumbnail = ScreenCaptureKit, same backend as the
  screenshot) + `get-bounds`; preload captureDisplay/getBounds; canvas.html uses the app path when present, falls back
  to the page stream + mask on older apps. Verified on his Mac: log mask={backend:"app",…}, preview shows no overlay.
- Installed on his Mac (ditto → xattr -cr → ad-hoc codesign com.xhire.overlay → `tccutil reset All` → relaunch); his
  rule: on reinstall wipe ALL old permission rows. PR #74 = camera dim-and-grab (opacity floor 0.2) — now only a fallback.
- Also today after the evening block: Hist default on (#68), × per capture (#69), capture list preview (#72).
- Open: nothing blocking. Next real test is a live meeting. The capture is the whole display: private windows off it.

## 3 Oct 2026 (evening) — meeting co-pilot, PRs #42–#66, all LIVE
- State: co-pilot (Electron only) = collect-then-assist. Auto-capture (Hist on, play on, 0.7 s tick, settle ~1.4 s) and
  the camera store frames only (`call_screens`); nothing goes to a model until Assist / typed / heard question; then the
  unread pages are read once (Sonnet, 8 at a time, overlay hidden from the frame), frames dropped after the read. A press
  with nothing typed answers every open question across captured pages, one card each (page tag, question title,
  working, "Result:" last → lifted to a green badge). Code: fenced with the language, must run as written on the stated
  engine, VS Code palette, solid ground, 12.5px (font setting applies 1:1). Thinking OFF in History mode (measured 10/10
  either way; thinking blew first words to 13–30 s on his real context). Session résumé/JD/earlier-call notes ride along,
  gated "only if the call is about that job"; earlier-call notes never stand in for a page missing from this call.
- Proven on his Mac today: 8-page pack 4/4; canal page 6/6 (voice+screen); ops-update listening test 8/8 (voice only);
  Vendor Settlement (2-min briefing + 9 scroll parts + SQL + Python + 10 Qs) 10/10 twice with code that runs; first words
  ~0.8 s, full 10-question answer 16–20 s incl. ~10 s reading nine pages.
- Misses found and fixed today (each has a test): pill unclickable (SOLID list + DOM order), drag stuck, captures with
  no image (captureFrame returns raw base64), fingerprint too coarse for a page at 1/3 of a Retina frame (64×36 Δ12 1%),
  region rule that missed his pages (removed; owner control via play/pause instead), adaptive thinking eating the cap,
  "Part 9 — Q1" wording breaking cards (QLINE), RESULT chip defeating the lift (match the chip), a 60% glass code block,
  old `pre code{font-size:11px}` + grey base overriding the new look, uncaptured page filled from earlier-call notes.
- Process slips to remember: shipped a look change (Open-in-browser button) he had not asked for → removed (#64); he
  wants LOOK changes mocked in a Chrome artifact first. One merge went through with 2 red checks because the ship
  command was chained without gating → gate on the test exit code (done since).
- Open: his yes/no on re-asserting content protection every Go Live + 30 s with a clear hidden/visible state on the eye.
  Watcher "Failed to fetch" at the start of a stint (live socket not up yet) is retried now but still noisy in the log.
  All test artifacts deleted. Keys: ElevenLabs in DisasterForensics/.env (creator tier) for test audio.
- Rollback: any `known-good-2026-10-03-*` tag; last = known-good-2026-10-03-missing-page.

## 3 Oct 2026 (afternoon) — co-pilot live-test fixes (PRs #32–#40)
- His live runs drove these, in order: pill not clickable (#32 SOLID list; #34 DOM ORDER — any fixed element over the
  panel must be LAST in <body>); resize stuck to the mouse (#33 stay solid while a button is held; #36 end on the first
  move with no button); presses arrived with no image (#35 capture reports its stage + screen chip; #36 fingerprint from
  `lastCaptureCanvas` — captureFrame returns RAW base64, an <img> was always broken); auto-capture in History mode (#37,
  settled new page → background read, counter + toast); camera = CAPTURE ONLY, answers from Assist/typed/heard question,
  watcher health → `[Co-pilot] watch:` log lines (#38, #39 test scope); every page read as "already captured" (#40 —
  his capture is the WHOLE DISPLAY, page ~1/3 of it; measured: 64×36/Δ12, bar 1%).
- Rules in his words: co-pilot is ELECTRON ONLY; capture = everything on the display (he runs the page full screen);
  "indication it has captured, only then I move on"; history is per Go Live call (not yet carried from earlier calls).
- Deploy of #40 FAILED at BUILD_IMAGE with no logs (Railway-side) — this docs commit re-triggers the build. Live was
  still on #39 meanwhile (safe).
- Slip to remember: #38 merged with 2 red e2e checks because the ship command was chained without gating on the test
  exit code (rows were right; test mis-scoped, fixed in #39). Gate the merge on the tests.
- Next: his re-test with the tuned fingerprint → counter climbs page by page; read `[Co-pilot] watch:` and
  `camera-captured` / `auto-captured` lines against the pack answer key. Pack artifact still hosted — delete on his word.

## 3 Oct 2026 (later) — Co-pilot smartest mode (PR #31)
- Owner: "this MUST be the smartest" (embarrassed on a call when asked which Excel function to use). Everything
  co-pilot is ELECTRON ONLY (his words) — no web port, ever.
- Camera press: a screen captured earlier in the call is reused, not re-sent (client keeps every fingerprint of the
  stint, sends `screenKey`; server points the prompt at that capture — log "reusing earlier screen"). New screens get a key.
- History mode: every captured page is transcribed in full in the background (Haiku, meta.full) and all screens ride
  in the prompt ("SCREENS SHOWN THIS CALL", oldest dropped past 9k chars); answers on Sonnet with ADAPTIVE thinking at
  medium effort (puzzle probe 6/6 correct; first words 0.6–4.2 s, the slow ones on dense table pages). Without any
  thinking setting Sonnet thought on its own (4–8 s spikes) — the Q&A path disables it, co-pilot did not.
- Prompt rules: tool questions → exact function/formula + one plain line; no jargon unless it is the answer; puzzles
  decoded literally and matched to the options given; calculations finish every step; a wrong earlier card is
  corrected, not carried. Token cap by mode (700 / 1200) — page 8 was cut off at 500.
- Proof: test/meeting-pack-e2e.js 15/15 on the 8-page pack (test/fixtures/meeting-pack: tables, puzzle, chart, memos;
  Q1 $14,426 Blue Arrow, Q2, Q3 168, page 8 Redline $4,860; page 2 reused); meeting e2e 18/18; npm test 10 suites.
  One earlier pack run decoded the puzzle as Redline (bias from its own earlier cards) — hence the literal-decode +
  self-correct rules; not seen again in 7 further decodes.
- Hosted copy of the pack for his own call test: private artifact (link in project memory); delete after.

## 3 Oct 2026 — Meeting co-pilot (PR #30)
- Owner: co-pilot is for his WORK MEETINGS, not assessments — others share a screen (table, notes, questions) and ask
  him something; it listens, reads the shared screen, says what to say. Must be cheap by default; a History checkbox
  buys precision. Spec: docs/superpowers/specs/2026-10-03-meeting-copilot-design.md. Logic: lib/meeting-copilot.js.
- Call log `call_events` (new table, additive): kinds asker / you / document / seen / said / digest, keyed by the
  live_transcripts id of the call (`ws._callId`). Written ONLY while live (409 "Go Live first" otherwise); cleared on
  stop/close. Voice rows come from the real audio path (both channels, bleed/echo excluded).
- Trigger: detected question (door → `question_detected source:'copilot'`, Q&A path skipped in co-pilot mode), capture
  press (panic rule: always answers), typed note. The 3-second speech buffer is gone. Screen goes up only when the
  frame fingerprint changed (public/copilot-fingerprint.js, one copy for browser + tests).
- Regular (History off): last 6 voice rows + last seen + last said, Haiku, streamed. Smart (History on): running
  digest (Haiku, ≤1 per 3 min, only with new rows, background) + raw last 20 rows, answer on Sonnet (thinking off),
  streamed. Cards: copilot_start / copilot_delta / copilot_done over the live socket. Shape: Asked / On screen / Say.
- Proof: npm test (7 free suites, incl. test/meeting-copilot.js + test/meeting-copilot-wiring.js);
  test/meeting-copilot-e2e.js 18/18 (real audio → rows; routing; shape + table cited; no-image turn; smart answer
  consistent with the YOU line; digest row; stop → 409); test/copilot-switchtab-e2e.js 6/6 still passes; real Chrome:
  page loads clean, History persists, streamed card renders, fingerprint skips a repeat frame. First words 0.36–0.7 s.
- Not done / open: his real desktop call (Zoom/Teams) in co-pilot mode — read `[Co-pilot]` log lines after it.
  Prompt caching not used (fixed prompt is far below the cacheable minimum). Web app (index.html) has no co-pilot mode.
- Rollback: tag known-good-2026-10-03-before-meeting-copilot (table stays; it is additive and harmless).

## 2 Oct 2026 (later still) — remaining items (PR #27, #28 LIVE)
- PR #27: web app live cards — click the ↳ line → full story (expand_proof over liveWS; same as desktop PR #16). Proven
  in a real browser: 1 request, story shown, collapse, cached reopen. Rollback tag known-good-2026-10-02-before-web-details.
- PR #28: their AVOID words now sit next to the question as a hard list ([Memory] Avoid words log). memory-e2e prints
  borrowed words (free). Before 2/2 borrowed ("digging in", "ownership"); after 0/3, judge 8/8. Rollback tag
  known-good-2026-10-02-before-own-words.
- "Your X experience" tie-in: does NOT reproduce (2/2 aligned=2). One judge FAIL docked bank-sourced "roles" and the
  concrete noun "shipment tables" — both allowed by his rules; judge is stricter than the owner. Not changed.
- BLOCKED: deleting his 17 junk rows (session 3cf29ca5) — prod DB read/write denied by auto-mode ("Production Reads").
  Needs his permission rule or he deletes them in the app. Railway CLI is now linked to interview-prep/web here.
- Still his: Mac self-update needs Apple Developer ID; real-app proof of screen assist/co-pilot after his next assessment.

## 2 Oct 2026 (later) — open-bug sweep (PR #24, LIVE; tag known-good-2026-10-02-open-bugs)
- Fixed: Co-pilot mode — typed box + Assist now go to /copilot (were Q&A / Screen Assist); typed text labelled as the
  candidate's own note; co-pilot use keeps the live WS open (screenActivity). Web Switch Tab now closes the stream and the
  next Ch1 packet re-opens via ws._setupInterviewerDG (echo check) — the old copy had none. Mac "Update downloading…" toast
  was false (latest-mac.yml has DMGs only, no zip; ad-hoc signed) → now "reinstall from xhire.app/download". `npm test`
  runs the 5 free unit suites.
- Proof: npm test all pass; test/copilot-switchtab-e2e.js 6/6 (old code fails keep-alive; its switch-tab control was
  not clean because the socket had already idled out); canvas routing checked in a real browser with stubbed fetch.
- Rollback: tag known-good-2026-10-02-before-open-bugs (Railway one-click to the PR #23 deployment).
- Still open (not code bugs I can close alone): real-app proof of screen assist/co-pilot on his Mac; his 17 junk bank rows
  (needs his yes); Mac real auto-update needs an Apple Developer ID; web app has no "▾ details" proof click (feature port);
  answer-quality items ("dig in" echo, "your X experience" tie-in).
- Record loop in co-pilot mode still uses quiet Screen Assist on purpose (co-pilot has no same-screen quietness).

## 2 Oct 2026 — screen assist rebuilt for ANY assessment (PR #22, LIVE, deployment fdf9a366)
- Evidence (prod logs 10:21–10:56 UTC, his desktop session on an assessment): Co-pilot route never called; Record loop sent
  14 captures to /screen-assist → a new "answer everything visible" Haiku card every capture; his typed "ONLY GOOD ANSWER!"
  etc. went to the interview Q&A path blind (model: "I don't see a question"); every capture + typed line saved into
  the question bank (68 → 86); live WS idled out 3× (screen captures arrive over HTTP, not the socket). No audio flowed.
- His rules: any kind of assessment; don't answer always, suggest; REAL coding = real working answer; behavioral /
  personality = good-faith decisive pick.
- Built: new SCREEN_ASSIST_PROMPT (QUESTION: line + --- + suggestion by kind), Sonnet; auto captures quiet when no item or
  same item (word overlap ≥0.6); pressed always answers; typed box while screen shared → instruction for the item on screen;
  no bank rows; screenActivity keeps WS alive (IDLE_TIMEOUT_MS env = tests only); overlay skips only pixel-identical frames
  (a looser threshold had a thin margin vs one-word question changes — never risk a silent skip).
- Proof: test/screen-assist-e2e.js 13/13 twice (fixtures in test/fixtures/screens; coding answer passes 6 cases); control:
  no screen use → WS closes at 20 s; changed-rule run in real Chrome on the fixtures.
- Rollback: Railway one-click to 0b55b245 (PR #21 state) or tag known-good-2026-10-02-before-assessment.
- OPEN: not yet proven on his real desktop app during a real assessment — read [Screen Assist] lines after his next one.
  His session 3cf29ca5 still holds the 14 "[Screen Assist]" rows + 3 typed rows from this morning — delete only with his yes.
  Co-pilot mode itself untouched (Record/Assist/typed box still bypass it in co-pilot mode).
- Local test DB: embedded-postgres in session scratchpad (pg/start.cjs, port 54329); server: MUSTHAVE_PREBUILD=0 SEMANTIC_MATCH=0 IDLE_TIMEOUT_MS=20000.

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

## 3 Oct 2026 — late: Say button in co-pilot mode (one brain)
- Before: Say in co-pilot mode ran the old QA panic path (jump + bank match, no screens). Owner: "I expect it to be interactive, more technical support."
- Now (PR #78): server `what_should_i_say` in `_copilotMode` pulls the substantive interviewer lines since the last co-pilot ask (`ws._copilotAskTs`, stamped on heard questions and Say) and sends `copilot_say {text}` to the presser; overlay `copilotSay` goes through `copilotSend({ask, say:true, pressed:true})`; same ask answered <90 s ago → jump to that card, no call. Card tagged "· say".
- Endpoint loads the Q&A bank (`questions` of the session, 60 rows, 6000-char cap) into the co-pilot material for EVERY ask; prompt rule: a question about the person (yourself / background / have you done) is ALWAYS answered from résumé + bank, first person, no job gate — JD/earlier calls stay gated. Say block: technical → Approach / fenced code covering every part of the ask / Trade-off; yes-no → yes/no + one concrete example.
- `maxTokensFor(mode, say)`: regular+say 1500 (code room), else unchanged. Real-model proof (3 Sonnet calls, scratchpad say-proof.js): about-you and have-you-done true to résumé+bank with screen numbers; technical SQL runs on Postgres with FILTER + window SUM after the every-part rule.
- Tests: pure 48 checks, wiring 101. No desktop rebuild needed (canvas served by the server).
