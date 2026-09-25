# Handoff

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
