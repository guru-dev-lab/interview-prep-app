# Handoff

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
