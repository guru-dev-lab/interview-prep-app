# xHire — working rules

xHire (xhire.app) is a LIVE interview-prep web app with real users: Node/Express + Postgres, JWT auth, Google
OAuth, plan limits, Anthropic + Deepgram for live answers. Deployed on Railway (`railway.toml`, `node server.js`).
A desktop wrapper lives in `electron/` (it loads `/launcher` from the server, so most web fixes need no new build;
a `v*` tag builds the desktop app via `.github/workflows/build-electron.yml`).

Layout: nearly all server logic is one file, `server.js` (~4,700 lines, ~54 routes). Pages are in `public/`
(`index.html`, `canvas.html`, `launcher.html`, `download.html`). Config is env vars — see `.env.example`.
There is no test suite yet.

This is its own project. Do not mix in ApplyPilot, ScoutPilot, trading or any other project's code or memory.
(Job Scout / ScoutPilot links into xHire only through the launcher; see ../XHIRE_SUITE_INTEGRATION_PLAN.md.)

## The owner
- Plain English, short bullets, direct. He skips long write-ups. Say what broke, what fixed it, what it proves.
- He is building while working; he should not have to repeat a complaint. Read the evidence yourself.

## Rule 1 — never break the live app on the side
- Never push to `main` or deploy without his go. Work on a branch; he approves what goes live.
- Before touching anything: tag the known-good state (`git tag known-good-YYYY-MM-DD-<what>`) so rollback is one step.
- A fix changes only what is broken. Never "tidy" a working route, page or query while you are in there.
- Database: no destructive migration, no DROP/DELETE on real data, without a backup and his explicit yes.
- Secrets never go in code, commits, logs, reports or git remote URLs. `.env` stays gitignored.

## Rule 2 — never guess; evidence first
- Every change needs evidence: a log line, a reproduced failure, a live request/response, a failing test.
- Reproduce the bug cold before fixing it. Prove the cause, then fix. If you cannot prove it, instrument first.
- Something starts but never finishes, or fails silently? Add a deadline + a result log line BEFORE fixing a guessed cause.
- Hunt swallowed errors (`catch {}`, `.catch(() => {})`). A zero or an empty result is a bug until proven otherwise.
- Measure what the USER SEES (the page, the answer, the response), not internal counters.
- Two changes shipped together and something broke? Revert ONE at a time; don't guess which.

## Rule 3 — fix the class, at the door, through every layer
- Fix the general cause, never one user's or one page's instance.
- Trace a fix through every layer the value travels (browser → route → DB/model → response → render). It counts
  only when proven end to end.
- One rule lives in ONE place. If the same logic exists in several copies, consolidate before changing it.
- Never gate an action on something merely being present; gate on it actually being needed.

## Rule 4 — prove it, then report honestly
- Test the real path (hit the actual route / page), not a helper called directly.
- A success message sits inside the success path. Never claim an action you did not verify.
- When something is proven working: commit, then report what changed + how it was proven + how to roll back.
- If tests are skipped or something fails, say so plainly with the output.

## Start of every session
1. `git fetch && git status` — local copy current? Anything uncommitted?
2. Read the latest block in `docs/HANDOFF.md` and this file.
3. End every session by writing the state, what's proven, what's open, to the top of `docs/HANDOFF.md`.
