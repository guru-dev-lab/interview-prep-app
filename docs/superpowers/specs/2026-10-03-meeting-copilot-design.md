# Meeting co-pilot — design (3 Oct 2026, owner-approved in chat)

## Purpose
Co-pilot is for the owner's WORK meetings (not assessments): someone shares a screen (table, notes, questions)
and asks him something. Co-pilot listens, reads what is shared, understands what is asked and why, and helps him
answer. Must be very cheap by default; a "History" checkbox buys precision.

## Call log — table `call_events` (LIVE sessions only)
One row per thing that happens on a live call. Written only while Go Live is on; nothing is recorded or used outside
a live session.

| column      | meaning |
|-------------|---------|
| id          | uuid |
| session_id  | sessions.id, ON DELETE CASCADE |
| call_id     | live_transcripts.id of this Go Live (one per call) |
| ts          | when |
| kind        | `asker` (what they said / asked), `you` (what he said), `document` (reference text he attached), `seen` (summary of a screen capture), `said` (what co-pilot answered), `digest` (smart-mode compaction) |
| text        | the line / summary / answer |
| meta        | jsonb: {ask: true} for detected questions, {hash} for screens, etc. |

One writer: `recordCallEvent(sessionId, callId, kind, text, meta)`. Called where the stream already pushes
transcript lines (both channels), when a document is attached, after every co-pilot capture (seen) and answer (said).
The in-memory transcript stays the live working set; the table is the record.

## Trigger (both modes)
Co-pilot fires only on: a question the existing door detects (`question_detected`), a capture press, or a typed note.
A capture press follows the panic rule: there IS something to answer (screen or last speech), even if not phrased as one.
Never on a 3-second pause any more. In co-pilot mode the Q&A answer path (bank match, live answer, bridges) is
skipped for detected questions — one question is paid once. The mode is sent to the server over the WS
(`update_settings {copilot, copilotHistory}`) and lives on the ws.

## Screen
Client captures a frame on each trigger, fingerprints it (tiny grayscale thumbnail), and sends the image only if it
changed since the last send. Unchanged → text-only call that reuses the latest `seen` summary. 1280 px JPEG as today.

## Regular mode (History off) — cheap
Context = last 6 voice rows (asker/you), the last ask, the last `seen`, the last `said`, pulled with one query; no
model picks anything. Plus role/company, gear files + instructions, and the current screen if changed. Haiku, streamed.

## Smart mode (History on) — precise
A running `digest` row for the call: what they want, what they shared on screen, what he already said/committed to,
what co-pilot already told him, open threads. Haiku updates it incrementally (current digest + rows since) at most
once per 3 minutes, only when new rows exist, only while the checkbox is on, never on the answer's clock.
Answer context = digest + raw last 20 rows + current screen. Sonnet (thinking off), streamed — precision is what the
checkbox buys; the digest itself stays on Haiku.

## Answer format (both modes)
```
Asked: <what is being asked of you and why they are showing this>
On screen: <the 1–3 facts from the shared screen that matter>
Say:
  <read-aloud line>
  <read-aloud line>
```
A task to do on screen turns Say into numbered steps. Never contradict or repeat what he already said (`you` rows).
Fixed instructions first with prompt caching; output capped short. Answers STREAM to the card (new
`callClaudeVisionStream`), so the Asked line shows before Say is finished.

## UI
History checkbox on the co-pilot pill (Electron overlay), persisted via `saveSetting('copilotHistory')`.

## Proof
- Free: recordCallEvent writer + live-only guard, regular-mode query shape, compaction budget, routing by mode,
  frame fingerprint skip, prompt contains You lines and never bridges/resume.
- One small e2e per mode on a REUSED local session (MUSTHAVE_PREBUILD=0, Haiku only): regular answers from screen +
  last few; smart cites an earlier screen and an earlier You line; second trigger on the same screen sends no image.

## Build order
1. Table + writer + live-only guard (free tests).  2. Mode/history flag over WS + door routing.  3. Co-pilot route:
new prompt, regular context query, image-optional.  4. Smart digest with budget.  5. Client: checkbox, trigger on
question_detected, fingerprint skip.  6. e2e, tag, PR, merge, live check, handoff.

Rollback: tag `known-good-2026-10-03-before-meeting-copilot`.
