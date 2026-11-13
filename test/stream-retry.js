// Stream retry (13 Nov rehearsal: an Anthropic HTTP 503 lost a heard ask's card — only "Overloaded" was retried). Free, no model.
const assert = require('assert');
const { withStreamRetry, isRetryable } = require('../lib/stream-retry');
let n = 0; const ok = (c, m) => { n++; assert(c, m); };
const err = (status, message, code) => Object.assign(new Error(message || 'HTTP ' + status), status ? { status } : {}, code ? { code } : {});
// a fake model call: fails with each error in `fails`, then streams "hello" and returns it
const fake = fails => { let calls = 0; const f = async d => { calls++; const e = fails.shift(); if (e && e.after) { d('partial'); throw e.after; } if (e) throw e; d('hello'); return 'hello'; }; f.calls = () => calls; return f; };

(async () => {
  for (const s of [429, 500, 502, 503, 504, 529]) ok(isRetryable(err(s)), 'HTTP ' + s + ' is retried');
  ok(isRetryable(err(0, 'Overloaded')) && isRetryable(err(0, 'socket hang up')) && isRetryable(err(0, 'x', 'ECONNRESET')), 'overloaded / dropped connection retried');
  ok(!isRetryable(err(400, 'prompt is too long')) && !isRetryable(err(401)), 'a bad request or bad key is not retried');

  let f = fake([err(503)]), got = [];
  ok(await withStreamRetry(f, t => got.push(t), { waitMs: 1 }) === 'hello' && f.calls() === 2 && got.join() === 'hello', 'a 503 then success → the card comes (the 13 Nov loss)');
  f = fake([err(503), err(502)]);
  ok(await withStreamRetry(f, () => {}, { waitMs: 1 }) === 'hello' && f.calls() === 3, 'two failures then success → third try answers');
  f = fake([err(503), err(503), err(503)]);
  await assert.rejects(withStreamRetry(f, () => {}, { waitMs: 1 }), /HTTP 503/); ok(f.calls() === 3, 'gives up after 3 tries');
  f = fake([err(400, 'bad request')]);
  await assert.rejects(withStreamRetry(f, () => {}, { waitMs: 1 }), /bad request/); ok(f.calls() === 1, 'a 400 is not retried');
  f = fake([{ after: err(503) }]); got = [];
  await assert.rejects(withStreamRetry(f, t => got.push(t), { waitMs: 1 })); ok(f.calls() === 1 && got.join() === 'partial', 'never retried once words are on the card (no doubled text)');
  console.log(`stream-retry: ${n} checks\nALL PASS (5xx / 429 / overloaded / dropped connection retried before the first word)`);
})().catch(e => { console.error(e); process.exit(1); });
