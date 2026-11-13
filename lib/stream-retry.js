// Retry for a streamed model call (13 Nov rehearsal: an Anthropic HTTP 503 lost a heard ask's card for good — the retry
// only caught the "Overloaded" message; a 503 / 502 / 500 / 429 or a dropped connection went straight to an error).
// Retried only while NOTHING has been streamed yet: once words are on the card, a retry would write them twice.
const RETRY_STATUS = new Set([429, 500, 502, 503, 504, 529]);
function isRetryable(e) {
  if (!e) return false;
  if (/overloaded/i.test(e.message || '')) return true;
  if (RETRY_STATUS.has(e.status)) return true;
  return /ECONNRESET|ETIMEDOUT|EPIPE|EAI_AGAIN|socket hang up/i.test((e.code || '') + ' ' + (e.message || ''));
}
// once(onDelta) → Promise<result>; up to `tries` attempts, waiting waitMs × attempt between them
async function withStreamRetry(once, onDelta, { tries = 3, waitMs = 1500, log = () => {} } = {}) {
  for (let attempt = 1; ; attempt++) {
    let emitted = false;
    try {
      return await once(t => { emitted = true; onDelta(t); });
    } catch (e) {
      if (emitted || attempt >= tries || !isRetryable(e)) throw e;
      log(`retry ${attempt}/${tries - 1} after ${e.status || ''} ${e.message}`.replace(/\s+/g, ' ').trim());
      await new Promise(r => setTimeout(r, attempt * waitMs));
    }
  }
}
module.exports = { isRetryable, withStreamRetry, RETRY_STATUS };
