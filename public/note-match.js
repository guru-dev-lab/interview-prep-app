// Answer Note — question matching. ONE copy for the browser (note.html jumps to the closest variation when the live
// call hears a question) and the server/tests (lib/answer-note.js). No dependencies: Dice bigram similarity (the same
// measure string-similarity gives the live FastMatch) + keyword overlap, so a paraphrase still lands on the right tab.
(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) module.exports = factory();
  else root.NoteMatch = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  var STOP = /^(a|an|the|and|or|of|to|in|on|at|for|with|is|are|was|were|be|do|does|did|you|your|me|my|i|we|our|us|it|this|that|what|how|when|why|which|who|about|tell|can|could|would|give|have|has|had|any|some|so|if|as|by|from|up|out|into|than|then|there|here|very|just|really|one|more)$/;
  function words(s) { return String(s || '').toLowerCase().replace(/iz(e|ing|ed|ation)/g, 'is$1').replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(function (w) { return w.length > 1 && !STOP.test(w); }).map(function (w) { return w.replace(/(ing|ed|es|s)$/, ''); }); }
  function bigrams(s) { var t = String(s || '').toLowerCase().replace(/\s+/g, ' ').trim(); var m = {}; for (var i = 0; i < t.length - 1; i++) { var b = t.substr(i, 2); m[b] = (m[b] || 0) + 1; } return m; }
  function dice(a, b) { // Dice coefficient on character bigrams, 0..1
    var A = bigrams(a), B = bigrams(b), inter = 0, na = 0, nb = 0, k;
    for (k in A) { na += A[k]; if (B[k]) inter += Math.min(A[k], B[k]); }
    for (k in B) nb += B[k];
    return (na + nb) ? (2 * inter) / (na + nb) : 0;
  }
  function keywordScore(a, b) { // containment of stemmed keywords: a long spoken question still holds the short written one
    var A = words(a), B = words(b); if (!A.length || !B.length) return 0;
    var setB = {}; B.forEach(function (w) { setB[w] = 1; });
    var seen = {}, inter = 0; A.forEach(function (w) { if (setB[w] && !seen[w]) { seen[w] = 1; inter++; } });
    var shortest = Math.min(Object.keys(setB).length, A.length);
    return (inter / shortest) * (shortest >= 2 ? 1 : 0.85); // one shared word alone counts a little less
  }
  function score(heard, candidate) { return dice(heard, candidate) * 0.5 + keywordScore(heard, candidate) * 0.5; }
  // groups: [{ id, name, items: [{ id, question }] }] → the best variation (or null below the threshold)
  // The note's questions best first by wording: the instant guess shown the moment a question is heard, and the
  // candidates whose answers the smart check (POST /api/note/heard) reads to pick the line to highlight.
  function rank(groups, heard, n) {
    var out = [];
    (groups || []).forEach(function (g) {
      var best = null;
      (g.items || []).forEach(function (it) { var s = score(heard, it.question); if (!best || s > best.score) best = { groupId: g.id, itemId: it.id, score: s, question: it.question }; });
      var gs = score(heard, g.name) * 0.9;
      if (g.items && g.items.length && (!best || gs > best.score)) best = { groupId: g.id, itemId: g.items[0].id, score: gs, question: g.items[0].question };
      if (best) out.push(best);
    });
    out.sort(function (a, b) { return b.score - a.score; });
    return out.slice(0, n || 5);
  }
  // "Has he said this line yet?" ONE rule for the call overlay's live coach and the note's ticks (moved here from
  // canvas.html, 24 Oct): a line's key words are its words of 4+ letters minus common ones (first 6), and the line is
  // said once half of them have come from his mic.
  var SAID_STOP = {the:1,and:1,for:1,that:1,this:1,with:1,your:1,you:1,they:1,them:1,have:1,has:1,are:1,was:1,were:1,will:1,would:1,from:1,into:1,about:1,what:1,when:1,which:1,their:1,there:1,then:1,been:1,being:1,also:1,more:1,most:1,some:1,such:1,just:1,like:1,here:1,does:1};
  function pointKeys(s) { var o = {}; (String(s).toLowerCase().match(/\b[a-z]{4,}\b/g) || []).forEach(function (w) { if (!SAID_STOP[w]) o[w] = 1; }); return Object.keys(o).slice(0, 6); }
  function saidWords(text) { var o = {}; (String(text || '').toLowerCase().match(/\b[a-z]{4,}\b/g) || []).forEach(function (w) { o[w] = 1; }); return o; }
  function isSaid(keys, said) { if (!keys || !keys.length) return false; var hit = 0; keys.forEach(function (w) { if (said[w]) hit++; }); return hit / keys.length >= 0.5; }
  function closest(groups, heard, threshold) {
    var th = typeof threshold === 'number' ? threshold : 0.4; var best = null;
    (groups || []).forEach(function (g) {
      (g.items || []).forEach(function (it) {
        var s = score(heard, it.question);
        if (!best || s > best.score) best = { groupId: g.id, itemId: it.id, score: s, question: it.question };
      });
      var gs = score(heard, g.name) * 0.9; // the group's name counts too ("prioritising" → the Prioritising group)
      if (g.items && g.items.length && (!best || gs > best.score)) best = { groupId: g.id, itemId: g.items[0].id, score: gs, question: g.items[0].question };
    });
    return best && best.score >= th ? best : null;
  }
  // Editor HTML → plain lines (search, copy, the writer's CURRENT ANSWER block). Same rule in the page and on the server.
  function htmlToText(html) {
    return String(html || '')
      .replace(/<\s*(br|\/p|\/div|\/li|\/h[1-6]|\/pre)\s*>/gi, '\n')
      .replace(/<[^>]+>/g, '')
      .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      .split('\n').map(function (l) { return l.trim(); }).filter(Boolean).join('\n');
  }
  // Search: groups and variations whose name, question, key points or answer text contain EVERY word typed.
  // A hit on the group name keeps all its variations.
  function searchNote(groups, query) {
    var q = String(query || '').toLowerCase().trim();
    if (!q) return groups;
    var terms = q.split(/\s+/).filter(Boolean);
    var hit = function (s) { var t = String(s || '').toLowerCase(); return terms.every(function (w) { return t.indexOf(w) !== -1; }); };
    return (groups || []).map(function (g) {
      var groupHit = hit(g.name);
      var items = (g.items || []).filter(function (it) { return groupHit || hit(it.question) || hit(it.key_points) || hit(htmlToText(it.answer_html)); });
      if (!items.length) return null;
      var copy = {}; for (var k in g) copy[k] = g[k]; copy.items = items; return copy;
    }).filter(Boolean);
  }
  // Pinned groups first, then the saved order.
  function sortGroups(groups) {
    return (groups || []).slice().sort(function (a, b) { return ((b.pinned ? 1 : 0) - (a.pinned ? 1 : 0)) || ((a.sort_order || 0) - (b.sort_order || 0)) || String(a.created_at || '').localeCompare(String(b.created_at || '')); });
  }
  var SAME_QUESTION = 0.72; // a question from a call this close to one in the note IS that question (not added twice)
  return { SAME_QUESTION: SAME_QUESTION, rank: rank, pointKeys: pointKeys, saidWords: saidWords, isSaid: isSaid, dice: dice, keywordScore: keywordScore, score: score, closest: closest, words: words, htmlToText: htmlToText, searchNote: searchNote, sortGroups: sortGroups };
});
