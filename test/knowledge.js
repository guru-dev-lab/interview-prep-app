// Add info (23 Nov) — lib/knowledge.js + the co-pilot prompt carrying it. Pure, no DB, no model: node test/knowledge.js
const assert = require('assert');
const k = require('../lib/knowledge');
const mc = require('../lib/meeting-copilot');
let n = 0; const ok = (c, m) => { assert(c, m); n++; };

// titles
ok(k.makeTitle('SELECT a, b FROM sales.orders o WHERE 1=1') === 'Query — sales.orders', 'SQL title names its table');
ok(k.makeTitle('with t as (select 1) select * from t') === 'Query — t', 'CTE query title');
ok(k.makeTitle('\n\nOrders table: order_id, amount\nmore') === 'Orders table: order_id, amount', 'first real line');
ok(k.makeTitle('x'.repeat(100)).length <= 60, 'long first line is shortened');
ok(k.makeTitle('anything', 'Schema.pdf') === 'Schema.pdf', 'file name wins');

// body
ok(k.cleanBody('  a\r\nb  ') === 'a\nb', 'trimmed, CRLF → LF');
ok(k.cleanBody('x'.repeat(k.ITEM_MAX_CHARS + 50)).length === k.ITEM_MAX_CHARS, 'one item is capped');
ok(k.cleanBody('') === '', 'empty stays empty');

// block
ok(k.buildKnowledgeBlock([], '') === '', 'nothing added → no block');
const two = k.buildKnowledgeBlock([{ title: 'Query — orders', body: 'SELECT * FROM orders' }, { title: 'Fields', body: 'orders: id, amount' }]);
ok(/^--- Query — orders ---\nSELECT \* FROM orders\n\n--- Fields ---\norders: id, amount$/.test(two), 'items in the order added, whole, named not numbered');
const big = 'y'.repeat(k.KNOWLEDGE_PROMPT_CHARS);
const over = k.buildKnowledgeBlock([{ title: 'old', body: 'z'.repeat(5000) }, { title: 'new', body: big }]);
ok(over.startsWith('--- new ---') && !over.includes('--- old ---'), 'over budget: the newest is kept, the oldest dropped');
ok(k.buildKnowledgeBlock([], 'USER INSTRUCTIONS:\nfocus on SQL').includes('focus on SQL'), 'an older page\'s in-window text still rides along');

// the co-pilot prompt carries it, with the rule, in the stable (cached) part
const session = { company: '', role: '', resume: '', jd: '', kind: 'assessment' };
const docs = k.buildKnowledgeBlock([{ title: 'Query — orders', body: 'SELECT customer_id, SUM(amount) FROM orders GROUP BY customer_id' }]);
const b = mc.buildCopilotBlocks({ mode: 'smart', rows: [], session, docs, ask: 'can you add the order count', typed: true, pressed: false, assessment: true });
const stable = b.stable.join('\n\n');
ok(stable.includes(k.KNOWLEDGE_RULE) && stable.includes('SUM(amount) FROM orders'), 'rule + item in the stable block');
ok(/change THEIR query/.test(k.KNOWLEDGE_RULE) && /easiest way first/.test(k.KNOWLEDGE_RULE), 'builds on their query, simple first');
const none = mc.buildCopilotBlocks({ mode: 'smart', rows: [], session, docs: '', ask: 'x', typed: true, assessment: true });
ok(!none.stable.join('\n').includes('INFO THEY ADDED'), 'no info → no rule line');

console.log(`knowledge: ${n} checks passed`);
