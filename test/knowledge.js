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
ok(k.cleanBody('x'.repeat(300000)).length === 300000, 'no size limit: nothing he adds is cut (owner 23 Nov)');
ok(k.cleanBody('') === '', 'empty stays empty');

// block
ok(k.buildKnowledgeBlock([], '') === '', 'nothing added → no block');
const two = k.buildKnowledgeBlock([{ title: 'Query — orders', body: 'SELECT * FROM orders' }, { title: 'Fields', body: 'orders: id, amount' }]);
ok(/^--- Query — orders ---\nSELECT \* FROM orders\n\n--- Fields ---\norders: id, amount$/.test(two), 'items in the order added, whole, named not numbered');
// long items: carried by their short version; before it exists, by their start
const VIEW = 'USE [Db]\nGO\nCREATE VIEW [dbo].[vw_big] AS\nSELECT\n' + Array.from({ length: 1500 }, (_, i) => `  , ISNULL(f.metric_${i}, 0) AS col_${i}`).join('\n') + "\n  , CASE WHEN o.churn_flag = 'Y' THEN 'At risk' END AS customer_health_status\nFROM dbo.fact f JOIN dbo.orders o ON o.id = f.order_id";
ok(k.needsCompact(VIEW) && !k.needsCompact('short'), 'long vs short');
ok(k.makeTitle(VIEW, 'downloaded-file-1795047840') === 'View — dbo.vw_big', 'no extension → titled from the SQL object it creates');
const withShort = k.buildKnowledgeBlock([{ title: 'View — dbo.vw_big', body: VIEW, compact: 'SHORT-VERSION-MARKER: vw_big over dbo.fact + dbo.orders' }]);
ok(withShort.includes('SHORT-VERSION-MARKER') && !withShort.includes('metric_700') && withShort.length < 1000, 'long item carried by its short version only');
const notYet = k.buildKnowledgeBlock([{ title: 'View — dbo.vw_big', body: VIEW }]);
ok(notYet.includes('its START') && notYet.length < 8600 && notYet.includes('metric_1,'), 'short version not written yet → its start meanwhile');
const many = Array.from({ length: 30 }, (_, i) => ({ title: 'doc' + i, body: 'q'.repeat(5000) }));
const over = k.buildKnowledgeBlock(many);
ok(over.includes('--- doc29 ---') && !over.includes('--- doc0 ---') && over.length <= k.COMPACTS_PROMPT_CHARS + 30 * 20, 'over the carried budget: newest kept, oldest dropped');
// the exact parts for ONE question
const det = k.pickDetail([{ title: 'View — dbo.vw_big', body: VIEW }], 'how is customer_health_status worked out?');
ok(det.includes("o.churn_flag = 'Y'") && det.length <= k.DETAIL_CHARS + 200, 'exact part that matches the question is picked from the full text', det.slice(0, 200));
ok(k.pickDetail([{ title: 'x', body: VIEW }], 'tell me about yourself') === '', 'nothing matches → nothing extra');
ok(k.pickDetail([{ title: 'q', body: 'SELECT customer_health_status FROM t' }], 'customer_health_status') === '', 'short items are already whole → no extra');
ok(k.termsOf('net_rev_usd please').has('net_rev_usd') && k.termsOf('net_rev_usd').has('rev') && !k.termsOf('please').size, 'names split on _ and stop words dropped');
// what a file is, by its bytes
ok(k.sniffFile(Buffer.from('USE [Db]\r\nGO\r\nCREATE VIEW x AS SELECT 1'), 'downloaded-file-1') === 'text', 'SQL with no extension = text');
ok(k.sniffFile(Buffer.from('%PDF-1.7 ...'), 'x') === 'pdf' && k.sniffFile(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0, 0]), 'x') === 'image', 'pdf / png by bytes');
ok(k.sniffFile(Buffer.from([1, 2, 0, 4, 5]), 'a.bin') === 'binary' && k.sniffFile(Buffer.from('PK\u0003\u0004word/document.xml'), 'cv') === 'docx', 'binary refused, docx by bytes');
ok(k.buildKnowledgeBlock([], 'USER INSTRUCTIONS:\nfocus on SQL').includes('focus on SQL'), 'an older page\'s in-window text still rides along');

// the co-pilot prompt carries it, with the rule, in the stable (cached) part
const session = { company: '', role: '', resume: '', jd: '', kind: 'assessment' };
const docs = k.buildKnowledgeBlock([{ title: 'Query — orders', body: 'SELECT customer_id, SUM(amount) FROM orders GROUP BY customer_id' }]);
const b = mc.buildCopilotBlocks({ mode: 'smart', rows: [], session, docs, ask: 'can you add the order count', typed: true, pressed: false, assessment: true });
const stable = b.stable.join('\n\n');
ok(stable.includes(k.KNOWLEDGE_RULE) && stable.includes('SUM(amount) FROM orders'), 'rule + item in the stable block');
ok(/change THEIR query/.test(k.KNOWLEDGE_RULE) && /easiest way first/.test(k.KNOWLEDGE_RULE), 'builds on their query, simple first');
const bd = mc.buildCopilotBlocks({ mode: 'smart', rows: [], session, docs, docsDetail: 'DETAIL-MARKER', ask: 'x', typed: true, assessment: true });
ok(bd.volatile.join('\n').includes('DETAIL-MARKER') && !bd.stable.join('\n').includes('DETAIL-MARKER'), 'exact parts ride in the per-question part, never the cached one');
const none = mc.buildCopilotBlocks({ mode: 'smart', rows: [], session, docs: '', ask: 'x', typed: true, assessment: true });
ok(!none.stable.join('\n').includes('INFO THEY ADDED'), 'no info → no rule line');

console.log(`knowledge: ${n} checks passed`);
