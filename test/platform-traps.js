// Unit test: applyPlatformTraps removes known false-feature advice only when that platform is in context.
const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'server.js'), 'utf8');
const f = new Function(src.slice(src.indexOf('const PLATFORM_TRAPS'), src.indexOf('// Grow: new sentences go above')) + ';return applyPlatformTraps;')();
const a = '• Check clustering keys.\n• Adding indexes on the join columns would help.\n• Size the warehouse.\n↳ At R&L Carriers — added indexes to a SQL Server claims report.';
let fail = 0;
const sf = f(a, 'our shipment queries in Snowflake are slow');
if (/Adding indexes/.test(sf)) { fail++; console.log('FAIL: index advice kept for Snowflake'); }
if (!/↳ At R&L Carriers — added indexes/.test(sf)) { fail++; console.log('FAIL: true proof line removed'); }
if (f(a, 'how do you tune SQL Server') !== a) { fail++; console.log('FAIL: changed a non-Snowflake answer'); }
for (const [line, keep] of [['• I would look at indexing the join columns.', false], ['• Snowflake does not use indexes, so I lean on clustering keys.', true], ['• Clustering keys instead of indexes help pruning.', true]]) {
  const kept = f(line, 'snowflake') === line; if (kept !== keep) { fail++; console.log('FAIL', keep ? 'removed a correct statement:' : 'kept wrong advice:', line); }
}
console.log(fail ? `${fail} FAILED` : 'ALL PASS (platform traps)'); process.exit(fail ? 1 : 0);
