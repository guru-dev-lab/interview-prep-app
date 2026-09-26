// Unit test: experienceFacts() computes years from resume date ranges (evaluated straight from server.js).
const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'server.js'), 'utf8');
const i = src.indexOf('const _MONTHS'), j = src.indexOf('// ONE answer generator for prepared (bank) answers');
const experienceFacts = new Function(src.slice(i, j) + '\nreturn experienceFacts;')();
const today = new Date('2026-09-26T12:00:00Z');
let fail = 0; const has = (name, out, re) => { if (!re.test(out)) { fail++; console.log('FAIL', name, '\n' + out); } };
const rl = experienceFacts(`Ridwan Akanbi — Data Analyst, R&L Carriers (Mar 2022–present). Freight reporting.
Junior Data Analyst — Midwest Health Clinics (2020–2022): weekly reports.`, today);
has('R&L = 4.5 years', rl, /R&L Carriers.*about 4\.5 years/);
has('Midwest = 2 years', rl, /Midwest Health Clinics.*about 2 years/);
has('total = 6.5 years', rl, /Total.*about 6\.5 years/);
const nw = experienceFacts(`Data Analyst — Northwind Retail, Chicago, IL (Mar 2021 – Present)\nJunior Data Analyst — Lakeview Health Partners (Jun 2019 – Feb 2021)`, today);
has('Northwind 5.5', nw, /Northwind Retail.*about 5\.5 years/);
has('Lakeview 1.5', nw, /Lakeview.*about 1\.5 years/);
has('total 7.5', nw, /Total.*about 7\.5 years/);
if (experienceFacts('No dates here at all.', today) !== '') { fail++; console.log('FAIL no dates should give empty'); }
console.log(fail ? `${fail} FAILED` : 'ALL PASS (experience facts)'); process.exit(fail ? 1 : 0);
