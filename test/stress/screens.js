// Demo screens for the co-pilot moments of the stress bank → ./screens/<name>.png (committed; rerun only to change them).
//   node test/stress/screens.js
const path = require('path');
const PW = process.env.PLAYWRIGHT || '/Users/rba-home/.local/node/lib/node_modules/@playwright/mcp/node_modules/playwright';
const { chromium } = require(PW);
const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
const code = (title, lines, result) => `<html><body style="margin:0;font-family:Menlo,monospace;background:#1e1e1e;color:#ddd">
<div style="background:#333;padding:8px 14px;font-family:Arial;color:#fff">${title}</div>
<pre style="margin:0;padding:14px;font-size:15px;line-height:1.5">${lines.map((l, i) => String(i + 1).padStart(2) + '  ' + esc(l)).join('\n')}</pre>
<div style="background:#252526;padding:10px 14px;font-family:Arial;font-size:14px;white-space:pre">${esc(result)}</div></body></html>`;
const doc = (title, body) => `<html><body style="margin:0;font-family:Arial;background:#fff;color:#222">
<div style="background:#2b579a;color:#fff;padding:8px 14px">${title}</div><div style="padding:18px 22px;font-size:15px;line-height:1.5">${body}</div></body></html>`;

const SCREENS = {
  dax: code('DAX.do by SQLBI — DAX query editor   (tables: Sales, Product, Customer, Date, Store)', [
    'DEFINE', '    MEASURE Sales[Total Sales] =', '        SUMX ( Sales, Sales[Quantity] * Sales[Net Price] )', '',
    'EVALUATE', 'SUMMARIZECOLUMNS (', "    'Product'[Product Name],", '    "Pct of Total", DIVIDE ( [Sales Amount], [Total Sales] )', ')'],
    'Results:  Product Name | Pct of Total\nContoso 512MB MP3 Player | 1\nContoso 1G MP3 Player | 1\nLitware Home Theater | 1'),
  sql: code('SQL Server — assessment.sql', [
    'WITH region_totals AS (', '    SELECT region, SUM(amount) AS region_amount', '    FROM orders', '    GROUP BY region', ')',
    'SELECT o.region, o.rep_name,', '       SUM(o.amount) AS rep_amount,', '       SUM(o.amount) / SUM(o.amount) AS share_of_region',
    'FROM orders o', 'GROUP BY o.region, o.rep_name;'],
    'Results: region | rep_name | rep_amount | share_of_region\nEast | Kim | 1200 | 1\nEast | Lee | 800 | 1'),
  py: code('notebook.ipynb — Python 3.11', [
    'import pandas as pd', '', 'def clean_amount(s):', '    """Strip $ and commas, return float; blanks -> 0."""',
    '    return pd.to_numeric(s.str.replace(r"[$,]", "", regex=True), errors="coerce").fillna(0)', '',
    'df = pd.read_csv("orders.csv")', 'df["amount"] = df["amount"].astype(float)', 'print(df.groupby("region")["amount"].sum())'],
    "ValueError: could not convert string to float: '$1,200.00'  (line 8)"),
  ytd: code('Power BI Desktop — Measure tools   (model: Sales, Date[Date] marked as date table? NO)', [
    'Sales YTD =', '    CALCULATE (', '        [Total Sales],', "        DATESYTD ( Sales[Order Date] )", '    )', '',
    'Total Sales = SUM ( Sales[Amount] )'],
    'Matrix:  Month | Total Sales | Sales YTD\nJan | 120,000 | 120,000\nFeb | 95,000 | 215,000\nMar | 110,000 | 110,000   <- expected 325,000'),
  case: doc('Case study — Bright Basket groceries (read, then discuss)', `
    <p><b>Context.</b> Bright Basket runs 140 stores. Online orders grew 38% last year, but gross margin fell from 31% to 26%.</p>
    <p><b>Data you have.</b> Orders (2 years, line level), store P&amp;L by month, delivery costs by zip code, promotions calendar, customer table with loyalty tier.</p>
    <p><b>The ask.</b> The COO wants to know why margin fell and what to do about it in the next two quarters. You have one week and one analyst.</p>
    <p><b>Discuss:</b> how you would approach it, what you would look at first, and what you would show the COO.</p>`),
  chart: doc('Weekly Sales Review — page 1 (sent to the Sales Director every Monday)', `
    <svg width="760" height="300" style="font-family:Arial;font-size:12px">
      <text x="10" y="18" font-size="15" font-weight="bold">Sales by Region and Product Category (all weeks, all years)</text>
      ${['North', 'South', 'East', 'West', 'Central', 'Online'].map((r, i) => ['#e6194b', '#3cb44b', '#ffe119', '#4363d8', '#f58231', '#911eb4', '#46f0f0', '#f032e6'].map((c, j) =>
        `<rect x="${30 + i * 120 + j * 13}" y="${280 - (40 + ((i * 7 + j * 13) % 9) * 22)}" width="11" height="${40 + ((i * 7 + j * 13) % 9) * 22}" fill="${c}"/>`).join('') +
        `<text x="${50 + i * 120}" y="296">${r}</text>`).join('')}
    </svg>`),
};

(async () => {
  const b = await chromium.launch({ channel: 'chrome' }); const p = await b.newPage({ viewport: { width: 900, height: 470 } });
  for (const [k, h] of Object.entries(SCREENS)) { await p.setContent(h); await p.screenshot({ path: path.join(__dirname, 'screens', k + '.png') }); }
  await b.close(); console.log('screens:', Object.keys(SCREENS).join(', '));
})().catch(e => { console.error(e.message); process.exit(1); });
