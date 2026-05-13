require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const https = require('https');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'sessions.json');
const QA_BANK = path.join(__dirname, 'qa-bank.txt');
const QUESTIONS_DB = path.join(__dirname, 'questions-db.json');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function readSessions() { if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]'); return JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8')); }
function writeSessions(s) { fs.writeFileSync(DATA_FILE, JSON.stringify(s, null, 2)); }
function getQABank() { return fs.existsSync(QA_BANK) ? fs.readFileSync(QA_BANK, 'utf-8') : ''; }

// Questions DB — grows over time as new questions are generated
function readQDB() { if (!fs.existsSync(QUESTIONS_DB)) fs.writeFileSync(QUESTIONS_DB, '[]'); return JSON.parse(fs.readFileSync(QUESTIONS_DB, 'utf-8')); }
function writeQDB(db) { fs.writeFileSync(QUESTIONS_DB, JSON.stringify(db, null, 2)); }
function addToQDB(questions) {
  const db = readQDB();
  const existing = new Set(db.map(q => q.text.toLowerCase().replace(/[^a-z]/g, '')));
  let added = 0;
  for (const q of questions) {
    const key = q.text.toLowerCase().replace(/[^a-z]/g, '');
    if (!existing.has(key) && q.text.length > 15) {
      existing.add(key);
      db.push({ text: q.text, type: q.type, source: q.source || 'generated', added: new Date().toISOString() });
      added++;
    }
  }
  if (added > 0) writeQDB(db);
  return added;
}

// Must-have questions — these ALWAYS appear and are starred
const MUST_HAVE = [
  'Tell me about yourself.',
  'What is your greatest accomplishment?',
  'What are your strengths?',
  'What are your weaknesses?',
  'Why are you leaving your current position?',
  'Why do you think you are a good fit for this position?',
  'What are your long-term career goals?',
  'Why do you want to work here?',
  'What motivates you to succeed in this role?',
  'How do you handle tight deadlines and pressure situations?',
  'Tell me about a time you had to present complex data to a non-technical audience.',
  'Do you have any questions for us?'
];

function detectType(t) {
  const l = t.toLowerCase();
  if (/tell me about a time|describe a time|give me an example|walk me through a situation/.test(l)) return 'Behavioral';
  if (/\b(sql|power bi|tableau|dax|python|etl|snowflake|dbt|excel|ssis|ssrs|azure|aws|looker|alteryx|cte|window function|join|union|intersect|except)\b/i.test(l)) return 'Technical';
  if (/how do you|what is your process|how would you|what would you do|what approach/.test(l)) return 'Situational';
  return 'Strategic';
}

const MODEL_SONNET = 'claude-sonnet-4-20250514';
const MODEL_HAIKU = 'claude-haiku-4-5-20251001';

function callClaude(system, user, maxTokens = 1500, model = MODEL_SONNET) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ model, max_tokens: maxTokens, system, messages: [{ role: 'user', content: user }] });
    const req = https.request({
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' }
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => { try { const p = JSON.parse(d); p.content?.[0]?.text ? resolve(p.content[0].text) : reject(new Error(p.error?.message || 'API error')); } catch (e) { reject(e); } });
    });
    req.on('error', reject);
    req.setTimeout(90000, () => { req.destroy(); reject(new Error('timeout')); });
    req.write(body); req.end();
  });
}

const ANSWER_PROMPT = `You are a real-time interview assistant. The candidate's name, role, and experience come ONLY from the resume provided below. Never use any hardcoded name or details — always extract from the resume.

You have access to the candidate's Q&A BANK — this is the SOURCE OF TRUTH for their real experience. USE IT.

FORMAT RULES — CRITICAL:
Every sentence on its own line.
Never write paragraphs.
One idea = one line.
Blank line between thought groups.
Lead with the answer — first line IS the point.
Contractions always.
Never say "Great question", "Certainly", or "As mentioned in my resume".

CONTENT RULES — THIS IS CRITICAL:
You are helping the candidate CLAIM this role. Every answer must strategically connect their real experience to what this JD is asking for.
Read the JD carefully. Identify what they value most. Then frame the answer so the candidate's experience sounds like it was built for THIS job.
Use the Q&A Bank as your primary source of real facts. Find the most relevant block(s) and ADAPT the language to mirror the JD's priorities.
If the JD says "stakeholder management" — use that exact phrase when describing the candidate's experience, not a synonym.
If the JD mentions a tool he's used — lead with that tool and how he used it in production.
If the JD mentions an industry or domain — bridge the candidate's past industry experience to show the pattern transfers.
For technical questions: lead with how the tool was used in production at a real company, then connect to what this role needs.
For behavioral SCENARIO questions ONLY (questions starting with "tell me about a time", "describe a situation", "give me an example of when"): STAR flow using a specific company, metric, and outcome. End with how that maps to this role.
For NON-SCENARIO personal questions ("tell me about yourself", "what are your strengths", "why this role", "why are you leaving", "what motivates you", "greatest accomplishment", "weaknesses", "career goals"): DO NOT use STAR. Give a direct narrative answer with rich detail about career, skills, and fit. Follow the specific structures below.
For strategic questions: lead with business impact, frame it as exactly what this company needs.
Never fabricate. Only use real facts from the Q&A Bank and resume — but frame them strategically.
Natural human voice — confident, specific, no buzzwords, no em dashes.

ANSWER STRUCTURE BY TYPE — FOLLOW STRICTLY:

"Tell me about yourself" → EXACTLY 6-8 lines. MAX 8 lines.
  Line 1: Name + years + domain.
  Line 2: Current role + what you own.
  Line 3-4: Biggest accomplishment with a metric.
  Line 5-6: Your approach (4 D's) in one sentence.
  Line 7-8: Why this role excites you, connecting to JD.
  STOP. Do not list every job. Do not list certs. Keep it tight.

Behavioral → STAR flow, 4–6 lines. MAX 6 lines.
  S: situation + company name.
  T: the task or problem.
  A: what you did (specific actions, tools, decisions).
  R: result with metric or outcome. Connect to this role.

Technical (tool-specific) → 2–4 lines. MAX 4 lines.
  Lead with production use at a real company.
  Mention scale.
  End with outcome.

Technical (process/flow, e.g. "Walk me through ETL") → 5-8 lines. MAX 8 lines.
  Walk through each phase with the phase name.
  Ground each phase in real experience.
  Use 4 D's framework when applicable.

Strategic → 3–5 lines. MAX 5 lines. Lead with business impact. Use a brief STAR example if it strengthens the answer.

Situational → 3–5 lines. MAX 5 lines. Describe approach, then ground in a real STAR example from the Q&A bank.

"What are your strengths/weaknesses" → 2-3 lines. MAX 3 lines. Direct and specific.

"Why this company / Why this role" → 3-4 lines. MAX 4 lines. Company-specific, reference JD.

HARD RULE: NEVER exceed the MAX line count. Shorter is better. Every line must earn its place.

Output ONLY the answer lines. No intro, no label, no "Here's my answer".`;

// --- File extraction ---
async function extractText(buf, name) {
  const ext = (name || '').toLowerCase().split('.').pop();
  if (ext === 'pdf') { try { return (await require('pdf-parse')(buf)).text; } catch(e) { return buf.toString('utf-8'); } }
  if (ext === 'docx' || ext === 'doc') { try { return (await require('mammoth').extractRawText({ buffer: buf })).value; } catch(e) { return buf.toString('utf-8'); } }
  return buf.toString('utf-8');
}

// --- Extract text from any uploaded file (PPTX, PDF, DOCX, TXT) ---
async function extractAnyFileText(buffer, name) {
  const ext = (name || '').toLowerCase().split('.').pop();

  if (ext === 'pptx') {
    // Extract all text from PPTX slides
    const AdmZip = require('adm-zip');
    const { XMLParser } = require('fast-xml-parser');
    const zip = new AdmZip(buffer);
    const parser = new XMLParser({ ignoreAttributes: false });
    const allText = [];

    const entries = zip.getEntries().filter(e => e.entryName.match(/ppt\/slides\/slide\d+\.xml$/))
      .sort((a, b) => parseInt(a.entryName.match(/slide(\d+)/)[1]) - parseInt(b.entryName.match(/slide(\d+)/)[1]));

    for (const entry of entries) {
      const xml = entry.getData().toString('utf-8');
      const parsed = parser.parse(xml);
      const texts = [];
      function walk(obj) {
        if (!obj) return;
        if (typeof obj === 'string') return;
        if (Array.isArray(obj)) { obj.forEach(walk); return; }
        if (typeof obj === 'object') {
          if (obj['a:t'] !== undefined) {
            const t = obj['a:t'];
            texts.push(typeof t === 'string' ? t : String(t));
          }
          Object.values(obj).forEach(walk);
        }
      }
      walk(parsed);
      allText.push(texts.join(' '));
    }
    return allText.join('\n');
  }

  // Fall back to existing extractors
  return await extractText(buffer, name);
}

// --- Extract questions from any file's text ---
function extractQuestionsFromText(text) {
  const questions = [];
  const seen = new Set();

  // Match anything ending with ?
  const matches = text.match(/[^\n.!?]*\?/g) || [];
  for (let q of matches) {
    q = q.replace(/^[\s\-\d.*•→►▸]+/, '').trim(); // Clean leading bullets/numbers
    if (q.length < 15) continue;
    // Skip non-question fragments
    if (/^(page|slide|note|source|ref|http)/i.test(q)) continue;
    const key = q.toLowerCase().replace(/[^a-z]/g, '');
    if (!seen.has(key)) { seen.add(key); questions.push(q); }
  }
  return questions;
}

// ============ ROUTES ============

app.post('/api/extract-text', upload.single('file'), async (req, res) => {
  try { if (!req.file) return res.status(400).json({ error: 'No file' }); res.json({ text: (await extractText(req.file.buffer, req.file.originalname)).trim() }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Import questions from ANY file (PPTX, PDF, DOCX, TXT) into a session
app.post('/api/sessions/:id/import-questions', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const sessions = readSessions(); const s = sessions.find(s => s.id === req.params.id);
    if (!s) return res.status(404).json({ error: 'Not found' });

    const text = await extractAnyFileText(req.file.buffer, req.file.originalname);
    const questions = extractQuestionsFromText(text);

    // Dedup against existing — normalize by stripping punctuation and lowercasing
    const existingKeys = new Set(s.questions.map(q => q.text.toLowerCase().replace(/[^a-z]/g, '')));
    const added = [];
    for (const q of questions) {
      const key = q.toLowerCase().replace(/[^a-z]/g, '');
      if (!existingKeys.has(key)) {
        existingKeys.add(key);
        const nq = { id: uuidv4(), text: q, type: detectType(q), answer: '' };
        s.questions.push(nq);
        added.push(nq);
      }
    }
    s.updated = new Date().toISOString(); writeSessions(sessions);
    console.log(`Imported ${added.length} new questions from ${req.file.originalname} (${questions.length} found, ${questions.length - added.length} duplicates)`);
    res.json({ added, total: s.questions.length, session: s });
  } catch (e) { console.error('Import error:', e); res.status(500).json({ error: e.message }); }
});

// Fetch job posting URL and extract text
app.post('/api/fetch-url', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'No URL' });
    const fetchUrl = new URL(url);
    const lib = fetchUrl.protocol === 'https:' ? https : require('http');
    const text = await new Promise((resolve, reject) => {
      lib.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } }, (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          // Follow redirect
          lib.get(response.headers.location, { headers: { 'User-Agent': 'Mozilla/5.0' } }, (r2) => {
            let d = ''; r2.on('data', c => d += c); r2.on('end', () => resolve(d));
          }).on('error', reject);
          return;
        }
        let d = ''; response.on('data', c => d += c); response.on('end', () => resolve(d));
      }).on('error', reject);
    });
    // Strip HTML tags to get plain text
    const plain = text.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    res.json({ text: plain.substring(0, 15000) });
  } catch (e) { res.json({ text: '', error: e.message }); }
});

app.get('/api/sessions', (req, res) => {
  res.json(readSessions().map(s => ({
    id: s.id, company: s.company, role: s.role, profile: s.profile || '',
    questionCount: s.questions.length, answeredCount: s.questions.filter(q => q.answer).length,
    meetingsCount: (s.meetings || []).length,
    currentMeeting: (s.meetings || []).find(m => m.isCurrent) || null,
    created: s.created, updated: s.updated
  })));
});

app.get('/api/sessions/:id', (req, res) => {
  const s = readSessions().find(s => s.id === req.params.id);
  s ? res.json(s) : res.status(404).json({ error: 'Not found' });
});

app.post('/api/sessions', (req, res) => {
  const { resume, jd, company, role } = req.body;
  const sessions = readSessions();
  const session = {
    id: uuidv4(), company: company || '', role: role || '',
    resume, jd, profile: '', meetings: [], questions: [],
    created: new Date().toISOString(), updated: new Date().toISOString()
  };
  sessions.push(session);
  writeSessions(sessions);
  res.json(session);
});

app.delete('/api/sessions/:id', (req, res) => {
  writeSessions(readSessions().filter(s => s.id !== req.params.id));
  res.json({ ok: true });
});

app.post('/api/sessions/:id/questions', (req, res) => {
  const sessions = readSessions(); const s = sessions.find(s => s.id === req.params.id);
  if (!s) return res.status(404).json({ error: 'Not found' });
  const added = (req.body.questions || '').split('\n').map(q => q.trim()).filter(q => q.length > 0)
    .map(q => { const nq = { id: uuidv4(), text: q, type: detectType(q), answer: '' }; s.questions.push(nq); return nq; });
  // Save to questions DB
  addToQDB(added.map(q => ({ text: q.text, type: q.type, source: 'manual' })));
  s.updated = new Date().toISOString(); writeSessions(sessions);
  res.json({ added, session: s });
});

// Add a meeting/interviewer
app.post('/api/sessions/:id/meetings', (req, res) => {
  const sessions = readSessions(); const s = sessions.find(s => s.id === req.params.id);
  if (!s) return res.status(404).json({ error: 'Not found' });
  if (!s.meetings) s.meetings = [];
  s.meetings.forEach(m => m.isCurrent = false);
  const { name, title, stage } = req.body;
  s.meetings.push({ id: uuidv4(), name, title: title || '', stage: stage || '', date: new Date().toISOString(), isCurrent: true });
  s.updated = new Date().toISOString(); writeSessions(sessions);
  res.json({ session: s });
});

// Delete a meeting
app.delete('/api/sessions/:id/meetings/:mid', function(req, res) {
  var sessions = readSessions(); var s = sessions.find(function(s){return s.id === req.params.id});
  if (!s) return res.status(404).json({ error: 'Not found' });
  s.meetings = (s.meetings || []).filter(function(m){return m.id !== req.params.mid});
  s.updated = new Date().toISOString(); writeSessions(sessions);
  res.json({ session: s });
});

// Set current meeting
app.put('/api/sessions/:id/meetings/:mid/current', (req, res) => {
  const sessions = readSessions(); const s = sessions.find(s => s.id === req.params.id);
  if (!s) return res.status(404).json({ error: 'Not found' });
  (s.meetings || []).forEach(m => m.isCurrent = (m.id === req.params.mid));
  s.updated = new Date().toISOString(); writeSessions(sessions);
  res.json({ session: s });
});

// Extract company + role from JD
app.post('/api/sessions/:id/extract-info', async (req, res) => {
  try {
    const sessions = readSessions(); const s = sessions.find(s => s.id === req.params.id);
    if (!s) return res.status(404).json({ error: 'Not found' });
    const txt = await callClaude('Extract company name and job title. Return ONLY {"company":"X","role":"Y"}. Nothing else.', s.jd.substring(0, 4000), 100, MODEL_HAIKU);
    const m = txt.match(/\{[^}]+\}/); const o = m ? JSON.parse(m[0]) : {};
    s.company = o.company || 'Unknown'; s.role = o.role || 'Unknown';
    s.updated = new Date().toISOString(); writeSessions(sessions);
    res.json({ company: s.company, role: s.role });
  } catch (e) { res.json({ company: 'Unknown', role: 'Unknown' }); }
});

// Generate profile
app.post('/api/sessions/:id/profile', async (req, res) => {
  try {
    const sessions = readSessions(); const s = sessions.find(s => s.id === req.params.id);
    if (!s || !s.resume || !s.jd) return res.json({ profile: '' });
    const p = await callClaude('Create a 2-3 sentence candidate profile. Focus on strongest alignment between candidate and role. No headers.', `Resume:\n${s.resume}\n\nJD:\n${s.jd}`, 250, MODEL_HAIKU);
    s.profile = p; s.updated = new Date().toISOString(); writeSessions(sessions);
    res.json({ profile: p });
  } catch (e) { res.json({ profile: '' }); }
});

// BUILD: Extract info + profile + generate all questions
app.post('/api/sessions/:id/build', async (req, res) => {
  try {
    const sessions = readSessions(); const s = sessions.find(s => s.id === req.params.id);
    if (!s) return res.status(404).json({ error: 'Not found' });
    const qaBank = getQABank();

    // Step 1+2: ALWAYS extract company/role from JD AND generate profile IN PARALLEL
    // Haiku for extraction (cheap), Sonnet only for quality-critical tasks
    const [infoResult, profileResult, resumeResult] = await Promise.allSettled([
      callClaude('Extract the company name and exact job title from this job description. Return ONLY a JSON object like {"company":"Acme Corp","role":"Senior Data Analyst"}. Nothing else, no explanation, no markdown.', s.jd.substring(0, 4000), 150, MODEL_HAIKU),
      callClaude('Write a 2 sentence brief about the COMPANY (not the candidate). What does the company do? What industry? What is their mission? Based on the job description. No headers.', s.jd.substring(0, 4000), 150, MODEL_HAIKU),
      callClaude('Extract from this resume: the person\'s full name and ALL their work experience. Include EVERY job listed on the resume — do not skip any. Return ONLY a JSON object like {"name":"John Smith","experience":[{"company":"Acme Corp","role":"Senior Analyst","years":"2020-Present"},{"company":"BigCo","role":"Analyst","years":"2017-2020"},{"company":"SmallCo","role":"Jr Analyst","years":"2015-2017"}]}. Most recent first. Include ALL positions even internships or short roles. No explanation, no markdown.', s.resume.substring(0, 8000), 500, MODEL_HAIKU)
    ]);

    // Company/role from JD
    if (infoResult.status === 'fulfilled') {
      try {
        console.log('Extract info response:', infoResult.value);
        var m = infoResult.value.match(/\{[^}]+\}/);
        var o = m ? JSON.parse(m[0]) : {};
        s.company = o.company || s.company || 'New Session';
        s.role = o.role || s.role || '';
      } catch(e) { console.error('Parse error:', e.message); }
    }
    if (!s.company || s.company === 'New Session') s.company = 'New Session';

    // Profile
    if (profileResult.status === 'fulfilled') s.profile = profileResult.value;
    else s.profile = '';

    // Resume info (name + experience)
    if (resumeResult.status === 'fulfilled') {
      try {
        var rm = resumeResult.value.match(/\{[\s\S]*\}/);
        var ro = rm ? JSON.parse(rm[0]) : {};
        s.candidateName = ro.name || '';
        s.experience = ro.experience || [];
      } catch(e) { console.error('Resume parse error:', e.message); }
    }

    // Step 3: Add must-have questions FIRST (always present, starred)
    const existingTexts = new Set();
    MUST_HAVE.forEach(function(q) {
      const key = q.toLowerCase().replace(/[^a-z]/g, '');
      if (!existingTexts.has(key)) {
        existingTexts.add(key);
        s.questions.push({ id: uuidv4(), text: q, type: detectType(q), answer: '', starred: true });
      }
    });

    // Step 4: Generate questions — AI picks from bank + generates JD-specific
    const bankQuestions = (qaBank.match(/Q:\s*(.+)/g) || []).map(l => l.replace(/^Q:\s*/, '').trim()).filter(q => q.length > 10);
    console.log('Bank has', bankQuestions.length, 'questions. JD length:', s.jd.length);

    try {
      const qTxt = await callClaude(
        'You are an expert interview coach. Your job is to generate questions that are DIRECTLY tied to what is in the JD. No generic filler. Every question must trace back to a specific tool, technology, responsibility, or requirement in the JD.',
        'CANDIDATE PREPARED QUESTIONS (pick relevant ones ONLY):\n' +
        bankQuestions.join('\n') +
        '\n\nJOB DESCRIPTION:\n' + s.jd.substring(0, 6000) +
        '\n\nINSTRUCTIONS:\n' +
        'PRIORITY 1 — JD TOOLS & TECHNOLOGIES (most important):\n' +
        'Read the JD. Find EVERY tool, technology, platform, and system mentioned.\n' +
        'For EACH one, generate 1-2 questions about how the candidate has used it in production.\n' +
        'Examples:\n' +
        '- JD says "Tableau Bridge" → "How have you configured and managed Tableau Bridge for on-prem to cloud connectivity?"\n' +
        '- JD says "dbt" → "Walk me through how you use dbt for data transformation in a production pipeline."\n' +
        '- JD says "Snowflake" → "How do you optimize query performance in Snowflake for large datasets?"\n' +
        'DO NOT SKIP ANY TOOL OR TECHNOLOGY. Every single one needs at least one question.\n\n' +
        'PRIORITY 2 — JD RESPONSIBILITIES:\n' +
        'For each key responsibility listed in the JD, generate 1 behavioral or situational question.\n' +
        'These must reference the SPECIFIC responsibility, not generic leadership/teamwork fluff.\n' +
        '- JD says "manage stakeholder reporting" → "Tell me about a time you had to manage conflicting stakeholder priorities around a BI deliverable."\n' +
        '- JD says "mentor junior analysts" → "How do you approach mentoring junior team members on data best practices?"\n\n' +
        'PRIORITY 3 — RELEVANT BANK QUESTIONS:\n' +
        'Pick 10-15 questions from the candidate prepared list that DIRECTLY relate to something in the JD.\n' +
        'Do NOT pick generic questions that have no connection to this specific role.\n\n' +
        'DO NOT GENERATE (these are already covered separately):\n' +
        '- "Tell me about yourself", "strengths", "weaknesses", "why this role", "why are you leaving", "career goals", "greatest accomplishment", "what motivates you", "questions for us" — these are MUST-KNOW questions handled separately\n' +
        '- Generic behavioral questions not tied to the JD (e.g. "how do you handle conflict" unless the JD mentions conflict resolution)\n' +
        '- Generic strategic questions about industries not in the JD\n' +
        '- Filler questions just to pad the count\n\n' +
        'OUTPUT 35-50 high-quality questions. One per line. No numbering. No categories. Just the question ending with ?\n' +
        'Quality over quantity. Every question must earn its place by connecting to something specific in the JD.',
        3500
      );
      console.log('AI generated response length:', qTxt.length);
      const qs = qTxt.split('\n').map(q => q.trim()).filter(q => q.length > 15 && q.includes('?'));
      console.log('Parsed', qs.length, 'questions from AI');
      qs.forEach(q => {
        const key = q.toLowerCase().replace(/[^a-z]/g, '');
        if (!existingTexts.has(key)) {
          existingTexts.add(key);
          s.questions.push({ id: uuidv4(), text: q, type: detectType(q), answer: '' });
        }
      });
    } catch(e) {
      console.error('AI question generation failed:', e.message);
      // FALLBACK: add all bank questions directly
      console.log('Using fallback: adding all bank questions');
      bankQuestions.forEach(q => {
        const key = q.toLowerCase().replace(/[^a-z]/g, '');
        if (!existingTexts.has(key)) {
          existingTexts.add(key);
          s.questions.push({ id: uuidv4(), text: q, type: detectType(q), answer: '' });
        }
      });
    }

    // Save questions to the persistent questions DB
    addToQDB(s.questions.map(q => ({ text: q.text, type: q.type, source: 'build' })));
    console.log(`Build complete: ${s.questions.length} questions. QDB total: ${readQDB().length}`);

    s.updated = new Date().toISOString();
    writeSessions(sessions);
    res.json({ session: s });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Questions DB API
app.get('/api/questions-db', (req, res) => {
  const db = readQDB();
  res.json({ total: db.length, questions: db });
});
app.post('/api/questions-db', (req, res) => {
  const { text, type } = req.body;
  if (!text) return res.status(400).json({ error: 'No question text' });
  const added = addToQDB([{ text, type: type || detectType(text), source: 'manual' }]);
  res.json({ added, total: readQDB().length });
});

// Generate answer for single question
app.post('/api/sessions/:id/generate/:qid', async (req, res) => {
  try {
    const sessions = readSessions(); const s = sessions.find(s => s.id === req.params.id);
    if (!s) return res.status(404).json({ error: 'Not found' });
    const q = s.questions.find(q => q.id === req.params.qid);
    if (!q) return res.status(404).json({ error: 'Q not found' });
    const qaBank = getQABank();
    const userInstruction = req.body && req.body.instruction ? req.body.instruction.trim() : '';
    let userMsg = `Q&A BANK:\n${qaBank}\n\nResume:\n${s.resume}\n\nJD:\n${s.jd}\n\nQuestion:\n${q.text}\n\n`;
    if (userInstruction) {
      userMsg += `USER INSTRUCTION (follow this closely): ${userInstruction}\n\nGenerate an answer following the user's instruction, tailored to the resume and JD.`;
    } else {
      userMsg += `Give me a strong answer tailored to this JD.`;
    }
    q.answer = await callClaude(ANSWER_PROMPT, userMsg);
    s.updated = new Date().toISOString(); writeSessions(sessions);
    res.json({ answer: q.answer });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Generate all unanswered — batched 5 at a time to reduce cost
const BATCH_PROMPT = `You are a real-time interview assistant. The candidate's name, role, and experience come ONLY from the resume provided below.

You will receive MULTIPLE interview questions. You MUST generate a separate, complete, high-quality answer for EACH question.

CRITICAL RULES FOR BATCHING:
- Treat EVERY question independently. Do NOT let one answer influence another.
- Give each answer the SAME depth and quality as if it were the only question.
- Do NOT get lazy or shorter on later questions. Question 5 gets the same effort as question 1.
- Follow ALL the type-specific formatting rules for EACH question individually.

OUTPUT FORMAT — FOLLOW EXACTLY:
===Q1===
[full answer for question 1]
===Q2===
[full answer for question 2]
===Q3===
[full answer for question 3]
...and so on for each question.

Each answer between the ===Q markers must be complete and standalone.

` + ANSWER_PROMPT;

// Generate a batch of questions (called by frontend in a loop for live progress)
app.post('/api/sessions/:id/generate-batch', async (req, res) => {
  try {
    const sessions = readSessions(); const s = sessions.find(s => s.id === req.params.id);
    if (!s) return res.status(404).json({ error: 'Not found' });
    const qaBank = getQABank();
    const { questionIds } = req.body;
    if (!questionIds || !questionIds.length) return res.status(400).json({ error: 'No question IDs' });

    const batch = questionIds.map(id => s.questions.find(q => q.id === id)).filter(Boolean);
    if (!batch.length) return res.status(404).json({ error: 'Questions not found' });

    const results = [];

    if (batch.length === 1) {
      try {
        batch[0].answer = await callClaude(ANSWER_PROMPT,
          `Q&A BANK:\n${qaBank}\n\nResume:\n${s.resume}\n\nJD:\n${s.jd}\n\nQuestion:\n${batch[0].text}\n\nGive me a strong answer tailored to this JD.`
        );
        results.push({ id: batch[0].id, answer: batch[0].answer });
      } catch(e) { results.push({ id: batch[0].id, error: e.message }); }
    } else {
      const questionsBlock = batch.map((q, idx) => `Q${idx + 1}: ${q.text}`).join('\n');
      try {
        const batchResponse = await callClaude(BATCH_PROMPT,
          `Q&A BANK:\n${qaBank}\n\nResume:\n${s.resume}\n\nJD:\n${s.jd}\n\n${batch.length} QUESTIONS TO ANSWER:\n${questionsBlock}\n\nGenerate a strong, complete answer for EACH question. Use the ===Q1=== ===Q2=== format. Every answer must be tailored to this JD.`,
          batch.length * 1500
        );

        const parts = batchResponse.split(/===Q\d+===/);
        // Only shift if first element is empty (model started with ===Q1===)
        if (!parts[0] || parts[0].trim().length < 20) parts.shift();

        batch.forEach((q, idx) => {
          const answer = parts[idx] ? parts[idx].trim() : '';
          if (answer && answer.length > 20) {
            q.answer = answer;
            results.push({ id: q.id, answer });
          } else {
            results.push({ id: q.id, error: 'Empty answer in batch' });
          }
        });
      } catch(e) {
        // Fallback to individual
        for (const q of batch) {
          try {
            q.answer = await callClaude(ANSWER_PROMPT,
              `Q&A BANK:\n${qaBank}\n\nResume:\n${s.resume}\n\nJD:\n${s.jd}\n\nQuestion:\n${q.text}\n\nGive me a strong answer tailored to this JD.`
            );
            results.push({ id: q.id, answer: q.answer });
          } catch(e2) { results.push({ id: q.id, error: e2.message }); }
        }
      }
    }

    s.updated = new Date().toISOString(); writeSessions(sessions);
    res.json({ results });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`Running on ${PORT}`));
