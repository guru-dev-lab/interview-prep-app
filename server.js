require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const https = require('https');
const http = require('http');
const multer = require('multer');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const stringSimilarity = require('string-similarity');
// Import only the submodules we need — avoid loading SentimentAnalyzer which has ESM-only deps
const TfIdf = require('natural/lib/natural/tfidf/tfidf');
const PorterStemmer = require('natural/lib/natural/stemmers/porter_stemmer');
const stemmer = PorterStemmer;

const app = express();
const PORT = process.env.PORT || 3000;
const QA_BANK = path.join(__dirname, 'qa-bank.txt');
const JWT_SECRET = process.env.JWT_SECRET || 'interview-prep-secret-change-me';
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

app.use(express.json({ limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ============ DATABASE ============
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' && process.env.DATABASE_PUBLIC_URL ? { rejectUnauthorized: false } : false
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255),
        google_id VARCHAR(255),
        avatar_url TEXT,
        is_admin BOOLEAN DEFAULT FALSE,
        plan VARCHAR(50) DEFAULT 'free',
        suspended BOOLEAN DEFAULT FALSE,
        plan_started_at TIMESTAMPTZ DEFAULT NOW(),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      -- Add columns if they don't exist (for existing tables)
      DO $$ BEGIN
        ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS plan VARCHAR(50) DEFAULT 'free';
        ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended BOOLEAN DEFAULT FALSE;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_started_at TIMESTAMPTZ DEFAULT NOW();
      EXCEPTION WHEN OTHERS THEN NULL;
      END $$;
      CREATE TABLE IF NOT EXISTS sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        company VARCHAR(255) DEFAULT '',
        role VARCHAR(255) DEFAULT '',
        profile TEXT DEFAULT '',
        resume TEXT DEFAULT '',
        jd TEXT DEFAULT '',
        candidate_name VARCHAR(255) DEFAULT '',
        experience JSONB DEFAULT '[]',
        pipeline_stages JSONB DEFAULT '[]',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS questions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        text TEXT NOT NULL,
        type VARCHAR(50) DEFAULT 'Strategic',
        answer TEXT DEFAULT '',
        starred BOOLEAN DEFAULT FALSE,
        sort_order INT DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS meetings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        name VARCHAR(255) DEFAULT '',
        title VARCHAR(255) DEFAULT '',
        stage VARCHAR(255) DEFAULT '',
        is_current BOOLEAN DEFAULT FALSE,
        date TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS questions_db (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        text TEXT NOT NULL,
        type VARCHAR(50) DEFAULT 'Strategic',
        source VARCHAR(50) DEFAULT 'generated',
        added_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS live_transcripts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        transcript JSONB DEFAULT '[]',
        questions_detected JSONB DEFAULT '[]',
        started_at TIMESTAMPTZ DEFAULT NOW(),
        ended_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS session_creations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_id UUID,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_questions_session ON questions(session_id);
      CREATE INDEX IF NOT EXISTS idx_meetings_session ON meetings(session_id);
      CREATE INDEX IF NOT EXISTS idx_live_transcripts_session ON live_transcripts(session_id);
      CREATE INDEX IF NOT EXISTS idx_session_creations_user ON session_creations(user_id);
    `);
    // Migrations for existing tables
    await client.query(`
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS pipeline_stages JSONB DEFAULT '[]';
      ALTER TABLE live_transcripts ADD COLUMN IF NOT EXISTS report JSONB;
      ALTER TABLE live_transcripts ADD COLUMN IF NOT EXISTS interviewer_name VARCHAR(255) DEFAULT '';
      ALTER TABLE live_transcripts ADD COLUMN IF NOT EXISTS interviewer_title VARCHAR(255) DEFAULT '';
      ALTER TABLE live_transcripts ADD COLUMN IF NOT EXISTS stage VARCHAR(255) DEFAULT '';
      ALTER TABLE questions ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'build';
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS answer_style VARCHAR(50) DEFAULT 'conversational';
    `).catch(() => {});
    console.log('Database tables ready');
  } finally { client.release(); }
}

// ============ AUTH MIDDLEWARE ============
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);

function isAdminEmail(email) {
  return ADMIN_EMAILS.includes(email.toLowerCase());
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userName = decoded.name;
    req.isAdmin = decoded.isAdmin || false;
    req.plan = decoded.plan || 'free';
    req.suspended = decoded.suspended || false;
    if (req.suspended && !req.isAdmin) return res.status(403).json({ error: 'Account suspended. Contact admin.' });
    next();
  } catch (e) { return res.status(401).json({ error: 'Invalid token' }); }
}

function generateToken(user) {
  return jwt.sign({ userId: user.id, name: user.name, email: user.email, isAdmin: user.is_admin || false, plan: user.plan || 'free', suspended: user.suspended || false }, JWT_SECRET, { expiresIn: '24h' });
}

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) return res.status(400).json({ error: 'Email, password, and name required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const admin = isAdminEmail(email);
    const plan = admin ? 'admin' : 'free';
    const result = await pool.query(
      'INSERT INTO users (email, name, password_hash, is_admin, plan) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, name, avatar_url, is_admin, plan, created_at',
      [email.toLowerCase(), name, hash, admin, plan]
    );
    const user = result.rows[0];
    res.json({ token: generateToken(user), user: { id: user.id, email: user.email, name: user.name, avatar_url: user.avatar_url, isAdmin: user.is_admin, plan: user.plan } });
  } catch (e) { console.error('Register error:', e.message, e.stack); res.status(500).json({ error: 'Registration failed: ' + e.message }); }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    if (!user.password_hash) return res.status(401).json({ error: 'This account uses Google sign-in' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    res.json({ token: generateToken(user), user: { id: user.id, email: user.email, name: user.name, avatar_url: user.avatar_url, isAdmin: user.is_admin, plan: user.plan } });
  } catch (e) { console.error('Login error:', e.message); res.status(500).json({ error: 'Login failed: ' + e.message }); }
});

// Google OAuth
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    // Decode Google JWT (ID token)
    const parts = credential.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    const { sub: googleId, email, name, picture } = payload;

    if (!email) return res.status(400).json({ error: 'No email in Google token' });

    // Check if user exists
    let result = await pool.query('SELECT * FROM users WHERE email = $1 OR google_id = $2', [email.toLowerCase(), googleId]);
    let user;

    if (result.rows.length) {
      user = result.rows[0];
      // Update google_id and avatar if not set
      await pool.query('UPDATE users SET google_id = COALESCE(google_id, $1), avatar_url = COALESCE(avatar_url, $2), updated_at = NOW() WHERE id = $3',
        [googleId, picture, user.id]);
    } else {
      // Create new user
      result = await pool.query(
        'INSERT INTO users (email, name, google_id, avatar_url) VALUES ($1, $2, $3, $4) RETURNING *',
        [email.toLowerCase(), name, googleId, picture]
      );
      user = result.rows[0];
    }

    // Re-fetch user to get latest is_admin and plan (may have been updated since last login)
    const freshUser = (await pool.query('SELECT * FROM users WHERE id = $1', [user.id])).rows[0];
    res.json({ token: generateToken(freshUser), user: { id: freshUser.id, email: freshUser.email, name: freshUser.name, avatar_url: freshUser.avatar_url || picture, isAdmin: freshUser.is_admin, plan: freshUser.plan } });
  } catch (e) { console.error('Google auth error:', e); res.status(500).json({ error: 'Google auth failed' }); }
});

// Get current user (also refreshes token with latest DB state)
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    const user = result.rows[0];
    // Always return fresh token + user data so frontend stays in sync
    res.json({
      token: generateToken(user),
      user: { id: user.id, email: user.email, name: user.name, avatar_url: user.avatar_url, isAdmin: user.is_admin, plan: user.plan }
    });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ============ HELPERS ============
function getQABank() { return fs.existsSync(QA_BANK) ? fs.readFileSync(QA_BANK, 'utf-8') : ''; }

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

// Vision API — sends image + text to Claude for screen analysis
function callClaudeVision(system, imageBase64, textPrompt, maxTokens = 1500, model = MODEL_HAIKU, imgMediaType = 'image/jpeg') {
  return new Promise((resolve, reject) => {
    const bodyObj = {
      model, max_tokens: maxTokens, system,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: imgMediaType, data: imageBase64 } },
          { type: 'text', text: textPrompt }
        ]
      }]
    };
    const body = JSON.stringify(bodyObj);
    const bodyBytes = Buffer.byteLength(body, 'utf8');
    console.log(`[Vision] Sending ${(bodyBytes / 1024 / 1024).toFixed(1)}MB to ${model}`);
    const req = https.request({
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': bodyBytes,
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      }
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const p = JSON.parse(d);
          if (p.content?.[0]?.text) { resolve(p.content[0].text); }
          else {
            console.error('[Vision] API response error:', JSON.stringify(p).substring(0, 500));
            reject(new Error(p.error?.message || 'Vision API error: ' + (p.type || 'unknown')));
          }
        } catch (e) { reject(e); }
      });
    });
    req.on('error', (e) => { console.error('[Vision] Request error:', e.message); reject(e); });
    req.setTimeout(120000, () => { req.destroy(); reject(new Error('Vision API timeout (120s)')); });
    req.write(body); req.end();
  });
}

const ANSWER_PROMPT = `You generate interview answers. The candidate reads these OUT LOUD in a live interview.

CRITICAL OUTPUT FORMAT — FOLLOW EXACTLY:
Each line = ONE short sentence. Max 15 words per line.
Put each sentence on its own line separated by \\n.
NEVER combine two sentences on one line.
NEVER write a line longer than 15 words. If it's longer, split it.
Line count depends on question type — see below. Short questions get 3-5 lines, detailed ones get up to 10.

EXAMPLE OF CORRECT FORMAT:
At R&L Carriers I set up Tableau Bridge for our cloud migration.
We had 120 users on live SQL Server connections that couldn't move yet.
So I configured Bridge on a dedicated server and monitored refresh schedules daily.
I built alerts for failed refreshes so I caught issues before users saw stale data.
And we ended up with zero downtime through the whole migration.

EXAMPLE OF WRONG FORMAT (DO NOT DO THIS):
"At R&L Carriers, I owned the Tableau Bridge configuration end-to-end when we migrated from on-premises SQL Server to Tableau Cloud. We had live connections to our TMS and billing systems that couldn't move to the cloud, so Bridge was the connective tissue. I set up the Bridge client on our on-prem server, configured the data source connections, and validated that refresh schedules were hitting on time without failures."
^ WRONG. Those are paragraphs. Each sentence must be its own line.

VOICE — READ-ALOUD READY:
The candidate is nervous, glancing at the screen, reading your words to the interviewer.
Use "I" on action lines: "I built", "I set up", "I configured."
Use spoken transitions: "So what I did was", "And the result was", "What made this tricky was."
NEVER use labels: "Result:", "Context:", "Additionally", "Furthermore."
Contractions always. Sound like a person talking, not a resume.

CONTENT:
Use the Q&A BANK as source of truth — real companies, tools, metrics, outcomes.
Use the resume for facts. Use the JD only to understand the role, never copy its language.
Never fabricate. Every line needs a specific fact — company, tool, metric, or action.
No filler lines. If a line could apply to any candidate, delete it.

QUESTION TYPES (line counts are STRICT):
"Tell me about yourself" → 8-10 lines. This is the candidate's opening statement — give it room.
  Name + years + domain. Current role + what you own.
  2-3 lines on biggest accomplishment with metrics.
  Your approach or framework in 1-2 lines.
  Why this specific role excites you — 2 lines. Be genuine.
Behavioral → 5-7 lines. Company + situation, the challenge, what I did (2-3 lines of detail), result with number, takeaway.
Technical (tool-specific) → 3-5 lines. Company + tool, what I did, scale, outcome.
Technical (process/walkthrough) → 6-8 lines. Walk through each step with real tools and companies.
Strategic/Situational → 4-6 lines. My approach, real example at a company with specifics, result.
Strengths/Weaknesses → 3-4 lines. Name it, prove with a real example, what I do about it.
Why this role → 4-5 lines. What excites me specifically, how my experience connects, what I'd bring.

Output ONLY the answer. No intro, no labels, no "Here's my answer."`;

// Universal addendum for ALL styles — keeps code answers clean
const CODE_ANSWER_ADDENDUM = `

TECHNICAL/CODE QUESTIONS — SPECIAL RULES:
When the question asks you to write code, explain code, or walk through a technical implementation:
- Give the code FIRST, then a 1-2 line explanation AFTER if needed.
- Code must be clean, minimal, and ready to read aloud or copy.
- NO jargon filler around the code. No "Let me walk you through this" or "Here's what I'd do."
- NO explaining what the code does line-by-line unless asked.
- NO buzzwords like "elegant solution", "robust implementation", "leveraging the power of."
- If they ask "what's the difference between X and Y" — state the difference plainly. 2-4 lines max.
- If they ask "how would you do X" — show the code or steps, then one line on why.
- Keep it like you're pair programming: direct, clean, no fluff.`;

// ============ ANSWER STYLE TEMPLATES ============
const ANSWER_STYLES = {
  conversational: {
    name: 'Conversational',
    description: 'Natural, read-aloud friendly — like talking to the interviewer',
    icon: '💬',
    prompt: ANSWER_PROMPT  // The default
  },
  technical: {
    name: 'Technical & Precise',
    description: 'Structured with metrics, tools, and architecture details',
    icon: '⚙️',
    prompt: `You generate interview answers. The candidate reads these OUT LOUD in a live interview.

OUTPUT FORMAT:
Each line = ONE concise sentence. Max 18 words per line.
Each sentence on its own line separated by \\n.
Total: 4-8 lines depending on complexity.

STYLE — TECHNICAL PRECISION:
Lead with the technical approach or architecture decision.
Name specific tools, frameworks, versions, and patterns.
Include metrics: latency, throughput, uptime, scale numbers.
Use precise technical terms — don't simplify for non-technical audience.
Structure: Problem → Technical approach → Implementation detail → Measurable result.

VOICE:
Professional and confident. Use "I" for ownership.
"I implemented", "I architected", "I optimized."
Avoid filler. Every sentence must contain a technical fact.
No "Additionally", "Furthermore", "In conclusion."
Contractions are fine. Sound like a senior engineer in a technical interview.

CONTENT:
Use the Q&A BANK for real examples — companies, tools, metrics.
Use resume for facts. Use JD to understand the role's technical stack.
Never fabricate metrics or tool names.

Output ONLY the answer. No intro, no labels.`
  },
  executive: {
    name: 'Executive Brief',
    description: 'Short, high-impact — bottom-line up front',
    icon: '📊',
    prompt: `You generate interview answers. The candidate reads these OUT LOUD in a live interview.

OUTPUT FORMAT:
Each line = ONE punchy sentence. Max 12 words per line.
Each sentence on its own line separated by \\n.
Total: 3-5 lines MAX. Brevity is everything.

STYLE — EXECUTIVE BRIEF:
Lead with the result or bottom line.
One line of context, one line of action, one line of impact.
Think: elevator pitch for every answer.
Cut anything that doesn't directly prove competence.

VOICE:
Confident and direct. No hedging, no filler.
"I drove", "I delivered", "I led."
Sound like someone who briefs C-suite.

CONTENT:
Use Q&A BANK for real outcomes — revenue, cost savings, team impact.
Every answer must have at least one concrete number.
Never fabricate. Prioritize impact over process.

Output ONLY the answer. No intro, no labels.`
  },
  star: {
    name: 'STAR Method',
    description: 'Situation → Task → Action → Result — classic interview format',
    icon: '⭐',
    prompt: `You generate interview answers. The candidate reads these OUT LOUD in a live interview.

OUTPUT FORMAT:
Each line = ONE short sentence. Max 15 words per line.
Each sentence on its own line separated by \\n.
Total: 6-10 lines following STAR structure.

STYLE — STAR METHOD:
Line 1-2: SITUATION — set the scene with company, team, timeline.
Line 3: TASK — what was your specific responsibility.
Line 4-6: ACTION — what YOU did, step by step. Be specific.
Line 7-8: RESULT — quantified outcome with real numbers.

Do NOT write labels like "Situation:" or "Action:" — just flow naturally.
The STAR structure should be invisible to the interviewer but clear in the logic.

VOICE:
Narrative and clear. Use "I" for ownership.
Spoken transitions: "So what happened was", "My role was to", "The result was."
Contractions always. Sound like you're telling a real story.

CONTENT:
Use Q&A BANK for real stories — actual companies, projects, outcomes.
Use resume for facts. Each answer must reference a real experience.
Never fabricate. If the question doesn't fit STAR, adapt — lead with your approach.

Output ONLY the answer. No intro, no labels.`
  },
  storytelling: {
    name: 'Storytelling',
    description: 'Narrative-driven — hook the interviewer with a compelling story',
    icon: '📖',
    prompt: `You generate interview answers. The candidate reads these OUT LOUD in a live interview.

OUTPUT FORMAT:
Each line = ONE sentence. Max 15 words per line.
Each sentence on its own line separated by \\n.
Total: 6-10 lines with narrative arc.

STYLE — STORYTELLING:
Open with a hook — a surprising fact, a challenge, or a moment.
Build tension: what was at stake, what could go wrong.
Show the turning point: your insight or action that changed things.
Close with the payoff: the result and what you learned.

Make the interviewer WANT to hear what happens next.
Every answer should feel like a mini story, not a list of facts.

VOICE:
Engaging and vivid. Use "I" naturally.
"Picture this:", "The problem was", "That's when I realized."
Paint pictures with specific details — names, numbers, moments.
Contractions always. Sound like you're sharing over coffee.

CONTENT:
Use Q&A BANK for real experiences. Real stories > generic answers.
Ground every story in real companies, real challenges, real outcomes.
Never fabricate. The best stories are true ones.

Output ONLY the answer. No intro, no labels.`
  },
  datadriven: {
    name: 'Data-Driven',
    description: 'Numbers-first — lead with metrics, ROI, and quantified impact',
    icon: '📈',
    prompt: `You generate interview answers. The candidate reads these OUT LOUD in a live interview.

OUTPUT FORMAT:
Each line = ONE sentence. Max 15 words per line.
Each sentence on its own line separated by \\n.
Total: 4-7 lines.

STYLE — DATA-DRIVEN:
Open with the biggest number or metric from your result.
Work backwards: result → what you did → why it mattered.
Every answer must have 2-3 specific numbers: percentages, dollar amounts, time saved, users affected.
Compare before/after when possible.

VOICE:
Analytical and confident. Use "I" for ownership.
"I reduced X by 40%", "I increased throughput from Y to Z."
Be precise — "about 50%" is weak, "47%" is strong.
No filler. If a sentence has no data point, cut it.

CONTENT:
Use Q&A BANK for real metrics from real projects.
Pull numbers from resume achievements.
Never fabricate metrics. If exact numbers aren't available, use realistic ranges.

Output ONLY the answer. No intro, no labels.`
  },
  direct: {
    name: 'Direct Answer',
    description: 'Straight to the point — no filler, no jargon, just the answer',
    icon: '🎯',
    prompt: `You generate interview answers. The candidate reads these OUT LOUD in a live interview.

OUTPUT FORMAT:
Each line = ONE clear sentence. Max 12 words per line.
Each sentence on its own line separated by \\n.
Total: 3-6 lines. Cut everything that isn't essential.

STYLE — DIRECT ANSWER:
Answer the question immediately. First line IS the answer.
No setup, no context-setting, no "Great question."
No jargon. No buzzwords. No corporate speak.
Use plain English a 12-year-old could understand.
If they ask what you did, say what you did. Period.

BANNED WORDS: leverage, utilize, synergy, paradigm, holistic, ecosystem, drive, facilitate, implement solutions, stakeholder alignment, cross-functional, scalable, robust, comprehensive.
USE INSTEAD: use, build, fix, run, help, work with, make, set up, improve.

VOICE:
Honest and plain. Like explaining to a friend.
"I built", "I fixed", "We shipped."
Short sentences. No compound sentences with semicolons.
If you can cut a word, cut it.

CONTENT:
Real facts from Q&A BANK. Company names, what you actually did.
One specific example beats three vague ones.
Numbers when you have them. Skip them when you don't.

Output ONLY the answer. No intro, no labels.`
  }
};

// Get style prompt by key — fallback to conversational, always append code rules
function getStylePrompt(styleKey) {
  return (ANSWER_STYLES[styleKey] || ANSWER_STYLES.conversational).prompt + CODE_ANSWER_ADDENDUM;
}

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

` + ANSWER_PROMPT + CODE_ANSWER_ADDENDUM;

// ============ FILE EXTRACTION ============
async function extractText(buf, name) {
  const ext = (name || '').toLowerCase().split('.').pop();
  if (ext === 'pdf') {
    try {
      const pdfjsLib = require('pdfjs-dist/legacy/build/pdf.js');
      const doc = await pdfjsLib.getDocument({ data: new Uint8Array(buf) }).promise;
      let text = '';
      for (let i = 1; i <= doc.numPages; i++) {
        const page = await doc.getPage(i);
        const content = await page.getTextContent();
        const pageText = content.items.map(item => item.str).join(' ');
        text += pageText + '\n';
      }
      doc.destroy();
      return text;
    } catch(e) { console.error('PDF extraction failed:', e.message); return ''; }
  }
  if (ext === 'docx' || ext === 'doc') { try { return (await require('mammoth').extractRawText({ buffer: buf })).value; } catch(e) { console.error('DOCX extraction failed:', e.message); return ''; } }
  return buf.toString('utf-8');
}

async function extractAnyFileText(buffer, name) {
  const ext = (name || '').toLowerCase().split('.').pop();
  if (ext === 'pptx') {
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
          if (obj['a:t'] !== undefined) texts.push(typeof obj['a:t'] === 'string' ? obj['a:t'] : String(obj['a:t']));
          Object.values(obj).forEach(walk);
        }
      }
      walk(parsed);
      allText.push(texts.join(' '));
    }
    return allText.join('\n');
  }
  return await extractText(buffer, name);
}

function extractQuestionsFromText(text) {
  const questions = [];
  const seen = new Set();
  const matches = text.match(/[^\n.!?]*\?/g) || [];
  for (let q of matches) {
    q = q.replace(/^[\s\-\d.*•→►▸]+/, '').trim();
    if (q.length < 15) continue;
    if (/^(page|slide|note|source|ref|http)/i.test(q)) continue;
    const key = q.toLowerCase().replace(/[^a-z]/g, '');
    if (!seen.has(key)) { seen.add(key); questions.push(q); }
  }
  return questions;
}

// Questions DB helpers (now PostgreSQL)
async function addToQDB(userId, questions) {
  let added = 0;
  for (const q of questions) {
    if (!q.text || q.text.length < 15) continue;
    const key = q.text.toLowerCase().replace(/[^a-z]/g, '');
    // Check if exists
    const existing = await pool.query(
      "SELECT id FROM questions_db WHERE user_id = $1 AND LOWER(REPLACE(text, ' ', '')) LIKE $2 LIMIT 1",
      [userId, '%' + key.substring(0, 50) + '%']
    );
    if (!existing.rows.length) {
      await pool.query('INSERT INTO questions_db (user_id, text, type, source) VALUES ($1, $2, $3, $4)',
        [userId, q.text, q.type || 'Strategic', q.source || 'generated']);
      added++;
    }
  }
  return added;
}

// ============ PROTECTED API ROUTES ============

// Extract text from file upload
app.post('/api/extract-text', upload.single('file'), async (req, res) => {
  try { if (!req.file) return res.status(400).json({ error: 'No file' }); res.json({ text: (await extractText(req.file.buffer, req.file.originalname)).trim() }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Fetch URL
app.post('/api/fetch-url', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'No URL' });
    const fetchUrl = new URL(url);
    const lib = fetchUrl.protocol === 'https:' ? https : require('http');
    const text = await new Promise((resolve, reject) => {
      lib.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } }, (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          lib.get(response.headers.location, { headers: { 'User-Agent': 'Mozilla/5.0' } }, (r2) => {
            let d = ''; r2.on('data', c => d += c); r2.on('end', () => resolve(d));
          }).on('error', reject);
          return;
        }
        let d = ''; response.on('data', c => d += c); response.on('end', () => resolve(d));
      }).on('error', reject);
    });
    const plain = text.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    res.json({ text: plain.substring(0, 15000) });
  } catch (e) { res.json({ text: '', error: e.message }); }
});

// UUID validator
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isValidUUID(s) { return UUID_RE.test(s); }

// --- All session routes require auth ---

// List sessions for current user
app.get('/api/sessions', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.id, s.company, s.role, s.profile,
        (SELECT COUNT(*) FROM questions q WHERE q.session_id = s.id) as question_count,
        (SELECT COUNT(*) FROM questions q WHERE q.session_id = s.id AND q.answer != '') as answered_count,
        (SELECT COUNT(*) FROM meetings m WHERE m.session_id = s.id) as meetings_count,
        s.created_at, s.updated_at
      FROM sessions s WHERE s.user_id = $1 ORDER BY s.created_at DESC
    `, [req.userId]);

    // Get current meeting for each session
    const sessions = [];
    for (const s of result.rows) {
      const cm = await pool.query('SELECT id, name, title, stage FROM meetings WHERE session_id = $1 AND is_current = true LIMIT 1', [s.id]);
      sessions.push({
        id: s.id, company: s.company, role: s.role, profile: s.profile || '',
        questionCount: parseInt(s.question_count), answeredCount: parseInt(s.answered_count),
        meetingsCount: parseInt(s.meetings_count),
        currentMeeting: cm.rows[0] || null,
        created: s.created_at, updated: s.updated_at
      });
    }
    res.json(sessions);
  } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// Get single session (full data)
app.get('/api/sessions/:id', authMiddleware, async (req, res) => {
  try {
    if (!isValidUUID(req.params.id)) return res.status(400).json({ error: 'Invalid session ID' });
    const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });
    const session = s.rows[0];

    const questions = await pool.query('SELECT * FROM questions WHERE session_id = $1 ORDER BY sort_order, created_at', [session.id]);
    const meetings = await pool.query('SELECT * FROM meetings WHERE session_id = $1 ORDER BY date', [session.id]);

    res.json({
      id: session.id, company: session.company, role: session.role, profile: session.profile,
      resume: session.resume, jd: session.jd, candidateName: session.candidate_name,
      experience: session.experience || [],
      pipelineStages: session.pipeline_stages || [],
      answerStyle: session.answer_style || 'conversational',
      questions: questions.rows.map(q => ({ id: q.id, text: q.text, type: q.type, answer: q.answer, starred: q.starred, source: q.source || 'build' })),
      meetings: meetings.rows.map(m => ({ id: m.id, name: m.name, title: m.title, stage: m.stage, isCurrent: m.is_current, date: m.date })),
      created: session.created_at, updated: session.updated_at
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Plan limits (monthly)
const PLAN_LIMITS = { free: { sessions: 1, answers: 10 }, test: { sessions: 2, answers: 999 }, pro: { sessions: 20, answers: 999 }, premium: { sessions: 60, answers: 999 }, admin: { sessions: 999, answers: 999 } };
function getPlanLimits(plan) { return PLAN_LIMITS[plan] || PLAN_LIMITS.free; }
// Get billing cycle start based on when user's plan was activated
async function getBillingCycleStart(userId) {
  const result = await pool.query('SELECT plan_started_at, created_at FROM users WHERE id = $1', [userId]);
  if (!result.rows.length) return new Date().toISOString();
  const paidDate = result.rows[0].plan_started_at || result.rows[0].created_at;
  const paidDay = new Date(paidDate).getDate(); // day of month they paid
  const now = new Date();
  // Cycle resets on the same day each month as when they paid
  let cycleStart;
  if (now.getDate() >= paidDay) {
    cycleStart = new Date(now.getFullYear(), now.getMonth(), paidDay);
  } else {
    cycleStart = new Date(now.getFullYear(), now.getMonth() - 1, paidDay);
  }
  return cycleStart.toISOString();
}

// Create session
app.post('/api/sessions', authMiddleware, async (req, res) => {
  try {
    // Check monthly session limit (counts ALL creations, even deleted — resets on billing cycle)
    const limits = getPlanLimits(req.plan);
    if (limits.sessions < 999) {
      const cycleStart = await getBillingCycleStart(req.userId);
      const count = await pool.query('SELECT COUNT(*) FROM session_creations WHERE user_id = $1 AND created_at >= $2', [req.userId, cycleStart]);
      if (parseInt(count.rows[0].count) >= limits.sessions) {
        return res.status(403).json({ error: `Your ${req.plan} plan allows ${limits.sessions} session(s)/month. Upgrade for more.` });
      }
    }
    const { resume, jd, company, role } = req.body;
    const result = await pool.query(
      'INSERT INTO sessions (user_id, company, role, resume, jd) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.userId, company || '', role || '', resume || '', jd || '']
    );
    const session = result.rows[0];
    // Log session creation (permanent — survives deletion, used for limit enforcement)
    await pool.query('INSERT INTO session_creations (user_id, session_id) VALUES ($1, $2)', [req.userId, session.id]);
    res.json({ id: session.id, company: session.company, role: session.role, resume: session.resume, jd: session.jd, questions: [], meetings: [], pipelineStages: [], created: session.created_at, updated: session.updated_at });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete session
app.delete('/api/sessions/:id', authMiddleware, async (req, res) => {
  try {
    // Test plan users cannot delete sessions (prevents gaming the session limit)
    if (req.plan === 'test') {
      return res.status(403).json({ error: 'Test accounts cannot delete sessions. Deleted sessions still count toward your limit. Upgrade for more sessions.' });
    }
    const delResult = await pool.query('DELETE FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (delResult.rowCount === 0) return res.status(404).json({ error: 'Session not found' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Add questions
app.post('/api/sessions/:id/questions', authMiddleware, async (req, res) => {
  try {
    const s = await pool.query('SELECT id FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });

    const lines = (req.body.questions || '').split('\n').map(q => q.trim()).filter(q => q.length > 0);
    const added = [];
    for (const text of lines) {
      const result = await pool.query(
        'INSERT INTO questions (session_id, text, type) VALUES ($1, $2, $3) RETURNING *',
        [req.params.id, text, detectType(text)]
      );
      added.push({ id: result.rows[0].id, text, type: result.rows[0].type, answer: '' });
    }

    // Save to questions DB
    await addToQDB(req.userId, added.map(q => ({ text: q.text, type: q.type, source: 'manual' })));

    // Return full session
    const fullSession = await getFullSession(req.params.id, req.userId);
    res.json({ added, session: fullSession });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Import questions from file
app.post('/api/sessions/:id/import-questions', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const s = await pool.query('SELECT id FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });

    const text = await extractAnyFileText(req.file.buffer, req.file.originalname);
    const questions = extractQuestionsFromText(text);

    // Get existing questions to dedup
    const existing = await pool.query('SELECT text FROM questions WHERE session_id = $1', [req.params.id]);
    const existingKeys = new Set(existing.rows.map(q => q.text.toLowerCase().replace(/[^a-z]/g, '')));

    const added = [];
    for (const q of questions) {
      const key = q.toLowerCase().replace(/[^a-z]/g, '');
      if (!existingKeys.has(key)) {
        existingKeys.add(key);
        const result = await pool.query(
          'INSERT INTO questions (session_id, text, type) VALUES ($1, $2, $3) RETURNING *',
          [req.params.id, q, detectType(q)]
        );
        added.push({ id: result.rows[0].id, text: q, type: result.rows[0].type, answer: '' });
      }
    }

    const fullSession = await getFullSession(req.params.id, req.userId);
    res.json({ added, total: fullSession.questions.length, session: fullSession });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Pipeline stages (independent of people)
app.post('/api/sessions/:id/stages', authMiddleware, async (req, res) => {
  try {
    const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });
    const { stage } = req.body;
    if (!stage) return res.status(400).json({ error: 'Stage name required' });
    const currentStages = s.rows[0].pipeline_stages || [];
    if (!currentStages.includes(stage)) {
      currentStages.push(stage);
      await pool.query('UPDATE sessions SET pipeline_stages = $1, updated_at = NOW() WHERE id = $2', [JSON.stringify(currentStages), req.params.id]);
    }
    const fullSession = await getFullSession(req.params.id, req.userId);
    res.json({ session: fullSession });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/sessions/:id/stages/:stageName', authMiddleware, async (req, res) => {
  try {
    const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });
    const currentStages = (s.rows[0].pipeline_stages || []).filter(st => st !== decodeURIComponent(req.params.stageName));
    await pool.query('UPDATE sessions SET pipeline_stages = $1, updated_at = NOW() WHERE id = $2', [JSON.stringify(currentStages), req.params.id]);
    // Also remove meetings in that stage
    await pool.query('DELETE FROM meetings WHERE session_id = $1 AND stage = $2', [req.params.id, decodeURIComponent(req.params.stageName)]);
    const fullSession = await getFullSession(req.params.id, req.userId);
    res.json({ session: fullSession });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Meetings
app.post('/api/sessions/:id/meetings', authMiddleware, async (req, res) => {
  try {
    const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });

    // Mark all as not current
    await pool.query('UPDATE meetings SET is_current = false WHERE session_id = $1', [req.params.id]);

    const { name, title, stage } = req.body;
    await pool.query(
      'INSERT INTO meetings (session_id, name, title, stage, is_current) VALUES ($1, $2, $3, $4, true)',
      [req.params.id, name || '', title || '', stage || '']
    );

    // Ensure stage is in pipeline_stages
    if (stage) {
      const currentStages = s.rows[0].pipeline_stages || [];
      if (!currentStages.includes(stage)) {
        currentStages.push(stage);
        await pool.query('UPDATE sessions SET pipeline_stages = $1 WHERE id = $2', [JSON.stringify(currentStages), req.params.id]);
      }
    }

    await pool.query('UPDATE sessions SET updated_at = NOW() WHERE id = $1', [req.params.id]);
    const fullSession = await getFullSession(req.params.id, req.userId);
    res.json({ session: fullSession });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/sessions/:id/meetings/:mid', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM meetings WHERE id = $1 AND session_id = $2', [req.params.mid, req.params.id]);
    await pool.query('UPDATE sessions SET updated_at = NOW() WHERE id = $1', [req.params.id]);
    const fullSession = await getFullSession(req.params.id, req.userId);
    res.json({ session: fullSession });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/sessions/:id/meetings/:mid/current', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE meetings SET is_current = false WHERE session_id = $1', [req.params.id]);
    await pool.query('UPDATE meetings SET is_current = true WHERE id = $1 AND session_id = $2', [req.params.mid, req.params.id]);
    await pool.query('UPDATE sessions SET updated_at = NOW() WHERE id = $1', [req.params.id]);
    const fullSession = await getFullSession(req.params.id, req.userId);
    res.json({ session: fullSession });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// BUILD session
app.post('/api/sessions/:id/build', authMiddleware, async (req, res) => {
  try {
    const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });
    const session = s.rows[0];
    const qaBank = getQABank();

    // Step 1: Extract info in parallel (Haiku)
    const [infoResult, profileResult, resumeResult] = await Promise.allSettled([
      callClaude('Extract the company name and exact job title from this job description. Return ONLY a JSON object like {"company":"Acme Corp","role":"Senior Data Analyst"}. Nothing else, no explanation, no markdown.', session.jd.substring(0, 4000), 150, MODEL_HAIKU),
      callClaude('Write a 2 sentence brief about the COMPANY (not the candidate). What does the company do? What industry? What is their mission? Based on the job description. No headers.', session.jd.substring(0, 4000), 150, MODEL_HAIKU),
      callClaude('Extract from this resume: the person\'s full name and ALL their work experience. Include EVERY job listed on the resume — do not skip any. Return ONLY a JSON object like {"name":"John Smith","experience":[{"company":"Acme Corp","role":"Senior Analyst","years":"2020-Present"}]}. Most recent first. No explanation, no markdown.', session.resume.substring(0, 8000), 500, MODEL_HAIKU)
    ]);

    let company = session.company || 'New Session';
    let role = session.role || '';
    let profile = '';
    let candidateName = '';
    let experience = [];

    if (infoResult.status === 'fulfilled') {
      try { const m = infoResult.value.match(/\{[^}]+\}/); const o = m ? JSON.parse(m[0]) : {}; company = o.company || company; role = o.role || role; } catch(e) {}
    }
    if (profileResult.status === 'fulfilled') profile = profileResult.value;
    if (resumeResult.status === 'fulfilled') {
      try { const rm = resumeResult.value.match(/\{[\s\S]*\}/); const ro = rm ? JSON.parse(rm[0]) : {}; candidateName = ro.name || ''; experience = ro.experience || []; } catch(e) {}
    }

    // Update session
    await pool.query('UPDATE sessions SET company=$1, role=$2, profile=$3, candidate_name=$4, experience=$5, updated_at=NOW() WHERE id=$6',
      [company, role, profile, candidateName, JSON.stringify(experience), req.params.id]);

    // Step 2: Add must-have questions
    const existingQ = await pool.query('SELECT text FROM questions WHERE session_id = $1', [req.params.id]);
    const existingTexts = new Set(existingQ.rows.map(q => q.text.toLowerCase().replace(/[^a-z]/g, '')));

    let sortOrder = 0;
    for (const q of MUST_HAVE) {
      const key = q.toLowerCase().replace(/[^a-z]/g, '');
      if (!existingTexts.has(key)) {
        existingTexts.add(key);
        await pool.query('INSERT INTO questions (session_id, text, type, starred, sort_order) VALUES ($1, $2, $3, true, $4)',
          [req.params.id, q, detectType(q), sortOrder++]);
      }
    }

    // Step 3: Generate JD-specific questions
    const bankQuestions = (qaBank.match(/Q:\s*(.+)/g) || []).map(l => l.replace(/^Q:\s*/, '').trim()).filter(q => q.length > 10);

    try {
      // Step 3a: Extract ALL tools, technologies, and must-haves from JD first
      let jdTools = '';
      try {
        jdTools = await callClaude(
          'Extract from this job description. List ALL tools, technologies, platforms, systems, languages, frameworks, and must-have requirements mentioned. One per line. Include everything — SQL, Python, Tableau, Snowflake, AWS, Excel, etc. Do not skip anything.',
          'JOB DESCRIPTION:\n' + session.jd.substring(0, 6000) + '\n\nList every tool, technology, and must-have requirement:',
          500, MODEL_HAIKU
        );
        console.log('[Build] JD tools extracted:', jdTools.substring(0, 200));
      } catch(e) { console.log('[Build] Tool extraction failed, continuing:', e.message); }

      // Step 3b: Generate questions — with extracted tools as checklist
      const qTxt = await callClaude(
        'You are an expert interview coach. Generate questions DIRECTLY tied to the JD. No generic filler.',
        'CANDIDATE PREPARED QUESTIONS (pick relevant ones ONLY):\n' + bankQuestions.join('\n') +
        '\n\nJOB DESCRIPTION:\n' + session.jd.substring(0, 6000) +
        (jdTools ? '\n\nTOOLS & TECHNOLOGIES FOUND IN JD (you MUST generate at least 1 question for EACH):\n' + jdTools : '') +
        '\n\nINSTRUCTIONS:\nPRIORITY 1 — TOOLS & TECHNOLOGIES COVERAGE (MANDATORY):\nYou MUST generate at least 1 question for EVERY tool, technology, and must-have listed above.\nFor major tools (SQL, Python, Tableau, etc.) generate 2-3 questions.\nAsk how the candidate used each tool in production at a real company.\nDO NOT SKIP ANY. If the JD mentions it, there must be a question about it.\n\nPRIORITY 2 — JD RESPONSIBILITIES:\nFor each key responsibility, generate 1 behavioral or situational question.\n\nPRIORITY 3 — RELEVANT BANK QUESTIONS:\nPick 10-15 from the candidate list that DIRECTLY relate to the JD.\n\nDO NOT GENERATE:\n- "Tell me about yourself", "strengths", "weaknesses", "why this role", "why are you leaving", "career goals", "greatest accomplishment", "what motivates you", "questions for us"\n- Generic behavioral questions not tied to the JD\n\nOUTPUT 40-60 high-quality questions. One per line. No numbering. Just the question ending with ?\nAt the end, verify: did you cover every tool from the list above? If not, add the missing ones.',
        4000, MODEL_HAIKU
      );
      const qs = qTxt.split('\n').map(q => q.trim()).filter(q => q.length > 15 && q.includes('?'));
      for (const q of qs) {
        const key = q.toLowerCase().replace(/[^a-z]/g, '');
        if (!existingTexts.has(key)) {
          existingTexts.add(key);
          await pool.query('INSERT INTO questions (session_id, text, type, sort_order) VALUES ($1, $2, $3, $4)',
            [req.params.id, q, detectType(q), sortOrder++]);
        }
      }
    } catch(e) {
      console.error('AI question generation failed:', e.message);
      for (const q of bankQuestions) {
        const key = q.toLowerCase().replace(/[^a-z]/g, '');
        if (!existingTexts.has(key)) {
          existingTexts.add(key);
          await pool.query('INSERT INTO questions (session_id, text, type, sort_order) VALUES ($1, $2, $3, $4)',
            [req.params.id, q, detectType(q), sortOrder++]);
        }
      }
    }

    // Save to questions DB
    const allQ = await pool.query('SELECT text, type FROM questions WHERE session_id = $1', [req.params.id]);
    await addToQDB(req.userId, allQ.rows.map(q => ({ text: q.text, type: q.type, source: 'build' })));

    const fullSession = await getFullSession(req.params.id, req.userId);
    console.log(`Build complete: ${fullSession.questions.length} questions`);
    res.json({ session: fullSession });
  } catch (e) { console.error('Build error:', e); res.status(500).json({ error: e.message }); }
});

// REGENERATE questions & answers (admin + premium only, preserves stages/meetings)
app.post('/api/sessions/:id/regenerate', authMiddleware, async (req, res) => {
  try {
    // Only admin and premium can regenerate
    if (!req.isAdmin && req.plan !== 'premium') {
      return res.status(403).json({ error: 'Regenerate is available for Premium and Admin users only.' });
    }
    const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });
    const session = s.rows[0];
    if (!session.resume || !session.jd) return res.status(400).json({ error: 'Session missing resume or JD' });

    // Delete existing questions & answers ONLY — preserve pipeline_stages, meetings, experience, etc.
    await pool.query('DELETE FROM questions WHERE session_id = $1', [req.params.id]);
    console.log(`[Regenerate] Cleared questions for session ${req.params.id}, preserving stages & meetings`);

    const qaBank = getQABank();

    // Re-run extraction (company/role/profile might improve with re-run)
    const [infoResult, profileResult, resumeResult] = await Promise.allSettled([
      callClaude('Extract the company name and exact job title from this job description. Return ONLY a JSON object like {"company":"Acme Corp","role":"Senior Data Analyst"}. Nothing else, no explanation, no markdown.', session.jd.substring(0, 4000), 150, MODEL_HAIKU),
      callClaude('Write a 2 sentence brief about the COMPANY (not the candidate). What does the company do? What industry? What is their mission? Based on the job description. No headers.', session.jd.substring(0, 4000), 150, MODEL_HAIKU),
      callClaude('Extract from this resume: the person\'s full name and ALL their work experience. Include EVERY job listed on the resume — do not skip any. Return ONLY a JSON object like {"name":"John Smith","experience":[{"company":"Acme Corp","role":"Senior Analyst","years":"2020-Present"}]}. Most recent first. No explanation, no markdown.', session.resume.substring(0, 8000), 500, MODEL_HAIKU)
    ]);

    let company = session.company || 'New Session';
    let role = session.role || '';
    let profile = '';
    let candidateName = session.candidate_name || '';
    let experience = session.experience || [];

    if (infoResult.status === 'fulfilled') {
      try { const m = infoResult.value.match(/\{[^}]+\}/); const o = m ? JSON.parse(m[0]) : {}; company = o.company || company; role = o.role || role; } catch(e) {}
    }
    if (profileResult.status === 'fulfilled') profile = profileResult.value;
    if (resumeResult.status === 'fulfilled') {
      try { const rm = resumeResult.value.match(/\{[\s\S]*\}/); const ro = rm ? JSON.parse(rm[0]) : {}; candidateName = ro.name || candidateName; experience = ro.experience || experience; } catch(e) {}
    }

    // Update session info but NOT pipeline_stages or meetings
    await pool.query('UPDATE sessions SET company=$1, role=$2, profile=$3, candidate_name=$4, experience=$5, updated_at=NOW() WHERE id=$6',
      [company, role, profile, candidateName, JSON.stringify(experience), req.params.id]);

    // Re-generate must-have questions
    const existingTexts = new Set();
    let sortOrder = 0;
    for (const q of MUST_HAVE) {
      const key = q.toLowerCase().replace(/[^a-z]/g, '');
      if (!existingTexts.has(key)) {
        existingTexts.add(key);
        await pool.query('INSERT INTO questions (session_id, text, type, starred, sort_order) VALUES ($1, $2, $3, true, $4)',
          [req.params.id, q, detectType(q), sortOrder++]);
      }
    }

    // Re-generate JD-specific questions
    const bankQuestions = (qaBank.match(/Q:\s*(.+)/g) || []).map(l => l.replace(/^Q:\s*/, '').trim()).filter(q => q.length > 10);
    try {
      let jdTools = '';
      try {
        jdTools = await callClaude(
          'Extract from this job description. List ALL tools, technologies, platforms, systems, languages, frameworks, and must-have requirements mentioned. One per line. Include everything — SQL, Python, Tableau, Snowflake, AWS, Excel, etc. Do not skip anything.',
          'JOB DESCRIPTION:\n' + session.jd.substring(0, 6000) + '\n\nList every tool, technology, and must-have requirement:',
          500, MODEL_HAIKU
        );
      } catch(e) { console.log('[Regenerate] Tool extraction failed:', e.message); }

      const qTxt = await callClaude(
        'You are an expert interview coach. Generate questions DIRECTLY tied to the JD. No generic filler.',
        'CANDIDATE PREPARED QUESTIONS (pick relevant ones ONLY):\n' + bankQuestions.join('\n') +
        '\n\nJOB DESCRIPTION:\n' + session.jd.substring(0, 6000) +
        (jdTools ? '\n\nTOOLS & TECHNOLOGIES FOUND IN JD (you MUST generate at least 1 question for EACH):\n' + jdTools : '') +
        '\n\nINSTRUCTIONS:\nPRIORITY 1 — TOOLS & TECHNOLOGIES COVERAGE (MANDATORY):\nYou MUST generate at least 1 question for EVERY tool, technology, and must-have listed above.\nFor major tools (SQL, Python, Tableau, etc.) generate 2-3 questions.\nAsk how the candidate used each tool in production at a real company.\nDO NOT SKIP ANY. If the JD mentions it, there must be a question about it.\n\nPRIORITY 2 — JD RESPONSIBILITIES:\nFor each key responsibility, generate 1 behavioral or situational question.\n\nPRIORITY 3 — RELEVANT BANK QUESTIONS:\nPick 10-15 from the candidate list that DIRECTLY relate to the JD.\n\nDO NOT GENERATE:\n- "Tell me about yourself", "strengths", "weaknesses", "why this role", "why are you leaving", "career goals", "greatest accomplishment", "what motivates you", "questions for us"\n- Generic behavioral questions not tied to the JD\n\nOUTPUT 40-60 high-quality questions. One per line. No numbering. Just the question ending with ?\nAt the end, verify: did you cover every tool from the list above? If not, add the missing ones.',
        4000, MODEL_HAIKU
      );
      const qs = qTxt.split('\n').map(q => q.trim()).filter(q => q.length > 15 && q.includes('?'));
      for (const q of qs) {
        const key = q.toLowerCase().replace(/[^a-z]/g, '');
        if (!existingTexts.has(key)) {
          existingTexts.add(key);
          await pool.query('INSERT INTO questions (session_id, text, type, sort_order) VALUES ($1, $2, $3, $4)',
            [req.params.id, q, detectType(q), sortOrder++]);
        }
      }
    } catch(e) {
      console.error('[Regenerate] AI question generation failed:', e.message);
      for (const q of bankQuestions) {
        const key = q.toLowerCase().replace(/[^a-z]/g, '');
        if (!existingTexts.has(key)) {
          existingTexts.add(key);
          await pool.query('INSERT INTO questions (session_id, text, type, sort_order) VALUES ($1, $2, $3, $4)',
            [req.params.id, q, detectType(q), sortOrder++]);
        }
      }
    }

    const allQ = await pool.query('SELECT text, type FROM questions WHERE session_id = $1', [req.params.id]);
    await addToQDB(req.userId, allQ.rows.map(q => ({ text: q.text, type: q.type, source: 'regenerate' })));

    const fullSession = await getFullSession(req.params.id, req.userId);
    console.log(`[Regenerate] Complete: ${fullSession.questions.length} questions, stages preserved: ${(fullSession.pipelineStages || []).length}, meetings preserved: ${(fullSession.meetings || []).length}`);
    res.json({ session: fullSession });
  } catch (e) { console.error('Regenerate error:', e); res.status(500).json({ error: e.message }); }
});

// EDIT resume/JD on existing session (paid users + admin)
app.put('/api/sessions/:id/documents', authMiddleware, async (req, res) => {
  try {
    // Free users cannot edit
    if (!req.isAdmin && req.plan === 'free') {
      return res.status(403).json({ error: 'Editing session documents requires a paid plan.' });
    }
    const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });
    const session = s.rows[0];

    const { resume, jd } = req.body;
    if (!resume && !jd) return res.status(400).json({ error: 'Provide resume or jd to update' });

    // Detect if changes affect company/role (significant change)
    let significantChange = false;
    let newCompany = session.company;
    let newRole = session.role;

    if (jd && jd !== session.jd) {
      try {
        const infoResult = await callClaude(
          'Extract the company name and exact job title from this job description. Return ONLY a JSON object like {"company":"Acme Corp","role":"Senior Data Analyst"}. Nothing else.',
          jd.substring(0, 4000), 150, MODEL_HAIKU
        );
        const m = infoResult.match(/\{[^}]+\}/);
        const o = m ? JSON.parse(m[0]) : {};
        newCompany = o.company || session.company;
        newRole = o.role || session.role;
        // Check if company or role changed significantly
        if (newCompany.toLowerCase() !== (session.company || '').toLowerCase() ||
            newRole.toLowerCase() !== (session.role || '').toLowerCase()) {
          significantChange = true;
        }
      } catch(e) {}
    }

    if (resume && resume !== session.resume) {
      try {
        const resumeResult = await callClaude(
          'Extract from this resume: the person\'s full name. Return ONLY a JSON object like {"name":"John Smith"}. Nothing else.',
          resume.substring(0, 4000), 100, MODEL_HAIKU
        );
        const rm = resumeResult.match(/\{[^}]+\}/);
        const ro = rm ? JSON.parse(rm[0]) : {};
        const newName = ro.name || '';
        if (newName && session.candidate_name && newName.toLowerCase() !== (session.candidate_name || '').toLowerCase()) {
          significantChange = true;
        }
      } catch(e) {}
    }

    // If significant change detected, return warning (don't auto-apply)
    if (significantChange && !req.body.forceUpdate) {
      return res.status(409).json({
        warning: true,
        message: `This changes the ${newCompany !== session.company ? 'company (' + newCompany + ')' : ''}${newCompany !== session.company && newRole !== session.role ? ' and ' : ''}${newRole !== session.role ? 'role (' + newRole + ')' : ''}. Existing questions won't match. You'll need to regenerate — this counts as a new session build.`,
        newCompany, newRole,
        requiresRegenerate: true
      });
    }

    // Apply the update
    const updates = [];
    const values = [];
    let idx = 1;
    if (resume) { updates.push(`resume = $${idx++}`); values.push(resume); }
    if (jd) { updates.push(`jd = $${idx++}`); values.push(jd); }
    if (significantChange) {
      updates.push(`company = $${idx++}`); values.push(newCompany);
      updates.push(`role = $${idx++}`); values.push(newRole);
    }
    updates.push('updated_at = NOW()');
    values.push(req.params.id);
    await pool.query(`UPDATE sessions SET ${updates.join(', ')} WHERE id = $${idx}`, values);

    const fullSession = await getFullSession(req.params.id, req.userId);
    res.json({ session: fullSession, significantChange, requiresRegenerate: significantChange });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Check monthly answer usage
async function checkAnswerLimit(userId, plan) {
  const limits = getPlanLimits(plan);
  if (limits.answers >= 999) return { ok: true };
  const cycleStart = await getBillingCycleStart(userId);
  const result = await pool.query(
    `SELECT COUNT(*) FROM questions q JOIN sessions s ON q.session_id = s.id WHERE s.user_id = $1 AND q.answer != '' AND q.created_at >= $2`,
    [userId, cycleStart]
  );
  const used = parseInt(result.rows[0].count);
  if (used >= limits.answers) return { ok: false, used, limit: limits.answers };
  return { ok: true, used, limit: limits.answers, remaining: limits.answers - used };
}

// Generate single answer
app.post('/api/sessions/:id/generate/:qid', authMiddleware, async (req, res) => {
  try {
    const answerCheck = await checkAnswerLimit(req.userId, req.plan);
    if (!answerCheck.ok) return res.status(403).json({ error: `Monthly answer limit reached (${answerCheck.limit}). Upgrade for more.` });

    const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });
    const session = s.rows[0];

    const q = await pool.query('SELECT * FROM questions WHERE id = $1 AND session_id = $2', [req.params.qid, req.params.id]);
    if (!q.rows.length) return res.status(404).json({ error: 'Q not found' });
    const question = q.rows[0];

    const qaBank = getQABank();
    const userInstruction = req.body?.instruction?.trim() || '';
    let userMsg = `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume}\n\nJD:\n${session.jd}\n\nQuestion:\n${question.text}\n\n`;
    if (userInstruction) {
      userMsg += `USER INSTRUCTION (follow this closely): ${userInstruction}\n\nGenerate an answer following the user's instruction, tailored to the resume and JD.`;
    } else {
      userMsg += `Give me a strong answer tailored to this JD.`;
    }

    const stylePrompt = getStylePrompt(session.answer_style);
    const answer = await callClaude(stylePrompt, userMsg, 1500, MODEL_HAIKU);
    await pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, question.id]);
    await pool.query('UPDATE sessions SET updated_at = NOW() WHERE id = $1', [req.params.id]);
    res.json({ answer });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Generate batch
app.post('/api/sessions/:id/generate-batch', authMiddleware, async (req, res) => {
  try {
    const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });
    const session = s.rows[0];
    const qaBank = getQABank();
    const { questionIds } = req.body;
    if (!questionIds || !questionIds.length) return res.status(400).json({ error: 'No question IDs' });

    const qResult = await pool.query('SELECT * FROM questions WHERE id = ANY($1) AND session_id = $2', [questionIds, req.params.id]);
    const batch = questionIds.map(id => qResult.rows.find(q => q.id === id)).filter(Boolean);
    if (!batch.length) return res.status(404).json({ error: 'Questions not found' });

    const results = [];

    const stylePrompt = getStylePrompt(session.answer_style);
    if (batch.length === 1) {
      try {
        const answer = await callClaude(stylePrompt,
          `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume}\n\nJD:\n${session.jd}\n\nQuestion:\n${batch[0].text}\n\nGive me a strong answer tailored to this JD.`,
          1500, MODEL_HAIKU
        );
        await pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, batch[0].id]);
        results.push({ id: batch[0].id, answer });
      } catch(e) { results.push({ id: batch[0].id, error: e.message }); }
    } else {
      const questionsBlock = batch.map((q, idx) => `Q${idx + 1}: ${q.text}`).join('\n');
      try {
        const batchResponse = await callClaude(BATCH_PROMPT,
          `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume}\n\nJD:\n${session.jd}\n\n${batch.length} QUESTIONS TO ANSWER:\n${questionsBlock}\n\nGenerate a strong, complete answer for EACH question. Use the ===Q1=== ===Q2=== format. Every answer must be tailored to this JD.`,
          batch.length * 1500, MODEL_HAIKU
        );
        const parts = batchResponse.split(/===Q\d+===/);
        if (!parts[0] || parts[0].trim().length < 20) parts.shift();

        for (let idx = 0; idx < batch.length; idx++) {
          const answer = parts[idx] ? parts[idx].trim() : '';
          if (answer && answer.length > 20) {
            await pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, batch[idx].id]);
            results.push({ id: batch[idx].id, answer });
          } else {
            results.push({ id: batch[idx].id, error: 'Empty answer in batch' });
          }
        }
      } catch(e) {
        for (const q of batch) {
          try {
            const answer = await callClaude(ANSWER_PROMPT,
              `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume}\n\nJD:\n${session.jd}\n\nQuestion:\n${q.text}\n\nGive me a strong answer tailored to this JD.`,
              1500, MODEL_HAIKU
            );
            await pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, q.id]);
            results.push({ id: q.id, answer });
          } catch(e2) { results.push({ id: q.id, error: e2.message }); }
        }
      }
    }

    await pool.query('UPDATE sessions SET updated_at = NOW() WHERE id = $1', [req.params.id]);
    res.json({ results });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Questions DB API
app.get('/api/questions-db', authMiddleware, async (req, res) => {
  const result = await pool.query('SELECT * FROM questions_db WHERE user_id = $1 ORDER BY added_at DESC', [req.userId]);
  res.json({ total: result.rows.length, questions: result.rows });
});

// ============ ADMIN API ============
function adminOnly(req, res, next) {
  if (!req.isAdmin) return res.status(403).json({ error: 'Admin only' });
  next();
}

// List all users
app.get('/api/admin/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.email, u.name, u.is_admin, u.plan, u.suspended, u.avatar_url, u.created_at, u.updated_at,
        (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) as session_count,
        (SELECT COUNT(*) FROM questions q JOIN sessions s ON q.session_id = s.id WHERE s.user_id = u.id) as question_count,
        (SELECT COUNT(*) FROM questions q JOIN sessions s ON q.session_id = s.id WHERE s.user_id = u.id AND q.answer != '') as answer_count
      FROM users u ORDER BY u.created_at DESC
    `);
    res.json({ total: result.rows.length, users: result.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get single user detail
app.get('/api/admin/users/:uid', authMiddleware, adminOnly, async (req, res) => {
  try {
    const u = await pool.query('SELECT id, email, name, is_admin, plan, avatar_url, created_at FROM users WHERE id = $1', [req.params.uid]);
    if (!u.rows.length) return res.status(404).json({ error: 'User not found' });
    const sessions = await pool.query(`
      SELECT s.id, s.company, s.role,
        (SELECT COUNT(*) FROM questions q WHERE q.session_id = s.id) as questions,
        (SELECT COUNT(*) FROM questions q WHERE q.session_id = s.id AND q.answer != '') as answered,
        s.created_at
      FROM sessions s WHERE s.user_id = $1 ORDER BY s.updated_at DESC
    `, [req.params.uid]);
    res.json({ user: u.rows[0], sessions: sessions.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Update user plan/admin status
app.put('/api/admin/users/:uid', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { plan, is_admin } = req.body;
    const updates = [];
    const values = [];
    let i = 1;
    if (plan !== undefined) { updates.push(`plan = $${i++}`); values.push(plan); updates.push(`plan_started_at = NOW()`); }
    if (is_admin !== undefined) { updates.push(`is_admin = $${i++}`); values.push(is_admin); }
    if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
    updates.push(`updated_at = NOW()`);
    values.push(req.params.uid);
    await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${i}`, values);
    const result = await pool.query('SELECT id, email, name, is_admin, plan, created_at FROM users WHERE id = $1', [req.params.uid]);
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Suspend / unsuspend user
app.put('/api/admin/users/:uid/suspend', authMiddleware, adminOnly, async (req, res) => {
  try {
    if (req.params.uid === req.userId) return res.status(400).json({ error: "Can't suspend yourself" });
    const { suspended } = req.body;
    await pool.query('UPDATE users SET suspended = $1, updated_at = NOW() WHERE id = $2', [suspended, req.params.uid]);
    const result = await pool.query('SELECT id, email, name, is_admin, plan, suspended, created_at FROM users WHERE id = $1', [req.params.uid]);
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete user
app.delete('/api/admin/users/:uid', authMiddleware, adminOnly, async (req, res) => {
  try {
    if (req.params.uid === req.userId) return res.status(400).json({ error: "Can't delete yourself" });
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.uid]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Admin stats
app.get('/api/admin/stats', authMiddleware, adminOnly, async (req, res) => {
  try {
    const users = await pool.query('SELECT COUNT(*) FROM users');
    const sessions = await pool.query('SELECT COUNT(*) FROM sessions');
    const questions = await pool.query('SELECT COUNT(*) FROM questions');
    const answers = await pool.query("SELECT COUNT(*) FROM questions WHERE answer != ''");
    const meetings = await pool.query('SELECT COUNT(*) FROM meetings');
    res.json({
      totalUsers: parseInt(users.rows[0].count),
      totalSessions: parseInt(sessions.rows[0].count),
      totalQuestions: parseInt(questions.rows[0].count),
      totalAnswers: parseInt(answers.rows[0].count),
      totalMeetings: parseInt(meetings.rows[0].count)
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Helper: get full session object
async function getFullSession(sessionId, userId) {
  const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [sessionId, userId]);
  if (!s.rows.length) return null;
  const session = s.rows[0];
  const questions = await pool.query('SELECT * FROM questions WHERE session_id = $1 ORDER BY sort_order, created_at', [sessionId]);
  const meetings = await pool.query('SELECT * FROM meetings WHERE session_id = $1 ORDER BY date', [sessionId]);
  return {
    id: session.id, company: session.company, role: session.role, profile: session.profile,
    resume: session.resume, jd: session.jd, candidateName: session.candidate_name,
    experience: session.experience || [],
    pipelineStages: session.pipeline_stages || [],
    answerStyle: session.answer_style || 'conversational',
    questions: questions.rows.map(q => ({ id: q.id, text: q.text, type: q.type, answer: q.answer, starred: q.starred, source: q.source || 'build' })),
    meetings: meetings.rows.map(m => ({ id: m.id, name: m.name, title: m.title, stage: m.stage, isCurrent: m.is_current, date: m.date })),
    created: session.created_at, updated: session.updated_at
  };
}

// Answer styles list endpoint
app.get('/api/answer-styles', (req, res) => {
  const styles = Object.entries(ANSWER_STYLES).map(([key, s]) => ({
    key, name: s.name, description: s.description, icon: s.icon
  }));
  res.json({ styles });
});

// Update session answer style
app.put('/api/sessions/:id/answer-style', authMiddleware, async (req, res) => {
  try {
    const { style } = req.body;
    if (!style || !ANSWER_STYLES[style]) return res.status(400).json({ error: 'Invalid style' });
    const result = await pool.query('UPDATE sessions SET answer_style = $1, updated_at = NOW() WHERE id = $2 AND user_id = $3 RETURNING id', [style, req.params.id, req.userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });

    // Generate a sample answer — pick a random question from this session
    const s = await pool.query('SELECT resume, jd FROM sessions WHERE id = $1', [req.params.id]);
    const session = s.rows[0];
    const qs = await pool.query('SELECT text FROM questions WHERE session_id = $1 AND starred = true ORDER BY RANDOM() LIMIT 1', [req.params.id]);
    const sampleQ = qs.rows.length ? qs.rows[0].text : 'Tell me about yourself.';
    const stylePrompt = getStylePrompt(style);
    const qaBank = getQABank();
    const sampleAnswer = await callClaude(stylePrompt,
      `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume || 'Experienced professional'}\n\nJD:\n${session.jd || 'Software role'}\n\nQuestion:\n${sampleQ}\n\nGive me a strong answer tailored to this JD.`,
      1000, MODEL_HAIKU
    );

    res.json({ style, sampleQuestion: sampleQ, sampleAnswer });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Config endpoint — passes public env vars to frontend
app.get('/api/config', (req, res) => {
  res.json({ googleClientId: process.env.GOOGLE_CLIENT_ID || '' });
});

// API: get transcripts for a session
app.get('/api/sessions/:id/transcripts', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, transcript, questions_detected, report, interviewer_name, interviewer_title, stage, started_at, ended_at FROM live_transcripts WHERE session_id = $1 AND user_id = $2 ORDER BY created_at DESC',
      [req.params.id, req.userId]
    );
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete a single transcript
app.delete('/api/sessions/:id/transcripts/:tid', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM live_transcripts WHERE id = $1 AND session_id = $2 AND user_id = $3',
      [req.params.tid, req.params.id, req.userId]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Generate AI report for a single transcript
app.post('/api/sessions/:id/transcripts/:tid/report', authMiddleware, async (req, res) => {
  try {
    const t = await pool.query(
      'SELECT * FROM live_transcripts WHERE id = $1 AND session_id = $2 AND user_id = $3',
      [req.params.tid, req.params.id, req.userId]
    );
    if (!t.rows.length) return res.status(404).json({ error: 'Transcript not found' });
    const tx = t.rows[0];
    const lines = typeof tx.transcript === 'string' ? JSON.parse(tx.transcript) : (tx.transcript || []);
    if (lines.length < 3) return res.status(400).json({ error: 'Transcript too short for a report' });

    // Get session context
    const s = await pool.query('SELECT company, role, jd FROM sessions WHERE id = $1', [req.params.id]);
    const session = s.rows[0] || {};
    const ctxLine = (session.company || session.role) ? `Interview for ${session.role || 'a role'} at ${session.company || 'a company'}.\n` : '';

    // Get prior call reports for context
    const priorReports = await pool.query(
      'SELECT report, started_at FROM live_transcripts WHERE session_id = $1 AND user_id = $2 AND id != $3 AND report IS NOT NULL ORDER BY started_at ASC',
      [req.params.id, req.userId, req.params.tid]
    );
    let priorContext = '';
    if (priorReports.rows.length) {
      priorContext = '\n\nPRIOR CALL REPORTS (same session):\n';
      priorReports.rows.forEach((r, i) => {
        const rep = typeof r.report === 'string' ? JSON.parse(r.report) : r.report;
        priorContext += `--- Call ${i + 1} (${new Date(r.started_at).toLocaleDateString()}) ---\n`;
        priorContext += `Summary: ${rep.summary || 'N/A'}\n`;
        if (rep.actionItems) priorContext += `Action Items: ${rep.actionItems.join('; ')}\n`;
        if (rep.keyTopics) priorContext += `Topics: ${rep.keyTopics.join(', ')}\n`;
        priorContext += '\n';
      });
    }

    // Format transcript for AI
    const txText = lines.map(l => {
      const time = l.ts ? new Date(l.ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : '';
      return `[${time}] ${l.text}`;
    }).join('\n');

    const duration = tx.ended_at ? Math.round((new Date(tx.ended_at) - new Date(tx.started_at)) / 60000) : 0;

    const reportResult = await callClaude(
      `You analyze interview call transcripts and generate structured reports. Output ONLY valid JSON — no markdown, no explanation, no code fences.

JSON structure:
{
  "summary": "2-3 sentence overview of what happened in the call",
  "duration": "${duration} minutes",
  "questionsAsked": ["list of interview questions that were asked"],
  "keyTopics": ["main topics or skills discussed"],
  "candidateStrengths": ["things the candidate explained well or handled strongly"],
  "areasToImprove": ["topics where candidate struggled, gave weak answers, or could improve"],
  "actionItems": ["specific things the candidate should do before next call"],
  "interviewerSignals": ["positive or negative signals from the interviewer — enthusiasm, follow-ups, concerns expressed"],
  "nextCallPrep": ["specific suggestions for what to prepare for the next round based on this call"]
}

Be specific — reference actual topics, tools, and moments from the transcript. No generic advice.`,
      ctxLine + 'TRANSCRIPT (' + duration + ' min, ' + lines.length + ' lines):\n' + txText.substring(0, 12000) + priorContext,
      2000, MODEL_HAIKU
    );

    let report;
    try {
      const jsonMatch = reportResult.match(/\{[\s\S]*\}/);
      report = jsonMatch ? JSON.parse(jsonMatch[0]) : { summary: reportResult, error: 'Could not parse structured report' };
    } catch (e) {
      report = { summary: reportResult.substring(0, 500), error: 'Parse failed' };
    }

    // Save report to DB
    await pool.query('UPDATE live_transcripts SET report = $1 WHERE id = $2', [JSON.stringify(report), req.params.tid]);

    res.json({ report });
  } catch (e) { console.error('Report generation error:', e); res.status(500).json({ error: e.message }); }
});

// Cross-call insights: uses all prior reports to generate next-call prep
app.get('/api/sessions/:id/transcript-insights', authMiddleware, async (req, res) => {
  try {
    const reports = await pool.query(
      'SELECT report, started_at, ended_at FROM live_transcripts WHERE session_id = $1 AND user_id = $2 AND report IS NOT NULL ORDER BY started_at ASC',
      [req.params.id, req.userId]
    );
    if (!reports.rows.length) return res.json({ insights: null, message: 'No call reports yet. Generate a report for at least one transcript first.' });

    const s = await pool.query('SELECT company, role, jd, resume FROM sessions WHERE id = $1', [req.params.id]);
    const session = s.rows[0] || {};

    // Build summary of all calls
    let callSummaries = '';
    reports.rows.forEach((r, i) => {
      const rep = typeof r.report === 'string' ? JSON.parse(r.report) : r.report;
      const dur = r.ended_at ? Math.round((new Date(r.ended_at) - new Date(r.started_at)) / 60000) : 0;
      callSummaries += `\n=== CALL ${i + 1} (${new Date(r.started_at).toLocaleDateString()}, ${dur} min) ===\n`;
      callSummaries += `Summary: ${rep.summary || 'N/A'}\n`;
      if (rep.questionsAsked) callSummaries += `Questions Asked: ${rep.questionsAsked.join('; ')}\n`;
      if (rep.keyTopics) callSummaries += `Topics Covered: ${rep.keyTopics.join(', ')}\n`;
      if (rep.candidateStrengths) callSummaries += `Strengths: ${rep.candidateStrengths.join('; ')}\n`;
      if (rep.areasToImprove) callSummaries += `Improve: ${rep.areasToImprove.join('; ')}\n`;
      if (rep.actionItems) callSummaries += `Action Items: ${rep.actionItems.join('; ')}\n`;
      if (rep.interviewerSignals) callSummaries += `Interviewer Signals: ${rep.interviewerSignals.join('; ')}\n`;
      if (rep.nextCallPrep) callSummaries += `Next Call Prep: ${rep.nextCallPrep.join('; ')}\n`;
    });

    const insights = await callClaude(
      `You are an expert interview coach analyzing a candidate's progress across multiple interview calls for the same position. Based on all the call reports below, generate strategic insights for the next call.

Output ONLY valid JSON:
{
  "overallProgress": "1-2 sentences on how the interview process is going overall",
  "topicsAlreadyCovered": ["topics/skills that have been discussed — don't repeat these unless asked"],
  "likelyNextTopics": ["topics the interviewer will probably ask about next, based on JD gaps and interview flow"],
  "unaskedJDRequirements": ["JD requirements or skills NOT yet discussed — high priority to prepare"],
  "strengthsToReinforce": ["things going well — lean into these"],
  "weaknessesToAddress": ["areas where candidate needs better answers ready"],
  "specificPrepTasks": ["concrete actions: 'Prepare a STAR story about X', 'Review Y concept', etc."],
  "interviewerReadout": "What the interviewer is likely thinking/looking for based on their signals across calls",
  "riskFactors": ["things that could hurt the candidacy if not addressed"]
}

Be specific. Reference actual topics, tools, and moments from the reports. No generic advice.`,
      `Role: ${session.role || 'Unknown'} at ${session.company || 'Unknown'}\n\nJD (key requirements):\n${(session.jd || '').substring(0, 3000)}\n\nCALL HISTORY (${reports.rows.length} calls):\n${callSummaries}`,
      2000, MODEL_HAIKU
    );

    let parsed;
    try {
      const jsonMatch = insights.match(/\{[\s\S]*\}/);
      parsed = jsonMatch ? JSON.parse(jsonMatch[0]) : { overallProgress: insights };
    } catch (e) {
      parsed = { overallProgress: insights.substring(0, 500), error: 'Parse failed' };
    }

    res.json({ insights: parsed, callCount: reports.rows.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ SCREEN ASSIST — Vision-based screen analysis ============
const SCREEN_ASSIST_PROMPT = `You are a real-time interview assistant analyzing the candidate's screen during a live interview.
The candidate is sharing or viewing a screen that contains interview content — it could be:
- A coding question or challenge
- Multiple choice questions
- A technical diagram or architecture question
- A text-based question or assessment
- A shared document with questions
- Data tables, schemas, or datasets that will be referenced later

Your job: identify what is being asked and provide a clear, helpful answer.

IMPORTANT — SESSION MEMORY:
You may receive "PREVIOUS SCREEN CAPTURES" in the prompt. These are summaries of what you analyzed in earlier screenshots from this same interview session.
If the current screen references data, tables, schemas, or code from earlier captures, USE that context to build a complete answer.
Example: if capture 1 showed a users table, capture 2 showed an orders table, and now the screen asks "write a query joining these" — reference the table structures from prior captures.

RULES:
- Identify EVERY question or task visible on screen
- For coding: write clean, working code with brief explanation
- For multiple choice: state the correct answer and why
- For data/tables: describe the structure clearly (columns, types, sample data) so future captures can reference it
- For open-ended: answer concisely using the candidate's real experience from their resume and Q&A bank
- Every sentence on its own line
- Lead with the answer — no preamble
- If multiple questions are visible, answer each one separated by a blank line with the question number
- Natural voice, no buzzwords
- Use the candidate's actual experience from the Q&A bank when relevant`;

// Screen Assist memory — rolling buffer of previous analyses per session
// So the AI remembers what it saw on earlier captures (tables, code, diagrams)
const screenAssistMemory = new Map(); // sessionId → [{ ts, summary }]
const SCREEN_MEMORY_MAX = 8; // Keep last 8 captures
const SCREEN_MEMORY_TTL = 30 * 60 * 1000; // Expire after 30 min

function getScreenMemory(sessionId) {
  const mem = screenAssistMemory.get(sessionId) || [];
  const now = Date.now();
  // Prune expired entries
  const fresh = mem.filter(m => now - m.ts < SCREEN_MEMORY_TTL);
  if (fresh.length !== mem.length) screenAssistMemory.set(sessionId, fresh);
  return fresh;
}

function addScreenMemory(sessionId, summary) {
  let mem = screenAssistMemory.get(sessionId) || [];
  mem.push({ ts: Date.now(), summary });
  if (mem.length > SCREEN_MEMORY_MAX) mem = mem.slice(-SCREEN_MEMORY_MAX);
  screenAssistMemory.set(sessionId, mem);
}

app.post('/api/sessions/:id/screen-assist', authMiddleware, async (req, res) => {
  try {
    const { image } = req.body;
    if (!image) return res.status(400).json({ error: 'No image provided' });

    const sessionId = req.params.id;
    const s = await pool.query('SELECT resume, jd, company, role FROM sessions WHERE id = $1 AND user_id = $2', [sessionId, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Session not found' });

    const session = s.rows[0];
    const company = session.company || 'the company';
    const role = session.role || 'this role';

    // Get Q&A bank for context
    const qResult = await pool.query('SELECT text, answer FROM questions WHERE session_id = $1 AND answer IS NOT NULL AND answer != \'\'', [sessionId]);
    const bankContext = qResult.rows.slice(0, 10).map(q => 'Q: ' + q.text + '\nA: ' + q.answer).join('\n\n');

    // Strip data URL prefix if present, detect media type
    const mediaMatch = image.match(/^data:image\/([\w+]+);base64,/);
    const mediaType = mediaMatch ? 'image/' + mediaMatch[1] : 'image/jpeg';
    const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
    console.log('[Screen Assist] Image size:', (base64Data.length / 1024).toFixed(0) + 'KB, type:', mediaType);

    // Build context from previous screen captures (memory)
    const priorCaptures = getScreenMemory(sessionId);
    let memoryContext = '';
    if (priorCaptures.length > 0) {
      memoryContext = '\n\nPREVIOUS SCREEN CAPTURES (what you saw earlier in this session):\n' +
        priorCaptures.map((m, i) => 'Capture ' + (i + 1) + ':\n' + m.summary).join('\n\n') +
        '\n\nUse the above context if the current screen references data, tables, code, or content from earlier captures.\n';
    }

    const textPrompt = 'INTERVIEW FOR: ' + role + ' at ' + company +
      '\n\nRESUME:\n' + (session.resume || 'N/A') +
      '\n\nQ&A BANK:\n' + bankContext +
      memoryContext +
      '\n\nAnalyze this screen. What is being asked? Provide clear answers for everything visible.';

    const answer = await callClaudeVision(SCREEN_ASSIST_PROMPT, base64Data, textPrompt, 2000, MODEL_HAIKU, mediaType);

    // Save a summary of what was seen + answered for future captures to reference
    // Truncate to keep memory lean
    const memorySummary = answer.substring(0, 600);
    addScreenMemory(sessionId, memorySummary);
    console.log('[Screen Assist] Memory now has', getScreenMemory(sessionId).length, 'captures for session', sessionId);

    // Save as a question in DB
    const newQ = await pool.query(
      'INSERT INTO questions (session_id, text, type, answer, source) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [sessionId, '[Screen Assist] Visual question from shared screen', 'Technical', answer, 'live']
    );
    const qId = newQ.rows[0].id;

    // Broadcast to all WS clients for this session
    const assistMsg = {
      type: 'screen_assist',
      questionId: qId,
      questionText: 'Screen Assist',
      answer: answer,
      generated: true
    };
    broadcastToSession(sessionId, assistMsg);

    res.json({ questionId: qId, questionText: 'Screen Assist', answer: answer });
  } catch (e) {
    console.error('[Screen Assist Error]', e.message, e.stack);
    res.status(500).json({ error: 'Screen analysis failed: ' + e.message });
  }
});

// Standalone Smart Canvas page
app.get('/canvas', (req, res) => res.sendFile(path.join(__dirname, 'public', 'canvas.html')));

// Serve frontend (MUST be last — catch-all for SPA routing)
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ============ HTTP + WEBSOCKET SERVER ============
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Session-level client tracking — broadcast to all clients (main app + canvas windows) for same session
const sessionClients = new Map(); // sessionId -> Set of ws connections

function broadcastToSession(sessionId, data, excludeWs) {
  const clients = sessionClients.get(sessionId);
  if (!clients) return;
  const msg = typeof data === 'string' ? data : JSON.stringify(data);
  clients.forEach(client => {
    if (client !== excludeWs && client.readyState === WebSocket.OPEN) {
      try { client.send(msg); } catch(e) {}
    }
  });
}

function addSessionClient(sessionId, ws) {
  if (!sessionClients.has(sessionId)) sessionClients.set(sessionId, new Set());
  sessionClients.get(sessionId).add(ws);
}

function removeSessionClient(sessionId, ws) {
  const clients = sessionClients.get(sessionId);
  if (clients) {
    clients.delete(ws);
    if (clients.size === 0) sessionClients.delete(sessionId);
  }
}

// ============ LIVE AUDIO - DEEPGRAM + MATCHING ============
const DEEPGRAM_API_KEY = process.env.DEEPGRAM_API_KEY;
const MATCH_THRESHOLD = 0.45; // Raised from 0.30 — prevents weak keyword overlaps (e.g. EDA matching "data, info, insights")

// Strip interviewer preambles from question text: "The next question is, explain X" → "explain X"
function cleanQuestionText(text) {
  return text.replace(/^(the next question is[,:]?\s*|okay so[,:]?\s*|alright[,:]?\s*|so[,:]?\s*|now[,:]?\s*|let's move on[,:]?\s*|moving on[,:]?\s*|next[,:]?\s*|next up[,:]?\s*|let me ask you[,:]?\s*|i('d| would) like to ask[,:]?\s*|here's (a|another) question[,:]?\s*)/i, '').trim();
}

function isQuestion(text) {
  const t = text.trim().toLowerCase();
  const words = t.split(/\s+/).length;
  // Minimum: 3 words, 15 chars
  if (words < 3 || t.length < 15) return false;
  // === REJECTION FILTERS ===
  // Reject self-referencing (interviewee talking about themselves)
  if (/^(i |i'm |i've |i was |i did |i think |i would |i used |i built |i have |so i |yeah i |and i |we |we're |we've |my |at my |in my |let me |if i |when i |that's |that is |it's |it is |this is |there |the |a |an |at |for |from |like |actually |basically |just )/.test(t)) return false;
  // Reject filler/agreement/casual speech
  if (/^(yeah|yes|no|okay|sure|right|exactly|absolutely|definitely|great|good|thanks|thank you|sorry|so basically|um |uh |well |hmm|oh |and |but |or |also |then |so )/.test(t)) return false;
  // Reject casual small-talk / pleasantries
  if (/^(how are you|how's it going|how have you been|nice to meet|good to meet|good morning|good afternoon|good evening|hey |hi |hello |what time|what's your time|where are you (based|located|calling|joining)|are you (doing well|ready)|can you hear me|is (my|the) (audio|video|screen)|one (moment|second|sec)|bear with me|sorry about|apologies for)/.test(t)) return false;
  // Reject scheduling/logistics
  if (/^(do you have any questions|any questions (for|from) (me|us)|that's (all|it|everything)|we('re| are) (running|almost)|let's (wrap|move|end)|before we (end|wrap|go))/.test(t)) return false;
  // === PASS FILTERS — must match a specific question pattern ===
  // Question mark with at least 5 words — real questions
  if (/\?/.test(t) && words >= 5) return true;
  // Direct interview commands with subject: "Explain X", "Define X" etc. (need 3+ words)
  if (words >= 3 && /^(explain |define |describe |compare |walk me through |tell me about |give me an example )/.test(t)) return true;
  // Interview question openers with enough substance (8+ words)
  if (words >= 8 && /^(what is your |what are your |what was your |what were your |what do you |what did you |what would you |how do you |how would you |how did you |how can you |why do you |why did you |why are you |why is |can you (explain|describe|walk|tell)|could you (explain|describe|walk|tell))/.test(t)) return true;
  // Nothing matched — NOT a question
  return false;
}

function classifyQuestion(text) {
  const t = text.toLowerCase();
  if (/(tell me about yourself|background|experience|walk me through your)/.test(t)) return 'Background';
  if (/(situation|time when|example of|describe a|have you ever)/.test(t)) return 'Behavioral';
  if (/(technical|code|system|design|architect|algorithm|data)/.test(t)) return 'Technical';
  if (/(why this|why do you want|what interests|what excites|where do you see)/.test(t)) return 'Motivation';
  if (/(strength|weakness|improve|challenge|difficult)/.test(t)) return 'Self-Awareness';
  if (/(team|collaborate|conflict|disagree|leadership|manage)/.test(t)) return 'Teamwork';
  return 'Strategic';
}

// Stop words to strip for keyword matching
const STOP_WORDS = new Set('i me my we our you your he she it its they them their a an the and but or so if in on at to for of is am are was were be been being have has had do does did will would shall should can could may might must not no nor about tell say would'.split(' '));

// Synonym clusters — maps STEMMED words to concept IDs for semantic matching
// All entries must be actual Porter Stemmer outputs (verified with stemmer.stem())
// Words can belong to multiple clusters (e.g. 'difficult' → conflict + problem-solving)
const SYNONYM_MAP = {}; // word → [SYN0, SYN3, ...] array
const SYNONYM_CLUSTERS = [
  ['strength', 'strong', 'best', 'good', 'biggest', 'greatest', 'excel', 'skill'],                                    // SYN0: strengths
  ['weak', 'improv', 'shortcom', 'limit'],                                                                              // SYN1: weaknesses
  ['fail', 'failur', 'mistak', 'wrong', 'learn', 'setback', 'error', 'regret'],                                        // SYN2: failure
  ['conflict', 'disagre', 'argument', 'tension', 'clash', 'difficult'],                                                // SYN3: conflict
  ['team', 'collabor', 'togeth', 'group', 'colleagu', 'cowork', 'peer', 'teammat'],                                    // SYN4: teamwork
  ['salari', 'compens', 'pai', 'money', 'expect', 'remuner', 'wage', 'offer', 'paid'],                                 // SYN5: salary
  ['futur', 'year', 'career', 'grow', 'goal', 'aspir', 'see', 'vision', 'plan', 'long', 'term'],                       // SYN6: future/career
  ['interest', 'want', 'motiv', 'excit', 'passion', 'reason', 'drive', 'appli', 'join', 'work', 'here', 'posit', 'job', 'compani', 'why'],  // SYN7: motivation
  ['background', 'yourself', 'experi', 'histori', 'journey', 'bio', 'introduc', 'walk', 'through'],                     // SYN8: background
  ['problem', 'challeng', 'solv', 'overcom', 'hard', 'obstacl', 'tackl', 'difficult'],                                  // SYN9: problem-solving
];
SYNONYM_CLUSTERS.forEach((cluster, idx) => {
  cluster.forEach(word => {
    if (!SYNONYM_MAP[word]) SYNONYM_MAP[word] = [];
    SYNONYM_MAP[word].push('SYN' + idx);
  });
});

function extractKeywords(text) {
  return text.toLowerCase().replace(/[^a-z0-9\s]/g, '').split(/\s+/)
    .filter(w => w.length > 2 && !STOP_WORDS.has(w))
    .map(w => stemmer.stem(w));
}

// Get synonym concept IDs for a set of keywords (words can map to multiple concepts)
function getConceptIds(keywords) {
  const concepts = new Set();
  keywords.forEach(k => {
    if (SYNONYM_MAP[k]) SYNONYM_MAP[k].forEach(syn => concepts.add(syn));
  });
  return concepts;
}

// Build TF-IDF index for session questions — call once when live starts
function buildQuestionIndex(sessionQuestions) {
  const tfidf = new TfIdf();
  sessionQuestions.forEach(q => tfidf.addDocument(q.text.toLowerCase()));
  const keywordSets = sessionQuestions.map(q => {
    const kws = extractKeywords(q.text);
    return { keywords: new Set(kws), concepts: getConceptIds(kws) };
  });
  return { tfidf, keywordSets };
}

// Smart multi-strategy match — 4 strategies: keywords, concepts, TF-IDF, fuzzy
function findBestMatch(questionText, sessionQuestions, questionIndex) {
  if (!sessionQuestions.length) return null;
  const inputLower = questionText.toLowerCase();
  const inputKeywords = extractKeywords(questionText);
  const inputKeywordSet = new Set(inputKeywords);
  const inputConcepts = getConceptIds(inputKeywords);

  let bestScore = 0;
  let bestIdx = -1;

  // Pre-compute TF-IDF scores once
  let tfidfScores = null;
  let maxTfidf = 1;
  if (questionIndex && questionIndex.tfidf) {
    tfidfScores = [];
    questionIndex.tfidf.tfidfs(inputLower, function(j, measure) { tfidfScores.push(measure); });
    maxTfidf = Math.max(...tfidfScores, 0.001);
  }

  for (let i = 0; i < sessionQuestions.length; i++) {
    let score = 0;
    let keywordScore = 0;
    let conceptScore = 0;

    if (questionIndex && questionIndex.keywordSets[i]) {
      const qData = questionIndex.keywordSets[i];

      // Strategy 1: Stemmed keyword overlap (Jaccard) — weighted 0.30
      const kIntersection = inputKeywords.filter(k => qData.keywords.has(k)).length;
      const kUnion = new Set([...inputKeywordSet, ...qData.keywords]).size;
      keywordScore = kUnion > 0 ? kIntersection / kUnion : 0;
      score += keywordScore * 0.30;

      // Strategy 2: Concept overlap — weighted 0.30 (high impact for semantic matches)
      if (inputConcepts.size > 0 && qData.concepts.size > 0) {
        const cIntersection = [...inputConcepts].filter(c => qData.concepts.has(c)).length;
        const cUnion = new Set([...inputConcepts, ...qData.concepts]).size;
        conceptScore = cUnion > 0 ? cIntersection / cUnion : 0;
        score += conceptScore * 0.30;
      }
    }

    // Strategy 3: TF-IDF relevance — weighted 0.15 (reduced: noisy with small question banks)
    if (tfidfScores) {
      score += ((tfidfScores[i] || 0) / maxTfidf) * 0.15;
    }

    // Strategy 4: Fuzzy string similarity (Dice coefficient) — weighted 0.25
    score += stringSimilarity.compareTwoStrings(inputLower, sessionQuestions[i].text.toLowerCase()) * 0.25;

    if (score > bestScore) {
      bestScore = score;
      bestIdx = i;
    }
  }

  if (bestIdx >= 0 && bestScore >= MATCH_THRESHOLD) {
    return { question: sessionQuestions[bestIdx], similarity: bestScore };
  }
  return null;
}

// Return top N matches above threshold — used by AI verification layer
function findTopMatches(questionText, sessionQuestions, questionIndex, topN = 3) {
  if (!sessionQuestions.length) return [];
  const inputLower = questionText.toLowerCase();
  const inputKeywords = extractKeywords(questionText);
  const inputKeywordSet = new Set(inputKeywords);
  const inputConcepts = getConceptIds(inputKeywords);

  let tfidfScores = null;
  let maxTfidf = 1;
  if (questionIndex && questionIndex.tfidf) {
    tfidfScores = [];
    questionIndex.tfidf.tfidfs(inputLower, function(j, measure) { tfidfScores.push(measure); });
    maxTfidf = Math.max(...tfidfScores, 0.001);
  }

  const scored = [];
  for (let i = 0; i < sessionQuestions.length; i++) {
    let score = 0;
    if (questionIndex && questionIndex.keywordSets[i]) {
      const qData = questionIndex.keywordSets[i];
      const kIntersection = inputKeywords.filter(k => qData.keywords.has(k)).length;
      const kUnion = new Set([...inputKeywordSet, ...qData.keywords]).size;
      score += (kUnion > 0 ? kIntersection / kUnion : 0) * 0.30;
      if (inputConcepts.size > 0 && qData.concepts.size > 0) {
        const cIntersection = [...inputConcepts].filter(c => qData.concepts.has(c)).length;
        const cUnion = new Set([...inputConcepts, ...qData.concepts]).size;
        score += (cUnion > 0 ? cIntersection / cUnion : 0) * 0.30;
      }
    }
    if (tfidfScores) score += ((tfidfScores[i] || 0) / maxTfidf) * 0.15;
    score += stringSimilarity.compareTwoStrings(inputLower, sessionQuestions[i].text.toLowerCase()) * 0.25;
    if (score >= MATCH_THRESHOLD) {
      scored.push({ question: sessionQuestions[i], similarity: score });
    }
  }
  scored.sort((a, b) => b.similarity - a.similarity);
  return scored.slice(0, topN);
}

// AI verification — send top candidates to Haiku for semantic confirmation
async function verifyMatch(utterance, candidates, sessionContext, timeoutMs = 2500) {
  if (!candidates || candidates.length === 0) return null;

  const candidateList = candidates.map((c, i) =>
    `${i + 1}. "${c.question.text}"`
  ).join('\n');

  const ctx = sessionContext || {};
  const ctxLine = (ctx.company || ctx.role) ? `This is an interview for ${ctx.role || 'a role'} at ${ctx.company || 'a company'}. ` : '';

  const system = ctxLine + 'You verify whether an interview question matches a candidate from a question bank. A match means the interviewer is asking THE SAME question — not just a related topic. "What is data governance?" does NOT match "What are ETL processes?" even though both are data topics. Be strict: if the core subject differs, reply NONE. Reply ONLY "MATCH:N" (N = candidate number) or "NONE". Nothing else.';
  const user = `Interviewer asked: "${utterance}"\n\nCandidates:\n${candidateList}\n\nIs any candidate asking the SAME question (not just related topic)? Reply MATCH:N or NONE.`;

  try {
    const result = await Promise.race([
      callClaude(system, user, 10, MODEL_HAIKU),
      new Promise((_, reject) => setTimeout(() => reject(new Error('verify_timeout')), timeoutMs))
    ]);

    const cleaned = result.trim().toUpperCase();
    const m = cleaned.match(/MATCH:(\d+)/);
    if (m) {
      const idx = parseInt(m[1]) - 1;
      if (idx >= 0 && idx < candidates.length) {
        console.log(`[VerifyMatch] Haiku confirmed MATCH:${idx + 1} — "${candidates[idx].question.text.substring(0, 50)}"`);
        return candidates[idx];
      }
    }
    console.log('[VerifyMatch] Haiku said NONE — no semantic match');
    return null;
  } catch (e) {
    if (e.message === 'verify_timeout') {
      console.log('[VerifyMatch] Timeout (>1.5s) — rejecting match, will create new question');
      return null; // Don't trust keyword match without AI verification
    }
    console.error('[VerifyMatch] Error:', e.message, '— rejecting match, will create new question');
    return null; // Don't trust keyword match without AI verification
  }
}

// Match + verify + respond — async with Haiku AI verification
async function fastMatchAndRespond(utterance, sessionQuestions, sessionId, userId, ws, lastMatchedQId, recentMatchedIds, questionIndex, onIndexRebuild) {
  const startMs = Date.now();
  const q = cleanQuestionText(utterance.trim());
  if (!q || q.length < 10) return lastMatchedQId;
  if (!isQuestion(q)) return lastMatchedQId;

  // Get top 3 keyword candidates, excluding already-matched questions
  const topMatches = findTopMatches(q, sessionQuestions, questionIndex, 3)
    .filter(m => m.question.id !== lastMatchedQId && !recentMatchedIds?.has?.(m.question.id));

  if (topMatches.length > 0) {
    // AI verification — Haiku checks if any candidate is semantically the same question
    const verified = await verifyMatch(q, topMatches, ws._sessionContext);

    if (verified) {
      const elapsed = Date.now() - startMs;
      console.log(`[FastMatch+AI] VERIFIED in ${elapsed}ms: "${q.substring(0,40)}..." → "${verified.question.text.substring(0,40)}..." (${Math.round(verified.similarity*100)}%)`);

      const matchMsg = {
        type: 'match',
        questionId: verified.question.id,
        questionText: verified.question.text,
        answer: verified.question.answer || '',
        similarity: Math.round(verified.similarity * 100),
        hasAnswer: !!verified.question.answer
      };
      ws.send(JSON.stringify(matchMsg));
      broadcastToSession(sessionId, matchMsg, ws);
      recentMatchedIds.add(verified.question.id);
      return verified.question.id;
    }
    // Haiku said NONE — keyword matches were false positives, create new question
    console.log(`[FastMatch+AI] Haiku rejected all ${topMatches.length} candidates — creating new question`);
  }

  // No matches above threshold, or Haiku rejected all — create new question + generate answer
  const elapsed = Date.now() - startMs;
  console.log(`[FastMatch] NO MATCH in ${elapsed}ms: "${q.substring(0,50)}..." — creating new question`);

  try {
    const newQ = await pool.query(
      'INSERT INTO questions (session_id, text, type, answer, source) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [sessionId, q, classifyQuestion(q), '', 'live']
    );
    const qId = newQ.rows[0].id;

    const newQMsg = {
      type: 'new_question',
      questionId: qId,
      questionText: q,
      questionType: classifyQuestion(q),
      source: 'live',
      generated: true  // Flag for frontend: this is an AI-generated answer, not from bank
    };
    ws.send(JSON.stringify(newQMsg));
    broadcastToSession(sessionId, newQMsg, ws);

    sessionQuestions.push({ id: qId, text: q, type: classifyQuestion(q), answer: '' });
    if (onIndexRebuild) onIndexRebuild();

    // Fire answer generation in background
    generateLiveAnswer(q, sessionId, userId, ws, qId).then(() => {
      pool.query('SELECT id, text, type, answer FROM questions WHERE session_id = $1', [sessionId])
        .then(qResult => {
          sessionQuestions.length = 0;
          sessionQuestions.push(...qResult.rows);
          if (onIndexRebuild) onIndexRebuild();
        });
    }).catch(e => console.error('[Async answer error]', e.message));
  } catch (e) {
    console.error('[Create question error]', e.message);
  }

  return lastMatchedQId;
}

function openDeepgramStream(onTranscript, onError) {
  if (!DEEPGRAM_API_KEY) { onError(new Error('DEEPGRAM_API_KEY not set')); return null; }
  const params = 'model=nova-3&punctuate=true&interim_results=true&utterance_end_ms=1500&vad_events=true&encoding=linear16&sample_rate=16000&channels=1';
  const dgWs = new WebSocket('wss://api.deepgram.com/v1/listen?' + params, {
    headers: { 'Authorization': 'Token ' + DEEPGRAM_API_KEY }
  });
  dgWs.on('open', () => console.log('[Deepgram] Stream connected'));
  dgWs.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      if (msg.type === 'Results' && msg.channel?.alternatives?.[0]) {
        const text = msg.channel.alternatives[0].transcript || '';
        if (text.trim()) onTranscript(text, msg.is_final, msg.speech_final);
      }
    } catch (e) { /* ignore parse errors */ }
  });
  dgWs.on('error', onError);
  dgWs.on('close', () => console.log('[Deepgram] Stream closed'));
  return dgWs;
}

wss.on('connection', (ws) => {
  console.log('[WS] New client connected');
  let sessionId = null;
  let userId = null;
  let isCanvasMode = false; // canvas clients are passive listeners — no Deepgram
  let sessionQuestions = [];
  let interviewerDG = null;
  let userDG = null;
  let transcript = [];
  let transcriptId = null;
  let interviewerBuffer = ''; // accumulate partial transcripts
  let lastMatchedQId = null;
  let lastWsayMatchId = null; // track last "What should I say?" result — exclude on re-click
  let recentMatchedIds = new Set(); // prevent duplicate matches within short window
  let questionIndex = null; // TF-IDF + keyword index for smart matching
  let idleTimer = null;
  const IDLE_TIMEOUT = 5 * 60 * 1000; // 5 minutes
  function resetIdleTimer() {
    if (isCanvasMode) return; // canvas clients don't have idle timeout
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      console.log('[WS] Idle timeout — closing connection');
      ws.send(JSON.stringify({ type: 'status', message: 'Live mode ended — idle timeout (5 min no data)' }));
      ws.close();
    }, IDLE_TIMEOUT);
  }
  let sentenceCountSinceReset = 0; // track sentences in current utterance

  // Helper: send to this client AND broadcast to all canvas listeners for same session
  function sendAndBroadcast(data) {
    const msg = typeof data === 'string' ? data : JSON.stringify(data);
    try { ws.send(msg); } catch(e) {}
    if (sessionId) broadcastToSession(sessionId, msg, ws);
  }

  ws.on('message', async (rawData) => {
    // Binary audio data: first byte = channel (1=interviewer, 2=user)
    if (rawData instanceof Buffer && rawData.length > 1 && rawData[0] !== 0x7b) {
      const channel = rawData[0];
      const audio = rawData.slice(1);
      if (channel === 1 && interviewerDG && interviewerDG.readyState === WebSocket.OPEN) {
        interviewerDG.send(audio);
      } else if (channel === 2 && userDG && userDG.readyState === WebSocket.OPEN) {
        userDG.send(audio);
      }
      return;
    }

    // JSON messages
    try {
      const msg = JSON.parse(rawData.toString());

      if (msg.type === 'start') {
        isCanvasMode = msg.mode === 'canvas';
        console.log('[WS] Start request received for session:', msg.sessionId, isCanvasMode ? '(CANVAS MODE)' : '');
        // Authenticate
        try {
          const decoded = jwt.verify(msg.token, JWT_SECRET);
          userId = decoded.userId;
          sessionId = msg.sessionId;
          console.log('[WS] Authenticated user:', userId);
        } catch (e) {
          console.error('[WS] Auth failed:', e.message);
          ws.send(JSON.stringify({ type: 'error', message: 'Authentication failed' }));
          return;
        }

        // Register this client for session broadcasting
        addSessionClient(sessionId, ws);

        // Canvas mode: passive listener only — receives broadcasts from main connection
        if (isCanvasMode) {
          // Load questions so canvas can handle what_should_i_say and canvas_question
          const [qResult, sResult] = await Promise.all([
            pool.query('SELECT id, text, type, answer FROM questions WHERE session_id = $1', [sessionId]),
            pool.query('SELECT resume, jd, company, role FROM sessions WHERE id = $1', [sessionId])
          ]);
          sessionQuestions = qResult.rows;
          questionIndex = buildQuestionIndex(sessionQuestions);
          ws._sessionContext = sResult.rows[0] || {};
          ws._sessionQuestions = sessionQuestions;
          ws._isCanvas = true; // Mark as canvas client for forwarding logic
          ws.send(JSON.stringify({ type: 'status', message: 'Canvas connected — waiting for live data' }));
          console.log(`[Canvas] Connected to session ${sessionId} with ${sessionQuestions.length} questions`);
          return; // Skip Deepgram, transcript, etc
        }

        // === FULL LIVE MODE (main app) ===

        // Load session questions + session context (cached for fast answer generation)
        const [qResult, sResult] = await Promise.all([
          pool.query('SELECT id, text, type, answer FROM questions WHERE session_id = $1', [sessionId]),
          pool.query('SELECT resume, jd, company, role FROM sessions WHERE id = $1', [sessionId])
        ]);
        sessionQuestions = qResult.rows;
        questionIndex = buildQuestionIndex(sessionQuestions);
        console.log(`[TF-IDF] Built index for ${sessionQuestions.length} questions`);

        // Cache session context + questions on WS for fast answer generation (no DB lookup needed)
        ws._sessionContext = sResult.rows[0] || {};
        ws._sessionQuestions = sessionQuestions;

        // Create transcript record — attach current meeting's interviewer info
        let interviewerName = '', interviewerTitle = '', interviewStage = '';
        try {
          const cm = await pool.query('SELECT name, title, stage FROM meetings WHERE session_id = $1 AND is_current = true LIMIT 1', [sessionId]);
          if (cm.rows.length) { interviewerName = cm.rows[0].name || ''; interviewerTitle = cm.rows[0].title || ''; interviewStage = cm.rows[0].stage || ''; }
        } catch(e) {}
        const tResult = await pool.query(
          'INSERT INTO live_transcripts (session_id, user_id, interviewer_name, interviewer_title, stage) VALUES ($1, $2, $3, $4, $5) RETURNING id',
          [sessionId, userId, interviewerName, interviewerTitle, interviewStage]
        );
        transcriptId = tResult.rows[0].id;
        transcript = [];
        lastMatchedQId = null;
        let lastAutoMatchTime = 0; // Timestamp of last auto-detected match
        const AUTO_MATCH_COOLDOWN = 15000; // 15s cooldown on auto-detect; manual "What should I say?" bypasses this

        // Single Deepgram stream — two detection layers:
        // 1. Fast: isQuestion() pattern match fires instantly on obvious questions
        // 2. Smart: On every speechFinal, Haiku extracts the question from recent transcript
        //    (same logic as "What should I say?" but automatic)
        let questionFiredForBuffer = false;
        let lastAiExtractedQ = ''; // prevent re-firing same extracted question
        let recentDetectedQs = []; // last 5 detected questions for fuzzy de-dup

        // AI auto-extract: send recent transcript to Haiku, get the question
        async function aiAutoExtract() {
          if (Date.now() - lastAutoMatchTime < AUTO_MATCH_COOLDOWN) return;
          const recent = transcript.slice(-4);
          if (recent.length < 1) return;

          const recentText = recent.slice(-2).map(t => t.text).join('\n');
          const wsCtx = ws._sessionContext || {};
          const ctxLine = (wsCtx.company || wsCtx.role) ? `Interview for ${wsCtx.role || 'a role'} at ${wsCtx.company || 'a company'}.\n` : '';

          try {
            const extracted = await Promise.race([
              callClaude(
                'You detect interview questions in conversation speech. Given recent transcript lines, determine if the speaker is asking the candidate an interview question. If YES, output ONLY the question text — nothing else, no quotes, no explanation. If NO question is being asked (statements, answers, small talk, filler, incomplete speech, or the candidate talking), output exactly one word: NONE. Never explain your reasoning. Never add commentary. One line only.',
                ctxLine + 'Recent speech:\n' + recentText + '\n\nOutput the interview question or NONE:',
                80, MODEL_HAIKU
              ),
              new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 2500))
            ]);
            const raw = extracted.trim().replace(/^["']|["']$/g, '');
            // Strong filtering: reject if NONE anywhere, prompt fragments leak, or multi-line
            if (!raw || /\bNONE\b/i.test(raw)) return;
            if (/output the question|interview question being asked|wait for the interviewer|speech is (incomplete|just)|small talk|filler/i.test(raw)) return;
            // Real questions are single-line; multi-line means Haiku is explaining itself
            const firstLine = raw.split(/\n/)[0].trim();
            if (!firstLine || firstLine.length < 10) return;
            const q = cleanQuestionText(firstLine);

            // Don't re-fire if this is the same or a subset of a recently detected question
            const qLow = q.toLowerCase();
            for (var ri = 0; ri < recentDetectedQs.length; ri++) {
              var prev = recentDetectedQs[ri].toLowerCase();
              // Exact match, substring either way, or high similarity
              if (qLow === prev || prev.includes(qLow) || qLow.includes(prev) ||
                  stringSimilarity.compareTwoStrings(qLow, prev) > 0.6) {
                console.log('[AI Auto-Detect] Skipping duplicate of recent:', prev.substring(0, 50));
                return;
              }
            }
            lastAiExtractedQ = q;
            recentDetectedQs.push(q);
            if (recentDetectedQs.length > 5) recentDetectedQs.shift();

            console.log('[AI Auto-Detect]', q.substring(0, 60));
            lastWsayMatchId = null;
            recentMatchedIds.clear();
            var qdMsg1 = { type: 'question_detected', text: q, source: 'auto' };
            ws.send(JSON.stringify(qdMsg1));
            broadcastToSession(sessionId, qdMsg1, ws);
            const rebuildIdx = () => { questionIndex = buildQuestionIndex(sessionQuestions); };
            fastMatchAndRespond(q, sessionQuestions, sessionId, userId, ws, lastMatchedQId, recentMatchedIds, questionIndex, rebuildIdx).then(newLastId => {
              if (newLastId) { lastMatchedQId = newLastId; lastAutoMatchTime = Date.now(); }
            });
          } catch (e) {
            // Timeout or error — silent, don't block
            console.log('[AI Auto-Detect] Skip:', e.message);
          }
        }

        interviewerDG = openDeepgramStream(
          (text, isFinal, speechFinal) => {
            if (!text.trim()) return;

            if (isFinal) {
              resetIdleTimer();
              interviewerBuffer += (interviewerBuffer ? ' ' : '') + text.trim();
              ws.send(JSON.stringify({ type: 'transcript', text: interviewerBuffer, isFinal: false }));

              // Fast path: obvious question patterns fire — require 12+ words to avoid partial captures
              const bufWordCount = interviewerBuffer.trim().split(/\s+/).length;
              if (!questionFiredForBuffer && bufWordCount >= 12 && isQuestion(interviewerBuffer) && (Date.now() - lastAutoMatchTime >= AUTO_MATCH_COOLDOWN)) {
                questionFiredForBuffer = true;
                const bufferSnapshot = cleanQuestionText(interviewerBuffer.trim());
                console.log('[Question FAST]', bufferSnapshot.substring(0, 60));
                lastAiExtractedQ = bufferSnapshot; // prevent AI from re-firing same
                recentDetectedQs.push(bufferSnapshot);
                if (recentDetectedQs.length > 5) recentDetectedQs.shift();
                lastWsayMatchId = null;
                var qdMsg1 = { type: 'question_detected', text: bufferSnapshot, source: 'auto' };
                ws.send(JSON.stringify(qdMsg1));
                broadcastToSession(sessionId, qdMsg1, ws);
                const rebuildIdx = () => { questionIndex = buildQuestionIndex(sessionQuestions); };
                fastMatchAndRespond(bufferSnapshot, sessionQuestions, sessionId, userId, ws, lastMatchedQId, recentMatchedIds, questionIndex, rebuildIdx).then(newLastId => {
                  if (newLastId) { lastMatchedQId = newLastId; lastAutoMatchTime = Date.now(); }
                });
              }
            } else {
              const preview = interviewerBuffer ? interviewerBuffer + ' ' + text.trim() : text.trim();
              ws.send(JSON.stringify({ type: 'transcript', text: preview, isFinal: false }));
            }

            // On speechFinal — speaker paused. Commit line + run AI extraction
            if (speechFinal && interviewerBuffer.trim()) {
              const fullUtterance = interviewerBuffer.trim();
              interviewerBuffer = '';
              const wasFired = questionFiredForBuffer;
              questionFiredForBuffer = false;

              ws.send(JSON.stringify({ type: 'transcript', text: fullUtterance, isFinal: true }));
              transcript.push({ text: fullUtterance, ts: Date.now() });
              ws._recentTranscript = transcript.slice(-6).map(t => t.text);

              // If fast path didn't fire, let AI try to extract a question
              if (!wasFired) {
                aiAutoExtract();
              }
              setTimeout(() => recentMatchedIds.clear(), 5000);
            }
          },
          (err) => {
            console.error('[Deepgram Error]', err.message);
            ws.send(JSON.stringify({ type: 'error', message: 'Transcription error: ' + err.message }));
          }
        );

        userDG = null;

        ws.send(JSON.stringify({ type: 'status', message: 'Live mode started', questionsLoaded: sessionQuestions.length }));
        resetIdleTimer();
      }

      else if (msg.type === 'manual_match') {
        // User clicked a transcript line to manually match — deliberate action, clear dedup
        const text = msg.text;
        if (text && sessionQuestions.length) {
          recentMatchedIds.clear();
          var qdMsg2 = { type: 'question_detected', text: text, source: 'manual' };
          ws.send(JSON.stringify(qdMsg2));
          broadcastToSession(sessionId, qdMsg2, ws);
          const rebuildIdx = () => { questionIndex = buildQuestionIndex(sessionQuestions); };
          fastMatchAndRespond(text, sessionQuestions, sessionId, userId, ws, null, recentMatchedIds, questionIndex, rebuildIdx).then(newLastId => {
            if (newLastId) lastMatchedQId = newLastId;
          });
        }
      }

      else if (msg.type === 'canvas_question') {
        // User typed a question in the Smart Canvas input bar — manual action, no cooldown
        const text = msg.text;
        if (!text || text.length < 5) return;
        console.log('[Canvas] Manual question:', text.substring(0, 60));
        recentMatchedIds.clear();
        var qdMsg3 = { type: 'question_detected', text: text, source: 'manual' };
        ws.send(JSON.stringify(qdMsg3));
        broadcastToSession(sessionId, qdMsg3, ws);
        const rebuildIdx = () => { questionIndex = buildQuestionIndex(sessionQuestions); };
        fastMatchAndRespond(text, sessionQuestions, sessionId, userId, ws, null, recentMatchedIds, questionIndex, rebuildIdx).then(newLastId => {
          if (newLastId) lastMatchedQId = newLastId;
        });
      }

      else if (msg.type === 'what_should_i_say') {
        // Canvas clients don't have transcript — forward to the main (full mode) client for this session
        if (isCanvasMode) {
          console.log('[Canvas] what_should_i_say — forwarding to main client');
          // Find the main (non-canvas) client for this session and send it the request
          const clients = sessionClients.get(sessionId);
          if (clients) {
            let forwarded = false;
            clients.forEach(client => {
              if (client !== ws && client.readyState === WebSocket.OPEN && !client._isCanvas) {
                client.send(JSON.stringify({ type: 'what_should_i_say' }));
                forwarded = true;
              }
            });
            if (!forwarded) {
              ws.send(JSON.stringify({ type: 'error', message: 'Go Live on xhire.app first — no active mic session found' }));
            }
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'No live session active' }));
          }
          return;
        }

        // Full mode: extract the MOST RECENT question from transcript
        // Priority: current buffer > last 3 lines (newest first)
        const currentBuf = interviewerBuffer.trim();
        const recentLines = transcript.slice(-5); // last 5 for context

        // Build transcript with recency markers — newest at bottom, labeled
        let rawTranscript = '';
        if (recentLines.length > 0) {
          rawTranscript = 'OLDER CONTEXT:\n' + recentLines.slice(0, -2).map(t => t.text).join('\n');
          rawTranscript += '\n\nMOST RECENT:\n' + recentLines.slice(-2).map(t => t.text).join('\n');
        }
        if (currentBuf) {
          rawTranscript += '\n\nRIGHT NOW (currently being spoken):\n' + currentBuf;
        }

        if (!rawTranscript || rawTranscript.length < 10) {
          ws.send(JSON.stringify({ type: 'error', message: 'No speech detected yet' }));
          return;
        }
        console.log('[WhatShouldISay] Raw transcript:', rawTranscript.substring(0, 150));

        // Step 1: Ask Haiku to extract the LATEST question
        const wsCtx = ws._sessionContext || {};
        const ctxLine = (wsCtx.company || wsCtx.role) ? `\nContext: Interview for ${wsCtx.role || 'a role'} at ${wsCtx.company || 'a company'}.\n` : '';
        const extractSystem = 'You extract interview questions from conversation transcripts. The transcript has recency markers — ALWAYS pick the question from "RIGHT NOW" or "MOST RECENT" sections. NEVER pick from "OLDER CONTEXT" unless there is no question in the recent sections. Output ONLY the question itself — nothing else. If the speech is a statement, rephrase as the implied question.';
        const extractUser = ctxLine + rawTranscript + '\n\nWhat is the interviewer CURRENTLY asking? Pick from the most recent speech. Output the question only.';

        let questionText;
        try {
          questionText = await Promise.race([
            callClaude(extractSystem, extractUser, 100, MODEL_HAIKU),
            new Promise((_, reject) => setTimeout(() => reject(new Error('extract_timeout')), 2000))
          ]);
          questionText = cleanQuestionText(questionText.trim().replace(/^["']|["']$/g, ''));
          console.log('[WhatShouldISay] Haiku extracted:', questionText);
        } catch (e) {
          // Fallback: use most recent lines
          console.log('[WhatShouldISay] Extraction failed, using raw transcript');
          questionText = currentBuf || transcript.slice(-2).map(t => t.text).join(' ');
        }

        if (!questionText || questionText.length < 5) {
          ws.send(JSON.stringify({ type: 'error', message: 'Could not identify a question from the conversation' }));
          return;
        }

        recentMatchedIds.clear();
        if (lastWsayMatchId) {
          recentMatchedIds.add(lastWsayMatchId);
          console.log('[WhatShouldISay] Excluding previous match:', lastWsayMatchId);
        }
        var qdMsg4 = { type: 'question_detected', text: questionText, source: 'manual' };
        ws.send(JSON.stringify(qdMsg4));
        broadcastToSession(sessionId, qdMsg4, ws);

        // Step 2: Match the extracted question against the bank (with AI verification)
        const rebuildIdx = () => { questionIndex = buildQuestionIndex(sessionQuestions); };
        fastMatchAndRespond(questionText, sessionQuestions, sessionId, userId, ws, null, recentMatchedIds, questionIndex, rebuildIdx).then(newLastId => {
          lastWsayMatchId = newLastId || null;
          if (newLastId) lastMatchedQId = newLastId;
        });
      }

      else if (msg.type === 'stop') {
        clearTimeout(idleTimer);
        // Close Deepgram streams
        if (interviewerDG && interviewerDG.readyState === WebSocket.OPEN) {
          interviewerDG.send(JSON.stringify({ type: 'CloseStream' }));
          interviewerDG.close();
        }
        if (userDG && userDG.readyState === WebSocket.OPEN) {
          userDG.send(JSON.stringify({ type: 'CloseStream' }));
          userDG.close();
        }
        interviewerDG = null;
        userDG = null;

        // Save transcript
        if (transcriptId && transcript.length) {
          await pool.query(
            'UPDATE live_transcripts SET transcript = $1, ended_at = NOW() WHERE id = $2',
            [JSON.stringify(transcript), transcriptId]
          );
        }

        ws.send(JSON.stringify({ type: 'status', message: 'Live mode ended', transcriptLines: transcript.length }));
      }

    } catch (e) {
      console.error('[WS Message Error]', e.message);
    }
  });

  ws.on('close', async () => {
    clearTimeout(idleTimer);
    // Remove from session clients map
    if (sessionId) removeSessionClient(sessionId, ws);
    // Canvas clients don't have Deepgram or transcripts to clean up
    if (isCanvasMode) return;
    // Cleanup Deepgram streams
    if (interviewerDG && interviewerDG.readyState === WebSocket.OPEN) {
      try { interviewerDG.send(JSON.stringify({ type: 'CloseStream' })); interviewerDG.close(); } catch (e) {}
    }
    if (userDG && userDG.readyState === WebSocket.OPEN) {
      try { userDG.send(JSON.stringify({ type: 'CloseStream' })); userDG.close(); } catch (e) {}
    }
    // Save transcript on unexpected close
    if (transcriptId && transcript.length) {
      try {
        await pool.query('UPDATE live_transcripts SET transcript = $1, ended_at = NOW() WHERE id = $2', [JSON.stringify(transcript), transcriptId]);
      } catch (e) {}
    }
  });
});

// Canvas question endpoint — for when user types a question without live WebSocket
app.post('/api/sessions/:id/canvas-ask', authMiddleware, async (req, res) => {
  try {
    const { question } = req.body;
    if (!question || question.length < 5) return res.status(400).json({ error: 'Question too short' });
    const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Session not found' });
    const session = s.rows[0];

    // Try to match existing questions first
    const existingQ = await pool.query('SELECT id, text, type, answer FROM questions WHERE session_id = $1', [req.params.id]);
    if (existingQ.rows.length) {
      const questionIndex = buildQuestionIndex(existingQ.rows);
      const match = findBestMatch(question, existingQ.rows, questionIndex);
      if (match && match.question.answer) {
        return res.json({
          questionId: match.question.id,
          questionText: match.question.text,
          answer: match.question.answer,
          type: match.question.type,
          source: 'matched',
          similarity: Math.round(match.similarity * 100)
        });
      }
    }

    // No match — generate fresh answer
    const qType = classifyQuestion(question);
    const isTechnical = /sql|query|code|write|function|script|algorithm|regex|api|join|window function|python|javascript|html|css|excel|vba|dax|power query|etl|pipeline/i.test(question);
    const qas = await pool.query("SELECT text, answer FROM questions WHERE session_id = $1 AND answer != '' LIMIT 10", [req.params.id]);
    const bankContext = qas.rows.map(q => `Q: ${q.text}\nA: ${q.answer}`).join('\n\n');

    const system = isTechnical
      ? `You are a real-time interview assistant. The interviewer asked a TECHNICAL question. Provide a clear, practical answer. If code is needed, write it in a markdown code block with the language tag. Keep explanations brief — lead with the code/solution, then 2-3 lines explaining the approach. Every sentence on its own line.`
      : `You are a real-time interview assistant. Answer concisely. Use the candidate's resume and JD context. Keep it to 4-6 sentences max. Every sentence on its own line. Lead with the answer.`;
    const userPrompt = `RESUME:\n${session.resume}\n\nJOB DESCRIPTION:\n${session.jd}\n\nQ&A BANK:\n${bankContext}\n\nQUESTION:\n${question}\n\nAnswer:`;

    const answer = await callClaude(system, userPrompt, isTechnical ? 1200 : 600, MODEL_HAIKU);

    // Save as new question
    const newQ = await pool.query(
      'INSERT INTO questions (session_id, text, type, answer, source) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [req.params.id, question, qType, answer, 'live']
    );

    res.json({ questionId: newQ.rows[0].id, questionText: question, answer, type: qType, source: 'new', similarity: 0 });
  } catch (e) {
    console.error('[Canvas Ask Error]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Generate answer for live question — questionId is the EXISTING DB row from fastMatchAndRespond
async function generateLiveAnswer(questionText, sessionId, userId, ws, questionId) {
  try {
    // Use cached session context — no DB lookup needed
    const session = ws._sessionContext || {};
    if (!session.resume) {
      const s = await pool.query('SELECT resume, jd, company, role, answer_style FROM sessions WHERE id = $1', [sessionId]);
      if (!s.rows.length) return;
      Object.assign(session, s.rows[0]);
      ws._sessionContext = session;
    }

    // Use in-memory Q&A bank — include up to 15 answered questions for rich context
    const answeredQs = (ws._sessionQuestions || []).filter(q => q.answer).slice(0, 15);
    const bankContext = answeredQs.map(q => `Q: ${q.text}\nA: ${q.answer}`).join('\n\n');

    // User's recent speech for conversational context
    const userLines = ws._userRecentLines || [];
    const userContext = userLines.length > 0 ? `\n\nCANDIDATE'S RECENT RESPONSES (build on this, don't repeat):\n${userLines.join('\n')}` : '';

    // Session identity — critical for role-specific answers
    const company = session.company || 'the company';
    const role = session.role || 'this role';
    const sessionHeader = `THIS INTERVIEW IS FOR: ${role} at ${company}\nThe candidate knows which role and company this is. If asked "why this role" or "why this company", they should reference ${company} and ${role} naturally — but NEVER parrot the JD. Answer from genuine experience.\n`;

    const isTechnical = /sql|query|code|write|function|script|algorithm|regex|api|join|window function|python|javascript|html|css|excel|vba|dax|power query|etl|pipeline/i.test(questionText);

    // Use the full ANSWER_PROMPT for strategic framing — not a watered-down version
    // Add a speed note for live context + technical override when needed
    const liveAddendum = isTechnical
      ? `\n\nLIVE MODE — TECHNICAL QUESTION: If code is needed, use a markdown code block with the language tag. Lead with the code/solution, then 2-3 lines explaining. If the candidate already started answering, complement — don't repeat what they said.\n\nIMPORTANT: The question was captured via live speech transcription and may be incomplete or slightly garbled. NEVER say "I'm not sure what you're asking" or ask for clarification. Instead, interpret the most likely intent based on the interview context (role, company, resume, Q&A bank) and answer that. If the question is ambiguous, pick the most relevant interpretation for this interview and answer confidently.`
      : `\n\nLIVE MODE: This is a real-time interview. The candidate needs this answer NOW. Be concise and authentic — speak from real experience, not talking points. If the candidate already started answering (see their recent responses below), add what they missed — don't repeat.\n\nIMPORTANT: The question was captured via live speech transcription and may be incomplete or slightly garbled. NEVER say "I'm not sure what you're asking" or ask for clarification. Instead, interpret the most likely intent based on the interview context (role, company, resume, Q&A bank) and answer that. If the question is ambiguous, pick the most relevant interpretation for this interview and answer confidently.`;

    const basePrompt = getStylePrompt(session.answer_style);
    const system = basePrompt + liveAddendum;
    // Include recent transcript so AI sees the full buildup, not just the tail-end question
    const recentLines = ws._recentTranscript || [];
    const transcriptContext = recentLines.length > 0
      ? `\n\nRECENT CONVERSATION (the interviewer's speech leading up to the question — use this to understand the FULL context):\n${recentLines.join('\n')}`
      : '';

    const userPrompt = `${sessionHeader}\nRESUME:\n${session.resume || 'N/A'}\n\nJOB DESCRIPTION:\n${session.jd || 'N/A'}\n\nQ&A BANK (candidate's real experience — USE THIS):\n${bankContext}${userContext}${transcriptContext}\n\nQUESTION (detected from speech — may be just the tail end, use RECENT CONVERSATION above for full context):\n${questionText}\n\nAnswer:`;

    const answer = await callClaude(system, userPrompt, isTechnical ? 1200 : 600, MODEL_HAIKU);

    // UPDATE the existing question row (created by fastMatchAndRespond) — NOT a new INSERT
    if (questionId) {
      pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, questionId])
        .catch(e => console.error('[Update answer error]', e.message));
    }

    // Send answer to client with the SAME questionId the client already knows about
    const liveAnswerMsg = {
      type: 'live_answer',
      questionId: questionId || ('temp-' + Date.now()),
      questionText,
      answer,
      isNew: true
    };
    ws.send(JSON.stringify(liveAnswerMsg));
    broadcastToSession(sessionId, liveAnswerMsg, ws); // Broadcast to canvas clients
  } catch (e) {
    console.error('[Live Answer Error]', e.message);
    ws.send(JSON.stringify({ type: 'error', message: 'Failed to generate answer' }));
  }
}

// (transcripts route moved before catch-all — see above)

// Start
initDB().then(() => {
  server.listen(PORT, () => console.log(`Running on ${PORT}`));
}).catch(e => {
  console.error('DB init failed:', e);
  server.listen(PORT, () => console.log(`Running on ${PORT} (DB not ready)`));
});
