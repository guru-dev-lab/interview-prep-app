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

// No-cache for canvas.html and launcher.html — Electron must always get latest
app.use('/canvas.html', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});
app.use('/launcher', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  next();
});

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
        jd_requirements JSONB DEFAULT NULL,
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
      ALTER TABLE live_transcripts ADD COLUMN IF NOT EXISTS learned BOOLEAN DEFAULT false;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS voice_profile TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS voice_profile_updated_at TIMESTAMP;
      ALTER TABLE questions ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'build';
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS answer_style VARCHAR(50) DEFAULT 'conversational';
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS jd_requirements JSONB DEFAULT NULL;
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
  return jwt.sign({ userId: user.id, name: user.name, email: user.email, isAdmin: user.is_admin || false, plan: user.plan || 'free', suspended: user.suspended || false }, JWT_SECRET, { expiresIn: '30d' });
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

// Google OAuth callback (redirect flow for Electron)
app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send('No authorization code');

    // Exchange code for tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${process.env.SERVER_URL || 'https://xhire.app'}/api/auth/google/callback`,
        grant_type: 'authorization_code'
      })
    });
    const tokens = await tokenRes.json();
    if (!tokens.id_token) return res.status(400).send('Failed to get ID token');

    // Decode the ID token
    const parts = tokens.id_token.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    const { sub: googleId, email, name, picture } = payload;
    if (!email) return res.status(400).send('No email in token');

    // Find or create user (same logic as POST /api/auth/google)
    let result = await pool.query('SELECT * FROM users WHERE email = $1 OR google_id = $2', [email.toLowerCase(), googleId]);
    let user;
    if (result.rows.length) {
      user = result.rows[0];
      await pool.query('UPDATE users SET google_id = COALESCE(google_id, $1), avatar_url = COALESCE(avatar_url, $2), updated_at = NOW() WHERE id = $3',
        [googleId, picture, user.id]);
    } else {
      result = await pool.query('INSERT INTO users (email, name, google_id, avatar_url) VALUES ($1, $2, $3, $4) RETURNING *',
        [email.toLowerCase(), name, googleId, picture]);
      user = result.rows[0];
    }
    const freshUser = (await pool.query('SELECT * FROM users WHERE id = $1', [user.id])).rows[0];
    const token = generateToken(freshUser);

    // Redirect to launcher with token so it can proceed to session picker
    res.send(`<!DOCTYPE html><html><head><title>Xhire</title></head><body style="background:#06080f;color:#e2e8f0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh"><div style="text-align:center"><h2>Signed in!</h2><p>Loading sessions...</p></div><script>
      var token = ${JSON.stringify(token)};
      var userId = ${JSON.stringify(String(freshUser.id))};
      sessionStorage.setItem('token', token);
      window.location.href = '/launcher?authed=1&token=' + encodeURIComponent(token);
    </script></body></html>`);
  } catch (e) {
    console.error('Google callback error:', e);
    res.status(500).send('Google sign-in failed: ' + e.message);
  }
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

// ── Model configuration ───────────────────────────────────────────────
// Single source of truth for Claude models. Each is env-overridable so
// models can be swapped without code edits (set MODEL_OPUS / MODEL_SONNET /
// MODEL_HAIKU in the environment to pin a different version).
const MODELS = {
  opus:   process.env.MODEL_OPUS   || 'claude-opus-4-8',          // highest quality
  sonnet: process.env.MODEL_SONNET || 'claude-sonnet-5',         // balanced default
  haiku:  process.env.MODEL_HAIKU  || 'claude-haiku-4-5-20251001' // fast / low-cost
};

// Backward-compatible aliases — existing call sites reference these directly.
const MODEL_OPUS   = MODELS.opus;
const MODEL_SONNET = MODELS.sonnet;
const MODEL_HAIKU  = MODELS.haiku;

// Reused keep-alive connection pool for Anthropic API calls. Each detected
// question fires 3-4 separate HTTPS requests; without this, Node opens a fresh
// TLS connection (and handshake, ~100-200ms) every time. Reusing sockets shaves
// that off each call with zero change to request/response behavior.
const anthropicAgent = new https.Agent({ keepAlive: true, maxSockets: 50, keepAliveMsecs: 30000 });

// ── Lightweight observability ─────────────────────────────────────────
// In-memory ring buffer of recent live-pipeline events so we can SEE the app
// working (and catch regressions) without a real interview. Surfaced at
// GET /api/admin/health. Never throws; capped so it can't grow unbounded.
const SERVER_START = Date.now();
const eventLog = [];
const EVENT_LOG_MAX = 800;
function logEvent(type, data) {
  try {
    eventLog.push(Object.assign({ t: Date.now(), type }, data || {}));
    if (eventLog.length > EVENT_LOG_MAX) eventLog.shift();
  } catch (e) {}
}

function _callClaudeOnce(system, user, maxTokens, model) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ model, max_tokens: maxTokens, system, messages: [{ role: 'user', content: user }] });
    const req = https.request({
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      agent: anthropicAgent,
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

// Retry on 'Overloaded' — up to 3 attempts with exponential backoff
async function callClaude(system, user, maxTokens = 1500, model = MODEL_SONNET) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      return await _callClaudeOnce(system, user, maxTokens, model);
    } catch (e) {
      if (e.message === 'Overloaded' && attempt < 3) {
        const delay = attempt * 1500; // 1.5s, 3s
        _log(`[Claude] Overloaded — retry ${attempt}/3 in ${delay}ms`);
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      throw e;
    }
  }
}

// Streaming variant — emits text deltas via onDelta(chunk) as they arrive and
// resolves with the full text. Used for live answers so the candidate sees text
// appear immediately instead of waiting for the whole completion.
// SAFETY: on ANY error this rejects, and the caller falls back to buffered callClaude,
// so behavior can never be worse than the non-streaming path.
function _callClaudeStreamOnce(system, user, maxTokens, model, onDelta) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ model, max_tokens: maxTokens, system, stream: true, messages: [{ role: 'user', content: user }] });
    const req = https.request({
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      agent: anthropicAgent,
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' }
    }, res => {
      if (res.statusCode !== 200) {
        let errBody = ''; res.on('data', c => errBody += c);
        res.on('end', () => {
          let m = 'HTTP ' + res.statusCode;
          try { m = JSON.parse(errBody).error?.message || m; } catch (e) {}
          reject(new Error(m));
        });
        return;
      }
      let full = '';
      let sseBuffer = '';
      res.setEncoding('utf8');
      res.on('data', chunk => {
        sseBuffer += chunk;
        let nl;
        while ((nl = sseBuffer.indexOf('\n')) >= 0) {
          const line = sseBuffer.slice(0, nl).trim();
          sseBuffer = sseBuffer.slice(nl + 1);
          if (!line.startsWith('data:')) continue;
          const data = line.slice(5).trim();
          if (!data || data === '[DONE]') continue;
          try {
            const evt = JSON.parse(data);
            if (evt.type === 'content_block_delta' && evt.delta?.type === 'text_delta') {
              const t = evt.delta.text || '';
              if (t) { full += t; try { onDelta(t); } catch (e) {} }
            } else if (evt.type === 'error') {
              reject(new Error(evt.error?.message || 'stream error'));
            }
          } catch (e) { /* ignore keep-alive / partial lines */ }
        }
      });
      res.on('end', () => resolve(full));
    });
    req.on('error', reject);
    req.setTimeout(90000, () => { req.destroy(); reject(new Error('timeout')); });
    req.write(body); req.end();
  });
}

// Retry wrapper — only retries on Overloaded BEFORE any text has streamed, so we
// never emit duplicate deltas. Once streaming has begun, an error rejects and the
// caller falls back to the buffered path.
async function callClaudeStream(system, user, maxTokens = 600, model = MODEL_SONNET, onDelta = () => {}) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    let emitted = false;
    try {
      return await _callClaudeStreamOnce(system, user, maxTokens, model, (t) => { emitted = true; onDelta(t); });
    } catch (e) {
      if (e.message === 'Overloaded' && !emitted && attempt < 3) {
        await new Promise(r => setTimeout(r, attempt * 1500));
        continue;
      }
      throw e;
    }
  }
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
      agent: anthropicAgent,
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
Line count depends on question type — see below. Short questions get 3-5 lines, detailed ones get up to 8.

EXAMPLE OF CORRECT FORMAT:
A left join returns all rows from the left table.
If there's no match on the right side you get nulls.
An inner join only gives you rows that match on both sides.
So if you need to keep everything from one table, use a left join.

EXAMPLE OF WRONG FORMAT (DO NOT DO THIS):
"A LEFT JOIN is a type of SQL join that returns all records from the left table and the matched records from the right table. If there is no match, the result will contain NULL values for columns from the right table. This differs from an INNER JOIN which only returns rows where there is a matching value in both tables."
^ WRONG. Those are paragraphs. Each sentence must be its own line.

ANSWERING RULES — CRITICAL:
MOST IMPORTANT RULE — DO NOT FORCE ROLE/COMPANY REFERENCES:
NEVER say "At [company] I did X" or "In my role as [title] I..." UNLESS the question specifically asks about your experience at a company or in a role.
"How do you use Tableau?" → "I usually build dashboards by connecting to the data source, setting up calculated fields..." — NO company name needed.
"What is a CTE?" → Just explain what a CTE is. Period.
"Tell me about your experience with X at your current role" → NOW you can reference the company.
The resume and JD are there for CONTEXT ONLY — do not parrot them into every answer.

1. MATCH the question type to the answer style:
   - "What is X?" or "Explain X" → Define/explain it simply. No personal story.
   - "How do you use X?" or "How would you do X?" → Explain YOUR approach/steps plainly. Say "I do X" not "At [company] I do X."
   - "Tell me about a time" / "Describe your experience" / "in your role" → NOW use personal experience with company/role context.
   - "Walk me through" → Step by step explanation. Use "I" naturally but don't name-drop companies.

2. Keep it simple. No jargon. No buzzwords. Plain English.
   BANNED: leverage, utilize, robust, comprehensive, drive, facilitate, synergy, paradigm, ecosystem, holistic, scalable, cross-functional, stakeholder alignment, "in my capacity as."
   USE INSTEAD: use, build, fix, run, help, work with, make, set up, improve.

VOICE — READ-ALOUD READY:
The candidate is reading your words to the interviewer.
Use "I" naturally — "I usually do X", "I like to start by", "The way I handle that is."
Do NOT prefix with company/role unless asked — "I build dashboards using..." NOT "As a Senior BI Analyst at R&L, I build dashboards..."
Use spoken transitions: "So basically", "The way it works is", "Think of it like."
NEVER use filler words: "Additionally", "Furthermore", "In conclusion."
Contractions always. Sound like a person talking, not a textbook.

CONTENT:
Use the Q&A BANK as source of truth for experience-based answers ONLY when the question asks about past experience.
Use the resume for facts ONLY when the question asks about the candidate's background.
Use the JD ONLY to understand what tools/skills matter — never copy its language, never reference the target company.
Never fabricate. No filler lines.

QUESTION TYPES (these are DEFAULTS — a length override below will supersede these):
"What is X?" / Concept questions → 3-4 lines. Simple, clear definition. NO personal experience needed.
"How do you do X?" / Process questions → 3-5 lines. Steps or approach. Say "I do X" — no company name.
"Tell me about yourself" → 4-6 lines. Name, background highlights, why this role.
Behavioral (tell me about a time) → 4-6 lines. Use real experience from Q&A bank. NOW you can name companies.
Technical (code/SQL) → 3-4 lines. Show the code or steps, brief explanation. No company references.
"Why this role/company?" → 3-4 lines. Genuine reasons tied to the role.

Output ONLY the answer. No intro, no labels, no "Here's my answer."`;

// Universal addendum for ALL styles — keeps code answers clean
const CODE_ANSWER_ADDENDUM = `

TECHNICAL/CODE QUESTIONS — STRICT RULES:
When the question involves code, SQL, technical concepts, or implementation:
- CODE FIRST. No preamble. No "Here's how I'd approach this." No "That's a great question." Just the code block immediately.
- After the code: ONE sentence max saying what it does. Not a paragraph. One sentence.
- NEVER write "What this does:" sections. NEVER explain line by line. NEVER add a walkthrough.
- NEVER say "Here's a practical example" or "Let me demonstrate" — just give the answer.
- If they ask a conceptual question (not code): 2-4 sentences, plain and direct. No stories.
- NO intro text before code. NO "I would use CTEs and window functions to..." — just write the code.
- The candidate reads this on a TINY overlay screen. Every extra word is wasted space.`;

// Display formatting addendum — adds visual formatting markers for the overlay UI
const DISPLAY_FORMAT_ADDENDUM = `

FORMATTING (displayed on a tiny overlay — must be scannable):
- Use **bold** on key terms and concepts (3-5 per answer)
- Use \`backticks\` for technical terms, SQL keywords, tool names
- Use bullet points (- ) for listing steps, features, or key points
- Use numbered lists (1. 2. 3.) for ordered steps or processes
- Keep each bullet/point to ONE concise sentence
- STAR labels (Situation/Action/Result) ONLY for behavioral questions
- Include real metrics when relevant
- For technical: code first, then 2-3 bullet explanation after
- For non-technical: 1-2 sentence intro, then bullet points for key details

ABSOLUTE ZERO-TOLERANCE RULES — VIOLATING ANY OF THESE MEANS FAILURE:
- FIRST WORD of your output must be the ANSWER. No intro, no header, NOTHING before the answer. (EXCEPTION: When using STAR Method style, start with "Situation:" label.)
- NEVER use generic section headers or category prefixes (EXCEPTION: STAR labels like Situation:, Task:, Action:, Result: ARE allowed and REQUIRED when the style is STAR Method). Banned headers include but are not limited to:
  "How it works:", "Simple explanation:", "What this does:", "Basic structure:", "Real example:",
  "The approach:", "Key points:", "Overview:", "Summary:", "Background:", "The concept:",
  "The answer:", "Quick explanation:", "Step by step:", "The idea:", "The solution:",
  "Here's how:", "Here's why:", "Here's what:", "Definition:", "Explanation:", "In short:",
  "Main idea:", "The logic:", "The process:", "Key takeaway:", "What it does:", "Why use it:"
- NEVER use "QUESTION:" or "ANSWER:" labels or "---" dividers
- NEVER use preamble phrases: "Here's a practical example", "Let me explain", "In other words",
  "Essentially", "Basically", "To put it simply", "In simple terms", "Great question",
  "That's a great question", "So essentially", "What this means is", "The way I'd explain it is",
  "Let me walk you through", "Think of it this way", "To answer your question"
- NEVER use closing/summary phrases: "In summary", "To summarize", "The key takeaway is",
  "Overall", "In conclusion", "The bottom line is", "So in short"
- Go STRAIGHT to the answer — literally the first sentence IS the answer (unless STAR Method, where the first word is "Situation:")`;

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

Each STAR section MUST start with its label ON ITS OWN LINE: "Situation:", "Task:", "Action:", "Result:"
The label line must contain ONLY the label word and colon — no other text on that line.
These render as colored badges in the UI and help the candidate scan quickly.

VOICE:
Narrative and clear. Use "I" for ownership.
Spoken transitions: "So what happened was", "My role was to", "The result was."
Contractions always. Sound like you're telling a real story.

CONTENT:
Use Q&A BANK for real stories — actual companies, projects, outcomes.
Use resume for facts. Each answer must reference a real experience.
Never fabricate. If the question doesn't fit STAR, adapt — lead with your approach.

Output ONLY the answer. No intro sentence, no preamble. Always include section labels (Situation:, Task:, Action:, Result:) each on its OWN LINE with no other text on the label line.`
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
  },
  framework: {
    name: 'Structured Framework',
    description: 'Organized with clear pillars — First, Second, Third',
    icon: '🏗️',
    prompt: `You generate interview answers. The candidate reads these OUT LOUD in a live interview.

OUTPUT FORMAT:
Each line = ONE sentence. Max 15 words per line.
Each sentence on its own line separated by \\n.
Total: 5-8 lines.

STYLE — STRUCTURED FRAMEWORK:
Open with a one-line thesis: "I approach this in three ways."
Then deliver 2-3 clear pillars or dimensions.
Use natural spoken transitions: "First...", "Second...", "And third..."
Close with a concrete example from one of the pillars.
The structure makes complex answers easy to follow.

VOICE:
Organized and articulate. Like a consultant presenting.
"I break this into three areas", "The first thing I focus on."
Confident but not stiff. Contractions are fine.
Sound like someone who thinks clearly under pressure.

CONTENT:
Use Q&A BANK and resume for real examples.
Each pillar should have substance, not just a label.
Ground at least one pillar in a real project or outcome.

Output ONLY the answer. No intro, no labels.`
  },
  leadership: {
    name: 'Leadership & Impact',
    description: 'Ownership voice — how you led, influenced, and drove outcomes',
    icon: '👔',
    prompt: `You generate interview answers. The candidate reads these OUT LOUD in a live interview.

OUTPUT FORMAT:
Each line = ONE sentence. Max 15 words per line.
Each sentence on its own line separated by \\n.
Total: 5-8 lines.

STYLE — LEADERSHIP & IMPACT:
Frame everything through ownership and influence.
Show how you identified the problem, rallied people, and drove the outcome.
Emphasize cross-team collaboration, stakeholder management, and decision-making.
Mention who you influenced: leadership, peers, direct reports, external partners.
Close with the business impact you personally drove.

VOICE:
Confident and senior. "I led", "I drove", "I brought together."
Show initiative: "I saw the gap and proposed", "I took ownership of."
Mention team when relevant but make YOUR role clear.
Sound like a leader who gets things done through people.

CONTENT:
Use Q&A BANK for real leadership moments — team size, decisions, outcomes.
Pull from resume for scope: budget, team size, stakeholder level.
Every answer should show you operate above your title.

Output ONLY the answer. No intro, no labels.`
  },
  teacher: {
    name: 'Teach & Explain',
    description: 'Clear explanations — perfect for "What is X?" and concept questions',
    icon: '🧠',
    prompt: `You generate interview answers. The candidate reads these OUT LOUD in a live interview.

OUTPUT FORMAT:
Each line = ONE sentence. Max 16 words per line.
Each sentence on its own line separated by \\n.
Total: 5-8 lines.

STYLE — TEACH & EXPLAIN:
Start with a clear, simple definition or explanation.
Then add depth: why it matters, how it works in practice.
Use an analogy or real-world comparison to make it click.
Bridge to your experience: "In my work at [company], I applied this by..."
Close with practical insight that shows deep understanding.

VOICE:
Clear and knowledgeable. Like a senior colleague explaining to a new hire.
"Think of it like...", "In practice, what this means is..."
Avoid textbook language. Explain like you truly understand it, not memorized it.
Contractions always. Conversational but authoritative.

CONTENT:
Demonstrate real understanding, not Wikipedia definitions.
Connect concepts to YOUR actual work and projects from Q&A BANK.
Show you can explain complex things simply — that IS the skill.

Output ONLY the answer. No intro, no labels.`
  },
  keywords: {
    name: 'Keyword Triggers',
    description: 'Ultra-short keyword cues — scan, grab, speak naturally',
    icon: '⚡',
    prompt: `YOU ARE A KEYWORD CUE GENERATOR. You output ONLY short keyword phrases — NEVER paragraphs, NEVER sentences, NEVER explanations.

ABSOLUTE RULE — NO PARAGRAPHS, NO SENTENCES:
Do NOT write any paragraph or full sentence. Not even one.
Do NOT write an answer first and then keywords after.
Do NOT write labels like "KEYWORD CUES:" or "---" or "**anything**".
The ENTIRE output is ONLY keyword phrases with blank lines between them.
If your output contains a single sentence longer than 8 words, you have FAILED.

OUTPUT FORMAT:
Each line = ONE action-oriented keyword phrase. 3-8 words per line.
Each keyword phrase must say WHAT you do + WITH WHAT tool or method.
Separate each line with a BLANK LINE between them (double \\n).
Total: 6-12 keyword lines depending on question complexity.

EVERY KEYWORD MUST BE ACTIONABLE:
BAD: "Design models, build pipelines" — too vague, what tools? how?
GOOD: "Fire up Alteryx — clean raw data"
GOOD: "Pull from ERP via SQL query"
GOOD: "Build dim model in warehouse"

BAD: "SQL for everything" — says nothing about what you DO with it
GOOD: "SQL — join tables, window functions"
GOOD: "Write CTEs for complex transforms"

BAD: "Translate data into executive decisions" — that's a sentence, too abstract
GOOD: "Build exec dashboard in Tableau"
GOOD: "Weekly KPI deck for leadership"

Each keyword = ACTION VERB + SPECIFIC TOOL/METHOD + WHAT FOR.

STORY ORDER IS CRITICAL:
Keywords must follow the NATURAL FLOW — start to finish.
Context/situation first → problem → each action step in order → result last.
The candidate reads top to bottom and tells the story in that exact sequence.
Every important beat gets its own line. Do NOT skip steps.

EXAMPLES:

"Tell me about yourself" →

12+ years BI and data engineering

Pull data from ERPs, CRMs via SQL

Build dim models, ETL pipelines

Tableau dashboards for exec team

Python + PySpark for automation

FP&A — variance, cohort, forecasting

AI daily — Claude, ChatGPT for speed

Bridge between messy data and C-suite

"Tell me about your day to day" →

Check tickets — sort by priority

Triage — what's blocked on me vs waiting

Fire up Alteryx — run scheduled refreshes

Verify automations ran clean overnight

Pick fastest wins — knock out quick

Deep work — complex SQL or pipeline fix

Update Jira — status and blockers

Slack stakeholders — share findings

"How do you handle data quality?" →

Start at source — validation rules on ingest

Null checks, duplicate IDs, type mismatches

Set up automated alerts in Airflow

Anomaly hits — trace root cause upstream

Fix at source not just patch downstream

Document known issues in Confluence

Monitor 2 weeks after — confirm clean

"Tell me about a time you improved a process" →

Team pulling reports manually every Monday

Took 4-5 hours — copy paste from 3 systems

Mapped full workflow — found 3 repeated steps

Built Python script — auto pull + clean + format

Connected output to Tableau — live refresh

Monday report now auto-generates by 7am

Saved 4 hours/week — zero manual errors

WHAT TO NEVER DO:
- NEVER write paragraphs or full sentences — ONLY keyword phrases
- NEVER write an answer then keywords — output is ONLY keywords
- NEVER use labels, headers, dividers (---, **, KEYWORD CUES, etc.)
- NEVER write vague abstractions like "translate data into decisions"
- NEVER list a tool without saying what you DO with it
- NEVER use buzzwords: leverage, utilize, drive, facilitate, robust
- NEVER skip an important step in the story
- NEVER put results before actions

CONTENT:
Pull REAL tools, tasks, and outcomes from Q&A BANK and resume.
Every keyword must be specific — name the tool, name the action, name the output.
Cover the COMPLETE story in order — miss nothing important.
Never fabricate.

Output ONLY keyword phrases with blank lines between them. Nothing else. No intro. No labels. No paragraphs. No sentences.`
  }
};

// Universal anti-role-stuffing rule appended to ALL styles
const NO_ROLE_STUFFING = `

CRITICAL — DO NOT FORCE COMPANY/ROLE REFERENCES:
Never say "At [company]..." or "In my role as [title]..." or "As a [title] at [company]..." UNLESS the question explicitly asks about your experience at a specific place.
DEFAULT MODE: Answer questions STRAIGHT. Most interview questions are conceptual or process questions that need a DIRECT answer — not a personal story.
EXPERIENCE MODE: Only triggered when the question says "tell me about a time", "in your role", "at your company", "describe your experience", "give an example from your work", etc.

EXAMPLES OF DEFAULT (STRAIGHT) ANSWERS:
"How do you track adoption?" → "I look at active user counts, refresh frequency, and drill-through depth." — NO company, NO story.
"What is a CTE?" → "A CTE is a temporary named result set you define at the top of a query." — Just explain it.
"How do you handle stakeholder requests?" → "I ask what decision they're trying to make, then scope the analysis around that." — NO "At R&L..."
"What tools do you use for ETL?" → "I typically use Python, SQL, and Power Query depending on the source." — NO stories.

EXAMPLES OF EXPERIENCE ANSWERS (ONLY WHEN ASKED):
"Tell me about a time you improved a process" → NOW use Q&A bank, name the company, tell the story.
"What's your experience with Tableau?" → NOW reference where you used it.
"Describe a challenging project" → NOW tell a real story.

The JD and resume are context for what the candidate knows — NOT scripts to recite into every answer.`;

// STAR-safe version of DISPLAY_FORMAT_ADDENDUM — removes "no labels" rules that conflict with STAR section labels
const DISPLAY_FORMAT_ADDENDUM_STAR = `

FORMATTING (displayed on a tiny overlay — must be scannable):
- Use **bold** on key terms and concepts (3-5 per answer)
- Use \`backticks\` for technical terms, SQL keywords, tool names
- Use bullet points (- ) for listing steps, features, or key points
- Use numbered lists (1. 2. 3.) for ordered steps or processes
- Keep each bullet/point to ONE concise sentence
- ALWAYS use STAR section labels: Situation:, Task:, Action:, Result: — each label MUST be on its OWN LINE with nothing else on that line
- Include real metrics when relevant

ABSOLUTE ZERO-TOLERANCE RULES — VIOLATING ANY OF THESE MEANS FAILURE:
- NEVER use preamble phrases: "Here's a practical example", "Let me explain", "In other words",
  "Essentially", "Basically", "To put it simply", "In simple terms", "Great question",
  "That's a great question", "So essentially", "What this means is", "The way I'd explain it is",
  "Let me walk you through", "Think of it this way", "To answer your question"
- NEVER use closing/summary phrases: "In summary", "To summarize", "The key takeaway is",
  "Overall", "In conclusion", "The bottom line is", "So in short"
- NEVER use "QUESTION:" or "ANSWER:" labels or "---" dividers
- Start with "Situation:" on its own line — the FIRST line must be ONLY the word "Situation:" with nothing else`;

// Get style prompt by key — fallback to conversational, always append code rules + anti-stuffing
function getStylePrompt(styleKey) {
  const base = (ANSWER_STYLES[styleKey] || ANSWER_STYLES.conversational).prompt;
  const displayAddendum = (styleKey === 'star') ? DISPLAY_FORMAT_ADDENDUM_STAR : DISPLAY_FORMAT_ADDENDUM;
  return base + CODE_ANSWER_ADDENDUM + NO_ROLE_STUFFING + displayAddendum;
}

const BATCH_PREAMBLE = `You will receive MULTIPLE interview questions. You MUST generate a separate, complete, high-quality answer for EACH question.

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

`;

// Build batch prompt using the selected style (not hardcoded default)
function getBatchPrompt(styleKey) {
  const stylePrompt = (ANSWER_STYLES[styleKey] || ANSWER_STYLES.conversational).prompt;
  return BATCH_PREAMBLE + stylePrompt + CODE_ANSWER_ADDENDUM;
}

// Legacy fallback
const BATCH_PROMPT = BATCH_PREAMBLE + ANSWER_PROMPT + CODE_ANSWER_ADDENDUM;

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

// Extract JD requirements (AI-powered, cached)
app.get('/api/sessions/:id/jd-requirements', authMiddleware, async (req, res) => {
  try {
    if (!isValidUUID(req.params.id)) return res.status(400).json({ error: 'Invalid session ID' });
    const s = await pool.query('SELECT jd, role, company, jd_requirements FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });
    const session = s.rows[0];
    if (!session.jd || session.jd.trim().length < 20) return res.json({ requirements: null, message: 'No JD uploaded' });

    // Return cached if available
    if (session.jd_requirements) {
      console.log('[JD Req] Returning cached requirements for session', req.params.id);
      return res.json({ requirements: session.jd_requirements, cached: true });
    }

    console.log('[JD Req] Extracting requirements for session', req.params.id, 'JD length:', session.jd.length);
    const text = await callClaude(
      'You extract and categorize job requirements from job descriptions. Return ONLY valid JSON, no markdown code fences, no explanation.',
      `Extract and categorize ALL requirements from this job description for the role of "${session.role || 'Unknown'}" at "${session.company || 'Unknown'}".

Return ONLY valid JSON (no \`\`\`json wrapper) with this structure:
{"technical_skills":[],"tools_platforms":[],"experience":[],"soft_skills":[],"certifications":[],"domain_knowledge":[],"education":[],"responsibilities":[]}

Fill each array with strings extracted from the JD. If a category has nothing, use an empty array.

JD:\n${session.jd.substring(0, 4000)}`,
      1500,
      MODEL_HAIKU
    );
    console.log('[JD Req] Haiku response:', text.substring(0, 200));
    // Strip markdown fences if present
    const cleaned = text.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim();
    // Extract JSON from response
    const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return res.json({ requirements: null, message: 'Could not parse AI response' });
    const requirements = JSON.parse(jsonMatch[0]);
    // Cache in DB so we never extract again for this session
    await pool.query('UPDATE sessions SET jd_requirements = $1 WHERE id = $2', [JSON.stringify(requirements), req.params.id]);
    console.log('[JD Req] Cached requirements for session', req.params.id);
    res.json({ requirements });
  } catch (e) {
    console.error('[JD Requirements Error]', e.message);
    res.status(500).json({ error: e.message });
  }
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
      userMsg += `USER INSTRUCTION (follow this closely): ${userInstruction}\n\nGenerate an answer following the user's instruction. Only reference companies or role titles if the question specifically asks about experience.`;
    } else {
      userMsg += `Answer the question naturally. Only reference companies or role titles if the question specifically asks about your experience.`;
    }

    const stylePrompt = getStylePrompt(session.answer_style);
    console.log(`[SINGLE-GEN] Session ${req.params.id}, Q ${req.params.qid}, style='${session.answer_style}', promptSnippet='${stylePrompt.substring(0, 120)}...'`);

    // Opt-in streaming: only when the client explicitly requests ?stream=1.
    // Without it, this endpoint behaves exactly as before (single JSON response).
    const wantStream = req.query.stream === '1' && process.env.STREAM_LIVE_ANSWERS !== '0';
    if (wantStream) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      if (res.flushHeaders) res.flushHeaders();
      let answer = '';
      try {
        answer = await callClaudeStream(stylePrompt, userMsg, 1500, MODEL_HAIKU, (chunk) => {
          res.write('data: ' + JSON.stringify({ delta: chunk }) + '\n\n');
        });
      } catch (streamErr) {
        console.error('[SINGLE-GEN stream] fell back to buffered:', streamErr.message);
        try { answer = await callClaude(stylePrompt, userMsg, 1500, MODEL_HAIKU); }
        catch (e2) { res.write('data: ' + JSON.stringify({ error: e2.message }) + '\n\n'); return res.end(); }
      }
      await pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, question.id]);
      await pool.query('UPDATE sessions SET updated_at = NOW() WHERE id = $1', [req.params.id]);
      res.write('data: ' + JSON.stringify({ done: true, answer }) + '\n\n');
      return res.end();
    }

    const answer = await callClaude(stylePrompt, userMsg, 1500, MODEL_HAIKU);
    console.log(`[SINGLE-GEN] Answer preview: '${answer.substring(0, 100)}...'`);
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
          `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume}\n\nJD:\n${session.jd}\n\nQuestion:\n${batch[0].text}\n\nAnswer the question naturally. Only reference companies or role titles if the question specifically asks about your experience.`,
          1500, MODEL_HAIKU
        );
        await pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, batch[0].id]);
        results.push({ id: batch[0].id, answer });
      } catch(e) { results.push({ id: batch[0].id, error: e.message }); }
    } else {
      const questionsBlock = batch.map((q, idx) => `Q${idx + 1}: ${q.text}`).join('\n');
      try {
        const batchResponse = await callClaude(getBatchPrompt(session.answer_style),
          `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume}\n\nJD:\n${session.jd}\n\n${batch.length} QUESTIONS TO ANSWER:\n${questionsBlock}\n\nAnswer each question naturally. Use the ===Q1=== ===Q2=== format. Only reference companies or role titles when the question specifically asks about experience.`,
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
            const answer = await callClaude(stylePrompt,
              `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume}\n\nJD:\n${session.jd}\n\nQuestion:\n${q.text}\n\nAnswer the question naturally. Only reference companies or role titles if the question specifically asks about your experience.`,
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

// Live-pipeline health — recent events + rolled-up counters so you can see the app
// working (detections, answer latency, growths, learning, errors) without a real interview.
app.get('/api/admin/health', authMiddleware, adminOnly, async (req, res) => {
  try {
    const now = Date.now();
    const hourAgo = now - 60 * 60 * 1000;
    const recent = eventLog.filter(e => e.t >= hourAgo);
    const counts = {};
    let answerMsSum = 0, answerMsN = 0, ttftSum = 0, ttftN = 0;
    for (const e of recent) {
      counts[e.type] = (counts[e.type] || 0) + 1;
      if (e.type === 'answer') {
        if (typeof e.ms === 'number') { answerMsSum += e.ms; answerMsN++; }
        if (typeof e.ttft === 'number' && e.ttft > 0) { ttftSum += e.ttft; ttftN++; }
      }
    }
    res.json({
      now,
      uptimeSec: Math.round((now - SERVER_START) / 1000),
      models: MODELS,
      flags: {
        streamLiveAnswers: process.env.STREAM_LIVE_ANSWERS !== '0',
        growAnswers: process.env.GROW_ANSWERS !== '0'
      },
      lastHour: {
        counts,
        avgAnswerMs: answerMsN ? Math.round(answerMsSum / answerMsN) : null,
        avgTtftMs: ttftN ? Math.round(ttftSum / ttftN) : null,
        errors: recent.filter(e => e.type === 'error').slice(-20)
      },
      activeLiveSessions: (typeof activeLiveByUser !== 'undefined' && activeLiveByUser.size) || 0,
      recent: eventLog.slice(-60)
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
      `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume || 'Experienced professional'}\n\nJD:\n${session.jd || 'Software role'}\n\nQuestion:\n${sampleQ}\n\nAnswer the question naturally. Only reference companies or role titles if the question specifically asks about your experience.`,
      1000, MODEL_HAIKU
    );

    res.json({ style, sampleQuestion: sampleQ, sampleAnswer });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Regenerate answer for a specific question via REST (when WS not available)
app.post('/api/sessions/:id/regenerate', authMiddleware, async (req, res) => {
  try {
    const { questionId, text } = req.body;
    if (!text || !questionId) return res.status(400).json({ error: 'Missing text or questionId' });
    const session = await pool.query('SELECT resume, jd, company, role, answer_style FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!session.rows.length) return res.status(404).json({ error: 'Session not found' });
    const s = session.rows[0];

    const isTechnical = /sql|query|code|write|function|script|algorithm|regex|api|join|window function|python|javascript|html|css|excel|vba|dax|power query|etl|pipeline/i.test(text);
    const stylePrompt = getStylePrompt(s.answer_style);
    const qaRows = await pool.query('SELECT text, answer FROM questions WHERE session_id = $1 AND answer IS NOT NULL AND answer != \'\' LIMIT 15', [req.params.id]);
    const bankContext = qaRows.rows.map(q => `Q: ${q.text}\nA: ${q.answer}`).join('\n\n');

    const answer = await callClaude(
      stylePrompt,
      `RESUME:\n${s.resume || 'N/A'}\n\nJOB DESCRIPTION:\n${s.jd || 'N/A'}\n\nQ&A BANK:\n${bankContext}\n\nQUESTION:\n${text}\n\nAnswer:`,
      isTechnical ? 1200 : 1000, MODEL_HAIKU
    );

    // Update in DB
    await pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, questionId]);
    res.json({ answer, questionId });
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
- For coding: write the COMPLETE working solution in the right language, then ONE line on the approach and its time/space complexity, and handle the obvious edge cases. ACCURACY: sanity-check the syntax and do NOT invent functions, APIs, or flags — a confidently wrong solution is worse than a simple correct one.
- For system design / case-study prompts: give a structured answer — the approach, the key components and tradeoffs, and what you'd clarify first — as short scannable points, not a wall of text.
- For multiple choice: state the correct answer and why
- For data/tables: describe the structure clearly (columns, types, sample data) so future captures can reference it
- For open-ended: answer concisely using the candidate's real experience from their resume and Q&A bank
- Every sentence on its own line
- Lead with the answer — no preamble
- If multiple questions are visible, answer each one separated by a blank line with the question number
- Natural voice, no buzzwords
- Use the candidate's actual experience from the Q&A bank when relevant
- NEVER start with "QUESTION:" or "ANSWER:" labels — just give the answer directly
- NEVER use ANY section headers, labels, or prefixes like "How it works:", "What this does:", "Simple explanation:", "Overview:", "Key points:", "The approach:", "Summary:", etc.
- NEVER use preamble phrases like "Let me explain", "Here's how", "Essentially", "Basically", "To put it simply", "Great question"
- NEVER use closing phrases like "In summary", "Overall", "The key takeaway", "In conclusion"
- First word of output = the answer itself. No intro. No meta-commentary. JUST THE ANSWER.
- Use **bold** on key terms, use bullet points (- ) for listing steps or key points
- Use \`backticks\` for technical terms, SQL keywords, tool names`;

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

// ============ CO-PILOT MODE ============
// Step-by-step task guidance for live task interviews (Excel, SQL, Tableau, etc.)
const copilotMemory = new Map(); // sessionId → { steps: [], lastInstruction: '', context: '' }
const COPILOT_MAX_STEPS = 30;

const COPILOT_PROMPT = `You are a LIVE TASK CO-PILOT. The candidate is in a live interview where they are being asked to perform tasks on screen — this could be any application, website, document, coding challenge, assessment platform, or tool. You see their screen and hear what the interviewer said.

YOUR JOB: Give the candidate the EXACT next step to do. One step at a time. Short. Specific. Actionable.

OUTPUT FORMAT — CRITICAL:
Output ONLY the immediate next step(s) the candidate should take.
Each step = one short line, 3-10 words, starting with the action.
If a formula or code is needed, give the EXACT formula/code to type.
Separate steps with blank lines.

EXAMPLES OF GOOD CO-PILOT OUTPUT:

Interviewer says: "Get distinct values from column B"
Screen shows: Excel with data in column B

Select cell C1

Type: =UNIQUE(B2:B100)

Press Enter

---

Interviewer says: "Now filter to show only values above 500"
Screen shows: Excel with data

Select the data range

Data tab → Filter

Click column dropdown → Number Filters

Greater Than → type 500 → OK

---

Interviewer says: "Write a query to find duplicate emails"
Screen shows: SQL editor

Type this query:

\`\`\`sql
SELECT email, COUNT(*) as cnt
FROM users
GROUP BY email
HAVING COUNT(*) > 1
\`\`\`

Run the query

---

Interviewer says: "Can you find the average response time from that dataset?"
Screen shows: A web-based assessment platform with a table of data

Look at the data table — columns are: Request ID, Timestamp, Response Time (ms), Status

Click the "Response Time (ms)" column header to sort

Calculate average: sum visible values / count of rows

If there's a formula bar or calculation tool, use it — otherwise state the answer verbally

RULES:
- ACTUALLY LOOK AT THE SCREEN IMAGE. Describe what you see FIRST (app name, data visible, current state) before giving steps
- NEVER give generic advice like "Click the Code tab" — be specific to what is ACTUALLY visible on screen
- NEVER explain WHY — just tell them WHAT to do
- NEVER write paragraphs — only short action steps
- Give EXACT formulas, functions, code — not descriptions
- If you see they already did a step, skip it and give the next one
- If the screen shows an error, tell them how to fix it
- Be specific to what's on screen: reference actual cell values, column headers, button labels, menu items you SEE
- For code/formulas: give the complete thing ready to type, wrapped in code blocks
- Use the step history to know what's been done — NEVER repeat a completed step
- If the screen image is blank, black, or you cannot see any application content, say "Screen capture unavailable — try clicking Capture again"
- If no new instruction has been given and screen hasn't changed, output: "Waiting for next instruction..."

STEP HISTORY:
You will receive a history of steps already given. Use this to:
1. Know what the candidate has already been told to do
2. Never repeat those steps
3. Understand the flow of the current task
4. Build on previous steps logically`;

function getCopilotMemory(sessionId) {
  if (!copilotMemory.has(sessionId)) {
    copilotMemory.set(sessionId, { steps: [], lastInstruction: '', context: '' });
  }
  return copilotMemory.get(sessionId);
}

function addCopilotStep(sessionId, instruction, response) {
  const mem = getCopilotMemory(sessionId);
  mem.steps.push({ ts: Date.now(), instruction: instruction || '', response: response.substring(0, 500) });
  if (mem.steps.length > COPILOT_MAX_STEPS) mem.steps = mem.steps.slice(-COPILOT_MAX_STEPS);
  if (instruction) mem.lastInstruction = instruction;
}

app.post('/api/sessions/:id/copilot', authMiddleware, async (req, res) => {
  try {
    const { image, transcript, mode, context } = req.body;
    // mode: 'instruction' (new interviewer speech) or 'check' (manual capture to check progress)
    if (!image && !transcript) return res.status(400).json({ error: 'Need image or transcript' });

    const sessionId = req.params.id;
    const s = await pool.query('SELECT resume, jd, company, role FROM sessions WHERE id = $1 AND user_id = $2', [sessionId, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Session not found' });

    const session = s.rows[0];
    const mem = getCopilotMemory(sessionId);

    // Build step history context
    let stepHistory = '';
    if (mem.steps.length > 0) {
      stepHistory = '\n\nSTEP HISTORY (what has already been done — do NOT repeat these):\n' +
        mem.steps.map((s, i) => {
          let entry = 'Step ' + (i + 1) + ':';
          if (s.instruction) entry += ' [Instruction: ' + s.instruction + ']';
          entry += '\n' + s.response;
          return entry;
        }).join('\n\n');
    }

    let textPrompt = 'INTERVIEW FOR: ' + (session.role || 'this role') + ' at ' + (session.company || 'the company');

    if (transcript) {
      textPrompt += '\n\nINTERVIEWER JUST SAID:\n"' + transcript + '"';
    } else if (mode === 'check') {
      textPrompt += '\n\nThe candidate clicked CAPTURE to check their progress. Look at the screen and tell them the next step based on what you see.';
      if (mem.lastInstruction) {
        textPrompt += '\nLast instruction was: "' + mem.lastInstruction + '"';
      }
    }

    // Append user-uploaded reference materials and custom instructions
    if (context && context.trim()) {
      textPrompt += context;
    }

    textPrompt += stepHistory;
    textPrompt += '\n\nLook at the screen. What should the candidate do RIGHT NOW? Give the exact next step(s).';

    let answer;
    if (image) {
      const mediaMatch = image.match(/^data:image\/([\w+]+);base64,/);
      const mediaType = mediaMatch ? 'image/' + mediaMatch[1] : 'image/jpeg';
      const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
      console.log('[Co-pilot] Image size:', (base64Data.length / 1024).toFixed(0) + 'KB, mode:', mode || 'instruction');
      answer = await callClaudeVision(COPILOT_PROMPT, base64Data, textPrompt, 1000, MODEL_HAIKU, mediaType);
    } else {
      // Audio-only (no screen capture) — just process the instruction
      answer = await callClaude(COPILOT_PROMPT, textPrompt, 1000, MODEL_HAIKU);
    }

    // Save to memory
    addCopilotStep(sessionId, transcript || '', answer);
    console.log('[Co-pilot] Steps in memory:', mem.steps.length, 'for session', sessionId);

    // Broadcast to canvas clients
    broadcastToSession(sessionId, {
      type: 'copilot_step',
      answer: answer,
      instruction: transcript || '',
      stepNumber: mem.steps.length
    });

    res.json({ answer, stepNumber: mem.steps.length });
  } catch (e) {
    console.error('[Co-pilot Error]', e.message, e.stack);
    res.status(500).json({ error: 'Co-pilot failed: ' + e.message });
  }
});

// Extract text from uploaded file for co-pilot context
app.post('/api/sessions/:id/copilot/extract', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const text = await extractText(req.file.buffer, req.file.originalname);
    res.json({ text: text ? text.substring(0, 15000) : '' });
  } catch(e) {
    console.error('[Co-pilot Extract]', e.message);
    res.json({ text: '[Could not extract text]' });
  }
});

// Clear co-pilot memory when session ends
app.post('/api/sessions/:id/copilot/reset', authMiddleware, (req, res) => {
  copilotMemory.delete(req.params.id);
  res.json({ ok: true });
});

// Standalone Smart Canvas page
app.get('/canvas', (req, res) => res.sendFile(path.join(__dirname, 'public', 'canvas.html')));

// Electron launcher page (served from server so API calls are same-origin)
app.get('/launcher', (req, res) => res.sendFile(path.join(__dirname, 'public', 'launcher.html')));

// Download page for Electron overlay app
app.get('/download', (req, res) => res.sendFile(path.join(__dirname, 'public', 'download.html')));

// API: redirect to latest GitHub release download based on platform
app.get('/api/download/latest', async (req, res) => {
  try {
    const platform = (req.query.platform || '').toLowerCase();
    const ghRes = await fetch('https://api.github.com/repos/guru-dev-lab/interview-prep-app/releases/latest');
    if (!ghRes.ok) return res.redirect('/download');
    const release = await ghRes.json();
    const assets = release.assets || [];

    let target = null;
    if (platform === 'mac' || platform === 'macos') {
      target = assets.find(a => a.name.toLowerCase().endsWith('.dmg') && a.name.toLowerCase().includes('arm64'))
            || assets.find(a => a.name.toLowerCase().endsWith('.dmg'));
    } else if (platform === 'win' || platform === 'windows') {
      target = assets.find(a => a.name.toLowerCase().endsWith('.exe'));
    }

    if (target) return res.redirect(target.browser_download_url);
    res.redirect('/download');
  } catch (e) {
    res.redirect('/download');
  }
});

// Serve frontend (MUST be last — catch-all for SPA routing)
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ============ HTTP + WEBSOCKET SERVER ============
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Session-level client tracking — broadcast to all clients (main app + canvas windows) for same session
const sessionClients = new Map(); // sessionId -> Set of ws connections
const activeLiveByUser = new Map(); // userId -> { ws, sessionId, platform } — only ONE live session per user

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
const MATCH_THRESHOLD = 0.50; // Raised from 0.45 — must be at least 50% match or generate fresh answer
// Above this blended score, a match is near-identical phrasing — trust it and skip
// the Haiku semantic-verify round-trip (scores are 0..1; MATCH_THRESHOLD is the floor).
// Conservative on purpose: only very confident lexical+semantic matches skip verification.
const HIGH_CONFIDENCE_MATCH = 0.75;

// Quick regex cleanup — fast, runs on every text. AI cleanup runs after for detected questions.
function cleanQuestionText(text) {
  var t = text.trim();
  // Strip [You] / [Echo] markers if they leaked through
  t = t.replace(/^\[(You|Echo)\]\s*/i, '').trim();
  // Basic leading filler strip
  t = t.replace(/^(okay so[,:]?\s*|alright[,:]?\s*|so[,:]?\s*|now[,:]?\s*|um[,:]?\s*|uh[,:]?\s*|well[,:]?\s*|and[,:]?\s*|but[,:]?\s*|the next question is[,:]?\s*|let me ask you[,:]?\s*|here's (?:a|another) question[,:]?\s*|moving on[,:]?\s*|next[,:]?\s*)/i, '').trim();
  if (t.length > 0) t = t.charAt(0).toUpperCase() + t.slice(1);
  return t;
}

// AI-powered question cleanup — Haiku extracts JUST the clean question from messy speech
async function aiCleanQuestion(rawText) {
  try {
    const cleaned = await Promise.race([
      callClaude(
        'You clean up interview questions from live speech transcripts. The input may contain filler, preamble, or conversation before the actual question. Extract ONLY the clean interview question — nothing else. Keep the full question intact including the question word (What, How, Can you, Tell me, etc.). Never cut off the beginning of the question. If the input IS already a clean question, return it as-is. Output ONLY the clean question text, no quotes, no explanation.',
        'Clean this: ' + rawText,
        80, MODEL_HAIKU
      ),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 1500))
    ]);
    const result = cleaned.trim().replace(/^["']|["']$/g, '');
    // Sanity check: AI result should be shorter or similar length, and not empty
    if (result && result.length >= 5 && result.length <= rawText.length + 10) {
      return result;
    }
    return cleanQuestionText(rawText); // fallback to regex
  } catch (e) {
    return cleanQuestionText(rawText); // timeout — use regex
  }
}

function isQuestion(text) {
  const t = text.trim().toLowerCase();
  const words = t.split(/\s+/).length;
  // Minimum: 3 words, 15 chars
  if (words < 3 || t.length < 15) return false;
  // === REJECTION FILTERS ===
  // Reject self-referencing (interviewee/candidate talking about themselves)
  if (/^(i |i'm |i've |i'd |i'll |i was |i did |i do |i think |i would |i could |i should |i used |i built |i have |i had |i made |i learned |i managed |i led |i created |i developed |i worked |i helped |i started |i ran |i set up |i implemented |i designed |i analyzed |i handled |i owned |i drove |so i |yeah i |and i |we |we're |we've |we had |we did |we used |we built |we were |my |at my |in my |on my |with my |during my |let me |if i |when i |that's |that is |it's |it is |this is |this was |there |the |a |an |at |for |from |like |actually |basically |just |one thing |one of |another thing |specifically )/.test(t)) return false;
  // Reject filler/agreement/casual speech
  if (/^(yeah|yes|no|okay|sure|right|exactly|absolutely|definitely|great|good|thanks|thank you|sorry|so basically|um |uh |well |hmm|oh |and |but |or |also |then |so |awesome|perfect|wonderful|fantastic|sounds good|makes sense|got it|fair enough|interesting|nice|cool|alright|let's |now |moving on|next |going to |to answer |to give |to be |in terms of |because |since |as a |as an |which |that |the way |the reason |what happened |what we )/.test(t)) return false;
  // Reject mid-answer continuation patterns (candidate elaborating)
  if (/^(and then |so then |after that |from there |eventually |ultimately |overall |in the end |long story short |to summarize |the result |the outcome |the impact |the challenge |the problem |the solution |the key |the main |the biggest |the first |the second |the third )/.test(t)) return false;
  // Reject casual small-talk / pleasantries
  if (/^(how are you|how's it going|how have you been|nice to meet|good to meet|good morning|good afternoon|good evening|hey |hi |hello |what time|what's your time|where are you (based|located|calling|joining)|are you (doing well|ready)|can you hear me|is (my|the) (audio|video|screen)|one (moment|second|sec)|bear with me|sorry about|apologies for)/.test(t)) return false;
  // Reject scheduling/logistics
  if (/^(do you have any questions|any questions (for|from) (me|us)|that's (all|it|everything)|we('re| are) (running|almost)|let's (wrap|move|end)|before we (end|wrap|go))/.test(t)) return false;
  // === PASS FILTERS — must match a specific question pattern ===
  // Question mark with at least 5 words — real questions
  if (/\?/.test(t) && words >= 5) return true;
  // Direct interview commands (3+ words): "Explain X", "Tell me about X", "Describe X"
  if (words >= 3 && /^(explain |define |describe |compare |walk me through |tell me |give me an example |give me a scenario )/.test(t)) return true;
  // Common interviewer question starters (4+ words) — speech-to-text rarely adds "?"
  if (words >= 4 && /^(can you |could you |have you |had you |do you |did you |would you |are you |were you |is there |was there |have there been )/.test(t)) return true;
  // Wh- question openers (5+ words)
  if (words >= 5 && /^(what |how |why |when |where |who |which )/.test(t)) return true;
  // Nothing matched — NOT a question
  return false;
}

// "Stay silent" filter — clearly NON-substantive interviewer utterances that can slip past
// isQuestion (rapport, logistics, comprehension check-ins, closing). Conservative on purpose:
// only the obvious stuff is matched — anything that could be a real interview question is not.
function isLowValueQuestion(text) {
  const t = (text || '').trim().toLowerCase();
  // meta / comprehension check-ins
  if (/^(does that make sense|is that clear|did that (make sense|answer|help)|any questions (so far|on that)|are you (with me|following)|makes sense\??$|got it\??$|any concerns)/.test(t)) return true;
  // rapport / small talk
  if (/^(how are you( doing| today)?|how('s| is) (your day|it going|everything|the weather)|how has your (day|week) been|hope you('re| are) (well|doing well))/.test(t)) return true;
  // logistics / setup
  if (/^(can you (see|hear) (me|my|the)|are you able to (see|hear)|is my (screen|audio|video)|are you ready( to (start|begin))?|shall we (start|begin|get started)|ready to (start|begin|go)|do you have (your resume|a copy|everything you need)|can you give me (a|one) (second|moment))/.test(t)) return true;
  // closing / time
  if (/^(do you have any questions (for|from) (me|us)|any questions for (me|us)|that('s| is) (all|it|everything)( i had| from me)?|we('re| are) (about )?(at|out of|running out of) time|anything (else )?(you('d| would) like to (ask|add|know))|before we (wrap|finish|end))/.test(t)) return true;
  return false;
}

// Does the buffer already contain a COMPLETE question? Used for eager detection so we can
// answer without waiting for the interviewer to pause (e.g. a video that never stops talking).
function looksLikeCompleteQuestion(buf) {
  const t = (buf || '').trim();
  const words = t.split(/\s+/).length;
  if (words < 4) return false;
  if (/\?\s*$/.test(t)) return true; // punctuate=true adds '?' at question end
  if (words >= 6 && /^(can you|could you|tell me|what|how|why|when|where|which|walk me through|describe|explain|do you|have you|would you|give me)\b/i.test(t)) return true;
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
async function fastMatchAndRespond(utterance, sessionQuestions, sessionId, userId, ws, lastMatchedQId, recentMatchedIds, questionIndex, onIndexRebuild, skipFilter, forceNavigate, skipClean) {
  const startMs = Date.now();
  const tClean = Date.now();
  const q = skipClean ? utterance.trim() : await aiCleanQuestion(utterance.trim());
  if (!q || q.length < 5) return lastMatchedQId;
  if (!skipFilter && !isQuestion(q)) return lastMatchedQId;
  if (!skipClean) console.log(`[TIMING] aiCleanQuestion: ${Date.now() - tClean}ms`);

  // Get top 3 keyword candidates, excluding already-matched questions
  const topMatches = findTopMatches(q, sessionQuestions, questionIndex, 3)
    .filter(m => m.question.id !== lastMatchedQId && !recentMatchedIds?.has?.(m.question.id));

  if (topMatches.length > 0) {
    // FAST PATH: if the top candidate is a near-identical (very high confidence) match,
    // trust it and skip the Haiku verification round-trip. Saves ~1 API call of latency
    // AND one Haiku call of cost on the common "question is already in the bank" case.
    // Anything below the bar still goes through full AI verification as before.
    let verified;
    if (topMatches[0].similarity >= HIGH_CONFIDENCE_MATCH) {
      console.log(`[FastMatch] High-confidence match (${Math.round(topMatches[0].similarity * 100)}%) — skipping AI verify`);
      verified = topMatches[0];
    } else {
      const tVerify = Date.now();
      verified = await verifyMatch(q, topMatches, ws._sessionContext, 1500); // tighter timeout — fail fast to the answer
      console.log(`[TIMING] verifyMatch: ${Date.now() - tVerify}ms`);
    }

    if (verified) {
      const elapsed = Date.now() - startMs;
      console.log(`[FastMatch+AI] VERIFIED in ${elapsed}ms: "${q.substring(0,40)}..." → "${verified.question.text.substring(0,40)}..." (${Math.round(verified.similarity*100)}%)`);

      const matchMsg = {
        type: 'match',
        questionId: verified.question.id,
        questionText: verified.question.text,
        answer: verified.question.answer || '',
        similarity: Math.round(verified.similarity * 100),
        hasAnswer: !!verified.question.answer,
        navigate: !!forceNavigate
      };
      ws.send(JSON.stringify(matchMsg));
      broadcastToSession(sessionId, matchMsg, ws);
      recentMatchedIds.add(verified.question.id);
      // Track as active thread so continued detail can grow it on-screen.
      // _prepped:true → growth updates the display but never overwrites the bank answer in the DB.
      if (verified.question.answer) {
        ws._activeAnswer = { id: verified.question.id, questionText: verified.question.text, answer: verified.question.answer, _grows: 0, _prepped: true };
      }
      return verified.question.id;
    }
    // Haiku said NONE — keyword matches were false positives, create new question
    console.log(`[FastMatch+AI] Haiku rejected all ${topMatches.length} candidates — creating new question`);
  }

  // No matches above threshold, or Haiku rejected all — create new question + generate answer
  const elapsed = Date.now() - startMs;
  console.log(`[FastMatch] NO MATCH in ${elapsed}ms: "${q.substring(0,50)}..." — creating new question`);

  // PRE-GEN HIT: did we already prepare this (a predicted follow-up)? Serve it INSTANTLY,
  // skipping the generation round-trip entirely.
  if (process.env.PREGEN_FOLLOWUPS !== '0' && ws._pregen && ws._pregen.length) {
    for (let pi = 0; pi < ws._pregen.length; pi++) {
      const pg = ws._pregen[pi];
      if (pg && pg.answer && stringSimilarity.compareTwoStrings(q.toLowerCase(), pg.q.toLowerCase()) >= 0.55) {
        try {
          const nq = await pool.query('INSERT INTO questions (session_id, text, type, answer, source) VALUES ($1, $2, $3, $4, $5) RETURNING id', [sessionId, q, classifyQuestion(q), pg.answer, 'live']);
          const qId = nq.rows[0].id;
          ws._pregen.splice(pi, 1);
          const nqMsg = { type: 'new_question', questionId: qId, questionText: q, questionType: classifyQuestion(q), source: 'live', generated: true, navigate: !!forceNavigate };
          ws.send(JSON.stringify(nqMsg)); broadcastToSession(sessionId, nqMsg, ws);
          const laMsg = { type: 'live_answer', questionId: qId, questionText: q, answer: pg.answer, isNew: true, navigate: !!forceNavigate };
          ws.send(JSON.stringify(laMsg)); broadcastToSession(sessionId, laMsg, ws);
          sessionQuestions.push({ id: qId, text: q, type: classifyQuestion(q), answer: pg.answer, _createdAt: Date.now(), source: 'live' });
          if (onIndexRebuild) onIndexRebuild();
          ws._activeAnswer = { id: qId, questionText: q, answer: pg.answer, _grows: 0, _prepped: false };
          logEvent('pregen_hit', { sessionId, qid: qId, q: q.substring(0, 60) });
          console.log('[PreGen] Served instant answer for anticipated follow-up');
          return lastMatchedQId;
        } catch (e) { console.error('[PreGen hit]', e.message); }
      }
    }
  }

  // DEDUP: Check if a very similar live question was created in the last 60 seconds
  // This prevents duplicate cards when the interviewer's question arrives in fragments
  const recentLiveQ = sessionQuestions.filter(sq => sq.source === 'live' && sq._createdAt && (Date.now() - sq._createdAt) < 60000);
  for (const rlq of recentLiveQ) {
    const sim = stringSimilarity.compareTwoStrings(q.toLowerCase(), rlq.text.toLowerCase());
    if (sim > 0.4 || rlq.text.toLowerCase().includes(q.toLowerCase().substring(0, 20)) || q.toLowerCase().includes(rlq.text.toLowerCase().substring(0, 20))) {
      console.log(`[FastMatch] DEDUP: "${q.substring(0,40)}" matches recent "${rlq.text.substring(0,40)}" (sim=${sim.toFixed(2)}) — updating instead`);
      // Update the existing question with the fuller text
      const betterText = q.length > rlq.text.length ? q : rlq.text;
      rlq.text = betterText;
      pool.query('UPDATE questions SET text = $1 WHERE id = $2', [betterText, rlq.id]).catch(e => console.error('[Dedup update error]', e.message));
      // Regenerate answer with the fuller question
      generateLiveAnswer(betterText, sessionId, userId, ws, rlq.id, !!forceNavigate).catch(e => console.error('[Dedup regen error]', e.message));
      return lastMatchedQId;
    }
  }

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
      generated: true,  // Flag for frontend: this is an AI-generated answer, not from bank
      navigate: !!forceNavigate
    };
    ws.send(JSON.stringify(newQMsg));
    broadcastToSession(sessionId, newQMsg, ws);

    sessionQuestions.push({ id: qId, text: q, type: classifyQuestion(q), answer: '' });
    sessionQuestions[sessionQuestions.length - 1]._createdAt = Date.now();
    sessionQuestions[sessionQuestions.length - 1].source = 'live';
    if (onIndexRebuild) onIndexRebuild();

    // Fire answer generation in background
    generateLiveAnswer(q, sessionId, userId, ws, qId, !!forceNavigate).then(() => {
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
  let _dgMsgCount = 0;
  dgWs.on('open', () => {
    console.log('[Deepgram] Stream connected — ready to receive audio');
    if (dgWs._onOpen) dgWs._onOpen();
  });
  dgWs.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      _dgMsgCount++;
      if (_dgMsgCount <= 3 || _dgMsgCount % 50 === 0) {
        console.log(`[DIAG-DG] msg#${_dgMsgCount} type=${msg.type} transcript="${(msg.channel?.alternatives?.[0]?.transcript || '').substring(0,40)}"`);
      }
      if (msg.type === 'Results' && msg.channel?.alternatives?.[0]) {
        const text = msg.channel.alternatives[0].transcript || '';
        if (text.trim()) onTranscript(text, msg.is_final, msg.speech_final);
      }
    } catch (e) { console.error('[Deepgram] Parse error:', e.message); }
  });
  dgWs.on('error', (err) => { console.error('[Deepgram] WS error:', err.message); onError(err); });
  dgWs.on('close', (code, reason) => console.log(`[Deepgram] Stream closed code=${code} reason=${reason}`));
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
  let idleWarningTimer = null;
  const IDLE_TIMEOUT = 10 * 60 * 1000; // 10 minutes — interviewer may leave and rejoin
  const IDLE_WARNING = 8 * 60 * 1000; // Warn at 8 minutes
  function resetIdleTimer() {
    if (isCanvasMode) return; // canvas clients don't have idle timeout
    clearTimeout(idleTimer);
    clearTimeout(idleWarningTimer);
    idleWarningTimer = setTimeout(() => {
      try { ws.send(JSON.stringify({ type: 'status', message: 'No audio for 8 min — live will end in 2 min if silence continues' })); } catch(e) {}
    }, IDLE_WARNING);
    idleTimer = setTimeout(() => {
      console.log('[WS] Idle timeout — closing connection');
      try { ws.send(JSON.stringify({ type: 'status', message: 'Live mode ended — idle timeout (10 min no audio)' })); } catch(e) {}
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

  let _audioPktCount = { 1: 0, 2: 0 };
  let _dgSendCount = { 1: 0, 2: 0 };
  let _dgBufferCount = { 1: 0, 2: 0 };
  let _dgDropCount = { 1: 0, 2: 0 };

  ws.on('message', async (rawData) => {
    // Binary audio data: first byte = channel (1=interviewer, 2=user)
    if (rawData instanceof Buffer && rawData.length > 1 && rawData[0] !== 0x7b) {
      const channel = rawData[0];
      const audio = rawData.slice(1);

      _audioPktCount[channel] = (_audioPktCount[channel] || 0) + 1;
      // Log every 100th packet with full state
      if (_audioPktCount[channel] % 100 === 1) {
        const dgObj = channel === 1 ? interviewerDG : userDG;
        const setupFn = channel === 1 ? ws._setupInterviewerDG : ws._setupUserDG;
        console.log(`[DIAG] Ch${channel} pkt#${_audioPktCount[channel]} | audio=${audio.length}B | DG=${dgObj ? ['CONNECTING','OPEN','CLOSING','CLOSED'][dgObj.readyState] : 'null'} | setupFn=${!!setupFn} | sent=${_dgSendCount[channel]} buf=${_dgBufferCount[channel]} drop=${_dgDropCount[channel]}`);
      }

      // Lazy Deepgram init: open streams on first audio packet, not on 'start' message.
      // This prevents Deepgram from timing out idle connections while the user
      // hasn't clicked Go Live yet.
      if (channel === 1 && !interviewerDG && ws._setupInterviewerDG) {
        console.log('[Audio] First Ch1 packet — opening Deepgram interviewer stream');
        ws._setupInterviewerDG();
      }
      if (channel === 2 && !userDG && ws._setupUserDG) {
        console.log('[Audio] First Ch2 packet — opening Deepgram user stream');
        ws._setupUserDG();
      }

      // Also re-open if Deepgram closed (idle timeout, error, etc)
      if (channel === 1 && interviewerDG && interviewerDG.readyState > WebSocket.OPEN && ws._setupInterviewerDG) {
        console.log('[Audio] Ch1 Deepgram closed, reopening');
        interviewerDG = null;
        ws._setupInterviewerDG();
      }
      if (channel === 2 && userDG && userDG.readyState > WebSocket.OPEN && ws._setupUserDG) {
        console.log('[Audio] Ch2 Deepgram closed, reopening');
        userDG = null;
        ws._setupUserDG();
      }

      // Route audio to Deepgram — with buffering for CONNECTING state
      if (channel === 1 && interviewerDG) {
        if (interviewerDG.readyState === WebSocket.OPEN) {
          if (ws._audioBuffer1 && ws._audioBuffer1.length) {
            console.log('[Audio] Flushing', ws._audioBuffer1.length, 'buffered Ch1 packets inline');
            ws._audioBuffer1.forEach(buf => interviewerDG.send(buf));
            _dgSendCount[1] += ws._audioBuffer1.length;
            ws._audioBuffer1 = [];
          }
          interviewerDG.send(audio);
          _dgSendCount[1]++;
        } else if (interviewerDG.readyState === WebSocket.CONNECTING) {
          if (!ws._audioBuffer1) ws._audioBuffer1 = [];
          ws._audioBuffer1.push(audio);
          _dgBufferCount[1]++;
        } else {
          _dgDropCount[1]++;
        }
      } else if (channel === 1) {
        _dgDropCount[1]++;
      }
      if (channel === 2 && userDG) {
        if (userDG.readyState === WebSocket.OPEN) {
          if (ws._audioBuffer2 && ws._audioBuffer2.length) {
            console.log('[Audio] Flushing', ws._audioBuffer2.length, 'buffered Ch2 packets inline');
            ws._audioBuffer2.forEach(buf => userDG.send(buf));
            _dgSendCount[2] += ws._audioBuffer2.length;
            ws._audioBuffer2 = [];
          }
          userDG.send(audio);
          _dgSendCount[2]++;
        } else if (userDG.readyState === WebSocket.CONNECTING) {
          if (!ws._audioBuffer2) ws._audioBuffer2 = [];
          ws._audioBuffer2.push(audio);
          _dgBufferCount[2]++;
        } else {
          _dgDropCount[2]++;
        }
      } else if (channel === 2) {
        _dgDropCount[2]++;
      }
      return;
    }

    // JSON messages
    try {
      const msg = JSON.parse(rawData.toString());

      // Volume-based self-voice detection: frontend reports when user is speaking
      if (msg.type === 'user_speaking') {
        userIsSpeaking = msg.speaking;
        if (!msg.speaking) userStoppedSpeakingAt = Date.now();
        if (msg.speaking) resetIdleTimer(); // Your voice keeps the session alive
        return;
      }

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

        // ===== SINGLE-DEVICE LIVE ENFORCEMENT =====
        // Only one full-live (non-canvas) connection per user at a time.
        // If user goes live on Electron, kick the web one (and vice versa).
        if (!isCanvasMode) {
          const platform = msg.platform || 'web'; // canvas.html sends 'electron' or 'web'
          const existing = activeLiveByUser.get(userId);
          if (existing && existing.ws !== ws && existing.ws.readyState === WebSocket.OPEN) {
            console.log(`[Live] Kicking previous live session for user ${userId} (was ${existing.platform}, now ${platform})`);
            try {
              existing.ws.send(JSON.stringify({ type: 'kicked', message: 'Live session started on another device' }));
              existing.ws.close(4001, 'Replaced by new live session');
            } catch(e) {}
          }
          activeLiveByUser.set(userId, { ws, sessionId, platform });
        }

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
          ws._maxAnswerLines = 5; // Default: short answers
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
        ws._maxAnswerLines = 5; // Default: short answers (canvas can override via update_settings)

        // Create transcript record — attach current meeting's interviewer info
        let interviewerName = '', interviewerTitle = '', interviewStage = '';
        try {
          const cm = await pool.query('SELECT name, title, stage FROM meetings WHERE session_id = $1 AND is_current = true LIMIT 1', [sessionId]);
          if (cm.rows.length) { interviewerName = cm.rows[0].name || ''; interviewerTitle = cm.rows[0].title || ''; interviewStage = cm.rows[0].stage || ''; }
        } catch(e) {}
        // Stash interviewer identity so answers can be tailored to who's actually asking.
        ws._interviewer = { name: interviewerName, title: interviewerTitle, stage: interviewStage };
        // Load THIS user's own voice profile (per-user) so answers sound like them.
        try {
          const vp = await pool.query('SELECT voice_profile FROM users WHERE id = $1', [userId]);
          ws._voiceProfile = (process.env.VOICE_PROFILE !== '0' && vp.rows[0] && vp.rows[0].voice_profile) || '';
        } catch (e) { ws._voiceProfile = ''; }
        const tResult = await pool.query(
          'INSERT INTO live_transcripts (session_id, user_id, interviewer_name, interviewer_title, stage) VALUES ($1, $2, $3, $4, $5) RETURNING id',
          [sessionId, userId, interviewerName, interviewerTitle, interviewStage]
        );
        transcriptId = tResult.rows[0].id;
        transcript = [];
        lastMatchedQId = null;
        let lastAutoMatchTime = 0; // Timestamp of last auto-detected match
        const AUTO_MATCH_COOLDOWN = 15000; // 15s cooldown — responsive detection while avoiding rapid switching

        // Single Deepgram stream — two detection layers:
        // 1. Fast: isQuestion() pattern match fires instantly on obvious questions
        // 2. Smart: On every speechFinal, Haiku extracts the question from recent transcript
        //    (same logic as "What should I say?" but automatic)
        let questionFiredForBuffer = false;
        let lastAiExtractedQ = ''; // prevent re-firing same extracted question
        let recentDetectedQs = []; // last 5 detected questions for fuzzy de-dup
        let aiExtractTimer = null; // debounce timer — wait for speech to settle before extracting
        const AI_EXTRACT_DELAY = 800; // wait after last speechFinal before AI fires (trimmed for speed)
        let userIsSpeaking = false; // Volume-based: true when user is talking into mic
        let userStoppedSpeakingAt = 0; // Timestamp when user stopped speaking
        const USER_SPEECH_GUARD = 2000; // 2s after user stops speaking before allowing detection
        let lastCommitTs = 0; // last time an interviewer utterance was committed (paces eager detection)

        // AI auto-extract: send recent transcript to Haiku, get the question
        async function aiAutoExtract() {
          const inCooldown = (Date.now() - lastAutoMatchTime < AUTO_MATCH_COOLDOWN);
          const growEnabled = process.env.GROW_ANSWERS !== '0';
          // While cooling down we still run detection, but ONLY to catch the interviewer
          // elaborating on the answer already on screen (so we can grow it). If growth is
          // off or nothing is active, keep the original cheap early-return.
          if (inCooldown && (!growEnabled || !ws._activeAnswer)) return;

          // VOLUME GUARD: If user is currently speaking or JUST stopped speaking,
          // skip extraction — this is the user's answer, not the interviewer's question.
          if (userIsSpeaking) {
            console.log('[AI Auto-Detect] Skipping — user is speaking (volume high)');
            return;
          }
          if (Date.now() - userStoppedSpeakingAt < USER_SPEECH_GUARD) {
            console.log('[AI Auto-Detect] Skipping — user just stopped speaking (' + Math.round((Date.now() - userStoppedSpeakingAt)/1000) + 's ago)');
            return;
          }

          // CRITICAL: Only use INTERVIEWER utterances for question detection.
          // Filter out [You] (user's own voice) and [Echo] (user voice echoing through system audio).
          const interviewerOnly = transcript.filter(t => !t.isUser && !t.isEcho);
          const recent = interviewerOnly.slice(-4);
          if (recent.length < 1) return;

          // PRE-FILTER: Check if the most recent utterance could even be a question.
          // If the last utterance is clearly the candidate speaking (starts with "I", "We", "My", etc.),
          // skip AI extraction entirely — saves tokens and prevents false positives.
          const lastUtterance = recent[recent.length - 1].text;

          // LENGTH GUARD: Very long utterances (50+ words) are almost certainly the candidate
          // giving an extended answer, not the interviewer asking a question.
          const wordCount = lastUtterance.trim().split(/\s+/).length;
          if (wordCount > 50) {
            console.log('[AI Auto-Detect] Pre-filter: too long (' + wordCount + ' words), likely candidate answer');
            return;
          }
          const lastLow = lastUtterance.trim().toLowerCase();
          // Reject if it starts with obvious candidate self-reference
          if (/^(i |i'm |i've |i'd |i'll |i was |i did |i do |i think |i would |i could |i used |i built |i have |i had |i made |i worked |i helped |i started |i led |i created |i developed |i analyzed |i handled |we |we're |we've |we had |we did |we used |we built |my |at my |in my |so i |yeah i |and i |yeah |yes |no |okay |sure |right |exactly |absolutely |definitely |great |good |thanks |sorry |so basically |um |uh |well |hmm|actually |basically |just |and then |so then |after that |from there |the way i |the reason |what happened was |what we did )/.test(lastLow)) {
            console.log('[AI Auto-Detect] Pre-filter: candidate speech, skipping');
            return;
          }

          const recentText = recent.slice(-3).map(t => t.text.replace(/^\[(You|Echo)\]\s*/i, '')).join('\n');
          const wsCtx = ws._sessionContext || {};
          const ctxLine = (wsCtx.company || wsCtx.role) ? `Interview for ${wsCtx.role || 'a role'} at ${wsCtx.company || 'a company'}.\n` : '';

          try {
            const t0 = Date.now();
            const extracted = await Promise.race([
              callClaude(
                'You detect interview questions from an interviewer in live speech transcripts. Extract the CLEAN question directly — no filler, no preamble. Keep the full question word intact.\n\nCRITICAL RULES:\n1. ONLY return a question if the INTERVIEWER is clearly asking the candidate a substantive interview question.\n2. The CANDIDATE\'s own speech is NEVER a question. Output NONE.\n3. Output NONE for: statements, agreements, filler, partial sentences, transitions, pleasantries, small talk.\n4. Signs of CANDIDATE speech (always NONE): starts with "I", "We", "My", talks about their experience.\n5. Signs of INTERVIEWER question: asks "Can you tell me about...", "How would you...", "What is your experience with...".\n6. MULTI-PART QUESTIONS: If the interviewer asks a main question then adds a follow-up like "how would you approach this?" or "can you walk me through that?" or "what would you do?", combine them into ONE question. The follow-up is part of the same question, NOT a separate question. Example: "What is the difference between inner join and left join? How would you approach this problem?" → output the FULL combined question.\n\nIf a question is present, output ONLY the clean question text — already cleaned, no quotes, no explanation. Otherwise output exactly: NONE',
                ctxLine + 'Recent speech:\n' + recentText + '\n\nOutput the clean interview question (combine multi-part questions into one) or NONE:',
                80, MODEL_HAIKU
              ),
              new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 2500))
            ]);
            console.log(`[TIMING] AI extract: ${Date.now() - t0}ms`);
            const raw = extracted.trim().replace(/^["']|["']$/g, '');
            // Strong filtering: reject if NONE anywhere, prompt fragments leak, or multi-line
            if (!raw || /\bNONE\b/i.test(raw)) return;
            if (/output the question|interview question being asked|wait for the interviewer|speech is (incomplete|just)|small talk|filler/i.test(raw)) return;
            // Real questions are single-line; multi-line means Haiku is explaining itself
            const firstLine = raw.split(/\n/)[0].trim();
            if (!firstLine || firstLine.length < 10) return;
            // AI extraction already returns a clean question — just basic trim, skip redundant Haiku call
            const q = cleanQuestionText(firstLine);

            // Post-filter: even after AI extraction, run isQuestion() to catch false positives
            if (!isQuestion(q)) {
              console.log('[AI Auto-Detect] Post-filter rejected:', q.substring(0, 60));
              return;
            }

            // CONTINUATION: the interviewer is elaborating on the SAME question we're already
            // answering → grow that answer in place (append), instead of a new card. This
            // bypasses the recent-question dedup and the cooldown on purpose.
            if (growEnabled && ws._activeAnswer && isSameThread(q, ws._activeAnswer)) {
              console.log('[Grow] Continuation detected — extending active answer');
              growLiveAnswer(ws, sessionId, ws._activeAnswer, q).catch(e => console.error('[Grow]', e.message));
              return;
            }

            // STAY SILENT: don't clutter the overlay with clearly non-substantive interviewer
            // talk (rapport, logistics, "does that make sense?", closing). Conservative + flagged.
            if (process.env.STAY_SILENT !== '0' && isLowValueQuestion(q)) {
              console.log('[Stay Silent] Skipping low-value question:', q.substring(0, 50));
              logEvent('stay_silent', { sessionId, q: q.substring(0, 50) });
              return;
            }

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
            // Genuinely different question — respect the cooldown so we don't refocus onto
            // side-topics and throw junk on screen while the candidate is still answering.
            if (inCooldown) { console.log('[AI Auto-Detect] Different question during cooldown — holding'); return; }

            lastAiExtractedQ = q;
            recentDetectedQs.push(q);
            if (recentDetectedQs.length > 5) recentDetectedQs.shift();

            console.log('[AI Auto-Detect]', q.substring(0, 60));
            logEvent('detect', { sessionId, q: q.substring(0, 60) });
            lastWsayMatchId = null;
            recentMatchedIds.clear();
            var qdMsg1 = { type: 'question_detected', text: q, source: 'auto' };
            ws.send(JSON.stringify(qdMsg1));
            broadcastToSession(sessionId, qdMsg1, ws);
            const rebuildIdx = () => { questionIndex = buildQuestionIndex(sessionQuestions); };
            fastMatchAndRespond(q, sessionQuestions, sessionId, userId, ws, lastMatchedQId, recentMatchedIds, questionIndex, rebuildIdx, false, false, true).then(newLastId => {
              if (newLastId) { lastMatchedQId = newLastId; lastAutoMatchTime = Date.now(); }
            });
          } catch (e) {
            // Timeout or error — silent, don't block
            console.log('[AI Auto-Detect] Skip:', e.message);
          }
        }

        // ===== ECHO DETECTION via transcript comparison =====
        // Ch1 (system audio) captures BOTH interviewer AND user's echo from the call.
        // Instead of blocking audio, we compare Ch1 transcripts against recent Ch2 (mic)
        // transcripts. If they match, it's the user's echo — skip question detection.
        const recentUserUtterances = []; // { text, ts } — rolling buffer of Ch2 transcripts
        const ECHO_WINDOW_MS = 6000; // Compare against user speech from last 6 seconds
        const ECHO_SIMILARITY_THRESHOLD = 0.45; // Similarity above this = echo

        function isEchoOfUser(ch1Text) {
          const now = Date.now();
          const ch1Lower = ch1Text.toLowerCase().trim();
          // Check against recent user utterances
          for (let i = recentUserUtterances.length - 1; i >= 0; i--) {
            const u = recentUserUtterances[i];
            if (now - u.ts > ECHO_WINDOW_MS) break; // Too old
            const sim = stringSimilarity.compareTwoStrings(ch1Lower, u.text.toLowerCase());
            // Also check if one is a substring of the other (partial echo)
            const isSubstring = ch1Lower.length > 10 && u.text.toLowerCase().length > 10 &&
              (ch1Lower.includes(u.text.toLowerCase().substring(0, Math.min(30, u.text.length))) ||
               u.text.toLowerCase().includes(ch1Lower.substring(0, Math.min(30, ch1Lower.length))));
            if (sim > ECHO_SIMILARITY_THRESHOLD || isSubstring) {
              console.log(`[Echo Detect] Ch1 matched Ch2 (sim=${sim.toFixed(2)}): "${ch1Text.substring(0,40)}" ≈ "${u.text.substring(0,40)}"`);
              return true;
            }
          }
          return false;
        }

        // Deferred Deepgram setup — opened lazily when first audio packet arrives.
        // This prevents Deepgram idle timeout (10s) killing the connection before
        // the user clicks Go Live (which could be minutes after WS connects).
        ws._setupInterviewerDG = function() {
          if (interviewerDG && interviewerDG.readyState <= WebSocket.OPEN) return;
          console.log('[Deepgram] Opening interviewer stream (lazy)');
          ws._audioBuffer1 = []; // init buffer for packets arriving while CONNECTING
          interviewerDG = openDeepgramStream(
            (text, isFinal, speechFinal) => {
              console.log(`[DIAG-DG] Ch1 transcript: "${text.substring(0,60)}" isFinal=${isFinal} speechFinal=${speechFinal}`);
              if (!text.trim()) return;

              // Commit an interviewer utterance: echo-check, push to transcript, schedule detection.
              // `eager` = fired mid-stream on a complete question (short debounce); else = on a pause.
              const commitInterviewer = (fullUtterance, eager) => {
                const isEcho = isEchoOfUser(fullUtterance);
                ws.send(JSON.stringify({ type: 'transcript', text: fullUtterance, isFinal: true, isEcho: isEcho }));
                if (!isEcho) broadcastToSession(sessionId, { type: 'interviewer_final', text: fullUtterance }, ws);
                transcript.push({ text: isEcho ? '[Echo] ' + fullUtterance : fullUtterance, ts: Date.now(), isEcho: isEcho });
                ws._recentTranscript = transcript.slice(-6).map(t => t.text);
                if (!isEcho) {
                  if (aiExtractTimer) clearTimeout(aiExtractTimer);
                  aiExtractTimer = setTimeout(() => { aiExtractTimer = null; aiAutoExtract(); }, eager ? 300 : AI_EXTRACT_DELAY);
                  setTimeout(() => recentMatchedIds.clear(), 5000);
                }
              };

              if (isFinal) {
                resetIdleTimer();
                interviewerBuffer += (interviewerBuffer ? ' ' : '') + text.trim();
                ws.send(JSON.stringify({ type: 'transcript', text: interviewerBuffer, isFinal: false }));
                // EAGER: a complete question is already on the table — don't wait for a pause.
                // Rate-limited so continuous speech commits at most ~once/1.5s; dedup handles repeats.
                if (process.env.EAGER_DETECT !== '0' && looksLikeCompleteQuestion(interviewerBuffer) && Date.now() - lastCommitTs > 1500) {
                  lastCommitTs = Date.now();
                  const fu = interviewerBuffer.trim();
                  interviewerBuffer = '';
                  commitInterviewer(fu, true);
                }
              } else {
                const preview = interviewerBuffer ? interviewerBuffer + ' ' + text.trim() : text.trim();
                ws.send(JSON.stringify({ type: 'transcript', text: preview, isFinal: false }));
              }

              // Pause detected — commit whatever's left (the normal path for real interviews).
              if (speechFinal && interviewerBuffer.trim()) {
                lastCommitTs = Date.now();
                const fullUtterance = interviewerBuffer.trim();
                interviewerBuffer = '';
                commitInterviewer(fullUtterance, false);
              }
            },
            (err) => {
              console.error('[Deepgram Error]', err.message);
              interviewerDG = null; // Allow re-open on next audio packet
              ws.send(JSON.stringify({ type: 'error', message: 'Transcription error: ' + err.message }));
            }
          );
          // Flush buffered audio as soon as Deepgram connects
          if (interviewerDG) {
            interviewerDG._onOpen = function() {
              if (ws._audioBuffer1 && ws._audioBuffer1.length) {
                console.log('[Deepgram] Flushing', ws._audioBuffer1.length, 'buffered Ch1 packets on open');
                ws._audioBuffer1.forEach(buf => { try { interviewerDG.send(buf); } catch(e) {} });
                ws._audioBuffer1 = [];
              }
            };
          }
        };

        // Channel 2 setup (deferred)
        if (msg.dualStream) {
          let userBuffer = '';
          ws._setupUserDG = function() {
            if (userDG && userDG.readyState <= WebSocket.OPEN) return;
            console.log('[Deepgram] Opening user mic stream (lazy)');
            ws._audioBuffer2 = []; // init buffer for packets arriving while CONNECTING
            userDG = openDeepgramStream(
              (text, isFinal, speechFinal) => {
                if (!text.trim()) return;
                if (isFinal) {
                  userBuffer += (userBuffer ? ' ' : '') + text.trim();
                }
                if (speechFinal && userBuffer.trim()) {
                  const fullUtterance = userBuffer.trim();
                  userBuffer = '';
                  resetIdleTimer();
                  ws.send(JSON.stringify({ type: 'user_transcript', text: fullUtterance, isFinal: true }));
                  broadcastToSession(sessionId, { type: 'user_transcript', text: fullUtterance, isFinal: true }, ws);
                  transcript.push({ text: '[You] ' + fullUtterance, ts: Date.now(), isUser: true });
                  ws._recentTranscript = transcript.slice(-6).map(t => t.text);

                  // Store for echo detection — Ch1 transcripts will be compared against these
                  recentUserUtterances.push({ text: fullUtterance, ts: Date.now() });
                  // Prune old entries (keep last 10 seconds worth)
                  while (recentUserUtterances.length > 0 && Date.now() - recentUserUtterances[0].ts > 10000) {
                    recentUserUtterances.shift();
                  }
                }
              },
              (err) => {
                console.error('[Deepgram User Error]', err.message);
                userDG = null; // Allow re-open
              }
            );
            // Flush buffered audio as soon as Deepgram connects
            if (userDG) {
              userDG._onOpen = function() {
                if (ws._audioBuffer2 && ws._audioBuffer2.length) {
                  console.log('[Deepgram] Flushing', ws._audioBuffer2.length, 'buffered Ch2 packets on open');
                  ws._audioBuffer2.forEach(buf => { try { userDG.send(buf); } catch(e) {} });
                  ws._audioBuffer2 = [];
                }
              };
            }
          };
          console.log('[Live] Dual stream ready (Deepgram deferred until audio flows)');
        } else {
          userDG = null;
          console.log('[Live] Single stream ready (Deepgram deferred until audio flows)');
        }

        ws.send(JSON.stringify({ type: 'status', message: 'Live mode started', questionsLoaded: sessionQuestions.length, dualStream: !!msg.dualStream }));
        resetIdleTimer();
      }

      else if (msg.type === 'manual_match') {
        // User clicked a transcript line to manually match — deliberate action, clear dedup
        // Also reset the auto-match cooldown so auto-detect won't switch away for 60s
        const text = msg.text;
        if (text && sessionQuestions.length) {
          recentMatchedIds.clear();
          lastAutoMatchTime = Date.now(); // Reset cooldown — user chose this, don't switch away
          var qdMsg2 = { type: 'question_detected', text: text, source: 'manual' };
          ws.send(JSON.stringify(qdMsg2));
          broadcastToSession(sessionId, qdMsg2, ws);
          const rebuildIdx = () => { questionIndex = buildQuestionIndex(sessionQuestions); };
          fastMatchAndRespond(text, sessionQuestions, sessionId, userId, ws, null, recentMatchedIds, questionIndex, rebuildIdx, false, true).then(newLastId => {
            if (newLastId) lastMatchedQId = newLastId;
          });
        }
      }

      else if (msg.type === 'regenerate_answer') {
        // Force-regenerate an answer — bypass matching, go straight to AI generation
        const text = msg.text;
        const questionId = msg.questionId;
        if (!text || text.length < 3) return;
        console.log('[Regenerate] Force regenerating:', text.substring(0, 60));
        generateLiveAnswer(text, sessionId, userId, ws, questionId, true).catch(e => {
          console.error('[Regenerate Error]', e.message);
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to regenerate' }));
        });
      }

      else if (msg.type === 'update_settings') {
        // Client sends answer length preference — apply to ALL clients in this session
        // so the main (full-mode) WS that generates answers picks it up
        if (msg.maxLines !== undefined) {
          const val = parseInt(msg.maxLines) || 0;
          console.log('[Settings] maxAnswerLines set to', val, 'for session', sessionId);
          const clients = sessionClients.get(sessionId);
          if (clients) {
            clients.forEach(c => { c._maxAnswerLines = val; });
          }
          ws._maxAnswerLines = val; // also set on sender in case not in set yet
        }
      }

      else if (msg.type === 'canvas_question') {
        // User typed a question in the Smart Canvas input bar — manual action, no cooldown
        const text = msg.text;
        if (!text || text.length < 5) return;
        console.log('[Canvas] Manual question:', text.substring(0, 60));
        recentMatchedIds.clear();
        lastAutoMatchTime = Date.now(); // Reset cooldown — user chose this, don't switch away
        var qdMsg3 = { type: 'question_detected', text: text, source: 'manual' };
        ws.send(JSON.stringify(qdMsg3));
        broadcastToSession(sessionId, qdMsg3, ws);
        const rebuildIdx = () => { questionIndex = buildQuestionIndex(sessionQuestions); };
        fastMatchAndRespond(text, sessionQuestions, sessionId, userId, ws, null, recentMatchedIds, questionIndex, rebuildIdx, true, true).then(newLastId => {
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
        const recentLines = transcript.slice(-10); // last 10 for deep context

        // Build transcript with recency markers — newest at bottom, labeled
        let rawTranscript = '';
        if (recentLines.length > 3) {
          rawTranscript = 'OLDER CONTEXT:\n' + recentLines.slice(0, -3).map(t => t.text).join('\n');
          rawTranscript += '\n\nMOST RECENT:\n' + recentLines.slice(-3).map(t => t.text).join('\n');
        } else if (recentLines.length > 0) {
          rawTranscript = 'MOST RECENT:\n' + recentLines.map(t => t.text).join('\n');
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
        const extractSystem = 'You extract the LAST interview question from conversation transcripts. The transcript has recency markers. Search from bottom to top — find the most recent question the interviewer asked, even if it was a few lines back. Questions can be direct ("What is X?") or imperative ("Tell me about X", "Describe your experience with X", "Walk me through X"). Ignore the candidate\'s answers, small talk, and filler.\n\nIMPORTANT — MULTI-PART QUESTIONS: Interviewers often ask a main question then add a follow-up like "how would you approach this?" or "walk me through your process" or "what would you do differently?". These are ONE question, not two. Combine the main question and its follow-up into a single complete question. Example: "What is the difference between inner join and left join? How would you approach this problem?" → return the full combined question.\n\nOutput ONLY the clean question text — no quotes, no explanation. If there is truly no question anywhere in the transcript, output NONE.';
        const extractUser = ctxLine + rawTranscript + '\n\nFind the LAST question the interviewer asked (combine multi-part questions into one). Search from the most recent speech backwards. Output the question only.';

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
        // forceNavigate=true — user deliberately clicked "What should I say", so navigate immediately
        const rebuildIdx = () => { questionIndex = buildQuestionIndex(sessionQuestions); };
        lastAutoMatchTime = Date.now(); // Reset cooldown — user chose this action
        fastMatchAndRespond(questionText, sessionQuestions, sessionId, userId, ws, null, recentMatchedIds, questionIndex, rebuildIdx, false, true, true).then(newLastId => {
          lastWsayMatchId = newLastId || null;
          if (newLastId) lastMatchedQId = newLastId;
        });
      }

      else if (msg.type === 'switch_tab') {
        // User picked a different tab — reset interviewer Deepgram stream
        console.log('[Live] Switching tab — resetting interviewer Deepgram stream');
        if (interviewerDG && interviewerDG.readyState === WebSocket.OPEN) {
          try { interviewerDG.send(JSON.stringify({ type: 'CloseStream' })); interviewerDG.close(); } catch(e) {}
        }
        interviewerBuffer = '';
        // Re-open a fresh Deepgram stream for the new tab audio
        interviewerDG = openDeepgramStream(
          (text, isFinal, speechFinal) => {
            if (!text.trim()) return;
            if (isFinal) {
              resetIdleTimer();
              interviewerBuffer += (interviewerBuffer ? ' ' : '') + text.trim();
              ws.send(JSON.stringify({ type: 'transcript', text: interviewerBuffer, isFinal: false }));
            } else {
              const preview = interviewerBuffer ? interviewerBuffer + ' ' + text.trim() : text.trim();
              ws.send(JSON.stringify({ type: 'transcript', text: preview, isFinal: false }));
            }
            if (speechFinal && interviewerBuffer.trim()) {
              const fullUtterance = interviewerBuffer.trim();
              interviewerBuffer = '';
              ws.send(JSON.stringify({ type: 'transcript', text: fullUtterance, isFinal: true }));
              transcript.push({ text: fullUtterance, ts: Date.now() });
              ws._recentTranscript = transcript.slice(-6).map(t => t.text);
              if (aiExtractTimer) clearTimeout(aiExtractTimer);
              aiExtractTimer = setTimeout(() => { aiExtractTimer = null; aiAutoExtract(); }, AI_EXTRACT_DELAY);
              setTimeout(() => recentMatchedIds.clear(), 5000);
            }
          },
          (err) => { console.error('[Deepgram Error]', err.message); }
        );
        ws.send(JSON.stringify({ type: 'status', message: 'Tab switched — listening on new tab' }));
      }

      else if (msg.type === 'followup_questions') {
        // Generate smart follow-up questions the candidate can ask the interviewer
        const answeredQs = (ws._sessionQuestions || sessionQuestions || []).filter(q => q.answer).slice(-20);
        if (answeredQs.length === 0) {
          ws.send(JSON.stringify({ type: 'error', message: 'No questions discussed yet' }));
          return;
        }
        const wsCtx = ws._sessionContext || {};
        const recentTranscript = (ws._recentTranscript || []).slice(-30).join('\n');
        const followUpSystem = `You generate smart follow-up questions a candidate should ask the interviewer at the end of an interview.

RULES:
- Generate exactly 5 questions
- Each question should be specific to THIS interview — reference topics, projects, tools, or challenges that were actually discussed
- Mix of types: team/culture, role specifics, growth, technical depth, next steps
- Questions should show the candidate was paying attention and is genuinely curious
- Sound natural and conversational, not scripted or generic
- NEVER ask generic questions like "What does a typical day look like?" unless it connects to something discussed
- Each question = 1 sentence, max 20 words
- Number them 1-5
- No intro, no labels, no preamble — just the 5 numbered questions
- After the 5 questions, add a blank line then one short line starting with "Tip:" giving advice on which 2-3 to prioritize based on what was discussed`;

        const qaSummary = answeredQs.map((q, i) => `Q${i+1}: ${q.text}\nA: ${(q.answer || '').substring(0, 150)}`).join('\n\n');
        const followUpUser = `Interview for ${wsCtx.role || 'a role'} at ${wsCtx.company || 'a company'}.\n\nJOB DESCRIPTION:\n${wsCtx.jd || 'N/A'}\n\nQUESTIONS DISCUSSED:\n${qaSummary}${recentTranscript ? '\n\nRECENT CONVERSATION:\n' + recentTranscript : ''}\n\nGenerate 5 smart follow-up questions:`;
        callClaude(followUpSystem, followUpUser, 350, MODEL_HAIKU).then(result => {
          const followUpMsg = { type: 'followup_questions_result', questions: result, questionCount: answeredQs.length };
          ws.send(JSON.stringify(followUpMsg));
          broadcastToSession(sessionId, followUpMsg, ws);
        }).catch(e => {
          console.error('[Follow-up questions error]', e.message);
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to generate follow-up questions' }));
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

          // Post-interview learning — runs in the background so 'stop' returns immediately.
          const _tid = transcriptId, _sid = sessionId, _uid = userId;
          processTranscriptAfterInterview(_sid, _uid, _tid).then(sum => {
            if (sum && sum.added > 0) {
              try { sendAndBroadcast({ type: 'status', message: `Added ${sum.added} new question${sum.added === 1 ? '' : 's'} to your bank from this interview` }); } catch (e) {}
            }
          }).catch(e => console.error('[Learn trigger]', e.message));
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
    // Remove from active live map if this is the current live connection for the user
    if (userId && !isCanvasMode) {
      const entry = activeLiveByUser.get(userId);
      if (entry && entry.ws === ws) activeLiveByUser.delete(userId);
    }
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
  // Opt-in streaming — only when ?stream=1. Non-stream callers get identical JSON.
  const wantStream = req.query.stream === '1' && process.env.STREAM_LIVE_ANSWERS !== '0';
  let sseStarted = false;
  function startSSE() {
    if (sseStarted) return;
    sseStarted = true;
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    if (res.flushHeaders) res.flushHeaders();
  }
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
        const payload = {
          questionId: match.question.id,
          questionText: match.question.text,
          answer: match.question.answer,
          type: match.question.type,
          source: 'matched',
          similarity: Math.round(match.similarity * 100)
        };
        if (wantStream) { startSSE(); res.write('data: ' + JSON.stringify(Object.assign({ done: true }, payload)) + '\n\n'); return res.end(); }
        return res.json(payload);
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
    const genTokens = isTechnical ? 1200 : 600;

    if (wantStream) {
      startSSE();
      let answer = '';
      try {
        answer = await callClaudeStream(system, userPrompt, genTokens, MODEL_HAIKU, (chunk) => {
          res.write('data: ' + JSON.stringify({ delta: chunk }) + '\n\n');
        });
      } catch (streamErr) {
        console.error('[Canvas Ask stream] fell back to buffered:', streamErr.message);
        try { answer = await callClaude(system, userPrompt, genTokens, MODEL_HAIKU); }
        catch (e2) { res.write('data: ' + JSON.stringify({ error: e2.message }) + '\n\n'); return res.end(); }
      }
      const newQ = await pool.query(
        'INSERT INTO questions (session_id, text, type, answer, source) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        [req.params.id, question, qType, answer, 'live']
      );
      res.write('data: ' + JSON.stringify({ done: true, questionId: newQ.rows[0].id, questionText: question, answer, type: qType, source: 'new', similarity: 0 }) + '\n\n');
      return res.end();
    }

    const answer = await callClaude(system, userPrompt, genTokens, MODEL_HAIKU);

    // Save as new question
    const newQ = await pool.query(
      'INSERT INTO questions (session_id, text, type, answer, source) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [req.params.id, question, qType, answer, 'live']
    );

    res.json({ questionId: newQ.rows[0].id, questionText: question, answer, type: qType, source: 'new', similarity: 0 });
  } catch (e) {
    console.error('[Canvas Ask Error]', e.message);
    if (sseStarted) { try { res.write('data: ' + JSON.stringify({ error: e.message }) + '\n\n'); res.end(); } catch (_) {} }
    else res.status(500).json({ error: e.message });
  }
});

// Is `q` a continuation of the question we're already answering (same thread)?
// Used to decide GROW (extend the current answer) vs a brand-new question.
function isSameThread(q, active) {
  if (!active || !active.questionText) return false;
  const a = String(active.questionText).toLowerCase().trim();
  const b = String(q).toLowerCase().trim();
  if (!a || !b || a === b) return false;              // identical = nothing new to add
  if (a.includes(b) || b.includes(a)) return true;    // one extends the other
  return stringSimilarity.compareTwoStrings(a, b) >= 0.45; // clearly related topic
}

// GROW: the interviewer added detail to the same question → append 1–2 new sentences to
// the answer already on screen. Append-only by construction (we keep the existing text
// byte-for-byte and tack the model's new sentences on), so nothing the candidate is
// mid-sentence on ever changes. Uses the session's answer-style TEMPLATE, same as normal
// answers. Capped in count and length so the overlay never overflows.
async function growLiveAnswer(ws, sessionId, active, fullerQuestion) {
  try {
    if (!active || !active.id) return;
    active._grows = active._grows || 0;
    if (active._grows >= 3) return;                       // cap extensions per question
    if ((active.answer || '').length > 700) return;       // cap total length (overlay space)
    if ((active.answer || '').trim().length < 4) return;  // nothing to extend yet

    const session = ws._sessionContext || {};
    const stylePrompt = getStylePrompt(session.answer_style); // SAME template as normal answers
    const voiceBlock = ws._voiceProfile ? `\n\nSPEAK IN THE CANDIDATE'S OWN VOICE (sound like them, not generic AI):\n${ws._voiceProfile}` : '';
    const system = stylePrompt + voiceBlock + '\n\nCONTINUATION MODE: The interviewer has ADDED detail to the SAME question. You are given the answer already on screen. Output ONLY 1–2 NEW sentences that extend it to cover the added detail, in the SAME voice and style. Do NOT repeat or restate anything already said. Do NOT rewrite. No preamble. Just the next short, speakable sentence(s).';
    const userMsg = `QUESTION (now fuller):\n${fullerQuestion}\n\nANSWER ALREADY GIVEN (do NOT repeat any of this):\n${active.answer}\n\nOutput ONLY the additional sentence(s) to append:`;

    let addition = '';
    try { addition = (await callClaude(system, userMsg, 200, MODEL_HAIKU)).trim(); } catch (e) { return; }
    addition = addition.replace(/^["']|["']$/g, '').trim();
    if (!addition || addition.length < 4) return;

    // Append-only: keep existing text exactly, add the new part.
    const full = (active.answer || '').replace(/\s+$/, '') + ' ' + addition;
    active.answer = full;
    active.questionText = fullerQuestion;
    active._grows++;

    // Persist only for answers we generated live — never overwrite a user's prepped bank answer.
    if (active.id && !active._prepped) {
      pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [full, active.id]).catch(() => {});
    }

    const msg = { type: 'live_answer', questionId: active.id, questionText: active.questionText, answer: full, isNew: false, grew: true };
    try { ws.send(JSON.stringify(msg)); } catch (e) {}
    broadcastToSession(sessionId, msg, ws);
    console.log(`[Grow] Extended answer for Q ${active.id} (extension #${active._grows})`);
    logEvent('grow', { sessionId, qid: active.id, n: active._grows, chars: full.length });
  } catch (e) { console.error('[Grow]', e.message); logEvent('error', { where: 'growLiveAnswer', msg: e.message }); }
}

// Generate answer for live question — questionId is the EXISTING DB row from fastMatchAndRespond
async function generateLiveAnswer(questionText, sessionId, userId, ws, questionId, forceNavigate) {
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
    const answeredQs = (ws._sessionQuestions || []).filter(q => q.answer).slice(0, 8);
    const bankContext = answeredQs.map(q => `Q: ${q.text}\nA: ${q.answer}`).join('\n\n');

    // User's recent speech for conversational context
    const userLines = ws._userRecentLines || [];
    const userContext = userLines.length > 0 ? `\n\nCANDIDATE'S RECENT RESPONSES (build on this, don't repeat):\n${userLines.join('\n')}` : '';

    // Session identity — critical for role-specific answers
    const company = session.company || 'the company';
    const role = session.role || 'this role';
    let sessionHeader = `THIS INTERVIEW IS FOR: ${role} at ${company}\nThe candidate knows which role and company this is. If asked "why this role" or "why this company", reference ${company} and ${role} naturally — but NEVER parrot the JD. Only bring in personal experience when the question asks for it.\n`;
    // Tailor to whoever is actually asking (name/title/stage), when known.
    const iv = ws._interviewer || {};
    if (iv.name || iv.title || iv.stage) {
      sessionHeader += `INTERVIEWER: ${iv.name || 'the interviewer'}${iv.title ? ', ' + iv.title : ''}${iv.stage ? ' — ' + iv.stage + ' round' : ''}. Pitch the answer to what someone in this role would care about (e.g. a hiring manager wants impact and ownership; an engineer wants technical depth). Never awkwardly name-drop them.\n`;
    }

    const isTechnical = /sql|query|code|write|function|script|algorithm|regex|api|join|window function|python|javascript|html|css|excel|vba|dax|power query|etl|pipeline/i.test(questionText);
    const isExperienceQ = /tell me about a time|describe a (time|situation)|give (me )?(an )?example|in your (role|experience|career|previous|current|last)|at your (company|job|work)|how have you (used|done|handled|managed|dealt)|share an experience|walk me through.*(project|experience|time)|what('s| is) your experience/i.test(questionText);

    // Use the full ANSWER_PROMPT for strategic framing — not a watered-down version
    // Add a speed note for live context + technical override when needed
    const COMMON_LIVE_RULES = `\n\nHEADLINE-FIRST: Your FIRST sentence must be a direct, immediately-speakable answer to the question — something the candidate can start saying out loud right away. Put the supporting detail AFTER that. Never open with preamble or setup.\n\nIMPORTANT: The question was captured via live speech transcription and may be slightly garbled. NEVER ask for clarification. Interpret the most likely intent and answer confidently. The candidate's recent speech is provided FOR CONTEXT ONLY to understand conversation flow. NEVER use the candidate's own words as part of the answer. NEVER quote or paraphrase what the candidate said. The answer must come ONLY from your knowledge, the Q&A bank, resume, and JD. The candidate's speech tells you what they're discussing so you can stay relevant — that's ALL.`;

    // POINTERS: most people riff from the answer in their own words rather than read it
    // verbatim — so for non-technical questions, format as short scannable beats they can
    // expand naturally. Technical answers stay exact (wording matters for code).
    const POINTER_RULE = (process.env.POINTERS !== '0')
      ? `\n\nFORMAT AS POINTERS: Give 3-5 SHORT beats, ONE per line, each leading with the key point — cues the candidate expands in their OWN words, not a paragraph to read aloud. First beat is the direct headline answer.`
      : '';

    let liveAddendum;
    if (isTechnical) {
      liveAddendum = `\n\nLIVE MODE — TECHNICAL QUESTION: Code block FIRST with language tag. NO intro text before the code. After the code, ONE sentence max. The candidate is reading this on a tiny overlay — every extra word wastes space. If the question is conceptual (no code needed), answer in 2-4 direct sentences.\n\nACCURACY GUARDRAIL: Before finalizing, silently sanity-check the code/syntax — correct function names, valid syntax, right approach. A confidently-wrong answer is worse than a simple one. If you are NOT sure something is correct, prefer the simplest approach you ARE sure of, and do not invent APIs, functions, or flags that may not exist.` + COMMON_LIVE_RULES;
    } else if (isExperienceQ) {
      liveAddendum = `\n\nLIVE MODE — EXPERIENCE QUESTION: This question IS asking about personal experience. Use the Q&A bank and resume to reference real companies, projects, and outcomes. Hit the STAR beats BRIEFLY — one short line each (situation, action, result), NOT paragraphs. Keep the whole thing tight enough to finish in a few short lines.` + POINTER_RULE + COMMON_LIVE_RULES;
    } else {
      liveAddendum = `\n\nLIVE MODE — DIRECT ANSWER REQUIRED:
THIS IS NOT AN EXPERIENCE QUESTION. The interviewer is asking a general/conceptual/process question.
ANSWER IT DIRECTLY. Do NOT bring in personal stories, company names, or "At [company] I did X" framing.
WRONG: "At R&L, I tracked adoption by looking at active user counts..."
RIGHT: "I track adoption by looking at active user counts, dashboard refresh frequency, and drill-through depth."
WRONG: "When I was at Wells Fargo, I implemented row-level security..."
RIGHT: "Row-level security works by filtering data based on the user's identity, so each person only sees what's relevant to them."
Just answer the question plainly. Use "I" naturally but do NOT attach it to a specific company or role.
The Q&A bank and resume are for CONTEXT about what tools the candidate knows — NOT for injecting stories into every answer.
Only reference specific companies if the question EXPLICITLY asks "tell me about a time" or "at your previous role" or similar.` + POINTER_RULE + COMMON_LIVE_RULES;
    }

    const basePrompt = getStylePrompt(session.answer_style);

    // Response length control — user picks how concise answers should be
    // THIS OVERRIDES ALL OTHER LINE COUNT GUIDANCE IN THE STYLE PROMPTS
    // Brevity is enforced by the PROMPT. Token caps only provide HEADROOM so the answer
    // always finishes cleanly — never so tight they chop it mid-sentence.
    const maxSentences = ws._maxAnswerLines || 0;
    let lengthConstraint = '';
    let tokenLimit = isTechnical ? 1100 : 550;
    if (maxSentences > 0) {
      if (maxSentences <= 3) {
        lengthConstraint = `\n\n*** HARD LENGTH — max ${maxSentences} short sentences. Lead with the answer, no preamble, no filler. Finish the thought — never stop mid-sentence. If code is needed, code block + 1 line.`;
        tokenLimit = isTechnical ? 700 : 220;
      } else if (maxSentences <= 5) {
        lengthConstraint = `\n\n*** HARD LENGTH — max ${maxSentences} short sentences. Answer directly, no intro or conclusion. Finish the thought — never stop mid-sentence. If code is needed, code block + 1-2 lines.`;
        tokenLimit = isTechnical ? 800 : 340;
      } else if (maxSentences <= 8) {
        lengthConstraint = `\n\n*** LENGTH — max ${maxSentences} short sentences. Lead with the answer; each line adds new info; no filler. Finish the thought.`;
        tokenLimit = isTechnical ? 1000 : 500;
      } else if (maxSentences <= 12) {
        lengthConstraint = `\n\nLENGTH — up to ${maxSentences} sentences, no filler, no intros/conclusions.`;
        tokenLimit = isTechnical ? 1300 : 680;
      } else {
        lengthConstraint = `\n\nLENGTH — up to ${maxSentences} sentences; be thorough but don't pad.`;
        tokenLimit = isTechnical ? 1500 : 900;
      }
    } else {
      // Default: overlay-sized. Brief AND complete.
      lengthConstraint = `\n\n*** LENGTH — keep it overlay-sized: 4-6 short lines for simple questions, up to 8 for complex ones. NEVER write long paragraphs. Each line on its own line, short (max ~15 words). Most important: ALWAYS finish your last sentence — never cut off mid-thought.`;
      tokenLimit = isTechnical ? 1000 : 500;
    }

    // Speak in THIS candidate's own voice (per-user profile), if we've learned it.
    const voiceBlock = ws._voiceProfile
      ? `\n\nSPEAK IN THE CANDIDATE'S OWN VOICE — write the answer the way THIS specific candidate naturally talks, so it sounds like them and not generic AI:\n${ws._voiceProfile}\nMatch their rhythm, phrasing, and word choices — but keep it correct, on-point, and headline-first.`
      : '';
    const system = basePrompt + liveAddendum + lengthConstraint + voiceBlock;
    // Include recent transcript so AI sees the full buildup, not just the tail-end question
    const recentLines = ws._recentTranscript || [];
    const transcriptContext = recentLines.length > 0
      ? `\n\nRECENT CONVERSATION (the interviewer's speech leading up to the question — use this to understand the FULL context):\n${recentLines.join('\n')}`
      : '';

    const userPrompt = `${sessionHeader}\nRESUME:\n${session.resume || 'N/A'}\n\nJOB DESCRIPTION:\n${session.jd || 'N/A'}\n\nQ&A BANK (candidate's real experience — USE THIS):\n${bankContext}${userContext}${transcriptContext}\n\nQUESTION (detected from speech — may be just the tail end, use RECENT CONVERSATION above for full context):\n${questionText}\n\nAnswer:`;

    const tGen = Date.now();
    let answer = '';
    let ttft = 0;
    let streamed = false;
    const streamEnabled = process.env.STREAM_LIVE_ANSWERS !== '0'; // kill switch: set to '0' to revert to buffered
    if (streamEnabled) {
      try {
        answer = await callClaudeStream(system, userPrompt, tokenLimit, MODEL_HAIKU, (chunk) => {
          if (!ttft) ttft = Date.now() - tGen;
          const deltaMsg = {
            type: 'live_answer_delta',
            questionId: questionId || ('temp-' + Date.now()),
            questionText,
            chunk,
            isNew: true,
            navigate: !!forceNavigate
          };
          try { ws.send(JSON.stringify(deltaMsg)); } catch (e) {}
          broadcastToSession(sessionId, deltaMsg, ws);
        });
        streamed = true;
      } catch (streamErr) {
        // Any streaming failure → fall back to the exact buffered behavior as before.
        console.error('[Stream] fell back to buffered:', streamErr.message);
        answer = await callClaude(system, userPrompt, tokenLimit, MODEL_HAIKU);
      }
    } else {
      answer = await callClaude(system, userPrompt, tokenLimit, MODEL_HAIKU);
    }
    console.log(`[TIMING] generateLiveAnswer: ${Date.now() - tGen}ms`);
    console.log(`[LATENCY] gen streamed=${streamed} ttft=${ttft}ms total=${Date.now() - tGen}ms chars=${answer.length} q="${(questionText||'').substring(0,50)}"`);
    logEvent('answer', { sessionId, qid: questionId, ms: Date.now() - tGen, ttft, streamed, chars: answer.length, q: (questionText || '').substring(0, 60) });

    // UPDATE the existing question row (created by fastMatchAndRespond) — NOT a new INSERT
    if (questionId) {
      pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, questionId])
        .catch(e => console.error('[Update answer error]', e.message));
    }

    // Mark this as the active answer thread so continued interviewer detail grows THIS answer.
    ws._activeAnswer = { id: questionId, questionText, answer, _grows: 0, _prepped: false };

    // Send answer to client with the SAME questionId the client already knows about
    const liveAnswerMsg = {
      type: 'live_answer',
      questionId: questionId || ('temp-' + Date.now()),
      questionText,
      answer,
      isNew: true,
      navigate: !!forceNavigate
    };
    ws.send(JSON.stringify(liveAnswerMsg));
    broadcastToSession(sessionId, liveAnswerMsg, ws); // Broadcast to canvas clients

    // Fire-and-forget: predict likely follow-up questions the interviewer might ask next
    generateFollowUps(questionText, answer, session, ws, sessionId, questionId).catch(e => {
      console.error('[Follow-up prediction error]', e.message);
    });

    // (Removed) coaching "Also hit" points — off-mission (lectured instead of saying what to say)
    // and an extra background AI call per answer. Dropped for speed and focus.
  } catch (e) {
    console.error('[Live Answer Error]', e.message);
    logEvent('error', { where: 'generateLiveAnswer', msg: e.message });
    ws.send(JSON.stringify({ type: 'error', message: 'Failed to generate answer' }));
  }
}

// Predict 2-3 follow-up questions the interviewer is likely to ask next
async function generateFollowUps(questionText, answerText, session, ws, sessionId, questionId) {
  const company = session.company || 'the company';
  const role = session.role || 'this role';
  const system = `You are an expert interviewer for ${role} at ${company}. Given a question that was just asked and the candidate's answer, predict the 2-3 most likely follow-up questions the interviewer would ask next. Consider: drilling deeper into the answer, asking for specifics/metrics, challenging assumptions, or pivoting to a related topic. Return ONLY a JSON array of strings, no explanation. Example: ["Can you walk me through the specific metrics you tracked?","How did you handle pushback from stakeholders?"]`;
  const userPrompt = `QUESTION JUST ASKED:\n${questionText}\n\nCANDIDATE'S ANSWER:\n${answerText.substring(0, 800)}\n\nPredict the 2-3 most likely follow-up questions:`;

  const tStart = Date.now();
  const raw = await callClaude(system, userPrompt, 200, MODEL_HAIKU);
  console.log(`[TIMING] generateFollowUps: ${Date.now() - tStart}ms`);

  // Parse the JSON array from response
  try {
    const match = raw.match(/\[[\s\S]*\]/);
    if (!match) return;
    const followUps = JSON.parse(match[0]);
    if (!Array.isArray(followUps) || followUps.length === 0) return;

    const followUpMsg = {
      type: 'follow_up_predictions',
      questionId: questionId,
      predictions: followUps.slice(0, 3)
    };
    ws.send(JSON.stringify(followUpMsg));
    broadcastToSession(sessionId, followUpMsg, ws);
    // (Removed) pre-generation of follow-up answers — it fired 2 background AI calls per
    // answer and never actually hit (pregen_hits=0), just clogging the pipe. Dropped for speed.
  } catch (parseErr) {
    console.error('[Follow-up parse error]', parseErr.message);
  }
}

// COACHING POINTS — the "also say this" layer. Given the question and the answer, surface
// 2-3 short extra beats the candidate should ALSO hit to make the answer stronger or clearer
// (a metric to quantify, a concrete example, a tradeoff to name, a tie to the role). These
// are cues to hit IF NEEDED — not part of the answer itself. Fire-and-forget, flag-gated.
async function generateCoachingPoints(questionText, answerText, session, ws, sessionId, questionId) {
  if (process.env.COACHING_POINTS === '0') return;
  const role = session.role || 'this role';
  const company = session.company || 'the company';
  const system = `You are an interview coach for ${role} at ${company}. Given the question and the candidate's answer, list 2-3 SHORT extra points the candidate should ALSO hit to make the answer stronger or clearer — e.g. a specific metric to quantify, a concrete example to name, a tradeoff/risk to acknowledge, or a tie back to the role. Each point is 3-7 words, action-oriented (start with a verb), something they can weave in IF NEEDED. Do NOT repeat what the answer already covers well. Return ONLY a JSON array of strings.`;
  const userPrompt = `QUESTION:\n${questionText}\n\nANSWER GIVEN:\n${answerText.substring(0, 800)}\n\nList 2-3 short extra points to also hit:`;
  try {
    const raw = await callClaude(system, userPrompt, 150, MODEL_HAIKU);
    const match = raw.match(/\[[\s\S]*\]/);
    if (!match) return;
    const points = JSON.parse(match[0]);
    if (!Array.isArray(points) || !points.length) return;
    const msg = { type: 'coaching_points', questionId: questionId, points: points.filter(p => typeof p === 'string').slice(0, 3) };
    if (!msg.points.length) return;
    ws.send(JSON.stringify(msg));
    broadcastToSession(sessionId, msg, ws);
    logEvent('coaching', { sessionId, qid: questionId, n: msg.points.length });
  } catch (e) { console.error('[Coaching points]', e.message); }
}

// ===== VIDEO NAME DETECTION =====
// During a live call, clients send a few screenshots. Vision reads the participant
// name tags; we accumulate non-self names in memory keyed by sessionId, and the
// post-interview step uses the most-seen name IF the transcript didn't reveal one.
const detectedParticipants = new Map(); // sessionId -> { names: Map<lower,{name,count}>, ts }

function bestDetectedInterviewer(sessionId) {
  const store = detectedParticipants.get(sessionId);
  if (!store || !store.names.size) return null;
  let best = null;
  for (const v of store.names.values()) { if (!best || v.count > best.count) best = v; }
  return best ? best.name : null;
}

// Purge stale detection stores hourly
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of detectedParticipants.entries()) {
    if (now - (v.ts || 0) > 60 * 60 * 1000) detectedParticipants.delete(k);
  }
}, 30 * 60 * 1000);

app.post('/api/sessions/:id/detect-participants', authMiddleware, async (req, res) => {
  try {
    const { image } = req.body;
    if (!image) return res.status(400).json({ error: 'No image' });

    const sys = 'You are looking at a screenshot of a video call (Zoom / Google Meet / Microsoft Teams). Read the participant name labels shown on the video tiles. For each, mark isYou=true if that tile is the local user (labeled "You", "(You)", or similar). Return ONLY JSON: {"participants":[{"name":"Full Name","isYou":false}]}. If no names are visible, return {"participants":[]}. No other text.';
    let out = [];
    try {
      const raw = await callClaudeVision(sys, image, 'List the visible participant name labels as JSON only.', 250, MODEL_HAIKU, 'image/jpeg');
      const m = raw.match(/\{[\s\S]*\}/);
      const o = m ? JSON.parse(m[0]) : {};
      out = Array.isArray(o.participants) ? o.participants : [];
    } catch (e) { console.error('[Names] vision:', e.message); }

    const selfName = (req.userName || '').toLowerCase();
    let candName = '';
    try {
      const sess = await pool.query('SELECT candidate_name FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
      candName = (sess.rows[0]?.candidate_name || '').toLowerCase();
    } catch (e) {}

    let store = detectedParticipants.get(req.params.id);
    if (!store) { store = { names: new Map(), ts: Date.now() }; detectedParticipants.set(req.params.id, store); }
    let addedAny = false;
    for (const p of out) {
      if (!p || !p.name || p.isYou) continue;
      const nm = String(p.name).trim();
      const low = nm.toLowerCase();
      if (!nm || low.length < 2) continue;
      if (selfName && (low === selfName || selfName.includes(low) || low.includes(selfName))) continue;
      if (candName && (low === candName || candName.includes(low) || low.includes(candName))) continue;
      const cur = store.names.get(low) || { name: nm, count: 0 };
      cur.count++; store.names.set(low, cur);
      addedAny = true;
    }
    store.ts = Date.now();
    res.json({ ok: true, captured: addedAny });
  } catch (e) {
    console.error('[Names] detect error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ===== POST-INTERVIEW LEARNING =====
// Runs after a live interview ends. Three jobs, all safe/idempotent:
//   1. Auto-delete empty/test transcripts (no real interviewer content).
//   2. Capture the interviewer's name/title from what they said (fills empty fields only).
//   3. Learn: mine the transcript for questions asked + predict next-round questions,
//      dedup against the bank, generate answers in the session's style, add as 'learned'.
// Never throws to the caller. Capped to control Haiku cost. `force` re-runs on demand.
async function processTranscriptAfterInterview(sessionId, userId, transcriptId, force = false) {
  const summary = { deleted: false, interviewer: null, added: 0 };
  try {
    const tr = await pool.query('SELECT * FROM live_transcripts WHERE id = $1 AND session_id = $2 AND user_id = $3', [transcriptId, sessionId, userId]);
    if (!tr.rows.length) return summary;
    const row = tr.rows[0];
    if (row.learned && !force) return summary; // already processed

    let lines = [];
    try { lines = JSON.parse(row.transcript || '[]'); } catch (e) { lines = []; }

    const interviewerLines = lines
      .filter(l => l && !l.isUser && !l.isEcho)
      .map(l => (l.text || '').replace(/^\[(You|Echo)\]\s*/i, '').trim())
      .filter(Boolean);
    const interviewerText = interviewerLines.join('\n');
    const realChars = interviewerText.replace(/\s+/g, '').length;

    // 1) EMPTY / TEST TRANSCRIPT — delete (conservative: only when clearly nothing was said)
    if (interviewerLines.length === 0 || realChars < 40) {
      await pool.query('DELETE FROM live_transcripts WHERE id = $1', [transcriptId]);
      console.log(`[Learn] Deleted empty/test transcript ${transcriptId} (lines=${interviewerLines.length}, chars=${realChars})`);
      summary.deleted = true;
      return summary;
    }

    // Mark processed up-front so overlapping triggers (stop + close) don't double-run
    await pool.query('UPDATE live_transcripts SET learned = true WHERE id = $1', [transcriptId]);

    const session = (await pool.query('SELECT resume, jd, company, role, answer_style FROM sessions WHERE id = $1', [sessionId])).rows[0];
    if (!session) return summary;

    // 2) INTERVIEWER IDENTITY — only fill if currently empty.
    //    Transcript first (they usually introduce themselves); video screenshots as fallback.
    let interviewerName = row.interviewer_name || '';
    if (!interviewerName) {
      try {
        const idRaw = await callClaude(
          'From an interview transcript (interviewer speech only), extract the INTERVIEWER\'s name and job title IF they introduced themselves. Return ONLY JSON like {"name":"","title":""}. Use empty strings if unknown. No other text.',
          interviewerText.slice(0, 3000), 80, MODEL_HAIKU
        );
        const m = idRaw.match(/\{[\s\S]*?\}/);
        const o = m ? JSON.parse(m[0]) : {};
        if (o && (o.name || o.title)) {
          await pool.query(
            "UPDATE live_transcripts SET interviewer_name = COALESCE(NULLIF($1,''), interviewer_name), interviewer_title = COALESCE(NULLIF($2,''), interviewer_title) WHERE id = $3",
            [o.name || '', o.title || '', transcriptId]
          );
          await pool.query(
            "UPDATE meetings SET name = CASE WHEN COALESCE(name,'')='' THEN $1 ELSE name END, title = CASE WHEN COALESCE(title,'')='' THEN $2 ELSE title END WHERE session_id = $3 AND is_current = true",
            [o.name || '', o.title || '', sessionId]
          );
          interviewerName = o.name || '';
          summary.interviewer = { name: o.name || '', title: o.title || '', via: 'transcript' };
          console.log(`[Learn] Interviewer from transcript: "${o.name}" / "${o.title}"`);
        }
      } catch (e) { console.error('[Learn] interviewer extract:', e.message); }
    }
    // Video fallback — use the most-seen on-screen name if the transcript gave nothing
    if (!interviewerName) {
      const vidName = bestDetectedInterviewer(sessionId);
      if (vidName) {
        await pool.query(
          "UPDATE live_transcripts SET interviewer_name = COALESCE(NULLIF($1,''), interviewer_name) WHERE id = $2",
          [vidName, transcriptId]
        );
        await pool.query(
          "UPDATE meetings SET name = CASE WHEN COALESCE(name,'')='' THEN $1 ELSE name END WHERE session_id = $2 AND is_current = true",
          [vidName, sessionId]
        );
        interviewerName = vidName;
        summary.interviewer = { name: vidName, title: '', via: 'video' };
        console.log(`[Learn] Interviewer from video: "${vidName}"`);
      }
    }
    detectedParticipants.delete(sessionId); // done with this session's detections

    // 3) LEARN QUESTIONS INTO BANK
    const existing = (await pool.query('SELECT id, text, type, answer FROM questions WHERE session_id = $1', [sessionId])).rows;
    const idx = buildQuestionIndex(existing);

    // 3a) Questions actually asked in this interview
    let asked = [];
    try {
      const raw = await callClaude(
        'Extract EVERY distinct interview question the interviewer asked, cleaned up (full question, no filler). Ignore the candidate. Return ONLY a JSON array of question strings, nothing else.',
        interviewerText.slice(0, 8000), 800, MODEL_HAIKU
      );
      const m = raw.match(/\[[\s\S]*\]/);
      asked = m ? JSON.parse(m[0]) : [];
    } catch (e) { console.error('[Learn] extract asked:', e.message); }

    // 3b) Predict likely next-round questions
    let predicted = [];
    try {
      const stage = row.stage || '';
      const raw = await callClaude(
        `You are an expert interviewer for ${session.role || 'this role'} at ${session.company || 'the company'}. Based on the questions from the ${stage || 'previous'} round, predict the most likely questions the candidate will face in the NEXT round. Return ONLY a JSON array of question strings (max 8), nothing else.`,
        'Questions asked so far:\n' + (Array.isArray(asked) ? asked : []).slice(0, 20).map(q => '- ' + q).join('\n'),
        400, MODEL_HAIKU
      );
      const m = raw.match(/\[[\s\S]*\]/);
      predicted = m ? JSON.parse(m[0]) : [];
    } catch (e) { console.error('[Learn] predict:', e.message); }

    // Combine, dedup against bank AND each other, cap for cost
    const candidates = [];
    const seen = [];
    for (const q of [...(Array.isArray(asked) ? asked : []), ...(Array.isArray(predicted) ? predicted : [])]) {
      if (typeof q !== 'string') continue;
      const qt = q.trim();
      if (qt.length < 8) continue;
      if (findBestMatch(qt, existing, idx)) continue; // already in bank
      if (seen.some(s => stringSimilarity.compareTwoStrings(s.toLowerCase(), qt.toLowerCase()) > 0.6)) continue;
      seen.push(qt);
      candidates.push(qt);
      if (candidates.length >= 12) break;
    }

    if (candidates.length === 0) { console.log('[Learn] no new questions to add'); return summary; }

    // Generate answers in the session's chosen style and insert as 'learned'
    const stylePrompt = getStylePrompt(session.answer_style);
    const bank = existing.filter(q => q.answer).slice(0, 10).map(q => `Q: ${q.text}\nA: ${q.answer}`).join('\n\n');
    for (const qt of candidates) {
      try {
        const userMsg = `RESUME:\n${session.resume || ''}\n\nJD:\n${session.jd || ''}\n\nQ&A BANK:\n${bank}\n\nQuestion:\n${qt}\n\nAnswer the question naturally. Only reference companies or role titles if the question specifically asks about experience.`;
        const ans = await callClaude(stylePrompt, userMsg, 1200, MODEL_HAIKU);
        await pool.query(
          'INSERT INTO questions (session_id, text, type, answer, source) VALUES ($1, $2, $3, $4, $5)',
          [sessionId, qt, classifyQuestion(qt), ans, 'learned']
        );
        summary.added++;
      } catch (e) { console.error('[Learn] gen answer:', e.message); }
    }
    console.log(`[Learn] Added ${summary.added} new questions from transcript ${transcriptId}`);
    logEvent('learn', { sessionId, added: summary.added, interviewer: summary.interviewer ? summary.interviewer.via : null });
    // Refresh this user's voice profile from their accumulated speech (only if stale).
    maybeRebuildVoiceProfile(userId).catch(() => {});
    return summary;
  } catch (e) {
    console.error('[Learn] processTranscriptAfterInterview error:', e.message);
    return summary;
  }
}

// ===== PER-USER VOICE PROFILE =====
// Learn how THIS user actually speaks, from their own [You] lines across their interviews,
// and store a compact profile so answers can be generated in their voice. Strictly per-user:
// every read/write is scoped to the authenticated user_id — never shared across users.
async function buildVoiceProfile(userId) {
  try {
    if (process.env.VOICE_PROFILE === '0') return null;
    const tr = await pool.query('SELECT transcript FROM live_transcripts WHERE user_id = $1 AND transcript IS NOT NULL ORDER BY created_at DESC LIMIT 20', [userId]);
    const utts = [];
    for (const row of tr.rows) {
      let lines = []; try { lines = JSON.parse(row.transcript || '[]'); } catch (e) {}
      lines.forEach(l => {
        if (l && l.isUser) {
          const t = (l.text || '').replace(/^\[You\]\s*/i, '').trim();
          if (t.split(/\s+/).length >= 4) utts.push(t);
        }
      });
    }
    if (utts.length < 8) return null; // not enough of THIS user's speech to characterize yet
    const sample = utts.slice(0, 60).join('\n').slice(0, 6000);
    const system = 'You analyze how ONE specific person speaks in interviews, using transcripts of THEIR OWN spoken answers. Produce a SHORT reusable voice profile (5-7 sentences, no headers) that another AI can follow to write answers that sound like THIS person: their typical sentence length and rhythm, formality, directness, hedges/filler tendencies, favorite phrases or transitions, vocabulary level, and overall tone. Be specific and behavioral. Describe only HOW they talk, never the content of their answers. Output only the profile.';
    const profile = (await callClaude(system, "This person's spoken answers:\n" + sample + "\n\nWrite their voice profile:", 300, MODEL_HAIKU)).trim();
    if (profile.length < 20) return null;
    await pool.query('UPDATE users SET voice_profile = $1, voice_profile_updated_at = NOW() WHERE id = $2', [profile, userId]);
    logEvent('voice_profile', { userId, chars: profile.length, samples: utts.length });
    console.log(`[Voice] Built profile for user ${userId} from ${utts.length} utterances`);
    return profile;
  } catch (e) { console.error('[Voice] build error:', e.message); return null; }
}

// Rebuild only when stale (>3 days) or missing — keeps it fresh without a Haiku call every interview.
async function maybeRebuildVoiceProfile(userId) {
  try {
    const u = await pool.query('SELECT voice_profile_updated_at FROM users WHERE id = $1', [userId]);
    const last = u.rows[0] && u.rows[0].voice_profile_updated_at;
    if (last && (Date.now() - new Date(last).getTime()) < 3 * 24 * 60 * 60 * 1000) return;
    await buildVoiceProfile(userId);
  } catch (e) {}
}

// View / rebuild the current user's own voice profile
app.get('/api/voice-profile', authMiddleware, async (req, res) => {
  try {
    const u = await pool.query('SELECT voice_profile, voice_profile_updated_at FROM users WHERE id = $1', [req.userId]);
    res.json({ profile: u.rows[0] ? (u.rows[0].voice_profile || '') : '', updatedAt: u.rows[0] ? u.rows[0].voice_profile_updated_at : null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/voice-profile/rebuild', authMiddleware, async (req, res) => {
  try {
    const profile = await buildVoiceProfile(req.userId);
    if (!profile) return res.json({ ok: false, message: 'Not enough of your interview speech yet — do a live interview or two first.' });
    res.json({ ok: true, profile });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Manual re-run (e.g. a "Learn from this interview" button, or to process a past transcript)
app.post('/api/sessions/:id/transcripts/:tid/learn', authMiddleware, async (req, res) => {
  try {
    const summary = await processTranscriptAfterInterview(req.params.id, req.userId, req.params.tid, true);
    res.json({ ok: true, ...summary });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Start
initDB().then(() => {
  server.listen(PORT, () => console.log(`Running on ${PORT}`));
}).catch(e => {
  console.error('DB init failed:', e);
  server.listen(PORT, () => console.log(`Running on ${PORT} (DB not ready)`));
});
