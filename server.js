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
const meetingCopilot = require('./lib/meeting-copilot');
const assessment = require('./lib/assessment'); // desktop Assessment: carry-over notes, title lock, who sees it // meeting co-pilot logic (call log, prompts, budget)
const answerNote = require('./lib/answer-note'); // Answer Note (23 Oct): seed, version history, search, AI change modes
const NoteMatchShared = require('./public/note-match'); // same ranking the note page shows
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

// The note's diagram drawer, served from xhire.app itself (owner 24 Oct: "we can not have anything weak for interview"):
// no outside site in the path. Stored gzipped (mermaid 10.9.1 from npm, integrity checked); cached for a year.
const MERMAID_GZ = path.join(__dirname, 'public', 'vendor', 'mermaid-10.9.1.min.js.gz');
let mermaidPlain = null;
app.get('/vendor/mermaid-10.9.1.min.js', (req, res) => {
  res.set({ 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'public, max-age=31536000, immutable', Vary: 'Accept-Encoding' });
  if (/\bgzip\b/.test(req.headers['accept-encoding'] || '')) { res.set('Content-Encoding', 'gzip'); return res.sendFile(MERMAID_GZ); }
  try { mermaidPlain = mermaidPlain || require('zlib').gunzipSync(fs.readFileSync(MERMAID_GZ)); res.send(mermaidPlain); } catch (e) { res.status(500).end(); }
});

app.use(express.static(path.join(__dirname, 'public')));

// ============ DATABASE ============
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' && process.env.DATABASE_PUBLIC_URL ? { rejectUnauthorized: false } : false
});
const recordCallEvent = meetingCopilot.makeRecorder(pool); // call log: writes ONLY during a live call (callId set)

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
      CREATE TABLE IF NOT EXISTS call_events (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        call_id UUID NOT NULL,
        ts TIMESTAMPTZ DEFAULT NOW(),
        kind TEXT NOT NULL,
        text TEXT NOT NULL,
        meta JSONB DEFAULT '{}'
      );
      CREATE INDEX IF NOT EXISTS idx_call_events_call ON call_events(call_id, ts);
      CREATE TABLE IF NOT EXISTS call_screens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        call_id UUID NOT NULL,
        key TEXT NOT NULL,
        ts TIMESTAMPTZ DEFAULT NOW(),
        media_type TEXT,
        image BYTEA,
        transcript TEXT,
        meta JSONB DEFAULT '{}'
      );
      CREATE INDEX IF NOT EXISTS idx_call_screens_call ON call_screens(call_id, ts);
    `);
    // Migrations for existing tables
    await client.query(`
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS pipeline_stages JSONB DEFAULT '[]';
      ALTER TABLE live_transcripts ADD COLUMN IF NOT EXISTS report JSONB;
      ALTER TABLE live_transcripts ADD COLUMN IF NOT EXISTS interviewer_name VARCHAR(255) DEFAULT '';
      ALTER TABLE live_transcripts ADD COLUMN IF NOT EXISTS interviewer_title VARCHAR(255) DEFAULT '';
      ALTER TABLE live_transcripts ADD COLUMN IF NOT EXISTS stage VARCHAR(255) DEFAULT '';
      ALTER TABLE live_transcripts ADD COLUMN IF NOT EXISTS learned BOOLEAN DEFAULT false;
      ALTER TABLE live_transcripts ADD COLUMN IF NOT EXISTS memory TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS voice_profile TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS voice_profile_updated_at TIMESTAMP;
      ALTER TABLE questions ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'build';
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS answer_style VARCHAR(50) DEFAULT 'conversational';
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS jd_requirements JSONB DEFAULT NULL;
    `).catch(() => {});
    // Assessment (desktop, 13 Oct): a session of kind 'assessment' is not tied to a company; its title is locked from content
    await client.query(`
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS kind VARCHAR(20) DEFAULT 'interview';
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS title VARCHAR(160) DEFAULT '';
      CREATE INDEX IF NOT EXISTS idx_sessions_user_kind ON sessions(user_id, kind);
      CREATE INDEX IF NOT EXISTS idx_call_events_session ON call_events(session_id, kind);
    `).catch(e => console.error('[DB] assessment migration failed:', e.message));
    // Answer Note (23 Oct): one note per user; groups (left rail) → items (the phrasings of one question, each with his
    // answer as editor HTML + its version history). Additive only.
    await client.query(`
      CREATE TABLE IF NOT EXISTS answer_notes (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        settings JSONB DEFAULT '{}',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS answer_note_groups (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        note_id UUID NOT NULL REFERENCES answer_notes(id) ON DELETE CASCADE,
        name VARCHAR(160) NOT NULL DEFAULT '',
        color VARCHAR(32) DEFAULT '',
        pinned BOOLEAN DEFAULT FALSE,
        sort_order INT DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS answer_note_items (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        note_id UUID NOT NULL REFERENCES answer_notes(id) ON DELETE CASCADE,
        group_id UUID NOT NULL REFERENCES answer_note_groups(id) ON DELETE CASCADE,
        question TEXT NOT NULL DEFAULT '',
        answer_html TEXT DEFAULT '',
        key_points TEXT DEFAULT '',
        versions JSONB DEFAULT '[]',
        version INT DEFAULT 0,
        edited_by VARCHAR(16) DEFAULT '',
        edit_label VARCHAR(120) DEFAULT '',
        sort_order INT DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_answer_note_groups_note ON answer_note_groups(note_id, sort_order);
      CREATE INDEX IF NOT EXISTS idx_answer_note_items_group ON answer_note_items(group_id, sort_order);
      ALTER TABLE answer_note_groups ADD COLUMN IF NOT EXISTS section VARCHAR(80) DEFAULT '';
      ALTER TABLE answer_note_groups ADD COLUMN IF NOT EXISTS scope VARCHAR(8) DEFAULT '';
      ALTER TABLE answer_note_groups ADD COLUMN IF NOT EXISTS job_ids UUID[] DEFAULT NULL;
      ALTER TABLE sessions ADD COLUMN IF NOT EXISTS note_people TEXT DEFAULT '';
      CREATE TABLE IF NOT EXISTS answer_note_job_answers (
        item_id UUID NOT NULL REFERENCES answer_note_items(id) ON DELETE CASCADE,
        session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        answer_html TEXT DEFAULT '',
        key_points TEXT DEFAULT '',
        versions JSONB DEFAULT '[]',
        version INT DEFAULT 0,
        edited_by VARCHAR(16) DEFAULT '',
        edit_label VARCHAR(120) DEFAULT '',
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (item_id, session_id)
      );
    `).catch(e => console.error('[DB] answer note migration failed:', e.message));
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
  'Do you have any questions for us?',
  // Influence & pushback — asked in almost every interview (owner, 25 Sep): always in the bank, answers ready
  'How do you convince executives to use a report, tool, or recommendation you built?',
  'How do you get buy-in when stakeholders are not sold on your idea?',
  'Tell me about a time someone pushed back on your recommendation. How did you handle it?',
  'What do you do when leadership disagrees with what your data or analysis shows?',
  'How do you get people to actually adopt something new you built?',
  'Tell me about a time you influenced a decision without having authority.',
  'How do you handle a stakeholder who keeps changing requirements?',
  'Tell me about a time you had to say no to a stakeholder.'
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

// Token usage per tagged call (extras.__tag — stripped before sending). Tells us what each feature really spends.
function splitTag(extras) { if (!extras || !extras.__tag) return { tag: '', ex: extras }; const ex = Object.assign({}, extras); const tag = ex.__tag; delete ex.__tag; return { tag, ex }; }
function logUsage(tag, model, u) {
  if (!tag || !u) return;
  console.log(`[Usage] ${tag} ${model} in=${u.input_tokens || 0} read=${u.cache_read_input_tokens || 0} write=${u.cache_creation_input_tokens || 0} out=${u.output_tokens || 0}`);
}
function _callClaudeOnce(system, user, maxTokens, model, extras) {
  const { tag, ex } = splitTag(extras); extras = ex;
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(Object.assign({ model, max_tokens: maxTokens, system, messages: [{ role: 'user', content: user }] }, extras || {}));
    const req = https.request({
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      agent: anthropicAgent,
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' }
    }, res => {
      let d = ''; res.on('data', c => d += c);
      // Take the reply's TEXT blocks wherever they are — Sonnet 5 may put a thinking block first, and reading only
      // content[0] threw real answers away as "API error" (26 Sep: must-have answers, and any Sonnet caller).
      res.on('end', () => { try { const p = JSON.parse(d); const txt = (p.content || []).filter(b => b.type === 'text').map(b => b.text).join(''); logUsage(tag, model, p.usage);
        if (Array.isArray(system) && p.usage) console.log(`[Cache] ${model} input=${p.usage.input_tokens} cached_read=${p.usage.cache_read_input_tokens || 0} cache_write=${p.usage.cache_creation_input_tokens || 0}`); // same check as the streaming path
        if (txt) return resolve(txt);
        console.log(`[Claude] ${model} returned no leading text — status=${res.statusCode} stop=${p.stop_reason} blocks=[${(p.content || []).map(b => b.type).join(',')}] err=${p.error?.type || ''}:${(p.error?.message || '').slice(0, 80)}`);
        reject(new Error(p.error?.message || 'API error')); } catch (e) { reject(e); } });
    });
    req.on('error', reject);
    req.setTimeout(90000, () => { req.destroy(); reject(new Error('timeout')); });
    req.write(body); req.end();
  });
}

// Retry on 'Overloaded' — up to 3 attempts with exponential backoff
async function callClaude(system, user, maxTokens = 1500, model = MODEL_SONNET, extras) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      return await _callClaudeOnce(system, user, maxTokens, model, extras);
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
function _callClaudeStreamOnce(system, user, maxTokens, model, onDelta, extras) {
  const { tag, ex } = splitTag(extras); extras = ex;
  const usage = {};
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(Object.assign({ model, max_tokens: maxTokens, system, stream: true, messages: [{ role: 'user', content: user }] }, extras || {}));
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
      const seenBlocks = []; let stopReason = '';
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
            } else if (evt.type === 'content_block_start') {
              seenBlocks.push(evt.content_block?.type || '?');
            } else if (evt.type === 'message_delta' && evt.delta?.stop_reason) {
              stopReason = evt.delta.stop_reason;
              if (evt.usage) Object.assign(usage, { output_tokens: evt.usage.output_tokens });
            } else if (evt.type === 'message_start' && !Array.isArray(system)) {
              Object.assign(usage, evt.message?.usage || {});
            } else if (evt.type === 'message_start' && Array.isArray(system)) {
              Object.assign(usage, evt.message?.usage || {});
              // Prompt caching check (live answers send system as blocks with a cache marker)
              const u = evt.message?.usage || {};
              console.log(`[Cache] ${model} input=${u.input_tokens} cached_read=${u.cache_read_input_tokens || 0} cache_write=${u.cache_creation_input_tokens || 0}`);
            } else if (evt.type === 'error') {
              reject(new Error(evt.error?.message || 'stream error'));
            }
          } catch (e) { /* ignore keep-alive / partial lines */ }
        }
      });
      res.on('end', () => {
        logUsage(tag, model, usage);
        if (!full) console.log(`[Stream] ${model} ended with NO text — stop_reason=${stopReason || 'none'} blocks=[${seenBlocks.join(',')}]`);
        else if (Array.isArray(system)) console.log(`[Stream] ${model} blocks=[${seenBlocks.join(',')}] stop=${stopReason}`);
        resolve(full);
      });
    });
    req.on('error', reject);
    req.setTimeout(90000, () => { req.destroy(); reject(new Error('timeout')); });
    req.write(body); req.end();
  });
}

// Retry wrapper — only retries on Overloaded BEFORE any text has streamed, so we
// never emit duplicate deltas. Once streaming has begun, an error rejects and the
// caller falls back to the buffered path.
async function callClaudeStream(system, user, maxTokens = 600, model = MODEL_SONNET, onDelta = () => {}, extras) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    let emitted = false;
    try {
      return await _callClaudeStreamOnce(system, user, maxTokens, model, (t) => { emitted = true; onDelta(t); }, extras);
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
function callClaudeVision(system, imageBase64, textPrompt, maxTokens = 1500, model = MODEL_HAIKU, imgMediaType = 'image/jpeg', extras) {
  const { tag, ex } = splitTag(extras); extras = ex;
  return new Promise((resolve, reject) => {
    const bodyObj = Object.assign({}, extras || {}, {
      model, max_tokens: maxTokens, system,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: imgMediaType, data: imageBase64 } },
          { type: 'text', text: textPrompt }
        ]
      }]
    });
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
          logUsage(tag, model, p.usage);
          const txt = (p.content || []).filter(b => b.type === 'text').map(b => b.text).join(''); // text blocks anywhere (thinking may come first)
          if (txt) { resolve(txt); }
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
      FROM sessions s WHERE s.user_id = $1 AND coalesce(s.kind, 'interview') <> 'assessment' ORDER BY s.created_at DESC
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
    // Must-have answers ready before the interview (background; paid plans) — see ensureMustHavesReady
    prepareMustHaveAnswers(req.params.id, req.userId).catch(e => console.error('[MustHave] build prepare failed:', e.message));
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
// Prepared answers are generated ahead of time (no live latency) → the stronger model; mock interview 26 Sep found the
// fast model rewriting an employer's industry in a prepared "tell me about yourself".
const PREPARED_MODEL = MODELS[process.env.PREPARED_MODEL] || MODEL_SONNET;

// Years of experience computed from the resume's date ranges — the model kept doing this arithmetic wrong
// ("about four years" for 2020–now, "3.5 years" for Mar 2022–now). ONE place; used by live and prepared answers.
const _MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, sept: 8, oct: 9, nov: 10, dec: 11 };
function experienceFacts(resume, today = new Date()) {
  const re = /(?:\b(jan|feb|mar|apr|may|jun|jul|aug|sept?|oct|nov|dec)[a-z]*\.?\s+)?\b((?:19|20)\d{2})\s*(?:–|—|-|to)\s*(?:(jan|feb|mar|apr|may|jun|jul|aug|sept?|oct|nov|dec)[a-z]*\.?\s+)?((?:19|20)\d{2}|present|current|now|today)\b/gi;
  const jobs = [];
  for (const line of String(resume || '').split('\n')) {
    let m; re.lastIndex = 0;
    while ((m = re.exec(line))) {
      const sy = +m[2], sm = m[1] ? _MONTHS[m[1].toLowerCase().slice(0, 3)] : 0;
      const open = /present|current|now|today/i.test(m[4]);
      const ey = open ? today.getFullYear() : +m[4];
      const em = open ? today.getMonth() : (m[3] ? _MONTHS[m[3].toLowerCase().slice(0, 3)] : (m[1] ? sm : 0));
      const months = (ey - sy) * 12 + (em - sm);
      if (months < 0 || months > 600) continue;
      const label = line.slice(0, m.index).replace(/[\s(,–—-]+$/, '').replace(/^[\s•*-]+/, '').slice(0, 70) || 'Role';
      jobs.push({ label, sy, sm, ey, em, months, range: m[0] });
    }
  }
  if (!jobs.length) return '';
  const yrs = mo => { const y = Math.round(mo / 6) / 2; return (y % 1 ? y.toFixed(1) : String(y)) + ' year' + (y === 1 ? '' : 's'); };
  const first = Math.min(...jobs.map(j => j.sy * 12 + j.sm)), last = Math.max(...jobs.map(j => j.ey * 12 + j.em));
  return 'EXPERIENCE (computed from the resume dates — use exactly these numbers, never work out years yourself):\n' +
    jobs.map(j => `- ${j.label} (${j.range}): about ${yrs(j.months)}`).join('\n') +
    `\n- Total, earliest start to now: about ${yrs(last - first)}`;
}

// ONE answer generator for prepared (bank) answers — used by the Generate buttons (generate-batch route) and by
// ensureMustHavesReady. Writes each answer to the question row; returns [{ id, answer } | { id, error }].
async function answerSessionQuestions(session, batch) {
  const results = [];
  const qaBank = getQABank();
  const expFacts = experienceFacts(session.resume); // computed years — see experienceFacts
  const expBlock = expFacts ? `\n\n${expFacts}` : '';

  const stylePrompt = getStylePrompt(session.answer_style);
  if (batch.length === 1) {
    try {
      const answer = await callClaude(stylePrompt,
        `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume}${expBlock}\n\nJD:\n${session.jd}\n\nQuestion:\n${batch[0].text}\n\nAnswer the question naturally. Only reference companies or role titles if the question specifically asks about your experience. Use only facts from the resume and Q&A bank — never invent employers, projects, tools, skills, numbers or learning, and never change what an employer does to fit the job.`,
        1500, PREPARED_MODEL
      );
      await pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, batch[0].id]);
      results.push({ id: batch[0].id, answer });
    } catch(e) { results.push({ id: batch[0].id, error: e.message }); }
  } else {
    const questionsBlock = batch.map((q, idx) => `Q${idx + 1}: ${q.text}`).join('\n');
    try {
      const batchResponse = await callClaude(getBatchPrompt(session.answer_style),
        `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume}${expBlock}\n\nJD:\n${session.jd}\n\n${batch.length} QUESTIONS TO ANSWER:\n${questionsBlock}\n\nAnswer each question naturally. Use the ===Q1=== ===Q2=== format. Only reference companies or role titles when the question specifically asks about experience. Use only facts from the resume and Q&A bank — never invent employers, projects, tools, skills, numbers or learning, and never change what an employer does to fit the job.`,
        batch.length * 1500, PREPARED_MODEL
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
      // Any answer the combined reply didn't yield (its format varies by model) gets its own call — never dropped.
      const missing = results.filter(r => r.error === 'Empty answer in batch').map(r => r.id);
      if (missing.length) console.log(`[Answers] ${missing.length}/${batch.length} missing from the batch reply — answering them one by one`);
      for (const id of missing) {
        const q = batch.find(b => b.id === id); const slot = results.findIndex(r => r.id === id);
        try {
          const answer = await callClaude(stylePrompt,
            `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume}${expBlock}\n\nJD:\n${session.jd}\n\nQuestion:\n${q.text}\n\nAnswer the question naturally. Only reference companies or role titles if the question specifically asks about your experience. Use only facts from the resume and Q&A bank — never invent employers, projects, tools, skills, numbers or learning, and never change what an employer does to fit the job.`,
            1500, PREPARED_MODEL
          );
          await pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, id]);
          results[slot] = { id, answer };
        } catch (e3) { results[slot] = { id, error: e3.message }; }
      }
    } catch(e) {
      for (const q of batch) {
        try {
          const answer = await callClaude(stylePrompt,
            `Q&A BANK:\n${qaBank}\n\nResume:\n${session.resume}${expBlock}\n\nJD:\n${session.jd}\n\nQuestion:\n${q.text}\n\nAnswer the question naturally. Only reference companies or role titles if the question specifically asks about your experience. Use only facts from the resume and Q&A bank — never invent employers, projects, tools, skills, numbers or learning, and never change what an employer does to fit the job.`,
            1500, PREPARED_MODEL
          );
          await pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, q.id]);
          results.push({ id: q.id, answer });
        } catch(e2) { results.push({ id: q.id, error: e2.message }); }
      }
    }
  }
  return results;
}

// Must-have questions (MUST_HAVE, incl. influence & pushback) in EVERY session, answers prepared before they're
// asked. Inserts missing ones (starred) now; prepares answers in the background — paid plans only (free plans cap
// answers in the web app, so they get the questions and generate within their limit). Idempotent.
async function insertMissingMustHaves(sessionId) {
  const existing = await pool.query('SELECT text FROM questions WHERE session_id = $1', [sessionId]);
  const have = new Set(existing.rows.map(q => q.text.toLowerCase().replace(/[^a-z]/g, '')));
  let added = 0;
  for (const q of MUST_HAVE) {
    const key = q.toLowerCase().replace(/[^a-z]/g, '');
    if (have.has(key)) continue;
    have.add(key);
    await pool.query('INSERT INTO questions (session_id, text, type, starred, sort_order) VALUES ($1, $2, $3, true, 0)', [sessionId, q, detectType(q)]);
    added++;
  }
  return added;
}
async function prepareMustHaveAnswers(sessionId, userId, onBatch) {
  const u = await pool.query('SELECT plan, is_admin FROM users WHERE id = $1', [userId]);
  const user = u.rows[0] || {};
  if (!user.is_admin && (user.plan || 'free') === 'free') return 0;
  const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [sessionId, userId]);
  if (!s.rows.length) return 0;
  const keys = new Set(MUST_HAVE.map(q => q.toLowerCase().replace(/[^a-z]/g, '')));
  const qs = (await pool.query("SELECT * FROM questions WHERE session_id = $1 AND (answer IS NULL OR answer = '')", [sessionId])).rows
    .filter(q => keys.has(q.text.toLowerCase().replace(/[^a-z]/g, '')));
  let done = 0;
  for (let i = 0; i < qs.length; i += 5) { // same batch size as Generate All
    const res = await answerSessionQuestions(s.rows[0], qs.slice(i, i + 5));
    done += res.filter(r => r.answer).length;
    res.filter(r => r.error).forEach(r => console.log(`[MustHave] Answer failed for ${r.id}: ${r.error}`));
    if (onBatch && res.some(r => r.answer)) { try { await onBatch(); } catch (e) {} } // a live call picks these up now
  }
  if (qs.length) console.log(`[MustHave] Prepared ${done}/${qs.length} answers for session ${sessionId}`);
  return done;
}
async function ensureMustHavesReady(sessionId, userId, onBatch) {
  const added = await insertMissingMustHaves(sessionId);
  if (added) console.log(`[MustHave] Added ${added} must-have questions to session ${sessionId}`);
  // MUSTHAVE_PREBUILD=0 (local test servers): don't pre-write ~20 Sonnet answers for every throwaway test session —
  // that was most of the 26 Sep test bill. They are still written the first time a question is actually asked.
  if (process.env.MUSTHAVE_PREBUILD === '0') return { added, answered: Promise.resolve(0) };
  return { added, answered: prepareMustHaveAnswers(sessionId, userId, onBatch) }; // answered: a promise (background)
}

app.post('/api/sessions/:id/generate-batch', authMiddleware, async (req, res) => {
  try {
    const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Not found' });
    const session = s.rows[0];
    const { questionIds } = req.body;
    if (!questionIds || !questionIds.length) return res.status(400).json({ error: 'No question IDs' });

    const qResult = await pool.query('SELECT * FROM questions WHERE id = ANY($1) AND session_id = $2', [questionIds, req.params.id]);
    const batch = questionIds.map(id => qResult.rows.find(q => q.id === id)).filter(Boolean);
    if (!batch.length) return res.status(404).json({ error: 'Questions not found' });

    const results = await answerSessionQuestions(session, batch);

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
    // A live call already running for this session picks up the new style on its NEXT answer (it caches the session).
    (sessionClients.get(req.params.id) || new Set()).forEach(c => { if (c._sessionContext) c._sessionContext.answer_style = style; });

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
    const lines = transcriptLines(tx.transcript);
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

    // The Answer Note's questions, numbered: the notes say which one each call question IS (same intent, any wording).
    // Wording alone cannot tell (measured 24 Oct: rewordings score 0.08 to 0.7, different questions up to 0.71).
    const noteQs = (await pool.query(`SELECT g.id, g.name, (SELECT i.question FROM answer_note_items i WHERE i.group_id = g.id ORDER BY i.sort_order, i.created_at LIMIT 1) AS q
      FROM answer_note_groups g JOIN answer_notes n ON n.id = g.note_id WHERE n.user_id = $1 ORDER BY g.sort_order LIMIT 150`, [req.userId])).rows.filter(r => r.q);
    const noteList = noteQs.length ? '\n\nCANDIDATE\'S NOTE (numbered questions they already prepared):\n' + noteQs.map((r, i) => `${i + 1}. ${r.q}`).join('\n') : '';

    // Format transcript for AI: who said it (Interviewer / Candidate), echoes and mic bleed dropped (labelTranscript),
    // so the notes never put the interviewer's words in the candidate's mouth (Answer Note call memory, 24 Oct).
    const txText = labelTranscript(lines).join('\n');

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
  "nextCallPrep": ["specific suggestions for what to prepare for the next round based on this call"],
  "aboutThem": ["facts the interviewers shared about the company, team, role, tools, data, problems, process, people (names and titles), next steps"],
  "candidateSaid": ["what the candidate claimed or told in this call: stories, tools, numbers, reasons, salary or dates given, so the next call stays consistent"],
  "noteQuestions": [{"title": "2 to 4 word label", "question": "the interviewer's real question, cleaned into one clear sentence", "ways": ["up to 3 other ways to word THAT SAME question"], "sameAs": 0}],
  "likelyNext": [{"title": "2 to 4 word label", "question": "a question the next round will likely ask, given this call", "ways": ["up to 3 other ways to word that same question"], "sameAs": 0}]
}

noteQuestions: every real interview question the interviewer asked (skip small talk, logistics chatter and "can you hear me"); merge a question asked in two parts into one. likelyNext: at most 5, specific to what came up. "ways" are rewordings of the same question, never a different question. "sameAs": the number of the question in CANDIDATE'S NOTE that asks the same thing (same intent, any wording), else 0. Plain words, no em dashes.

Be specific — reference actual topics, tools, and moments from the transcript. No generic advice.`,
      ctxLine + 'TRANSCRIPT (' + duration + ' min, ' + lines.length + ' lines):\n' + txText.substring(0, 14000) + priorContext + noteList,
      3500, MODEL_HAIKU
    );

    let report;
    try {
      const jsonMatch = reportResult.match(/\{[\s\S]*\}/);
      report = jsonMatch ? JSON.parse(jsonMatch[0]) : { summary: reportResult, error: 'Could not parse structured report' };
    } catch (e) {
      report = { summary: reportResult.substring(0, 500), error: 'Parse failed' };
    }

    // "sameAs" number → the note question it is (id + title), so the note can say "In your note: Prioritizing"
    for (const k of ['noteQuestions', 'likelyNext']) if (Array.isArray(report[k])) report[k] = report[k].map(q => {
      const hit = noteQs[(parseInt(q && q.sameAs, 10) || 0) - 1];
      return { ...q, sameAs: hit ? { id: hit.id, name: hit.name } : null };
    });

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
const SCREEN_ASSIST_PROMPT = `You help a candidate during an online ASSESSMENT or interview task shown on their screen. It can be ANY kind of
assessment: multiple choice, true/false, select-all, numerical or logic reasoning, situational judgement, personality
(agree/disagree, most/least like me), coding, SQL, spreadsheet, data tables, or a written response.

You give a SUGGESTION the candidate can act on in seconds — never an essay, never a description of the screen.

OUTPUT CONTRACT — follow exactly:
Line 1: QUESTION: <the item being asked right now, in at most 20 words>
        or QUESTION: NONE when no question or task is on screen (instructions page, loading, results, a blank editor
        with no task, a video call with no question).
Line 2: ---
Then the suggestion, by kind:
- Multiple choice / true-false / select-all: **Suggested: B** — <that option's text>
  then ONE line: why.
- Numerical / logic: **Suggested: <value>**
  then ONE line of working.
- Behavioral / situational judgement / personality (most/least effective, rank actions, agree-disagree, "most like
  me"): there is no single right answer — make a GOOD-FAITH best-fit pick for a strong candidate in this role, decisively,
  never "it depends" and never "unsure". **Suggested: Most — A · Least — D** or **Suggested: Agree**
  then ONE line: what that choice shows (ownership, teamwork, honesty, calm under pressure…). Keep picks consistent with
  the earlier items in the step history — personality tests check for contradictions.
- Coding / SQL / any real programming task: the REAL answer — the complete, working solution in a code block in the
  language and signature on screen, ready to paste and pass the tests; then one line with the approach and time/space
  complexity. Handle the edge cases the task names. Do NOT invent functions, APIs or flags.
- Spreadsheet: **Suggested: <exact formula>** in <cell>, then one line why.
- Written / open response: 3–5 short lines the candidate can type, in their own voice, using their real experience.
- Several items visible: the same short block for each, numbered as on screen.
- Data or tables with no question yet: QUESTION: NONE (it is remembered for later items).

RULES:
- Lead with the suggestion. No preamble, no headers, no closing lines, no "the screen shows".
- Only when the item is cut off or unreadable: write **Suggested (unsure): …** and name what is missing. Never invent options.
- Use the candidate's real experience only for written responses; never invent employers, dates or numbers.
- Use \`backticks\` for code terms.`;

// Screen memory — rolling buffer of what was seen per session, so later items can use earlier tables/code
const screenAssistMemory = new Map(); // sessionId → [{ ts, summary }]
const SCREEN_MEMORY_MAX = 8; // Keep last 8 captures
const SCREEN_MEMORY_TTL = 30 * 60 * 1000; // Expire after 30 min
const screenLastQuestion = new Map(); // sessionId → last item suggested for (auto captures stay quiet while it is unchanged)
const screenActivity = new Map(); // sessionId → last screen capture time (keeps the live connection from idling out)

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

// Split the model's reply into the item it saw and the suggestion (see SCREEN_ASSIST_PROMPT's output contract)
function parseScreenReply(text) {
  const m = String(text || '').match(/^\s*QUESTION:\s*(.*?)\s*\n\s*-{3,}\s*\n?([\s\S]*)$/i);
  if (!m) return { question: '', suggestion: String(text || '').trim() };
  const q = m[1].trim();
  return { question: /^none\.?$/i.test(q) ? 'NONE' : q, suggestion: m[2].trim() };
}

// Same item as last time? Word overlap, so a re-read with slightly different wording still counts as the same item
function sameScreenQuestion(a, b) {
  const words = s => new Set(String(s || '').toLowerCase().replace(/[^a-z0-9 ]/g, ' ').split(/\s+/).filter(w => w.length > 2));
  const A = words(a), B = words(b);
  if (!A.size || !B.size) return false;
  let inter = 0; for (const w of A) if (B.has(w)) inter++;
  return inter / (A.size + B.size - inter) >= 0.6;
}

app.post('/api/sessions/:id/screen-assist', authMiddleware, async (req, res) => {
  try {
    // auto = the Record loop's capture (stay quiet unless a NEW item is on screen); instruction = what the candidate typed
    const { image, auto, instruction } = req.body;
    if (!image) return res.status(400).json({ error: 'No image provided' });

    const sessionId = req.params.id;
    const s = await pool.query('SELECT resume, jd, company, role FROM sessions WHERE id = $1 AND user_id = $2', [sessionId, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Session not found' });
    screenActivity.set(sessionId, Date.now());

    const session = s.rows[0];
    const company = session.company || 'the company';
    const role = session.role || 'this role';

    // Strip data URL prefix if present, detect media type
    const mediaMatch = image.match(/^data:image\/([\w+]+);base64,/);
    const mediaType = mediaMatch ? 'image/' + mediaMatch[1] : 'image/jpeg';
    const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
    console.log('[Screen Assist] Image size:', (base64Data.length / 1024).toFixed(0) + 'KB, type:', mediaType, auto ? '(auto)' : '(pressed)', instruction ? 'typed="' + String(instruction).slice(0, 60) + '"' : '');

    // Build context from previous screen captures (memory)
    const priorCaptures = getScreenMemory(sessionId);
    let memoryContext = '';
    if (priorCaptures.length > 0) {
      memoryContext = '\n\nSTEP HISTORY — earlier screens in this assessment (use their tables/code/answers when the current item refers to them):\n' +
        priorCaptures.map((m, i) => 'Screen ' + (i + 1) + ':\n' + m.summary).join('\n\n');
    }

    const textPrompt = 'ASSESSMENT FOR: ' + role + ' at ' + company +
      '\n\nCANDIDATE RESUME:\n' + (session.resume || 'N/A') +
      memoryContext +
      (instruction ? '\n\nTHE CANDIDATE TYPED (this IS the question to answer; the screen is context for it, and if the screen shows nothing related, answer the typed text from the résumé and the role — never answer QUESTION: NONE when the candidate typed): "' + String(instruction).slice(0, 500) + '"' : '') +
      '\n\nGive your suggestion for the item on screen now, following the output contract.';

    const reply = await callClaudeVision(SCREEN_ASSIST_PROMPT, base64Data, textPrompt, 3000, MODEL_SONNET, mediaType); // room for a full coding solution
    let { question, suggestion } = parseScreenReply(reply);
    if (instruction && !suggestion) suggestion = String(reply || '').trim(); // what he typed never gets an empty answer (owner, 4 Oct: "No question on screen yet" to a typed question)
    const prev = screenLastQuestion.get(sessionId);
    const noItem = !instruction && (question === 'NONE' || !suggestion);
    const sameItem = !noItem && prev && sameScreenQuestion(prev, question);

    if (!noItem || !prev) addScreenMemory(sessionId, ('Item: ' + question + '\n' + suggestion).substring(0, 600));
    if (auto && (noItem || sameItem)) {
      // Nothing new to suggest — no card (the Record loop used to drop a fresh card every capture, 2 Oct)
      console.log('[Screen Assist] quiet —', noItem ? 'no item on screen' : 'same item as before', '| q="' + question.slice(0, 80) + '"');
      return res.json({ unchanged: true, reason: noItem ? 'no_item' : 'same_item', question });
    }
    if (!noItem) screenLastQuestion.set(sessionId, question);
    const answer = noItem ? 'No question on screen yet — capture again when one is showing.' : suggestion;
    const questionText = noItem ? 'Screen' : (instruction || question);
    console.log('[Screen Assist] suggestion | q="' + questionText.slice(0, 80) + '" chars=' + answer.length);

    // Screen items are NOT saved to the question bank: they were feeding screen output back in as prepared answers
    const qId = 'screen-' + Date.now();
    broadcastToSession(sessionId, { type: 'screen_assist', questionId: qId, questionText, answer, generated: true });
    res.json({ questionId: qId, questionText, answer });
  } catch (e) {
    console.error('[Screen Assist Error]', e.message, e.stack);
    res.status(500).json({ error: 'Screen analysis failed: ' + e.message });
  }
});

// ============ MEETING CO-PILOT ============
// Owner (3 Oct 2026): co-pilot is for WORK MEETINGS — others share a screen (table, notes, questions) and ask him
// something; it listens, reads the shared screen and says what to say. Logic lives in lib/meeting-copilot.js; the call
// log (call_events) is written only during a live call. Design: docs/superpowers/specs/2026-10-03-meeting-copilot-design.md
const copilotDigests = new Map(); // callId → { text, lastAt, lastCount, running } (smart-mode compaction state)
const copilotDocs = new Map();    // callId → last recorded reference text (a document is logged once per call)

function liveWsForSession(sessionId) {
  const clients = sessionClients.get(sessionId);
  if (!clients) return null;
  for (const c of clients) if (c._callId && c.readyState === WebSocket.OPEN) return c;
  return null;
}

async function loadCallRows(callId) {
  // The NEWEST 400 rows, in time order. (Was the oldest 400: on 9 Oct a long call sat at rows=400 from 18:24 on — every
  // later screen, answer and digest was invisible to the co-pilot.) The digest row carries the compacted start.
  // Pages, answers and documents ALWAYS load (an all-day call keeps every page reachable); talk = the newest 400 lines;
  // the digest = the newest one (it already folds in everything before it).
  const r = await pool.query(`SELECT kind, text, meta, ts FROM (
      (SELECT kind, text, meta, ts FROM call_events WHERE call_id = $1 AND kind IN ('seen', 'said', 'document'))
      UNION ALL (SELECT kind, text, meta, ts FROM call_events WHERE call_id = $1 AND kind NOT IN ('seen', 'said', 'document', 'digest') ORDER BY ts DESC LIMIT 400)
      UNION ALL (SELECT kind, text, meta, ts FROM call_events WHERE call_id = $1 AND kind = 'digest' ORDER BY ts DESC LIMIT 1)
    ) t ORDER BY ts ASC`, [callId]);
  return r.rows.map(x => ({ kind: x.kind, text: x.text, meta: x.meta || {}, ts: new Date(x.ts).getTime() }));
}

// Smart mode only: compact the call in the background on a budget (≤ 1 run per 3 min, only with new rows) — never on
// the answer's clock. The digest row survives a server restart.
function maybeCompactCall(sessionId, callId, rows, historyOn) {
  const st = copilotDigests.get(callId) || { text: '', lastAt: 0, lastCount: 0, running: false };
  copilotDigests.set(callId, st);
  // Counted by time, not by position: the row window holds the newest 400, so positions shift on a long call
  const newer = rows.filter(r => r.kind !== 'digest' && r.ts > (st.lastTs || 0)).length;
  if (st.running || !meetingCopilot.shouldCompact(st, { now: Date.now(), rowCount: (st.lastCount || 0) + newer, historyOn })) return;
  return compactCall(sessionId, callId, rows, st);
}
// Compact now (awaitable). At an Assist with no digest and more raw talk than fits word for word, the server waits for
// this so the start of a long call is not dropped (3 Oct: the first 40 s of an update were stored but never handed over).
function compactCall(sessionId, callId, rows, st) {
  const freshRows = rows.filter(r => r.kind !== 'digest' && r.ts > (st.lastTs || 0));
  st.running = true;
  const fresh = freshRows.map(r => `[${r.kind}] ${r.text}`).join('\n');
  const user = (st.text ? `CURRENT NOTES:\n${st.text}\n\n` : '') + `NEW LINES (newest last):\n${fresh}\n\nUPDATED NOTES:`;
  const t0 = Date.now(), count = (st.lastCount || 0) + freshRows.length, upTo = freshRows.length ? freshRows[freshRows.length - 1].ts : (st.lastTs || 0);
  return callClaude(meetingCopilot.DIGEST_PROMPT, user, 600, MODEL_HAIKU, { __tag: 'copilot-digest' }).then(out => {
    st.text = String(out || '').trim(); st.lastAt = Date.now(); st.lastCount = count; st.lastTs = upTo;
    recordCallEvent(sessionId, callId, 'digest', st.text, { rows: count, upTo });
    console.log(`[Co-pilot] digest updated in ${Date.now() - t0}ms (${st.text.length} chars from ${count} rows)`);
    return st.text;
  }).catch(e => { console.error('[Co-pilot] digest failed:', e.message); return st.text; }).finally(() => { st.running = false; });
}

// At assist time: every stored screen of this call not yet read is read ONCE (Sonnet, thinking off, 4 at a time) and
// becomes a `seen` row. Returns how many were read.
// One read at a time per call (live 26 Oct: a Say and a heard question pressed together both read the same 11 screens)
const pendingReads = new Map();
function readPendingScreens(sessionId, callId) {
  if (pendingReads.has(callId)) return pendingReads.get(callId);
  const p = readPendingScreensOnce(sessionId, callId).finally(() => pendingReads.delete(callId));
  pendingReads.set(callId, p);
  return p;
}
async function readPendingScreensOnce(sessionId, callId) {
  const pend = (await pool.query('SELECT id, key, media_type, image, meta FROM call_screens WHERE call_id = $1 AND transcript IS NULL AND image IS NOT NULL ORDER BY ts ASC', [callId])).rows;
  if (!pend.length) return 0;
  const t0 = Date.now(); let done = 0;
  const tModel = meetingCopilot.transcribeModelFor('smart') === 'sonnet' ? MODEL_SONNET : MODEL_HAIKU;
  const one = async p => {
    try {
      const txt = String(await callClaudeVision(meetingCopilot.TRANSCRIBE_PROMPT, p.image.toString('base64'), 'Transcribe the screen.', 900, tModel, p.media_type || 'image/jpeg', Object.assign({ __tag: 'copilot-read' }, meetingCopilot.transcribeExtras())) || '').trim();
      await pool.query('UPDATE call_screens SET transcript = $1, image = NULL WHERE id = $2', [txt, p.id]); // live keeps no frames: once read, only the text stays
      await recordCallEvent(sessionId, callId, 'seen', txt, Object.assign({ key: p.key, full: true }, p.meta || {}));
      done++;
      console.log(`[Co-pilot] read ${p.key} (${txt.length} chars) :: ${txt.replace(/\s+/g, ' ').slice(0, 200)}`);
    } catch (e) { console.error('[Co-pilot] read failed for', p.key, e.message); }
  };
  // All at once (up to 16): 8 at a time made 11 coding screens two rounds, 14.4 s before the answer began (live 26 Oct)
  for (let i = 0; i < pend.length; i += 16) await Promise.all(pend.slice(i, i + 16).map(one));
  console.log(`[Co-pilot] read ${done} pending screens at assist in ${Date.now() - t0}ms on ${tModel}`);
  return done;
}

app.post('/api/sessions/:id/copilot', authMiddleware, async (req, res) => {
  try {
    const sessionId = req.params.id;
    const { image, pressed, context } = req.body;
    const screenKey = String(req.body.screenKey || '').slice(0, 40);
    const captureError = String(req.body.captureError || '').slice(0, 200);
    if (captureError) console.warn('[Co-pilot] capture problem on the client:', captureError); // client's id for this screen: new capture → tags the seen row; repeat → reuse that row
    const ask = String(req.body.ask || req.body.transcript || '').trim(); // `transcript` = the older client field
    const say = !!req.body.say; // the Say button: answer what they just asked of this person (owner, 3 Oct)
    const typed = !!req.body.typed; // typed in the box: his own instruction — do it, never judge it (owner, 4 Oct)
    const live = liveWsForSession(sessionId);
    if (!live) return res.status(409).json({ error: 'Go Live first — co-pilot works during a live call' });
    const callId = live._callId;
    const s = await pool.query('SELECT company, role, resume, jd, kind FROM sessions WHERE id = $1 AND user_id = $2', [sessionId, req.userId]);
    if (!s.rows.length) return res.status(404).json({ error: 'Session not found' });
    screenActivity.set(sessionId, Date.now()); // co-pilot use is activity — keeps the live connection from idling out

    const historyOn = !!live._copilotHistory;
    const mode = historyOn ? 'smart' : 'regular';
    const docs = String(context || '').trim();
    if (docs && copilotDocs.get(callId) !== docs) { copilotDocs.set(callId, docs); recordCallEvent(sessionId, callId, 'document', docs, {}); }
    let rows = await loadCallRows(callId);
    let digest = (copilotDigests.get(callId) || {}).text;
    if (!digest) { const d = rows.filter(r => r.kind === 'digest').pop(); if (d) digest = d.text; }
    if (historyOn && !digest && !req.body.auto && !req.body.capture && meetingCopilot.rawCharsOf(rows) > meetingCopilot.SMART_RAW_CHARS) {
      // more talk than fits word for word and nothing compacted yet: compact first, on the answer's clock, rather than drop the start
      const st = copilotDigests.get(callId) || { text: '', lastAt: 0, lastCount: 0, running: false }; copilotDigests.set(callId, st);
      console.log('[Co-pilot] compacting before the answer (raw ' + meetingCopilot.rawCharsOf(rows) + ' chars, no digest yet)');
      digest = await compactCall(sessionId, callId, rows, st);
    }
    const hasImage = !!image;
    let imgBlock = null;
    if (hasImage) {
      const sniffed = meetingCopilot.sniffImage(image); // raw base64 from the overlay: type decided from the bytes
      imgBlock = { type: 'image', source: { type: 'base64', media_type: sniffed.mediaType, data: sniffed.data } };
    }
    if (req.body.auto || req.body.capture) {
      // CAPTURE = DATA COLLECTION ONLY (owner, 3 Oct: "capturing, listening and all is data collection; time of assist is
      // when you do it"). The frame is stored; it is read at the first Assist that needs it. No model call here.
      if (req.body.auto && !historyOn) return res.json({ ignored: true, reason: 'history off' });
      if (!hasImage) return res.status(400).json({ error: 'capture needs an image' });
      if (screenKey) {
        const dup = await pool.query('SELECT 1 FROM call_screens WHERE call_id = $1 AND key = $2', [callId, screenKey]);
        if (dup.rows.length) return res.json({ unchanged: true, key: screenKey });
      }
      await pool.query('INSERT INTO call_screens (session_id, call_id, key, media_type, image, meta) VALUES ($1, $2, $3, $4, $5, $6)',
        [sessionId, callId, screenKey || ('scr-' + Date.now().toString(36)), imgBlock.source.media_type, Buffer.from(imgBlock.source.data, 'base64'), JSON.stringify({ auto: !!req.body.auto, camera: !!req.body.capture })]);
      console.log(`[Co-pilot] ${req.body.auto ? 'auto-captured' : 'camera-captured'} page ${screenKey || '(no key)'} stored (${(imgBlock.source.data.length / 1024).toFixed(0)}KB) — read at assist | mask=${JSON.stringify(req.body.mask || null)}`);
      broadcastToSession(sessionId, { type: 'copilot_captured', key: screenKey });
      return res.json({ captured: true, stored: true, key: screenKey });
    }
    // ASSIST (or typed / heard question): now is when the stored pages get read — once each
    // Live 26 Oct: every press waited 7–16 s here for the new screens to be read before the card even appeared ("when i
    // click say it does nothing"). The unread screens now go into the answer itself as pictures; their text is written
    // in the background for the call's history.
    let unread = [];
    if (historyOn) {
      const pend = (await pool.query('SELECT key, media_type, image FROM call_screens WHERE call_id = $1 AND transcript IS NULL AND image IS NOT NULL ORDER BY ts DESC LIMIT 12', [callId])).rows.reverse();
      unread = pend.map(p => ({ type: 'image', source: { type: 'base64', media_type: p.media_type || 'image/jpeg', data: p.image.toString('base64') } }));
      if (pend.length) readPendingScreens(sessionId, callId).catch(e => console.error('[Co-pilot] background screen read failed:', e.message));
    }
    const unreadIntro = unread.length ? [{ type: 'text', text: `NEW SCREENS (${unread.length}, oldest first, the last is what is on screen now) — not in the screen text above yet:` }] : [];
    const isPress = !!pressed || req.body.mode === 'check' || !ask;
    const reusing = !hasImage && screenKey && rows.some(r => r.kind === 'seen' && r.meta && r.meta.key === screenKey);
    // Q&A bank = his real answers about himself; it rides with the résumé so "tell me about yourself" on a work call is true to him
    const bankQ = await pool.query("SELECT text, answer FROM questions WHERE session_id = $1 AND answer != '' ORDER BY id LIMIT 60", [sessionId]);
    const bank = bankQ.rows.map(q => `Q: ${q.text}\nA: ${q.answer}`).join('\n\n');
    const digestUpTo = ((copilotDigests.get(callId) || {}).lastTs) || ((rows.filter(r => r.kind === 'digest').pop() || {}).meta || {}).upTo || 0;
    // Smarter pull-back (13 Oct): the free rules (page numbers, "the chart", shared names/numbers) run inside the builder;
    // when they find nothing and an earlier page sits as an index line, Haiku picks from the index lines (1.5 s deadline).
    let pullIdx = [];
    const plan = meetingCopilot.planPull({ mode, rows, ask, seenKey: reusing ? screenKey : '' });
    if (plan && plan.needRouter) {
      const tP = Date.now();
      const pick = await Promise.race([
        callClaude(meetingCopilot.PULL_ROUTER_PROMPT, plan.routerInput, 30, MODEL_HAIKU, { __tag: 'copilot-pull' }).catch(e => 'PAGES: none (router failed: ' + e.message + ')'),
        new Promise(r => setTimeout(() => r('PAGES: none (router timed out)'), 1500)),
      ]);
      pullIdx = meetingCopilot.parseRouterPick(pick);
      console.log(`[Co-pilot] pull router in ${Date.now() - tP}ms → ${String(pick).trim().slice(0, 80)}`);
    }
    const parts = meetingCopilot.buildCopilotBlocks({ pullIdx, mode, rows, digest, digestUpTo, session: s.rows[0], bank, priorMemory: live._priorMemory || '', assessment: s.rows[0].kind === 'assessment', docs, ask, say, typed, pressed: isPress, screenChanged: hasImage || unread.length > 0, seenKey: reusing ? screenKey : '' });
    const model = meetingCopilot.modelFor(mode) === 'sonnet' ? MODEL_SONNET : MODEL_HAIKU;
    const cardId = 'copilot-' + Date.now();
    console.log(`[Co-pilot] ${mode} on ${model} | ${hasImage ? 'image ' + (image.length / 1024).toFixed(0) + 'KB' + (screenKey ? ' key=' + screenKey : '') : reusing ? 'no image — reusing earlier screen ' + screenKey : 'no image — using the last screen summary'} | rows=${rows.length}${unread.length ? ' +' + unread.length + ' unread screens as pictures' : ''}${digest ? ' digest' : ''} | ${say ? 'SAY ' : ''}${ask ? 'ask="' + ask.slice(0, 60) + '"' : 'pressed'}`);
    const screenState = hasImage || unread.length ? 'captured' : reusing ? 'same' : rows.some(r => r.kind === 'seen') ? 'last' : 'none';
    broadcastToSession(sessionId, { type: 'copilot_start', cardId, ask, mode, say, screen: screenState, reason: captureError || (screenState === 'none' ? 'nothing captured yet on this call' : '') });
    if (mode === 'smart') console.log('[Co-pilot] screens given:', meetingCopilot.dedupeScreens(rows.filter(r => r.kind === 'seen')).map(r => (r.meta && r.meta.key || '?') + ' "' + r.text.replace(/\s+/g, ' ').slice(0, 50) + '"').join(' | ').slice(0, 1200));

    // History mode (Sonnet): cache order — instructions + session material + every page (one block each, new pages only
    // append) are cached; the image and what changes per press come after. A press re-pays ~10% for what is cached.
    // Regular mode (Haiku): one short string, no cache (below the cacheable minimum).
    let content, system = meetingCopilot.MEETING_PROMPT;
    if (mode === 'smart') {
      system = [{ type: 'text', text: meetingCopilot.MEETING_PROMPT, cache_control: { type: 'ephemeral' } }];
      const head = [];
      if (parts.stable.length) head.push({ type: 'text', text: parts.stable.join('\n\n') });
      for (const t of parts.screens) head.push({ type: 'text', text: t });
      if (head.length) head[head.length - 1].cache_control = { type: 'ephemeral' };
      content = head.concat(unreadIntro, unread, hasImage ? [imgBlock] : [], [{ type: 'text', text: parts.volatile.join('\n\n') }]);
    } else {
      const textPrompt = parts.stable.concat(parts.screens, parts.volatile).join('\n\n');
      content = hasImage || unread.length ? unreadIntro.concat(unread, hasImage ? [imgBlock] : [], [{ type: 'text', text: textPrompt }]) : textPrompt;
    }
    const t0 = Date.now(); let first = 0;
    const answer = String(await callClaudeStream(system, content, meetingCopilot.maxTokensFor(mode, say), model, t => {
      if (!first) first = Date.now() - t0;
      broadcastToSession(sessionId, { type: 'copilot_delta', cardId, text: t });
    }, Object.assign({ __tag: 'copilot-answer' }, meetingCopilot.requestExtrasFor(mode) || {})) || '').trim();
    console.log(`[Co-pilot] answered in ${Date.now() - t0}ms (first words ${first}ms, ${answer.length} chars)`);
    broadcastToSession(sessionId, { type: 'copilot_done', cardId, answer });

    // Log what was seen (the model's own "On screen" line) and what was said, then compact in the background
    const writes = [];
    if (hasImage && historyOn) {
      // Smart mode: the whole page is transcribed in the background (Haiku) so a question pages later can use it
      const t1 = Date.now();
      writes.push(callClaudeVision(meetingCopilot.TRANSCRIBE_PROMPT, imgBlock.source.data, 'Transcribe the screen.', 900, MODEL_SONNET, imgBlock.source.media_type, Object.assign({ __tag: 'copilot-read' }, meetingCopilot.transcribeExtras()))
        .then(txt => { console.log(`[Co-pilot] screen transcribed in ${Date.now() - t1}ms (${String(txt).length} chars) :: ${String(txt).replace(/\s+/g, ' ').slice(0, 240)}`); return recordCallEvent(sessionId, callId, 'seen', txt, { key: screenKey, full: true }); })
        .catch(e => { console.error('[Co-pilot] transcription failed:', e.message); const seen = (answer.match(/^On screen:\s*(.+)$/mi) || [])[1]; return seen ? recordCallEvent(sessionId, callId, 'seen', seen, { key: screenKey }) : false; }));
    } else if (hasImage) { const seen = (answer.match(/^On screen:\s*(.+)$/mi) || [])[1]; if (seen) writes.push(recordCallEvent(sessionId, callId, 'seen', seen, { key: screenKey })); }
    writes.push(recordCallEvent(sessionId, callId, 'said', answer.slice(0, 600), { mode, cardId, ask: typed ? '' : ask.slice(0, 300), answered: meetingCopilot.answeredItems(answer) })); // the ledger keeps every block title — the text is cut at 600
    await Promise.all(writes); // on record before we answer — the response never claims what isn't logged yet
    maybeCompactCall(sessionId, callId, rows, historyOn);
    res.json({ answer, cardId, mode });
  } catch (e) {
    console.error('[Co-pilot Error]', e.message, e.stack);
    res.status(500).json({ error: 'Co-pilot failed: ' + e.message });
  }
});

// What has been captured on the live call — the owner checks this before pressing Assist ("not sure the captures is right")
app.get('/api/sessions/:id/copilot/screens', authMiddleware, async (req, res) => {
  try {
    const live = liveWsForSession(req.params.id);
    if (!live) return res.json({ screens: [], live: false });
    const r = await pool.query('SELECT key, ts, meta, (transcript IS NOT NULL) AS read, left(regexp_replace(coalesce(transcript, \'\'), \'\\s+\', \' \', \'g\'), 120) AS head FROM call_screens WHERE call_id = $1 ORDER BY ts ASC', [live._callId]);
    res.json({ live: true, screens: r.rows.map(x => ({ key: x.key, ts: x.ts, read: x.read, head: x.head || '', auto: !!(x.meta && x.meta.auto) })) });
  } catch (e) { console.error('[Co-pilot] screens list failed:', e.message); res.status(500).json({ error: e.message }); }
});

// × on a capture (owner, 3 Oct): the stored page, its frame and its text leave the live call
app.delete('/api/sessions/:id/copilot/screens/:key', authMiddleware, async (req, res) => {
  try {
    const live = liveWsForSession(req.params.id);
    if (!live) return res.status(409).json({ error: 'Go Live first' });
    const key = String(req.params.key || '').slice(0, 40);
    const a = await pool.query('DELETE FROM call_screens WHERE call_id = $1 AND key = $2', [live._callId, key]);
    await pool.query("DELETE FROM call_events WHERE call_id = $1 AND kind = 'seen' AND meta->>'key' = $2", [live._callId, key]);
    console.log(`[Co-pilot] capture ${key} deleted (${a.rowCount} frame)`);
    res.json({ deleted: a.rowCount, key });
  } catch (e) { console.error('[Co-pilot] delete capture failed:', e.message); res.status(500).json({ error: e.message }); }
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
  res.json({ ok: true }); // kept for older clients; the call log is per call and needs no reset
});

// ===== ASSESSMENT (desktop only) — logic in lib/assessment.js =====
// Each sitting (one Go Live) ends with a CARRY: Sonnet compacts everything the sitting saw and answered (+ the carry before
// it) into notes stored on live_transcripts.memory. The first carry with real content locks the assessment's title.
// Continue = a new sitting in the same assessment; its co-pilot starts from the latest carry.
const assessmentFinishing = new Map(); // callId → the carry in progress (a reconnect's new sitting waits for it, never starts blind)
function finishAssessmentCall(sessionId, callId) {
  if (!sessionId || !callId) return Promise.resolve(null);
  if (!assessmentFinishing.has(callId)) assessmentFinishing.set(callId, carryAssessmentCall(sessionId, callId).finally(() => assessmentFinishing.delete(callId)));
  return assessmentFinishing.get(callId);
}
async function carryAssessmentCall(sessionId, callId) {
  const t0 = Date.now();
  try {
    const rows = await loadCallRows(callId);
    if (!assessment.hasMaterial(rows)) { console.log(`[Assessment] sitting ${callId} has nothing to carry (${rows.length} rows)`); return null; }
    const prev = await pool.query(`SELECT memory FROM live_transcripts WHERE session_id = $1 AND id <> $2 AND coalesce(memory, '') <> ''
      AND started_at < (SELECT started_at FROM live_transcripts WHERE id = $2) ORDER BY started_at DESC LIMIT 1`, [sessionId, callId]);
    const out = await callClaude(assessment.CARRY_PROMPT, assessment.buildCarryInput((prev.rows[0] || {}).memory || '', rows), 1400, MODEL_SONNET, { __tag: 'assessment-carry', thinking: { type: 'disabled' } });
    const { title, notes } = assessment.parseCarry(out);
    if (!notes) throw new Error('the model returned no notes');
    await pool.query('UPDATE live_transcripts SET memory = $1 WHERE id = $2', [notes, callId]);
    let locked = false;
    if (title) locked = !!(await pool.query("UPDATE sessions SET title = $1 WHERE id = $2 AND coalesce(title, '') = '' RETURNING id", [title, sessionId])).rowCount;
    await pool.query('UPDATE sessions SET updated_at = NOW() WHERE id = $1', [sessionId]);
    console.log(`[Assessment] sitting ${callId} carried in ${Date.now() - t0}ms (${notes.length} chars from ${rows.length} rows)${locked ? ` — title locked: "${title}"` : ''}`);
    return notes;
  } catch (e) { console.error(`[Assessment] carry failed for sitting ${callId} after ${Date.now() - t0}ms:`, e.message); return null; }
}
// Latest carry of this assessment for a new sitting. A sitting that ended without its carry (app closed, server restart)
// gets it built now, so Continue never starts blind.
async function loadAssessmentCarry(sessionId, currentCallId) {
  const r = await pool.query('SELECT id, memory FROM live_transcripts WHERE session_id = $1 AND id <> $2 ORDER BY started_at DESC LIMIT 5', [sessionId, currentCallId]);
  for (const row of r.rows) {
    if (row.memory) return row.memory;
    const has = await pool.query("SELECT 1 FROM call_events WHERE call_id = $1 AND kind IN ('seen', 'said', 'digest') LIMIT 1", [row.id]);
    if (has.rows.length) { const m = await finishAssessmentCall(sessionId, row.id); if (m) return m; }
  }
  return '';
}
async function assessmentAllowed(req) {
  const u = await pool.query('SELECT plan, is_admin FROM users WHERE id = $1', [req.userId]);
  return assessment.canUseAssessment(u.rows[0] || { plan: req.plan, is_admin: req.isAdmin }, process.env);
}
const HAS_MATERIAL_SQL = "EXISTS (SELECT 1 FROM call_events e WHERE e.session_id = s.id AND e.kind IN ('seen', 'said', 'digest'))";

// The desktop launcher's list: assessments with content, newest sitting first, each with its locked title + start time
app.get('/api/assessments', authMiddleware, async (req, res) => {
  try {
    if (!(await assessmentAllowed(req))) return res.json({ allowed: false, items: [] });
    const r = await pool.query(`SELECT s.id, s.title, s.created_at, lt.last_used, lt.sittings,
        EXISTS (SELECT 1 FROM live_transcripts t WHERE t.session_id = s.id AND coalesce(t.memory, '') <> '') AS has_carry
      FROM sessions s
      LEFT JOIN LATERAL (SELECT max(started_at) AS last_used, count(*) AS sittings FROM live_transcripts t WHERE t.session_id = s.id) lt ON true
      WHERE s.user_id = $1 AND s.kind = 'assessment' AND ${HAS_MATERIAL_SQL}
      ORDER BY coalesce(lt.last_used, s.created_at) DESC LIMIT 50`, [req.userId]);
    // content but no title yet (its sitting never got its carry): build it in the background — the next look shows the title
    for (const x of r.rows.filter(x => !x.title).slice(0, 2)) {
      pool.query('SELECT id FROM live_transcripts WHERE session_id = $1 ORDER BY started_at DESC LIMIT 1', [x.id])
        .then(c => c.rows[0] && finishAssessmentCall(x.id, c.rows[0].id)).catch(e => console.error('[Assessment] background title failed:', e.message));
    }
    res.json({ allowed: true, items: r.rows.map(x => ({ id: x.id, title: x.title || '', started: x.created_at, lastUsed: x.last_used || x.created_at, sittings: parseInt(x.sittings, 10) || 0, carried: !!x.has_carry })) });
  } catch (e) { console.error('[Assessment] list failed:', e.message); res.status(500).json({ error: e.message }); }
});

// × on an assessment (owner, 13 Oct: "remove it completely"): the assessment and everything under it (sittings, call log,
// screens, carry) — the FKs cascade. Only kind='assessment' rows of this user; never one that is live right now.
app.delete('/api/assessments/:id', authMiddleware, async (req, res) => {
  try {
    if (!isValidUUID(req.params.id)) return res.status(400).json({ error: 'Invalid assessment' });
    if (liveWsForSession(req.params.id)) return res.status(409).json({ error: 'This assessment is open in the overlay — stop it first' });
    const d = await pool.query("DELETE FROM sessions WHERE id = $1 AND user_id = $2 AND kind = 'assessment' RETURNING title", [req.params.id, req.userId]);
    if (!d.rowCount) return res.status(404).json({ error: 'Assessment not found' });
    console.log(`[Assessment] removed ${req.params.id} ("${d.rows[0].title || 'untitled'}") for user ${req.userId}`);
    res.json({ removed: true, id: req.params.id });
  } catch (e) { console.error('[Assessment] remove failed:', e.message); res.status(500).json({ error: e.message }); }
});

// Start a new assessment. An earlier one that was opened but never got any content is reused (no pile of blanks).
// His résumé rides along from his latest interview session — a personality/behavioural section asks about him.
app.post('/api/assessments', authMiddleware, async (req, res) => {
  try {
    if (!(await assessmentAllowed(req))) return res.status(403).json({ error: 'Assessment is not on your plan' });
    const blank = await pool.query(`SELECT s.id FROM sessions s WHERE s.user_id = $1 AND s.kind = 'assessment' AND NOT ${HAS_MATERIAL_SQL} ORDER BY s.created_at DESC LIMIT 1`, [req.userId]);
    if (blank.rows.length) {
      const u = await pool.query('UPDATE sessions SET created_at = NOW(), updated_at = NOW() WHERE id = $1 RETURNING id, created_at', [blank.rows[0].id]);
      console.log(`[Assessment] new (reused blank ${u.rows[0].id}) for user ${req.userId}`);
      return res.json({ id: u.rows[0].id, started: u.rows[0].created_at, reused: true });
    }
    const rs = await pool.query("SELECT resume FROM sessions WHERE user_id = $1 AND coalesce(kind, 'interview') <> 'assessment' AND coalesce(resume, '') <> '' ORDER BY updated_at DESC LIMIT 1", [req.userId]);
    const ins = await pool.query("INSERT INTO sessions (user_id, kind, company, role, resume) VALUES ($1, 'assessment', '', '', $2) RETURNING id, created_at", [req.userId, (rs.rows[0] || {}).resume || '']);
    console.log(`[Assessment] new ${ins.rows[0].id} for user ${req.userId} (résumé ${rs.rows.length ? 'carried' : 'none'})`);
    res.json({ id: ins.rows[0].id, started: ins.rows[0].created_at, reused: false });
  } catch (e) { console.error('[Assessment] create failed:', e.message); res.status(500).json({ error: e.message }); }
});

// ============ ANSWER NOTE (owner, 23 Oct) ============
// A desktop note he reads from during a live interview. ONE note per user, seeded from data/note-seed.json on first
// open (43 questions mined from his real interviews: short title, full question, up to 3 other ways to ask it). Logic in lib/answer-note.js; this block
// is the DB + the writer. Every content write goes through answerNote.applyChange (history kept, stale writes → 409).
async function loadNote(userId) {
  let n = (await pool.query('SELECT * FROM answer_notes WHERE user_id = $1', [userId])).rows[0];
  if (!n) n = (await pool.query('INSERT INTO answer_notes (user_id) VALUES ($1) ON CONFLICT (user_id) DO UPDATE SET updated_at = NOW() RETURNING *', [userId])).rows[0];
  const has = await pool.query('SELECT 1 FROM answer_note_groups WHERE note_id = $1 LIMIT 1', [n.id]);
  if (!has.rows.length && !n.settings?.seeded) {
    let items = 0;
    for (const g of answerNote.seedRows()) {
      const gr = await pool.query('INSERT INTO answer_note_groups (note_id, name, section, sort_order) VALUES ($1, $2, $3, $4) RETURNING id', [n.id, g.name, g.section, g.sort_order]);
      for (const it of g.items) { await pool.query('INSERT INTO answer_note_items (note_id, group_id, question, sort_order) VALUES ($1, $2, $3, $4)', [n.id, gr.rows[0].id, it.question, it.sort_order]); items++; }
    }
    n = (await pool.query("UPDATE answer_notes SET settings = coalesce(settings, '{}'::jsonb) || jsonb_build_object('seeded', true, 'seedVersion', $2::int) WHERE id = $1 RETURNING *", [n.id, answerNote.SEED.version])).rows[0]; // seeded once; deleting every group later does not re-seed
    console.log(`[Note] Seeded ${items} answers in ${answerNote.seedRows().length} groups for user ${userId}`);
  } else if (n.settings?.seeded && !n.settings?.seedVersion) n = await upgradeNoteSeed(n);
  else if (n.settings?.seeded && n.settings.seedVersion < answerNote.SEED.version) n = await addNewSeedQuestions(n);
  if (!n.settings?.perJob) n = await moveNoteToPerJob(n, userId);
  if (!n.settings?.yqLast) n = await yourQuestionsToEnd(n);
  if (!n.settings?.aiAlways) n = await aiForEveryJob(n);
  return n;
}
// Once per note (owner 25 Oct: "AI, agentic AI and its current usage, my contribution and impact" matter for every
// job): the seed AI questions were made data-jobs-only by the per-job move; they show for every job again.
async function aiForEveryJob(n) {
  const names = answerNote.SEED.groups.filter(g => g.section === 'AI and tools').map(g => g.title);
  await pool.query("UPDATE answer_note_groups SET job_ids = NULL WHERE note_id = $1 AND section = 'AI and tools' AND name = ANY($2::text[])", [n.id, names]);
  return (await pool.query("UPDATE answer_notes SET settings = coalesce(settings, '{}'::jsonb) || '{\"aiAlways\": true}'::jsonb WHERE id = $1 RETURNING *", [n.id])).rows[0];
}
// Once per note (owner 25 Oct): the job sections used to land below "Your questions"; it goes back to the end, just
// above New questions. Only the order changes.
async function yourQuestionsToEnd(n) {
  const rows = (await pool.query('SELECT id, section FROM answer_note_groups WHERE note_id = $1 ORDER BY sort_order, created_at', [n.id])).rows;
  const ids = answerNote.yourQuestionsLast(rows);
  await pool.query('UPDATE answer_note_groups g SET sort_order = o.i - 1 FROM unnest($1::uuid[]) WITH ORDINALITY AS o(id, i) WHERE g.id = o.id AND g.note_id = $2', [ids, n.id]);
  return (await pool.query("UPDATE answer_notes SET settings = coalesce(settings, '{}'::jsonb) || '{\"yqLast\": true}'::jsonb WHERE id = $1 RETURNING *", [n.id])).rows[0];
}
// Where new sections go: just above "Your questions" (room is made for count), else the end. db = pool or a client.
async function slotAboveYourQuestions(db, noteId, count) {
  const p = (await db.query('SELECT min(sort_order) AS p FROM answer_note_groups WHERE note_id = $1 AND section = $2', [noteId, answerNote.YOUR_QUESTIONS])).rows[0].p;
  if (p === null || p === undefined) return (await db.query('SELECT coalesce(max(sort_order), -1) + 1 AS n FROM answer_note_groups WHERE note_id = $1', [noteId])).rows[0].n;
  await db.query('UPDATE answer_note_groups SET sort_order = sort_order + $3 WHERE note_id = $1 AND sort_order >= $2', [noteId, p, count]);
  return p;
}
// Once per note (owner 25 Oct, answers per job): the role sections become job-only, and every answer he already has
// for a per-job question is copied to the job it was written for. Nothing is deleted: the old columns stay as they were.
// "The job it was written for" = the job of his latest call, else his latest résumé (nothing recorded the job before).
async function moveNoteToPerJob(n, userId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const locked = (await client.query('SELECT * FROM answer_notes WHERE id = $1 FOR UPDATE', [n.id])).rows[0];
    if (!locked || locked.settings?.perJob) { await client.query('ROLLBACK'); return locked || n; }
    let legacy = (await client.query('SELECT s.id FROM live_transcripts t JOIN sessions s ON s.id = t.session_id AND s.user_id = t.user_id WHERE t.user_id = $1 ORDER BY t.started_at DESC LIMIT 1', [userId])).rows[0];
    if (!legacy) legacy = await noteSessionFor(userId, '');
    const lid = legacy ? legacy.id : null;
    const groups = (await client.query('SELECT * FROM answer_note_groups WHERE note_id = $1', [n.id])).rows;
    const items = (await client.query('SELECT * FROM answer_note_items WHERE note_id = $1', [n.id])).rows;
    const has = i => !!(answerNote.htmlToText(i.answer_html) || String(i.key_points || '').trim() || (i.versions || []).length);
    let linked = 0, copied = 0;
    for (const g of groups) {
      const mine = items.filter(i => i.group_id === g.id);
      if (!Array.isArray(g.job_ids) && answerNote.isRoleSection(g.section)) {
        const company = (String(g.section).match(/^from calls: (.+)$/i) || [])[1];
        let ids = company ? (await client.query('SELECT id FROM sessions WHERE user_id = $1 AND lower(company) = lower($2)', [userId, company.trim()])).rows.map(r => r.id) : [];
        if (!ids.length && lid && (company || mine.some(has))) ids = [lid]; // what he already wrote stays where he wrote it
        await client.query('UPDATE answer_note_groups SET job_ids = $1::uuid[] WHERE id = $2', [ids, g.id]); linked++;
      }
      if (lid && answerNote.scopeOf(g) === 'job') for (const i of mine.filter(has)) {
        const r = await client.query(`INSERT INTO answer_note_job_answers (item_id, session_id, answer_html, key_points, versions, version, edited_by, edit_label, updated_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (item_id, session_id) DO NOTHING`, [i.id, lid, i.answer_html || '', i.key_points || '', JSON.stringify(i.versions || []), i.version || 0, i.edited_by || '', i.edit_label || '', i.updated_at || new Date()]);
        copied += r.rowCount;
      }
    }
    const out = (await client.query("UPDATE answer_notes SET settings = coalesce(settings, '{}'::jsonb) || jsonb_build_object('perJob', 1, 'perJobFrom', $2::text) WHERE id = $1 RETURNING *", [n.id, lid || ''])).rows[0];
    await client.query('COMMIT');
    console.log(`[Note] Note ${n.id} now per job: ${linked} role groups made job-only, ${copied} answers copied to job ${lid || '(none)'}`);
    return out;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(`[Note] Per-job move failed for note ${n.id}, left as it was: ${e.message}`);
    return n;
  } finally { client.release(); }
}
// Questions added to the seed since this note was made (seed "since") go in once, after the last question of their
// section. One transaction, note row locked (two windows opening together cannot both add them). Nothing is removed.
async function addNewSeedQuestions(n) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const locked = (await client.query('SELECT * FROM answer_notes WHERE id = $1 FOR UPDATE', [n.id])).rows[0];
    const from = Number(locked && locked.settings && locked.settings.seedVersion) || 0;
    if (!locked || from >= answerNote.SEED.version) { await client.query('ROLLBACK'); return locked || n; }
    const groups = (await client.query('SELECT * FROM answer_note_groups WHERE note_id = $1', [n.id])).rows;
    const items = (await client.query('SELECT group_id, question FROM answer_note_items WHERE note_id = $1', [n.id])).rows;
    const plan = answerNote.additionsPlan(groups.map(g => ({ ...g, items: items.filter(i => i.group_id === g.id) })), from);
    for (const a of plan) {
      await client.query('UPDATE answer_note_groups SET sort_order = sort_order + 1 WHERE note_id = $1 AND sort_order > $2', [n.id, a.after]);
      const gr = await client.query('INSERT INTO answer_note_groups (note_id, name, section, sort_order, job_ids) VALUES ($1, $2, $3, $4, $5::uuid[]) RETURNING id', [n.id, a.name, a.section, a.after + 1, locked.settings?.perJob && answerNote.isRoleSection(a.section) ? [] : null]); // a role question waits for a job it fits
      for (let j = 0; j < a.items.length; j++) await client.query('INSERT INTO answer_note_items (note_id, group_id, question, sort_order) VALUES ($1, $2, $3, $4)', [n.id, gr.rows[0].id, a.items[j], j]);
    }
    const out = (await client.query("UPDATE answer_notes SET settings = coalesce(settings, '{}'::jsonb) || jsonb_build_object('seedVersion', $2::int) WHERE id = $1 RETURNING *", [n.id, answerNote.SEED.version])).rows[0];
    await client.query('COMMIT');
    console.log(`[Note] Added ${plan.length} new questions to note ${n.id} (seed v${from} → v${answerNote.SEED.version}): ${plan.map(a => a.name).join(', ')}`);
    return out;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(`[Note] Adding new questions failed for note ${n.id}, left as it was: ${e.message}`);
    return n;
  } finally { client.release(); }
}
// v1 → v2 seed (24 Oct): short titles in sections, the full question under each, at most 3 other ways. Runs once per
// note, in one transaction, the note row locked so two windows opening together cannot both run it.
// answerNote.upgradePlan decides; a row is only removed here if it is STILL empty at that moment (no answer, no KEY,
// no history), so nothing he wrote or generated can go.
async function upgradeNoteSeed(n) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const locked = (await client.query('SELECT * FROM answer_notes WHERE id = $1 FOR UPDATE', [n.id])).rows[0];
    if (!locked || locked.settings?.seedVersion) { await client.query('ROLLBACK'); return locked || n; }
    const groups = (await client.query('SELECT * FROM answer_note_groups WHERE note_id = $1', [n.id])).rows;
    const items = (await client.query('SELECT * FROM answer_note_items WHERE note_id = $1', [n.id])).rows;
    const ops = answerNote.upgradePlan(groups.map(g => ({ ...g, items: items.filter(i => i.group_id === g.id) })));
    const count = {};
    for (const o of ops) {
      count[o.op] = (count[o.op] || 0) + 1;
      if (o.op === 'updateGroup') await client.query('UPDATE answer_note_groups SET name = coalesce($1, name), section = coalesce($2, section), sort_order = $3 WHERE id = $4 AND note_id = $5', [o.name || null, o.section === undefined ? null : o.section, o.sort_order, o.id, n.id]);
      else if (o.op === 'updateItem') await client.query('UPDATE answer_note_items SET question = coalesce($1, question), sort_order = $2 WHERE id = $3 AND note_id = $4', [o.question || null, o.sort_order, o.id, n.id]);
      else if (o.op === 'insertItem') await client.query('INSERT INTO answer_note_items (note_id, group_id, question, sort_order) VALUES ($1, $2, $3, $4)', [n.id, o.group_id, o.question, o.sort_order]);
      else if (o.op === 'deleteEmptyItem') await client.query("DELETE FROM answer_note_items WHERE id = $1 AND note_id = $2 AND coalesce(answer_html, '') = '' AND coalesce(key_points, '') = '' AND coalesce(versions, '[]'::jsonb) = '[]'::jsonb", [o.id, n.id]);
      else if (o.op === 'insertGroup') {
        const gr = await client.query('INSERT INTO answer_note_groups (note_id, name, section, sort_order) VALUES ($1, $2, $3, $4) RETURNING id', [n.id, o.name, o.section || '', o.sort_order]);
        for (let j = 0; j < o.items.length; j++) await client.query('INSERT INTO answer_note_items (note_id, group_id, question, sort_order) VALUES ($1, $2, $3, $4)', [n.id, gr.rows[0].id, o.items[j], j]);
      }
    }
    const out = (await client.query("UPDATE answer_notes SET settings = coalesce(settings, '{}'::jsonb) || jsonb_build_object('seedVersion', $2::int) WHERE id = $1 RETURNING *", [n.id, answerNote.SEED.version])).rows[0]; // upgradePlan already added every current seed question
    await client.query('COMMIT');
    console.log(`[Note] Upgraded note ${n.id} to seed v${answerNote.SEED.version}: ${JSON.stringify(count)}`);
    return out;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(`[Note] Seed upgrade failed for note ${n.id}, left as it was: ${e.message}`);
    return n;
  } finally { client.release(); }
}
function noteItemOut(i) {
  return { id: i.id, group_id: i.group_id, question: i.question, answer_html: i.answer_html || '', key_points: i.key_points || '', version: i.version || 0,
    edited_by: i.edited_by || '', edit_label: i.edit_label || '', sort_order: i.sort_order, updated_at: i.updated_at,
    versions: (i.versions || []).map(v => ({ id: v.id, ts: v.ts, by: v.by, label: v.label, version: v.version, preview: answerNote.htmlToText(v.html).slice(0, 90) })) }; // history list only; the text comes back on restore
}
// Per job: a 'job' question shows the answer for the job on screen (empty until written for it); a 'you' question its
// one answer. Groups linked to other jobs only are left out.
function forJob(item, row, sid) {
  return Object.assign({}, item, { answer_html: row ? row.answer_html : '', key_points: row ? row.key_points : '', versions: row ? row.versions : [], version: row ? row.version : 0,
    edited_by: row ? row.edited_by : '', edit_label: row ? row.edit_label : '', updated_at: row ? row.updated_at : item.updated_at, _sid: sid });
}
async function noteTree(note, session) {
  const sid = session ? session.id : null;
  const groups = (await pool.query('SELECT * FROM answer_note_groups WHERE note_id = $1 ORDER BY sort_order, created_at', [note.id])).rows.filter(g => answerNote.visibleFor(g, sid));
  const items = (await pool.query('SELECT * FROM answer_note_items WHERE note_id = $1 ORDER BY sort_order, created_at', [note.id])).rows;
  const rows = sid ? new Map((await pool.query('SELECT j.* FROM answer_note_job_answers j JOIN answer_note_items i ON i.id = j.item_id WHERE i.note_id = $1 AND j.session_id = $2', [note.id, sid])).rows.map(r => [r.item_id, r])) : new Map();
  const built = ((note.settings || {}).jobsBuilt || []).includes(sid);
  return { id: note.id, settings: note.settings || {},
    job: session ? { id: session.id, company: session.company || '', role: session.role || '', people: session.note_people || '' } : null,
    needsBuild: !!session && !built && !!(String(session.jd || '').trim() || String(session.role || '').trim()),
    groups: answerNote.sortGroups(groups).map(g => { const scope = answerNote.scopeOf(g); return { id: g.id, name: g.name, section: g.section || '', color: g.color || '', pinned: !!g.pinned, sort_order: g.sort_order, scope, jobOnly: Array.isArray(g.job_ids),
      items: items.filter(i => i.group_id === g.id).map(i => noteItemOut(scope === 'job' && sid ? forJob(i, rows.get(i.id), sid) : i)) }; }) };
}
async function ownNoteGroup(userId, gid) {
  if (!isValidUUID(gid)) return null;
  return (await pool.query('SELECT g.* FROM answer_note_groups g JOIN answer_notes n ON n.id = g.note_id WHERE g.id = $1 AND n.user_id = $2', [gid, userId])).rows[0] || null;
}
// With a job: a per-job question comes back holding that job's answer (_sid set), so every write below lands on it.
async function ownNoteItem(userId, iid, session) {
  if (!isValidUUID(iid)) return null;
  const item = (await pool.query('SELECT i.*, g.name AS group_name, g.scope AS group_scope FROM answer_note_items i JOIN answer_notes n ON n.id = i.note_id JOIN answer_note_groups g ON g.id = i.group_id WHERE i.id = $1 AND n.user_id = $2', [iid, userId])).rows[0] || null;
  if (!item || !session || answerNote.scopeOf({ name: item.group_name, scope: item.group_scope }) !== 'job') return item;
  return forJob(item, (await pool.query('SELECT * FROM answer_note_job_answers WHERE item_id = $1 AND session_id = $2', [item.id, session.id])).rows[0], session.id);
}
async function writeNoteItem(item, change) { // the one write for content changes (applyChange result)
  if (item._sid) {
    const j = (await pool.query(`INSERT INTO answer_note_job_answers (item_id, session_id, answer_html, key_points, versions, version, edited_by, edit_label, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      ON CONFLICT (item_id, session_id) DO UPDATE SET answer_html = EXCLUDED.answer_html, key_points = EXCLUDED.key_points, versions = EXCLUDED.versions, version = EXCLUDED.version, edited_by = EXCLUDED.edited_by, edit_label = EXCLUDED.edit_label, updated_at = NOW() RETURNING *`,
      [item.id, item._sid, change.answer_html, change.key_points, JSON.stringify(change.versions), change.version, change.edited_by || item.edited_by || '', change.edit_label || ''])).rows[0];
    return forJob(item, j, item._sid);
  }
  const r = await pool.query('UPDATE answer_note_items SET answer_html = $1, key_points = $2, versions = $3, version = $4, edited_by = $5, edit_label = $6, updated_at = NOW() WHERE id = $7 RETURNING *',
    [change.answer_html, change.key_points, JSON.stringify(change.versions), change.version, change.edited_by || item.edited_by || '', change.edit_label || '', item.id]);
  return r.rows[0];
}
// The job the answers are written for: the chosen session, else his latest interview session that has a résumé.
async function noteSessionFor(userId, sessionId) {
  if (sessionId && isValidUUID(sessionId)) {
    const s = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [sessionId, userId]);
    if (s.rows.length) return s.rows[0];
  }
  const s = await pool.query("SELECT * FROM sessions WHERE user_id = $1 AND coalesce(kind, 'interview') <> 'assessment' AND coalesce(resume, '') <> '' ORDER BY updated_at DESC LIMIT 1", [userId]);
  return s.rows[0] || null;
}
const noteSes = req => noteSessionFor(req.userId, String(req.body?.sessionId || req.query.sessionId || '')); // the job on screen
// Note answers use the SAME writer rules as live answers (LIVE_CORE: first person, short spoken lines, a real number
// where the résumé has one, never invent; layout by question shape; style = tone) on the fast model. No conversation
// exists yet, so the answer must stand alone; his own example (↳ line) is always welcome. Ends with a KEY line for the
// 2-second glance. mode/custom = the change asked for (lib MODES); the current note text rides along for a rewrite.
async function generateNoteAnswer(session, userId, item, mode, custom) {
  const question = String(item.question || '').trim();
  const { shape, technical } = classifyQuestionShape(question);
  const vp = await pool.query('SELECT voice_profile FROM users WHERE id = $1', [userId]);
  const voiceProfile = (process.env.VOICE_PROFILE !== '0' && vp.rows[0] && vp.rows[0].voice_profile) || '';
  const styleKey = session.answer_style || 'conversational';
  const calls = await noteCallContext(session.id, userId);
  const system = composeLiveSystemPrompt({ shape, technical, styleKey, maxLines: 0, voiceProfile, withConversation: !!calls, questionText: question, employerLine: true });
  const bankRows = (await pool.query("SELECT text, answer FROM questions WHERE session_id = $1 AND answer <> '' ORDER BY id LIMIT 8", [session.id])).rows;
  const bank = bankRows.map(q => `Q: ${q.text}\nA: ${q.answer}`).join('\n\n');
  const material = `SESSION MATERIAL — the candidate and the job:\nTHIS NOTE IS FOR: ${session.role || 'this role'} at ${session.company || 'the company'}. Reference them naturally when a question asks "why this role/company"; never parrot the JD.\n\nRESUME:\n${session.resume || 'N/A'}\n\nJOB DESCRIPTION:\n${session.jd || 'N/A'}\n\nQ&A BANK (candidate's real experience — USE THIS):\n${bank || 'N/A'}`;
  const systemBlocks = [
    Object.assign({ type: 'text', text: material }, process.env.PROMPT_CACHE === '0' ? {} : { cache_control: { type: 'ephemeral' } }), // same material for every answer in the note → cached
    { type: 'text', text: system },
  ];
  const todayLine = `TODAY: ${new Date().toISOString().slice(0, 10)}\n`;
  const expFacts = experienceFacts(session.resume);
  const instruction = answerNote.changeInstruction(mode, custom);
  const current = answerNote.htmlToText(item.answer_html);
  const changeBlock = instruction && current
    ? `\n\nCURRENT ANSWER (the candidate's note as it stands):\n${current}\n\nCHANGE REQUESTED: ${instruction}\nKeep every fact that is still true; add nothing the resume or Q&A bank does not have.`
    : (instruction ? `\n\nINSTRUCTION: ${instruction}` : '');
  const user = `${todayLine}${expFacts ? expFacts + '\n' : ''}${calls ? `\nTHE CONVERSATION:\n${calls}\n` : ''}${changeBlock}\n\nQUESTION (one way an interviewer phrases it — this is a prepared note read from during a call, so the answer must stand on its own):\n${question}\n\nAnswer in the LAYOUT above. Then, as the very last line, exactly: KEY: <at most 12 words — the one thing to remember to say>\n\nAnswer:`;
  const t0 = Date.now();
  const raw = await callClaude(systemBlocks, user, shape === 'code' ? 1000 : 600, MODEL_HAIKU, { __tag: 'note-answer' });
  const { answer, keyPoints } = answerNote.parseGenerated(raw);
  const text = normalizeLiveAnswer(answer, shape, { cap: liveLineCap(styleKey, 0, shape), employerLineAllowed: true, cueOnly: (STYLE_LAYOUT[styleKey] || {}).unit === 'cue' && shape !== 'code' });
  console.log(`[Note] ${mode || 'regenerate'} shape=${shape} ${Date.now() - t0}ms calls=${calls.length} lines=${(text || '').split('\n').length} key=${keyPoints ? 'yes' : 'no'} q="${question.slice(0, 50)}"`);
  if (!text || isNonAnswer(text)) throw new Error('The writer gave no usable answer. Try again.');
  return { answerHtml: answerNote.answerToHtml(text), keyPoints };
}
// The same short note answers, up to 5 per call (Write all answers). Questions of one shape share one layout, so they
// are grouped by shape; one call per group of 5. Returns one result per item, in order; null = not in the reply.
async function generateNoteAnswersBatch(session, userId, items) {
  const vp = await pool.query('SELECT voice_profile FROM users WHERE id = $1', [userId]);
  const voiceProfile = (process.env.VOICE_PROFILE !== '0' && vp.rows[0] && vp.rows[0].voice_profile) || '';
  const styleKey = session.answer_style || 'conversational';
  const calls = await noteCallContext(session.id, userId);
  const bankRows = (await pool.query("SELECT text, answer FROM questions WHERE session_id = $1 AND answer <> '' ORDER BY id LIMIT 8", [session.id])).rows;
  const material = `SESSION MATERIAL — the candidate and the job:\nTHIS NOTE IS FOR: ${session.role || 'this role'} at ${session.company || 'the company'}. Reference them naturally when a question asks "why this role/company"; never parrot the JD.\n\nRESUME:\n${session.resume || 'N/A'}\n\nJOB DESCRIPTION:\n${session.jd || 'N/A'}\n\nQ&A BANK (candidate's real experience — USE THIS):\n${bankRows.map(q => `Q: ${q.text}\nA: ${q.answer}`).join('\n\n') || 'N/A'}`;
  const expFacts = experienceFacts(session.resume);
  const out = new Array(items.length).fill(null);
  const groups = new Map();
  items.forEach((it, i) => { const s = classifyQuestionShape(String(it.question || '').trim()); const k = s.shape + '|' + s.technical; if (!groups.has(k)) groups.set(k, { s, idx: [] }); groups.get(k).idx.push(i); });
  const jobs = [];
  for (const { s, idx } of groups.values()) for (let c = 0; c < idx.length; c += 5) jobs.push({ s, idx: idx.slice(c, c + 5) });
  await Promise.all(jobs.map(async ({ s, idx }) => {
    const system = composeLiveSystemPrompt({ shape: s.shape, technical: s.technical, styleKey, maxLines: 0, voiceProfile, withConversation: !!calls, questionText: '', employerLine: true });
    const systemBlocks = [Object.assign({ type: 'text', text: material }, process.env.PROMPT_CACHE === '0' ? {} : { cache_control: { type: 'ephemeral' } }), { type: 'text', text: system }];
    const qs = idx.map((i, n) => `Q${n + 1}: ${String(items[i].question || '').trim()}`).join('\n');
    const user = `TODAY: ${new Date().toISOString().slice(0, 10)}\n${expFacts ? expFacts + '\n' : ''}${calls ? `\nTHE CONVERSATION:\n${calls}\n` : ''}\n${idx.length} QUESTIONS (each is one way an interviewer phrases it — this is a prepared note read from during a call, so every answer must stand on its own):\n${qs}\n\nWrite a separate, complete answer for EACH question, in the LAYOUT above. Start each with its marker on its own line: ===Q1===, ===Q2===, and so on. After each answer, as its last line, exactly: KEY: <at most 12 words — the one thing to remember to say>`;
    const t0 = Date.now();
    let raw = '';
    try { raw = await callClaude(systemBlocks, user, idx.length * (s.shape === 'code' ? 1000 : 600), MODEL_HAIKU, { __tag: 'note-answer-batch' }); }
    catch (e) { console.error('[Note] batch call failed:', e.message); return; }
    const parts = String(raw || '').split(/===\s*Q(\d+)\s*===/);
    const byNum = {}; for (let p = 1; p < parts.length; p += 2) byNum[parts[p]] = parts[p + 1] || '';
    let got = 0;
    idx.forEach((i, n) => {
      const { answer, keyPoints } = answerNote.parseGenerated(String(byNum[n + 1] || '').trim());
      const text = answer ? normalizeLiveAnswer(answer, s.shape, { cap: liveLineCap(styleKey, 0, s.shape), employerLineAllowed: true, cueOnly: (STYLE_LAYOUT[styleKey] || {}).unit === 'cue' && s.shape !== 'code' }) : '';
      if (text && !isNonAnswer(text)) { out[i] = { answerHtml: answerNote.answerToHtml(text), keyPoints }; got++; }
    });
    console.log(`[Note] batch shape=${s.shape} ${Date.now() - t0}ms calls=${calls.length} got=${got}/${idx.length}`);
  }));
  return out;
}

// Detailed spoken answers (owner, 24 Oct: "some questions required good details...
// that human and slow word for word start"). For the questions the seed marks (lib DETAIL_ARCS): paragraphs he reads
// out loud slowly, following that question's path, built for this job and company from the résumé only. Written once
// ahead of the call, so the better model; Shorter / Add a number / Sound like me / his own change still apply.
async function generateDetailedAnswer(session, userId, item, arc, mode, custom) {
  const question = String(item.question || '').trim();
  const vp = await pool.query('SELECT voice_profile FROM users WHERE id = $1', [userId]);
  const voiceProfile = (process.env.VOICE_PROFILE !== '0' && vp.rows[0] && vp.rows[0].voice_profile) || '';
  const bankRows = (await pool.query("SELECT text, answer FROM questions WHERE session_id = $1 AND answer <> '' ORDER BY id LIMIT 8", [session.id])).rows;
  const material = `THE CANDIDATE AND THE JOB:\nTHIS NOTE IS FOR: ${session.role || 'this role'} at ${session.company || 'the company'}.\n\nRESUME:\n${session.resume || 'N/A'}\n\nJOB DESCRIPTION:\n${session.jd || 'N/A'}\n\nQ&A BANK (the candidate's real experience):\n${bankRows.map(q => `Q: ${q.text}\nA: ${q.answer}`).join('\n\n') || 'N/A'}`;
  const quick = /\b(quick|brief|briefly|short|in a nutshell|30 seconds|one minute)\b/i.test(question);
  const length = quick ? 'about 120 to 160 words (under a minute spoken), three short paragraphs'
    : arc === 'intro' ? 'about 330 to 400 words (about two and a half minutes read slowly)' : 'about 220 to 300 words (about a minute and a half read slowly)';
  const rules = `You write what the candidate will SAY in a live interview, word for word. They read it slowly from a note, so it must sound like a real person talking, not a written essay or a cover letter.
VOICE: first person, contractions, short sentences (most under 20 words), one idea per sentence, plain words. Include two or three natural, memorable lines in the candidate's own words about their own work: a short plain line that sums up a strength, the way a person says it out loud. Write fresh ones every time; never reuse stock phrases. No buzzwords (passionate, leverage, synergy, results-driven, dynamic, spearheaded), no em dashes, no bullet points, no headings, no lists. Never open with "Sure", "Great question" or "So"; start straight with the first sentence of the answer. ${answerNote.READ_ALOUD}
FACTS: every concrete detail (employer, team, project, tool, action, number, result, what it was like before) must come from the resume, the Q&A bank or the job description. Use the real employers, titles, tools, certifications and numbers. Never add a detail to make it richer: no invented numbers, teams, projects, stories or before-and-after. Never invent quotes, conversations or what someone said or still does. Results only as the resume or Q&A bank states them. If the material is thin for a step, say less there, keep it true and general, or skip the step. Nothing after the last step.
FIT: aim it at THIS role at THIS company. Lean on what the job description cares about most. Name the company naturally, once or twice at most.
SHAPE: plain paragraphs separated by one blank line, 2 to 4 sentences each, one paragraph per step of the path below. Length: ${length}.
PATH:
${quick ? quickPath(DETAIL_ARCS_TEXT(arc)) : DETAIL_ARCS_TEXT(arc)}${voiceProfile ? `\nHOW THIS CANDIDATE TALKS (match it): ${voiceProfile}` : ''}
${answerNote.EXAMPLE_RULE}
${answerNote.AI_RULE}
Last line, outside the answer: KEY: <at most 12 words, the one thing to remember>`;
  const instruction = answerNote.changeInstruction(mode, custom);
  const current = answerNote.htmlToText(item.answer_html);
  const changeBlock = instruction && current ? `\nCURRENT ANSWER:\n${current}\n\nCHANGE REQUESTED: ${instruction}\nKeep the spoken paragraphs and the path; keep every fact that is still true; add nothing the resume or Q&A bank does not have.\n` : '';
  const calls = await noteCallContext(session.id, userId);
  const user = `TODAY: ${new Date().toISOString().slice(0, 10)}\n${calls ? `\nTHE CALLS FOR THIS JOB:\n${calls}\n\n${NOTE_CALLS_RULE}\n` : ''}${changeBlock}\nQUESTION: ${question}\n\nWrite what they will say now.`;
  const t0 = Date.now();
  const raw = await callClaude([Object.assign({ type: 'text', text: material }, process.env.PROMPT_CACHE === '0' ? {} : { cache_control: { type: 'ephemeral' } }), { type: 'text', text: rules }], user, 1400, MODEL_SONNET, { __tag: 'note-detailed', thinking: { type: 'disabled' } });
  const { answer, keyPoints } = answerNote.parseGenerated(String(raw || '').replace(/\u2014/g, ', '));
  const html = answerNote.paragraphsToHtml(answer);
  const words = answerNote.htmlToText(html).split(/\s+/).filter(Boolean).length;
  console.log(`[Note] detailed ${arc} ${mode || 'regenerate'} ${Date.now() - t0}ms calls=${calls.length} words=${words} paragraphs=${(html.match(/<p>/g) || []).length} q="${question.slice(0, 50)}"`);
  if (!words || isNonAnswer(answer)) throw new Error('The writer gave no usable answer. Try again.');
  return { answerHtml: html, keyPoints };
}
const DETAIL_ARCS_TEXT = arc => answerNote.DETAIL_ARCS[arc] || '';
// The best way to answer this question (lib FORM_GUIDE): the seed's mark wins; anything else (his own questions, ones
// from calls, renamed ones) is decided by the fast model in about half a second, once per wording, then remembered.
const answerFormSeen = new Map();
async function pickAnswerForm(groupName, question) {
  const seeded = answerNote.detailFor(groupName); if (seeded) return seeded;
  const q = String(question || '').trim().slice(0, 400), k = q.toLowerCase();
  if (!q) return 'short';
  if (answerFormSeen.has(k)) return answerFormSeen.get(k);
  const t0 = Date.now();
  let form = 'short';
  try { form = answerNote.parseForm(await callClaude(answerNote.FORM_GUIDE, 'QUESTION: ' + q, 8, MODEL_HAIKU, { __tag: 'note-form', temperature: 0 })); }
  catch (e) { console.error('[Note] form pick failed, writing it short:', e.message); return 'short'; }
  if (answerFormSeen.size > 2000) answerFormSeen.clear();
  answerFormSeen.set(k, form);
  console.log(`[Note] form ${form} ${Date.now() - t0}ms q="${q.slice(0, 60)}"`);
  return form;
}
// "Give us a quick introduction": only the first two steps and the close, renumbered, so the path can't outvote the length
const quickPath = text => { const steps = text.split('\n').filter(l => /^\d+\./.test(l)); return [steps[0], steps[1], steps[steps.length - 1]].filter(Boolean).map((l, i) => l.replace(/^\d+\./, (i + 1) + '.')).join('\n'); };

// ---- Calls (owner, 24 Oct): "take note of what was said on the call, so next time I can read it and build more
// questions from it for the same session". The notes are the call report (POST /api/sessions/:id/transcripts/:tid/report,
// one place); these routes list a job's calls, give one call's conversation, and add a call's questions to the note.
app.get('/api/note/calls', authMiddleware, async (req, res) => {
  try {
    const session = await noteSessionFor(req.userId, String(req.query.sessionId || ''));
    if (!session) return res.json({ session: null, calls: [] });
    const r = await pool.query(`SELECT id, started_at, ended_at, stage, interviewer_name, interviewer_title, report, jsonb_array_length(coalesce(transcript, '[]'::jsonb)) AS n
      FROM live_transcripts WHERE session_id = $1 AND user_id = $2 ORDER BY started_at DESC LIMIT 30`, [session.id, req.userId]);
    res.json({ session: { id: session.id, company: session.company || '', role: session.role || '' },
      calls: r.rows.map(c => ({ id: c.id, started_at: c.started_at, ended_at: c.ended_at, stage: c.stage || '', interviewer: [c.interviewer_name, c.interviewer_title].filter(Boolean).join(', '), lines: c.n || 0,
        report: typeof c.report === 'string' ? (() => { try { return JSON.parse(c.report); } catch (e) { return null; } })() : (c.report || null) })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/note/calls/:tid', authMiddleware, async (req, res) => {
  try {
    if (!isValidUUID(req.params.tid)) return res.status(404).json({ error: 'Call not found' });
    const r = await pool.query('SELECT transcript FROM live_transcripts WHERE id = $1 AND user_id = $2', [req.params.tid, req.userId]);
    if (!r.rows.length) return res.status(404).json({ error: 'Call not found' });
    const lines = labelTranscript(transcriptLines(r.rows[0].transcript)).map(l => { const you = /^Candidate: /.test(l); return { who: you ? 'you' : 'them', text: l.replace(/^(Candidate|Interviewer): /, '') }; });
    res.json({ lines });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/note/from-call', authMiddleware, async (req, res) => {
  try {
    const note = await loadNote(req.userId);
    const ses = await noteSes(req); // questions from a job's call belong to that job
    let section = String(req.body?.section || '').trim().slice(0, 80);
    if (!section) section = ses && ses.company ? ('From calls: ' + ses.company).slice(0, 80) : 'From my calls'; // no job picked: his latest job, like the answers
    const tree = await noteTree(note, ses);
    const out = answerNote.questionsToAdd(tree.groups, req.body?.questions);
    const added = [];
    let order = section === 'New questions' ? (await pool.query('SELECT coalesce(max(sort_order), -1) + 1 AS n FROM answer_note_groups WHERE note_id = $1', [note.id])).rows[0].n
      : await slotAboveYourQuestions(pool, note.id, out.add.length); // New questions stay last; a call's own section goes above Your questions
    for (const q of out.add) {
      const g = (await pool.query('INSERT INTO answer_note_groups (note_id, name, section, sort_order, job_ids) VALUES ($1, $2, $3, $4, $5::uuid[]) RETURNING *', [note.id, q.title, section, order++, ses ? [ses.id] : null])).rows[0];
      const items = [];
      for (let j = 0; j < q.items.length; j++) items.push((await pool.query('INSERT INTO answer_note_items (note_id, group_id, question, sort_order) VALUES ($1, $2, $3, $4) RETURNING *', [note.id, g.id, q.items[j], j])).rows[0]);
      added.push({ id: g.id, name: g.name, section: g.section, color: '', pinned: false, sort_order: g.sort_order, scope: answerNote.scopeOf(g), jobOnly: !!ses, items: items.map(noteItemOut) });
    }
    console.log(`[Note] From a call: added ${added.length}, already in the note ${out.skipped.length}, section "${section}"`);
    res.json({ added, skipped: out.skipped });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---- Smart call (owner, 24 Oct): "use voice from interview to highlight where it is possible to get the answer",
// "no auto switching", "very fast so anything to delay is not needed". The note calls this AFTER it already showed
// its instant wording guess; it never touches the live answer path. One small fast-model call: which note question
// this IS (wording alone cannot tell, measured), which line of that answer to highlight, and for a question not in
// the note, a short title + clean wording so it can be added after the call.
const noteHeardLast = new Map(); // userId → time of the last check (one at a time per user, newest wins on the page)
// Measured 25 Oct on 195 independent interviewer turns: Sonnet switched to the right card 98.4% (near-misses 100%), Haiku
// 96.1%, for about 0.15 s more (median 0.8 s). NOTE_HEARD_MODEL=haiku goes back.
const HEARD_MODEL = process.env.NOTE_HEARD_MODEL === 'haiku' ? MODEL_HAIKU : MODEL_SONNET;
app.post('/api/note/heard', authMiddleware, async (req, res) => {
  try {
    const text = String(req.body?.text || '').replace(/\s+/g, ' ').trim().slice(0, 600);
    if (text.length < 8) return res.json({ groupId: null });
    const now = Date.now(); if (now - (noteHeardLast.get(req.userId) || 0) < 700) return res.status(429).json({ error: 'too fast' });
    noteHeardLast.set(req.userId, now);
    const note = await loadNote(req.userId);
    const groups = (await noteTree(note, await noteSes(req))).groups.filter(g => g.items.length); // only this job's questions and answers
    if (!groups.length) return res.json({ groupId: null });
    const ranked = NoteMatchShared.rank(groups, text, 3).map(r => groups.find(g => g.id === r.groupId));
    const cur = groups.find(g => g.id === req.body?.currentGroupId);
    const withAnswers = [...new Set([cur, ...ranked].filter(Boolean))].map(g => ({ g, it: g.items.find(i => i.answer_html) })).filter(x => x.it).slice(0, 4);
    const list = groups.map((g, i) => `${i + 1}. ${g.items[0].question}`).join('\n');
    const answers = withAnswers.map(x => `ANSWER TO ${groups.indexOf(x.g) + 1}:\n` + answerNote.htmlToText(x.it.answer_html).split('\n').map((l, j) => `  L${j + 1}. ${l}`).join('\n')).join('\n\n');
    const system = [
      Object.assign({ type: 'text', text: `The candidate's prepared questions, numbered:\n${list}` }, process.env.PROMPT_CACHE === '0' ? {} : { cache_control: { type: 'ephemeral' } }),
      // Owner 24 Oct: "Walk me through the Fabric architecture you built" landed on "Dashboard end to end"; the old rule
      // ("same intent in any wording") let same-SHAPE or same-TOPIC questions match. A question only matches when it asks
      // the same thing; anything else goes to New questions, where it gets its own study note.
      { type: 'text', text: 'An interviewer just said the text below, live on a call. Reply with ONE line of JSON only:\n{"q": <the number of the prepared question it asks, or 0>, "line": <for that question, the number L of the answer line that best answers exactly what was asked, 0 if no answer shown>, "title": "<2 to 4 word label, only when q is 0>", "question": "<the question as one clean sentence, only when q is 0>"}\nMatch ONLY when it is the SAME question in other words: same subject AND same ask, so the prepared answer fully answers it. It is NOT the same when:\n- the subject differs, even if shaped alike ("walk me through a dashboard you built" vs "walk me through the Fabric architecture you built");\n- the ask differs on the same subject ("what experience do you have with Fabric" vs "walk me through the Fabric architecture you built": that one needs the design, step by step);\n- it names one specific tool, platform, system or project while the prepared one is general ("what is your experience with Snowflake" vs "what tools have you used").\nA follow-up that only asks for MORE of the question on screen (say more, an example, how it turned out) counts as that one: use its number. A follow-up that asks something the prepared answer does not answer (what would you do differently, what would you build from the start, why that and not another way, how it affects size or speed) is a NEW question: q 0, and write the question whole with what it points back to, so it reads on its own ("If you could rebuild the Direct Lake setup from the start, what would you implement?"). When unsure, 0.\nIf the text is small talk or not a question, use q 0 and leave title and question empty.\nIf the question is cut off before its ask is clear (it stops mid-sentence, like "so how do you usually" or "tell me about the time when"), it is not heard yet: q 0, title and question empty. Never guess the end of a question.' },
    ];
    const t0 = Date.now();
    const onScreen = cur ? `QUESTION ON SCREEN: ${groups.indexOf(cur) + 1}\n` : '';
    // Owner 24 Oct live: the same question went to "Prioritizing" once and to New questions the next time. A matcher must
    // give the same answer every time, so no sampling randomness here (and in the form picker).
    const raw = await callClaude(system, `${answers ? answers + '\n\n' : ''}${onScreen}INTERVIEWER: ${text}\n\nJSON:`, 120, HEARD_MODEL, Object.assign({ __tag: 'note-heard' }, HEARD_MODEL === MODEL_HAIKU ? { temperature: 0 } : { thinking: { type: 'disabled' } }));
    let j = {}; try { j = JSON.parse((raw.match(/\{[\s\S]*\}/) || ['{}'])[0]); } catch (e) {}
    const g = groups[(parseInt(j.q, 10) || 0) - 1] || null;
    const src = g && withAnswers.find(x => x.g.id === g.id);
    const lines = src ? answerNote.htmlToText(src.it.answer_html).split('\n') : [];
    const line = lines[(parseInt(j.line, 10) || 0) - 1] || '';
    console.log(`[Note] heard ${Date.now() - t0}ms → ${g ? '"' + g.name + '"' + (line ? ' line ' + j.line : '') : 'not in the note'} q="${text.slice(0, 50)}"`);
    res.json(g ? { groupId: g.id, itemId: (src ? src.it.id : g.items[0].id), name: g.name, line }
      : { groupId: null, title: String(j.title || '').trim().slice(0, 60), question: String(j.question || '').trim().slice(0, 300) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Which answer lines he has covered IN MEANING (owner: "I don't go word for word... I dazzle"). The note calls this when
// he pauses, only for lines its instant check has not ticked yet; one tiny fast-model call, nothing waits on it.
// Live coach: what they are really after + one line to say (lib COACH_PROMPT). One small fast call per question heard,
// only for a job he picked in the note (owner: never generate for a job he has not opened). Nothing when plain.
const noteCoachLast = new Map();
app.post('/api/note/coach', authMiddleware, async (req, res) => {
  try {
    const text = String(req.body?.text || '').replace(/\s+/g, ' ').trim().slice(0, 600);
    const sid = String(req.body?.sessionId || '');
    if (text.length < 8 || !isValidUUID(sid)) return res.json({ coach: null });
    const now = Date.now(); if (now - (noteCoachLast.get(req.userId) || 0) < 700) return res.status(429).json({ error: 'too fast' });
    noteCoachLast.set(req.userId, now);
    const s = (await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [sid, req.userId])).rows[0];
    if (!s) return res.json({ coach: null });
    // xHire's own earlier answer to THIS question is left out: the strip copied its loose method ("filters") over the expert one (row-level security)
    const bank = (await pool.query("SELECT text, answer FROM questions WHERE session_id = $1 AND answer <> '' ORDER BY id LIMIT 12", [s.id])).rows
      .filter(q => NoteMatchShared.score(text, q.text) < NoteMatchShared.SAME_QUESTION).slice(0, 6);
    const material = `THE JOB: ${s.role || 'this role'} at ${s.company || 'the company'}.\nJOB DESCRIPTION:\n${String(s.jd || 'N/A').slice(0, 3000)}\n\nRESUME:\n${String(s.resume || 'N/A').slice(0, 5000)}\n\nQ&A BANK:\n${bank.map(q => `Q: ${q.text}\nA: ${String(q.answer).slice(0, 400)}`).join('\n\n') || 'N/A'}`;
    const recent = (Array.isArray(req.body?.recent) ? req.body.recent : []).map(q => String(q || '').slice(0, 200)).filter(Boolean).slice(-3);
    // What they said leading up to the question (their company pitch: "say something nice about it first") and, mid-answer,
    // what he has said so far (the coach then gives the one thing to ADD).
    const theySaid = String(req.body?.theySaid || '').replace(/\s+/g, ' ').trim().slice(-1500), youSaid = String(req.body?.youSaid || '').replace(/\s+/g, ' ').trim().slice(-1500);
    const shown = (Array.isArray(req.body?.shown) ? req.body.shown : []).map(t => String(t || '').slice(0, 200)).filter(Boolean).slice(-4);
    const t0 = Date.now(), coachFast = process.env.NOTE_COACH_MODEL === 'haiku';
    const raw = await callClaude([Object.assign({ type: 'text', text: material }, process.env.PROMPT_CACHE === '0' ? {} : { cache_control: { type: 'ephemeral' } }), { type: 'text', text: answerNote.COACH_PROMPT }],
      `${recent.length ? 'ASKED EARLIER IN THIS CALL:\n' + recent.join('\n') + '\n\n' : ''}${theySaid ? 'THE INTERVIEWER SAID, LEADING UP TO NOW:\n' + theySaid + '\n\n' : ''}${req.body?.chat ? 'INTERVIEWER JUST SAID (chatting, no question)' : 'INTERVIEWER JUST ASKED'}: ${text}\n\n${youSaid ? 'THE CANDIDATE HAS SAID SO FAR:\n' + youSaid : 'The candidate has not started answering.'}${shown.length ? '\n\nALREADY SUGGESTED FOR THIS QUESTION (never repeat these or their facts; give a new point or NONE):\n' + shown.join('\n') : ''}`, 160, coachFast ? MODEL_HAIKU : MODEL_SONNET, Object.assign({ __tag: 'note-coach' }, coachFast ? { temperature: 0 } : { thinking: { type: 'disabled' } })); // Sonnet 5: no temperature; thinking ate the whole budget (stop=max_tokens, no text)
    const coach = answerNote.parseCoach(raw);
    console.log(`[Note] coach${req.body?.chat ? ' chat' : ''}${youSaid ? ' add' : ''} ${Date.now() - t0}ms → ${coach ? 'want "' + coach.want + '"' : 'nothing shown (' + String(raw || '').replace(/\s+/g, ' ').slice(0, 120) + ')'} q="${text.slice(0, 50)}"`);
    res.json({ coach });
  } catch (e) { console.error('[Note] coach failed:', e.message); res.status(500).json({ error: e.message }); }
});
const noteSaidLast = new Map();
app.post('/api/note/said', authMiddleware, async (req, res) => {
  try {
    const lines = (Array.isArray(req.body?.lines) ? req.body.lines : []).map(l => String(l || '').replace(/\s+/g, ' ').trim().slice(0, 300)).filter(Boolean).slice(0, 12);
    const said = String(req.body?.said || '').replace(/\s+/g, ' ').trim().slice(-3000);
    if (!lines.length || said.length < 15) return res.json({ covered: [] });
    const now = Date.now(); if (now - (noteSaidLast.get(req.userId) || 0) < 1500) return res.status(429).json({ error: 'too fast' });
    noteSaidLast.set(req.userId, now);
    const t0 = Date.now();
    const raw = await callClaude('A candidate is answering an interview question out loud. Below are the points from their prepared answer, numbered, and what they actually said. A point counts as covered when they got its meaning across in any words (a paraphrase, the same example told differently, the same number or result). It does not count if they only touched the topic. Reply with ONE line of JSON only: {"covered": [numbers]}',
      `POINTS:\n${lines.map((l, i) => `${i + 1}. ${l}`).join('\n')}\n\nTHEY SAID:\n${said}\n\nJSON:`, 60, MODEL_HAIKU, { __tag: 'note-said' });
    let j = {}; try { j = JSON.parse((raw.match(/\{[\s\S]*\}/) || ['{}'])[0]); } catch (e) {}
    const covered = (Array.isArray(j.covered) ? j.covered : []).map(n => parseInt(n, 10)).filter(n => n >= 1 && n <= lines.length).map(n => lines[n - 1]);
    console.log(`[Note] said ${Date.now() - t0}ms → ${covered.length}/${lines.length} covered`);
    res.json({ covered });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// How many of his calls asked each note question (from the call notes' "same as"). No AI.
app.get('/api/note/asked', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query('SELECT report FROM live_transcripts WHERE user_id = $1 AND report IS NOT NULL', [req.userId]);
    const counts = {};
    for (const row of r.rows) {
      let rep = row.report; if (typeof rep === 'string') { try { rep = JSON.parse(rep); } catch (e) { continue; } }
      const ids = new Set((Array.isArray(rep && rep.noteQuestions) ? rep.noteQuestions : []).map(q => q && q.sameAs && q.sameAs.id).filter(Boolean));
      ids.forEach(id => { counts[id] = (counts[id] || 0) + 1; });
    }
    res.json({ counts });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Owner 25 Oct: "xhire uses history to better next answer ... make sure note using that". The note's writers get the
// same history xHire's live answers get, with no extra model call: during a call, buildConversationContext (earlier
// calls' notes, this call's notes, the newest talk word for word, what they care about); after it, the notes each call
// saved when it ended. With screens (new questions): what the shared screen showed and what Assist answered, as xHire
// read and wrote them. Empty when this job has had no calls.
const notePriorInflight = new Map();
async function noteCallContext(sessionId, userId, opts = {}) {
  try {
    const live = liveWsForSession(sessionId), parts = [];
    if (live) { const c = buildConversationContext(live); if (c) parts.push(c); }
    else {
      // the same loader the live answers use: a finished call with no notes yet gets them once (cached in the row), so the
      // note sees today's call while he preps tonight. One load per job at a time (Write all answers runs writers in parallel).
      let p = notePriorInflight.get(sessionId);
      if (!p) { p = loadPriorCallsMemory(sessionId, userId, null).finally(() => notePriorInflight.delete(sessionId)); notePriorInflight.set(sessionId, p); }
      const m = await p;
      if (m) parts.push('FROM EARLIER CALLS IN THIS INTERVIEW PROCESS:\n' + m);
    }
    if (opts.screens) {
      const callId = (live && live._callId) || ((await pool.query('SELECT id FROM live_transcripts WHERE session_id = $1 AND user_id = $2 ORDER BY started_at DESC LIMIT 1', [sessionId, userId])).rows[0] || {}).id;
      if (callId) {
        const ev = (await pool.query("SELECT kind, text, meta FROM call_events WHERE call_id = $1 AND session_id = $2 AND kind IN ('seen', 'said') ORDER BY ts DESC LIMIT 30", [callId, sessionId])).rows;
        const seen = [], said = [];
        for (const e of ev) {
          if (e.kind === 'seen' && seen.length < 3 && !seen.includes(e.text)) seen.push(e.text);
          if (e.kind === 'said' && said.length < 4) said.push(((e.meta || {}).ask ? `(he asked: ${e.meta.ask})\n` : '') + e.text);
        }
        if (seen.length) parts.push('ON THE SHARED SCREEN (read by xHire, newest last):\n' + seen.reverse().map(t => t.slice(0, 2500)).join('\n---\n'));
        if (said.length) parts.push('WHAT XHIRE ASSIST ANSWERED ON THE CALL (newest last):\n' + said.reverse().join('\n---\n'));
      }
    }
    return parts.join('\n\n').slice(-12000);
  } catch (e) { console.error('[Note] call history failed:', e.message); return ''; }
}
const NOTE_CALLS_RULE = 'THE CALLS FOR THIS JOB are background: aim the answer at what they said they care about. When the question is about something shown on the shared screen (a table, a dataset, a task, a page), use its real names, columns and values exactly as xHire read them. Facts about the candidate still come only from the resume, the Q&A bank and what the candidate said on the call.';
// ---- New questions (owner, 24 Oct): "we should have one that is plain.. when [the note] finds a question, especially
// the one xHire got.. it should pick it up, and answer its own way.. be more clean, can put table, can draw, use image".
// The note adds a question heard on a call to the plain "New questions" section (from-call route), keeps what xHire
// answered live (below), and on first open writes a study note: clean HTML with a table where one fits and a diagram
// (Mermaid, drawn by the page) where a flow fits. The better model: this is the note he studies before the next round.
// What is shown while a study note is still being written: the HTML so far, without the KEY line or a half-written tag.
function studyPartial(raw) {
  let t = String(raw || '').replace(/^\s*```(?:html)?\s*/i, '');
  const k = t.search(/(^|\n)\s*KEY:/); if (k >= 0) t = t.slice(0, k);
  return answerNote.sanitizeHtml(t.replace(/```(?:html)?/gi, '').replace(/<[^>]*$/, ''));
}
async function generateStudyNote(session, userId, item, onPartial) {
  const question = String(item.question || '').trim();
  const bankRows = (await pool.query("SELECT text, answer FROM questions WHERE session_id = $1 AND answer <> '' ORDER BY id LIMIT 8", [session.id])).rows;
  const material = `THE CANDIDATE AND THE JOB:\nTHIS NOTE IS FOR: ${session.role || 'this role'} at ${session.company || 'the company'}.\n\nRESUME:\n${session.resume || 'N/A'}\n\nJOB DESCRIPTION:\n${session.jd || 'N/A'}\n\nQ&A BANK (the candidate's real experience):\n${bankRows.map(q => `Q: ${q.text}\nA: ${q.answer}`).join('\n\n') || 'N/A'}`;
  const rules = `You write a clean study note the candidate reads before the next interview, on how to answer one question well. Output an HTML fragment ONLY (no markdown, no code fences), using only these tags: h3, p, b, i, ul, li, table, thead, tbody, tr, th, td, ONE <pre class="diagram">...</pre> holding a Mermaid flowchart, and for code ONE plain <pre>...</pre>.
${answerNote.CODE_RULE}
FLOW (owner: "if explain something more like process, steps, for example Fabric architecture"): whenever the answer explains a process, steps, a pipeline, a workflow or an architecture, ALWAYS draw it: "flowchart LR", short node labels (2 to 4 words), up to 10 nodes, one "subgraph" per layer when there are layers (for example Microsoft Fabric: Sources -> Data Factory pipelines -> OneLake Lakehouse -> Warehouse -> Semantic model -> Power BI reports). Plain node ids (A, B, C), labels in square brackets, no special characters inside labels. No diagram for a pure opinion or a yes/no answer.
Layout:
<p><b>One-line takeaway: the point to land.</b></p>
For a code question, the one <pre> with the code comes here, before "How to say it".
<h3>How to say it</h3> 3 to 5 short bullets in the first person, one sentence each (under 20 words). ${answerNote.READ_ALOUD}
A <table> where it makes things clearer: for any "tell me about a time" or story question ALWAYS a STAR table (Situation, Task, Action, Result); steps for a process; before/after numbers; or a comparison.
<h3>If they push</h3> 1 or 2 follow-ups they may ask, each with a one-line answer they can read out as it is.
${answerNote.EXAMPLE_RULE} In "How to say it" the first bullet is the plain idea; examples come after it.
Rules: only facts from the resume, Q&A bank and what was said on the call; never invent a number, tool, employer or title. If the resume has no exact match, never say they have not done it: answer confidently from the closest real experience in the resume (the same skill, a similar situation) and tell it as their story. Plain words, no em dashes, no buzzwords.
Last line, outside the HTML: KEY: <at most 12 words, the one thing to remember>`;
  const said = answerNote.htmlToText(item.answer_html);
  const calls = await noteCallContext(session.id, userId, { screens: true });
  const user = `${calls ? `THE CALLS FOR THIS JOB:\n${calls}\n\n${NOTE_CALLS_RULE}\n\n` : ''}QUESTION: ${question}\n${said ? `\nWHAT XHIRE SAID LIVE ON THE CALL (rough, build on it):\n${said}\n` : ''}\nWrite the study note now.`;
  const t0 = Date.now();
  const sys = [Object.assign({ type: 'text', text: material }, process.env.PROMPT_CACHE === '0' ? {} : { cache_control: { type: 'ephemeral' } }), { type: 'text', text: rules }];
  // Owner 26 Oct: "why 10 seconds for new questions". The whole note took ~10 s before anything showed. Streamed, the
  // takeaway and "How to say it" (written first) show in about a second and the rest grows under them.
  let raw = '', first = 0;
  if (onPartial) {
    let acc = '', last = 0;
    try {
      raw = await callClaudeStream(sys, user, 1800, MODEL_SONNET, t => {
        acc += t; const now = Date.now(); if (now - last < 150) return; last = now;
        const html = studyPartial(acc); if (!answerNote.htmlToText(html)) return;
        if (!first) first = now - t0; onPartial(html);
      }, { __tag: 'note-study', thinking: { type: 'disabled' } });
    } catch (e) { console.log('[Note] study note stream failed, writing it whole:', e.message); raw = ''; }
  }
  if (!raw) raw = await callClaude(sys, user, 1800, MODEL_SONNET, { __tag: 'note-study', thinking: { type: 'disabled' } });
  const { answer, keyPoints } = answerNote.parseGenerated(String(raw || '').replace(/^\s*```(?:html)?\s*/i, '').replace(/```\s*$/m, ''));
  const html = answerNote.sanitizeHtml(answer.replace(/```(?:html)?/gi, '').trim());
  console.log(`[Note] study note ${Date.now() - t0}ms${onPartial ? ' first=' + first + 'ms' : ''} calls=${calls.length} table=${/<table/.test(html)} diagram=${/class="diagram"/.test(html)} code=${/<pre>/.test(html)} q="${question.slice(0, 50)}"`);
  if (!answerNote.htmlToText(html)) throw new Error('The writer gave no usable study note. Try again.');
  return { answerHtml: html, keyPoints };
}
// What xHire answered live for a new question, kept on it (only while it is still empty; never over his words).
app.post('/api/note/items/:iid/live', authMiddleware, async (req, res) => {
  try {
    const item = await ownNoteItem(req.userId, req.params.iid, await noteSes(req));
    if (!item) return res.status(404).json({ error: 'Question not found' });
    const text = String(req.body?.answer || '').trim().slice(0, 6000);
    if (!text) return res.status(400).json({ error: 'No answer' });
    if (answerNote.htmlToText(item.answer_html)) return res.json(noteItemOut(item)); // already has an answer: leave it
    const change = answerNote.applyChange(item, { answer_html: answerNote.answerToHtml(text) }, { by: 'call', label: 'What xHire said on the call' });
    res.json(noteItemOut(change.changed ? await writeNoteItem(item, change) : item));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Note page — served no-store like the launcher (Electron must always get the latest)
app.get('/note', (req, res) => { res.set('Cache-Control', 'no-store, no-cache, must-revalidate'); res.sendFile(path.join(__dirname, 'public', 'note.html')); });

app.get('/api/note', authMiddleware, async (req, res) => {
  try { const note = await loadNote(req.userId); res.json(await noteTree(note, await noteSes(req))); }
  catch (e) { console.error('[Note] load failed:', e.message); res.status(500).json({ error: e.message }); }
});
const NOTE_SETTING_KEYS = ['bg', 'theme', 'fontFamily', 'fontSize', 'sessionId', 'readMode', 'autoGenerate', 'railWidth', 'seeThrough', 'autoSwitch', 'autoOpen', 'coach'];
app.put('/api/note/settings', authMiddleware, async (req, res) => {
  try {
    const note = await loadNote(req.userId);
    const patch = {};
    for (const k of NOTE_SETTING_KEYS) if (req.body && req.body[k] !== undefined) patch[k] = req.body[k];
    const r = await pool.query("UPDATE answer_notes SET settings = coalesce(settings, '{}'::jsonb) || $1::jsonb, updated_at = NOW() WHERE id = $2 RETURNING settings", [JSON.stringify(patch), note.id]);
    res.json({ settings: r.rows[0].settings });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/note/groups', authMiddleware, async (req, res) => {
  try {
    const note = await loadNote(req.userId);
    const name = String(req.body?.name || '').trim().slice(0, 160) || 'New group';
    const section = String(req.body?.section || '').trim().slice(0, 80);
    const mx = await pool.query('SELECT coalesce(max(sort_order), -1) + 1 AS n FROM answer_note_groups WHERE note_id = $1', [note.id]);
    const g = (await pool.query('INSERT INTO answer_note_groups (note_id, name, section, sort_order) VALUES ($1, $2, $3, $4) RETURNING *', [note.id, name, section, mx.rows[0].n])).rows[0];
    res.json({ id: g.id, name: g.name, section: g.section || '', color: '', pinned: false, sort_order: g.sort_order, items: [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// The People pad (owner 25 Oct): who he has met and is meeting for this job, with small details, so he addresses them
// properly. One per job; his own words, no AI. updated_at is left alone (it decides his "latest résumé").
app.put('/api/note/people', authMiddleware, async (req, res) => {
  try {
    const sid = String(req.body?.sessionId || '');
    if (!isValidUUID(sid)) return res.status(400).json({ error: 'Pick a job first' });
    const text = String(req.body?.text || '').slice(0, 4000);
    const r = await pool.query('UPDATE sessions SET note_people = $1 WHERE id = $2 AND user_id = $3 RETURNING id', [text, sid, req.userId]);
    if (!r.rows.length) return res.status(404).json({ error: 'Job not found' });
    res.json({ ok: true, people: text });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Owner 25 Oct: "do we have things to clear all answers?" -> the job on screen; his every-job answers only when he ticks
// it. Each cleared answer goes to its History (the same write as any edit), so any one comes back.
app.post('/api/note/clear-all', authMiddleware, async (req, res) => {
  try {
    const note = await loadNote(req.userId);
    const ses = await noteSes(req);
    if (!ses) return res.status(400).json({ error: 'Pick a job first' });
    const includeYou = !!req.body?.includeYou;
    let cleared = 0;
    for (const g of (await noteTree(note, ses)).groups) {
      if (g.scope === 'you' && !includeYou) continue;
      for (const it of g.items) {
        if (!it.answer_html && !it.key_points) continue;
        const item = await ownNoteItem(req.userId, it.id, ses); if (!item) continue;
        const change = answerNote.applyChange(item, { answer_html: '', key_points: '' }, { by: 'you', label: 'Cleared' });
        if (change.changed) { await writeNoteItem(item, change); cleared++; }
      }
    }
    console.log(`[Note] cleared ${cleared} answers for job ${ses.id}${includeYou ? ' (and every-job answers)' : ''}`);
    res.json({ cleared });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/note/groups/order', authMiddleware, async (req, res) => { // before /:gid so "order" is never read as an id
  try {
    const note = await loadNote(req.userId);
    const have = (await pool.query('SELECT id FROM answer_note_groups WHERE note_id = $1 ORDER BY sort_order, created_at', [note.id])).rows.map(r => r.id);
    // The page sends only the questions of the job on screen: they swap among their own places, the other jobs' stay put
    const asked = Array.isArray(req.body?.ids) ? req.body.ids : [], sent = new Set(asked);
    const mine = answerNote.reorderIds(have.filter(id => sent.has(id)), asked);
    let k = 0; const order = have.map(id => sent.has(id) ? mine[k++] : id);
    for (let i = 0; i < order.length; i++) await pool.query('UPDATE answer_note_groups SET sort_order = $1 WHERE id = $2 AND note_id = $3', [i, order[i], note.id]);
    res.json({ ids: order });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/note/groups/:gid', authMiddleware, async (req, res) => {
  try {
    const g = await ownNoteGroup(req.userId, req.params.gid);
    if (!g) return res.status(404).json({ error: 'Group not found' });
    const name = req.body?.name !== undefined ? (String(req.body.name).trim().slice(0, 160) || g.name) : g.name;
    const color = req.body?.color !== undefined ? String(req.body.color || '').slice(0, 32) : g.color;
    const pinned = req.body?.pinned !== undefined ? !!req.body.pinned : g.pinned;
    const section = req.body?.section !== undefined ? String(req.body.section || '').trim().slice(0, 80) : (g.section || '');
    const scope = req.body?.scope === 'you' || req.body?.scope === 'job' ? req.body.scope : (g.scope || '');
    // Flipped: the answer on screen goes with it when the other side is still empty (nothing he wrote is lost or overwritten)
    const ses = scope !== answerNote.scopeOf(g) ? await noteSes(req) : null;
    if (ses) for (const it of (await pool.query('SELECT * FROM answer_note_items WHERE group_id = $1', [g.id])).rows) {
      const row = (await pool.query('SELECT * FROM answer_note_job_answers WHERE item_id = $1 AND session_id = $2', [it.id, ses.id])).rows[0];
      if (scope === 'you' && row && answerNote.htmlToText(row.answer_html) && !answerNote.htmlToText(it.answer_html))
        await pool.query('UPDATE answer_note_items SET answer_html = $1, key_points = $2, versions = $3, version = $4, edited_by = $5, edit_label = $6, updated_at = NOW() WHERE id = $7', [row.answer_html, row.key_points, JSON.stringify(row.versions || []), row.version, row.edited_by, row.edit_label, it.id]);
      if (scope === 'job' && answerNote.htmlToText(it.answer_html) && !(row && answerNote.htmlToText(row.answer_html)))
        await pool.query(`INSERT INTO answer_note_job_answers (item_id, session_id, answer_html, key_points, versions, version, edited_by, edit_label) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          ON CONFLICT (item_id, session_id) DO UPDATE SET answer_html = EXCLUDED.answer_html, key_points = EXCLUDED.key_points, versions = EXCLUDED.versions, version = EXCLUDED.version, edited_by = EXCLUDED.edited_by, edit_label = EXCLUDED.edit_label, updated_at = NOW()`,
          [it.id, ses.id, it.answer_html, it.key_points || '', JSON.stringify(it.versions || []), it.version || 0, it.edited_by || '', it.edit_label || '']);
    }
    const r = await pool.query('UPDATE answer_note_groups SET name = $1, color = $2, pinned = $3, section = $4, scope = $5 WHERE id = $6 RETURNING *', [name, color, pinned, section, scope, g.id]);
    res.json({ id: r.rows[0].id, name: r.rows[0].name, section: r.rows[0].section || '', color: r.rows[0].color || '', pinned: !!r.rows[0].pinned, sort_order: r.rows[0].sort_order, scope: answerNote.scopeOf(r.rows[0]) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/note/groups/:gid', authMiddleware, async (req, res) => {
  try {
    const g = await ownNoteGroup(req.userId, req.params.gid);
    if (!g) return res.status(404).json({ error: 'Group not found' });
    await pool.query('DELETE FROM answer_note_groups WHERE id = $1', [g.id]); // its items go with it (FK cascade)
    res.json({ removed: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/note/groups/:gid/items', authMiddleware, async (req, res) => {
  try {
    const g = await ownNoteGroup(req.userId, req.params.gid);
    if (!g) return res.status(404).json({ error: 'Group not found' });
    const question = String(req.body?.question || '').trim().slice(0, 500) || 'New question';
    const cnt = await pool.query('SELECT count(*)::int AS n FROM answer_note_items WHERE group_id = $1', [g.id]);
    if (cnt.rows[0].n >= answerNote.MAX_WAYS + 1) return res.status(400).json({ error: `A question holds at most ${answerNote.MAX_WAYS} other ways to ask it. Delete one first.` });
    const mx = await pool.query('SELECT coalesce(max(sort_order), -1) + 1 AS n FROM answer_note_items WHERE group_id = $1', [g.id]);
    const it = (await pool.query('INSERT INTO answer_note_items (note_id, group_id, question, sort_order) VALUES ($1, $2, $3, $4) RETURNING *', [g.note_id, g.id, question, mx.rows[0].n])).rows[0];
    res.json(noteItemOut(it));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/note/groups/:gid/items/order', authMiddleware, async (req, res) => {
  try {
    const g = await ownNoteGroup(req.userId, req.params.gid);
    if (!g) return res.status(404).json({ error: 'Group not found' });
    const have = (await pool.query('SELECT id FROM answer_note_items WHERE group_id = $1 ORDER BY sort_order, created_at', [g.id])).rows.map(r => r.id);
    const order = answerNote.reorderIds(have, Array.isArray(req.body?.ids) ? req.body.ids : []);
    for (let i = 0; i < order.length; i++) await pool.query('UPDATE answer_note_items SET sort_order = $1 WHERE id = $2 AND group_id = $3', [i, order[i], g.id]);
    res.json({ ids: order });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Save: question rename and/or content. Content carries baseVersion (the version the editor loaded); a stale one is
// refused with 409 + the live row — the page then shows both, nothing is overwritten silently.
app.put('/api/note/items/:iid', authMiddleware, async (req, res) => {
  try {
    const ses = await noteSes(req);
    let item = await ownNoteItem(req.userId, req.params.iid, ses);
    if (!item) return res.status(404).json({ error: 'Question not found' });
    if (req.body?.question !== undefined) {
      const q = String(req.body.question).trim().slice(0, 500);
      if (q) { await pool.query('UPDATE answer_note_items SET question = $1, updated_at = NOW() WHERE id = $2', [q, item.id]); item = await ownNoteItem(req.userId, item.id, ses); }
    }
    if (req.body?.answer_html !== undefined || req.body?.key_points !== undefined) {
      let change;
      try { change = answerNote.applyChange(item, { answer_html: req.body.answer_html, key_points: req.body.key_points, baseVersion: req.body.baseVersion }, { by: 'you', label: 'Your edit' }); }
      catch (e) { if (e.code === 'CONFLICT') { console.log(`[Note] Stale save refused for ${item.id} (base ${req.body.baseVersion}, live ${item.version})`); return res.status(409).json({ error: e.message, item: noteItemOut(item) }); } throw e; }
      if (change.changed) item = await writeNoteItem(item, change);
    }
    res.json(noteItemOut(item));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/note/items/:iid', authMiddleware, async (req, res) => {
  try {
    const item = await ownNoteItem(req.userId, req.params.iid);
    if (!item) return res.status(404).json({ error: 'Question not found' });
    await pool.query('DELETE FROM answer_note_items WHERE id = $1', [item.id]);
    res.json({ removed: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// The first time the note opens for a job (owner 25 Oct: the app is for any job, not only data): one call picks which
// of his role questions this job asks and adds the ones this kind of job asks that he has none for. Once per job;
// two windows asking at once share the one call. Only for a job he opened (no AI for a job he has not).
const noteBuilding = new Map();
async function buildJobQuestions(noteId, ses) {
  const fresh = (await pool.query('SELECT settings FROM answer_notes WHERE id = $1', [noteId])).rows[0];
  if (!fresh || ((fresh.settings || {}).jobsBuilt || []).includes(ses.id)) return;
  const groups = (await pool.query('SELECT * FROM answer_note_groups WHERE note_id = $1 ORDER BY sort_order, created_at', [noteId])).rows;
  const items = (await pool.query('SELECT id, group_id, question FROM answer_note_items WHERE note_id = $1 ORDER BY sort_order, created_at', [noteId])).rows;
  const first = g => (items.find(i => i.group_id === g.id) || {}).question || g.name;
  const role = groups.filter(g => Array.isArray(g.job_ids) && !g.job_ids.includes(ses.id) && !/^(from calls|new questions)/i.test(g.section || ''));
  const shown = groups.filter(g => answerNote.visibleFor(g, ses.id));
  let plan = { keep: [], add: [] };
  const t0 = Date.now();
  if (String(ses.jd || '').trim() || String(ses.role || '').trim()) {
    const user = `JOB: ${ses.role || '(no title)'}${ses.company ? ' at ' + ses.company : ''}\nJOB DESCRIPTION:\n${String(ses.jd || '').slice(0, 6000) || '(none given)'}\n\nROLE QUESTIONS:\n${role.map((g, i) => `${i + 1}. [${g.section}] ${first(g)}`).join('\n') || '(none)'}\n\nGENERAL QUESTIONS (already in the note):\n${shown.map(g => '- ' + first(g)).join('\n')}\n\nJSON:`;
    const raw = await callClaude([{ type: 'text', text: answerNote.JOB_BUILD_PROMPT }], user, 5000, MODEL_SONNET, { __tag: 'note-job-build', thinking: { type: 'disabled' } });
    plan = answerNote.parseJobBuild(raw, role.length);
    if (!plan.ok) { console.error(`[Note] job build reply unreadable for ${ses.id} after ${Date.now() - t0}ms (${String(raw || '').length} chars, ends "${String(raw || '').slice(-60).replace(/\s+/g, ' ')}")`); throw new Error('unreadable build reply'); }
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const locked = (await client.query('SELECT * FROM answer_notes WHERE id = $1 FOR UPDATE', [noteId])).rows[0];
    if (((locked.settings || {}).jobsBuilt || []).includes(ses.id)) { await client.query('ROLLBACK'); return; }
    const keepIds = plan.keep.map(n => role[n - 1].id);
    if (keepIds.length) await client.query('UPDATE answer_note_groups SET job_ids = array_append(job_ids, $1::uuid) WHERE id = ANY($2::uuid[]) AND NOT ($1::uuid = ANY(job_ids))', [ses.id, keepIds]);
    let pool2 = shown.concat(role.filter(g => keepIds.includes(g.id))).map(g => ({ id: g.id, name: g.name, items: items.filter(i => i.group_id === g.id) }));
    let order = await slotAboveYourQuestions(client, noteId, plan.add.length), added = 0;
    for (const a of plan.add) {
      const out = answerNote.questionsToAdd(pool2, [{ title: a.title, question: a.question, ways: a.ways }]);
      for (const q of out.add) {
        const gr = (await client.query('INSERT INTO answer_note_groups (note_id, name, section, sort_order, job_ids) VALUES ($1, $2, $3, $4, $5::uuid[]) RETURNING id', [noteId, q.title, a.section, order++, [ses.id]])).rows[0];
        for (let j = 0; j < q.items.length; j++) await client.query('INSERT INTO answer_note_items (note_id, group_id, question, sort_order) VALUES ($1, $2, $3, $4)', [noteId, gr.id, q.items[j], j]);
        pool2.push({ id: gr.id, name: q.title, items: q.items.map(x => ({ question: x })) }); added++;
      }
    }
    await client.query("UPDATE answer_notes SET settings = coalesce(settings, '{}'::jsonb) || jsonb_build_object('jobsBuilt', coalesce(settings->'jobsBuilt', '[]'::jsonb) || to_jsonb($2::text)) WHERE id = $1", [noteId, ses.id]);
    await client.query('COMMIT');
    console.log(`[Note] Built questions for job ${ses.id} (${ses.role || ''} @ ${ses.company || ''}) in ${Date.now() - t0}ms: kept ${keepIds.length} of ${role.length} role questions, added ${added}`);
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
}
app.post('/api/note/build', authMiddleware, async (req, res) => {
  try {
    const note = await loadNote(req.userId);
    const ses = await noteSes(req);
    if (ses) {
      const key = note.id + ':' + ses.id;
      if (!noteBuilding.has(key)) noteBuilding.set(key, buildJobQuestions(note.id, ses).finally(() => noteBuilding.delete(key)));
      await noteBuilding.get(key);
    }
    res.json(await noteTree(await loadNote(req.userId), ses));
  } catch (e) { console.error('[Note] job build failed:', e.message); res.status(500).json({ error: 'Could not make the questions for this job' }); }
});

// AI: write or change one answer. The current text goes into history BEFORE the AI result replaces it (Undo = restore).
app.post('/api/note/items/:iid/generate', authMiddleware, async (req, res) => {
  try {
    const session = await noteSes(req); // no job given = his latest résumé (owner 24 Oct), never an old saved pick
    const item = await ownNoteItem(req.userId, req.params.iid, session); // a per-job question: written into THIS job's answer
    if (!item) return res.status(404).json({ error: 'Question not found' });
    const answerCheck = await checkAnswerLimit(req.userId, req.plan); // same monthly cap as the bank's Generate buttons
    if (!answerCheck.ok) return res.status(403).json({ error: `Monthly answer limit reached (${answerCheck.limit}). Upgrade for more.` });
    const note = await loadNote(req.userId);
    if (!session) return res.status(400).json({ error: 'Add your résumé to a session first. The note writes answers from it.' });
    if (!String(session.resume || '').trim()) return res.status(400).json({ error: 'That session has no résumé. Pick one that does.' });
    const mode = answerNote.MODES[req.body?.mode] ? req.body.mode : 'regenerate';
    const custom = String(req.body?.instruction || '').trim();
    if (mode === 'custom' && !custom) return res.status(400).json({ error: 'Say how to change it.' });
    // stream: the page shows a study note as it is written (events: {partial: html}, then {done: item} or {error})
    let streaming = false;
    const onPartial = req.body?.stream ? html => {
      if (!streaming) { streaming = true; res.setHeader('Content-Type', 'text/event-stream'); res.setHeader('Cache-Control', 'no-cache'); res.setHeader('Connection', 'keep-alive'); if (res.flushHeaders) res.flushHeaders(); }
      res.write('data: ' + JSON.stringify({ partial: html }) + '\n\n');
    } : null;
    try {
      const saved = await noteWriteOne(session, req.userId, item, mode, custom, null, onPartial);
      const out = Object.assign(noteItemOut(saved), { job: { id: session.id, company: session.company, role: session.role } });
      if (streaming) { res.write('data: ' + JSON.stringify({ done: out }) + '\n\n'); res.end(); } else res.json(out);
    } catch (e) { if (!streaming) throw e; console.error('[Note] generate failed:', e.message); res.write('data: ' + JSON.stringify({ error: e.message }) + '\n\n'); res.end(); }
  } catch (e) { console.error('[Note] generate failed:', e.message); res.status(500).json({ error: e.message }); }
});
const noteFormOf = async (item, mode) => mode === 'rich' ? 'explain' : pickAnswerForm((await pool.query('SELECT name FROM answer_note_groups WHERE id = $1', [item.group_id])).rows[0]?.name, item.question);
async function noteSaveAi(item, out, label) {
  const change = answerNote.applyChange(item, { answer_html: out.answerHtml, key_points: out.keyPoints }, { by: 'ai', label });
  return change.changed ? await writeNoteItem(item, change) : item;
}
async function noteWriteOne(session, userId, item, mode, custom, knownForm, onPartial) {
  const form = knownForm || await noteFormOf(item, mode);
  const out = mode === 'rich' || (form === 'explain' && mode === 'regenerate') ? await generateStudyNote(session, userId, item, onPartial)
    : answerNote.DETAIL_ARCS[form] ? await generateDetailedAnswer(session, userId, item, form, mode, custom)
    : await generateNoteAnswer(session, userId, item, mode, custom); // a change to a study note (Shorter, his own) is written as short lines
  const label = mode === 'regenerate' ? answerNote.FORM_LABEL[form] || answerNote.changeLabel(mode, custom) : answerNote.changeLabel(mode, custom);
  return noteSaveAi(item, out, label);
}
// Write all answers (owner 25 Oct: "thats what we do on xhire web.. batching"): like the bank's Generate All, the short
// answers go up to 5 per call (same writer rules, same shape), so a whole job is a few calls, not one per question.
// Detailed and study answers stay one call each: they are long and each follows its own path.
app.post('/api/note/generate-batch', authMiddleware, async (req, res) => {
  try {
    const session = await noteSes(req);
    if (!session) return res.status(400).json({ error: 'Add your résumé to a session first. The note writes answers from it.' });
    if (!String(session.resume || '').trim()) return res.status(400).json({ error: 'That session has no résumé. Pick one that does.' });
    const answerCheck = await checkAnswerLimit(req.userId, req.plan);
    if (!answerCheck.ok) return res.status(403).json({ error: `Monthly answer limit reached (${answerCheck.limit}). Upgrade for more.` });
    const asked = (Array.isArray(req.body?.items) ? req.body.items : []).slice(0, 10);
    const work = [];
    for (const a of asked) {
      const item = await ownNoteItem(req.userId, String(a && a.id || ''), session);
      if (item) work.push({ item, mode: a.mode === 'rich' ? 'rich' : 'regenerate' });
    }
    for (const w of work) w.form = await noteFormOf(w.item, w.mode);
    const results = [];
    const short = work.filter(w => w.mode === 'regenerate' && w.form !== 'explain' && !answerNote.DETAIL_ARCS[w.form]);
    const single = work.filter(w => !short.includes(w));
    const doShort = async () => {
      let outs = [];
      try { outs = short.length ? await generateNoteAnswersBatch(session, req.userId, short.map(w => w.item)) : []; }
      catch (e) { console.error('[Note] batch call failed, writing them one by one:', e.message); }
      for (let k = 0; k < short.length; k++) {
        const w = short[k];
        try {
          const saved = outs[k] ? await noteSaveAi(w.item, outs[k], answerNote.FORM_LABEL[w.form] || answerNote.changeLabel('regenerate', ''))
            : await noteWriteOne(session, req.userId, w.item, 'regenerate', '', w.form); // missing from the batch reply: written on its own
          results.push(noteItemOut(saved));
        } catch (e) { results.push({ id: w.item.id, error: e.message }); }
      }
    };
    const doSingle = async () => {
      let next = 0;
      const worker = async () => { while (next < single.length) { const w = single[next++];
        try { results.push(noteItemOut(await noteWriteOne(session, req.userId, w.item, w.mode, '', w.form))); } catch (e) { results.push({ id: w.item.id, error: e.message }); } } };
      await Promise.all([worker(), worker()]);
    };
    await Promise.all([doShort(), doSingle()]);
    console.log(`[Note] batch ${work.length} asked: short=${short.length} single=${single.length} ok=${results.filter(r => !r.error).length}`);
    res.json({ items: results, job: { id: session.id, company: session.company, role: session.role } });
  } catch (e) { console.error('[Note] batch failed:', e.message); res.status(500).json({ error: e.message }); }
});
app.post('/api/note/items/:iid/restore', authMiddleware, async (req, res) => {
  try {
    const item = await ownNoteItem(req.userId, req.params.iid, await noteSes(req));
    if (!item) return res.status(404).json({ error: 'Question not found' });
    let change;
    try { change = answerNote.restoreVersion(item, String(req.body?.versionId || '')); }
    catch (e) { if (e.code === 'NOT_FOUND') return res.status(404).json({ error: e.message }); throw e; }
    res.json(noteItemOut(change.changed ? await writeNoteItem(item, change) : item));
  } catch (e) { res.status(500).json({ error: e.message }); }
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

// The question in an interviewer's line, or null if the line isn't clearly a question (then the AI route decides).
// Short lines are kept whole (context like "A lot of our clients use Salesforce." matters); long ones are trimmed to
// start at the first sentence that begins the question.
function questionPartOf(text) {
  let raw = (text || '').trim();
  // A line that starts lowercase is the rest of a sentence Deepgram cut ("…how I wanna | describe the culture. So far…") —
  // its first sentence is never a question of its own (21 Oct: "describe the culture." became an answer card).
  if (/^[a-z]/.test(raw)) { const k = raw.search(/[.?!]\s+/); raw = k === -1 ? '' : raw.slice(k + 1).trim(); }
  let t = cleanQuestionText(raw);
  // strip spoken lead-ins ("Okay. So…", "Great, so…") with the shared filler rule, keep the question's own casing
  const leadRe = new RegExp(LEAD_FILLER_RE.source, 'i'); let prev;
  do { prev = t; t = t.replace(leadRe, ''); } while (t !== prev && t);
  if (t) t = t.charAt(0).toUpperCase() + t.slice(1);
  if (!t || !isQuestion(t)) return null;
  if (t.split(/\s+/).length <= 35) return t;
  const sentences = t.split(/(?<=[.?!])\s+/);
  for (let i = 0; i < sentences.length; i++) {
    const tail = sentences.slice(i).join(' ');
    if (isQuestion(sentences[i]) || (i === sentences.length - 1 && isQuestion(tail))) return tail;
  }
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

// === QUESTION RULES (one place — used by isQuestion, live auto-detect, and test/question-rules.js) ===
// Candidate talking about themselves / mid-answer — never an interview question.
const CANDIDATE_SPEECH_RE = /^(i |i'm |i've |i'd |i'll |i was |i did |i do |i think |i would |i could |i should |i used |i built |i have |i had |i made |i learned |i managed |i led |i created |i developed |i worked |i helped |i started |i ran |i set up |i implemented |i designed |i analyzed |i handled |i owned |i drove |we |we're |we've |we had |we did |we used |we built |we were |my |at my |in my |on my |with my |during my |if i |when i |one thing |one of the things i |another thing |the way i |the reason i |what happened was |what we did |and then |so then |after that |from there |long story short |to summarize |in the end )/;
// Interviewer asking in first person ("I'd love to hear how you…") — would otherwise look like candidate speech.
const INTERVIEWER_ASK_RE = /\b(i('d| would)( really| also| just)? (like|love) to (know|hear|understand|learn|see)|i( really| also| just)? want(ed)? to (ask|know|hear|understand)|i'm (curious|interested|wondering|trying to understand|keen to (hear|know|understand))|my (next |last |final |first )?question (is|would be)|the next question is|let me ask you|can you (tell|walk|talk|share|give|explain|describe)|could you (tell|walk|talk|share|give|explain|describe))\b/;
// Leading filler/acknowledgement the interviewer says before the real question ("Okay. So…", "Great question,").
const LEAD_FILLER_RE = /^(okay|ok|so|now|well|great question|good question|great|alright|all right|right|yeah|yes|sure|cool|awesome|perfect|good|nice|and|but|also|then|um|uh|hmm|oh|next|moving on|thanks|thank you|got it|makes sense|interesting|fair enough|sounds good|absolutely|definitely|exactly|actually|basically|just)\b[,.!:;]?\s*/;
function stripLeadFiller(t) { let prev; do { prev = t; t = t.replace(LEAD_FILLER_RE, ''); } while (t !== prev && t); return t; }
// A clause cut off mid-sentence ("…when it comes to Power BI, right,", "Build reports that") — Deepgram splits lines at tiny
// pauses; the rest is still coming. Live call 21 Oct: these got answer cards before the question was asked.
const CUT_OFF_END_RE = /(,|\b(that|how|of|and|the|to|a|an|in|on|for|with|or|but|so|like|which|what|when|where|who|why|is|are|was|were|be|about|if|because|from|as|at|by|your|my|our|their|this|these|those|i|we|you|they|it|than|then|into|do|does|did|can|could|would|will|should|have|has|had))$/;
// "How are you?" is small talk only as the greeting — "How are you currently using AI…?" is a question (stress bank 27 Oct)
const HOW_ARE_YOU_RE = /^how are you(?=\s*(doing|today|keeping|feeling|holding up|this (morning|afternoon|evening)|[,.!?]|$))/;
function isQuestionClause(s) {
  s = stripLeadFiller(s.trim());
  const words = s ? s.split(/\s+/).length : 0;
  if (words < 3) return false;
  if (!/[?.!]["')\]]?$/.test(s) && CUT_OFF_END_RE.test(s)) return false;
  if (CANDIDATE_SPEECH_RE.test(s)) return false;
  // Tag questions that only check the listener is following — "You know what I'm trying to say?", "Does that make sense?"
  if (/^((you\s+)+)?(know what i('m| am) (trying to say|saying|getting at)|know what i mean)|^(does|did) (that|this|it) make sense|^(that )?makes? sense\b/.test(s)) return false;
  // "What I did was…", "How we solved it…" — a statement, not a question
  if (/^(what|how|why|when|where|who|which) (i|we|they|he|she|it|this|that)\b/.test(s)) return false;
  // Small talk / logistics / wrap-up
  if (HOW_ARE_YOU_RE.test(s)) return false;
  if (/^(how's it going|how have you been|nice to meet|good to meet|good morning|good afternoon|good evening|hey |hi |hello |what time|what's your time|where are you (based|located|calling|joining)|are you (doing well|ready)|can you hear me|is (my|the) (audio|video|screen)|one (moment|second|sec)|bear with me|sorry about|apologies for|do you have any questions|any questions (for|from) (me|us)|that's (all|it|everything)|we('re| are) (running|almost)|let's (wrap|move|end)|before we (end|wrap|go))/.test(s)) return false;
  // Audio/video check-ins however they start ("…you hear me okay?" when noise ate "Can") — mock interview 26 Sep
  if (/\b(hear|see) me (okay|ok|alright|all right|fine|well|clearly)\b|\b(hear|see) me\?$/.test(s)) return false;
  // Candidate mid-answer continuation
  if (/^(eventually |ultimately |overall |the result |the outcome |the impact |the challenge |the problem |the solution |the key |the main |the biggest |the first |the second |the third )/.test(s)) return false;
  // "…I like that you said what you've done in the past." — a clause ABOUT what the candidate did/said, not a question
  if (/^(what|how|why|where|when|which) you('ve|'re|'d| have| had| did| said| do| were| are| \w+ed)\b/.test(s) && !/\?$/.test(s)) return false;
  // "…a role at Stripe. Which is a pretty cool company." — a relative clause continuing the last sentence, not a question
  if (/^which (is|was|were|are|has|have|had|means|meant|makes|made|would|will|can|could|should|sounds|looks|seems|gives|gave|lets|helps|helped|led|leads|includes|included|brings|brought|explains)\b/.test(s) && !/\?$/.test(s)) return false;
  if (/\?$/.test(s) && words >= 4) return true;
  // A scenario set up, the ask still to come: "So imagine you join us on Monday." (stress bank 27 Oct: answered as a question)
  const scen = s.match(/^(please )?(imagine|suppose|say you|let's say|pretend)\b(.*)$/);
  if (scen && !/\b(what|how|why|which|would you|will you|could you|can you|do you|walk|talk|tell|explain|describe|show|give)\b/.test(scen[3])) return false;
  // Imperative interview prompts: "Please describe…", "Talk me through…", "Share an example…"
  if (/^(please |kindly )?(explain|define|describe|compare|contrast|walk (me|us) through|talk (me|us) through|talk (to (me|us) )?about|tell (me|us)|give (me|us)|share|show (me|us)|outline|discuss|elaborate|summarize|list|name|provide|imagine|suppose|say you|let's say|what if|pretend|think of|think about|how about)\b/.test(s)) return true;
  // Task requests ("Write me a quick SQL query…", "Build a measure that…", "Calculate the…") — mock interview 26 Sep
  // …but not the interviewer describing what THEIR team does ("Build datasets, helping them build dashboards…" — 21 Oct)
  if (/^(please |kindly |can you |could you )?(write|code|build|create|design|draft|sketch|calculate|compute|find|model|set up|put together)\b/.test(s)
    && !(/\b(they|them|their)\b/.test(s) && !/\b(you|your|me|us)\b/.test(s))) return true;
  if (words >= 4 && /^(can you |could you |have you |had you |do you |did you |would you |will you |are you |were you |should you |is there |was there |have there been |what's |how's |where's |who's )/.test(s)) return true;
  if (words >= 5 && /^(what |how |why |when |where |who |which )/.test(s)) return true;
  return false;
}
function isQuestion(text) {
  const t = text.trim().toLowerCase();
  if (t.split(/\s+/).length < 3 || t.length < 15) return false;
  // Announcing a question that hasn't been asked yet — "I do have one question I wanted to ask you." (21 Oct)
  if (!/\?/.test(t) && /\b(ask you|for you)[.!]?$/.test(t) && /\b(question|ask)\b/.test(t)) return false;
  // Announcing the topic, the question still to come — "Let me ask you about stakeholders." (stress bank 27 Oct: jumped
  // to an OLD stakeholder card before the question was asked)
  const tParts = t.split(/(?<=[.?!])\s+/);
  if (/^(?:(?:okay|ok|so|now|alright|right|great|good)[,.]?\s+)*(let me ask you|i('d| would) like to ask you|i want(ed)? to ask you|let's talk|i want(ed)? to talk( to you)?) about\b[^.?!]*[.!]?$/.test(tParts[0].trim())
    && !tParts.slice(1).some(x => isQuestionClause(x))) return false;
  if (/\byou(r|'re|'ve|'d)?\b/.test(t) && INTERVIEWER_ASK_RE.test(t)) return true;
  // The utterance opens as the candidate talking about themselves → not a question.
  // …unless a later sentence is a clear question TO the candidate ("I didn't catch the company names. So what companies
  // did you work for?" — interviewers open with "I…" all the time; prod 26 Sep 23:16).
  const askedYou = t.split(/(?<=[.?!])\s+/).slice(1).some(x => /\?$/.test(x.trim()) && /\byou(r)?\b/.test(x) && isQuestionClause(x));
  if (CANDIDATE_SPEECH_RE.test(stripLeadFiller(t)) && !askedYou) return false;
  // Any sentence — or the tail after a lead-in clause ("In your current role, what…") — can carry the question.
  for (const sentence of t.split(/(?<=[.?!;])\s+|\s+[—–]\s+|\s+-\s+/)) {
    if (isQuestionClause(sentence)) return true;
    // The tail after a lead-in clause counts only when it is asked of the candidate ("In your role, what…", "…, how would
    // you…") or ends in "?" — never a clause continuing a statement ("We report up to Tricia, who is our manager." 21 Oct)
    let i = sentence.indexOf(',');
    while (i !== -1) { const tail = sentence.slice(i + 1).trim(); if ((/\?["')\]]?$/.test(tail) || /\byou(r)?\b/.test(tail)) && isQuestionClause(tail)) return true; i = sentence.indexOf(',', i + 1); }
  }
  return false;
}
// Any sign a line MIGHT be asking something — the gate before the AI question check (cheap superset of the rules above).
const QUESTION_SIGNAL_RE = /\?|\b(you|your|yours|you're|you've|you'd|you'll)\b|^(so |and |okay,? |ok,? |now,? |alright,? )?(what|how|why|when|where|which|who)\b|\b(tell me|tell us|walk me|walk us|talk me|describe|explain|share|give me|thoughts on|example of|imagine|suppose|let's say|what if)\b/i;
// === END QUESTION RULES ===

// "Stay silent" filter — clearly NON-substantive interviewer utterances that can slip past
// isQuestion (rapport, logistics, comprehension check-ins, closing). Conservative on purpose:
// only the obvious stuff is matched — anything that could be a real interview question is not.
function isLowValueQuestion(text) {
  const t = (text || '').trim().toLowerCase();
  // meta / comprehension check-ins
  if (/^(does that make sense|is that clear|did that (make sense|answer|help)|any questions (so far|on that)|are you (with me|following)|makes sense\??$|got it\??$|any concerns)/.test(t)) return true;
  // rapport / small talk
  if (HOW_ARE_YOU_RE.test(t)) return true;
  if (/^(how('s| is) (your day|it going|everything|the weather)|how has your (day|week) been|hope you('re| are) (well|doing well))/.test(t)) return true;
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

// ===== SEMANTIC MATCH — find bank questions by MEANING, not shared words =====
// Interviewers paraphrase ("convince people who aren't buying your idea" ↔ "get buy-in when stakeholders aren't sold")
// and word matching misses that. A small local embedding model (all-MiniLM-L6-v2, ~23 MB, ~1–2 ms per question on CPU)
// adds meaning-based candidates; Haiku verification still confirms every match. Loads in the background at server
// start — until it's ready, or if it fails, matching is word-based exactly as before. SEMANTIC_MATCH=0 turns it off.
const SEMANTIC_MIN = 0.5;   // measured 25 Sep: true paraphrases 0.59–0.66, unrelated bank questions ≤ 0.40
let _embedder = null, _embedderState = 'off';
const _vecCache = new Map(); // normalized text → Float32Array
function startSemanticModel() {
  if (process.env.SEMANTIC_MATCH === '0' || _embedderState !== 'off') return;
  _embedderState = 'loading'; const t0 = Date.now();
  import('@huggingface/transformers')
    .then(({ pipeline }) => pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2'))
    .then(p => { _embedder = p; _embedderState = 'ready'; console.log(`[Semantic] Model ready in ${Date.now() - t0}ms`); })
    .catch(e => { _embedderState = 'failed'; console.error('[Semantic] Model failed to load — word matching only:', e.message); });
}
async function embedText(text) {
  if (!_embedder) return null;
  const k = (text || '').trim().toLowerCase();
  if (!k) return null;
  if (_vecCache.has(k)) return _vecCache.get(k);
  const v = (await _embedder(k, { pooling: 'mean', normalize: true })).data;
  if (_vecCache.size > 20000) _vecCache.clear();
  _vecCache.set(k, v);
  return v;
}
function warmSemantic(questions) { // embed a session's bank ahead of time (background) so matching stays ~1 ms
  if (!_embedder) return;
  (async () => { for (const q of questions) { try { await embedText(q.text); } catch (e) { return; } } })();
}
async function findSemanticMatches(questionText, sessionQuestions, topN = 3) {
  if (!_embedder || !sessionQuestions.length) return [];
  const v = await embedText(questionText);
  if (!v) return [];
  const scored = [];
  for (const sq of sessionQuestions) {
    const w = await embedText(sq.text); if (!w) continue;
    let sim = 0; for (let i = 0; i < v.length; i++) sim += v[i] * w[i];
    if (sim >= SEMANTIC_MIN) scored.push({ question: sq, similarity: sim, semantic: true });
  }
  return scored.sort((a, b) => b.similarity - a.similarity).slice(0, topN);
}

// Is `newQ` the SAME question continued (a second part asked straight after), not a new one? Owner (26 Sep): people ask
// "…difference between inner and left join? How would you approach this?" — that is ONE question; the app must not
// jump to a new card. Continuation words, a pointer back to it, or the same topic by meaning.
const FOLLOW_UP_SIMILARITY = 0.55;
async function isFollowUpOf(newQ, prevQ) {
  const t = (newQ || '').trim().toLowerCase();
  if (/^(and|also|plus|what about|how about|what if)\b/.test(t)) return true; // question clean-up strips a leading And
  // An example of what was just asked: "Right? Just give me an example where…", "For example, what…" (stress bank 27 Oct)
  // — not a new prompt that names its own topic ("Give me an example of a time you failed").
  if (/^((right|so|just|and|okay|now|maybe)[?,.]?\s+)*((can|could|would) you\s+)?(just\s+)?(give|share|tell|walk)\s+(me|us)\s+(an?|one)\s+((quick|real|concrete|specific)\s+)?example\b(?!\s+of\s+(a|the)\s+time\b)|^(for example|for instance)\b/.test(t)) return true;
  if (t.split(/\s+/).length <= 14 && (/\b(this|that|those|these|each|either|both)\b/.test(t) || /\b(it|them)\s*[?.!]?$/.test(t))) return true;
  // "What tools did you use for it? And who used it every week?" (22 Oct test): "it/them" pointing back, anywhere in a short ask.
  if (t.split(/\s+/).length <= 20 && /\b(for|with|on|about|in|of|from|to|into|use|used|using|build|built|do|did|run|ran|make|made|handle|handled|share|test|tested|explain)\s+(it|them)(\s*([?.!,]|$)|\s+(and|or|every|each|daily|weekly|at|in|on|with|for)\b)/.test(t)) return true; // not "handle it when…" (points forward)
  try {
    const a = await embedText(newQ), b = await embedText(prevQ);
    if (a && b) { let sim = 0; for (let i = 0; i < a.length; i++) sim += a[i] * b[i]; if (sim >= FOLLOW_UP_SIMILARITY) return true; }
  } catch (e) {}
  return false;
}

// AI verification — send top candidates to Haiku for semantic confirmation
async function verifyMatch(utterance, candidates, sessionContext, timeoutMs = 2500) {
  if (!candidates || candidates.length === 0) return null;

  const candidateList = candidates.map((c, i) =>
    `${i + 1}. "${c.question.text}"`
  ).join('\n');

  const ctx = sessionContext || {};
  const ctxLine = (ctx.company || ctx.role) ? `This is an interview for ${ctx.role || 'a role'} at ${ctx.company || 'a company'}. ` : '';

  const system = ctxLine + 'You verify whether an interview question matches a candidate from a question bank. A match means the interviewer is asking THE SAME question — not just a related topic. "What is data governance?" does NOT match "What are ETL processes?" even though both are data topics. The same question in different words IS a match, even when the people or objects are named differently ("How do you convince people who are not buying your idea?" = "How do you get buy-in when stakeholders are not sold on your idea?"; "manager" = "leadership"; "dashboard" = "report"). Be strict on SUBJECT: the specific skill, tool or topic must be the same — a broader or neighbouring topic is NOT a match ("experience with demand forecasting" does NOT match "experience with logistics or supply chain data"). If the core subject differs, reply NONE. Reply ONLY "MATCH:N" (N = candidate number) or "NONE". Nothing else.';
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
async function fastMatchAndRespond(utterance, sessionQuestions, sessionId, userId, ws, lastMatchedQId, recentMatchedIds, questionIndex, onIndexRebuild, skipFilter, forceNavigate, skipClean, extraOpts) {
  const startMs = Date.now();
  const tClean = Date.now();
  const q = skipClean ? utterance.trim() : await aiCleanQuestion(utterance.trim());
  // forceNavigate = the user asked for this (What should I say / typed / clicked a line): never filter
  // it away, and never end silently — tell them why nothing came back.
  if (!q || q.length < 5) {
    if (forceNavigate) ws.send(JSON.stringify({ type: 'error', message: 'Could not identify a question from the conversation' }));
    return lastMatchedQId;
  }
  if (!skipFilter && !forceNavigate && !isQuestion(q)) return lastMatchedQId;
  if (!skipClean) console.log(`[TIMING] aiCleanQuestion: ${Date.now() - tClean}ms`);

  // Get top 3 keyword candidates, excluding already-matched questions
  // A card made earlier in THIS call that the candidate has already answered is not a prepared answer for a new question —
  // only the same question asked again may show it (live call 21 Oct: "How do you handle conflicting priorities?" showed
  // the 3-minute-old card for "Have you come across issues like that…"). Earlier calls' cards and the bank are unaffected.
  const staleThisCall = m => m.question.source === 'live' && m.question._createdAt && (ws._lastUserSpeechTs || 0) > m.question._createdAt
    && stringSimilarity.compareTwoStrings(String(m.question.text || '').toLowerCase(), q.toLowerCase()) < 0.85;
  const allowed = m => m.question.id !== lastMatchedQId && !recentMatchedIds?.has?.(m.question.id)
    && !(staleThisCall(m) && (console.log(`[FastMatch] Skipping already-answered card from this call: "${String(m.question.text).slice(0, 50)}"`), true));
  const topMatches = findTopMatches(q, sessionQuestions, questionIndex, 3).filter(allowed);
  // + meaning-based candidates the word matcher missed (paraphrases). Haiku verification below confirms any pick.
  try {
    const tSem = Date.now();
    const sem = (await findSemanticMatches(q, sessionQuestions, 3)).filter(allowed).filter(m => !topMatches.some(t => t.question.id === m.question.id));
    if (sem.length) console.log(`[Semantic] +${sem.length} candidate(s) in ${Date.now() - tSem}ms, best ${sem[0].similarity.toFixed(2)}: "${sem[0].question.text.slice(0, 50)}"`);
    topMatches.push(...sem);
  } catch (e) { console.error('[Semantic] match failed — word matching only:', e.message); }

  if (topMatches.length > 0) {
    // FAST PATH: if the top candidate is a near-identical (very high confidence) match,
    // trust it and skip the Haiku verification round-trip. Saves ~1 API call of latency
    // AND one Haiku call of cost on the common "question is already in the bank" case.
    // Anything below the bar still goes through full AI verification as before.
    let verified;
    if (!topMatches[0].semantic && topMatches[0].similarity >= HIGH_CONFIDENCE_MATCH) {
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
        answer: displayPrepared(verified.question.answer || '', verified.question.text),
        similarity: Math.round(verified.similarity * 100),
        hasAnswer: !!verified.question.answer,
        navigate: !!forceNavigate
      };
      ws.send(JSON.stringify(matchMsg));
      broadcastToSession(sessionId, matchMsg, ws);
      recentMatchedIds.add(verified.question.id);
      ws._lastCard = { id: verified.question.id, q: verified.question.text, asked: q, ts: Date.now(), isBank: true };
      // Track as active thread so continued detail can grow it on-screen.
      // _prepped:true → growth updates the display but never overwrites the bank answer in the DB.
      if (!verified.question.answer) {
        // Matched a bank question whose answer isn't prepared yet (e.g. a must-have still being prepared) — answer it
        // now; generateLiveAnswer streams onto this card and fills the bank row. Never leave an empty card.
        console.log('[FastMatch] Matched bank question has no answer yet — generating it now');
        generateLiveAnswer(verified.question.text, sessionId, userId, ws, verified.question.id, !!forceNavigate, Object.assign({}, extraOpts || {}))
          .catch(e => console.error('[FastMatch] answer for empty bank question failed:', e.message));
      }
      if (verified.question.answer) {
        ws._activeAnswer = { id: verified.question.id, questionText: verified.question.text, answer: displayPrepared(verified.question.answer, verified.question.text), _grows: 0, _prepped: true };
        // SESSION MEMORY: the prepared answer shows instantly; if this session already discussed the topic, stream a
        // version adapted to what was said onto the SAME card (the bank itself is never changed).
        if (hasConversation(ws)) {
          console.log('[Memory] Checking prepared answer against the conversation');
          generateLiveAnswer(verified.question.text, sessionId, userId, ws, verified.question.id, !!forceNavigate, Object.assign({}, extraOpts || {}, { bankAnswer: verified.question.answer }))
            .catch(e => console.error('[Memory] adapt failed:', e.message));
        }
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
      generateLiveAnswer(betterText, sessionId, userId, ws, rlq.id, !!forceNavigate, Object.assign({}, extraOpts || {})).catch(e => console.error('[Dedup regen error]', e.message));
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
    ws._lastNewCard = { id: qId, q, ts: Date.now() };
    ws._lastCard = { id: qId, q, asked: q, ts: Date.now(), isBank: false };

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

// opts.endpointing = ms of real silence before Deepgram marks speech_final (its default, 10 ms, fires on every breath —
// live call 21 Oct: sentences cut mid-way and answered). opts.onUtteranceEnd = the speaker has stopped (utterance_end_ms).
function openDeepgramStream(onTranscript, onError, opts = {}) {
  if (!DEEPGRAM_API_KEY) { onError(new Error('DEEPGRAM_API_KEY not set')); return null; }
  const params = 'model=nova-3&punctuate=true&interim_results=true&utterance_end_ms=1500&vad_events=true&encoding=linear16&sample_rate=16000&channels=1'
    + (opts.endpointing ? '&endpointing=' + opts.endpointing : '');
  const dgWs = new WebSocket('wss://api.deepgram.com/v1/listen?' + params, {
    headers: { 'Authorization': 'Token ' + DEEPGRAM_API_KEY }
  });
  // Timeline: map Deepgram's audio seconds (restart per stream) to server arrival time, so the interviewer
  // channel and the mic channel can be compared on ONE clock ("who started speaking first?").
  const rawSend = dgWs.send.bind(dgWs);
  let audioSec = 0; const timeline = []; // [audioSecondsAtEndOfPacket, arrivalMs]
  dgWs.send = (data, ...rest) => {
    if (Buffer.isBuffer(data)) {
      audioSec += data.length / 32000; // linear16 mono 16 kHz
      timeline.push([audioSec, data._wall || Date.now()]);
      if (timeline.length > 3000) timeline.shift();
    }
    return rawSend(data, ...rest);
  };
  const wallAt = (sec) => {
    if (typeof sec !== 'number') return null;
    for (let i = 0; i < timeline.length; i++) if (timeline[i][0] >= sec) return Math.round(timeline[i][1] - (timeline[i][0] - sec) * 1000);
    return null;
  };
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
        // When speech began = first WORD's start (msg.start is the result window, which can include leading silence)
        const w0 = msg.channel.alternatives[0].words && msg.channel.alternatives[0].words[0];
        if (text.trim()) onTranscript(text, msg.is_final, msg.speech_final, { startWall: wallAt(w0 ? w0.start : msg.start) });
      } else if (msg.type === 'UtteranceEnd' && opts.onUtteranceEnd) opts.onUtteranceEnd();
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
  let interviewerInterim = ''; // words still being spoken (not final yet) — Say reads them too
  let lastMatchedQId = null;
  let lastWsayMatchId = null; // track last "What should I say?" result — exclude on re-click
  let recentMatchedIds = new Set(); // prevent duplicate matches within short window
  let questionIndex = null; // TF-IDF + keyword index for smart matching
  let idleTimer = null;
  let idleWarningTimer = null;
  const IDLE_TIMEOUT = Number(process.env.IDLE_TIMEOUT_MS) || 10 * 60 * 1000; // 10 minutes — interviewer may leave and rejoin (env = tests only)
  const IDLE_WARNING = Math.round(IDLE_TIMEOUT * 0.8); // Warn at 8 minutes
  function resetIdleTimer() {
    if (isCanvasMode) return; // canvas clients don't have idle timeout
    clearTimeout(idleTimer);
    clearTimeout(idleWarningTimer);
    idleWarningTimer = setTimeout(() => {
      const lastScreen = sessionId ? screenActivity.get(sessionId) : 0;
      if (lastScreen && Date.now() - lastScreen < IDLE_WARNING) return; // screen in use — not idle
      try { ws.send(JSON.stringify({ type: 'status', message: 'No audio for 8 min — live will end in 2 min if silence continues' })); } catch(e) {}
    }, IDLE_WARNING);
    idleTimer = setTimeout(() => {
      // Screen captures arrive over HTTP, not this socket — an assessment with no talking is still a live session (2 Oct)
      const lastScreen = sessionId ? screenActivity.get(sessionId) : 0;
      if (lastScreen && Date.now() - lastScreen < IDLE_TIMEOUT) { console.log('[WS] Idle check — screen in use, staying live'); resetIdleTimer(); return; }
      console.log('[WS] Idle timeout — closing connection');
      try { ws.send(JSON.stringify({ type: 'status', message: 'Live mode ended — idle timeout (10 min no audio)' })); } catch(e) {}
      ws.close();
    }, IDLE_TIMEOUT);
  }
  let sentenceCountSinceReset = 0; // track sentences in current utterance
  // ONE rule: only the interviewer's committed lines may ever be read as a question — never the user's
  // own mic ([You]) or their voice leaking into call audio ([Echo]). Used by auto-detect AND "What should I say".
  const interviewerLines = () => transcript.filter(t => !t.isUser && !t.isEcho);
  ws._getTranscript = () => transcript; // SESSION MEMORY reads this call through here (transcript is reassigned per call)
  // Volume-based self-voice state, per connection (was an accidental global shared across ALL users).
  let userIsSpeaking = false; // true when user is talking into mic
  let userStoppedSpeakingAt = 0; // Timestamp when user stopped speaking

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
      audio._wall = Date.now(); // arrival time — survives buffering, read by the Deepgram timeline

      _audioPktCount[channel] = (_audioPktCount[channel] || 0) + 1;
      // Loudness per channel over time — decides echo vs bleed when word timing can't (see isEchoOfUser)
      if (audio.length >= 2 && (channel === 1 || channel === 2)) {
        let sum = 0; const n = audio.length >> 1;
        for (let i = 0; i < n; i++) { const v = audio.readInt16LE(i * 2); sum += v * v; }
        const log = (ws._rms = ws._rms || { 1: [], 2: [] })[channel];
        log.push([audio._wall, Math.sqrt(sum / n)]); if (log.length > 600) log.shift();
      }
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
            pool.query('SELECT resume, jd, company, role, answer_style FROM sessions WHERE id = $1', [sessionId])
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

        // Must-have questions (incl. influence & pushback) in this session's bank BEFORE it loads; answers are
        // prepared in the background and the bank below is reloaded when they land.
        let mustHaves = null;
        const reloadBank = () => pool.query('SELECT id, text, type, answer FROM questions WHERE session_id = $1', [sessionId]).then(r => {
          sessionQuestions.length = 0; sessionQuestions.push(...r.rows); // same array the call already holds
          questionIndex = buildQuestionIndex(sessionQuestions); warmSemantic(sessionQuestions);
        });
        try { mustHaves = await ensureMustHavesReady(sessionId, userId, reloadBank); } catch (e) { console.error('[MustHave] ensure failed:', e.message); }

        // Load session questions + session context (cached for fast answer generation)
        const [qResult, sResult] = await Promise.all([
          pool.query('SELECT id, text, type, answer FROM questions WHERE session_id = $1', [sessionId]),
          pool.query('SELECT resume, jd, company, role, answer_style FROM sessions WHERE id = $1', [sessionId])
        ]);
        sessionQuestions = qResult.rows;
        questionIndex = buildQuestionIndex(sessionQuestions);
        console.log(`[TF-IDF] Built index for ${sessionQuestions.length} questions`);
        warmSemantic(sessionQuestions);
        if (mustHaves) mustHaves.answered.then(n => { if (n) console.log(`[MustHave] Live bank has all ${n} newly prepared answers`); })
          .catch(e => console.error('[MustHave] prepare failed:', e.message));

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
        ws._callId = transcriptId; // the call log (call_events) is keyed by this; cleared on stop/close
        transcript = [];
        // SESSION MEMORY: fresh notes for this call; load what was said in earlier calls of this session (background)
        ws._callNotes = ''; ws._digestedLines = 0; ws._priorMemory = ''; ws._bridges = ''; ws._bridgesSeen = 0; ws._bridgesAt = 0; ws._bridgesRuns = 0; clearTimeout(ws._bridgeTimer); ws._bridgeTimer = null; ws._bankSnapshot = null;
        const _memT0 = Date.now(), _memTid = transcriptId;
        pool.query('SELECT kind FROM sessions WHERE id = $1', [sessionId]).then(k => {
          ws._isAssessment = (k.rows[0] || {}).kind === 'assessment';
          if (ws._isAssessment) return loadAssessmentCarry(sessionId, _memTid).then(m => { // no interviewers, no bridges: the carry is the memory
            ws._priorMemory = m;
            console.log(`[Assessment] sitting ${_memTid} starts from ${m ? 'the carry (' + m.length + ' chars)' : 'nothing (first sitting)'} in ${Date.now() - _memT0}ms`);
          });
          return loadPriorCallsMemory(sessionId, userId, _memTid).then(m => {
            ws._priorMemory = m;
            ws._bridges = '';
            if (m) refreshBridgesSoon(ws);
            console.log(`[Memory] Earlier calls loaded: ${m ? m.length + ' chars' : 'none'} in ${Date.now() - _memT0}ms`);
          });
        }).catch(e => console.error('[Memory] load failed:', e.message));
        lastMatchedQId = null;
        let lastAutoMatchTime = 0; // Timestamp of last auto-detected match
        const AUTO_MATCH_COOLDOWN = parseInt(process.env.AUTO_MATCH_COOLDOWN_MS, 10) || 15000; // 15s cooldown (env only for tests) — responsive detection while avoiding rapid switching

        // Single Deepgram stream — two detection layers:
        // 1. Fast: isQuestion() pattern match fires instantly on obvious questions
        // 2. Smart: On every speechFinal, Haiku extracts the question from recent transcript
        //    (same logic as "What should I say?" but automatic)
        let questionFiredForBuffer = false;
        let lastAiExtractedQ = ''; // prevent re-firing same extracted question
        let recentDetectedQs = []; // last 5 detected questions for fuzzy de-dup
        let aiExtractTimer = null; // debounce timer — wait for speech to settle before extracting
        const AI_EXTRACT_DELAY = 800;
        const AI_READ_WINDOW_MS = 40000; // the AI reader looks only at interviewer lines this recent
        const GROW_WINDOW_MS = 20000; // the rest of a question updates its card only this soon after it was asked // wait after last speechFinal before AI fires (trimmed for speed)
        const USER_SPEECH_GUARD = 2000; // 2s after user stops speaking before allowing detection
        let lastCommitTs = 0; // last time an interviewer utterance was committed (paces eager detection)
        let ch1BufStartWall = null; // server time the current interviewer utterance started (shared clock)
        let lastInterviewerCommit = null; // { text, ts } — to re-join a question split across two commits
        let pendingFastTimer = null, pendingFastQ = null, pendingSince = 0; // a cut-off question waits for its continuation
        ws._questionPending = () => !!(pendingFastQ || aiExtractTimer); // Say: a heard question not answered yet belongs to the press
        // (re)arm the hold. The real "they stopped" signals are Deepgram's: speech_final (500 ms of silence, endpointing) and
        // UtteranceEnd (1.5 s) — both fire it at once. This timer is only the safety net: 3 s after the last word we
        // received (Deepgram sends words ~1 s apart while someone talks, so a short timer fired mid-sentence — 21 Oct
        // e2e), never later than 10 s after the question. Live call 21 Oct: answers came before the question was finished.
        const armPendingFast = () => {
          if (pendingFastTimer) clearTimeout(pendingFastTimer);
          const q = pendingFastQ, wait = Math.max(0, Math.min(3000, 10000 - (Date.now() - pendingSince)));
          pendingFastTimer = setTimeout(() => { pendingFastTimer = null; pendingFastQ = null; console.log('[Fast] Interviewer stopped — answering held question'); fireDetectedQuestion(q, 'fast'); }, wait);
        };
        const firePendingNow = (why) => {
          if (!pendingFastTimer) return;
          clearTimeout(pendingFastTimer); pendingFastTimer = null;
          const q = pendingFastQ; pendingFastQ = null;
          console.log('[Fast] ' + why + ' — answering held question');
          fireDetectedQuestion(q, 'fast');
        };

        // Re-answer a card for its full question: prepared bank answer when one matches, else a fresh answer — same card id.
        // The rest of the question after a mid-question Say press: grow that card (lines on screen stay; 1–2 added).
        function growSayCard(fullQ) {
          const lc = ws._lastCard; if (!lc) return;
          const before = String(lc.asked || lc.q).toLowerCase();
          // Only the tail may arrive ("…on their phones?" when the line was split) — keep the start of the question with it.
          if (!fullQ.toLowerCase().includes(before.split(/\s+/).slice(0, 4).join(' '))) fullQ = `${(lc.asked || lc.q).replace(/\?\s*$/, '')}, ${fullQ}`;
          lc.asked = fullQ; lc.heardTs = Date.now();
          recentDetectedQs.push(fullQ); if (recentDetectedQs.length > 5) recentDetectedQs.shift();
          // Nothing to add only when no new word was said (23 Oct test: "…open it" vs "…open it on their phones?" is 90% alike —
          // the similarity check skipped "phones", the part that mattered).
          const added = fullQ.toLowerCase().match(/[a-z][a-z'-]{3,}/g) || [];
          if (!added.some(w => !before.includes(w.replace(/(ies|es|s)$/, '')))) { console.log('[WhatShouldISay] Finished question is the one on screen — nothing to add'); return; }
          // The card's title becomes the whole question (pressed early: it was the half heard, "…how you would build a").
          if (ws._activeAnswer && ws._activeAnswer.id === lc.id) ws._activeAnswer.questionText = fullQ;
          const sq = sessionQuestions.find(x => x.id === lc.id); if (sq && !lc.isBank) sq.text = fullQ;
          if (!lc.isBank) pool.query('UPDATE questions SET text = $1 WHERE id = $2', [fullQ, lc.id]).catch(e => console.error('[WhatShouldISay] title update failed:', e.message));
          console.log('[WhatShouldISay] Rest of the question arrived — growing the card on screen:', fullQ.substring(0, 80));
          if (ws._activeAnswer && ws._activeAnswer.id === lc.id) growLiveAnswer(ws, sessionId, ws._activeAnswer, fullQ).catch(e => console.error('[Grow]', e.message));
          else ws._pendingGrow = { id: lc.id, q: fullQ, title: lc.isBank ? null : fullQ };
        }
        ws._growSayCard = growSayCard; // the Say handler grows its card when they finish during the press

        // The FULL question after its first half made a card. Owner 24 Oct: "it grows if there is more to read.. you dont
        // want to start speaking on something and it changes and you are lost.. this is app wide". It used to SWAP the card
        // (a prepared answer or a full rewrite) while he may already be reading it; now it grows like Say and follow-ups:
        // the lines on screen stay, 1-2 are added for what the rest of the question asked.
        async function upgradeCard(fullQ, cardId) {
          console.log('[Upgrade] Full question arrived — growing the card on screen:', fullQ.substring(0, 60));
          pool.query('UPDATE questions SET text = $1 WHERE id = $2', [fullQ, cardId]).catch(e => console.error('[Upgrade] title update failed:', e.message));
          const sq = sessionQuestions.find(x => x.id === cardId); if (sq) sq.text = fullQ;
          if (ws._activeAnswer && ws._activeAnswer.id === cardId) await growLiveAnswer(ws, sessionId, ws._activeAnswer, fullQ);
          else ws._pendingGrow = { id: cardId, q: fullQ, title: fullQ }; // still arriving: grows the moment it finishes
        }

        // CO-PILOT DOOR for a heard line (owner, 13 Oct: no card unless someone actually asked, never the same question twice).
        // 1) finished ask aimed at him (gate)  2) not already answered / in flight on this call → jump to that card
        // 3) Haiku: a person asking him now, not a video's voice-over or a checklist read out. Every skip logs its reason.
        async function routeHeardToCopilot(q, via) {
          const gate = meetingCopilot.heardAskGate(q);
          if (!gate.ok) { console.log(`[Co-pilot] heard, not answered (${gate.reason}): ${q.substring(0, 80)}`); return; }
          const now = Date.now();
          ws._copilotHeard = (ws._copilotHeard || []).filter(a => now - a.ts < 10 * 60 * 1000);
          let rows = [];
          try { rows = ws._callId ? await loadCallRows(ws._callId) : []; } catch (e) { console.error('[Co-pilot] call rows failed (dedupe runs on in-flight asks only):', e.message); }
          const asked = ws._copilotHeard.map(a => ({ text: a.text, cardId: a.cardId }));
          for (const r of rows) if (r.kind === 'said' && r.meta) for (const x of [r.meta.ask].concat(r.meta.answered || [])) if (x) asked.push({ text: x, cardId: r.meta.cardId || '' });
          const dup = meetingCopilot.findAnsweredAsk(q, asked);
          if (dup) {
            console.log(`[Co-pilot] heard again, already answered${dup.cardId ? ' (card ' + dup.cardId + ')' : ' (in flight)'}: ${q.substring(0, 80)}`);
            if (dup.cardId) { const m = { type: 'copilot_dup', cardId: dup.cardId, text: q }; ws.send(JSON.stringify(m)); broadcastToSession(sessionId, m, ws); }
            return;
          }
          const entry = { text: q, ts: now, cardId: '' };
          ws._copilotHeard.push(entry); // claims it now: a second route firing the same line 0.5 s later is a duplicate
          const t0 = Date.now();
          const verdict = await Promise.race([
            callClaude(meetingCopilot.HEARD_ASK_JUDGE, meetingCopilot.buildHeardAskJudgeInput(q, rows), 30, MODEL_HAIKU, { __tag: 'copilot-judge' }).catch(e => 'ASK (judge failed: ' + e.message + ')'),
            new Promise(r => setTimeout(() => r('ASK (judge timed out)'), 3000)),
          ]);
          if (!meetingCopilot.judgeSaysAsk(verdict)) {
            ws._copilotHeard = ws._copilotHeard.filter(a => a !== entry);
            console.log(`[Co-pilot] heard, not answered (${String(verdict).trim().slice(0, 80)}) in ${Date.now() - t0}ms: ${q.substring(0, 80)}`);
            return;
          }
          console.log(`[Co-pilot] question routed to co-pilot (${via}, judge ${String(verdict).trim().slice(0, 40)} in ${Date.now() - t0}ms):`, q.substring(0, 60));
          ws._copilotAskTs = Date.now(); // "just asked" for a later Say press starts after this
          const qd = { type: 'question_detected', text: q, source: 'copilot' };
          ws.send(JSON.stringify(qd)); broadcastToSession(sessionId, qd, ws);
        }

        // ONE door for an auto-detected question (both the fast route and the AI route): quality filter, continuation →
        // grow, stay-silent, de-dup, cooldown, then match/answer. Only ever called with INTERVIEWER speech.
        async function fireDetectedQuestion(q, via) {
          q = String(q || '').replace(/^[\s?.!,;:]+/, ''); // "Right? Just give me…" with the filler stripped left "? Just…" as the title
          const inCooldown = (Date.now() - lastAutoMatchTime < AUTO_MATCH_COOLDOWN);
          const growEnabled = process.env.GROW_ANSWERS !== '0';

          // Post-filter: even after AI extraction, run isQuestion() to catch false positives
          if (!isQuestion(q)) {
            console.log('[AI Auto-Detect] Post-filter rejected:', q.substring(0, 60));
            return;
          }
          // MEETING CO-PILOT MODE: the question goes to co-pilot (the client answers it with the shared screen) —
          // no Q&A card, no bank match, no bridges. One question is paid once.
          if (ws._copilotMode) return routeHeardToCopilot(q, via);

          // SAY PRESSED MID-QUESTION (owner, 23 Oct: "they click early because they can already hear the question"): the
          // question the interviewer then finishes is the one that press is answering — the same card, grown with the rest.
          const st = ws._sayTurn;
          if (st && !st.used && Date.now() - st.at < 20000 && !((ws._lastUserSpeechTs || 0) > st.at)) {
            st.used = true;
            if (!st.done) { st.fullQ = q; console.log('[WhatShouldISay] The question they were asking is finished — the press answers it:', q.substring(0, 60)); return; }
            growSayCard(q); return;
          }

          // CONTINUATION: the interviewer is elaborating on the SAME question we're already
          // answering → grow that answer in place (append), instead of a new card. This
          // bypasses the recent-question dedup and the cooldown on purpose.
          // Growth needs something NEW: the same question found again (e.g. the AI re-reading the last question when the
          // next line is only "In Power BI,") must not grow or relabel the card — mock interview 26 Sep.
          const qLowG = q.toLowerCase().trim();
          // Grow only a card asked moments ago (owner, 21 Oct: new questions minutes later were folded into an old card —
          // "stale"). Older than GROW_WINDOW_MS → a new question gets its own answer.
          const growFresh = !!(ws._activeAnswer && ws._lastCard && ws._lastCard.id === ws._activeAnswer.id && Date.now() - ws._lastCard.ts < GROW_WINDOW_MS);
          const alreadyAsked = [...recentDetectedQs, ws._activeAnswer && ws._activeAnswer.questionText, ws._lastCard && ws._lastCard.asked]
            .filter(Boolean).some(p => { const pl = String(p).toLowerCase().trim(); return pl.includes(qLowG) || stringSimilarity.compareTwoStrings(pl, qLowG) >= 0.75; });
          if (alreadyAsked && ws._activeAnswer && isSameThread(q, ws._activeAnswer)) { console.log('[Grow] Same question found again — nothing new to add'); return; }
          if (growEnabled && growFresh && ws._activeAnswer && isSameThread(q, ws._activeAnswer)) {
            console.log('[Grow] Continuation detected — extending active answer:', q.substring(0, 80));
            ws._lastCard.heardTs = Date.now(); // Say: this line is part of the card on screen, not a newer question
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
              // The FULL question after its first half already made a card ("…your manager pushes" → "…pushes back on
              // your analysis?"): upgrade that SAME card instead of skipping — prepared answer if the bank has it.
              const last = ws._lastNewCard;
              if (qLow.includes(prev) && qLow.length >= prev.length + 8 && last && last.q.toLowerCase() === prev && Date.now() - last.ts < GROW_WINDOW_MS) {
                recentDetectedQs[ri] = q; last.q = q;
                if (ws._lastCard && ws._lastCard.id === last.id) { ws._lastCard.asked = q; ws._lastCard.heardTs = Date.now(); } // Say stays on it
                upgradeCard(q, last.id).catch(e => console.error('[Upgrade] failed:', e.message));
                return;
              }
              console.log('[AI Auto-Detect] Skipping duplicate of recent:', prev.substring(0, 50));
              return;
            }
          }
          // SAME QUESTION CONTINUED: a second part asked right after the first (≤ 15 s, candidate hasn't spoken since) that
          // follows on from it → merge into the card on screen and answer both parts together; no new card, no jump.
          const lc = ws._lastCard;
          if (lc && Date.now() - lc.ts < 15000 && !((ws._lastUserSpeechTs || 0) > lc.ts) && await isFollowUpOf(q, lc.asked || lc.q)) {
            const combined = `${(lc.asked || lc.q).replace(/\s+$/, '')} ${q}`;
            console.log(`[Follow-up] Same question continued — merging into the card on screen: "${combined.substring(0, 80)}"`);
            lc.asked = combined; lc.ts = Date.now();
            recentDetectedQs.push(q); if (recentDetectedQs.length > 5) recentDetectedQs.shift();
            // GROW, don't rewrite (owner): lines already on screen stay exactly as they are; 1–2 lines covering the added
            // part are appended. If the first answer is still arriving, grow the moment it finishes.
            if (ws._activeAnswer && ws._activeAnswer.id === lc.id) growLiveAnswer(ws, sessionId, ws._activeAnswer, combined).catch(e => console.error('[Grow]', e.message));
            else ws._pendingGrow = { id: lc.id, q: combined };
            return;
          }
          // Genuinely different question — respect the cooldown so we don't refocus onto
          // side-topics and throw junk on screen while the candidate is still answering.
          // Unclear lines (AI route) wait out the cooldown so side remarks don't hijack the screen; a CLEAR interviewer
          // question (fast route) is always answered — back-to-back questions were being dropped (mock interview 26 Sep).
          // HOLD means hold (prod 26 Sep 23:16: "So what companies did you work for?" was 'held' and never came back):
          // wait out the cooldown, then ask it — unless a newer card has appeared since.
          if (inCooldown && via !== 'fast' && via !== 'held') {
            const wait = Math.max(500, AUTO_MATCH_COOLDOWN - (Date.now() - lastAutoMatchTime) + 300);
            const hold = { q, at: Date.now() }; ws._heldQ = hold;
            console.log(`[AI Auto-Detect] Different question during cooldown — holding ${Math.round(wait / 1000)}s: ${q.substring(0, 60)}`);
            setTimeout(() => {
              if (ws._heldQ !== hold) return; // a newer held question replaced it
              ws._heldQ = null;
              if (((ws._lastNewCard || {}).ts || 0) > hold.at || ((ws._lastCard || {}).ts || 0) > hold.at) { console.log('[AI Auto-Detect] Held question superseded by a newer card:', q.substring(0, 50)); return; }
              console.log('[AI Auto-Detect] Releasing held question:', q.substring(0, 60));
              fireDetectedQuestion(q, 'held').catch(e => console.error('[Held]', e.message));
            }, wait);
            return;
          }

          lastAiExtractedQ = q;
          recentDetectedQs.push(q);
          if (recentDetectedQs.length > 5) recentDetectedQs.shift();

          console.log(`[AI Auto-Detect] (${via})`, q.substring(0, 60));
          logEvent('detect', { sessionId, q: q.substring(0, 60) });
          lastWsayMatchId = null;
          recentMatchedIds.clear();
          var qdMsg1 = { type: 'question_detected', text: q, source: 'auto' };
          ws.send(JSON.stringify(qdMsg1));
          broadcastToSession(sessionId, qdMsg1, ws);
          const rebuildIdx = () => { questionIndex = buildQuestionIndex(sessionQuestions); };
          // Bridges refresh ONCE per detected question — it used to re-run after every sentence (either side), resending
          // the resume + whole conversation each time; that was the biggest live cost (owner, 26 Sep: "don't burn my money").
          refreshBridgesSoon(ws);
          fastMatchAndRespond(q, sessionQuestions, sessionId, userId, ws, lastMatchedQId, recentMatchedIds, questionIndex, rebuildIdx, false, false, true).then(newLastId => {
            if (newLastId) { lastMatchedQId = newLastId; lastAutoMatchTime = Date.now(); }
          });
        }

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
          // Off by default (it never actually ran before — the flag was written to a global). Without
          // headphones the mic hears the interviewer, so turning this on can mute detection. USER_SPEECH_GUARD=1 enables.
          const speechGuardOn = process.env.USER_SPEECH_GUARD === '1';
          if (speechGuardOn && userIsSpeaking) {
            console.log('[AI Auto-Detect] Skipping — user is speaking (volume high)');
            return;
          }
          if (speechGuardOn && Date.now() - userStoppedSpeakingAt < USER_SPEECH_GUARD) {
            console.log('[AI Auto-Detect] Skipping — user just stopped speaking (' + Math.round((Date.now() - userStoppedSpeakingAt)/1000) + 's ago)');
            return;
          }

          // CRITICAL: Only use INTERVIEWER utterances for question detection.
          // Filter out [You] (user's own voice) and [Echo] (user voice echoing through system audio).
          // Only what they said lately: after a long answer, the last 4 interviewer lines reach back minutes, and the old
          // question in them was read again and jumped the overlay and the note back to it (live interview 26 Oct, twice).
          const interviewerOnly = interviewerLines();
          const recent = interviewerOnly.filter(t => Date.now() - (t.ts || 0) <= AI_READ_WINDOW_MS).slice(-4);
          if (recent.length < 1) return;

          // PRE-FILTER: Check if the most recent utterance could even be a question.
          // If the last utterance is clearly the candidate speaking (starts with "I", "We", "My", etc.),
          // skip AI extraction entirely — saves tokens and prevents false positives.
          const lastUtterance = recent[recent.length - 1].text;

          // LENGTH GUARD: Very long utterances (50+ words) are almost certainly the candidate
          // giving an extended answer, not the interviewer asking a question.
          // Interviewers often set a question up at length — only skip a long one if no sentence in it is a question.
          const wordCount = lastUtterance.trim().split(/\s+/).length;
          if (wordCount > 50 && !isQuestion(lastUtterance)) {
            console.log('[AI Auto-Detect] Pre-filter: too long (' + wordCount + ' words), likely candidate answer');
            return;
          }
          const lastLow = lastUtterance.trim().toLowerCase();
          // Reject if it opens as candidate self-reference (after "Okay, so…" style lead-ins) — shared rule
          if (CANDIDATE_SPEECH_RE.test(stripLeadFiller(lastLow)) && !INTERVIEWER_ASK_RE.test(lastLow)) {
            console.log('[AI Auto-Detect] Pre-filter: candidate speech, skipping');
            return;
          }

          // COST GATE (owner, 26 Sep: "stop burning my money"): this Haiku check ran after EVERY interviewer pause.
          // Skip it when (a) the fast rules already made a card for this very line, or (b) the last two interviewer lines
          // show no sign of a question at all ("Okay.", "We moved off Excel last quarter."). Never while an answer is
          // fresh on screen — the interviewer adding detail must still grow it. Measured on 1,050 local interviewer lines:
          // ~half skipped, every question in test/question-rules.js still passes.
          const lastLine = recent[recent.length - 1];
          const answerFresh = ws._activeAnswer && ws._lastCard && Date.now() - ws._lastCard.ts < 20000;
          if (!answerFresh) {
            if (ws._lastCard && lastLine.ts && ws._lastCard.ts >= lastLine.ts) { console.log('[AI Auto-Detect] Gate: fast route already answered this line — skipped'); return; }
            const lastTwo = recent.slice(-2).map(t => t.text.replace(/^\[(You|Echo)\]\s*/i, '')).join(' ');
            if (!QUESTION_SIGNAL_RE.test(lastTwo) && !isQuestion(lastTwo)) { console.log('[AI Auto-Detect] Gate: no question signal — skipped'); return; }
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
            fireDetectedQuestion(q, 'ai');
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

        // Echo vs bleed cutoff, measured through Deepgram (25 Sep): your echo → mic first by 122–245 ms; interviewer
        // bleed into mic → call audio first by 83–163 ms. Any mic lead = you. Ties go to "you" (never answer the user).
        const ECHO_MIN_LEAD_MS = 0;
        // Average loudness of each channel over [from, to] (server clock). null if either channel has no audio there.
        function channelLoudness(from, to) {
          const avg = ch => { const xs = ((ws._rms || {})[ch] || []).filter(([t]) => t >= from && t <= to).map(([, r]) => r); return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null; };
          const c1 = avg(1), c2 = avg(2);
          return c1 === null || c2 === null ? null : { c1, c2 };
        }
        function isEchoOfUser(ch1Text, ch1StartWall) {
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
              // Same words on both channels. LOUDNESS first: your own voice is loud on your mic and quiet as an echo in the
              // call audio; the interviewer is loud in the call audio and quiet as bleed into your mic. A clear (1.5×)
              // winner decides. Word timing (±50 ms) misjudged a real question as echo in the mock interview (26 Sep).
              if (ch1StartWall) {
                const loud = channelLoudness(ch1StartWall, ch1StartWall + 1500);
                if (loud && loud.c1 > loud.c2 * 1.5) { console.log(`[Echo Detect] Same words, call audio ${(loud.c1 / loud.c2).toFixed(1)}× louder — interviewer bleed into mic, NOT echo: "${ch1Text.substring(0, 40)}"`); continue; }
                if (loud && loud.c2 > loud.c1 * 1.5) { console.log(`[Echo Detect] Ch1 matched Ch2, mic ${(loud.c2 / loud.c1).toFixed(1)}× louder — your echo: "${ch1Text.substring(0, 40)}"`); return true; }
              }
              // Loudness too close to call → whoever started FIRST said it; ties go to "you" (never answer the user).
              if (ch1StartWall && u.startWall && u.startWall > ch1StartWall - ECHO_MIN_LEAD_MS) {
                console.log(`[Echo Detect] Same words, but call audio started first (${u.startWall - ch1StartWall}ms) — interviewer bleed into mic, NOT echo: "${ch1Text.substring(0,40)}"`);
                continue;
              }
              console.log(`[Echo Detect] Ch1 matched Ch2 (mic led by ${ch1StartWall && u.startWall ? (ch1StartWall - u.startWall) + 'ms' : 'n/a'}) (sim=${sim.toFixed(2)}): "${ch1Text.substring(0,40)}" ≈ "${u.text.substring(0,40)}"`);
              return true;
            }
          }
          // No matching mic words yet (the mic's transcript can arrive AFTER the echo does): loudness alone. If the mic was
          // clearly louder than the call audio during this line, the user was speaking — it's their echo. (A card once
          // joined the user's echoed sentence onto the interviewer's next question — mock interview 26 Sep.)
          if (ch1StartWall) {
            const loud = channelLoudness(ch1StartWall, ch1StartWall + 1500);
            if (loud && loud.c2 > 500 && loud.c2 > loud.c1 * 1.5) {
              console.log(`[Echo Detect] No mic words yet, mic ${(loud.c2 / loud.c1).toFixed(1)}× louder — your echo: "${ch1Text.substring(0, 40)}"`);
              return true;
            }
          }
          return false;
        }
        ws._isEchoOfUser = isEchoOfUser; // lets "What should I say" drop an in-progress line that is the user's echo

        // Deferred Deepgram setup — opened lazily when first audio packet arrives.
        // This prevents Deepgram idle timeout (10s) killing the connection before
        // the user clicks Go Live (which could be minutes after WS connects).
        ws._setupInterviewerDG = function() {
          if (interviewerDG && interviewerDG.readyState <= WebSocket.OPEN) return;
          console.log('[Deepgram] Opening interviewer stream (lazy)');
          ws._audioBuffer1 = []; // init buffer for packets arriving while CONNECTING
          interviewerDG = openDeepgramStream(
            (text, isFinal, speechFinal, meta) => {
              console.log(`[DIAG-DG] Ch1 transcript: "${text.substring(0,60)}" isFinal=${isFinal} speechFinal=${speechFinal}`);
              if (!text.trim()) return;
              ws._ch1HeardTs = Date.now(); // Say: words still arriving = they are mid-question

              // Commit an interviewer utterance: echo-check, push to transcript, schedule detection.
              // `eager` = fired mid-stream on a complete question (short debounce); else = on a pause.
              const commitInterviewer = (fullUtterance, eager, startWall) => {
                const isEcho = isEchoOfUser(fullUtterance, startWall);
                ws.send(JSON.stringify({ type: 'transcript', text: fullUtterance, isFinal: true, isEcho: isEcho }));
                if (!isEcho) broadcastToSession(sessionId, { type: 'interviewer_final', text: fullUtterance }, ws);
                transcript.push({ text: isEcho ? '[Echo] ' + fullUtterance : fullUtterance, ts: Date.now(), isEcho: isEcho });
                if (!isEcho) recordCallEvent(sessionId, ws._callId, 'asker', fullUtterance, {});
                ws._recentTranscript = transcript.slice(-6).map(t => t.text);
                maybeDigestCurrentCall(ws);
                if (!isEcho) {
                  if (aiExtractTimer) { clearTimeout(aiExtractTimer); aiExtractTimer = null; }
                  // FAST ROUTE: the interviewer's own line is already a clear question → answer now (skips the 0.8 s wait +
                  // ~0.6 s AI extraction). Unclear lines take the AI route exactly as before. FAST_DETECT=0 turns it off.
                  // Deepgram cuts at pauses/noise ("…pushes | back on your analysis?", "…Snowflake got slow. | How would you
                  // speed them up?") — if the interviewer's previous line ended < 2.5 s ago and wasn't a finished question,
                  // judge the two together so the question keeps its words and its context.
                  // Join rules (mock interview 26 Sep): after a finished question ("?") never; after a CUT line (no end
                  // punctuation) only a lowercase continuation ("back on your analysis?") — a new capitalized sentence is its
                  // own question; after a finished statement ("…Snowflake got slow.") join within 4 s so the question
                  // keeps its setup.
                  const prevLine = lastInterviewerCommit;
                  const prevT = prevLine ? prevLine.text.trim() : '';
                  const recent = prevLine && Date.now() - prevLine.ts < 4000;
                  const prevCut = !/[?.!]["')\]]?$/.test(prevT);
                  // A line cut mid-sentence + a lowercase continuation is ONE sentence however long the speaker took to
                  // finish it (21 Oct: "…how I wanna | describe the culture." 4.9 s apart became the question "Describe the
                  // culture."), up to 15 s.
                  const lowerCont = prevCut && /^[a-z]/.test(fullUtterance.trim()) && prevLine && Date.now() - prevLine.ts < 15000;
                  const continues = lowerCont || (recent && !/\?["')\]]?$/.test(prevT) && !prevCut);
                  const joined = continues ? prevT + ' ' + fullUtterance : fullUtterance;
                  lastInterviewerCommit = { text: fullUtterance, ts: Date.now() };
                  let fastQ = process.env.FAST_DETECT !== '0' ? questionPartOf(joined) : null;
                  const heldQ = pendingFastQ; // a question held from the previous line, if any
                  const heldSince = pendingSince;
                  if (pendingFastTimer) { clearTimeout(pendingFastTimer); pendingFastTimer = null; pendingFastQ = null; }
                  // The interviewer kept talking after a held question → it is one turn: judge the question with what followed
                  // ("How do you handle conflicting priorities? Right? Just give me an example of how…" = one card, not three).
                  if (heldQ && !continues) fastQ = (process.env.FAST_DETECT !== '0' && questionPartOf(heldQ + ' ' + fullUtterance)) || fastQ || heldQ;
                  else if (heldQ && !fastQ) fastQ = heldQ; // joined text isn't a question — never drop the held one
                  // Answer only once the interviewer has STOPPED: a line committed on a real pause (Deepgram speech_final after
                  // 500 ms of silence) that ends a sentence fires now; a line cut mid-sentence or committed mid-speech (eager)
                  // is held until they stop (armPendingFast / UtteranceEnd).
                  if (fastQ && !eager && /[?.!]["')\]]?\s*$/.test(fullUtterance)) fireDetectedQuestion(fastQ, 'fast');
                  else if (fastQ) { pendingFastQ = fastQ; pendingSince = heldQ ? heldSince : Date.now(); armPendingFast(); }
                  else aiExtractTimer = setTimeout(() => { aiExtractTimer = null; aiAutoExtract(); }, eager ? 300 : AI_EXTRACT_DELAY);
                  setTimeout(() => recentMatchedIds.clear(), 5000);
                }
              };

              if (isFinal) {
                resetIdleTimer();
                interviewerInterim = '';
                if (!interviewerBuffer) { ch1BufStartWall = (meta && meta.startWall) || null; ws._ch1BufStartWall = ch1BufStartWall; }
                interviewerBuffer += (interviewerBuffer ? ' ' : '') + text.trim();
                ws.send(JSON.stringify({ type: 'transcript', text: interviewerBuffer, isFinal: false }));
                if (pendingFastTimer) armPendingFast(); // still talking → keep holding the question
                // EAGER: a complete question is already on the table — don't wait for a pause.
                // Rate-limited so continuous speech commits at most ~once/1.5s; dedup handles repeats.
                if (process.env.EAGER_DETECT !== '0' && looksLikeCompleteQuestion(interviewerBuffer) && Date.now() - lastCommitTs > 1500) {
                  lastCommitTs = Date.now();
                  const fu = interviewerBuffer.trim();
                  interviewerBuffer = '';
                  const st = ch1BufStartWall; ch1BufStartWall = null;
                  commitInterviewer(fu, true, st);
                }
              } else {
                interviewerInterim = text.trim();
                const preview = interviewerBuffer ? interviewerBuffer + ' ' + text.trim() : text.trim();
                ws.send(JSON.stringify({ type: 'transcript', text: preview, isFinal: false }));
                if (pendingFastTimer && text.trim()) armPendingFast(); // still talking → keep holding the cut-off question
              }
              // Still talking → the AI read of "what did they ask" waits too (it used to fire 0.8 s after a pause even when
              // the next words were already arriving).
              if (aiExtractTimer && text.trim()) { clearTimeout(aiExtractTimer); aiExtractTimer = setTimeout(() => { aiExtractTimer = null; aiAutoExtract(); }, AI_EXTRACT_DELAY); }

              // Pause detected — commit whatever's left (the normal path for real interviews).
              if (speechFinal) ws._ch1PauseTs = Date.now();
              if (speechFinal && interviewerBuffer.trim()) {
                lastCommitTs = Date.now();
                const fullUtterance = interviewerBuffer.trim();
                interviewerBuffer = '';
                const st = ch1BufStartWall; ch1BufStartWall = null;
                commitInterviewer(fullUtterance, false, st);
              } else if (speechFinal) firePendingNow('Interviewer paused'); // an eager commit took every word — the pause ends it
            },
            (err) => {
              console.error('[Deepgram Error]', err.message);
              interviewerDG = null; // Allow re-open on next audio packet
              ws.send(JSON.stringify({ type: 'error', message: 'Transcription error: ' + err.message }));
            },
            { endpointing: Number(process.env.DG_ENDPOINTING_MS || 500), onUtteranceEnd: () => firePendingNow('Interviewer stopped (UtteranceEnd)') }
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
          let userBufStartWall = null; // server time the current mic utterance started (shared clock)
          ws._setupUserDG = function() {
            if (userDG && userDG.readyState <= WebSocket.OPEN) return;
            console.log('[Deepgram] Opening user mic stream (lazy)');
            ws._audioBuffer2 = []; // init buffer for packets arriving while CONNECTING
            userDG = openDeepgramStream(
              (text, isFinal, speechFinal, meta) => {
                if (!text.trim()) return;
                if (isFinal) {
                  if (!userBuffer) userBufStartWall = (meta && meta.startWall) || null;
                  userBuffer += (userBuffer ? ' ' : '') + text.trim();
                }
                if (speechFinal && userBuffer.trim()) {
                  const fullUtterance = userBuffer.trim();
                  userBuffer = '';
                  resetIdleTimer();
                  // Only REAL candidate speech ends the follow-up window — not the interviewer leaking into the mic. Loudness
                  // decides (bleed is quieter on the mic than in the call audio); text similarity as a backup.
                  const uLoud = userBufStartWall ? channelLoudness(userBufStartWall, userBufStartWall + 1500) : null;
                  const isBleed = (uLoud && uLoud.c1 > uLoud.c2 * 1.2) || transcript.some(t => !t.isUser && !t.isEcho && Date.now() - (t.ts || 0) < 10000 &&
                    stringSimilarity.compareTwoStrings(fullUtterance.toLowerCase(), (t.text || '').toLowerCase()) > 0.6);
                  // Owner 25 Oct: a mock video on his speakers greyed his answer lines (the mic heard the video). Bleed is judged
                  // BEFORE it goes out, and marked, so the note and the coach never take it as his words.
                  ws.send(JSON.stringify({ type: 'user_transcript', text: fullUtterance, isFinal: true, bleed: !!isBleed }));
                  broadcastToSession(sessionId, { type: 'user_transcript', text: fullUtterance, isFinal: true, bleed: !!isBleed }, ws);
                  transcript.push({ text: '[You] ' + fullUtterance, ts: Date.now(), isUser: true });
                  ws._recentTranscript = transcript.slice(-6).map(t => t.text);
                  maybeDigestCurrentCall(ws);

                  // Store for echo detection — Ch1 transcripts will be compared against these
                  recentUserUtterances.push({ text: fullUtterance, ts: Date.now(), startWall: userBufStartWall });
                  if (!isBleed) recordCallEvent(sessionId, ws._callId, 'you', fullUtterance, {});
                  if (!isBleed) ws._lastUserSpeechTs = Date.now();
                  userBufStartWall = null;
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
          }).catch(e => {
            console.error('[ManualMatch] failed:', e.message);
            try { ws.send(JSON.stringify({ type: 'error', message: 'Could not get an answer — try again' })); } catch (_) {}
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
        if (msg.followUps !== undefined) { // Follow-Up Predictions setting: off = don't write them at all (they cost a call per answer)
          const on = !!msg.followUps;
          const clients = sessionClients.get(sessionId);
          if (clients) clients.forEach(c => { c._followUpsOn = on; });
          ws._followUpsOn = on;
        }
        if (msg.copilot !== undefined || msg.copilotHistory !== undefined) { // meeting co-pilot mode + its History checkbox (all clients in the session)
          const clients = sessionClients.get(sessionId) || new Set();
          const apply = c => { if (msg.copilot !== undefined) c._copilotMode = !!msg.copilot; if (msg.copilotHistory !== undefined) c._copilotHistory = !!msg.copilotHistory; };
          clients.forEach(apply); apply(ws);
          console.log(`[Co-pilot] settings: mode=${ws._copilotMode ? 'on' : 'off'} history=${ws._copilotHistory ? 'on' : 'off'} for session ${sessionId}`);
        }
      }

      else if (msg.type === 'overlay_diag') { // overlay responsiveness while live (13 Oct drag investigation)
        console.log('[Overlay] diag:', JSON.stringify(msg.stats || {}).slice(0, 400));
      }
      else if (msg.type === 'copilot_watch') { // overlay watcher health (its console is out of reach)
        console.log('[Co-pilot] watch:', JSON.stringify(msg.stats || {}).slice(0, 400));
      }

      else if (msg.type === 'expand_proof') {
        // Owner clicked the "↳ At <Employer>" line on a card — write the full story behind it (one call, on demand)
        const proofLine = String(msg.proofLine || '').slice(0, 600), questionId = msg.questionId;
        if (proofLine.length < 10) return;
        expandProofLine(ws, sessionId, { questionText: String(msg.questionText || '').slice(0, 600), answer: String(msg.answer || '').slice(0, 2500), proofLine })
          .then(text => { console.log('[Proof] Expanded for', questionId); try { ws.send(JSON.stringify({ type: 'proof_detail', questionId, proofLine, text })); } catch (e) {} })
          .catch(e => { console.error('[Proof]', e.message); try { ws.send(JSON.stringify({ type: 'proof_detail', questionId, proofLine, error: true })); } catch (_) {} });
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
        fastMatchAndRespond(text, sessionQuestions, sessionId, userId, ws, null, recentMatchedIds, questionIndex, rebuildIdx, true, true, { typed: true }).then(newLastId => { // typed = his own order (owner, 4 Oct)
          if (newLastId) lastMatchedQId = newLastId;
        }).catch(e => {
          console.error('[Canvas] Manual question failed:', e.message);
          try { ws.send(JSON.stringify({ type: 'error', message: 'Could not get an answer — try again' })); } catch (_) {}
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
        // Interviewer speech only — the user's own words must never come back as "the question".
        // The words still being spoken count (23 Oct test: pressed mid-question, "Can you walk me through how you would build
        // a dashboard that" was not final yet → Say saw nothing new and showed the OLD card).
        let currentBuf = (interviewerBuffer + ' ' + interviewerInterim).trim();
        if (currentBuf && ws._isEchoOfUser && ws._isEchoOfUser(currentBuf, ws._ch1BufStartWall)) {
          console.log('[WhatShouldISay] Ignoring in-progress line — it is the user\'s echo');
          currentBuf = '';
        }
        const recentLines = interviewerLines().slice(-10); // last 10 for deep context

        // INSTANT (owner, 26 Sep: "when I press it, I heard a question, answer it immediately"): if the interviewer's latest
        // question already has an answer on screen — and they haven't asked a newer one since — jump to it NOW: no AI call,
        // nothing rewritten. The check below still re-reads the conversation in case the question on screen is wrong.
        const lc = ws._lastCard;
        // PANIC BUTTON (owner): pressing it means there IS something to answer, even if it isn't shaped like a question.
        // Anything substantive the interviewer said since the card ("Your thoughts on dbt.") is what gets answered —
        // only acknowledgements ("okay", "great", "take your time") leave the card on screen as the answer.
        const substantive = txt => { const t = String(txt || '').trim().toLowerCase(); if (!t) return false;
          if (/^(okay|ok|great|good|sure|right|thanks|thank you|makes sense|got it|perfect|awesome|cool|nice|alright|all right|mm+|hmm+|yeah|yes|no rush|take your time)\b[\s,.!]*((take your time|no rush)[\s,.!]*)?$/.test(t)) return false;
          return t.split(/\s+/).length >= 3 && !isLowValueQuestion(t); };
        // MEETING CO-PILOT MODE (owner, 3 Oct): Say = "answer what they just asked me, right now" through the co-pilot door —
        // with the pages, the call log, résumé + bank. Never the QA jump / bank-match below (that ignores the screen).
        if (ws._copilotMode) {
          const since = ws._copilotAskTs || 0;
          let fresh = interviewerLines().filter(t => (t.ts || 0) > since && substantive(t.text)).slice(-3).map(t => t.text.trim());
          if (substantive(currentBuf) && !fresh.includes(currentBuf)) fresh.push(currentBuf);
          if (!fresh.length) fresh = recentLines.filter(t => substantive(t.text)).slice(-2).map(t => t.text.trim()); // nothing new since the last ask: they may be re-asking — take the last thing said
          // Their LAST question + what they said after it (owner, 26 Oct: "always say using last question"); the old pick
          // (lines since the last ask) only when no question was asked in the last few minutes
          const lastQ = meetingCopilot.sayText(interviewerLines().concat(substantive(currentBuf) ? [{ text: currentBuf, ts: Date.now() }] : []), Date.now());
          const text = lastQ || fresh.join(' ').slice(0, 1200);
          ws._copilotAskTs = Date.now();
          console.log('[Co-pilot] Say pressed — ' + (text ? 'they just asked: "' + text.slice(0, 80) + '"' : 'nothing caught, answering the latest thing said'));
          ws.send(JSON.stringify({ type: 'copilot_say', text }));
          return;
        }
        // heardTs: the card was grown/upgraded with later lines — those are this card's question, not a newer one.
        // Pressed while they are still asking: the question they finish is THIS press's card (fireDetectedQuestion), not a new one.
        // (23 Oct test: pressed the instant a phrase went final → nothing "in progress" → the press wasn't treated as mid-question)
        // A question they just finished that the automatic side is still holding is this press's too (else: two cards).
        const stillTalking = substantive(currentBuf) || (Date.now() - (ws._ch1HeardTs || 0) < 1500 && !((ws._ch1PauseTs || 0) >= (ws._ch1HeardTs || 0)))
          || !!(ws._questionPending && ws._questionPending());
        ws._sayTurn = stillTalking ? { at: Date.now(), done: false, fullQ: null, used: false } : null;
        const newerQuestion = !lc || interviewerLines().some(t => (t.ts || 0) > (lc.heardTs || lc.ts) && substantive(t.text)) || substantive(currentBuf);
        // The jump ALWAYS happens first (owner: "don't remove the jump — it may be answered already, or the AI is still
        // writing it and I just need something to start talking"). If the interviewer asked something newer, the re-read
        // below answers that too and moves the screen to it.
        // …but only when that card IS their latest question (owner, 21 Oct: every press showed the old card first while
        // they had already asked something new — "stale"). Something new since the card → answer the new thing directly.
        let jumpedTo = null;
        if (lc && !newerQuestion) { // no age limit (22 Oct): after a long answer (> 90 s) the press rewrote the card — nothing new since = it is still their latest question
          const onScreen = (ws._activeAnswer && ws._activeAnswer.id === lc.id) ? ws._activeAnswer.answer : ((sessionQuestions.find(x => x.id === lc.id) || {}).answer || '');
          const focusMsg = { type: 'match', questionId: lc.id, questionText: lc.isBank ? lc.q : (lc.asked || lc.q), answer: onScreen || '', similarity: 100, hasAnswer: !!onScreen, navigate: true };
          ws.send(JSON.stringify(focusMsg)); broadcastToSession(sessionId, focusMsg, ws);
          jumpedTo = lc;
          console.log(`[WhatShouldISay] Jumped instantly to the newest answer card (no AI call)${newerQuestion ? ' — interviewer said more since; re-reading' : ''}`);
        }

        // Build transcript with recency markers — newest at bottom, labeled. With a card on screen, MOST RECENT = everything
        // the interviewer said AFTER that card (that is what's being asked now); the card's own question is older context.
        let rawTranscript = '';
        const sinceCard = lc ? recentLines.filter(t => (t.ts || 0) > lc.ts) : [];
        if (lc && sinceCard.length) {
          const before = recentLines.filter(t => (t.ts || 0) <= lc.ts).slice(-4);
          if (before.length) rawTranscript = 'OLDER CONTEXT (already answered on screen):\n' + before.map(t => t.text).join('\n') + '\n\n';
          rawTranscript += 'MOST RECENT:\n' + sinceCard.slice(-6).map(t => t.text).join('\n');
        } else if (recentLines.length > 3) {
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
        const extractSystem = 'The candidate just pressed a PANIC button in a live interview: there IS something they must respond to right now. From the interviewer\'s speech below (newest at the bottom), find the MOST RECENT thing the interviewer wants the candidate to respond to — a direct question, a request ("tell me more", "walk me through that"), a statement that invites a reply ("so you\'ve used Snowflake", "your thoughts on dbt"), or a problem they described ("we struggle with data quality") — and write it as ONE clear question for the candidate to answer. Combine a question with its immediate follow-up. Output ONLY that question. Never output NONE unless the interviewer said nothing at all. KEEP THE INTERVIEWER\'S OWN WORDS: "you/your" always means the candidate who pressed the button. Never add a company, school, employer, product, place or person\'s name the interviewer did not say IN THAT QUESTION — other voices in the audio (another candidate, a presenter, a recording) often run straight into the question and must never leak into it (e.g. "…I worked at Calvert College. And when you talk about your role, what projects…" → "When you talk about your role, what projects are you working on…", never "…at Calvert College").\n\nOLD GUIDANCE (still applies): You extract the LAST interview question from conversation transcripts. The transcript has recency markers. Search from bottom to top — find the most recent question the interviewer asked, even if it was a few lines back. Questions can be direct ("What is X?") or imperative ("Tell me about X", "Describe your experience with X", "Walk me through X"). Ignore the candidate\'s answers, small talk, and filler.\n\nIMPORTANT — MULTI-PART QUESTIONS: Interviewers often ask a main question then add a follow-up like "how would you approach this?" or "walk me through your process" or "what would you do differently?". These are ONE question, not two. Combine the main question and its follow-up into a single complete question. Example: "What is the difference between inner join and left join? How would you approach this problem?" → return the full combined question.\n\nOutput ONLY the clean question text — no quotes, no explanation. If there is truly no question anywhere in the transcript, output NONE.\n\nNEWEST FIRST: when MOST RECENT or RIGHT NOW holds a request, that is the question — even if OLDER CONTEXT holds a clearer one (that one is already answered). If the newest question is still unfinished (cut off mid-sentence), write it as the question it is clearly heading toward. Never write about the transcript or explain — a question or NONE only.';
        const extractUser = ctxLine + rawTranscript + '\n\nPANIC PRESS — output the one question the candidate must answer now (never NONE if the interviewer spoke). Find the LAST question the interviewer asked (combine multi-part questions into one). Search from the most recent speech backwards. Output the question only.';

        let questionText;
        try {
          questionText = await Promise.race([
            callClaude(extractSystem, extractUser, 100, MODEL_HAIKU),
            new Promise((_, reject) => setTimeout(() => reject(new Error('extract_timeout')), 2000))
          ]);
          questionText = cleanQuestionText(questionText.trim().replace(/^["']|["']$/g, ''));
          console.log('[WhatShouldISay] Haiku extracted:', questionText);
          // The extractor sometimes explains itself instead of giving a question (21 Oct: "I understand you want me to find
          // the most recent question, but…" was answered as the question). That is never the question.
          if (/^(i understand|i (can't|cannot|don't|do not)|based on|it (appears|seems|looks like)|the (most recent|transcript|interviewer'?s? (speech|words))|there (is|are|was|were) no|sorry|unfortunately|note:|however)\b/i.test(questionText)
            || /MOST RECENT|OLDER CONTEXT|RIGHT NOW|cut off mid|incomplete/i.test(questionText) || questionText.length > 400) {
            console.log('[WhatShouldISay] Extraction was not a question — using the interviewer\'s latest words');
            questionText = '';
          }
        } catch (e) {
          // Fallback: use most recent lines
          console.log('[WhatShouldISay] Extraction failed, using raw transcript');
          // Fallback must also be INTERVIEWER-only — transcript.slice(-2) put "[You]…[Echo]…" on a card under load (26 Sep).
          questionText = currentBuf || interviewerLines().slice(-2).map(t => t.text).join(' ');
        }

        // PANIC: a NONE / empty extraction still answers — the interviewer's latest words ARE what to respond to.
        if (!questionText || questionText.length < 5 || /^\s*NONE\b/i.test(questionText)) {
          const latest = (sinceCard.length ? sinceCard.slice(-3) : interviewerLines().slice(-2)).map(t => t.text);
          if (currentBuf) latest.push(currentBuf);
          questionText = latest.join(' ').trim();
          console.log('[WhatShouldISay] Nothing question-shaped found — answering the interviewer\'s latest words:', (questionText || '').substring(0, 60));
        }
        if (!questionText || questionText.length < 5) {
          ws.send(JSON.stringify({ type: 'error', message: 'Could not identify a question from the conversation' }));
          return;
        }

        const sayTurn = ws._sayTurn;
        if (sayTurn && sayTurn.fullQ) { console.log('[WhatShouldISay] They finished the question while it was read — answering the whole of it:', sayTurn.fullQ.substring(0, 60)); questionText = sayTurn.fullQ; sayTurn.fullQ = null; }
        // Same as the card already on screen (jumped to or not)? Show THAT card — never rewrite it.
        if (!jumpedTo && lc) {
          const a0 = questionText.toLowerCase();
          if ([lc.asked, lc.q].filter(Boolean).some(b => { b = b.toLowerCase(); return b.includes(a0) || a0.includes(b) || stringSimilarity.compareTwoStrings(a0, b) >= 0.6; })) {
            const onScreen = (ws._activeAnswer && ws._activeAnswer.id === lc.id) ? ws._activeAnswer.answer : ((sessionQuestions.find(x => x.id === lc.id) || {}).answer || '');
            const focusMsg = { type: 'match', questionId: lc.id, questionText: lc.isBank ? lc.q : (lc.asked || lc.q), answer: onScreen || '', similarity: 100, hasAnswer: !!onScreen, navigate: true };
            ws.send(JSON.stringify(focusMsg)); broadcastToSession(sessionId, focusMsg, ws);
            console.log('[WhatShouldISay] The question is the one already on screen — showing it; nothing rewritten');
            return;
          }
        }

        if (jumpedTo) {
          // Same question as the card we jumped to (or a follow-up of it)? Then the answer on screen is the one — stop,
          // never rewrite it. A DIFFERENT question gets its own answer below.
          const a = questionText.toLowerCase(), cands = [jumpedTo.asked, jumpedTo.q].filter(Boolean).map(x => x.toLowerCase());
          const same = cands.some(b => b.includes(a) || a.includes(b) || stringSimilarity.compareTwoStrings(a, b) >= 0.6) || await isFollowUpOf(questionText, jumpedTo.asked || jumpedTo.q);
          if (same) { console.log('[WhatShouldISay] Confirmed — the answer on screen is for this question; nothing rewritten'); return; }
          console.log('[WhatShouldISay] The question you heard differs from the one on screen — answering it:', questionText.substring(0, 60));
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
          if (sayTurn && ws._sayTurn === sayTurn) {
            sayTurn.done = true;
            if (sayTurn.fullQ) { const fq = sayTurn.fullQ; sayTurn.fullQ = null; if (ws._growSayCard) ws._growSayCard(fq); } // finished while the card was being made
          }
          lastWsayMatchId = newLastId || null;
          if (newLastId) lastMatchedQId = newLastId;
          console.log('[WhatShouldISay] done:', newLastId ? 'matched bank question' : 'new/updated live question');
        }).catch(e => {
          console.error('[WhatShouldISay] failed:', e.message);
          try { ws.send(JSON.stringify({ type: 'error', message: 'Could not get an answer — try again' })); } catch (_) {}
        });
      }

      else if (msg.type === 'switch_tab') {
        // User picked a different tab — close the interviewer stream; the next Ch1 packet re-opens it through
        // ws._setupInterviewerDG, the ONE interviewer handler (echo check, fast/eager detection). This path used to open its
        // own copy without the echo check, so the user's own voice from the new tab could be answered.
        console.log('[Live] Switching tab — resetting interviewer Deepgram stream');
        if (interviewerDG) {
          try { if (interviewerDG.readyState === WebSocket.OPEN) interviewerDG.send(JSON.stringify({ type: 'CloseStream' })); interviewerDG.close(); } catch(e) {}
        }
        interviewerDG = null;
        interviewerBuffer = '';
        interviewerInterim = '';
        ws.send(JSON.stringify({ type: 'status', message: 'Tab switched — listening on new tab' }));
      }

      else if (msg.type === 'followup_questions') {
        // Questions the candidate can ask the interviewers — built only from what THEY said (generateQuestionsToAsk)
        if (!hasConversation(ws) && !(ws._sessionContext || {}).jd) {
          ws.send(JSON.stringify({ type: 'error', message: 'Nothing said yet' }));
          return;
        }
        generateQuestionsToAsk(ws).then(result => {
          const followUpMsg = { type: 'followup_questions_result', questions: result, questionCount: 0 };
          ws.send(JSON.stringify(followUpMsg));
          broadcastToSession(sessionId, followUpMsg, ws);
        }).catch(e => {
          console.error('[Follow-up questions error]', e.message);
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to generate follow-up questions' }));
        });
      }

      else if (msg.type === 'stop') {
        clearTimeout(idleTimer);
        if (ws._callId) pool.query('UPDATE call_screens SET image = NULL WHERE call_id = $1', [ws._callId]).catch(e => console.error('[Co-pilot] image cleanup failed:', e.message)); // frames are for the call only; transcripts stay
        if (ws._isAssessment && ws._callId) finishAssessmentCall(sessionId, ws._callId); // background: carry + title lock
        ws._callId = null; // call over — the call log stops here; co-pilot refuses until the next Go Live
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
          // Auto-learning after every call is OFF (owner, 26 Sep: "don't keep learning" — it answered every learned question
          // on Sonnet after each call). LEARN_AFTER_CALL=1 turns it back on; the manual Learn button still works.
          if (process.env.LEARN_AFTER_CALL === '1') processTranscriptAfterInterview(_sid, _uid, _tid).then(sum => {
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
    if (ws._callId) pool.query('UPDATE call_screens SET image = NULL WHERE call_id = $1', [ws._callId]).catch(e => console.error('[Co-pilot] image cleanup failed:', e.message));
    if (ws._isAssessment && ws._callId) finishAssessmentCall(sessionId, ws._callId); // app closed mid-assessment: still carried
    ws._callId = null;
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
// A stored live transcript as an array of lines. Postgres returns the JSONB column already parsed (an array);
// JSON.parse on that array throws → callers saw 0 lines → finished calls were deleted as "empty". ONE reader for all.
function transcriptLines(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') { try { const v = JSON.parse(value || '[]'); return Array.isArray(v) ? v : []; } catch (e) { return []; } }
  return [];
}

// ===== SESSION MEMORY (one place — every live answer path reads buildConversationContext) =====
// Owner's rule: answers must use everything said in this interview session — the candidate's own claims and the
// interviewer's explanations, this call AND earlier calls — so they stay consistent with what the candidate said and
// aligned to how the company works, while the proof stays in the candidate's own experience and domain.
const MEMORY_RAW_CHARS = 6000;   // newest part of this call, passed word-for-word
const MEMORY_DIGEST_KEEP = 3000; // when digesting, keep this much of the newest text raw

// Transcript entries → "Interviewer: …" / "Candidate: …". Drops [Echo] (Ch1 copy of the candidate — the [You] line is
// kept) and drops mic lines that are the INTERVIEWER leaking into the mic (same words on Ch1 within 10 s), so the
// interviewer's words can never be remembered as the candidate's claims.
function labelTranscript(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i];
    if (!t || !t.text || t.isEcho) continue;
    const text = t.text.replace(/^\[(You|Echo)\]\s*/i, '').trim();
    if (!text) continue;
    if (t.isUser) {
      const bleed = lines.some(o => o && !o.isUser && !o.isEcho && Math.abs((o.ts || 0) - (t.ts || 0)) < 10000 &&
        stringSimilarity.compareTwoStrings(text.toLowerCase(), (o.text || '').toLowerCase()) > 0.6);
      if (bleed) continue;
      out.push('Candidate: ' + text);
    } else out.push('Interviewer: ' + text);
  }
  return out;
}

const MEMORY_DIGEST_SYSTEM = `You keep interview notes for a candidate's live copilot. From the conversation, write compact notes in exactly these sections (short bullets, facts only, no advice):
CANDIDATE SAID — every claim the candidate made about themselves: skills, tools, years, level ("I do X daily", "I'm strong in Y"), numbers, stories/examples already told.
INTERVIEWERS — one line per person (name/title as they introduced themselves), then what THEY said:
  • VALUES / WANTS in a candidate (e.g. "wants someone who investigates before escalating")
  • CONCERNS / PAIN POINTS / how their environment really is (e.g. "data is messy, hard to find things")
  • COMPANY FACTS: stack, use cases, team, priorities, what they said in their introduction
COVERED — questions already asked, each with the gist of the candidate's answer.
Never attribute an interviewer's statement to the candidate. Keep names, numbers and tools exactly. Max 300 words.`;

async function digestConversation(labeledText, previousNotes) {
  const user = (previousNotes ? `EXISTING NOTES (merge into them, keep everything still true):\n${previousNotes}\n\n` : '') + `CONVERSATION:\n${labeledText}\n\nNotes:`;
  return (await callClaude(MEMORY_DIGEST_SYSTEM, user, 450, MODEL_HAIKU)).trim();
}

// Notes for every EARLIER call in this session (cached per call in live_transcripts.memory).
async function loadPriorCallsMemory(sessionId, userId, currentTranscriptId) {
  const r = await pool.query(
    `SELECT id, transcript, memory, interviewer_name, interviewer_title, stage, started_at FROM live_transcripts
     WHERE session_id = $1 AND user_id = $2 AND id != $3 AND transcript IS NOT NULL ORDER BY started_at ASC`,
    [sessionId, userId, currentTranscriptId || '00000000-0000-0000-0000-000000000000']);
  const parts = [];
  for (const row of r.rows.slice(-5)) { // last 5 calls is plenty; keeps the prompt small
    let notes = row.memory;
    if (!notes) {
      const lines = transcriptLines(row.transcript);
      const labeled = labelTranscript(lines).join('\n');
      if (labeled.replace(/\s+/g, '').length < 40) continue;
      try {
        notes = await digestConversation(labeled.slice(-24000));
        pool.query('UPDATE live_transcripts SET memory = $1 WHERE id = $2', [notes, row.id]).catch(e => console.error('[Memory] save failed:', e.message));
      } catch (e) { console.error('[Memory] digest of earlier call failed:', e.message); continue; }
    }
    const who = [row.interviewer_name, row.interviewer_title, row.stage].filter(Boolean).join(', ');
    parts.push(`EARLIER CALL (${new Date(row.started_at).toISOString().slice(0, 10)}${who ? ' — ' + who : ''}):\n${notes}`);
  }
  return parts.join('\n\n');
}

// Keep this call's older part as notes so long calls fit; the newest MEMORY_RAW_CHARS stay word-for-word.
function maybeDigestCurrentCall(ws) {
  if (ws._digesting || !ws._getTranscript) return;
  const labeled = labelTranscript(ws._getTranscript());
  const from = ws._digestedLines || 0;
  const pending = labeled.slice(from);
  if (pending.join('\n').length <= MEMORY_RAW_CHARS) return;
  // digest everything except the newest ~MEMORY_DIGEST_KEEP chars
  let keep = 0, chars = 0;
  while (keep < pending.length && chars + pending[pending.length - 1 - keep].length < MEMORY_DIGEST_KEEP) { chars += pending[pending.length - 1 - keep].length + 1; keep++; }
  const toDigest = pending.slice(0, pending.length - keep);
  if (!toDigest.length) return;
  ws._digesting = true;
  digestConversation(toDigest.join('\n'), ws._callNotes || '').then(notes => {
    ws._callNotes = notes; ws._digestedLines = from + toDigest.length;
    console.log(`[Memory] Digested ${toDigest.length} lines of this call (${notes.length} chars of notes)`);
  }).catch(e => console.error('[Memory] digest failed:', e.message)).finally(() => { ws._digesting = false; });
}

// BRIDGES — computed in the background as the conversation happens (never on the answer's clock): each thing an
// interviewer cares about (value, concern, environment, use case) mapped to the candidate's OWN matching example.
// A short explicit map is followed far more reliably by the fast answer model than long notes.
const BRIDGES_SYSTEM = `You prepare a job candidate for the rest of their interview. From what was said so far and their resume, write BRIDGES: for each thing an interviewer cares about — a value or trait they want, a concern or pain point, how their environment really is, a use case or problem — pair it with the candidate's OWN real example that proves it.
Format, one per line (max 6 lines, most important first):
THEY: <what they care about, paraphrased> → PROOF: <a specific real example from the candidate's resume or earlier answers — employer, project, number/result> → SAY IT AS: <one plain sentence in the candidate's own everyday words, with no words borrowed from the interviewer>
Then one line: CLAIMS: <the candidate's own stated claims to stay consistent with (tools, years, level)>.
Then one line: AVOID: <the interviewers' distinctive phrases for what they VALUE or how they describe things, comma-separated, e.g. "dig in", "messy", "ownership" — NOT concrete nouns like their tables, tools or team, which are fine to name>.
Rules: proof comes ONLY from the candidate's resume or their own earlier answers; never invent employers, titles, dates, years, degrees or numbers; never say the candidate did the company's own use case. If nothing has been said about what they care about yet, output NONE.`;

// BRIDGES budget (owner, 26 Sep): about 10–15 runs per hour of interview, each one building on the last.
// Runs at most once per BRIDGES_MIN_GAP_MS; a question inside the gap queues ONE run for when the gap is up.
const BRIDGES_MIN_GAP_MS = parseInt(process.env.BRIDGES_GAP_MS, 10) || 4 * 60 * 1000; // → at most 15 per hour (env only for tests)
const BRIDGES_UPDATE_SYSTEM = BRIDGES_SYSTEM + `

UPDATE MODE: you are given the CURRENT BRIDGES and only what was said SINCE they were written. Return the full updated list in the same format: keep every line that is still true, sharpen lines the new talk adds to, add new ones, drop only what the new talk contradicts. If nothing new matters, return the current list unchanged.`;
function refreshBridgesSoon(ws) {
  if (!ws || ws._isCanvas) return;
  const wait = Math.max(1200, (ws._bridgesAt || 0) + BRIDGES_MIN_GAP_MS - Date.now());
  if (ws._bridgeTimer && wait > 1200) return; // one run already queued for when the gap is up
  clearTimeout(ws._bridgeTimer);
  ws._bridgeTimer = setTimeout(() => { ws._bridgeTimer = null; refreshBridges(ws); }, wait);
}
async function refreshBridges(ws) {
  if (ws.readyState !== WebSocket.OPEN) return; // call ended — nothing to prepare
  if (ws._bridgesBusy) { ws._bridgesAgain = true; return; }
  const session = ws._sessionContext || {};
  const labeled = ws._getTranscript ? labelTranscript(ws._getTranscript()) : [];
  if (!ws._priorMemory && !ws._callNotes && labeled.filter(l => l.startsWith('Interviewer:')).length === 0) return;
  // Only what was said since the last run — nothing new from the interviewer → no call at all
  const fresh = labeled.slice(Math.min(ws._bridgesSeen || 0, labeled.length));
  if (ws._bridges && !fresh.some(l => l.startsWith('Interviewer:'))) return;
  ws._bridgesBusy = true;
  const t0 = Date.now();
  try {
    let system, user, mode;
    if (ws._bridges) { // build on the last run: current list + only the new talk
      mode = 'update';
      let newTalk = fresh.join('\n');
      if (newTalk.length > MEMORY_RAW_CHARS) newTalk = newTalk.slice(-MEMORY_RAW_CHARS).replace(/^[^\n]*\n/, '');
      system = BRIDGES_UPDATE_SYSTEM;
      user = `RESUME:\n${session.resume || 'N/A'}\n\nCURRENT BRIDGES:\n${ws._bridges}\n\nSAID SINCE THEN (newest last):\n${newTalk}\n\nUPDATED BRIDGES:`;
    } else { // first run of this call: earlier calls' notes + this call so far
      mode = 'first';
      system = BRIDGES_SYSTEM;
      user = `RESUME:\n${session.resume || 'N/A'}\n\n${buildConversationContext(ws, { noBridges: true })}\n\nBRIDGES:`;
    }
    const out = (await callClaude(system, user, 500, MODEL_HAIKU)).trim();
    if (!/^NONE\b/i.test(out)) ws._bridges = out;
    ws._bridgesSeen = labeled.length; ws._bridgesAt = Date.now();
    ws._bridgesRuns = (ws._bridgesRuns || 0) + 1;
    console.log(`[Memory] Bridges ${mode} #${ws._bridgesRuns} in ${Date.now() - t0}ms (${ws._bridges ? ws._bridges.split('\n').length + ' lines' : 'none yet'}, ${user.length} chars in)`);
  } catch (e) { console.error('[Memory] bridges failed:', e.message); }
  finally {
    ws._bridgesBusy = false;
    if (ws._bridgesAgain) { ws._bridgesAgain = false; refreshBridgesSoon(ws); }
  }
}

function buildConversationContext(ws, opts = {}) {
  const parts = [];
  if (ws._priorMemory) parts.push(`FROM EARLIER CALLS IN THIS INTERVIEW PROCESS:\n${ws._priorMemory}`);
  if (ws._callNotes) parts.push(`EARLIER IN THIS CALL (notes):\n${ws._callNotes}`);
  const labeled = ws._getTranscript ? labelTranscript(ws._getTranscript()).slice(ws._digestedLines || 0) : [];
  let raw = labeled.join('\n');
  if (raw.length > MEMORY_RAW_CHARS) raw = raw.slice(-MEMORY_RAW_CHARS).replace(/^[^\n]*\n/, '');
  if (raw) parts.push(`THIS CALL SO FAR (word for word, newest last):\n${raw}`);
  if (!opts.noBridges && ws._bridges) parts.push(`BRIDGES — what they care about → the candidate's own proof (use the one that fits this question):\n${ws._bridges}`);
  return parts.join('\n\n');
}

// Has anything been said in this interview process yet (earlier calls, or the interviewer in this call)?
function hasConversation(ws) {
  if (ws._priorMemory || ws._callNotes) return true;
  const t = ws._getTranscript ? ws._getTranscript() : [];
  return t.filter(x => x && !x.isUser && !x.isEcho).length > 1;
}

// ===== QUESTIONS TO ASK THEM (the "?" button, used at the end of a call) =====
// Owner (26 Sep): it built questions from HIS OWN statements (it read only the last 6 lines — at the end of a call
// that is him talking) and they sounded fake. Now it reads ONLY the interviewer side — every interviewer line of this
// call plus the interviewer part of earlier calls' notes — and never the candidate's statements or the AI answers.
const ASK_THEM_SYSTEM = `You suggest the questions a job candidate asks the interviewer at the END of an interview.
They must sound like a real person talking — the kind of question a sharp, curious candidate would actually say out loud.

WHERE QUESTIONS COME FROM (in this order):
1. What the INTERVIEWERS said — their team, projects, systems, data, problems, changes, priorities, how they work, what they want from this hire. Pick the things that matter most for doing THIS role well.
2. Only if the interviewers said little: what the job description says the role will own.
Never build a question from anything the candidate said about themselves (you are not given it — do not invent it).
Cover the WHOLE interview process: when an earlier call raised a problem, change or priority, at least one question follows it up with this interviewer (a real candidate remembers what the last person said, e.g. asking whether that issue touches this team).

EACH QUESTION:
- Asks about THEIR world: how something works, what's changing, what's hard, what success looks like, who the person works with, what comes first.
- Is plain spoken English, 8–22 words, one sentence. Contractions are fine. Name their concrete things plainly (their tool, team, project, metric).
- Never repeat something the interviewers already answered, and never repeat a question the candidate already asked.

NEVER:
- "You mentioned…", "You said…", "Earlier you talked about…", "I noticed…", "Given that…", "As someone who…" openers.
- Praise or flattery ("That sounds exciting", "I love that…"), buzzwords (synergy, leverage, culture of excellence, dynamic, fast-paced), or two questions glued with "and".
- Generic filler ("What does a typical day look like?", "What do you like about working here?", "What are the next steps?") unless nothing else was said.
- Salary, benefits, time off, remote policy.

OUTPUT: exactly 4 questions, numbered 1–4, most useful first. Nothing else — no intro, no tips, no explanations.`;

// The interviewer part of digested call notes: drop CANDIDATE SAID and COVERED (candidate answers).
function interviewerSideOfNotes(notes) {
  const n = String(notes || '');
  const start = n.search(/INTERVIEWERS/i);
  if (start < 0) return '';
  const rest = n.slice(start);
  const end = rest.search(/\n\s*\**\s*COVERED/i);
  return (end > 0 ? rest.slice(0, end) : rest).trim();
}

function askThemMaterial(ws) {
  const lines = ws._getTranscript ? labelTranscript(ws._getTranscript()) : [];
  let said = lines.filter(l => l.startsWith('Interviewer: ')).join('\n');
  if (said.length > 16000) said = said.slice(-16000).replace(/^[^\n]*\n/, '');
  const asked = lines.filter(l => l.startsWith('Candidate: ') && /\?\s*$/.test(l)).map(l => '- ' + l.slice(11)).slice(-8).join('\n');
  const earlier = String(ws._priorMemory || '').split(/(?=EARLIER CALL \()/).map(block => {
    const head = (block.match(/^EARLIER CALL \([^\n]*\n?/) || [''])[0];
    const side = interviewerSideOfNotes(block);
    return side ? head + side : '';
  }).filter(Boolean).join('\n\n');
  const thisCallNotes = interviewerSideOfNotes(ws._callNotes);
  return { said, asked, earlier, thisCallNotes };
}

async function generateQuestionsToAsk(ws) {
  const ctx = ws._sessionContext || {};
  const m = askThemMaterial(ws);
  const parts = [`ROLE: ${ctx.role || 'the role'} at ${ctx.company || 'the company'}`];
  if (m.earlier) parts.push(`WHAT INTERVIEWERS SAID IN EARLIER CALLS:\n${m.earlier}`);
  if (m.thisCallNotes) parts.push(`EARLIER IN THIS CALL — WHAT THE INTERVIEWERS SAID (notes):\n${m.thisCallNotes}`);
  if (m.said) parts.push(`THIS CALL — THE INTERVIEWERS' OWN WORDS:\n${m.said}`);
  if (m.asked) parts.push(`ALREADY ASKED BY THE CANDIDATE (don't repeat):\n${m.asked}`);
  if (ctx.jd) parts.push(`JOB DESCRIPTION:\n${String(ctx.jd).slice(0, 6000)}`);
  const user = parts.join('\n\n') + '\n\nThe 4 questions:';
  const out = await callClaude(ASK_THEM_SYSTEM, user, 400, MODEL_SONNET, { thinking: { type: 'disabled' } });
  const qs = out.split('\n').map(l => l.trim()).filter(l => /^\d+[.)]\s+\S/.test(l)).slice(0, 4);
  logEvent('ask_them', { interviewerChars: m.said.length, earlier: !!m.earlier, notes: !!m.thisCallNotes, n: qs.length });
  return qs.length ? qs.join('\n') : out.trim();
}

const MEMORY_RULES = `

USE THE CONVERSATION (everything said in this interview session is below the resume):
- Stay CONSISTENT with what the candidate already said — the same tools, years, level and numbers. Build on it ("as I mentioned…" is fine); never contradict it; don't retell a story already told unless asked.
- Use what the INTERVIEWER explained (their stack, use cases, problems) to pick WHICH of the candidate's experiences to lead with and to say how it transfers to their situation.
- ADDRESS WHAT THEY CARE ABOUT: if anyone in this interview process — this call or an earlier one, the same or a different interviewer — said what they value, what worries them, or what their environment is like, and this question gives room for it, make the answer SHOW that quality through a matching situation from the candidate's OWN workplace (e.g. they said their data is hard to navigate → the candidate describes how their own environment is also messy and how they work through it before raising anything). Settle the concern without pointing at it — no "since you said…".
- SHOW, DON'T ECHO: never borrow the interviewers' phrases for what they VALUE or how they describe things (tags like "ownership", "independent", "dig in", "messy") — if the BRIDGES list an AVOID line, none of those phrases may appear. Never restate their sentence, and never say "you mentioned" / "since you said". Prove the quality with what the candidate actually does, in the candidate's own everyday words (e.g. "I'd rather trace it back myself first" instead of "I dig in before escalating").
- NAMING THEIR THINGS IS GOOD: their concrete nouns — their tables, systems, tools, product, customers, warehouses, team — should be named plainly when the answer is about them ("on your shipment tables", "for the warehouse forecasts"). That shows listening; it is not echoing. "Our/your environment/data/team" in a question means what the interviewers described — refer to it concretely.
- The candidate's own situations may be framed to parallel theirs, but hard facts NEVER change: employers, titles, dates, years of experience, degrees, certifications, and numbers already stated stay exactly as in the resume or earlier answers. Never claim the candidate did the company's own use case.`;

async function growLiveAnswer(ws, sessionId, active, fullerQuestion) {
  try {
    if (!active || !active.id) return;
    active._grows = active._grows || 0;
    if (active._grows >= 3) return;                       // cap extensions per question
    if ((active.answer || '').length > 1400) return;      // cap total length (overlay space) — full-sentence answers run 400–900 chars
    if ((active.answer || '').trim().length < 4) return;  // nothing to extend yet

    const session = ws._sessionContext || {};
    const growShape = active.shape || classifyQuestionShape(fullerQuestion).shape;
    const growContext = recentInterviewerText(ws);
    const growTechnical = classifyQuestionShape(fullerQuestion).technical || TECH_TERMS_RE.test(growContext); // same rule as new answers
    const stylePrompt = composeLiveSystemPrompt({ shape: growShape, technical: growTechnical, styleKey: session.answer_style, maxLines: 0, voiceProfile: ws._voiceProfile, withConversation: false, questionText: fullerQuestion }); // SAME composer as the answer
    const system = stylePrompt + '\n\nCONTINUATION MODE: The interviewer has ADDED detail to the SAME question. You are given the answer already on screen. Output ONLY 1–2 NEW sentences that DIRECTLY answer what was added (the follow-up, the new scenario or the extra detail) — say how the answer changes for it — in the SAME voice and style, each on its own line starting with "• ". Never add a ↳ employer line or a heading. Do NOT repeat or restate anything already said. Do NOT rewrite. No preamble.';
    const convo = buildConversationContext(ws);
    const userMsg = `${convo ? convo + '\n\n' : ''}QUESTION (now fuller):\n${fullerQuestion}\n\nANSWER ALREADY GIVEN (do NOT repeat any of this):\n${active.answer}\n\nOutput ONLY the additional sentence(s) to append:`;

    let addition = '';
    try { addition = (await callClaude(system, userMsg, 200, MODEL_HAIKU)).trim(); } catch (e) { return; }
    addition = addition.replace(/^["']|["']$/g, '').trim();
    if (!addition || addition.length < 4) return;
    if (isNonAnswer(addition)) { console.log('[Grow] dropped an addition that talks to the user:', addition.replace(/\n/g, ' / ').substring(0, 160)); logEvent('grow_dropped', { sessionId, a: addition.substring(0, 160) }); return; } // never on screen

    // Append-only: keep existing lines exactly; new "• " lines go above the ↳ employer line.
    const full = applyPlatformTraps(appendToLiveAnswer(active.answer || '', addition, growShape), fullerQuestion + ' ' + growContext); // same guard as new answers
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

// ===== LIVE ANSWER COMPOSER (one place for how a live answer is shaped) =====
// Owner's design (25 Sep): full sentences he can read out loud, one per line; the LAYOUT is fixed by the question
// type; the style picker changes WORDING only; his employer appears only on a separate, dimmed, skippable line —
// and only when a real example of his helps. Output contract (drawn by canvas.html formatAnswer, index.html rAns +
// formatCanvasAnswer):
//   "• <sentence>"                     one sayable sentence per line
//   "↳ At <Employer> — <sentence>"     optional proof line, always LAST (general / code / pitch)
//   "▸ At <Employer>"                  story heading, always FIRST (story questions)
//   ```lang … ```                       code questions: the code block comes first
const TECH_TERMS_RE = /\b(sql|query|queries|code|script|function|algorithm|regex|api|join|joins|window function|cte|index|indexes|schema|python|javascript|html|css|excel|vba|dax|power query|power bi|tableau|looker|snowflake|bigquery|redshift|databricks|spark|dbt|airflow|etl|elt|pipeline|clustering key|partition|where|having|group by|primary key|foreign key|vlookup|xlookup|pivot|measure|calculated column|normaliz\w*|regression|p-value|a\/b test)\b/i;
const SHAPE_PITCH_RE = /\b(tell (me|us) (a (little )?(bit )?)?about yourself|walk (me|us) through your (resume|background|career)|introduce yourself|why (do you want|are you interested|this (role|company|job|position|team)|us\b|should we hire)|why (are you )?(leaving|looking)|what are you looking for|where do you see yourself|what('s| is| are) your (greatest |biggest )?(strengths?|weakness(es)?)|what makes you (a good fit|unique|stand out))/i;
const SHAPE_STORY_RE = /\b(tell (me|us) about a (time|situation|project)|describe a (time|situation)|give (me |us )?an example of a time|share (an|a) (experience|time|example)|a time (when|you)|have you ever (had|dealt|faced|handled|worked through)|what did you do when|how did you (handle|deal with|resolve))\b/i;
// Code only when they ask for the code itself. "implement", "in SQL", "a query" alone also sit in design questions (live
// interview 26 Oct: "what would you implement from the start", "does the logic land in SQL queries", "a measure compared
// to SQL") — those got a code answer instead of the explanation.
const SHAPE_CODE_RE = /\b(write|type|code up|show me|give me)\b[^?.!]{0,40}\b(query|queries|sql|code|script|formula|syntax|measure|function|statement)\b|\bwhat('s| is) the (syntax|formula|query)\b|^(how (would|do|can) you) (find|get|calculate|compute|remove|dedupe|de-dupe|rank|pivot|count|return|select|pull)\b/i;

function classifyQuestionShape(questionText) {
  const q = (questionText || '').trim();
  const technical = TECH_TERMS_RE.test(q);
  let shape = 'general';
  if (SHAPE_PITCH_RE.test(q)) shape = 'pitch';
  else if (SHAPE_STORY_RE.test(q)) shape = 'story';
  else if (technical && SHAPE_CODE_RE.test(q)) shape = 'code';
  return { shape, technical };
}

// A live answer that isn't an answer: the writer's NOT_A_QUESTION signal, or it talking to the user instead of
// giving lines to say ("Could you provide the full question…") — owner's mock-video run, 26 Sep.
const NOT_A_QUESTION = 'NOT_A_QUESTION';
const META_REPLY_RE = /\b(could you (please )?(provide|share|clarify|repeat|confirm)|i need (to clarify|more context|the (full|complete|specific) question)|the question (appears|seems) (to be )?(incomplete|cut off|unclear)|once i have the (complete|full) question|appears to be (incomplete|cut off)|as an ai\b|i appreciate you (providing|sharing) the (conversation|transcript|context))/i;
// Category, not phrases: the answer is the CANDIDATE SPEAKING. These are things a speaking candidate never says —
// the writer talking about its job, the inputs, or the candidate in the third person (owner's run 26 Sep 16:34:
// "I need to stop and clarify: the conversation transcript provided does not match the candidate I'm supposed to be coaching").
const OUT_OF_CHARACTER_RE = /\b(the candidate|this candidate|a different candidate|candidate i('| a)m|(the|this|conversation|interview) transcripts? (provided|shows|is for|does(n't| not)|suggests|contains|appears)|conversation transcript|transcript (provided|does(n't| not) match)|(the|this) resume (provided|shows|is for|does(n't| not))|prep(aration)? materials|does(n't| not) match the (candidate|resume|profile)|i('| a)m supposed to|my instructions|stop and clarify|i need to (stop|pause) and (clarify|check|flag|point)|i (should|must|have to|want to) (flag|clarify|point out) (that|this|something)|i can('|no)t (answer|help with|respond to) (this|that)|to be coaching|i('| a)m (coaching|here to coach))\b/i;
// How a reply that talks to the user OPENS — checked on the first few words, before anything reaches the screen.
const META_OPENING_RE = /^[•\-*\s]*(i appreciate you|i need (to clarify|more context|the (full|complete|specific) question)|i'd need (more|the full)|i would need (more|the full)|could you (please )?(provide|clarify|share|repeat|confirm|give me the)|can you (please )?(provide|clarify|share|repeat|confirm)|please (provide|share|clarify|repeat)|it (seems|looks|appears) (like )?(the|your) (question|message|transcript|input)|the (question|transcript|text|input|message) (seems|appears) |i('m| am) not sure (what|which) (the question|you('re| are) asking|question)|i don't (see|have) (a|the|any) (question|context)|there('s| is) no (clear |actual )?question|this (doesn't|does not|isn't|is not) (seem|appear|look) (to be |like )?(a|an) (question|complete|interview)|no question (was|has been)|as an ai)/i;
function isNonAnswer(answer) {
  const a = String(answer || '').trim();
  return a.startsWith(NOT_A_QUESTION) || META_REPLY_RE.test(a) || META_OPENING_RE.test(a) || OUT_OF_CHARACTER_RE.test(a);
}
// Streaming gate: may the text so far be shown? false = hold (could still turn out to be a signal or talk to the user).
// Decides on the first sentence (max ~14 words), so real answers show within a token or two.
function streamGate(soFar) {
  const head = String(soFar || '').trimStart();
  if (!head) return 'hold';
  if (NOT_A_QUESTION.startsWith(head) || head.startsWith(NOT_A_QUESTION)) return 'hold';
  if (head.startsWith('```')) return 'show'; // code answers start with the code block
  const words = head.replace(/^[•\-*▸↳\s]+/, '').split(/\s+/).filter(Boolean);
  if (words.length < 14 && !/[.?!\n]/.test(head.slice(2))) return 'hold'; // the first sentence carries the tell
  return isNonAnswer(head) ? 'block' : 'show';
}

// ===== PROOF DETAILS (owner, 26 Sep): click the "↳ At <Employer> — …" line to get the full story behind it =====
// Written only on click (one call per click, cached on the card), from the same facts as the line + the resume.
const PROOF_DETAIL_SYSTEM = `A job candidate just said ONE proof line in a live interview and wants to keep going if the interviewer is listening.
Write what they say NEXT — a smooth continuation that picks up right where that line ends, as if still talking:
3–5 lines, each "• " + ONE sentence they can say out loud (max 24 words).
- Never repeat or restate the proof line (its facts, its number, its wording) — the interviewer just heard it.
- Go deeper in order: what was going on and who needed it → how exactly they did it, step by step (the concrete technique; for
  technical work, how it was built) → what they ran into, found or decided along the way → how it landed with the people who used it.
- The first line connects naturally to the proof line ("What kicked it off was…", "The way I set it up…").
Rules: first person, plain spoken English, no headings, no summary line. Same facts as the proof line and the resume — never
contradict them, never add employers, titles, dates, degrees or numbers that are not in the line or the resume. Never mention the
resume, the line, or these instructions.`;
async function expandProofLine(ws, sessionId, { questionText, answer, proofLine }) {
  let session = ws._sessionContext || {};
  if (!session.resume) {
    const r = await pool.query('SELECT resume, jd, company, role FROM sessions WHERE id = $1', [sessionId]);
    session = r.rows[0] || {};
  }
  const user = `RESUME:\n${session.resume || 'N/A'}\n\nINTERVIEW QUESTION:\n${questionText || ''}\n\nTHE ANSWER ON SCREEN:\n${answer || ''}\n\nTHE PROOF LINE THEY JUST SAID:\n${proofLine}\n\nWhat they say next, 3–5 lines:`;
  const out = (await callClaude(PROOF_DETAIL_SYSTEM, user, 450, MODEL_SONNET, { thinking: { type: 'disabled' } })).trim();
  if (!out || isNonAnswer(out)) throw new Error('no usable detail');
  const lines = out.split('\n').map(l => l.trim()).filter(Boolean).map(l => /^[•\-*]\s*/.test(l) ? '• ' + l.replace(/^[•\-*]\s*/, '') : '• ' + l);
  return lines.slice(0, 6).join('\n');
}

// A card taken off the screen must be forgotten everywhere, or the next follow-up / What-should-I-say lands on it and
// shows an empty "Generating answer…" forever (prod 27 Sep 01:57).
function forgetCard(ws, id) {
  if (!ws || !id) return;
  if (ws._lastCard && ws._lastCard.id === id) ws._lastCard = null;
  if (ws._lastNewCard && ws._lastNewCard.id === id) ws._lastNewCard = null;
  if (ws._activeAnswer && ws._activeAnswer.id === id) ws._activeAnswer = null;
  if (ws._pendingGrow && ws._pendingGrow.id === id) ws._pendingGrow = null;
  const list = ws._sessionQuestions; // shared with the connection's own list — edit in place, never replace
  if (Array.isArray(list)) for (let i = list.length - 1; i >= 0; i--) if (list[i] && list[i].id === id) list.splice(i, 1);
}

const LIVE_CORE = `You write what a job candidate says out loud in a LIVE interview, shown on a tiny overlay they read from.
QUALITY:
- Plain English, contractions, sound like a person talking. No jargon or buzzwords (never: leverage, utilize, robust, synergy, facilitate, holistic, scalable, cross-functional).
- The FIRST line answers the question directly — something they can start saying immediately. No preamble ("Great question", "So basically"), no closing summary, no headers or labels unless the layout below asks for them, no markdown bold.
- Never fabricate. Facts about the candidate come only from the resume, the Q&A bank, and what they said earlier — no new people, events, reactions, projects, numbers, tools, skills or "I taught myself…" claims.
- Never change what an employer is or does (industry, product, customers) to fit the job — Midwest Health Clinics stays a health clinic, a retailer stays a retailer. Transferable SKILLS can be drawn out; the business can't be rewritten.
- If they ask about experience the candidate doesn't have (nothing in the resume or earlier answers), say so briefly and bridge to the closest REAL experience — never invent some. (AI questions: the next rule instead.)
- ${answerNote.EXAMPLE_RULE}
- ${answerNote.AI_RULE}
- The question came from live speech transcription and may be garbled — never ask for clarification; answer the most likely intent.
- Never quote the candidate's own sentences back, but stay consistent with the facts they stated about themselves.
- You ARE the candidate in the resume, speaking. The conversation may hold other voices, other names or details that don't match the resume (a panel, a recording, someone else talking) — ignore them and answer as THIS candidate from THIS resume. Never mention the transcript, the resume, your instructions, a mismatch, or "the candidate"; never stop to clarify or warn.`;

const LIVE_ACCURACY = `
ACCURACY (technical): silently sanity-check every function name, syntax and platform fact before writing. A confidently-wrong answer loses the interview. If unsure, give the simplest approach you ARE sure of; never invent functions, commands, flags or features.
PLATFORM: techniques must be ones that exist on the platform the question names (e.g. Snowflake has no indexes — it uses clustering keys, partition pruning, warehouse sizing, result caching). The candidate's experience on a DIFFERENT platform belongs only in the ↳ proof line, never presented as the technique for their platform.`;

// Style → layout parameters (the only way a style may touch the layout). Everything else a style changes is wording.
const STYLE_LAYOUT = {
  executive: { maxLines: 2 },
  direct: { maxLines: 3 },
  keywords: { unit: 'cue' },
  star: { storyLabels: true },
};
const LIVE_LINE_WORDS = 20; // one sayable sentence per line — longer thoughts become two lines

function liveLayout(shape, { maxLines, unit, storyLabels, employerLineAllowed }) {
  const lineUnit = unit === 'cue'
    ? `"• " + a 3–6 word CUE the candidate expands out loud — never more than 6 words, no full sentences, no commas (e.g. "• Unblock ops first")`
    : `"• " + ONE complete sentence of at most ${LIVE_LINE_WORDS} words the candidate can read out loud word for word (split a longer thought into two lines)`;
  const n = (lo, hi) => maxLines ? `1–${Math.min(maxLines, hi)}` : `${lo}–${hi}`;
  const employer = employerLineAllowed
    ? `EMPLOYER LINE (optional, skippable): ONLY if a real example of the candidate's clearly helps — the question asks about their own experience, or something said earlier in this interview process makes one of their examples worth giving — add ONE final line in exactly this form:
↳ At <employer where it happened> — <one sentence of at most ${LIVE_LINE_WORDS} words: what they did there and the result — ONLY facts stated in the resume or their earlier answers, no added people, events or reactions>
Use the employer from the resume where that example happened. If no example clearly helps, leave the line out.`
    : `NO employer line and no employer name — this question doesn't call for the candidate's own example.`;
  if (shape === 'code') return `LAYOUT — fixed:
- Start with the code block (\`\`\`sql … \`\`\` or the right language). Nothing before it.
- Then ${n(1, 2)} lines, each ${lineUnit}, saying why it works (the key choice). Do NOT name any employer.
- ${employer}`;
  if (shape === 'story') return `LAYOUT — fixed:
- First line exactly: ▸ At <employer where the story happened, from the resume>
- Then ${storyLabels
      ? `the story as labelled lines, each starting with its label instead of "• ": "Situation: …", "Action: …" (one or two), "Result: …" — each ONE sentence of at most ${LIVE_LINE_WORDS} words`
      : `${n(5, 7)} lines, each ${lineUnit}, telling the story in order: the situation (what was at stake, who was involved) → what the candidate actually did, step by step → what they FOUND or what turned it around, named concretely (the specific assumption, definition, data issue or objection — never just "we found gaps") → the result (a real number if there is one). If the question is about a difficult person or a conflict, one line says how the candidate handled the PERSON (tone, one-on-one, what they cared about) and the last line says how the working relationship ended up`}.
- No separate employer line — the heading is it. Use a real example from the resume, Q&A bank or their earlier answers; never invent one.`;
  if (shape === 'pitch') return `LAYOUT — fixed:
- ${n(3, 5)} lines, each ${lineUnit}, in this order: who they are now (role and focus) → one real proof (a result from the resume) → why this role and team.
- The employer can be named naturally inside these lines. No separate employer line.`;
  return `LAYOUT — fixed:
- ${n(2, 4)} lines, each ${lineUnit}, that answer the question. If the interviewer described their own situation (their tables, tools, problem, team), aim these lines at it, in the candidate's words. Do NOT name any employer in these lines — they must stand on their own.
- If the question asks about the candidate's experience with something the interviewers said THEY use or struggle with, the last of these lines says how that experience carries over to their use (e.g. "…which is the same kind of tuning your shipment queries need").
- ${employer}`;
}

// Style = tone only (wording). Layout parameters for a style live in STYLE_LAYOUT above.
const LIVE_TONES = {
  conversational: 'Plain spoken sentences, like talking to the interviewer across the table.',
  technical: 'Precise: name the exact tools, methods and real metrics in each line.',
  executive: 'Bottom line first; punchy; every line proves competence.',
  star: 'Clear and concrete; on story questions follow the Situation / Action / Result labels exactly.',
  storytelling: 'On STORY questions, the first story line is a hook — the moment or the problem — then tell it as a story. Elsewhere, plain spoken sentences.',
  datadriven: 'Lead each line with the real number when one exists ("20 minutes, down from 4 hours…"). Never invent numbers.',
  direct: 'The answer only — fewest words.',
  framework: 'Organize the lines as clear steps: the first line states the approach, the next lines start "First,", "Second,", "And third,".',
  leadership: 'Show what the candidate noticed, decided and moved forward — initiative and outcomes, in plain words (not the label "ownership").',
  teacher: 'Define it simply first, then one everyday comparison that makes it click.',
  keywords: 'Ultra-short cues only — nouns and verbs, no filler.',
};

// Questions that ask for the candidate's own experience (employer line allowed even with no earlier conversation).
const OWN_EXPERIENCE_RE = /\b(your experience|have you (used|worked|done|built|led|handled|managed)|how have you|in your (current |last |previous )?(role|job|position|experience|work)|at your (current |last |previous )?(company|job|work)|what did you|what have you)\b/i;

function liveLengthRule(maxLines) {
  if (!maxLines) return `LENGTH: the line counts above; every line at most ${LIVE_LINE_WORDS} words; always finish the last sentence.`;
  return `LENGTH (user setting — overrides the line counts above): at most ${maxLines} "• " lines (the heading, the employer line and code do not count); every line at most ${LIVE_LINE_WORDS} words. Always finish the last sentence.`;
}

// The line cap actually in force: the stricter of the style's cap and the user's length setting.
// Stories keep their middle (owner, 26 Sep: "it doesn't really say what happened … and what the gap was"):
// a length setting or a short style never cuts a story below STORY_MIN_LINES.
const STORY_MIN_LINES = 7;
function liveLineCap(styleKey, userMaxLines, shape) {
  const caps = [(STYLE_LAYOUT[styleKey] || {}).maxLines, userMaxLines].filter(x => x > 0);
  const cap = caps.length ? Math.min(...caps) : 0;
  return shape === 'story' && cap ? Math.max(cap, STORY_MIN_LINES) : cap;
}

function composeLiveSystemPrompt({ shape, technical, styleKey, maxLines, voiceProfile, withConversation, questionText, employerLine }) {
  const sp = STYLE_LAYOUT[styleKey] || {};
  const cap = liveLineCap(styleKey, maxLines, shape);
  // employerLine === true: the Answer Note (prepared ahead, no conversation) always welcomes his own example; live answers unchanged
  const employerLineAllowed = employerLine === true || !!withConversation || OWN_EXPERIENCE_RE.test(questionText || '');
  const parts = [LIVE_CORE];
  if (technical) parts.push(LIVE_ACCURACY);
  parts.push('\n' + liveLayout(shape, { maxLines: cap, unit: sp.unit, storyLabels: sp.storyLabels && shape === 'story', employerLineAllowed }));
  parts.push(`\nTONE (${(ANSWER_STYLES[styleKey] || ANSWER_STYLES.conversational).name}) — wording only, never the layout: ${LIVE_TONES[styleKey] || LIVE_TONES.conversational}`);
  parts.push('\n' + liveLengthRule(cap));
  if (voiceProfile) parts.push(`\nSOUND LIKE THIS CANDIDATE (rhythm and word choice only — layout and accuracy come first):\n${voiceProfile}`);
  parts.push(MEMORY_RULES);
  if (withConversation) {
    parts.push(`\n\nCONNECT TO WHAT WAS SAID: decide whether anything said earlier in this interview process relates to this question — the same topic, tool or problem, OR a value, concern or environment an interviewer described that this question lets the candidate show. If it does, the candidate's own proof goes where the LAYOUT puts it: the ↳ employer line (general/code), the story itself (story), or the proof line (pitch) — use the fitting BRIDGE's PROOF, in the candidate's own words. If nothing earlier relates, leave the employer line out.`);
  }
  return parts.join('');
}

// Enforce the output contract deterministically (the model is usually right; this makes "usually" into "always"):
// bullets on sentence lines, at most one ↳ line and it goes last, one ▸ heading and it goes first.
// opts.cap: max "• " lines (style/length setting); opts.employerLineAllowed === false strips any ↳ line;
// opts.cueOnly (Keyword Triggers style): prose lines (> 10 words) are dropped — the style's contract is cues only.
function normalizeLiveAnswer(text, shape, opts = {}) {
  if (!text) return text;
  const lines = text.replace(/\r/g, '').split('\n');
  const body = []; let heading = null; let employer = null; let inCode = false;
  for (let raw of lines) {
    const line = raw.replace(/\s+$/, '');
    if (/^\s*```/.test(line)) { inCode = !inCode; body.push(line.trim()); continue; }
    if (inCode) { body.push(line); continue; }
    const t = line.trim();
    if (!t) continue;
    if (/^▸/.test(t)) { if (!heading) heading = '▸ ' + t.replace(/^▸\s*/, ''); continue; }
    if (/^↳/.test(t)) { employer = '↳ ' + t.replace(/^↳\s*/, ''); continue; } // keep the last one
    if (/^(Situation|Task|Action|Result)\s*:/i.test(t)) { body.push(t); continue; }
    body.push(/^[•\-*]\s+/.test(t) ? '• ' + t.replace(/^[•\-*]\s+/, '') : '• ' + t.replace(/^\*\*|\*\*$/g, ''));
  }
  if (inCode) body.push('```'); // close an unterminated block
  if (opts.cueOnly) {
    for (let i = 0; i < body.length; i++) if (body[i].startsWith('• ') && body[i].split(/\s+/).length - 1 > 8) {
      console.log('[Layout] Dropped a prose line from a cue-only answer:', body[i].slice(0, 60)); body.splice(i, 1); i--;
    }
  }
  if (opts.cap > 0) { // keep the first N sentence lines (headline-first, so the first lines matter most)
    let kept = 0;
    for (let i = 0; i < body.length; i++) if (body[i].startsWith('• ') && ++kept > opts.cap) { body.splice(i, 1); i--; }
  }
  if (opts.employerLineAllowed === false) employer = null;
  const out = [];
  if (heading && shape === 'story') out.push(heading);
  else if (heading) body.unshift('• ' + heading.replace(/^▸\s*/, '')); // a heading outside a story reads as a line
  out.push(...body);
  if (employer && shape !== 'story') out.push(employer);
  return out.join('\n');
}

// PLATFORM TRAPS — features that do NOT exist on a platform but models keep suggesting (from the candidate's other
// stacks). When the question's context names the platform, answer lines recommending the missing feature are removed.
const PLATFORM_TRAPS = [
  { platform: /\bsnowflake\b/i, wrong: /\bindex(es|ing|ed)?\b/i, unless: /\b(no|not|n't|without|instead of|rather than|doesn't|don't|isn't)\b[^.]{0,40}\bindex/i, note: 'Snowflake has no indexes' },
];
function applyPlatformTraps(answer, context) {
  let out = answer;
  for (const t of PLATFORM_TRAPS) {
    if (!t.platform.test(context || '')) continue;
    out = out.split('\n').filter(l => {
      if (l.startsWith('• ') && t.wrong.test(l) && !(t.unless && t.unless.test(l))) { console.log(`[Platform] Removed a line (${t.note}):`, l.slice(0, 70)); return false; }
      return true;
    }).join('\n');
  }
  return out;
}

// What the interviewer said in the last 45 s (last 4 lines) — the topic of a "speed THEM up" question, and the
// platform context for PLATFORM_TRAPS. ONE helper for new answers AND growth.
function recentInterviewerText(ws) {
  return (ws._getTranscript ? ws._getTranscript() : []).filter(t => !t.isUser && !t.isEcho && Date.now() - (t.ts || 0) < 45000).slice(-4).map(t => t.text).join(' ');
}

// A prepared (bank) answer shown live gets the SAME layout as live answers — display only, words unchanged, the bank in
// the database stays exactly as written (mock interview 26 Sep: prepared answers showed as unbulleted text).
function displayPrepared(answer, questionText) {
  if (!answer) return answer;
  return normalizeLiveAnswer(answer, classifyQuestionShape(questionText).shape);
}

// Grow: new sentences go above the ↳ employer line, as normal "• " lines.
function appendToLiveAnswer(answer, addition, shape) {
  const add = (addition || '').split('\n').map(x => x.trim()).filter(Boolean).map(x => /^[•\-*]\s+/.test(x) ? '• ' + x.replace(/^[•\-*]\s+/, '') : '• ' + x);
  const lines = (answer || '').split('\n');
  const idx = lines.findIndex(l => /^↳/.test(l.trim()));
  if (idx === -1) lines.push(...add); else lines.splice(idx, 0, ...add);
  return normalizeLiveAnswer(lines.join('\n'), shape);
}

// Generate answer for live question — questionId is the EXISTING DB row from fastMatchAndRespond
// opts.bankAnswer: a prepared answer to ADAPT to the conversation (shown on the same card; never written back to the bank)
async function generateLiveAnswer(questionText, sessionId, userId, ws, questionId, forceNavigate, opts = {}) {
  // Only the NEWEST answer for a card may write to it (a card can be re-answered when its full question arrives).
  const genTicket = Symbol('gen');
  if (questionId) (ws._cardGen = ws._cardGen || new Map()).set(questionId, genTicket);
  const isCurrent = () => !questionId || !ws._cardGen || ws._cardGen.get(questionId) === genTicket;
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
    // Stable order (DB rows come back unordered) so this block stays byte-identical across answers → prompt cache hits
    // FROZEN per call (prod logs 26 Sep: cached_read=0 on every Haiku answer — each live answer added a new answered row with
    // a random id into this top-8, so the cached block changed every time). Answers given during the call are in THE
    // CONVERSATION already; the snapshot is reset when a new call starts.
    if (!ws._bankSnapshot) {
      const answeredQs = (ws._sessionQuestions || []).filter(q => q.answer).sort((a, b) => String(a.id).localeCompare(String(b.id))).slice(0, 8);
      ws._bankSnapshot = answeredQs.map(q => `Q: ${q.text}\nA: ${q.answer}`).join('\n\n');
    }
    const bankContext = ws._bankSnapshot;


    // Session identity — critical for role-specific answers
    const company = session.company || 'the company';
    const role = session.role || 'this role';
    // Today's date so "2022–present" becomes the right number of years (the model otherwise guesses: 2 vs 4 years seen)
    const todayLine = `TODAY: ${new Date().toISOString().slice(0, 10)} — compute any years of experience from the resume dates and today; never round up.\n`;
    let sessionHeader = todayLine + `THIS INTERVIEW IS FOR: ${role} at ${company}\nThe candidate knows which role and company this is. If asked "why this role" or "why this company", reference ${company} and ${role} naturally — but NEVER parrot the JD. Only bring in personal experience when the question asks for it.\n`;
    // Tailor to whoever is actually asking (name/title/stage), when known.
    const iv = ws._interviewer || {};
    if (iv.name || iv.title || iv.stage) {
      sessionHeader += `INTERVIEWER: ${iv.name || 'the interviewer'}${iv.title ? ', ' + iv.title : ''}${iv.stage ? ' — ' + iv.stage + ' round' : ''}. Pitch the answer to what someone in this role would care about (e.g. a hiring manager wants impact and ownership; an engineer wants technical depth). Never awkwardly name-drop them.\n`;
    }

    // LIVE ANSWER COMPOSER: question type → fixed layout; style → tone only; + length, voice, session memory.
    const { shape, technical: techInQuestion } = classifyQuestionShape(questionText);
    const recentInterviewer = recentInterviewerText(ws);
    const technical = techInQuestion || TECH_TERMS_RE.test(recentInterviewer); // "them/it" questions take their topic from the setup
    const isTechnical = technical; // accuracy guardrail + model choice
    console.log(`[Live Answer] shape=${shape} technical=${technical} recent="${recentInterviewer.slice(-90)}" q="${(questionText || '').slice(0, 50)}"`);
    // Token caps are HEADROOM only (brevity comes from the prompt) — never so tight they chop a sentence.
    const maxSentences = ws._maxAnswerLines || 0;
    let tokenLimit = shape === 'code' ? 1000 : 500;
    if (maxSentences > 0) {
      if (maxSentences <= 3) tokenLimit = shape === 'code' ? 700 : 260;
      else if (maxSentences <= 5) tokenLimit = shape === 'code' ? 800 : 380;
      else if (maxSentences <= 8) tokenLimit = shape === 'code' ? 1000 : 540;
      else if (maxSentences <= 12) tokenLimit = shape === 'code' ? 1300 : 700;
      else tokenLimit = shape === 'code' ? 1500 : 900;
    }
    if (shape === 'story') tokenLimit = Math.max(tokenLimit, 540); // 5–7 story lines must never be cut mid-sentence
    const withConversation = hasConversation(ws);
    const system = composeLiveSystemPrompt({
      shape, technical, styleKey: session.answer_style, maxLines: maxSentences,
      voiceProfile: ws._voiceProfile, withConversation, questionText,
    });
    const layoutRules = { cap: liveLineCap(session.answer_style, maxSentences, shape), employerLineAllowed: withConversation || OWN_EXPERIENCE_RE.test(questionText),
      cueOnly: (STYLE_LAYOUT[session.answer_style] || {}).unit === 'cue' && shape !== 'code' };
    // Everything said in this interview session (earlier calls + this call) — see SESSION MEMORY
    const convo = buildConversationContext(ws);
    const conversationContext = convo ? `\n\nTHE CONVERSATION:\n${convo}` : '';
    const preparedBlock = opts.bankAnswer
      ? `\n\nCANDIDATE'S PREPARED ANSWER to this question (their own facts — keep them; adapt the angle to the conversation):\n${opts.bankAnswer}\n\nRewrite it in the LAYOUT above, aimed at what was said in this interview. Output exactly KEEP (and nothing else) ONLY if nothing said earlier in this interview relates to this question at all.`
      : '';

    // PROMPT CACHING: the session material (who/what/resume/JD/bank) is identical for every answer in a call, so it
    // goes FIRST as its own cached system block; the per-question rules (layout/tone vary by question type), today's
    // date, the conversation and the question come after it. Any byte change before the marker = no reuse.
    const sessionMaterial = `${sessionHeader.replace(todayLine, '')}\nRESUME:\n${session.resume || 'N/A'}\n\nJOB DESCRIPTION:\n${session.jd || 'N/A'}\n\nQ&A BANK (candidate's real experience — USE THIS):\n${bankContext}`;
    const systemBlocks = [
      Object.assign({ type: 'text', text: `SESSION MATERIAL — the candidate and the job:\n${sessionMaterial}` },
        process.env.PROMPT_CACHE === '0' ? {} : { cache_control: { type: 'ephemeral' } }), // PROMPT_CACHE=0 = off
      { type: 'text', text: system },
    ];
    // AIM: what they've said they care about, right next to the question (proximity makes the model actually use it)
    const theyCare = (ws._bridges || '').split('\n').map(l => l.trim()).filter(l => /^THEY:/i.test(l))
      .map(l => '- ' + l.replace(/^THEY:\s*/i, '').split('→')[0].trim()).filter(l => l.length > 3).slice(0, 4);
    console.log(`[Memory] Answer context: aim=${theyCare.length} bridges=${ws._bridges ? 'yes' : 'no'} priorCalls=${ws._priorMemory ? 'yes' : 'no'} q="${(questionText || '').slice(0, 40)}"`);
    // AVOID: their own value words ("dig in", "ownership") — the rule sat far up in the system text and answers still
    // borrowed them (memory-e2e 2 Oct: 2 of 2). Next to the question, like AIM, as a hard word list.
    const avoidWords = ((ws._bridges || '').split('\n').map(l => l.trim()).find(l => /^AVOID:/i.test(l)) || '')
      .replace(/^AVOID:\s*/i, '').split(',').map(w => w.trim().replace(/^["'“]+|["'”.]+$/g, '')).filter(w => w.length > 2).slice(0, 12);
    if (avoidWords.length) console.log(`[Memory] Avoid words: ${avoidWords.join(', ')}`);
    const avoidBlock = avoidWords.length ? `\n\nTHEIR WORDS — never use these words or any form of them (e.g. "dig in" also bans "digging in"); say the same thing in the candidate's own everyday words: ${avoidWords.map(w => '"' + w + '"').join(', ')}` : '';
    const aimBlock = theyCare.length ? `\n\nWHAT THIS INTERVIEW HAS TOLD YOU THEY CARE ABOUT (use one ONLY if it directly relates to THIS question; never add a line about a different topic — in the candidate's words, never theirs):\n${theyCare.join('\n')}` : '';
    const expFacts = experienceFacts(session.resume);
    // Auto-detected text may not be a question at all (a host's intro, an announcement). Only then may the writer
    // skip it — never when the user asked (What should I say / typed / regenerate = forceNavigate) or for a bank answer.
    const mayRefuse = !forceNavigate && !opts.bankAnswer;
    // The writer may NOT skip a detected question any more (it dropped real questions twice on 26 Sep — a case question
    // phrased with "they", and one aimed at a video's other candidate). Detection rules decide what is a question.
    const refuseLine = '';
    // Typed in the box = the candidate's own order (owner, 4 Oct: "write an essay about anything" came back "I can't write an
    // essay. That question doesn't match what we're discussing"). A typed line is done in full, never judged or redirected.
    const typedBlock = opts.typed ? '\n\nTYPED BY THE CANDIDATE (not heard on the call — their own instruction to you): do exactly what it says, in full, in the candidate\'s voice — an essay is written out, a query is written out, a message is drafted. It is never declined, never redirected to "what we are discussing", never answered with a question back.' : '';
    const qLabel = opts.typed ? 'QUESTION (typed by the candidate — do exactly this):' : 'QUESTION (detected from speech — may be just the tail end, use THE CONVERSATION above for full context):';
    const userPrompt = `${todayLine}${expFacts ? expFacts + '\n' : ''}${conversationContext}${preparedBlock}${aimBlock}${avoidBlock}${typedBlock}\n\n${qLabel}\n${questionText}\n\nAnswer ONLY this question. Earlier questions in the conversation already have their own answers — never answer them again here.${refuseLine}\n\nAnswer:`;

    // Model: technical questions use Sonnet by default — measured 25 Sep (test/accuracy-bench.js, 2 runs): Haiku 15/20,
    // Sonnet 18/20 correct, ~+0.3–1.0 s to first words. LIVE_TECH_MODEL=haiku|sonnet|opus overrides. Others: Haiku.
    // Stories and "about you" answers are the most fact-heavy — embellishments in the mock interview came from Haiku there.
    const answerModel = (isTechnical || shape === 'story' || shape === 'pitch') ? (MODELS[process.env.LIVE_TECH_MODEL || 'sonnet'] || MODEL_SONNET) : MODEL_HAIKU;
    // Sonnet 5 decides on its own to "think" first — measured 25 Sep: with a thinking block first words took 1.3–3.3 s,
    // without 0.6–0.9 s. Live answers turn it off; LIVE_THINKING=adaptive puts it back. (Haiku doesn't think by default.)
    const answerExtras = (answerModel !== MODEL_HAIKU && process.env.LIVE_THINKING !== 'adaptive') ? { thinking: { type: 'disabled' } } : undefined;
    const tGen = Date.now();
    let answer = '';
    let ttft = 0;
    let streamed = false;
    const streamEnabled = process.env.STREAM_LIVE_ANSWERS !== '0' && !opts.bankAnswer && !opts.noStream; // '0' = buffered. Adapted/upgraded answers swap in whole.
    if (streamEnabled) {
      try {
        // Nothing reaches the screen until the opening words are checked: a reply that talks to the user, or the
        // NOT_A_QUESTION signal, is never shown — not even for a moment (owner, 26 Sep).
        let streamedSoFar = '', held = '', gate = 'hold';
        answer = await callClaudeStream(systemBlocks, userPrompt, tokenLimit, answerModel, (chunk) => {
          if (!isCurrent()) return; // superseded by a newer answer for this card
          if (gate === 'block') return;
          streamedSoFar += chunk;
          if (gate !== 'show') {
            gate = streamGate(streamedSoFar);
            if (gate !== 'show') { held += chunk; return; }
            chunk = held + chunk; held = '';
          } else if (/[.?!:\n]/.test(chunk) && isNonAnswer(streamedSoFar)) {
            gate = 'block'; // broke character mid-answer — stop here; the final check takes the card down
            return;
          }
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
        }, answerExtras);
        streamed = true;
      } catch (streamErr) {
        // Any streaming failure → fall back to the exact buffered behavior as before.
        console.error('[Stream] fell back to buffered:', streamErr.message);
        answer = await callClaude(systemBlocks, userPrompt, tokenLimit, answerModel, answerExtras);
      }
    } else {
      answer = await callClaude(systemBlocks, userPrompt, tokenLimit, answerModel, answerExtras);
    }
    if (!answer || !answer.trim()) {
      console.log('[Live Answer] Empty answer from the model — retrying once (buffered)');
      logEvent('error', { where: 'generateLiveAnswer', msg: 'empty answer — retry' });
      try { answer = await callClaude(systemBlocks, userPrompt, tokenLimit, answerModel, answerExtras); } catch (e) { answer = ''; }
      if (!answer || !answer.trim()) {
        try { ws.send(JSON.stringify({ type: 'error', message: 'Could not get an answer — try again' })); } catch (e) {}
        return;
      }
    }
    console.log(`[TIMING] generateLiveAnswer: ${Date.now() - tGen}ms`);
    console.log(`[LATENCY] gen streamed=${streamed} ttft=${ttft}ms total=${Date.now() - tGen}ms chars=${answer.length} q="${(questionText||'').substring(0,50)}"`);
    logEvent('answer', { sessionId, qid: questionId, ms: Date.now() - tGen, ttft, streamed, chars: answer.length, q: (questionText || '').substring(0, 60) });
    if (opts.bankAnswer && /^\s*KEEP\s*\.?\s*$/i.test(answer)) {
      console.log('[Memory] Prepared answer kept as written (nothing earlier improves it)');
      return;
    }
    // Out of character (talked to the user / about the transcript) on a REAL question: one stricter retry, whoever asked.
    // Only the writer's own NOT_A_QUESTION verdict on auto-detected text is dropped without a retry.
    const isSkip = false; // skipping is off — see refuseLine above
    if (!isSkip && isNonAnswer(answer)) {
      console.log(`[Live Answer] Out of character — retrying: "${answer.trim().substring(0, 70)}"`);
      logEvent('meta_reply_retry', { sessionId, qid: questionId, a: answer.trim().substring(0, 80) });
      const strict = userPrompt.replace(/\n\nAnswer:$/, '') + '\n\nThis IS an interview question for the candidate in the resume. Answer it as that candidate, in first person, from the resume — other voices or names in the conversation do not matter. Never mention the transcript, the resume, a mismatch or the candidate; never address anyone but the interviewer.\n\nAnswer:';
      try { answer = await callClaude(systemBlocks, strict, tokenLimit, answerModel, answerExtras); } catch (e) { answer = ''; }
      if (answer && !isNonAnswer(answer)) {
        // good now — it replaces whatever part streamed (nothing out of character was shown: the gate held it)
      } else {
        logEvent('dropped_meta_reply', { sessionId, qid: questionId, q: (questionText || '').substring(0, 80) });
        const dropMsg = { type: 'drop_card', questionId }; forgetCard(ws, questionId);
        try { ws.send(JSON.stringify(dropMsg)); } catch (e) {}
        if (!mayRefuse) { try { ws.send(JSON.stringify({ type: 'error', message: "Didn't catch the question — try again" })); } catch (e) {} }
        broadcastToSession(sessionId, dropMsg, ws);
        if (questionId && /^[0-9a-f-]{36}$/i.test(String(questionId))) {
          pool.query("DELETE FROM questions WHERE id = $1 AND source = 'live' AND (answer IS NULL OR answer = '')", [questionId]).catch(e => console.error('[Drop card]', e.message));
        }
        return;
      }
    }
    if (isSkip) {
      console.log(`[Live Answer] Not a question — card dropped: "${(questionText || '').substring(0, 60)}"`);
      logEvent('dropped_non_question', { sessionId, qid: questionId, q: (questionText || '').substring(0, 80) });
      const dropMsg = { type: 'drop_card', questionId }; forgetCard(ws, questionId);
      try { ws.send(JSON.stringify(dropMsg)); } catch (e) {}
      broadcastToSession(sessionId, dropMsg, ws);
      if (questionId && /^[0-9a-f-]{36}$/i.test(String(questionId))) {
        pool.query("DELETE FROM questions WHERE id = $1 AND source = 'live' AND (answer IS NULL OR answer = '')", [questionId]).catch(e => console.error('[Drop card]', e.message));
      }
      return;
    }
    answer = normalizeLiveAnswer(answer, shape, layoutRules); // enforce the layout contract before it's saved or shown
    answer = applyPlatformTraps(answer, questionText + ' ' + recentInterviewer);
    if (!isCurrent()) { console.log('[Live Answer] Superseded by a newer answer for this card — not shown'); return; }

    // UPDATE the existing question row (created by fastMatchAndRespond) — NOT a new INSERT.
    // An adapted prepared answer is for this conversation only — the bank answer stays as the user wrote it.
    if (questionId && !opts.bankAnswer && !opts.noSave) {
      pool.query('UPDATE questions SET answer = $1 WHERE id = $2', [answer, questionId])
        .catch(e => console.error('[Update answer error]', e.message));
    }

    // Mark this as the active answer thread so continued interviewer detail grows THIS answer.
    ws._activeAnswer = { id: questionId, questionText, answer, _grows: 0, _prepped: !!opts.bankAnswer, shape };
    // A follow-up arrived while this answer was still coming in → grow it now (append-only).
    if (ws._pendingGrow && ws._pendingGrow.id === questionId) {
      const pg = ws._pendingGrow; ws._pendingGrow = null;
      if (pg.title) ws._activeAnswer.questionText = pg.title; // a Say card's title becomes the whole question
      setTimeout(() => growLiveAnswer(ws, sessionId, ws._activeAnswer, pg.q).catch(e => console.error('[Grow]', e.message)), 0);
    }

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
    // Only when the user turned Follow-Up Predictions on (default off — the chips were hidden but still paid for)
    if (ws._followUpsOn) generateFollowUps(questionText, answer, session, ws, sessionId, questionId).catch(e => {
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
    lines = transcriptLines(row.transcript);

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

    // SESSION MEMORY: notes for this call, so the next call in this session starts with them
    try {
      const notes = await digestConversation(labelTranscript(lines).join('\n').slice(-24000));
      await pool.query('UPDATE live_transcripts SET memory = $1 WHERE id = $2', [notes, transcriptId]);
      console.log(`[Memory] Saved notes for call ${transcriptId} (${notes.length} chars)`);
    } catch (e) { console.error('[Memory] notes for finished call failed:', e.message); }

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
      const lines = transcriptLines(row.transcript);
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
  server.listen(PORT, () => { console.log(`Running on ${PORT}`); startSemanticModel(); });
}).catch(e => {
  console.error('DB init failed:', e);
  server.listen(PORT, () => console.log(`Running on ${PORT} (DB not ready)`));
});
