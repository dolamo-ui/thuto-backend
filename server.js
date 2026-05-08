// ─────────────────────────────────────────────────────────────────────────────
// Thuto Notes — Secure AI Proxy Backend
// Node.js + Express  |  Runs free on Render.com
// ─────────────────────────────────────────────────────────────────────────────

import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
// ✅ No node-fetch import — Node 18+ has fetch built in globally

// ─── Config ───────────────────────────────────────────────────────────────────

const PORT      = process.env.PORT || 3001;
const APP_TOKEN = process.env.APP_TOKEN || '';

// ─── Load all 4 Groq keys (at least 1 required) ──────────────────────────────

const GROQ_KEYS = [
  process.env.GROQ_KEY_1,
  process.env.GROQ_KEY_2,
  process.env.GROQ_KEY_3,
  process.env.GROQ_KEY_4,
].filter(k => k && k.trim().startsWith('gsk_') && k.trim().length > 20)
 .map(k => k.trim());

// ─── Validation at startup ────────────────────────────────────────────────────

if (!APP_TOKEN) {
  console.error('❌  APP_TOKEN is not set. Add it to your Render environment variables.');
  process.exit(1);
}
if (APP_TOKEN.length < 8) {
  console.error('❌  APP_TOKEN is too short. Use at least 8 characters.');
  process.exit(1);
}
if (GROQ_KEYS.length === 0) {
  console.error('❌  No valid Groq API keys found. Add GROQ_KEY_1 (and optionally 2, 3, 4) to Render env vars.');
  process.exit(1);
}

console.log('✅  APP_TOKEN loaded');
console.log(`✅  ${GROQ_KEYS.length} Groq key(s) loaded`);
GROQ_KEYS.forEach((k, i) => {
  console.log(`    Key ${i + 1}: ${k.slice(0, 8)}...`);
});

// ─── Key rotation state ───────────────────────────────────────────────────────

let currentKeyIndex = 0;
const keyCooldowns = new Map();

function getNextKey() {
  const now = Date.now();
  for (let attempt = 0; attempt < GROQ_KEYS.length; attempt++) {
    const idx = (currentKeyIndex + attempt) % GROQ_KEYS.length;
    const cooldownUntil = keyCooldowns.get(idx) ?? 0;
    if (now >= cooldownUntil) {
      currentKeyIndex = (idx + 1) % GROQ_KEYS.length;
      return { key: GROQ_KEYS[idx], idx };
    }
  }
  let soonestIdx = 0;
  let soonestExpiry = Infinity;
  for (let i = 0; i < GROQ_KEYS.length; i++) {
    const expiry = keyCooldowns.get(i) ?? 0;
    if (expiry < soonestExpiry) {
      soonestExpiry = expiry;
      soonestIdx = i;
    }
  }
  console.warn(`⚠️  All ${GROQ_KEYS.length} keys are cooling down. Using key ${soonestIdx + 1} anyway.`);
  return { key: GROQ_KEYS[soonestIdx], idx: soonestIdx };
}

function markKeyCooling(idx, retryAfterSec = 60) {
  const until = Date.now() + retryAfterSec * 1000;
  keyCooldowns.set(idx, until);
  console.warn(`🔄  Key ${idx + 1} rate-limited — cooling for ${retryAfterSec}s. Rotating to next key.`);
}

// ─── Allowed models whitelist ─────────────────────────────────────────────────

const ALLOWED_MODELS = new Set([
  'llama-3.3-70b-versatile',
  'llama-3.1-8b-instant',
  'meta-llama/llama-4-scout-17b-16e-instruct',
  'llama-3.2-90b-vision-preview',
  'llama-3.2-11b-vision-preview',
]);

// ─── Token limits ─────────────────────────────────────────────────────────────

const MAX_TOKENS_ALLOWED = 8192;
const MIN_TOKENS_ALLOWED = 100;

// ─── Express app ──────────────────────────────────────────────────────────────

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.set('trust proxy', 1);

// ─── CORS ─────────────────────────────────────────────────────────────────────

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.length === 0) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-App-Token', 'X-Timestamp', 'X-Signature', 'X-Firebase-Token'],
}));

app.use(express.json({ limit: '2mb' }));

// ─── Global rate limit ────────────────────────────────────────────────────────

const globalLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'TOO_MANY_REQUESTS', message: 'Too many requests from this IP.' },
});

app.use(globalLimiter);

// ─── Per-device rate limit ────────────────────────────────────────────────────

const deviceStore = new Map();
const DEVICE_LIMIT  = 100;
const DEVICE_WINDOW = 60 * 60 * 1000;

function checkDeviceLimit(deviceId) {
  if (!deviceId) return { allowed: true };
  const now = Date.now();
  const rec = deviceStore.get(deviceId);
  if (!rec || now > rec.resetAt) {
    deviceStore.set(deviceId, { count: 1, resetAt: now + DEVICE_WINDOW });
    return { allowed: true, remaining: DEVICE_LIMIT - 1 };
  }
  if (rec.count >= DEVICE_LIMIT) {
    const retryAfterSec = Math.ceil((rec.resetAt - now) / 1000);
    return { allowed: false, retryAfterSec };
  }
  rec.count++;
  return { allowed: true, remaining: DEVICE_LIMIT - rec.count };
}

setInterval(() => {
  const now = Date.now();
  for (const [id, rec] of deviceStore.entries()) {
    if (now > rec.resetAt) deviceStore.delete(id);
  }
}, 60 * 60 * 1000);

// ─── Auth middleware ──────────────────────────────────────────────────────────

function requireToken(req, res, next) {
  const token = req.headers['x-app-token'] || '';
  if (!token) {
    return res.status(401).json({
      error: 'MISSING_TOKEN',
      message: 'X-App-Token header is required.',
    });
  }
  if (!safeEqual(token, APP_TOKEN)) {
    console.warn('⚠️  Bad app token from IP:', req.ip, '| token:', token.slice(0, 4) + '...');
    return res.status(403).json({
      error: 'AUTH_FAILED',
      message: 'Invalid app token.',
    });
  }
  next();
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ─── Input validation ─────────────────────────────────────────────────────────

function validateGroqBody(body) {
  const errors = [];

  if (!body.model || typeof body.model !== 'string') {
    errors.push('model must be a string');
  } else if (!ALLOWED_MODELS.has(body.model)) {
    errors.push(`model "${body.model}" is not allowed. Allowed: ${[...ALLOWED_MODELS].join(', ')}`);
  }

  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    errors.push('messages must be a non-empty array');
  }

  if (body.messages) {
    for (let i = 0; i < body.messages.length; i++) {
      const m = body.messages[i];
      if (!m.role || !['system', 'user', 'assistant'].includes(m.role)) {
        errors.push(`messages[${i}].role must be system, user, or assistant`);
      }
      if (!m.content && m.content !== '') {
        errors.push(`messages[${i}].content is required`);
      }
    }
  }

  const maxTokens = body.max_tokens || 4096;
  if (maxTokens < MIN_TOKENS_ALLOWED || maxTokens > MAX_TOKENS_ALLOWED) {
    errors.push(`max_tokens must be between ${MIN_TOKENS_ALLOWED} and ${MAX_TOKENS_ALLOWED}`);
  }

  return errors;
}

// ─── Core Groq proxy (with key rotation + retry on 429) ──────────────────────

async function callGroq(groqBody) {
  let lastError = null;

  for (let attempt = 0; attempt < GROQ_KEYS.length; attempt++) {
    const { key, idx } = getNextKey();

    let response;
    try {
      response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${key}`,
        },
        body: JSON.stringify(groqBody),
        signal: AbortSignal.timeout(60_000),
      });
    } catch (fetchErr) {
      throw fetchErr;
    }

    const text = await response.text();

    if (response.status === 429) {
      const retryAfter = parseInt(response.headers.get('retry-after') ?? '60', 10);
      markKeyCooling(idx, retryAfter);
      lastError = { status: 429, code: 'GROQ_RATE_LIMITED', message: 'Groq rate limit hit. Try again shortly.' };
      continue;
    }

    if (response.status === 401) {
      console.error(`❌  Key ${idx + 1} rejected by Groq — check GROQ_KEY_${idx + 1} in Render env vars`);
      lastError = { status: 502, code: 'GROQ_AUTH_FAILED', message: 'AI service authentication failed.' };
      continue;
    }

    if (!response.ok) {
      let errData = {};
      try { errData = JSON.parse(text); } catch {}
      throw {
        status: response.status,
        code:   'GROQ_ERROR',
        message: errData?.error?.message || `Groq returned ${response.status}`,
      };
    }

    console.log(`✅  Key ${idx + 1} used successfully`);
    return JSON.parse(text);
  }

  throw lastError ?? { status: 429, code: 'GROQ_RATE_LIMITED', message: 'All API keys are rate-limited. Please try again shortly.' };
}

// ─── Health check ─────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  const now = Date.now();
  const keyStatuses = GROQ_KEYS.map((_, i) => {
    const cooldownUntil = keyCooldowns.get(i) ?? 0;
    const cooling = now < cooldownUntil;
    return {
      key:     `key_${i + 1}`,
      status:  cooling ? 'cooling' : 'ready',
      coolsIn: cooling ? `${Math.ceil((cooldownUntil - now) / 1000)}s` : null,
    };
  });

  res.json({
    status:    'ok',
    service:   'thuto-backend',
    timestamp: new Date().toISOString(),
    uptime:    Math.floor(process.uptime()),
    keys:      keyStatuses,
  });
});

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'Thuto Notes API', keys: GROQ_KEYS.length });
});

// ─── Route: /api/generate ─────────────────────────────────────────────────────

app.post('/api/generate', requireToken, async (req, res) => {
  try {
    const { deviceId, ...groqBody } = req.body;

    const limit = checkDeviceLimit(deviceId);
    if (!limit.allowed) {
      return res.status(429).json({
        error: 'QUOTA_EXHAUSTED',
        message: `Daily limit reached. Try again in ${Math.ceil(limit.retryAfterSec / 60)} minutes.`,
        retryAfterSec: limit.retryAfterSec,
      });
    }

    const errors = validateGroqBody(groqBody);
    if (errors.length > 0) {
      return res.status(400).json({ error: 'INVALID_REQUEST', details: errors });
    }

    console.log(`📝 /api/generate | model: ${groqBody.model} | device: ${deviceId?.slice(0, 8) || 'unknown'}`);

    const data = await callGroq({
      model:       groqBody.model,
      messages:    groqBody.messages,
      max_tokens:  groqBody.max_tokens  || 4096,
      temperature: groqBody.temperature ?? 0.35,
      top_p:       groqBody.top_p       ?? 0.9,
    });

    res.json(data);

  } catch (err) {
    handleError(err, res, '/api/generate');
  }
});

// ─── Route: /api/analyse (vision) ────────────────────────────────────────────

app.post('/api/analyse', requireToken, async (req, res) => {
  try {
    const { deviceId, ...groqBody } = req.body;

    const limit = checkDeviceLimit(deviceId);
    if (!limit.allowed) {
      return res.status(429).json({
        error: 'QUOTA_EXHAUSTED',
        message: `Daily limit reached. Try again in ${Math.ceil(limit.retryAfterSec / 60)} minutes.`,
        retryAfterSec: limit.retryAfterSec,
      });
    }

    const errors = validateGroqBody(groqBody);
    if (errors.length > 0) {
      return res.status(400).json({ error: 'INVALID_REQUEST', details: errors });
    }

    console.log(`📸 /api/analyse | model: ${groqBody.model} | device: ${deviceId?.slice(0, 8) || 'unknown'}`);

    const data = await callGroq({
      model:       groqBody.model,
      messages:    groqBody.messages,
      max_tokens:  groqBody.max_tokens  || 1500,
      temperature: groqBody.temperature ?? 0.1,
      top_p:       groqBody.top_p       ?? 0.9,
    });

    res.json(data);

  } catch (err) {
    handleError(err, res, '/api/analyse');
  }
});

// ─── Route: /api/svg ──────────────────────────────────────────────────────────

app.post('/api/svg', requireToken, async (req, res) => {
  try {
    const { deviceId, ...groqBody } = req.body;

    const limit = checkDeviceLimit(deviceId);
    if (!limit.allowed) {
      return res.status(429).json({
        error: 'QUOTA_EXHAUSTED',
        message: `Daily limit reached. Try again in ${Math.ceil(limit.retryAfterSec / 60)} minutes.`,
        retryAfterSec: limit.retryAfterSec,
      });
    }

    const errors = validateGroqBody(groqBody);
    if (errors.length > 0) {
      return res.status(400).json({ error: 'INVALID_REQUEST', details: errors });
    }

    console.log(`🎨 /api/svg | model: ${groqBody.model} | device: ${deviceId?.slice(0, 8) || 'unknown'}`);

    const data = await callGroq({
      model:       groqBody.model,
      messages:    groqBody.messages,
      max_tokens:  groqBody.max_tokens  || 2048,
      temperature: groqBody.temperature ?? 0.5,
      top_p:       groqBody.top_p       ?? 0.9,
    });

    res.json(data);

  } catch (err) {
    handleError(err, res, '/api/svg');
  }
});

// ─── 404 ──────────────────────────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ error: 'NOT_FOUND', path: req.path });
});

// ─── Error handler ────────────────────────────────────────────────────────────

function handleError(err, res, route) {
  if (err.status && err.code) {
    console.error(`❌  ${route} error: [${err.code}] ${err.message}`);
    return res.status(err.status).json({ error: err.code, message: err.message });
  }
  if (err.name === 'TimeoutError' || err.name === 'AbortError') {
    console.error(`⏱️  ${route} timeout`);
    return res.status(504).json({ error: 'TIMEOUT', message: 'AI request timed out. Try again.' });
  }
  if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND') {
    console.error(`🌐  ${route} network error:`, err.message);
    return res.status(503).json({ error: 'NETWORK_ERROR', message: 'Cannot reach AI service.' });
  }
  console.error(`💥  ${route} unexpected error:`, err);
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Something went wrong.' });
}

app.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS_BLOCKED', message: 'Origin not allowed.' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'PAYLOAD_TOO_LARGE', message: 'Request body too large (max 2mb).' });
  }
  handleError(err, res, req.path);
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log('');
  console.log('🚀  Thuto Notes backend running');
  console.log(`📡  Port: ${PORT}`);
  console.log(`🔒  Token auth: enabled`);
  console.log(`⚡  Rate limit: ${DEVICE_LIMIT} req/hr per device`);
  console.log(`🔑  Groq keys loaded: ${GROQ_KEYS.length}`);
  console.log('');
});

export default app;
