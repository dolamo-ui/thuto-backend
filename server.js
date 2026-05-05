// ─────────────────────────────────────────────────────────────────────────────
// Thuto Notes — Secure AI Proxy Backend
// Node.js + Express  |  Runs free on Render.com
// ─────────────────────────────────────────────────────────────────────────────
// WHAT THIS DOES:
//   1. Receives requests from your Thuto app
//   2. Checks the secret app token (so strangers can't use your Groq key)
//   3. Rate limits requests per device (so one user can't spam the AI)
//   4. Forwards the request to Groq with your secret API key
//   5. Returns the Groq response to your app
//
// YOUR GROQ KEY NEVER TOUCHES THE APP — it only lives here on the server.
// ─────────────────────────────────────────────────────────────────────────────

import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import fetch from 'node-fetch';

// ─── Config ───────────────────────────────────────────────────────────────────

const PORT      = process.env.PORT || 3001;
const APP_TOKEN = process.env.APP_TOKEN || '';
const GROQ_KEY  = process.env.GROQ_KEY_1 || process.env.GROQ_KEY || '';

// On Render the free tier spins down after 15 min idle.
// Your app will wake it up on the next request (takes ~30s).
// You can use uptimerobot.com (free) to ping /health every 14 min if you
// want to keep it awake — but that breaks Render's free tier ToS technically,
// so only do it if your usage is legitimate.

// ─── Validation at startup ────────────────────────────────────────────────────

if (!APP_TOKEN) {
  console.error('❌  APP_TOKEN is not set. Add it to your Render environment variables.');
  process.exit(1);
}
if (!GROQ_KEY) {
  console.error('❌  GROQ_KEY_1 is not set. Add your Groq API key to Render environment variables.');
  process.exit(1);
}
if (APP_TOKEN.length < 8) {
  console.error('❌  APP_TOKEN is too short. Use at least 8 characters.');
  process.exit(1);
}

console.log('✅  APP_TOKEN loaded');
console.log('✅  GROQ_KEY loaded (starts with:', GROQ_KEY.slice(0, 8), '...)');

// ─── Allowed models whitelist ─────────────────────────────────────────────────
// Only these models can be requested through your proxy.
// This stops anyone who gets past the token from using other expensive models.

const ALLOWED_MODELS = new Set([
  'llama-3.3-70b-versatile',
  'llama-3.1-8b-instant',
  'meta-llama/llama-4-scout-17b-16e-instruct',
  'llama-3.2-90b-vision-preview',
  'llama-3.2-11b-vision-preview',
]);

// ─── Groq API limits per model ────────────────────────────────────────────────
// Prevents your app from requesting absurd token counts

const MAX_TOKENS_ALLOWED = 8192;
const MIN_TOKENS_ALLOWED = 100;

// ─── Express app ──────────────────────────────────────────────────────────────

const app = express();

// Helmet sets secure HTTP headers (protects against common web attacks)
app.use(helmet({
  contentSecurityPolicy: false, // We're an API, not a website
}));

// Trust Render's reverse proxy (needed for correct IP detection)
app.set('trust proxy', 1);

// ─── CORS ─────────────────────────────────────────────────────────────────────
// Controls which origins can call your server.
// React Native apps don't send an Origin header, so we allow null too.
// Expo Go on a device also needs to be allowed.

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (React Native, Postman, server-to-server)
    if (!origin) return callback(null, true);
    if (allowedOrigins.length === 0) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    // Block unknown origins
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-App-Token'],
}));

// Parse JSON bodies (max 2mb — images are base64 encoded so they can be large)
app.use(express.json({ limit: '2mb' }));

// ─── Global rate limit ────────────────────────────────────────────────────────
// 200 requests per hour per IP address.
// This is a broad limit — per-device limits are applied inside routes.

const globalLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'TOO_MANY_REQUESTS', message: 'Too many requests from this IP.' },
});

app.use(globalLimiter);

// ─── Per-device rate limit ────────────────────────────────────────────────────
// 100 AI requests per hour per deviceId.
// deviceId comes from the app's AsyncStorage (see groqClient.ts getDeviceId).

const deviceStore = new Map(); // deviceId → { count, resetAt }
const DEVICE_LIMIT  = 100;
const DEVICE_WINDOW = 60 * 60 * 1000; // 1 hour

function checkDeviceLimit(deviceId) {
  if (!deviceId) return { allowed: true }; // no device id = skip per-device limit

  const now = Date.now();
  const rec = deviceStore.get(deviceId);

  if (!rec || now > rec.resetAt) {
    // First request or window expired — reset
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

// Clean up old device records every hour to prevent memory leaks
setInterval(() => {
  const now = Date.now();
  for (const [id, rec] of deviceStore.entries()) {
    if (now > rec.resetAt) deviceStore.delete(id);
  }
}, 60 * 60 * 1000);

// ─── Auth middleware ───────────────────────────────────────────────────────────
// Every AI route requires the correct X-App-Token header.
// This is the shared secret between your app and this server.

function requireToken(req, res, next) {
  const token = req.headers['x-app-token'] || '';

  if (!token) {
    return res.status(401).json({
      error: 'MISSING_TOKEN',
      message: 'X-App-Token header is required.',
    });
  }

  // Constant-time comparison to prevent timing attacks
  if (!safeEqual(token, APP_TOKEN)) {
    console.warn('⚠️  Bad app token from IP:', req.ip, '| token:', token.slice(0, 4) + '...');
    return res.status(403).json({
      error: 'AUTH_FAILED',
      message: 'Invalid app token.',
    });
  }

  next();
}

// Constant-time string comparison (prevents timing side-channel attacks)
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

// ─── Core Groq proxy function ─────────────────────────────────────────────────

async function callGroq(groqBody) {
  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${GROQ_KEY}`,
    },
    body: JSON.stringify(groqBody),
    // 60 second timeout
    signal: AbortSignal.timeout(60_000),
  });

  const text = await response.text();

  if (!response.ok) {
    let errData = {};
    try { errData = JSON.parse(text); } catch {}

    if (response.status === 429) {
      throw { status: 429, code: 'GROQ_RATE_LIMITED', message: 'Groq rate limit hit. Try again shortly.' };
    }
    if (response.status === 401) {
      console.error('❌  Groq rejected the API key — check GROQ_KEY_1 in Render env vars');
      throw { status: 502, code: 'GROQ_AUTH_FAILED', message: 'AI service authentication failed.' };
    }
    throw {
      status: response.status,
      code: 'GROQ_ERROR',
      message: errData?.error?.message || `Groq returned ${response.status}`,
    };
  }

  return JSON.parse(text);
}

// ─── Route: health check ───────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'thuto-backend',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
  });
});

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'Thuto Notes API' });
});

// ─── Route: /api/generate (text generation) ───────────────────────────────────

app.post('/api/generate', requireToken, async (req, res) => {
  try {
    const { deviceId, ...groqBody } = req.body;

    // Per-device rate limit
    const limit = checkDeviceLimit(deviceId);
    if (!limit.allowed) {
      return res.status(429).json({
        error: 'QUOTA_EXHAUSTED',
        message: `Daily limit reached. Try again in ${Math.ceil(limit.retryAfterSec / 60)} minutes.`,
        retryAfterSec: limit.retryAfterSec,
      });
    }

    // Validate request body
    const errors = validateGroqBody(groqBody);
    if (errors.length > 0) {
      return res.status(400).json({ error: 'INVALID_REQUEST', details: errors });
    }

    // Log (no personal data, just model and token count for debugging)
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

// ─── Route: /api/analyse (vision — base64 image + text) ──────────────────────

app.post('/api/analyse', requireToken, async (req, res) => {
  try {
    const { deviceId, ...groqBody } = req.body;

    // Per-device rate limit (vision counts as 3 requests due to cost)
    const limit = checkDeviceLimit(deviceId);
    if (!limit.allowed) {
      return res.status(429).json({
        error: 'QUOTA_EXHAUSTED',
        message: `Daily limit reached. Try again in ${Math.ceil(limit.retryAfterSec / 60)} minutes.`,
        retryAfterSec: limit.retryAfterSec,
      });
    }

    // Validate
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

// ─── Route: /api/svg (optional — same as generate, for SVG content) ───────────

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

// ─── Catch unknown routes ─────────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ error: 'NOT_FOUND', path: req.path });
});

// ─── Error handler ─────────────────────────────────────────────────────────────

function handleError(err, res, route) {
  // Our own structured errors
  if (err.status && err.code) {
    console.error(`❌  ${route} error: [${err.code}] ${err.message}`);
    return res.status(err.status).json({ error: err.code, message: err.message });
  }

  // Timeout
  if (err.name === 'TimeoutError' || err.name === 'AbortError') {
    console.error(`⏱️  ${route} timeout`);
    return res.status(504).json({ error: 'TIMEOUT', message: 'AI request timed out. Try again.' });
  }

  // Network errors
  if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND') {
    console.error(`🌐  ${route} network error:`, err.message);
    return res.status(503).json({ error: 'NETWORK_ERROR', message: 'Cannot reach AI service.' });
  }

  // Unknown
  console.error(`💥  ${route} unexpected error:`, err);
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Something went wrong.' });
}

// ─── Global Express error handler ─────────────────────────────────────────────

app.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS_BLOCKED', message: 'Origin not allowed.' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'PAYLOAD_TOO_LARGE', message: 'Request body too large (max 2mb).' });
  }
  handleError(err, res, req.path);
});

// ─── Start server ─────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log('');
  console.log('🚀  Thuto Notes backend running');
  console.log(`📡  Port: ${PORT}`);
  console.log(`🔒  Token auth: enabled`);
  console.log(`⚡  Rate limit: ${DEVICE_LIMIT} req/hr per device`);
  console.log('');
});

export default app;