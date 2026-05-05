// ─────────────────────────────────────────────────────────────────────────────
// Thuto Notes — Secure AI Proxy Backend  v2.0
// Node.js + Express  |  Runs free on Render.com
// ─────────────────────────────────────────────────────────────────────────────
// SECURITY IMPROVEMENTS IN THIS VERSION:
//   ✅ IP + Device ID combined rate limiting (stops key-cycling abuse)
//   ✅ Hard message content length cap (stops giant payload attacks)
//   ✅ Base64 image size cap on the server side
//   ✅ Request body field whitelist (strips unknown fields before sending to Groq)
//   ✅ Suspicious pattern detection (blocks prompt injection on the server)
//   ✅ Startup token strength check (rejects weak tokens)
//   ✅ X-Forwarded-For spoofing protection
//   ✅ Graceful shutdown handler
//   ✅ Memory-safe device store with hard cap
// ─────────────────────────────────────────────────────────────────────────────

import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { rateLimit, ipKeyGenerator } from 'express-rate-limit';
import fetch from 'node-fetch';

// ─── Config ───────────────────────────────────────────────────────────────────

const PORT      = process.env.PORT || 3001;
const APP_TOKEN = (process.env.APP_TOKEN || '').trim();

// ─── Multi-key rotation ───────────────────────────────────────────────────────

const GROQ_KEYS = [
  process.env.GROQ_KEY_1,
  process.env.GROQ_KEY_2,
  process.env.GROQ_KEY_3,
  process.env.GROQ_KEY_4,
].filter(k => typeof k === 'string' && k.trim().startsWith('gsk_') && k.length > 20)
 .map(k => k.trim());

// ─── Limits ───────────────────────────────────────────────────────────────────

const MAX_TOKENS_ALLOWED      = 8192;
const MIN_TOKENS_ALLOWED      = 100;

// Per-message content length: stops someone sending a 1 MB prompt
const MAX_TEXT_CONTENT_CHARS  = 12_000;

// Base64 image cap: ~2 MB decoded ≈ 2.7 MB base64
const MAX_BASE64_IMAGE_CHARS  = 2_800_000;

// How many devices we track before we start evicting the oldest ones
// This stops a memory attack where someone sends millions of fake device IDs
const MAX_DEVICE_STORE_SIZE   = 50_000;

// Per-device: 100 requests per hour
const DEVICE_LIMIT            = 100;
const DEVICE_WINDOW_MS        = 60 * 60 * 1000;

// Per-IP: 300 requests per hour (covers unauthenticated probing too)
const IP_HOURLY_LIMIT         = 300;

// ─── Validation at startup ────────────────────────────────────────────────────

if (!APP_TOKEN) {
  console.error('❌  APP_TOKEN is not set. Add it to your Render environment variables.');
  process.exit(1);
}
if (APP_TOKEN.length < 24) {
  console.error('❌  APP_TOKEN is too short — must be at least 24 characters. Generate a new one.');
  process.exit(1);
}
// Warn if someone left the example token from the README
const EXAMPLE_TOKENS = new Set(['beastnotes2025', 'changeme', 'secret', 'password', 'token']);
if (EXAMPLE_TOKENS.has(APP_TOKEN.toLowerCase())) {
  console.error('❌  APP_TOKEN looks like an example value. Set a real random token.');
  process.exit(1);
}
if (GROQ_KEYS.length === 0) {
  console.error('❌  No valid Groq keys found. Add GROQ_KEY_1 in Render env vars.');
  process.exit(1);
}

console.log('✅  APP_TOKEN loaded and strength OK');
console.log(`✅  ${GROQ_KEYS.length} Groq key(s) loaded:`);
GROQ_KEYS.forEach((k, i) => {
  console.log(`     Key ${i + 1}: ${k.slice(0, 8)}...${k.slice(-4)}`);
});

// ─── Key rotation ─────────────────────────────────────────────────────────────

let keyIndex = 0;

function getNextKey() {
  const key = GROQ_KEYS[keyIndex];
  keyIndex = (keyIndex + 1) % GROQ_KEYS.length;
  return key;
}

// ─── Allowed models whitelist ─────────────────────────────────────────────────

const ALLOWED_MODELS = new Set([
  'llama-3.3-70b-versatile',
  'llama-3.1-8b-instant',
  'meta-llama/llama-4-scout-17b-16e-instruct',
  'llama-3.2-90b-vision-preview',
  'llama-3.2-11b-vision-preview',
]);

// ─── Express app ──────────────────────────────────────────────────────────────

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));

// Tell Express to trust the first proxy hop only (Render sits behind one)
// This prevents X-Forwarded-For spoofing where someone sends fake IPs
app.set('trust proxy', 1);

// ─── CORS ─────────────────────────────────────────────────────────────────────

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (React Native app, Expo Go, Postman)
    if (!origin) return callback(null, true);
    if (allowedOrigins.length === 0) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-App-Token'],
}));

// Body limit: 4 MB allows large base64 images with some headroom
app.use(express.json({ limit: '4mb' }));

// ─── Global IP rate limiter ────────────────────────────────────────────────────
// Catches bots and scanners before they even check the token

const globalLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: IP_HOURLY_LIMIT,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req),
  message: { error: 'TOO_MANY_REQUESTS', message: 'Too many requests from this IP.' },
});

app.use(globalLimiter);

// ─── Per-device + Per-IP rate limiter ─────────────────────────────────────────
// Two-factor rate limiting:
//   - Device ID alone can be cycled (delete app, reinstall = new ID)
//   - IP alone can be shared (school WiFi, mobile carrier NAT)
//   - Combined: both must be under limit — much harder to abuse

const deviceStore = new Map();

function checkCombinedLimit(deviceId, ip) {
  const now = Date.now();

  // ── Device limit ──────────────────────────────────────────────────────────
  let deviceResult = { allowed: true };

  if (deviceId && typeof deviceId === 'string' && deviceId.length >= 8) {
    // Evict oldest entries if the store is too big (memory protection)
    if (deviceStore.size >= MAX_DEVICE_STORE_SIZE) {
      const oldestKey = deviceStore.keys().next().value;
      deviceStore.delete(oldestKey);
    }

    const key = `d:${deviceId.slice(0, 64)}`; // cap key length
    const rec = deviceStore.get(key);

    if (!rec || now > rec.resetAt) {
      deviceStore.set(key, { count: 1, resetAt: now + DEVICE_WINDOW_MS });
    } else if (rec.count >= DEVICE_LIMIT) {
      deviceResult = {
        allowed: false,
        reason: 'DEVICE',
        retryAfterSec: Math.ceil((rec.resetAt - now) / 1000),
      };
    } else {
      rec.count++;
    }
  }

  // ── IP limit (separate bucket, same window) ───────────────────────────────
  let ipResult = { allowed: true };

  if (ip) {
    const key = `ip:${ip}`;
    const rec = deviceStore.get(key);

    if (!rec || now > rec.resetAt) {
      deviceStore.set(key, { count: 1, resetAt: now + DEVICE_WINDOW_MS });
    } else if (rec.count >= DEVICE_LIMIT) {
      // IP bucket uses same limit as device bucket
      ipResult = {
        allowed: false,
        reason: 'IP',
        retryAfterSec: Math.ceil((rec.resetAt - now) / 1000),
      };
    } else {
      rec.count++;
    }
  }

  // Both must pass
  if (!deviceResult.allowed) return deviceResult;
  if (!ipResult.allowed)    return ipResult;
  return { allowed: true };
}

// Clean up expired entries every hour
setInterval(() => {
  const now = Date.now();
  for (const [id, rec] of deviceStore.entries()) {
    if (now > rec.resetAt) deviceStore.delete(id);
  }
  console.log(`🧹  Device store cleaned. Entries: ${deviceStore.size}`);
}, 60 * 60 * 1000);

// ─── Auth middleware ───────────────────────────────────────────────────────────

function requireToken(req, res, next) {
  const token = (req.headers['x-app-token'] || '').trim();

  if (!token) {
    return res.status(401).json({
      error: 'MISSING_TOKEN',
      message: 'X-App-Token header is required.',
    });
  }

  if (!safeEqual(token, APP_TOKEN)) {
    // Log only the first 4 chars so the real token is never in logs
    console.warn(`⚠️  Bad token from IP: ${req.ip} | starts: ${token.slice(0, 4)}...`);
    return res.status(403).json({
      error: 'AUTH_FAILED',
      message: 'Invalid app token.',
    });
  }

  next();
}

// Constant-time string comparison — prevents timing attacks
// (without this, an attacker could measure response times to guess the token
//  one character at a time)
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ─── Suspicious content patterns ──────────────────────────────────────────────
// Catches prompt injection attacks on the server side
// (the frontend has similar checks but backend is the real guard)

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /system\s*prompt/i,
  /you\s+are\s+now\s+(a|an)/i,
  /forget\s+(everything|all)/i,
  /jailbreak/i,
  /DAN\s+mode/i,
  /override\s+(safety|filter)/i,
  /sudo\s+mode/i,
  /act\s+as\s+(a|an)\s+/i,
];

function containsInjection(text) {
  if (typeof text !== 'string') return false;
  return INJECTION_PATTERNS.some(p => p.test(text));
}

// ─── Input validation ─────────────────────────────────────────────────────────

function validateGroqBody(body, isVision = false) {
  const errors = [];

  // ── Model ─────────────────────────────────────────────────────────────────
  if (!body.model || typeof body.model !== 'string') {
    errors.push('model must be a string');
  } else if (!ALLOWED_MODELS.has(body.model)) {
    errors.push(`model "${body.model}" is not allowed`);
  }

  // ── Messages ──────────────────────────────────────────────────────────────
  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    errors.push('messages must be a non-empty array');
    return errors; // no point checking further
  }

  if (body.messages.length > 20) {
    errors.push('too many messages (max 20)');
  }

  for (let i = 0; i < body.messages.length; i++) {
    const m = body.messages[i];

    if (!m || typeof m !== 'object') {
      errors.push(`messages[${i}] must be an object`);
      continue;
    }

    if (!['system', 'user', 'assistant'].includes(m.role)) {
      errors.push(`messages[${i}].role must be system, user, or assistant`);
    }

    // Content can be a string (text) or array (vision multimodal)
    if (typeof m.content === 'string') {
      if (m.content.length > MAX_TEXT_CONTENT_CHARS) {
        errors.push(`messages[${i}].content is too long (max ${MAX_TEXT_CONTENT_CHARS} chars)`);
      }
      // Check for injection in text messages
      if (m.role === 'user' && containsInjection(m.content)) {
        errors.push(`messages[${i}].content contains disallowed content`);
      }
    } else if (Array.isArray(m.content)) {
      // Vision multimodal content array
      for (let j = 0; j < m.content.length; j++) {
        const part = m.content[j];

        if (part.type === 'text') {
          if (typeof part.text === 'string' && part.text.length > MAX_TEXT_CONTENT_CHARS) {
            errors.push(`messages[${i}].content[${j}].text is too long`);
          }
          if (part.text && containsInjection(part.text)) {
            errors.push(`messages[${i}].content[${j}].text contains disallowed content`);
          }
        } else if (part.type === 'image_url') {
          // Validate base64 image
          const url = part.image_url?.url || '';
          if (!url.startsWith('data:image/')) {
            errors.push(`messages[${i}].content[${j}].image_url.url must be a data: URI`);
          } else if (url.length > MAX_BASE64_IMAGE_CHARS) {
            errors.push(`Image in messages[${i}].content[${j}] is too large (max ~2 MB)`);
          }
        }
      }
    } else if (m.content !== undefined) {
      errors.push(`messages[${i}].content must be a string or array`);
    }
  }

  // ── Token limits ──────────────────────────────────────────────────────────
  const maxTokens = body.max_tokens;
  if (maxTokens !== undefined) {
    if (typeof maxTokens !== 'number' || !Number.isInteger(maxTokens)) {
      errors.push('max_tokens must be an integer');
    } else if (maxTokens < MIN_TOKENS_ALLOWED || maxTokens > MAX_TOKENS_ALLOWED) {
      errors.push(`max_tokens must be between ${MIN_TOKENS_ALLOWED} and ${MAX_TOKENS_ALLOWED}`);
    }
  }

  return errors;
}

// ─── Build a clean Groq body (whitelist only known fields) ────────────────────
// This ensures we never accidentally forward unknown fields to Groq

function buildGroqBody(body, defaultMaxTokens, defaultTemp) {
  return {
    model:       body.model,
    messages:    body.messages,
    max_tokens:  body.max_tokens  ?? defaultMaxTokens,
    temperature: body.temperature ?? defaultTemp,
    top_p:       body.top_p       ?? 0.9,
    // Note: stream is intentionally NOT forwarded — streaming not supported
  };
}

// ─── Core Groq proxy — with automatic key rotation ───────────────────────────

async function callGroq(groqBody) {
  let lastError = null;

  for (let attempt = 0; attempt < GROQ_KEYS.length; attempt++) {
    const key      = getNextKey();
    const keyLabel = `Key ${((keyIndex - 1 + GROQ_KEYS.length) % GROQ_KEYS.length) + 1}`;

    let response;
    try {
      response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${key}`,
        },
        body:   JSON.stringify(groqBody),
        signal: AbortSignal.timeout(65_000),
      });
    } catch (fetchErr) {
      if (fetchErr.name === 'TimeoutError' || fetchErr.name === 'AbortError') {
        console.warn(`⏱️  ${keyLabel} timed out — trying next key...`);
        lastError = { name: 'TimeoutError', status: 504, code: 'TIMEOUT', message: 'AI request timed out.' };
      } else {
        console.warn(`🌐  ${keyLabel} network error: ${fetchErr.message}`);
        lastError = { status: 503, code: 'NETWORK_ERROR', message: 'Cannot reach AI service.' };
      }
      continue;
    }

    const text = await response.text();

    if (response.status === 429) {
      console.warn(`⚠️  ${keyLabel} rate limited (429) — trying next key...`);
      lastError = { status: 429, code: 'GROQ_RATE_LIMITED', message: 'AI rate limit hit — please wait.' };
      continue;
    }

    if (response.status === 401) {
      console.error(`❌  ${keyLabel} rejected by Groq (401) — check env vars`);
      lastError = { status: 502, code: 'GROQ_AUTH_FAILED', message: 'AI service authentication failed.' };
      continue;
    }

    if (!response.ok) {
      let errData = {};
      try { errData = JSON.parse(text); } catch {}
      console.warn(`⚠️  ${keyLabel} returned ${response.status}`);
      lastError = {
        status:  response.status >= 500 ? 502 : response.status,
        code:    'GROQ_ERROR',
        message: errData?.error?.message || `AI service error ${response.status}`,
      };
      continue;
    }

    console.log(`✅  ${keyLabel} succeeded`);
    return JSON.parse(text);
  }

  console.error(`❌  All ${GROQ_KEYS.length} key(s) failed. Last:`, lastError);
  throw lastError ?? {
    status:  503,
    code:    'ALL_KEYS_FAILED',
    message: `All AI keys are unavailable right now. Please try again in a few minutes.`,
  };
}

// ─── Shared route handler factory ─────────────────────────────────────────────
// All three routes (generate, analyse, svg) do the same thing — just
// different default max_tokens and temperature. This avoids copy-paste bugs.

function makeHandler(routeName, defaultMaxTokens, defaultTemp, isVision = false) {
  return async (req, res) => {
    try {
      const { deviceId, ...rest } = req.body;

      // ── Rate limit check ───────────────────────────────────────────────────
      const limit = checkCombinedLimit(deviceId, req.ip);
      if (!limit.allowed) {
        const minutes = Math.ceil(limit.retryAfterSec / 60);
        return res.status(429).json({
          error:         'QUOTA_EXHAUSTED',
          message:       `Too many requests. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`,
          retryAfterSec: limit.retryAfterSec,
        });
      }

      // ── Validate input ─────────────────────────────────────────────────────
      const errors = validateGroqBody(rest, isVision);
      if (errors.length > 0) {
        return res.status(400).json({ error: 'INVALID_REQUEST', details: errors });
      }

      const deviceLabel = typeof deviceId === 'string'
        ? deviceId.slice(0, 8)
        : 'unknown';

      console.log(`📡 ${routeName} | model: ${rest.model} | device: ${deviceLabel} | ip: ${req.ip}`);

      // ── Call Groq ──────────────────────────────────────────────────────────
      const groqBody = buildGroqBody(rest, defaultMaxTokens, defaultTemp);
      const data     = await callGroq(groqBody);

      res.json(data);
    } catch (err) {
      handleError(err, res, routeName);
    }
  };
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health check — no auth required (Render uses this to check if you are alive)
app.get('/health', (req, res) => {
  res.json({
    status:    'ok',
    service:   'thuto-backend',
    version:   '2.0',
    keys:      GROQ_KEYS.length,
    devices:   deviceStore.size,
    timestamp: new Date().toISOString(),
    uptime:    Math.floor(process.uptime()),
  });
});

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'Thuto Notes API v2.0' });
});

// Text generation (study notes, quiz questions)
app.post(
  '/api/generate',
  requireToken,
  makeHandler('/api/generate', 4096, 0.35, false),
);

// Vision analysis (homework photo)
app.post(
  '/api/analyse',
  requireToken,
  makeHandler('/api/analyse', 1500, 0.1, true),
);

// SVG generation
app.post(
  '/api/svg',
  requireToken,
  makeHandler('/api/svg', 2048, 0.5, false),
);

// ─── 404 ──────────────────────────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ error: 'NOT_FOUND', path: req.path });
});

// ─── Global Express error handler ─────────────────────────────────────────────

app.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS_BLOCKED', message: 'Origin not allowed.' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'PAYLOAD_TOO_LARGE', message: 'Request body too large (max 4 MB).' });
  }
  handleError(err, res, req.path);
});

// ─── Error formatter ──────────────────────────────────────────────────────────

function handleError(err, res, route) {
  if (err && err.status && err.code) {
    console.error(`❌  ${route} [${err.code}] ${err.message}`);
    return res.status(err.status).json({ error: err.code, message: err.message });
  }
  if (err && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
    return res.status(504).json({ error: 'TIMEOUT', message: 'AI request timed out. Try again.' });
  }
  if (err && (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND')) {
    return res.status(503).json({ error: 'NETWORK_ERROR', message: 'Cannot reach AI service.' });
  }
  console.error(`💥  ${route} unexpected error:`, err);
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Something went wrong.' });
}

// ─── Graceful shutdown ────────────────────────────────────────────────────────
// When Render restarts your server, it sends SIGTERM first.
// This gives in-flight requests up to 10 seconds to finish.

let isShuttingDown = false;

function gracefulShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`\n🛑  ${signal} received — shutting down gracefully...`);

  server.close(() => {
    console.log('✅  All connections closed. Exiting.');
    process.exit(0);
  });

  // Force-exit after 10 seconds if connections don't close
  setTimeout(() => {
    console.error('⚠️  Force-exiting after timeout');
    process.exit(1);
  }, 10_000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

// ─── Start ────────────────────────────────────────────────────────────────────

const server = app.listen(PORT, () => {
  console.log('');
  console.log('🚀  Thuto Notes backend v2.0 running');
  console.log(`📡  Port:         ${PORT}`);
  console.log(`🔒  Token auth:   enabled (${APP_TOKEN.length} chars)`);
  console.log(`🔑  Groq keys:    ${GROQ_KEYS.length} loaded (rotation active)`);
  console.log(`⚡  Rate limits:  ${DEVICE_LIMIT}/hr per device + ${DEVICE_LIMIT}/hr per IP`);
  console.log(`🛡️  Inj. filter:  ${INJECTION_PATTERNS.length} patterns`);
  console.log('');
});

export default app;