'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// Thuto Notes — Secure AI Proxy Backend  v4.4
// ─────────────────────────────────────────────────────────────────────────────

require('dotenv').config();

const express       = require('express');
const helmet        = require('helmet');
const cors          = require('cors');
const crypto        = require('crypto');
const admin         = require('firebase-admin');
const { rateLimit } = require('express-rate-limit');
const fetch         = require('node-fetch');

// ─── Config ───────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3001;

// Strip ALL whitespace — prevents stray newline/space in Render env editor
const APP_TOKEN = (process.env.APP_TOKEN || '').replace(/\s/g, '');

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID   || '';

// ─── Firebase Admin (optional) ───────────────────────────────────────────────

let firebaseReady = false;

try {
  const raw = (process.env.FIREBASE_SERVICE_ACCOUNT || '').trim();
  if (raw && raw.startsWith('{')) {
    const sa = JSON.parse(raw);
    if (sa.project_id && sa.private_key && sa.client_email) {
      admin.initializeApp({ credential: admin.credential.cert(sa) });
      firebaseReady = true;
      console.log('✅  Firebase Admin initialized — project:', sa.project_id);
    }
  } else if (raw) {
    console.warn('⚠️  FIREBASE_SERVICE_ACCOUNT present but not valid JSON');
  } else {
    console.warn('⚠️  FIREBASE_SERVICE_ACCOUNT not set — Firebase disabled (HMAC only)');
  }
} catch (err) {
  console.error('❌  Firebase init failed:', err.message);
}

// ─── Groq Key Rotation ────────────────────────────────────────────────────────

const GROQ_KEYS = [
  process.env.GROQ_KEY_1,
  process.env.GROQ_KEY_2,
  process.env.GROQ_KEY_3,
  process.env.GROQ_KEY_4,
].filter(k => typeof k === 'string' && k.trim().startsWith('gsk_') && k.length > 20)
 .map(k => k.trim());

// ─── Constants ────────────────────────────────────────────────────────────────

const MAX_TOKENS_ALLOWED     = 8192;
const MIN_TOKENS_ALLOWED     = 100;
const MAX_TEXT_CONTENT_CHARS = 12000;
const MAX_BASE64_IMAGE_CHARS = 2800000;
const MAX_DEVICE_STORE_SIZE  = 50000;

const DEVICE_HOURLY_LIMIT  = 20;
const DEVICE_DAILY_LIMIT   = 50;
const IP_HOURLY_LIMIT      = 60;
const HOUR_MS              = 60 * 60 * 1000;
const DAY_MS               = 24 * 60 * 60 * 1000;
const SIGNATURE_MAX_AGE_MS = 30000;
const CACHE_TTL_MS         = 24 * 60 * 60 * 1000;

// ─── Startup Checks ───────────────────────────────────────────────────────────

if (!APP_TOKEN || APP_TOKEN.length < 24) {
  console.error('❌  APP_TOKEN missing or too short (' + APP_TOKEN.length + ' chars). Exiting.');
  process.exit(1);
}
if (GROQ_KEYS.length === 0) {
  console.error('❌  No valid Groq keys found. Add GROQ_KEY_1 to environment variables.');
  process.exit(1);
}

// Log fingerprint — NEVER the full token
console.log('✅  APP_TOKEN: length=' + APP_TOKEN.length + ' prefix=' + APP_TOKEN.slice(0, 8) + '… suffix=…' + APP_TOKEN.slice(-4));
console.log('✅  Groq keys:', GROQ_KEYS.length);

// ─── Key Rotation ─────────────────────────────────────────────────────────────

let keyIndex = 0;
function getNextKey() {
  const key = GROQ_KEYS[keyIndex];
  keyIndex = (keyIndex + 1) % GROQ_KEYS.length;
  return key;
}

// ─── Allowed Models ───────────────────────────────────────────────────────────

const ALLOWED_MODELS = new Set([
  'llama-3.3-70b-versatile',
  'llama-3.1-8b-instant',
  'meta-llama/llama-4-scout-17b-16e-instruct',
  'llama-3.2-90b-vision-preview',
  'llama-3.2-11b-vision-preview',
]);

// ─── Express ──────────────────────────────────────────────────────────────────

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.set('trust proxy', 1);

// ─── CORS ─────────────────────────────────────────────────────────────────────
// For React Native apps (APK/AAB), ALLOWED_ORIGINS should be EMPTY.
// React Native does not send an Origin header. We filter out any
// localhost/exp:// values that were accidentally left from dev config.

const rawOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean)
  .filter(o => !o.includes('localhost') && !o.startsWith('exp://'));

const allowAll = rawOrigins.length === 0;

console.log('🌐  CORS:', allowAll ? 'allow all (React Native mode)' : rawOrigins.join(', '));

app.use(cors({
  origin: function(origin, cb) {
    if (!origin || allowAll || rawOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('CORS blocked: ' + origin));
  },
  methods:        ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-App-Token', 'X-Timestamp', 'X-Signature', 'X-Firebase-Token'],
}));

app.use(express.json({ limit: '4mb' }));

// ─── Global Rate Limiter ──────────────────────────────────────────────────────

app.use(rateLimit({
  windowMs: HOUR_MS, max: IP_HOURLY_LIMIT,
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: req => req.ip || 'unknown',
  message: { error: 'TOO_MANY_REQUESTS', message: 'Too many requests from this IP.' },
}));

// ─── Device Store ─────────────────────────────────────────────────────────────

const deviceStore = new Map();

function checkCombinedLimit(identifier, ip) {
  const now = Date.now();
  let hourly = { allowed: true }, daily = { allowed: true }, ipR = { allowed: true };

  if (identifier && identifier.length >= 4) {
    if (deviceStore.size >= MAX_DEVICE_STORE_SIZE) deviceStore.delete(deviceStore.keys().next().value);
    const id = identifier.slice(0, 128);

    const hKey = 'dh:' + id, hRec = deviceStore.get(hKey);
    if (!hRec || now > hRec.resetAt) deviceStore.set(hKey, { count: 1, resetAt: now + HOUR_MS });
    else if (hRec.count >= DEVICE_HOURLY_LIMIT) hourly = { allowed: false, reason: 'DEVICE_HOURLY', retryAfterSec: Math.ceil((hRec.resetAt - now) / 1000) };
    else hRec.count++;

    const dKey = 'dd:' + id, dRec = deviceStore.get(dKey);
    if (!dRec || now > dRec.resetAt) deviceStore.set(dKey, { count: 1, resetAt: now + DAY_MS });
    else if (dRec.count >= DEVICE_DAILY_LIMIT) daily = { allowed: false, reason: 'DEVICE_DAILY', retryAfterSec: Math.ceil((dRec.resetAt - now) / 1000) };
    else dRec.count++;
  }

  if (ip) {
    const iKey = 'ip:' + ip, iRec = deviceStore.get(iKey);
    if (!iRec || now > iRec.resetAt) deviceStore.set(iKey, { count: 1, resetAt: now + HOUR_MS });
    else if (iRec.count >= IP_HOURLY_LIMIT) ipR = { allowed: false, reason: 'IP', retryAfterSec: Math.ceil((iRec.resetAt - now) / 1000) };
    else iRec.count++;
  }

  return !hourly.allowed ? hourly : !daily.allowed ? daily : !ipR.allowed ? ipR : { allowed: true };
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of deviceStore) if (now > v.resetAt) deviceStore.delete(k);
}, HOUR_MS);

// ─── Response Cache ───────────────────────────────────────────────────────────

const responseCache = new Map();

function getCacheKey(body) {
  return crypto.createHash('sha256').update(JSON.stringify({ model: body.model, messages: body.messages })).digest('hex');
}
function getCached(key) {
  const e = responseCache.get(key);
  if (e && Date.now() < e.expiresAt) return e.data;
  if (e) responseCache.delete(key);
  return null;
}
function setCache(key, data) {
  if (responseCache.size > 10000) responseCache.delete(responseCache.keys().next().value);
  responseCache.set(key, { data, expiresAt: Date.now() + CACHE_TTL_MS });
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of responseCache) if (now > v.expiresAt) responseCache.delete(k);
}, 6 * HOUR_MS);

// ─── Telegram ─────────────────────────────────────────────────────────────────

function alertAbuse(ip, id, reason) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  fetch('https://api.telegram.org/bot' + TELEGRAM_BOT_TOKEN + '/sendMessage', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: '🚨 *Thuto Abuse*\nIP: `' + ip + '`\nID: `' + id.slice(0, 16) + '`\nReason: ' + reason, parse_mode: 'Markdown' }),
  }).catch(() => {});
}

// ─── HMAC ─────────────────────────────────────────────────────────────────────

function hmacSign(message, secret) {
  return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const len = Math.max(a.length, b.length);
  const aB  = Buffer.alloc(len); Buffer.from(a).copy(aB);
  const bB  = Buffer.alloc(len); Buffer.from(b).copy(bB);
  return crypto.timingSafeEqual(aB, bB);
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────

function requireToken(req, res, next) {
  // Strip whitespace from ALL incoming header values before comparing
  const token     = (req.headers['x-app-token']  || '').replace(/\s/g, '');
  const timestamp = (req.headers['x-timestamp']  || '').replace(/\s/g, '');
  const signature = (req.headers['x-signature']  || '').replace(/\s/g, '');

  if (!token) {
    console.warn('⚠️  MISSING TOKEN | ip:', req.ip);
    return res.status(401).json({ error: 'MISSING_TOKEN' });
  }

  if (!safeEqual(token, APP_TOKEN)) {
    // Detailed fingerprint log — helps diagnose mismatch without leaking tokens
    console.warn(
      '⚠️  TOKEN MISMATCH | ip:', req.ip,
      '| received len:', token.length, 'prefix:', token.slice(0, 8) + '… suffix:…' + token.slice(-4),
      '| expected len:', APP_TOKEN.length, 'prefix:', APP_TOKEN.slice(0, 8) + '… suffix:…' + APP_TOKEN.slice(-4)
    );
    return res.status(403).json({ error: 'AUTH_FAILED', message: 'Invalid app token.' });
  }

  if (!timestamp || isNaN(+timestamp)) {
    return res.status(401).json({ error: 'MISSING_TIMESTAMP' });
  }

  const age = Date.now() - parseInt(timestamp, 10);
  if (age > SIGNATURE_MAX_AGE_MS || age < -5000) {
    console.warn('⚠️  EXPIRED REQUEST | age:', age + 'ms | ip:', req.ip);
    return res.status(401).json({ error: 'REQUEST_EXPIRED', message: 'Request expired. Check device clock.' });
  }

  if (!signature) return res.status(401).json({ error: 'MISSING_SIGNATURE' });

  const expected = hmacSign(timestamp, APP_TOKEN);
  if (!safeEqual(signature, expected)) {
    console.warn(
      '⚠️  BAD SIGNATURE | ip:', req.ip,
      '| received prefix:', signature.slice(0, 8) + '…',
      '| expected prefix:', expected.slice(0, 8) + '…'
    );
    return res.status(403).json({ error: 'BAD_SIGNATURE' });
  }

  next();
}

function verifyFirebaseToken(req, res, next) {
  if (!firebaseReady) { req.firebaseUid = null; return next(); }
  const token = (req.headers['x-firebase-token'] || '').trim();
  if (!token) { req.firebaseUid = null; return next(); }

  admin.auth().verifyIdToken(token)
    .then(decoded => { req.firebaseUid = decoded.uid; next(); })
    .catch(err => {
      console.warn('⚠️  Firebase token invalid (continuing):', err.message);
      req.firebaseUid = null; next();
    });
}

// ─── Injection Detection ──────────────────────────────────────────────────────

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i, /system\s*prompt/i,
  /you\s+are\s+now\s+(a|an)/i, /forget\s+(everything|all)/i,
  /jailbreak/i, /DAN\s+mode/i, /override\s+(safety|filter)/i,
  /sudo\s+mode/i, /act\s+as\s+(a|an)\s+/i,
];
function containsInjection(text) {
  return INJECTION_PATTERNS.some(p => p.test(text));
}

// ─── Validation ───────────────────────────────────────────────────────────────

function validateGroqBody(body) {
  const errors = [];
  if (!body.model || !ALLOWED_MODELS.has(body.model)) errors.push('invalid or missing model');
  if (!Array.isArray(body.messages) || body.messages.length === 0) { errors.push('messages required'); return errors; }
  if (body.messages.length > 20) errors.push('too many messages');

  for (let i = 0; i < body.messages.length; i++) {
    const m = body.messages[i];
    if (!m || !['system', 'user', 'assistant'].includes(m.role)) errors.push('messages[' + i + '] invalid role');
    if (typeof m.content === 'string') {
      if (m.content.length > MAX_TEXT_CONTENT_CHARS) errors.push('messages[' + i + '].content too long');
      if (m.role === 'user' && containsInjection(m.content)) errors.push('messages[' + i + '] disallowed content');
    } else if (Array.isArray(m.content)) {
      for (let j = 0; j < m.content.length; j++) {
        const p = m.content[j];
        if (p.type === 'text' && p.text) {
          if (p.text.length > MAX_TEXT_CONTENT_CHARS) errors.push('part ' + j + ' text too long');
          if (containsInjection(p.text)) errors.push('part ' + j + ' disallowed');
        } else if (p.type === 'image_url') {
          const url = (p.image_url && p.image_url.url) || '';
          if (!url.startsWith('data:image/')) errors.push('part ' + j + ' invalid image');
          else if (url.length > MAX_BASE64_IMAGE_CHARS) errors.push('part ' + j + ' image too large');
        }
      }
    }
  }

  if (body.max_tokens !== undefined) {
    if (!Number.isInteger(body.max_tokens) || body.max_tokens < MIN_TOKENS_ALLOWED || body.max_tokens > MAX_TOKENS_ALLOWED)
      errors.push('max_tokens must be ' + MIN_TOKENS_ALLOWED + '–' + MAX_TOKENS_ALLOWED);
  }
  return errors;
}

// ─── Groq Call ────────────────────────────────────────────────────────────────

async function callGroq(groqBody) {
  let lastError = null;
  for (let attempt = 0; attempt < GROQ_KEYS.length; attempt++) {
    const key   = getNextKey();
    const label = 'Key ' + (((keyIndex - 1 + GROQ_KEYS.length) % GROQ_KEYS.length) + 1);
    let res;
    try {
      res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
        body: JSON.stringify(groqBody),
        signal: AbortSignal.timeout(65000),
      });
    } catch (e) {
      console.warn('⏱️ ', label, 'fetch failed:', e.message);
      lastError = { status: 503, code: 'NETWORK_ERROR', message: 'Cannot reach AI service.' }; continue;
    }

    const text = await res.text();
    if (res.status === 429) { console.warn('⚠️ ', label, 'rate limited'); lastError = { status: 429, code: 'GROQ_RATE_LIMITED', message: 'AI rate limit hit.' }; continue; }
    if (res.status === 401) { console.error('❌ ', label, 'auth failed'); lastError = { status: 502, code: 'GROQ_AUTH_FAILED', message: 'AI auth failed.' }; continue; }
    if (!res.ok) {
      let d = {}; try { d = JSON.parse(text); } catch (_) {}
      lastError = { status: res.status >= 500 ? 502 : res.status, code: 'GROQ_ERROR', message: (d.error && d.error.message) || 'Groq error ' + res.status }; continue;
    }
    console.log('✅ ', label, 'succeeded');
    return JSON.parse(text);
  }
  throw lastError || { status: 503, code: 'ALL_KEYS_FAILED', message: 'All AI keys unavailable.' };
}

// ─── Handler Factory ──────────────────────────────────────────────────────────

function makeHandler(route, maxTokens, temp, isVision) {
  return async function(req, res) {
    try {
      const body     = req.body;
      const deviceId = body.deviceId;
      const rest     = Object.assign({}, body);
      delete rest.deviceId;

      const rateLimitId = req.firebaseUid || deviceId || 'unknown';
      const limit = checkCombinedLimit(rateLimitId, req.ip);
      if (!limit.allowed) {
        const mins = Math.ceil(limit.retryAfterSec / 60);
        alertAbuse(req.ip, rateLimitId, limit.reason);
        return res.status(429).json({
          error: 'QUOTA_EXHAUSTED',
          message: limit.reason === 'DEVICE_DAILY' ? 'Daily limit reached. Try again tomorrow.' : 'Too many requests. Try again in ' + mins + ' minute(s).',
          retryAfterSec: limit.retryAfterSec,
        });
      }

      const errors = validateGroqBody(rest);
      if (errors.length > 0) return res.status(400).json({ error: 'INVALID_REQUEST', details: errors });

      const groqBody = {
        model:       rest.model,
        messages:    rest.messages,
        max_tokens:  rest.max_tokens  !== undefined ? rest.max_tokens  : maxTokens,
        temperature: rest.temperature !== undefined ? rest.temperature : temp,
        top_p:       rest.top_p       !== undefined ? rest.top_p       : 0.9,
      };

      console.log('📡', route, '| model:', rest.model, '| id:', rateLimitId.slice(0, 8), '| auth:', req.firebaseUid ? 'HMAC+FB' : 'HMAC');

      if (!isVision) {
        const cKey = getCacheKey(groqBody), cached = getCached(cKey);
        if (cached) { console.log('💾  Cache hit'); return res.json(cached); }
        const data = await callGroq(groqBody);
        setCache(cKey, data);
        return res.json(data);
      }
      return res.json(await callGroq(groqBody));
    } catch (err) {
      handleError(err, res, route);
    }
  };
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => res.json({
  status: 'ok', version: '4.4', firebase: firebaseReady,
  keys: GROQ_KEYS.length, devices: deviceStore.size, cache: responseCache.size,
  uptime: Math.floor(process.uptime()), cors: allowAll ? 'allow-all' : rawOrigins,
  token_len: APP_TOKEN.length, token_prefix: APP_TOKEN.slice(0, 8) + '…',
}));

app.get('/', (_req, res) => res.json({ status: 'ok', service: 'Thuto Notes API v4.4' }));

app.get('/api/status', (_req, res) => {
  const maintenance = process.env.MAINTENANCE || '';
  res.json({ operational: !maintenance, message: maintenance || null, version: '4.4', firebase: firebaseReady });
});

app.post('/api/generate', requireToken, verifyFirebaseToken, makeHandler('/api/generate', 4096, 0.35, false));
app.post('/api/analyse',  requireToken, verifyFirebaseToken, makeHandler('/api/analyse',  1500, 0.1,  true));
app.post('/api/svg',      requireToken, verifyFirebaseToken, makeHandler('/api/svg',      2048, 0.5,  false));

app.use((req, res) => res.status(404).json({ error: 'NOT_FOUND', path: req.path }));

app.use((err, req, res, _next) => {
  if (err.message && err.message.startsWith('CORS blocked')) return res.status(403).json({ error: 'CORS_BLOCKED' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'PAYLOAD_TOO_LARGE' });
  handleError(err, res, req.path);
});

function handleError(err, res, route) {
  if (err && err.status && err.code) {
    console.error('❌ ', route, '[' + err.code + ']', err.message);
    return res.status(err.status).json({ error: err.code, message: err.message });
  }
  if (err && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
    return res.status(504).json({ error: 'TIMEOUT', message: 'AI timed out. Try again.' });
  }
  console.error('💥 ', route, 'unexpected:', err);
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Something went wrong.' });
}

// ─── Shutdown ─────────────────────────────────────────────────────────────────

let shuttingDown = false;
function shutdown(sig) {
  if (shuttingDown) return; shuttingDown = true;
  console.log('\n🛑 ', sig, '— shutting down...');
  server.close(() => { console.log('✅  Done.'); process.exit(0); });
  setTimeout(() => process.exit(1), 10000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

// ─── Start ────────────────────────────────────────────────────────────────────

const server = app.listen(PORT, () => {
  console.log('');
  console.log('🚀  Thuto Notes v4.4 — port', PORT);
  console.log('🔒  HMAC:', SIGNATURE_MAX_AGE_MS / 1000 + 's window');
  console.log('🔥  Firebase:', firebaseReady ? 'optional ✅' : 'disabled ⚠️');
  console.log('🌐  CORS:', allowAll ? 'allow-all' : rawOrigins.join(', '));
  console.log('🔑  Keys:', GROQ_KEYS.length);
  console.log('');
});

module.exports = server;
