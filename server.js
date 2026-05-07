'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// Thuto Notes — Secure AI Proxy Backend  v4.3
// Pure CommonJS (require).  No TypeScript.  Deploy directly on Render.
// Start command: node server.js
//
// v4.3 changes:
//   - ALLOWED_ORIGINS: empty string now correctly treated as "allow all"
//     (fixes Android APK rejections when Render env has localhost values)
//   - requireToken: strip ALL whitespace/control chars from token before compare
//   - Enhanced 403 logging to show exactly what token the server received vs expected
//   - CORS preflight explicitly handled for React Native clients
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

const PORT      = process.env.PORT      || 3001;

// Strip ALL whitespace (spaces, tabs, newlines, carriage returns) from APP_TOKEN.
// This is the most common cause of "token rejected" — a stray newline in the
// Render env var editor pastes invisibly and breaks safeEqual().
const APP_TOKEN = (process.env.APP_TOKEN || '').replace(/\s/g, '');

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID   || '';

// ─── Firebase Admin ───────────────────────────────────────────────────────────

let firebaseReady = false;

try {
  const raw = (process.env.FIREBASE_SERVICE_ACCOUNT || '').trim();

  if (!raw) {
    console.warn('⚠️  FIREBASE_SERVICE_ACCOUNT is empty — Firebase verification disabled.');
  } else if (!raw.startsWith('{')) {
    console.error('❌  FIREBASE_SERVICE_ACCOUNT does not look like JSON (must start with {)');
  } else {
    const serviceAccount = JSON.parse(raw);
    if (!serviceAccount.project_id || !serviceAccount.private_key || !serviceAccount.client_email) {
      console.error('❌  FIREBASE_SERVICE_ACCOUNT JSON is missing required fields.');
    } else {
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
      firebaseReady = true;
      console.log('✅  Firebase Admin initialized — project: ' + serviceAccount.project_id);
    }
  }
} catch (err) {
  console.error('❌  Firebase Admin init failed:', err.message);
}

// ─── Groq Key Rotation ────────────────────────────────────────────────────────

const GROQ_KEYS = [
  process.env.GROQ_KEY_1,
  process.env.GROQ_KEY_2,
  process.env.GROQ_KEY_3,
  process.env.GROQ_KEY_4,
].filter(function(k) {
  return typeof k === 'string' && k.trim().startsWith('gsk_') && k.length > 20;
}).map(function(k) { return k.trim(); });

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

if (!APP_TOKEN) {
  console.error('❌  APP_TOKEN is not set. Add it to Render environment variables.');
  process.exit(1);
}
if (APP_TOKEN.length < 24) {
  console.error('❌  APP_TOKEN is too short (' + APP_TOKEN.length + ' chars) — must be at least 24 characters.');
  process.exit(1);
}

const WEAK_TOKENS = new Set(['beastnotes2025', 'changeme', 'secret', 'password', 'token']);
if (WEAK_TOKENS.has(APP_TOKEN.toLowerCase())) {
  console.error('❌  APP_TOKEN looks like an example value. Use a real random token.');
  process.exit(1);
}
if (GROQ_KEYS.length === 0) {
  console.error('❌  No valid Groq keys found. Add GROQ_KEY_1 to your environment variables.');
  process.exit(1);
}

// ── Print token fingerprint for debugging (NEVER print the full token in logs) ─
console.log('✅  APP_TOKEN loaded: length=' + APP_TOKEN.length + ' prefix=' + APP_TOKEN.slice(0, 8) + '…');
console.log('✅  ' + GROQ_KEYS.length + ' Groq key(s) loaded');

// ─── Key Rotation ─────────────────────────────────────────────────────────────

var keyIndex = 0;

function getNextKey() {
  var key = GROQ_KEYS[keyIndex];
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

// ─── Express App ──────────────────────────────────────────────────────────────

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.set('trust proxy', 1);

// ─── CORS ─────────────────────────────────────────────────────────────────────
//
// CRITICAL FIX (v4.3):
//
// The Render dashboard had ALLOWED_ORIGINS=http://localhost:8081,exp://localhost:8081
// React Native apps running on real Android devices send requests WITHOUT an
// Origin header. With non-empty allowedOrigins, the old code correctly passed
// `!origin` requests through — but some Android HTTP stacks DO send an Origin
// header (e.g. "null" or the app package name), which then fails the allowedOrigins
// check and returns a CORS error that manifests as a network/auth failure.
//
// THE FIX: For a React Native backend, ALLOWED_ORIGINS should always be empty.
// We now filter out localhost/expo origins since they're dev-only and don't
// apply to production APK builds at all.
//
// To keep things simple and correct: if ALL origins in the list are localhost
// or exp:// (i.e. dev-only), we treat it as "allow all" for production.

const rawOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(function(s) { return s.trim(); })
  .filter(Boolean);

// Keep only non-localhost, non-exp:// origins for the production allowlist
const productionOrigins = rawOrigins.filter(function(o) {
  return !o.includes('localhost') && !o.startsWith('exp://');
});

// If nothing is left after filtering dev origins, allow all (correct for RN APK)
const allowedOrigins = productionOrigins;
const allowAll       = allowedOrigins.length === 0;

console.log('🌐  CORS: ' + (allowAll
  ? 'allow all origins (correct for React Native)'
  : 'restricted to: ' + allowedOrigins.join(', ')));

app.use(cors({
  origin: function(origin, callback) {
    // No origin header = React Native on real device — always allow
    if (!origin)       return callback(null, true);
    // Allow all configured
    if (allowAll)      return callback(null, true);
    // Check allowlist
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS: ' + origin));
  },
  methods:        ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'X-App-Token',
    'X-Timestamp',
    'X-Signature',
    'X-Firebase-Token',
  ],
}));

app.use(express.json({ limit: '4mb' }));

// ─── Global IP Rate Limiter ───────────────────────────────────────────────────

const globalLimiter = rateLimit({
  windowMs:        HOUR_MS,
  max:             IP_HOURLY_LIMIT,
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator:    function(req) { return req.ip || 'unknown'; },
  message:         { error: 'TOO_MANY_REQUESTS', message: 'Too many requests from this IP.' },
});

app.use(globalLimiter);

// ─── Device / UID Store ───────────────────────────────────────────────────────

const deviceStore = new Map();

function checkCombinedLimit(identifier, ip) {
  const now = Date.now();
  var hourlyResult = { allowed: true };
  var dailyResult  = { allowed: true };
  var ipResult     = { allowed: true };

  if (identifier && identifier.length >= 4) {
    if (deviceStore.size >= MAX_DEVICE_STORE_SIZE) {
      deviceStore.delete(deviceStore.keys().next().value);
    }

    var id = identifier.slice(0, 128);

    var hKey = 'dh:' + id;
    var hRec = deviceStore.get(hKey);
    if (!hRec || now > hRec.resetAt) {
      deviceStore.set(hKey, { count: 1, resetAt: now + HOUR_MS });
    } else if (hRec.count >= DEVICE_HOURLY_LIMIT) {
      hourlyResult = { allowed: false, reason: 'DEVICE_HOURLY', retryAfterSec: Math.ceil((hRec.resetAt - now) / 1000) };
    } else {
      hRec.count++;
    }

    var dKey = 'dd:' + id;
    var dRec = deviceStore.get(dKey);
    if (!dRec || now > dRec.resetAt) {
      deviceStore.set(dKey, { count: 1, resetAt: now + DAY_MS });
    } else if (dRec.count >= DEVICE_DAILY_LIMIT) {
      dailyResult = { allowed: false, reason: 'DEVICE_DAILY', retryAfterSec: Math.ceil((dRec.resetAt - now) / 1000) };
    } else {
      dRec.count++;
    }
  }

  if (ip) {
    var iKey = 'ip:' + ip;
    var iRec = deviceStore.get(iKey);
    if (!iRec || now > iRec.resetAt) {
      deviceStore.set(iKey, { count: 1, resetAt: now + HOUR_MS });
    } else if (iRec.count >= IP_HOURLY_LIMIT) {
      ipResult = { allowed: false, reason: 'IP', retryAfterSec: Math.ceil((iRec.resetAt - now) / 1000) };
    } else {
      iRec.count++;
    }
  }

  if (!hourlyResult.allowed) return hourlyResult;
  if (!dailyResult.allowed)  return dailyResult;
  if (!ipResult.allowed)     return ipResult;
  return { allowed: true };
}

setInterval(function() {
  const now = Date.now();
  for (const [k, v] of deviceStore) {
    if (now > v.resetAt) deviceStore.delete(k);
  }
  console.log('🧹  Store cleaned. Entries: ' + deviceStore.size);
}, HOUR_MS);

// ─── Response Cache ───────────────────────────────────────────────────────────

const responseCache = new Map();

function getCacheKey(body) {
  return crypto.createHash('sha256')
    .update(JSON.stringify({ model: body.model, messages: body.messages }))
    .digest('hex');
}

function getCached(key) {
  var e = responseCache.get(key);
  if (e && Date.now() < e.expiresAt) return e.data;
  if (e) responseCache.delete(key);
  return null;
}

function setCache(key, data) {
  if (responseCache.size > 10000) responseCache.delete(responseCache.keys().next().value);
  responseCache.set(key, { data: data, expiresAt: Date.now() + CACHE_TTL_MS });
}

setInterval(function() {
  const now = Date.now();
  for (const [k, v] of responseCache) {
    if (now > v.expiresAt) responseCache.delete(k);
  }
}, 6 * HOUR_MS);

// ─── Telegram Alerting ────────────────────────────────────────────────────────

function alertAbuse(ip, id, reason) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  fetch('https://api.telegram.org/bot' + TELEGRAM_BOT_TOKEN + '/sendMessage', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id:    TELEGRAM_CHAT_ID,
      text:       '🚨 *Thuto — Abuse*\nIP: `' + ip + '`\nID: `' + id.slice(0, 16) + '`\nReason: ' + reason + '\nTime: ' + new Date().toISOString(),
      parse_mode: 'Markdown',
    }),
  }).catch(function() {});
}

// ─── HMAC Signing ─────────────────────────────────────────────────────────────

function hmacSign(message, secret) {
  return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  // Constant-time compare — pad shorter string to avoid length leak
  var maxLen = Math.max(a.length, b.length);
  var aB = Buffer.alloc(maxLen);
  var bB = Buffer.alloc(maxLen);
  Buffer.from(a).copy(aB);
  Buffer.from(b).copy(bB);
  return crypto.timingSafeEqual(aB, bB);
}

// ─── Middleware 1: HMAC Token Check ──────────────────────────────────────────
//
// v4.3 FIX: Strip whitespace from the incoming token before comparing.
// Android APK builds on some devices add trailing whitespace or a newline
// to header values due to HTTP client quirks. Stripping ensures the compare
// works even if the app sends "TOKEN\n" vs the server's "TOKEN".

function requireToken(req, res, next) {
  // Strip all whitespace from received values
  var token     = (req.headers['x-app-token']  || '').replace(/\s/g, '');
  var timestamp = (req.headers['x-timestamp']  || '').trim();
  var signature = (req.headers['x-signature']  || '').trim();

  if (!token) {
    console.warn('⚠️  Missing X-App-Token | ip: ' + req.ip);
    return res.status(401).json({ error: 'MISSING_TOKEN' });
  }

  if (!safeEqual(token, APP_TOKEN)) {
    // Log a fingerprint to help diagnose mismatches WITHOUT leaking full tokens
    console.warn('⚠️  Token mismatch | ip: ' + req.ip
      + ' | received: len=' + token.length + ' prefix=' + token.slice(0, 8) + '…'
      + ' | expected: len=' + APP_TOKEN.length + ' prefix=' + APP_TOKEN.slice(0, 8) + '…');
    return res.status(403).json({ error: 'AUTH_FAILED', message: 'Invalid app token.' });
  }

  if (!timestamp || isNaN(+timestamp)) {
    return res.status(401).json({ error: 'MISSING_TIMESTAMP' });
  }

  var age = Date.now() - parseInt(timestamp, 10);
  if (age > SIGNATURE_MAX_AGE_MS || age < -5000) {
    console.warn('⚠️  Expired request | age: ' + age + 'ms | ip: ' + req.ip);
    return res.status(401).json({
      error:   'REQUEST_EXPIRED',
      message: 'Request has expired. Check device clock.',
    });
  }

  if (!signature) {
    return res.status(401).json({ error: 'MISSING_SIGNATURE' });
  }

  var expected = hmacSign(timestamp, APP_TOKEN);
  if (!safeEqual(signature, expected)) {
    console.warn('⚠️  Bad HMAC signature | ip: ' + req.ip
      + ' | received prefix: ' + signature.slice(0, 8) + '…'
      + ' | expected prefix: ' + expected.slice(0, 8) + '…');
    return res.status(403).json({ error: 'BAD_SIGNATURE' });
  }

  next();
}

// ─── Middleware 2: Firebase Token Check (OPTIONAL) ───────────────────────────

function verifyFirebaseToken(req, res, next) {
  if (!firebaseReady) return next();

  var token = (req.headers['x-firebase-token'] || '').trim();

  if (!token) {
    req.firebaseUid  = null;
    req.firebaseAnon = false;
    return next();
  }

  admin.auth().verifyIdToken(token)
    .then(function(decoded) {
      req.firebaseUid  = decoded.uid;
      req.firebaseAnon = decoded.firebase && decoded.firebase.sign_in_provider === 'anonymous';
      next();
    })
    .catch(function(err) {
      console.warn('⚠️  Firebase token invalid — HMAC-only | ip: ' + req.ip + ' | ' + err.message);
      req.firebaseUid  = null;
      req.firebaseAnon = false;
      next();
    });
}

// ─── Injection Detection ──────────────────────────────────────────────────────

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
  return INJECTION_PATTERNS.some(function(p) { return p.test(text); });
}

// ─── Input Validation ─────────────────────────────────────────────────────────

function validateGroqBody(body) {
  var errors = [];

  if (!body.model || typeof body.model !== 'string') {
    errors.push('model must be a string');
  } else if (!ALLOWED_MODELS.has(body.model)) {
    errors.push('model "' + body.model + '" is not allowed');
  }

  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    errors.push('messages must be a non-empty array');
    return errors;
  }

  if (body.messages.length > 20) errors.push('too many messages (max 20)');

  for (var i = 0; i < body.messages.length; i++) {
    var m = body.messages[i];
    if (!m || typeof m !== 'object') { errors.push('messages[' + i + '] must be an object'); continue; }
    if (!['system', 'user', 'assistant'].includes(m.role)) {
      errors.push('messages[' + i + '].role must be system, user, or assistant');
    }
    if (typeof m.content === 'string') {
      if (m.content.length > MAX_TEXT_CONTENT_CHARS) errors.push('messages[' + i + '].content too long');
      if (m.role === 'user' && containsInjection(m.content)) errors.push('messages[' + i + '].content has disallowed content');
    } else if (Array.isArray(m.content)) {
      for (var j = 0; j < m.content.length; j++) {
        var p = m.content[j];
        if (p.type === 'text') {
          if (p.text && p.text.length > MAX_TEXT_CONTENT_CHARS) errors.push('messages[' + i + '][' + j + '].text too long');
          if (p.text && containsInjection(p.text))             errors.push('messages[' + i + '][' + j + '].text disallowed');
        } else if (p.type === 'image_url') {
          var url = (p.image_url && p.image_url.url) || '';
          if (!url.startsWith('data:image/'))          errors.push('messages[' + i + '][' + j + '].image_url must be data URI');
          else if (url.length > MAX_BASE64_IMAGE_CHARS) errors.push('messages[' + i + '][' + j + '] image too large');
        }
      }
    }
  }

  if (body.max_tokens !== undefined) {
    if (!Number.isInteger(body.max_tokens)) errors.push('max_tokens must be integer');
    else if (body.max_tokens < MIN_TOKENS_ALLOWED || body.max_tokens > MAX_TOKENS_ALLOWED) {
      errors.push('max_tokens must be ' + MIN_TOKENS_ALLOWED + '–' + MAX_TOKENS_ALLOWED);
    }
  }

  return errors;
}

// ─── Build Groq Body ──────────────────────────────────────────────────────────

function buildGroqBody(body, maxTokens, temp) {
  return {
    model:       body.model,
    messages:    body.messages,
    max_tokens:  body.max_tokens  !== undefined ? body.max_tokens  : maxTokens,
    temperature: body.temperature !== undefined ? body.temperature : temp,
    top_p:       body.top_p       !== undefined ? body.top_p       : 0.9,
  };
}

// ─── Call Groq with Key Rotation ─────────────────────────────────────────────

async function callGroq(groqBody) {
  var lastError = null;

  for (var attempt = 0; attempt < GROQ_KEYS.length; attempt++) {
    var key   = getNextKey();
    var label = 'Key ' + (((keyIndex - 1 + GROQ_KEYS.length) % GROQ_KEYS.length) + 1);
    var res;

    try {
      res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method:  'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': 'Bearer ' + key,
        },
        body:   JSON.stringify(groqBody),
        signal: AbortSignal.timeout(65000),
      });
    } catch (e) {
      console.warn('⏱️  ' + label + ' fetch failed:', e.message);
      lastError = { status: 503, code: 'NETWORK_ERROR', message: 'Cannot reach AI service.' };
      continue;
    }

    var text = await res.text();

    if (res.status === 429) {
      console.warn('⚠️  ' + label + ' rate limited');
      lastError = { status: 429, code: 'GROQ_RATE_LIMITED', message: 'AI rate limit hit.' };
      continue;
    }
    if (res.status === 401) {
      console.error('❌  ' + label + ' auth failed');
      lastError = { status: 502, code: 'GROQ_AUTH_FAILED', message: 'AI auth failed.' };
      continue;
    }
    if (!res.ok) {
      var d = {};
      try { d = JSON.parse(text); } catch (_) {}
      lastError = {
        status:  res.status >= 500 ? 502 : res.status,
        code:    'GROQ_ERROR',
        message: (d.error && d.error.message) || ('Groq error ' + res.status),
      };
      continue;
    }

    console.log('✅  ' + label + ' succeeded');
    return JSON.parse(text);
  }

  throw lastError || { status: 503, code: 'ALL_KEYS_FAILED', message: 'All AI keys unavailable. Try again later.' };
}

// ─── Route Handler Factory ────────────────────────────────────────────────────

function makeHandler(route, maxTokens, temp, isVision) {
  return async function(req, res) {
    try {
      var body     = req.body;
      var deviceId = body.deviceId;
      var rest     = Object.assign({}, body);
      delete rest.deviceId;

      var rateLimitId = req.firebaseUid || deviceId || 'unknown';

      var limit = checkCombinedLimit(rateLimitId, req.ip);
      if (!limit.allowed) {
        var mins   = Math.ceil(limit.retryAfterSec / 60);
        var reason = limit.reason === 'DEVICE_DAILY'
          ? 'Daily limit reached. Try again tomorrow.'
          : 'Too many requests. Try again in ' + mins + ' minute' + (mins === 1 ? '' : 's') + '.';
        alertAbuse(req.ip, rateLimitId, 'Rate limit: ' + limit.reason);
        return res.status(429).json({
          error:         'QUOTA_EXHAUSTED',
          message:       reason,
          retryAfterSec: limit.retryAfterSec,
        });
      }

      var errors = validateGroqBody(rest);
      if (errors.length > 0) return res.status(400).json({ error: 'INVALID_REQUEST', details: errors });

      var authMode = req.firebaseUid ? 'HMAC+Firebase' : 'HMAC-only';
      console.log('📡 ' + route + ' | model: ' + rest.model + ' | uid: ' + rateLimitId.slice(0, 8) + ' | auth: ' + authMode);

      var groqBody = buildGroqBody(rest, maxTokens, temp);

      if (!isVision) {
        var cKey   = getCacheKey(groqBody);
        var cached = getCached(cKey);
        if (cached) { console.log('💾  Cache hit'); return res.json(cached); }
        var data = await callGroq(groqBody);
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

app.get('/health', function(_req, res) {
  return res.json({
    status:   'ok',
    version:  '4.3',
    firebase: firebaseReady,
    keys:     GROQ_KEYS.length,
    devices:  deviceStore.size,
    cache:    responseCache.size,
    uptime:   Math.floor(process.uptime()),
    cors:     allowAll ? 'allow-all' : allowedOrigins,
    token_len: APP_TOKEN.length,
    token_prefix: APP_TOKEN.slice(0, 8) + '…',
  });
});

app.get('/', function(_req, res) {
  return res.json({ status: 'ok', service: 'Thuto Notes API v4.3' });
});

app.get('/api/status', function(_req, res) {
  var maintenance = process.env.MAINTENANCE || '';
  return res.json({
    operational: !maintenance,
    message:     maintenance || null,
    version:     '4.3',
    firebase:    firebaseReady,
  });
});

app.post('/api/generate', requireToken, verifyFirebaseToken, makeHandler('/api/generate', 4096, 0.35, false));
app.post('/api/analyse',  requireToken, verifyFirebaseToken, makeHandler('/api/analyse',  1500, 0.1,  true));
app.post('/api/svg',      requireToken, verifyFirebaseToken, makeHandler('/api/svg',      2048, 0.5,  false));

// ─── 404 ──────────────────────────────────────────────────────────────────────

app.use(function(req, res) {
  return res.status(404).json({ error: 'NOT_FOUND', path: req.path });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────

app.use(function(err, req, res, _next) {
  if (err.message && err.message.startsWith('Not allowed by CORS')) {
    return res.status(403).json({ error: 'CORS_BLOCKED', origin: err.message });
  }
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'PAYLOAD_TOO_LARGE' });
  handleError(err, res, req.path);
});

// ─── Error Formatter ──────────────────────────────────────────────────────────

function handleError(err, res, route) {
  if (err && err.status && err.code) {
    console.error('❌  ' + route + ' [' + err.code + '] ' + err.message);
    return res.status(err.status).json({ error: err.code, message: err.message });
  }
  if (err && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
    return res.status(504).json({ error: 'TIMEOUT', message: 'AI timed out. Try again.' });
  }
  console.error('💥  ' + route + ' unexpected:', err);
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Something went wrong.' });
}

// ─── Graceful Shutdown ────────────────────────────────────────────────────────

var shuttingDown = false;

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('\n🛑  ' + signal + ' — shutting down...');
  server.close(function() { console.log('✅  Done.'); process.exit(0); });
  setTimeout(function() { process.exit(1); }, 10000);
}

process.on('SIGTERM', function() { shutdown('SIGTERM'); });
process.on('SIGINT',  function() { shutdown('SIGINT'); });

// ─── Start ────────────────────────────────────────────────────────────────────

const server = app.listen(PORT, function() {
  console.log('');
  console.log('🚀  Thuto Notes backend v4.3 running on port ' + PORT);
  console.log('🔒  HMAC signing: REQUIRED (' + (SIGNATURE_MAX_AGE_MS / 1000) + 's window)');
  console.log('🔥  Firebase:     ' + (firebaseReady ? 'OPTIONAL ✅' : 'not configured ⚠️'));
  console.log('🌐  CORS:         ' + (allowAll ? 'allow all (React Native mode)' : allowedOrigins.join(', ')));
  console.log('🔑  Groq keys:    ' + GROQ_KEYS.length);
  console.log('');
});

module.exports = server;
