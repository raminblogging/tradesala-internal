/**
 * Internal Portal — Shared Utilities
 * ─────────────────────────────────────
 * Exports: corsHeaders, json, signJWT, verifyJWT, hashPassword, verifyPassword, logActivity
 */

// ── CORS ──────────────────────────────────────────────────────────
export function corsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '*';
  return {
    'Access-Control-Allow-Origin':  origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age':       '86400',
  };
}

// ── JSON RESPONSE ─────────────────────────────────────────────────
export function json(data, status = 200, request = null) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(request),
    },
  });
}

// ── JWT  (HMAC-SHA256 via Web Crypto — native in CF Workers) ──────
const JWT_ALG = { name: 'HMAC', hash: 'SHA-256' };

async function importKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    JWT_ALG,
    false,
    ['sign', 'verify']
  );
}

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function b64urlDecode(str) {
  return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
}

/**
 * Sign and return a JWT valid for 7 days.
 * @param {object} payload  - data to embed (avoid sensitive fields)
 * @param {string} secret   - JWT_SECRET env var
 */
export async function signJWT(payload, secret) {
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body   = b64url(new TextEncoder().encode(JSON.stringify({
    ...payload,
    iat: Date.now(),
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,   // 7 days
  })));
  const key = await importKey(secret);
  const sig = await crypto.subtle.sign(JWT_ALG, key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${b64url(sig)}`;
}

/**
 * Verify a JWT from the Authorization header.
 * Returns the decoded payload or null on failure.
 */
export async function verifyJWT(request, env) {
  try {
    const auth = request.headers.get('Authorization');
    if (!auth?.startsWith('Bearer ')) return null;

    const [header, body, sig] = auth.slice(7).split('.');
    if (!header || !body || !sig) return null;

    const key   = await importKey(env.JWT_SECRET);
    const valid = await crypto.subtle.verify(
      JWT_ALG,
      key,
      Uint8Array.from(b64urlDecode(sig), c => c.charCodeAt(0)),
      new TextEncoder().encode(`${header}.${body}`)
    );
    if (!valid) return null;

    const payload = JSON.parse(b64urlDecode(body));
    if (payload.exp < Date.now()) return null;   // expired

    return payload;
  } catch {
    return null;
  }
}

// ── PASSWORD  (PBKDF2-SHA256, 100 000 iterations) ─────────────────
/**
 * Hash a plain-text password.
 * Returns "saltHex:hashHex" string suitable for DB storage.
 */
export async function hashPassword(password) {
  const salt   = crypto.getRandomValues(new Uint8Array(16));
  const km     = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits   = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    km, 256
  );
  const hex = (arr) => Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex(salt)}:${hex(new Uint8Array(bits))}`;
}

/**
 * Verify a plain-text password against a stored "saltHex:hashHex" string.
 */
export async function verifyPassword(password, stored) {
  try {
    const [saltHex, hashHex] = stored.split(':');
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const km   = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
      km, 256
    );
    const testHex = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
    return testHex === hashHex;
  } catch {
    return false;
  }
}

// ── ACTIVITY LOGGER ───────────────────────────────────────────────
/**
 * Append a row to the activity_log table.
 * Non-critical — errors are swallowed so they never break a request.
 */
export async function logActivity(db, userId, type, description) {
  try {
    await db.prepare(
      `INSERT INTO activity_log (user_id, type, description, created_at)
       VALUES (?, ?, ?, ?)`
    ).bind(userId, type, description, new Date().toISOString()).run();
  } catch (e) {
    console.warn('[logActivity]', e?.message);
  }
}
