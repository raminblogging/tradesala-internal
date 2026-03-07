/**
 * Internal Portal — Cloudflare Worker (Single File)
 * All modules combined into one file for Cloudflare dashboard deployment.
 * Timezone: Asia/Kolkata (IST, UTC+5:30)
 */

// ── IST HELPERS ───────────────────────────────────────────────────
/** Returns today's date in IST as "YYYY-MM-DD" */
function istDateStr() {
  return new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
}
/** Returns current IST datetime string for DB storage e.g. "2024-03-07T14:30:00" */
function istNow() {
  return new Date().toLocaleString('sv-SE', { timeZone: 'Asia/Kolkata' }).replace(' ', 'T');
}
/** Formats a stored datetime string to IST time display e.g. "02:30 PM" */
function fmtISTTime(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit' });
}

// ═══════════════════════════════════════════════════════════════════
// UTILS
// ═══════════════════════════════════════════════════════════════════

function corsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '*';
  return {
    'Access-Control-Allow-Origin':  origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age':       '86400',
  };
}

function json(data, status = 200, request = null) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(request),
    },
  });
}

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

async function signJWT(payload, secret) {
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body   = b64url(new TextEncoder().encode(JSON.stringify({
    ...payload,
    iat: Date.now(),
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  })));
  const key = await importKey(secret);
  const sig = await crypto.subtle.sign(JWT_ALG, key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${b64url(sig)}`;
}

async function verifyJWT(request, env) {
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
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const km   = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    km, 256
  );
  const hex = (arr) => Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex(salt)}:${hex(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
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

async function logActivity(db, userId, type, description) {
  try {
    await db.prepare(
      `INSERT INTO activity_log (user_id, type, description, created_at) VALUES (?, ?, ?, ?)`
    ).bind(userId, type, description, istNow()).run();
  } catch (e) {
    console.warn('[logActivity]', e?.message);
  }
}

// ═══════════════════════════════════════════════════════════════════
// AUTH ROUTER
// ═══════════════════════════════════════════════════════════════════

async function AuthRouter(request, env, path) {
  if (path === '/auth/login' && request.method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    const { employee_id, password } = body;
    if (!employee_id?.trim() || !password) {
      return json({ error: 'Employee ID and password are required' }, 400, request);
    }

    const emp = await env.DB.prepare(
      `SELECT id, employee_id, name, department, designation, role, password_hash, status
       FROM employees WHERE LOWER(employee_id) = LOWER(?) LIMIT 1`
    ).bind(employee_id.trim()).first();

    if (!emp) return json({ error: 'Invalid Employee ID or password' }, 401, request);
    if (emp.status === 'inactive') return json({ error: 'Your account has been deactivated. Please contact the admin.' }, 403, request);

    const valid = await verifyPassword(password, emp.password_hash);
    if (!valid) return json({ error: 'Invalid Employee ID or password' }, 401, request);

    const payload = {
      id:          emp.id,
      employee_id: emp.employee_id,
      name:        emp.name,
      department:  emp.department,
      designation: emp.designation,
      role:        emp.role,
    };

    const token = await signJWT(payload, env.JWT_SECRET);

    env.DB.prepare(`UPDATE employees SET last_login = ? WHERE id = ?`)
      .bind(istNow(), emp.id).run().catch(() => {});

    return json({ token, user: payload }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}

// ═══════════════════════════════════════════════════════════════════
// ATTENDANCE ROUTER
// ═══════════════════════════════════════════════════════════════════

function todayStr() {
  return istDateStr();
}
function fmtTime(iso) {
  return new Date(iso).toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit' });
}

async function AttendanceRouter(request, env, path, ctx) {
  const user = await verifyJWT(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401, request);

  const url = new URL(request.url);

  if (path === '/attendance/today' && request.method === 'GET') {
    const today = todayStr();
    const rec   = await env.DB.prepare(
      `SELECT check_in, check_out FROM attendance WHERE employee_id = ? AND date = ?`
    ).bind(user.id, today).first();
    return json({
      checked_in:     !!rec?.check_in,
      checked_out:    !!rec?.check_out,
      check_in_time:  rec?.check_in  ?? null,
      check_out_time: rec?.check_out ?? null,
    }, 200, request);
  }

  if (path === '/attendance/checkin' && request.method === 'POST') {
    const today    = todayStr();
    const existing = await env.DB.prepare(
      `SELECT id, check_in FROM attendance WHERE employee_id = ? AND date = ?`
    ).bind(user.id, today).first();

    if (existing?.check_in) return json({ error: 'You have already checked in today' }, 400, request);

    const now = istNow();
    if (existing) {
      await env.DB.prepare(`UPDATE attendance SET check_in = ?, status = 'present' WHERE id = ?`).bind(now, existing.id).run();
    } else {
      await env.DB.prepare(`INSERT INTO attendance (employee_id, date, check_in, status) VALUES (?, ?, ?, 'present')`).bind(user.id, today, now).run();
    }
    ctx.waitUntil(logActivity(env.DB, user.id, 'checkin', `Checked in at ${fmtTime(now)}`));
    return json({ ok: true, time: now }, 200, request);
  }

  if (path === '/attendance/checkout' && request.method === 'POST') {
    const today = todayStr();
    const rec   = await env.DB.prepare(
      `SELECT id, check_in, check_out FROM attendance WHERE employee_id = ? AND date = ?`
    ).bind(user.id, today).first();

    if (!rec?.check_in)  return json({ error: 'You have not checked in today' }, 400, request);
    if (rec?.check_out)  return json({ error: 'You have already checked out today' }, 400, request);

    const now      = istNow();
    const diffMs   = new Date(now) - new Date(rec.check_in);
    const totalMin = Math.floor(diffMs / 60_000);
    const duration = `${Math.floor(totalMin / 60)}h ${totalMin % 60}m`;

    await env.DB.prepare(`UPDATE attendance SET check_out = ?, duration_minutes = ? WHERE id = ?`).bind(now, totalMin, rec.id).run();
    ctx.waitUntil(logActivity(env.DB, user.id, 'checkout', `Checked out at ${fmtTime(now)} — Total: ${duration}`));
    return json({ ok: true, time: now, duration }, 200, request);
  }

  if (path === '/attendance/summary' && request.method === 'GET') {
    const today       = todayStr();
    const monthPrefix = today.slice(0, 7);
    const [summary, todayRec] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as cnt FROM attendance WHERE employee_id = ? AND date LIKE ? AND status = 'present'`).bind(user.id, `${monthPrefix}%`).first(),
      env.DB.prepare(`SELECT check_in FROM attendance WHERE employee_id = ? AND date = ?`).bind(user.id, today).first(),
    ]);
    return json({ present_days: summary?.cnt ?? 0, checked_in_today: !!todayRec?.check_in }, 200, request);
  }

  if (path === '/attendance/stats' && request.method === 'GET') {
    const month  = url.searchParams.get('month')  || (new Date().getMonth() + 1);
    const year   = url.searchParams.get('year')   || new Date().getFullYear();
    const prefix = `${year}-${String(month).padStart(2, '0')}`;
    const rows   = await env.DB.prepare(
      `SELECT status, COUNT(*) as cnt, AVG(duration_minutes) as avg_min FROM attendance WHERE employee_id = ? AND date LIKE ? GROUP BY status`
    ).bind(user.id, `${prefix}%`).all();

    let present = 0, absent = 0, on_leave = 0, avg_min = 0;
    for (const r of rows.results) {
      if (r.status === 'present')  { present  = r.cnt; avg_min = r.avg_min ?? 0; }
      if (r.status === 'absent')   { absent   = r.cnt; }
      if (r.status === 'leave')    { on_leave = r.cnt; }
    }
    const workingDays     = Math.max(present + absent + on_leave, 1);
    const attendance_rate = Math.round((present / workingDays) * 100);
    const avg_hours       = avg_min ? (avg_min / 60).toFixed(1) : null;
    return json({ present, absent, on_leave, avg_hours, attendance_rate }, 200, request);
  }

  if (path === '/attendance/monthly' && request.method === 'GET') {
    const month  = url.searchParams.get('month')  || (new Date().getMonth() + 1);
    const year   = url.searchParams.get('year')   || new Date().getFullYear();
    const prefix = `${year}-${String(month).padStart(2, '0')}`;
    const rows   = await env.DB.prepare(
      `SELECT date, check_in, check_out, status FROM attendance WHERE employee_id = ? AND date LIKE ? ORDER BY date`
    ).bind(user.id, `${prefix}%`).all();
    return json({ days: rows.results }, 200, request);
  }

  if (path === '/attendance/logs' && request.method === 'GET') {
    const filter = url.searchParams.get('filter') || 'current_month';
    const today  = new Date();
    let query, params;

    if (filter === 'last_30') {
      const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
      query  = `SELECT date, check_in, check_out, status, duration_minutes FROM attendance WHERE employee_id = ? AND date >= ? ORDER BY date DESC`;
      params = [user.id, since];
    } else {
      const d      = filter === 'last_month' ? new Date(today.getFullYear(), today.getMonth() - 1, 1) : today;
      const prefix = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      query  = `SELECT date, check_in, check_out, status, duration_minutes FROM attendance WHERE employee_id = ? AND date LIKE ? ORDER BY date DESC`;
      params = [user.id, `${prefix}%`];
    }

    const rows = await env.DB.prepare(query).bind(...params).all();
    const logs = rows.results.map(r => ({
      ...r,
      duration: r.duration_minutes ? `${Math.floor(r.duration_minutes / 60)}h ${r.duration_minutes % 60}m` : null,
    }));
    return json({ logs }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}

// ═══════════════════════════════════════════════════════════════════
// LEAVE ROUTER
// ═══════════════════════════════════════════════════════════════════

async function LeaveRouter(request, env, path) {
  const user = await verifyJWT(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401, request);

  if (path === '/leave/balance' && request.method === 'GET') {
    const [bal, usedRows, pendingRow] = await Promise.all([
      env.DB.prepare(`SELECT cl_balance, sl_balance FROM employees WHERE id = ?`).bind(user.id).first(),
      env.DB.prepare(`SELECT type, SUM(days) as total FROM leave_requests WHERE employee_id = ? AND status = 'approved' AND strftime('%Y', created_at) = strftime('%Y', 'now') GROUP BY type`).bind(user.id).all(),
      env.DB.prepare(`SELECT COUNT(*) as cnt FROM leave_requests WHERE employee_id = ? AND status = 'pending'`).bind(user.id).first(),
    ]);
    let cl_used = 0, sl_used = 0;
    for (const r of usedRows.results) {
      if (r.type === 'CL') cl_used = r.total ?? 0;
      if (r.type === 'SL') sl_used = r.total ?? 0;
    }
    return json({
      cl_remaining: bal?.cl_balance ?? 12, cl_total: 12, cl_used,
      sl_remaining: bal?.sl_balance ?? 12, sl_total: 12, sl_used,
      pending_requests: pendingRow?.cnt ?? 0,
    }, 200, request);
  }

  if (path === '/leave/requests' && request.method === 'GET') {
    const rows = await env.DB.prepare(
      `SELECT id, type, from_date, to_date, days, reason, status, created_at FROM leave_requests WHERE employee_id = ? ORDER BY created_at DESC LIMIT 60`
    ).bind(user.id).all();
    return json({ requests: rows.results }, 200, request);
  }

  if (path === '/leave/apply' && request.method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    const { type, from_date, to_date, reason } = body;
    if (!type || !from_date || !to_date) return json({ error: 'type, from_date and to_date are required' }, 400, request);
    if (!['CL', 'SL'].includes(type))   return json({ error: 'type must be CL or SL' }, 400, request);

    const days = Math.ceil((new Date(to_date) - new Date(from_date)) / (1000 * 60 * 60 * 24)) + 1;
    if (days <= 0) return json({ error: 'to_date must be on or after from_date' }, 400, request);

    const emp     = await env.DB.prepare(`SELECT cl_balance, sl_balance FROM employees WHERE id = ?`).bind(user.id).first();
    const balance = type === 'CL' ? emp?.cl_balance : emp?.sl_balance;
    if (balance == null || balance < days) return json({ error: `Insufficient ${type} balance — ${balance ?? 0} day(s) remaining, ${days} requested` }, 400, request);

    const overlap = await env.DB.prepare(
      `SELECT id FROM leave_requests WHERE employee_id = ? AND status IN ('pending','approved') AND from_date <= ? AND to_date >= ?`
    ).bind(user.id, to_date, from_date).first();
    if (overlap) return json({ error: 'You already have a leave request for this date range' }, 409, request);

    await env.DB.prepare(
      `INSERT INTO leave_requests (employee_id, type, from_date, to_date, days, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`
    ).bind(user.id, type, from_date, to_date, days, reason?.trim() || '', istNow()).run();

    await logActivity(env.DB, user.id, 'leave', `Applied for ${days}-day ${type} (${from_date} → ${to_date})`);
    return json({ ok: true }, 201, request);
  }

  const cancelMatch = path.match(/^\/leave\/requests\/(\d+)$/);
  if (cancelMatch && request.method === 'DELETE') {
    const id  = cancelMatch[1];
    const req = await env.DB.prepare(`SELECT id, employee_id, status FROM leave_requests WHERE id = ?`).bind(id).first();
    if (!req || req.employee_id !== user.id) return json({ error: 'Request not found' }, 404, request);
    if (req.status !== 'pending') return json({ error: 'Only pending requests can be cancelled' }, 400, request);
    await env.DB.prepare(`DELETE FROM leave_requests WHERE id = ?`).bind(id).run();
    return json({ ok: true }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}

// ═══════════════════════════════════════════════════════════════════
// FEED ROUTER
// ═══════════════════════════════════════════════════════════════════

async function FeedRouter(request, env, path) {
  const user = await verifyJWT(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401, request);

  const url = new URL(request.url);

  if (path === '/feed/posts' && request.method === 'GET') {
    const offset = parseInt(url.searchParams.get('offset') || '0');
    const limit  = Math.min(parseInt(url.searchParams.get('limit') || '10'), 30);
    const rows   = await env.DB.prepare(`
      SELECT p.id, p.content, p.image_url, p.created_at,
             e.id AS author_id, e.name AS author_name, e.department,
             (SELECT COUNT(*) FROM post_likes    WHERE post_id = p.id) AS likes_count,
             (SELECT COUNT(*) FROM post_comments WHERE post_id = p.id) AS comments_count,
             (SELECT COUNT(*) FROM post_likes    WHERE post_id = p.id AND user_id = ?) AS user_liked
      FROM feed_posts p JOIN employees e ON e.id = p.author_id
      ORDER BY p.created_at DESC LIMIT ? OFFSET ?
    `).bind(user.id, limit + 1, offset).all();

    const has_more = rows.results.length > limit;
    const posts    = rows.results.slice(0, limit).map(p => ({ ...p, user_liked: p.user_liked > 0 }));
    return json({ posts, has_more }, 200, request);
  }

  if (path === '/feed/posts' && request.method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    const { content } = body;
    if (!content?.trim()) return json({ error: 'Post must contain text' }, 400, request);

    await env.DB.prepare(
      `INSERT INTO feed_posts (author_id, content, image_url, created_at) VALUES (?, ?, null, ?)`
    ).bind(user.id, content.trim(), istNow()).run();

    await logActivity(env.DB, user.id, 'post', 'Shared a new post on the feed');
    return json({ ok: true }, 201, request);
  }

  const postIdMatch  = path.match(/^\/feed\/posts\/(\d+)$/);
  const likeMatch    = path.match(/^\/feed\/posts\/(\d+)\/like$/);
  const commentsMatch = path.match(/^\/feed\/posts\/(\d+)\/comments$/);

  if (postIdMatch && request.method === 'DELETE') {
    const postId = postIdMatch[1];
    const post   = await env.DB.prepare(`SELECT id, author_id FROM feed_posts WHERE id = ?`).bind(postId).first();
    if (!post) return json({ error: 'Post not found' }, 404, request);
    if (post.author_id !== user.id && user.role !== 'admin') return json({ error: 'Forbidden' }, 403, request);
    await env.DB.prepare(`DELETE FROM feed_posts WHERE id = ?`).bind(postId).run();
    return json({ ok: true }, 200, request);
  }

  if (likeMatch && request.method === 'POST') {
    const postId = likeMatch[1];
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }
    if (body.liked) {
      await env.DB.prepare(`INSERT OR IGNORE INTO post_likes (post_id, user_id, created_at) VALUES (?, ?, ?)`).bind(postId, user.id, istNow()).run();
    } else {
      await env.DB.prepare(`DELETE FROM post_likes WHERE post_id = ? AND user_id = ?`).bind(postId, user.id).run();
    }
    return json({ ok: true }, 200, request);
  }

  if (commentsMatch && request.method === 'GET') {
    const rows = await env.DB.prepare(`
      SELECT c.id, c.content, c.created_at, e.name AS author_name, e.id AS author_id
      FROM post_comments c JOIN employees e ON e.id = c.author_id
      WHERE c.post_id = ? ORDER BY c.created_at ASC
    `).bind(commentsMatch[1]).all();
    return json({ comments: rows.results }, 200, request);
  }

  if (commentsMatch && request.method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }
    const content = body.content?.trim();
    if (!content) return json({ error: 'Comment cannot be empty' }, 400, request);
    await env.DB.prepare(`INSERT INTO post_comments (post_id, author_id, content, created_at) VALUES (?, ?, ?, ?)`).bind(commentsMatch[1], user.id, content, istNow()).run();
    return json({ ok: true }, 201, request);
  }

  if (path === '/feed/stats' && request.method === 'GET') {
    const today = istDateStr();
    const [todayCount, totalCount, activeCount] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as c FROM feed_posts WHERE date(created_at) = ?`).bind(today).first(),
      env.DB.prepare(`SELECT COUNT(*) as c FROM feed_posts`).first(),
      env.DB.prepare(`SELECT COUNT(DISTINCT author_id) as c FROM feed_posts WHERE date(created_at) >= date('now', '-30 days')`).first(),
    ]);
    return json({ posts_today: todayCount?.c ?? 0, total_posts: totalCount?.c ?? 0, active_members: activeCount?.c ?? 0 }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}

// ═══════════════════════════════════════════════════════════════════
// ADMIN ROUTER
// ═══════════════════════════════════════════════════════════════════

async function AdminRouter(request, env, path) {
  const user = await verifyJWT(request, env);
  if (!user)                 return json({ error: 'Unauthorized' }, 401, request);
  if (user.role !== 'admin') return json({ error: 'Forbidden — admin access required' }, 403, request);

  const url = new URL(request.url);

  if (path === '/admin/stats' && request.method === 'GET') {
    const today = istDateStr();
    const [empRow, presentRow, pendingRow, postsRow] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as c FROM employees WHERE status = 'active'`).first(),
      env.DB.prepare(`SELECT COUNT(*) as c FROM attendance WHERE date = ? AND status = 'present'`).bind(today).first(),
      env.DB.prepare(`SELECT COUNT(*) as c FROM leave_requests WHERE status = 'pending'`).first(),
      env.DB.prepare(`SELECT COUNT(*) as c FROM feed_posts WHERE date(created_at) = ?`).bind(today).first(),
    ]);
    return json({ total_employees: empRow?.c ?? 0, present_today: presentRow?.c ?? 0, pending_leave: pendingRow?.c ?? 0, posts_today: postsRow?.c ?? 0 }, 200, request);
  }

  if (path === '/admin/employees' && request.method === 'GET') {
    const rows = await env.DB.prepare(
      `SELECT id, employee_id, name, department, designation, role, email, phone, join_date, status, cl_balance, sl_balance, last_login FROM employees ORDER BY name`
    ).all();
    return json({ employees: rows.results }, 200, request);
  }

  if (path === '/admin/employees' && request.method === 'POST') {
    let d;
    try { d = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }
    if (!d.name?.trim() || !d.employee_id?.trim() || !d.password) return json({ error: 'name, employee_id and password are required' }, 400, request);

    const exists = await env.DB.prepare(`SELECT id FROM employees WHERE LOWER(employee_id) = LOWER(?)`).bind(d.employee_id.trim()).first();
    if (exists) return json({ error: 'Employee ID already exists' }, 409, request);

    const hash = await hashPassword(d.password);
    await env.DB.prepare(`
      INSERT INTO employees (employee_id, name, department, designation, email, phone, join_date, role, cl_balance, sl_balance, password_hash, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
    `).bind(
      d.employee_id.trim(), d.name.trim(),
      d.department?.trim() || '', d.designation?.trim() || '',
      d.email?.trim() || '', d.phone?.trim() || '',
      d.join_date || istDateStr(),
      ['admin','employee'].includes(d.role) ? d.role : 'employee',
      Number.isFinite(d.cl_balance) ? d.cl_balance : 12,
      Number.isFinite(d.sl_balance) ? d.sl_balance : 12,
      hash, istNow()
    ).run();
    return json({ ok: true }, 201, request);
  }

  const editEmpMatch  = path.match(/^\/admin\/employees\/(\d+)$/);
  const resetPwMatch  = path.match(/^\/admin\/employees\/(\d+)\/reset-password$/);

  if (editEmpMatch && request.method === 'PUT') {
    let d;
    try { d = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }
    await env.DB.prepare(`UPDATE employees SET name = ?, department = ?, designation = ?, cl_balance = ?, sl_balance = ?, status = ? WHERE id = ?`)
      .bind(d.name?.trim() ?? '', d.department?.trim() ?? '', d.designation?.trim() ?? '',
            Number.isFinite(d.cl_balance) ? d.cl_balance : 12,
            Number.isFinite(d.sl_balance) ? d.sl_balance : 12,
            ['active','inactive'].includes(d.status) ? d.status : 'active',
            editEmpMatch[1]).run();
    return json({ ok: true }, 200, request);
  }

  if (resetPwMatch && request.method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }
    if (!body.password) return json({ error: 'password is required' }, 400, request);
    const hash = await hashPassword(body.password);
    await env.DB.prepare(`UPDATE employees SET password_hash = ? WHERE id = ?`).bind(hash, resetPwMatch[1]).run();
    return json({ ok: true }, 200, request);
  }

  if (path === '/admin/leave' && request.method === 'GET') {
    const status = url.searchParams.get('status') || 'pending';
    let rows;
    if (status === 'all') {
      rows = await env.DB.prepare(`SELECT lr.*, e.name AS employee_name FROM leave_requests lr JOIN employees e ON e.id = lr.employee_id ORDER BY lr.created_at DESC LIMIT 100`).all();
    } else {
      rows = await env.DB.prepare(`SELECT lr.*, e.name AS employee_name FROM leave_requests lr JOIN employees e ON e.id = lr.employee_id WHERE lr.status = ? ORDER BY lr.created_at DESC LIMIT 100`).bind(status).all();
    }
    return json({ requests: rows.results }, 200, request);
  }

  const leaveActionMatch = path.match(/^\/admin\/leave\/(\d+)$/);
  if (leaveActionMatch && request.method === 'PUT') {
    const leaveId = leaveActionMatch[1];
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }
    const { status } = body;
    if (!['approved','rejected'].includes(status)) return json({ error: 'status must be approved or rejected' }, 400, request);

    const req = await env.DB.prepare(`SELECT * FROM leave_requests WHERE id = ?`).bind(leaveId).first();
    if (!req) return json({ error: 'Leave request not found' }, 404, request);
    if (req.status !== 'pending') return json({ error: 'Only pending requests can be actioned' }, 400, request);

    const now = istNow();
    await env.DB.prepare(`UPDATE leave_requests SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?`).bind(status, user.id, now, leaveId).run();

    if (status === 'approved') {
      const col = req.type === 'CL' ? 'cl_balance' : 'sl_balance';
      await env.DB.prepare(`UPDATE employees SET ${col} = MAX(0, ${col} - ?) WHERE id = ?`).bind(req.days, req.employee_id).run();
      const from = new Date(req.from_date);
      const to   = new Date(req.to_date);
      for (let d = new Date(from); d <= to; d.setDate(d.getDate() + 1)) {
        const dateStr = d.toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
        await env.DB.prepare(`INSERT INTO attendance (employee_id, date, status) VALUES (?, ?, 'leave') ON CONFLICT(employee_id, date) DO UPDATE SET status = 'leave'`).bind(req.employee_id, dateStr).run();
      }
    }
    return json({ ok: true }, 200, request);
  }

  if (path === '/admin/attendance/today' && request.method === 'GET') {
    const today = istDateStr();
    const rows  = await env.DB.prepare(`
      SELECT e.name, e.department, a.check_in, a.check_out, COALESCE(a.status, 'absent') AS status
      FROM employees e LEFT JOIN attendance a ON a.employee_id = e.id AND a.date = ?
      WHERE e.status = 'active' ORDER BY e.name
    `).bind(today).all();
    return json({ records: rows.results }, 200, request);
  }

  if (path === '/admin/attendance/override' && request.method === 'POST') {
    let d;
    try { d = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }
    if (!d.employee_id || !d.date) return json({ error: 'employee_id and date are required' }, 400, request);

    const checkIn  = d.check_in  ? `${d.date}T${d.check_in}:00.000Z`  : null;
    const checkOut = d.check_out ? `${d.date}T${d.check_out}:00.000Z` : null;
    let durationMin = null;
    if (checkIn && checkOut) durationMin = Math.floor((new Date(checkOut) - new Date(checkIn)) / 60_000);

    const validStatuses = ['present','absent','leave','holiday'];
    const status = validStatuses.includes(d.status) ? d.status : 'present';

    await env.DB.prepare(`
      INSERT INTO attendance (employee_id, date, check_in, check_out, duration_minutes, status, override_note, override_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(employee_id, date) DO UPDATE
        SET check_in = excluded.check_in, check_out = excluded.check_out,
            duration_minutes = excluded.duration_minutes, status = excluded.status,
            override_note = excluded.override_note, override_by = excluded.override_by
    `).bind(d.employee_id, d.date, checkIn, checkOut, durationMin, status, d.note?.trim() || '', user.id).run();
    return json({ ok: true }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}


// ═══════════════════════════════════════════════════════════════════
// TASKS ROUTER
// ═══════════════════════════════════════════════════════════════════

async function TasksRouter(request, env, path) {
  const user = await verifyJWT(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401, request);

  const url = new URL(request.url);

  if (path === '/tasks' && request.method === 'GET') {
    const rows = await env.DB.prepare(`
      SELECT t.id, t.title, t.description, t.priority, t.status, t.due_date, t.created_at,
             c.name AS creator_name, a.name AS assignee_name, t.assignee_id, t.creator_id
      FROM tasks t
      JOIN employees c ON c.id = t.creator_id
      LEFT JOIN employees a ON a.id = t.assignee_id
      WHERE (t.creator_id = ? OR t.assignee_id = ? OR ? = 'admin')
      ORDER BY t.created_at DESC LIMIT 100
    `).bind(user.id, user.id, user.role).all();
    return json({ tasks: rows.results }, 200, request);
  }

  if (path === '/tasks' && request.method === 'POST') {
    let d; try { d = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400, request); }
    if (!d.title?.trim()) return json({ error: 'title is required' }, 400, request);
    const result = await env.DB.prepare(`
      INSERT INTO tasks (title, description, priority, status, due_date, creator_id, assignee_id, created_at, updated_at)
      VALUES (?, ?, ?, 'todo', ?, ?, ?, ?, ?)
    `).bind(d.title.trim(), d.description||'', d.priority||'medium', d.due_date||null, user.id, d.assignee_id||null, istNow(), istNow()).run();
    const taskId = result.meta?.last_row_id;
    if (taskId) {
      await env.DB.prepare(`INSERT INTO task_activity (task_id,actor_id,description,created_at) VALUES (?,?,?,?)`).bind(taskId,user.id,`Task created by ${user.name}`,istNow()).run();
      if (d.assignee_id && d.assignee_id !== user.id) {
        await env.DB.prepare(`INSERT INTO notifications (user_id,type,message,entity_type,entity_id,created_at) VALUES (?,?,?,?,?,?)`).bind(d.assignee_id,'task',`You have been assigned a new task: "${d.title.trim()}"`, 'task',taskId,istNow()).run();
      }
    }
    return json({ ok: true }, 201, request);
  }

  const taskMatch = path.match(/^\/tasks\/(\d+)$/);
  if (taskMatch && request.method === 'PUT') {
    let d; try { d = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400, request); }
    const task = await env.DB.prepare(`SELECT * FROM tasks WHERE id = ?`).bind(taskMatch[1]).first();
    if (!task) return json({ error: 'Task not found' }, 404, request);
    const validStatus = ['todo','in_progress','completed','blocked'];
    const validPriority = ['low','medium','high'];
    const status = validStatus.includes(d.status) ? d.status : task.status;
    const priority = validPriority.includes(d.priority) ? d.priority : task.priority;
    await env.DB.prepare(`UPDATE tasks SET title=?,description=?,priority=?,status=?,due_date=?,assignee_id=?,updated_at=? WHERE id=?`)
      .bind(d.title||task.title, d.description??task.description, priority, status, d.due_date??task.due_date, d.assignee_id??task.assignee_id, istNow(), taskMatch[1]).run();
    if (d.status && d.status !== task.status) {
      await env.DB.prepare(`INSERT INTO task_activity (task_id,actor_id,description,created_at) VALUES (?,?,?,?)`).bind(taskMatch[1],user.id,`Status changed from "${task.status}" to "${status}" by ${user.name}`,istNow()).run();
    }
    return json({ ok: true }, 200, request);
  }

  const commentsMatch = path.match(/^\/tasks\/(\d+)\/comments$/);
  if (commentsMatch && request.method === 'GET') {
    const rows = await env.DB.prepare(`SELECT c.*,e.name AS author_name FROM task_comments c JOIN employees e ON e.id=c.author_id WHERE c.task_id=? ORDER BY c.created_at ASC`).bind(commentsMatch[1]).all();
    return json({ comments: rows.results }, 200, request);
  }
  if (commentsMatch && request.method === 'POST') {
    let d; try { d = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400, request); }
    if (!d.content?.trim()) return json({ error: 'content is required' }, 400, request);
    await env.DB.prepare(`INSERT INTO task_comments (task_id,author_id,content,created_at) VALUES (?,?,?,?)`).bind(commentsMatch[1],user.id,d.content.trim(),istNow()).run();
    return json({ ok: true }, 201, request);
  }

  const activityMatch = path.match(/^\/tasks\/(\d+)\/activity$/);
  if (activityMatch && request.method === 'GET') {
    const rows = await env.DB.prepare(`SELECT a.*,e.name AS actor_name FROM task_activity a JOIN employees e ON e.id=a.actor_id WHERE a.task_id=? ORDER BY a.created_at DESC`).bind(activityMatch[1]).all();
    return json({ activity: rows.results }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}

// ═══════════════════════════════════════════════════════════════════
// EVENTS ROUTER
// ═══════════════════════════════════════════════════════════════════

async function EventsRouter(request, env, path) {
  const user = await verifyJWT(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401, request);
  const url = new URL(request.url);

  if (path === '/events' && request.method === 'GET') {
    const year  = url.searchParams.get('year')  || new Date().getFullYear();
    const month = url.searchParams.get('month') || (new Date().getMonth()+1);
    const prefix = `${year}-${String(month).padStart(2,'0')}`;
    const rows = await env.DB.prepare(`
      SELECT e.*, emp.name AS organizer_name FROM events e
      JOIN employees emp ON emp.id = e.organizer_id
      WHERE (e.date LIKE ? OR e.type = 'holiday')
      ORDER BY e.date ASC, e.time ASC
    `).bind(`${prefix}%`).all();
    return json({ events: rows.results }, 200, request);
  }

  if (path === '/events' && request.method === 'POST') {
    let d; try { d = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400, request); }
    if (!d.title?.trim() || !d.date) return json({ error: 'title and date are required' }, 400, request);
    const validTypes = ['company','meeting','holiday','personal'];
    const validRecur = ['none','daily','weekly','monthly'];
    await env.DB.prepare(`
      INSERT INTO events (title,description,date,time,location,type,recurrence,organizer_id,created_at)
      VALUES (?,?,?,?,?,?,?,?,?)
    `).bind(d.title.trim(), d.description||'', d.date, d.time||null, d.location||'', validTypes.includes(d.type)?d.type:'company', validRecur.includes(d.recurrence)?d.recurrence:'none', user.id, istNow()).run();
    return json({ ok: true }, 201, request);
  }

  const evMatch = path.match(/^\/events\/(\d+)$/);
  if (evMatch && request.method === 'DELETE') {
    const ev = await env.DB.prepare(`SELECT id,organizer_id FROM events WHERE id=?`).bind(evMatch[1]).first();
    if (!ev) return json({ error: 'Not found' }, 404, request);
    if (ev.organizer_id !== user.id && user.role !== 'admin') return json({ error: 'Forbidden' }, 403, request);
    await env.DB.prepare(`DELETE FROM events WHERE id=?`).bind(evMatch[1]).run();
    return json({ ok: true }, 200, request);
  }

  if (path === '/events/upcoming' && request.method === 'GET') {
    const today = istDateStr();
    const rows = await env.DB.prepare(`
      SELECT e.*, emp.name AS organizer_name FROM events e
      JOIN employees emp ON emp.id = e.organizer_id
      WHERE e.date >= ? ORDER BY e.date ASC, e.time ASC LIMIT 10
    `).bind(today).all();
    return json({ events: rows.results }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}

// ═══════════════════════════════════════════════════════════════════
// QUERIES ROUTER
// ═══════════════════════════════════════════════════════════════════

async function QueriesRouter(request, env, path) {
  const user = await verifyJWT(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401, request);

  if (path === '/queries' && request.method === 'GET') {
    let rows;
    if (user.role === 'admin') {
      rows = await env.DB.prepare(`SELECT q.*,a.name AS author_name,asn.name AS assignee_name FROM queries q JOIN employees a ON a.id=q.author_id LEFT JOIN employees asn ON asn.id=q.assignee_id ORDER BY q.created_at DESC LIMIT 200`).all();
    } else {
      rows = await env.DB.prepare(`SELECT q.*,a.name AS author_name,asn.name AS assignee_name FROM queries q JOIN employees a ON a.id=q.author_id LEFT JOIN employees asn ON asn.id=q.assignee_id WHERE q.author_id=? OR q.assignee_id=? ORDER BY q.created_at DESC LIMIT 100`).bind(user.id,user.id).all();
    }
    return json({ queries: rows.results }, 200, request);
  }

  if (path === '/queries' && request.method === 'POST') {
    let d; try { d = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400, request); }
    if (!d.title?.trim() || !d.description?.trim()) return json({ error: 'title and description are required' }, 400, request);
    await env.DB.prepare(`INSERT INTO queries (title,description,department,priority,status,author_id,created_at,updated_at) VALUES (?,?,?,?,'open',?,?,?)`).bind(d.title.trim(),d.description.trim(),d.department||'IT',d.priority||'medium',user.id,istNow(),istNow()).run();
    return json({ ok: true }, 201, request);
  }

  const qMatch = path.match(/^\/queries\/(\d+)$/);
  if (qMatch && request.method === 'PUT') {
    let d; try { d = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400, request); }
    const validStatus = ['open','in_progress','waiting','resolved','closed'];
    if (d.status && !validStatus.includes(d.status)) return json({ error: 'Invalid status' }, 400, request);
    const q = await env.DB.prepare(`SELECT * FROM queries WHERE id=?`).bind(qMatch[1]).first();
    if (!q) return json({ error: 'Not found' }, 404, request);
    if (q.author_id !== user.id && user.role !== 'admin') return json({ error: 'Forbidden' }, 403, request);
    await env.DB.prepare(`UPDATE queries SET status=?,assignee_id=?,updated_at=? WHERE id=?`).bind(d.status||q.status,d.assignee_id??q.assignee_id,istNow(),qMatch[1]).run();
    return json({ ok: true }, 200, request);
  }

  const qCommMatch = path.match(/^\/queries\/(\d+)\/comments$/);
  if (qCommMatch && request.method === 'GET') {
    const rows = await env.DB.prepare(`SELECT c.*,e.name AS author_name FROM query_comments c JOIN employees e ON e.id=c.author_id WHERE c.query_id=? ORDER BY c.created_at ASC`).bind(qCommMatch[1]).all();
    return json({ comments: rows.results }, 200, request);
  }
  if (qCommMatch && request.method === 'POST') {
    let d; try { d = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400, request); }
    if (!d.content?.trim()) return json({ error: 'content is required' }, 400, request);
    await env.DB.prepare(`INSERT INTO query_comments (query_id,author_id,content,created_at) VALUES (?,?,?,?)`).bind(qCommMatch[1],user.id,d.content.trim(),istNow()).run();
    return json({ ok: true }, 201, request);
  }

  return json({ error: 'Not found' }, 404, request);
}

// ═══════════════════════════════════════════════════════════════════
// NOTIFICATIONS ROUTER
// ═══════════════════════════════════════════════════════════════════

async function NotificationsRouter(request, env, path) {
  const user = await verifyJWT(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401, request);

  if (path === '/notifications' && request.method === 'GET') {
    const rows = await env.DB.prepare(`SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 30`).bind(user.id).all();
    return json({ notifications: rows.results }, 200, request);
  }

  const readMatch = path.match(/^\/notifications\/(\d+)\/read$/);
  if (readMatch && request.method === 'PUT') {
    await env.DB.prepare(`UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?`).bind(readMatch[1],user.id).run();
    return json({ ok: true }, 200, request);
  }

  if (path === '/notifications/read-all' && request.method === 'POST') {
    await env.DB.prepare(`UPDATE notifications SET is_read=1 WHERE user_id=?`).bind(user.id).run();
    return json({ ok: true }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}

// ═══════════════════════════════════════════════════════════════════
// MAIN FETCH HANDLER
// ═══════════════════════════════════════════════════════════════════

export default {
  async fetch(request, env, ctx) {

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    try {

      // ── TEMP: Seed admin password — DELETE AFTER FIRST USE ──────
      if (path === '/auth/seed-admin' && request.method === 'GET') {
        const hash = await hashPassword('Admin@123');
        await env.DB.prepare(`UPDATE employees SET password_hash = ? WHERE employee_id = 'ADMIN01'`).bind(hash).run();
        return new Response(JSON.stringify({ ok: true, message: 'Admin password set! Remove this route now.' }), {
          status: 200, headers: { 'Content-Type': 'application/json' }
        });
      }

      if (path.startsWith('/auth'))          return AuthRouter(request, env, path);
      if (path.startsWith('/attendance'))   return AttendanceRouter(request, env, path, ctx);
      if (path.startsWith('/leave'))        return LeaveRouter(request, env, path);
      if (path.startsWith('/feed'))         return FeedRouter(request, env, path);
      if (path.startsWith('/admin'))        return AdminRouter(request, env, path);
      if (path.startsWith('/tasks'))        return TasksRouter(request, env, path);
      if (path.startsWith('/events'))       return EventsRouter(request, env, path);
      if (path.startsWith('/queries'))      return QueriesRouter(request, env, path);
      if (path.startsWith('/notifications'))return NotificationsRouter(request, env, path);

      if (path === '/employees/online' && request.method === 'GET') {
        const user = await verifyJWT(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401, request);
        const since = new Date(Date.now() - 15 * 60 * 1000).toLocaleString('sv-SE', { timeZone: 'Asia/Kolkata' }).replace(' ', 'T');
        const rows  = await env.DB.prepare(
          `SELECT id, name, department FROM employees WHERE last_login >= ? AND status = 'active' ORDER BY last_login DESC LIMIT 12`
        ).bind(since).all();
        return json({ members: rows.results }, 200, request);
      }

      if (path === '/activity/recent' && request.method === 'GET') {
        const user = await verifyJWT(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401, request);
        const rows = await env.DB.prepare(
          `SELECT type, description, created_at FROM activity_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 10`
        ).bind(user.id).all();
        return json({ activities: rows.results }, 200, request);
      }

      return json({ error: 'Not found' }, 404, request);

    } catch (err) {
      console.error('[Worker Error]', err);
      return json({ error: 'Internal server error' }, 500, request);
    }
  },
};
