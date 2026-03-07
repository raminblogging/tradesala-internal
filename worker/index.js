/**
 * Internal Portal — Cloudflare Worker API
 * ─────────────────────────────────────────────────
 * Deploy : wrangler deploy
 * DB     : Cloudflare D1  (binding → DB)
 * Storage: Cloudflare R2  (binding → R2_BUCKET)
 * Secret : JWT_SECRET     (wrangler secret put JWT_SECRET)
 */

import { AuthRouter }       from './routes/auth.js';
import { AttendanceRouter } from './routes/attendance.js';
import { LeaveRouter }      from './routes/leave.js';
import { FeedRouter }       from './routes/feed.js';
import { AdminRouter }      from './routes/admin.js';
import { verifyJWT, json }  from './utils.js';

export default {
  async fetch(request, env, ctx) {

    // ── CORS preflight ────────────────────────────────────────────
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    try {
      // ── TEMP: Seed admin password — DELETE AFTER FIRST USE ──────
      if (path === '/auth/seed-admin' && request.method === 'GET') {
        const { hashPassword } = await import('./utils.js');
        const hash = await hashPassword('Admin@123');
        await env.DB.prepare(
          `UPDATE employees SET password_hash = ? WHERE employee_id = 'ADMIN01'`
        ).bind(hash).run();
        return new Response(JSON.stringify({ ok: true, message: 'Admin password set! Remove this route now.' }), {
          status: 200, headers: { 'Content-Type': 'application/json' }
        });
      }

      // ── Route dispatch ──────────────────────────────────────────
      if (path.startsWith('/auth'))       return AuthRouter(request, env, path);
      if (path.startsWith('/attendance')) return AttendanceRouter(request, env, path, ctx);
      if (path.startsWith('/leave'))      return LeaveRouter(request, env, path);
      if (path.startsWith('/feed'))       return FeedRouter(request, env, path);
      if (path.startsWith('/admin'))      return AdminRouter(request, env, path);

      // ── /employees/online ───────────────────────────────────────
      if (path === '/employees/online' && request.method === 'GET') {
        const user = await verifyJWT(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401, request);
        const since = new Date(Date.now() - 15 * 60 * 1000).toISOString();
        const rows  = await env.DB.prepare(
          `SELECT id, name, department FROM employees
           WHERE last_login >= ? AND status = 'active'
           ORDER BY last_login DESC LIMIT 12`
        ).bind(since).all();
        return json({ members: rows.results }, 200, request);
      }

      // ── /activity/recent ────────────────────────────────────────
      if (path === '/activity/recent' && request.method === 'GET') {
        const user = await verifyJWT(request, env);
        if (!user) return json({ error: 'Unauthorized' }, 401, request);
        const rows = await env.DB.prepare(
          `SELECT type, description, created_at FROM activity_log
           WHERE user_id = ? ORDER BY created_at DESC LIMIT 10`
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

// exported so route files can reuse if needed
export function corsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '*';
  return {
    'Access-Control-Allow-Origin':  origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age':       '86400',
  };
}
