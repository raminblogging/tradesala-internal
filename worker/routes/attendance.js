/**
 * Attendance Router
 * ──────────────────
 * GET  /attendance/today       → today's check-in status
 * POST /attendance/checkin     → record check-in
 * POST /attendance/checkout    → record check-out
 * GET  /attendance/summary     → month summary + checked_in_today flag
 * GET  /attendance/stats       → present/absent/leave/avg counts for a month
 * GET  /attendance/monthly     → per-day records for calendar view
 * GET  /attendance/logs        → paginated log with filter
 */

import { json, verifyJWT, logActivity } from '../utils.js';

export async function AttendanceRouter(request, env, path, ctx) {
  const user = await verifyJWT(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401, request);

  const url = new URL(request.url);

  // ── GET /attendance/today ──────────────────────────────────────
  if (path === '/attendance/today' && request.method === 'GET') {
    const today = todayStr();
    const rec   = await env.DB.prepare(
      `SELECT check_in, check_out FROM attendance
       WHERE  employee_id = ? AND date = ?`
    ).bind(user.id, today).first();

    return json({
      checked_in:      !!rec?.check_in,
      checked_out:     !!rec?.check_out,
      check_in_time:   rec?.check_in  ?? null,
      check_out_time:  rec?.check_out ?? null,
    }, 200, request);
  }

  // ── POST /attendance/checkin ───────────────────────────────────
  if (path === '/attendance/checkin' && request.method === 'POST') {
    const today    = todayStr();
    const existing = await env.DB.prepare(
      `SELECT id, check_in FROM attendance WHERE employee_id = ? AND date = ?`
    ).bind(user.id, today).first();

    if (existing?.check_in) {
      return json({ error: 'You have already checked in today' }, 400, request);
    }

    const now = new Date().toISOString();

    if (existing) {
      await env.DB.prepare(
        `UPDATE attendance SET check_in = ?, status = 'present' WHERE id = ?`
      ).bind(now, existing.id).run();
    } else {
      await env.DB.prepare(
        `INSERT INTO attendance (employee_id, date, check_in, status) VALUES (?, ?, ?, 'present')`
      ).bind(user.id, today, now).run();
    }

    ctx.waitUntil(logActivity(env.DB, user.id, 'checkin',
      `Checked in at ${fmtTime(now)}`));

    return json({ ok: true, time: now }, 200, request);
  }

  // ── POST /attendance/checkout ──────────────────────────────────
  if (path === '/attendance/checkout' && request.method === 'POST') {
    const today = todayStr();
    const rec   = await env.DB.prepare(
      `SELECT id, check_in, check_out FROM attendance WHERE employee_id = ? AND date = ?`
    ).bind(user.id, today).first();

    if (!rec?.check_in)  return json({ error: 'You have not checked in today' }, 400, request);
    if (rec?.check_out)  return json({ error: 'You have already checked out today' }, 400, request);

    const now     = new Date().toISOString();
    const diffMs  = new Date(now) - new Date(rec.check_in);
    const totalMin = Math.floor(diffMs / 60_000);
    const hours   = Math.floor(totalMin / 60);
    const mins    = totalMin % 60;
    const duration = `${hours}h ${mins}m`;

    await env.DB.prepare(
      `UPDATE attendance SET check_out = ?, duration_minutes = ? WHERE id = ?`
    ).bind(now, totalMin, rec.id).run();

    ctx.waitUntil(logActivity(env.DB, user.id, 'checkout',
      `Checked out at ${fmtTime(now)} — Total: ${duration}`));

    return json({ ok: true, time: now, duration }, 200, request);
  }

  // ── GET /attendance/summary ────────────────────────────────────
  if (path === '/attendance/summary' && request.method === 'GET') {
    const today       = todayStr();
    const monthPrefix = today.slice(0, 7);

    const [summary, todayRec] = await Promise.all([
      env.DB.prepare(
        `SELECT COUNT(*) as cnt FROM attendance
         WHERE  employee_id = ? AND date LIKE ? AND status = 'present'`
      ).bind(user.id, `${monthPrefix}%`).first(),
      env.DB.prepare(
        `SELECT check_in FROM attendance WHERE employee_id = ? AND date = ?`
      ).bind(user.id, today).first(),
    ]);

    return json({
      present_days:     summary?.cnt ?? 0,
      checked_in_today: !!todayRec?.check_in,
    }, 200, request);
  }

  // ── GET /attendance/stats?month=M&year=Y ───────────────────────
  if (path === '/attendance/stats' && request.method === 'GET') {
    const month  = url.searchParams.get('month')  || (new Date().getMonth() + 1);
    const year   = url.searchParams.get('year')   || new Date().getFullYear();
    const prefix = `${year}-${String(month).padStart(2, '0')}`;

    const rows = await env.DB.prepare(
      `SELECT status,
              COUNT(*) as cnt,
              AVG(duration_minutes) as avg_min
       FROM   attendance
       WHERE  employee_id = ? AND date LIKE ?
       GROUP  BY status`
    ).bind(user.id, `${prefix}%`).all();

    let present = 0, absent = 0, on_leave = 0, avg_min = 0;
    for (const r of rows.results) {
      if (r.status === 'present')  { present  = r.cnt; avg_min = r.avg_min ?? 0; }
      if (r.status === 'absent')   { absent   = r.cnt; }
      if (r.status === 'leave')    { on_leave = r.cnt; }
    }

    const workingDays       = Math.max(present + absent + on_leave, 1);
    const attendance_rate   = Math.round((present / workingDays) * 100);
    const avg_hours         = avg_min ? (avg_min / 60).toFixed(1) : null;

    return json({ present, absent, on_leave, avg_hours, attendance_rate }, 200, request);
  }

  // ── GET /attendance/monthly?month=M&year=Y ─────────────────────
  if (path === '/attendance/monthly' && request.method === 'GET') {
    const month  = url.searchParams.get('month')  || (new Date().getMonth() + 1);
    const year   = url.searchParams.get('year')   || new Date().getFullYear();
    const prefix = `${year}-${String(month).padStart(2, '0')}`;

    const rows = await env.DB.prepare(
      `SELECT date, check_in, check_out, status
       FROM   attendance
       WHERE  employee_id = ? AND date LIKE ?
       ORDER  BY date`
    ).bind(user.id, `${prefix}%`).all();

    return json({ days: rows.results }, 200, request);
  }

  // ── GET /attendance/logs?filter=current_month|last_month|last_30 ─
  if (path === '/attendance/logs' && request.method === 'GET') {
    const filter = url.searchParams.get('filter') || 'current_month';
    const today  = new Date();

    let query, params;

    if (filter === 'last_30') {
      const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
      query  = `SELECT date, check_in, check_out, status, duration_minutes
                FROM   attendance
                WHERE  employee_id = ? AND date >= ?
                ORDER  BY date DESC`;
      params = [user.id, since];

    } else {
      const d = filter === 'last_month'
        ? new Date(today.getFullYear(), today.getMonth() - 1, 1)
        : today;
      const prefix = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      query  = `SELECT date, check_in, check_out, status, duration_minutes
                FROM   attendance
                WHERE  employee_id = ? AND date LIKE ?
                ORDER  BY date DESC`;
      params = [user.id, `${prefix}%`];
    }

    const rows = await env.DB.prepare(query).bind(...params).all();
    const logs = rows.results.map(r => ({
      ...r,
      duration: r.duration_minutes
        ? `${Math.floor(r.duration_minutes / 60)}h ${r.duration_minutes % 60}m`
        : null,
    }));

    return json({ logs }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}

// ── helpers ───────────────────────────────────────────────────────
function todayStr() {
  return new Date().toISOString().split('T')[0];
}
function fmtTime(iso) {
  return new Date(iso).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
}
