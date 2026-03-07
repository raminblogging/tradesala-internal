/**
 * Leave Router
 * ─────────────
 * GET    /leave/balance              → CL / SL balance + pending count
 * GET    /leave/requests             → employee's own leave history
 * POST   /leave/apply                → submit a new leave request
 * DELETE /leave/requests/:id         → cancel a pending request
 */

import { json, verifyJWT, logActivity } from '../utils.js';

export async function LeaveRouter(request, env, path) {
  const user = await verifyJWT(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401, request);

  // ── GET /leave/balance ─────────────────────────────────────────
  if (path === '/leave/balance' && request.method === 'GET') {
    const [bal, usedRows, pendingRow] = await Promise.all([
      env.DB.prepare(
        `SELECT cl_balance, sl_balance FROM employees WHERE id = ?`
      ).bind(user.id).first(),

      env.DB.prepare(
        `SELECT type, SUM(days) as total
         FROM   leave_requests
         WHERE  employee_id = ?
           AND  status = 'approved'
           AND  strftime('%Y', created_at) = strftime('%Y', 'now')
         GROUP  BY type`
      ).bind(user.id).all(),

      env.DB.prepare(
        `SELECT COUNT(*) as cnt FROM leave_requests
         WHERE  employee_id = ? AND status = 'pending'`
      ).bind(user.id).first(),
    ]);

    let cl_used = 0, sl_used = 0;
    for (const r of usedRows.results) {
      if (r.type === 'CL') cl_used = r.total ?? 0;
      if (r.type === 'SL') sl_used = r.total ?? 0;
    }

    const CL_TOTAL = 12;
    const SL_TOTAL = 12;

    return json({
      cl_remaining:     bal?.cl_balance ?? CL_TOTAL,
      cl_total:         CL_TOTAL,
      cl_used,
      sl_remaining:     bal?.sl_balance ?? SL_TOTAL,
      sl_total:         SL_TOTAL,
      sl_used,
      pending_requests: pendingRow?.cnt ?? 0,
    }, 200, request);
  }

  // ── GET /leave/requests ────────────────────────────────────────
  if (path === '/leave/requests' && request.method === 'GET') {
    const rows = await env.DB.prepare(
      `SELECT id, type, from_date, to_date, days, reason, status, created_at
       FROM   leave_requests
       WHERE  employee_id = ?
       ORDER  BY created_at DESC
       LIMIT  60`
    ).bind(user.id).all();

    return json({ requests: rows.results }, 200, request);
  }

  // ── POST /leave/apply ──────────────────────────────────────────
  if (path === '/leave/apply' && request.method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    const { type, from_date, to_date, reason } = body;

    if (!type || !from_date || !to_date) {
      return json({ error: 'type, from_date and to_date are required' }, 400, request);
    }
    if (!['CL', 'SL'].includes(type)) {
      return json({ error: 'type must be CL or SL' }, 400, request);
    }

    const days = Math.ceil(
      (new Date(to_date) - new Date(from_date)) / (1000 * 60 * 60 * 24)
    ) + 1;

    if (days <= 0) {
      return json({ error: 'to_date must be on or after from_date' }, 400, request);
    }

    // Check remaining balance
    const emp      = await env.DB.prepare(
      `SELECT cl_balance, sl_balance FROM employees WHERE id = ?`
    ).bind(user.id).first();
    const balance  = type === 'CL' ? emp?.cl_balance : emp?.sl_balance;

    if (balance == null || balance < days) {
      return json({
        error: `Insufficient ${type} balance — ${balance ?? 0} day(s) remaining, ${days} requested`,
      }, 400, request);
    }

    // Check for overlapping approved / pending requests
    const overlap = await env.DB.prepare(
      `SELECT id FROM leave_requests
       WHERE  employee_id = ?
         AND  status IN ('pending','approved')
         AND  from_date <= ? AND to_date >= ?`
    ).bind(user.id, to_date, from_date).first();

    if (overlap) {
      return json({ error: 'You already have a leave request for this date range' }, 409, request);
    }

    await env.DB.prepare(
      `INSERT INTO leave_requests
         (employee_id, type, from_date, to_date, days, reason, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`
    ).bind(user.id, type, from_date, to_date, days, reason?.trim() || '', new Date().toISOString()).run();

    await logActivity(env.DB, user.id, 'leave',
      `Applied for ${days}-day ${type} (${from_date} → ${to_date})`);

    return json({ ok: true }, 201, request);
  }

  // ── DELETE /leave/requests/:id ─────────────────────────────────
  const cancelMatch = path.match(/^\/leave\/requests\/(\d+)$/);
  if (cancelMatch && request.method === 'DELETE') {
    const id  = cancelMatch[1];
    const req = await env.DB.prepare(
      `SELECT id, employee_id, status FROM leave_requests WHERE id = ?`
    ).bind(id).first();

    if (!req || req.employee_id !== user.id) {
      return json({ error: 'Request not found' }, 404, request);
    }
    if (req.status !== 'pending') {
      return json({ error: 'Only pending requests can be cancelled' }, 400, request);
    }

    await env.DB.prepare(`DELETE FROM leave_requests WHERE id = ?`).bind(id).run();
    return json({ ok: true }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}
