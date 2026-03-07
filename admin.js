/**
 * Admin Router  (role = 'admin' required for every endpoint)
 * ────────────────────────────────────────────────────────────
 * GET  /admin/stats                           → dashboard counters
 *
 * GET  /admin/employees                       → full employee list
 * POST /admin/employees                       → create new employee
 * PUT  /admin/employees/:id                   → update employee details
 * POST /admin/employees/:id/reset-password    → set new password
 *
 * GET  /admin/leave?status=pending|approved|rejected|all
 * PUT  /admin/leave/:id                       → approve or reject
 *
 * GET  /admin/attendance/today                → all employees' status today
 * POST /admin/attendance/override             → manually set a record
 */

import { json, verifyJWT, hashPassword } from '../utils.js';

export async function AdminRouter(request, env, path) {
  // ── Auth + role guard ──────────────────────────────────────────
  const user = await verifyJWT(request, env);
  if (!user)                return json({ error: 'Unauthorized' }, 401, request);
  if (user.role !== 'admin') return json({ error: 'Forbidden — admin access required' }, 403, request);

  const url = new URL(request.url);

  // ════════════════════════════════════════════════════════════════
  // STATS
  // ════════════════════════════════════════════════════════════════

  // GET /admin/stats
  if (path === '/admin/stats' && request.method === 'GET') {
    const today = new Date().toISOString().split('T')[0];

    const [empRow, presentRow, pendingRow, postsRow] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as c FROM employees WHERE status = 'active'`).first(),
      env.DB.prepare(`SELECT COUNT(*) as c FROM attendance WHERE date = ? AND status = 'present'`).bind(today).first(),
      env.DB.prepare(`SELECT COUNT(*) as c FROM leave_requests WHERE status = 'pending'`).first(),
      env.DB.prepare(`SELECT COUNT(*) as c FROM feed_posts WHERE date(created_at) = ?`).bind(today).first(),
    ]);

    return json({
      total_employees: empRow?.c     ?? 0,
      present_today:   presentRow?.c ?? 0,
      pending_leave:   pendingRow?.c ?? 0,
      posts_today:     postsRow?.c   ?? 0,
    }, 200, request);
  }

  // ════════════════════════════════════════════════════════════════
  // EMPLOYEES
  // ════════════════════════════════════════════════════════════════

  // GET /admin/employees
  if (path === '/admin/employees' && request.method === 'GET') {
    const rows = await env.DB.prepare(
      `SELECT id, employee_id, name, department, designation,
              role, email, phone, join_date, status,
              cl_balance, sl_balance, last_login
       FROM   employees
       ORDER  BY name`
    ).all();
    return json({ employees: rows.results }, 200, request);
  }

  // POST /admin/employees  — create new employee
  if (path === '/admin/employees' && request.method === 'POST') {
    let d;
    try { d = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    if (!d.name?.trim() || !d.employee_id?.trim() || !d.password) {
      return json({ error: 'name, employee_id and password are required' }, 400, request);
    }

    // Duplicate check
    const exists = await env.DB.prepare(
      `SELECT id FROM employees WHERE LOWER(employee_id) = LOWER(?)`
    ).bind(d.employee_id.trim()).first();
    if (exists) return json({ error: 'Employee ID already exists' }, 409, request);

    const hash = await hashPassword(d.password);
    const now  = new Date().toISOString();

    await env.DB.prepare(`
      INSERT INTO employees
        (employee_id, name, department, designation, email, phone,
         join_date, role, cl_balance, sl_balance, password_hash, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
    `).bind(
      d.employee_id.trim(),
      d.name.trim(),
      d.department?.trim()  || '',
      d.designation?.trim() || '',
      d.email?.trim()       || '',
      d.phone?.trim()       || '',
      d.join_date           || now.split('T')[0],
      ['admin','employee'].includes(d.role) ? d.role : 'employee',
      Number.isFinite(d.cl_balance) ? d.cl_balance : 12,
      Number.isFinite(d.sl_balance) ? d.sl_balance : 12,
      hash,
      now
    ).run();

    return json({ ok: true }, 201, request);
  }

  // PUT /admin/employees/:id
  const editEmpMatch = path.match(/^\/admin\/employees\/(\d+)$/);
  if (editEmpMatch && request.method === 'PUT') {
    const empId = editEmpMatch[1];
    let d;
    try { d = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    await env.DB.prepare(`
      UPDATE employees
      SET name        = ?,
          department  = ?,
          designation = ?,
          cl_balance  = ?,
          sl_balance  = ?,
          status      = ?
      WHERE id = ?
    `).bind(
      d.name?.trim()        ?? '',
      d.department?.trim()  ?? '',
      d.designation?.trim() ?? '',
      Number.isFinite(d.cl_balance) ? d.cl_balance : 12,
      Number.isFinite(d.sl_balance) ? d.sl_balance : 12,
      ['active','inactive'].includes(d.status) ? d.status : 'active',
      empId
    ).run();

    return json({ ok: true }, 200, request);
  }

  // POST /admin/employees/:id/reset-password
  const resetPwMatch = path.match(/^\/admin\/employees\/(\d+)\/reset-password$/);
  if (resetPwMatch && request.method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    if (!body.password) return json({ error: 'password is required' }, 400, request);

    const hash = await hashPassword(body.password);
    await env.DB.prepare(
      `UPDATE employees SET password_hash = ? WHERE id = ?`
    ).bind(hash, resetPwMatch[1]).run();

    return json({ ok: true }, 200, request);
  }

  // ════════════════════════════════════════════════════════════════
  // LEAVE APPROVALS
  // ════════════════════════════════════════════════════════════════

  // GET /admin/leave?status=pending|approved|rejected|all
  if (path === '/admin/leave' && request.method === 'GET') {
    const status = url.searchParams.get('status') || 'pending';

    let rows;
    if (status === 'all') {
      rows = await env.DB.prepare(`
        SELECT lr.*, e.name AS employee_name
        FROM   leave_requests lr
        JOIN   employees      e ON e.id = lr.employee_id
        ORDER  BY lr.created_at DESC
        LIMIT  100
      `).all();
    } else {
      rows = await env.DB.prepare(`
        SELECT lr.*, e.name AS employee_name
        FROM   leave_requests lr
        JOIN   employees      e ON e.id = lr.employee_id
        WHERE  lr.status = ?
        ORDER  BY lr.created_at DESC
        LIMIT  100
      `).bind(status).all();
    }

    return json({ requests: rows.results }, 200, request);
  }

  // PUT /admin/leave/:id  — approve or reject
  const leaveActionMatch = path.match(/^\/admin\/leave\/(\d+)$/);
  if (leaveActionMatch && request.method === 'PUT') {
    const leaveId = leaveActionMatch[1];
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    const { status } = body;
    if (!['approved','rejected'].includes(status)) {
      return json({ error: 'status must be approved or rejected' }, 400, request);
    }

    const req = await env.DB.prepare(
      `SELECT * FROM leave_requests WHERE id = ?`
    ).bind(leaveId).first();

    if (!req) return json({ error: 'Leave request not found' }, 404, request);
    if (req.status !== 'pending') {
      return json({ error: 'Only pending requests can be actioned' }, 400, request);
    }

    const now = new Date().toISOString();

    await env.DB.prepare(`
      UPDATE leave_requests
      SET    status      = ?,
             reviewed_by = ?,
             reviewed_at = ?
      WHERE  id = ?
    `).bind(status, user.id, now, leaveId).run();

    if (status === 'approved') {
      // Deduct balance
      const col = req.type === 'CL' ? 'cl_balance' : 'sl_balance';
      await env.DB.prepare(
        `UPDATE employees SET ${col} = MAX(0, ${col} - ?) WHERE id = ?`
      ).bind(req.days, req.employee_id).run();

      // Stamp attendance rows for the leave period
      const from = new Date(req.from_date);
      const to   = new Date(req.to_date);
      for (let d = new Date(from); d <= to; d.setDate(d.getDate() + 1)) {
        const dateStr = d.toISOString().split('T')[0];
        await env.DB.prepare(`
          INSERT INTO attendance (employee_id, date, status)
          VALUES (?, ?, 'leave')
          ON CONFLICT(employee_id, date)
          DO UPDATE SET status = 'leave'
        `).bind(req.employee_id, dateStr).run();
      }
    }

    return json({ ok: true }, 200, request);
  }

  // ════════════════════════════════════════════════════════════════
  // ATTENDANCE (admin view + override)
  // ════════════════════════════════════════════════════════════════

  // GET /admin/attendance/today
  if (path === '/admin/attendance/today' && request.method === 'GET') {
    const today = new Date().toISOString().split('T')[0];

    const rows = await env.DB.prepare(`
      SELECT e.name,
             e.department,
             a.check_in,
             a.check_out,
             COALESCE(a.status, 'absent') AS status
      FROM   employees e
      LEFT JOIN attendance a
        ON  a.employee_id = e.id AND a.date = ?
      WHERE  e.status = 'active'
      ORDER  BY e.name
    `).bind(today).all();

    return json({ records: rows.results }, 200, request);
  }

  // POST /admin/attendance/override
  if (path === '/admin/attendance/override' && request.method === 'POST') {
    let d;
    try { d = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    if (!d.employee_id || !d.date) {
      return json({ error: 'employee_id and date are required' }, 400, request);
    }

    // Build ISO timestamps from date + time strings
    const checkIn  = d.check_in  ? `${d.date}T${d.check_in}:00.000Z`  : null;
    const checkOut = d.check_out ? `${d.date}T${d.check_out}:00.000Z` : null;

    let durationMin = null;
    if (checkIn && checkOut) {
      durationMin = Math.floor((new Date(checkOut) - new Date(checkIn)) / 60_000);
    }

    const validStatuses = ['present','absent','leave','holiday'];
    const status = validStatuses.includes(d.status) ? d.status : 'present';

    await env.DB.prepare(`
      INSERT INTO attendance
        (employee_id, date, check_in, check_out, duration_minutes,
         status, override_note, override_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(employee_id, date) DO UPDATE
        SET check_in          = excluded.check_in,
            check_out         = excluded.check_out,
            duration_minutes  = excluded.duration_minutes,
            status            = excluded.status,
            override_note     = excluded.override_note,
            override_by       = excluded.override_by
    `).bind(
      d.employee_id,
      d.date,
      checkIn,
      checkOut,
      durationMin,
      status,
      d.note?.trim() || '',
      user.id
    ).run();

    return json({ ok: true }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}
