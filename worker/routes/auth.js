/**
 * Auth Router
 * ───────────
 * POST /auth/login   → { token, user }
 */

import { json, signJWT, verifyPassword } from '../utils.js';

export async function AuthRouter(request, env, path) {

  // ── POST /auth/login ───────────────────────────────────────────
  if (path === '/auth/login' && request.method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON body' }, 400, request); }

    const { employee_id, password } = body;

    if (!employee_id?.trim() || !password) {
      return json({ error: 'Employee ID and password are required' }, 400, request);
    }

    // Fetch employee by ID (case-insensitive)
    const emp = await env.DB.prepare(
      `SELECT id, employee_id, name, department, designation,
              role, password_hash, status
       FROM   employees
       WHERE  LOWER(employee_id) = LOWER(?)
       LIMIT  1`
    ).bind(employee_id.trim()).first();

    if (!emp) {
      return json({ error: 'Invalid Employee ID or password' }, 401, request);
    }

    if (emp.status === 'inactive') {
      return json({ error: 'Your account has been deactivated. Please contact the admin.' }, 403, request);
    }

    const valid = await verifyPassword(password, emp.password_hash);
    if (!valid) {
      return json({ error: 'Invalid Employee ID or password' }, 401, request);
    }

    // Build JWT payload (no sensitive data)
    const payload = {
      id:          emp.id,
      employee_id: emp.employee_id,
      name:        emp.name,
      department:  emp.department,
      designation: emp.designation,
      role:        emp.role,
    };

    const token = await signJWT(payload, env.JWT_SECRET);

    // Update last_login timestamp (fire-and-forget)
    env.DB.prepare(`UPDATE employees SET last_login = ? WHERE id = ?`)
      .bind(new Date().toISOString(), emp.id)
      .run()
      .catch(() => {});

    return json({ token, user: payload }, 200, request);
  }

  return json({ error: 'Not found' }, 404, request);
}
