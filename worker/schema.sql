-- TradeSala Internal Portal — D1 Database Schema
-- Run: wrangler d1 execute tradesala-db --file=schema.sql

-- Employees
CREATE TABLE IF NOT EXISTS employees (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
  name          TEXT    NOT NULL,
  department    TEXT,
  designation   TEXT,
  email         TEXT,
  phone         TEXT,
  join_date     TEXT,
  role          TEXT    NOT NULL DEFAULT 'employee', -- 'employee' | 'admin'
  cl_balance    INTEGER NOT NULL DEFAULT 12,
  sl_balance    INTEGER NOT NULL DEFAULT 12,
  password_hash TEXT    NOT NULL,
  status        TEXT    NOT NULL DEFAULT 'active',   -- 'active' | 'inactive'
  last_login    TEXT,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Attendance
CREATE TABLE IF NOT EXISTS attendance (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id     INTEGER NOT NULL REFERENCES employees(id),
  date            TEXT    NOT NULL,
  check_in        TEXT,
  check_out       TEXT,
  duration_minutes INTEGER,
  status          TEXT    NOT NULL DEFAULT 'present', -- 'present'|'absent'|'leave'|'holiday'
  override_note   TEXT,
  override_by     INTEGER REFERENCES employees(id),
  UNIQUE(employee_id, date)
);

-- Leave Requests
CREATE TABLE IF NOT EXISTS leave_requests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  type        TEXT    NOT NULL,  -- 'CL' | 'SL'
  from_date   TEXT    NOT NULL,
  to_date     TEXT    NOT NULL,
  days        INTEGER NOT NULL,
  reason      TEXT,
  status      TEXT    NOT NULL DEFAULT 'pending', -- 'pending'|'approved'|'rejected'
  reviewed_by INTEGER REFERENCES employees(id),
  reviewed_at TEXT,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Feed Posts
CREATE TABLE IF NOT EXISTS feed_posts (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER NOT NULL REFERENCES employees(id),
  content   TEXT,
  image_url TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Post Likes
CREATE TABLE IF NOT EXISTS post_likes (
  post_id    INTEGER NOT NULL REFERENCES feed_posts(id) ON DELETE CASCADE,
  user_id    INTEGER NOT NULL REFERENCES employees(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (post_id, user_id)
);

-- Post Comments
CREATE TABLE IF NOT EXISTS post_comments (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id    INTEGER NOT NULL REFERENCES feed_posts(id) ON DELETE CASCADE,
  author_id  INTEGER NOT NULL REFERENCES employees(id),
  content    TEXT    NOT NULL,
  created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Activity Log
CREATE TABLE IF NOT EXISTS activity_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES employees(id),
  type        TEXT    NOT NULL, -- 'checkin'|'checkout'|'leave'|'post'
  description TEXT,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_att_emp_date  ON attendance(employee_id, date);
CREATE INDEX IF NOT EXISTS idx_leave_emp     ON leave_requests(employee_id, status);
CREATE INDEX IF NOT EXISTS idx_feed_created  ON feed_posts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_log(user_id, created_at DESC);

-- ─── SEED DATA ───────────────────────────────────────────────────
-- Admin user inserted with temporary password hash.
-- After deploying the worker, visit:
--   https://tradesala-internal.ramsrinivasants2023.workers.dev/auth/seed-admin
-- This will set the real hashed password for Admin@123
-- Then DELETE the /auth/seed-admin route from index.js and redeploy.

INSERT OR IGNORE INTO employees (employee_id, name, department, designation, role, password_hash, cl_balance, sl_balance)
VALUES
  ('ADMIN01', 'Admin User', 'Management', 'System Admin', 'admin', 'PENDING_SEED', 12, 12);

-- ─── NEW MODULES ─────────────────────────────────────────────────

-- Events / Calendar
CREATE TABLE IF NOT EXISTS events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id    INTEGER DEFAULT 1,
  title         TEXT    NOT NULL,
  description   TEXT,
  date          TEXT    NOT NULL,
  time          TEXT,
  end_date      TEXT,
  location      TEXT,
  type          TEXT    NOT NULL DEFAULT 'company', -- company|meeting|holiday|personal
  recurrence    TEXT    NOT NULL DEFAULT 'none',    -- none|daily|weekly|monthly
  organizer_id  INTEGER NOT NULL REFERENCES employees(id),
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Event Participants
CREATE TABLE IF NOT EXISTS event_participants (
  event_id    INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  PRIMARY KEY (event_id, employee_id)
);

-- Tasks
CREATE TABLE IF NOT EXISTS tasks (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id  INTEGER DEFAULT 1,
  title       TEXT    NOT NULL,
  description TEXT,
  priority    TEXT    NOT NULL DEFAULT 'medium', -- low|medium|high
  status      TEXT    NOT NULL DEFAULT 'todo',   -- todo|in_progress|completed|blocked
  due_date    TEXT,
  creator_id  INTEGER NOT NULL REFERENCES employees(id),
  assignee_id INTEGER REFERENCES employees(id),
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Task Comments
CREATE TABLE IF NOT EXISTS task_comments (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id     INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  author_id   INTEGER NOT NULL REFERENCES employees(id),
  content     TEXT    NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Task Activity Log
CREATE TABLE IF NOT EXISTS task_activity (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id     INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  actor_id    INTEGER NOT NULL REFERENCES employees(id),
  description TEXT    NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Queries / Issues
CREATE TABLE IF NOT EXISTS queries (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id  INTEGER DEFAULT 1,
  title       TEXT    NOT NULL,
  description TEXT    NOT NULL,
  department  TEXT    NOT NULL DEFAULT 'IT',
  priority    TEXT    NOT NULL DEFAULT 'medium',
  status      TEXT    NOT NULL DEFAULT 'open', -- open|in_progress|waiting|resolved|closed
  author_id   INTEGER NOT NULL REFERENCES employees(id),
  assignee_id INTEGER REFERENCES employees(id),
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Query Comments
CREATE TABLE IF NOT EXISTS query_comments (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  query_id    INTEGER NOT NULL REFERENCES queries(id) ON DELETE CASCADE,
  author_id   INTEGER NOT NULL REFERENCES employees(id),
  content     TEXT    NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Notifications
CREATE TABLE IF NOT EXISTS notifications (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES employees(id),
  type        TEXT    NOT NULL, -- task|event|leave|query|mention
  message     TEXT    NOT NULL,
  entity_type TEXT,
  entity_id   INTEGER,
  is_read     INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Extended Employee Profile
ALTER TABLE employees ADD COLUMN manager_id    INTEGER REFERENCES employees(id);
ALTER TABLE employees ADD COLUMN work_location TEXT;
ALTER TABLE employees ADD COLUMN shift_schedule TEXT;
ALTER TABLE employees ADD COLUMN emergency_contact TEXT;
ALTER TABLE employees ADD COLUMN employment_status TEXT DEFAULT 'active';

-- Indexes
CREATE INDEX IF NOT EXISTS idx_tasks_assignee  ON tasks(assignee_id, status);
CREATE INDEX IF NOT EXISTS idx_tasks_creator   ON tasks(creator_id);
CREATE INDEX IF NOT EXISTS idx_events_date     ON events(date);
CREATE INDEX IF NOT EXISTS idx_queries_status  ON queries(status, department);
CREATE INDEX IF NOT EXISTS idx_notifs_user     ON notifications(user_id, is_read, created_at DESC);
