// ─── CONFIG ────────────────────────────────────────────────────
const CONFIG = {
  WORKER_URL: 'https://tradesala-internal.ramsrinivasants2023.workers.dev',
  COMPANY_NAME: 'Ramsrinivasan.in',
  COMPANY_SUBTITLE: 'Internal Portal',
  BASE_PATH: '/tradesala-internal'
};

// ─── AUTH ───────────────────────────────────────────────────────
const Auth = {
  getToken: () => localStorage.getItem('ts_token'),
  getUser: () => {
    try { return JSON.parse(localStorage.getItem('ts_user') || 'null'); }
    catch { return null; }
  },
  setSession: (token, user) => {
    localStorage.setItem('ts_token', token);
    localStorage.setItem('ts_user', JSON.stringify(user));
  },
  clearSession: () => {
    localStorage.removeItem('ts_token');
    localStorage.removeItem('ts_user');
  },
  isLoggedIn: () => !!localStorage.getItem('ts_token'),
  isAdmin: () => {
    const u = Auth.getUser();
    return u && u.role === 'admin';
  },
  requireAuth: () => {
    if (!Auth.isLoggedIn()) {
      window.location.href = CONFIG.BASE_PATH + '/login.html';
      return null;
    }
    return Auth.getUser();
  },
  requireAdmin: () => {
    const u = Auth.requireAuth();
    if (u && u.role !== 'admin') {
      window.location.href = CONFIG.BASE_PATH + '/index.html';
      return null;
    }
    return u;
  }
};

// ─── API ─────────────────────────────────────────────────────────
const API = {
  async request(method, path, body = null) {
    const headers = { 'Content-Type': 'application/json' };
    const token = Auth.getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);
    try {
      const res = await fetch(CONFIG.WORKER_URL + path, opts);
      const data = await res.json();
      if (res.status === 401) { Auth.clearSession(); window.location.href = CONFIG.BASE_PATH + '/login.html'; }
      return { ok: res.ok, status: res.status, data };
    } catch (e) {
      return { ok: false, data: { error: 'Network error. Please check connection.' } };
    }
  },
  get: (path) => API.request('GET', path),
  post: (path, body) => API.request('POST', path, body),
  put: (path, body) => API.request('PUT', path, body),
  delete: (path) => API.request('DELETE', path),
};

// ─── THEME ──────────────────────────────────────────────────────
const Theme = {
  get: () => localStorage.getItem('ts_theme') || 'light',
  set: (t) => {
    localStorage.setItem('ts_theme', t);
    document.documentElement.setAttribute('data-theme', t);
    const btn = document.querySelector('.theme-toggle');
    if (btn) btn.textContent = t === 'dark' ? '☀️' : '🌙';
  },
  toggle: () => Theme.set(Theme.get() === 'dark' ? 'light' : 'dark'),
  init: () => Theme.set(Theme.get())
};

// ─── TOAST ──────────────────────────────────────────────────────
const Toast = {
  container: null,
  init() {
    this.container = document.createElement('div');
    this.container.className = 'toast-container';
    document.body.appendChild(this.container);
  },
  show(msg, type = 'info', duration = 3500) {
    if (!this.container) this.init();
    const icons = { success: '✅', error: '❌', info: 'ℹ️', warning: '⚠️' };
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${msg}</span>`;
    this.container.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; t.style.transform = 'translateX(16px)'; t.style.transition = 'all .3s'; setTimeout(() => t.remove(), 300); }, duration);
  },
  success: (m) => Toast.show(m, 'success'),
  error: (m) => Toast.show(m, 'error'),
  info: (m) => Toast.show(m, 'info'),
};

// ─── SIDEBAR ─────────────────────────────────────────────────────
function buildSidebar(activePage) {
  const user = Auth.getUser();
  if (!user) return;

  const isAdmin = user.role === 'admin';
  const initials = user.name ? user.name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0,2) : 'U';

  const navItems = [
    { id: 'dashboard',  label: 'Dashboard',   icon: iconGrid,     href: CONFIG.BASE_PATH + '/index.html' },
    { id: 'attendance', label: 'Attendance',   icon: iconClock,    href: CONFIG.BASE_PATH + '/attendance.html' },
    { id: 'leave',      label: 'Leave',        icon: iconCalendar, href: CONFIG.BASE_PATH + '/leave.html' },
    { id: 'tasks',      label: 'Tasks',        icon: iconTask,     href: CONFIG.BASE_PATH + '/tasks.html' },
    { id: 'calendar',   label: 'Calendar',     icon: iconCalFull,  href: CONFIG.BASE_PATH + '/calendar.html' },
    { id: 'queries',    label: 'Queries',      icon: iconQuery,    href: CONFIG.BASE_PATH + '/queries.html' },
    { id: 'feed',       label: 'Company Feed', icon: iconFeed,     href: CONFIG.BASE_PATH + '/feed.html' },
    { id: 'employees',  label: 'Employees',    icon: iconPeople,   href: CONFIG.BASE_PATH + '/employees.html' },
  ];

  const adminItems = [
    { id: 'admin',   label: 'Admin Center', icon: iconShield,  href: CONFIG.BASE_PATH + '/admin/index.html' },
    { id: 'reports', label: 'Reports',      icon: iconReports, href: CONFIG.BASE_PATH + '/reports.html' },
  ];

  // On mobile, tapping a nav link should close the sidebar before navigating
  const mobileClose = 'onclick="if(window.innerWidth<=768)closeSidebar()"';

  let navHTML = navItems.map(item => `
    <a href="${item.href}" class="nav-item ${activePage === item.id ? 'active' : ''}" ${mobileClose}>
      ${item.icon()}
      <span>${item.label}</span>
    </a>
  `).join('');

  if (isAdmin) {
    navHTML += `<div class="nav-label">Administration</div>`;
    navHTML += adminItems.map(item => `
      <a href="${item.href}" class="nav-item ${activePage === item.id ? 'active' : ''}" ${mobileClose}>
        ${item.icon()}
        <span>${item.label}</span>
      </a>
    `).join('');
  }

  const sidebarEl = document.querySelector('.sidebar');
  if (!sidebarEl) return;

  sidebarEl.innerHTML = `
    <div class="sidebar-brand">
      <div class="sidebar-logo">TS</div>
      <div class="sidebar-brand-text">
        ${CONFIG.COMPANY_NAME}
        <span>${CONFIG.COMPANY_SUBTITLE}</span>
      </div>
    </div>
    <nav class="sidebar-nav">
      <div class="nav-label">Main Menu</div>
      ${navHTML}
    </nav>
    <div class="sidebar-footer">
      <div class="sidebar-user" onclick="handleLogout()">
        <div class="avatar">${initials}</div>
        <div>
          <div class="sidebar-user-name">${user.name || 'Employee'}</div>
          <div class="sidebar-user-id">#${user.employee_id || '---'}</div>
        </div>
        <svg style="margin-left:auto;width:13px;height:13px;opacity:.3;color:#fff;flex-shrink:0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      </div>
    </div>
  `;
}

function buildTopbar(title) {
  const user = Auth.getUser();
  if (!user) return;
  const initials = user.name ? user.name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0,2) : 'U';
  const topbar = document.querySelector('.topbar');
  if (!topbar) return;
  // menuToggle visibility is controlled by CSS (display:none on desktop, flex on mobile)
  // No inline style or JS-based show/hide needed — works across resize & orientation change
  topbar.innerHTML = `
    <button class="btn btn-ghost" id="menuToggle" aria-label="Open navigation" onclick="toggleSidebar()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px;display:block"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
    </button>
    <div class="topbar-title">${title}</div>
    <div class="topbar-actions">
      <div class="notif-btn-wrap">
        <button class="notif-btn" onclick="toggleNotifPanel(event)" aria-label="Notifications" id="notifBtn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:15px;height:15px"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
          <div class="notif-dot" id="notifDot" style="display:none"></div>
        </button>
        <div class="notif-panel" id="notifPanel" style="display:none">
          <div class="notif-panel-header">
            <span class="notif-panel-title">Notifications</span>
            <button class="btn btn-ghost btn-sm" onclick="markAllRead()">Mark all read</button>
          </div>
          <div class="notif-list" id="notifList">
            <div style="padding:24px;text-align:center;color:var(--text-muted);font-size:13px">Loading…</div>
          </div>
        </div>
      </div>
      <button class="theme-toggle" onclick="Theme.toggle()" aria-label="Toggle theme">${Theme.get() === 'dark' ? '☀️' : '🌙'}</button>
      <div class="topbar-profile">
        <div class="avatar">${initials}</div>
        <div class="topbar-profile-info">
          <div class="topbar-profile-name">${user.name || 'Employee'}</div>
          <div class="topbar-profile-id">${user.employee_id || '---'} · ${user.department || 'Staff'}</div>
        </div>
      </div>
    </div>
  `;
}

function toggleSidebar() {
  const sidebar = document.querySelector('.sidebar');
  if (!sidebar) return;

  const isOpen = sidebar.classList.contains('open');

  // Create overlay if it doesn't exist
  let overlay = document.getElementById('sidebarOverlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'sidebarOverlay';
    overlay.className = 'sidebar-overlay';
    overlay.addEventListener('click', closeSidebar);
    document.body.appendChild(overlay);
  }

  if (isOpen) {
    closeSidebar();
  } else {
    sidebar.classList.add('open');
    overlay.classList.add('open');
    document.body.style.overflow = 'hidden';
  }
}

function closeSidebar() {
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  if (sidebar) sidebar.classList.remove('open');
  if (overlay) overlay.classList.remove('open');
  document.body.style.overflow = '';
}

// Close sidebar with Escape key on mobile
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeSidebar();
});

function handleLogout() {
  if (confirm('Sign out of the portal?')) {
    Auth.clearSession();
    window.location.href = CONFIG.BASE_PATH + '/login.html';
  }
}

// ─── ICONS ──────────────────────────────────────────────────────
const iconGrid     = () => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>`;
const iconClock    = () => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`;
const iconCalendar = () => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`;
const iconFeed     = () => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`;
const iconPeople   = () => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`;
const iconShield   = () => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
const iconTask     = () => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>`;
const iconCalFull  = () => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/><line x1="8" y1="14" x2="8" y2="14"/><line x1="12" y1="14" x2="12" y2="14"/><line x1="16" y1="14" x2="16" y2="14"/></svg>`;
const iconQuery    = () => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
const iconReports  = () => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>`;

// ─── UTILS ──────────────────────────────────────────────────────
const Utils = {
  formatDate: (d) => {
    if (!d) return '—';
    return new Date(d).toLocaleDateString('en-IN', { timeZone: 'Asia/Kolkata', day: 'numeric', month: 'short', year: 'numeric' });
  },
  formatTime: (d) => {
    if (!d) return '—';
    return new Date(d).toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit' });
  },
  formatDateTime: (d) => {
    if (!d) return '—';
    const dt = new Date(d);
    return dt.toLocaleDateString('en-IN', { timeZone: 'Asia/Kolkata', day: 'numeric', month: 'short' }) + ' · ' +
           dt.toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit' });
  },
  timeAgo: (d) => {
    const diff = Date.now() - new Date(d).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1) return 'Just now';
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return Utils.formatDate(d);
  },
  initials: (name) => name ? name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0,2) : '?',
  debounce: (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; },
};

// ─── MODAL HELPERS ──────────────────────────────────────────────
function openModal(id) { document.getElementById(id)?.classList.add('open'); }
function closeModal(id) { document.getElementById(id)?.classList.remove('open'); }
document.addEventListener('click', (e) => {
  if (e.target.classList.contains('modal-overlay')) {
    e.target.classList.remove('open');
  }
});

// ─── NOTIFICATIONS ──────────────────────────────────────────────
const Notifications = {
  cache: [],
  async load() {
    const res = await API.get('/notifications');
    if (!res.ok) return;
    this.cache = res.data.notifications || [];
    this.render();
  },
  render() {
    const list = document.getElementById('notifList');
    const dot  = document.getElementById('notifDot');
    if (!list) return;
    const unread = this.cache.filter(n => !n.is_read).length;
    if (dot) dot.style.display = unread > 0 ? 'block' : 'none';
    if (!this.cache.length) {
      list.innerHTML = '<div style="padding:28px;text-align:center;color:var(--text-muted);font-size:13px">No notifications yet</div>';
      return;
    }
    const iconMap = { task: '📋', event: '📅', leave: '🏖️', query: '❓', mention: '💬', default: '🔔' };
    list.innerHTML = this.cache.map(n => `
      <div class="notif-item ${n.is_read ? '' : 'unread'}" onclick="Notifications.markRead(${n.id})">
        <div class="notif-icon">${iconMap[n.type] || iconMap.default}</div>
        <div style="flex:1;min-width:0">
          <div class="notif-text">${n.message}</div>
          <div class="notif-time">${Utils.timeAgo(n.created_at)}</div>
        </div>
      </div>
    `).join('');
  },
  async markRead(id) {
    await API.put('/notifications/' + id + '/read', {});
    const n = this.cache.find(x => x.id === id);
    if (n) n.is_read = true;
    this.render();
  },
};

async function markAllRead() {
  await API.post('/notifications/read-all', {});
  Notifications.cache.forEach(n => n.is_read = true);
  Notifications.render();
}

function toggleNotifPanel(e) {
  e.stopPropagation();
  const panel = document.getElementById('notifPanel');
  const isOpen = panel.style.display !== 'none';
  panel.style.display = isOpen ? 'none' : 'block';
  if (!isOpen) Notifications.load();
}

document.addEventListener('click', (e) => {
  const panel = document.getElementById('notifPanel');
  const btn   = document.getElementById('notifBtn');
  if (panel && !panel.contains(e.target) && e.target !== btn && !btn?.contains(e.target)) {
    panel.style.display = 'none';
  }
});

// ─── INIT ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  Theme.init();
  Toast.init();
  // Load notifications if logged in
  if (Auth.isLoggedIn()) setTimeout(() => Notifications.load(), 1000);
});

// Close sidebar when resizing to desktop to avoid stale open state
window.addEventListener('resize', () => {
  if (window.innerWidth > 768) {
    closeSidebar();
  }
});
