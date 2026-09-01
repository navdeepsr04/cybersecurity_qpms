const API_BASE = "http://127.0.0.1:8000";
const TOKEN_KEY = "qpms_token";

function getToken() { return localStorage.getItem(TOKEN_KEY); }
function setToken(t) { localStorage.setItem(TOKEN_KEY, t); }
function clearToken() { localStorage.removeItem(TOKEN_KEY); }

// JWTs are signed, not encrypted -- decoding the payload client-side just
// reads what the server already told the browser (username, role, expiry).
// It is NOT a trust boundary; every real permission check still happens
// server-side via require_role().
function decodeToken() {
  const token = getToken();
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split(".")[1]));
    if (payload.exp && Date.now() >= payload.exp * 1000) {
      clearToken();
      return null;
    }
    return payload; // { sub: username, role, exp }
  } catch {
    return null;
  }
}

// Call at the top of every protected page. Redirects if not logged in, or
// if logged in as the wrong role.
function requireAuth(requiredRole) {
  const payload = decodeToken();
  if (!payload) {
    window.location.replace("login.html");
    return null;
  }
  if (requiredRole && payload.role !== requiredRole) {
    window.location.replace("dashboard.html");
    return null;
  }
  return payload;
}

// Wraps fetch() with the Authorization header and handles token expiry.
async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { ...(options.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 401) {
    clearToken();
    window.location.replace("login.html");
    throw new Error("Session expired");
  }
  return res;
}

// FastAPI validation errors come back as {detail: [{msg, loc}, ...]} for
// 422s, or {detail: "some string"} for everything else. Normalize both.
async function readError(res) {
  try {
    const body = await res.json();
    if (Array.isArray(body.detail)) {
      return body.detail.map((d) => d.msg).join("; ");
    }
    return body.detail || `Request failed (${res.status})`;
  } catch {
    return `Request failed (${res.status})`;
  }
}

function showMsg(el, text, kind) {
  el.textContent = text;
  el.className = `msg show msg-${kind}`;
}

function hideMsg(el) {
  el.className = "msg";
}

async function logout() {
  try {
    await apiFetch("/auth/logout", { method: "POST" });
  } catch {
    /* already logged out client-side either way */
  }
  clearToken();
  window.location.replace("login.html");
}

function stampHtml(status) {
  return `<span class="stamp stamp-${status}">${status}</span>`;
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s ?? "";
  return div.innerHTML;
}