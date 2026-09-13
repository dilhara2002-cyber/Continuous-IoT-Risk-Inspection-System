/**
 * Authentication management for Secure IoT System (Chapter 11.2)
 */

const TOKEN_KEY = "iot_sec_token";
const USER_KEY = "iot_sec_user";

function saveSession(token, user) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function getCurrentUser() {
  const user = localStorage.getItem(USER_KEY);
  return user ? JSON.parse(user) : null;
}

function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

function getAuthHeaders() {
  const token = getToken();
  return {
    "Content-Type": "application/json",
    ...(token ? { "Authorization": `Bearer ${token}` } : {})
  };
}

async function handleLogin(username, password) {
  const response = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || "Authentication failed. Check credentials.");
  }

  const data = await response.json();
  saveSession(data.access_token, data.user);
  return data.user;
}

function logout() {
  const token = getToken();
  if (token) {
    fetch("/api/auth/logout", {
      method: "POST",
      headers: getAuthHeaders()
    }).finally(() => {
      clearSession();
      window.location.href = "/login";
    });
  } else {
    clearSession();
    window.location.href = "/login";
  }
}

function checkAuth(requireAuth = true) {
  const token = getToken();
  const currentPath = window.location.pathname;

  if (requireAuth && !token && currentPath !== "/login") {
    window.location.href = "/login";
  } else if (!requireAuth && token && currentPath === "/login") {
    window.location.href = "/";
  }
}
