"use strict";
document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = document.getElementById("err");
  err.textContent = "";
  try {
    const r = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Requested-With": "skynet" },
      body: JSON.stringify({ username: document.getElementById("u").value, password: document.getElementById("p").value }),
    });
    if (r.ok) { location.href = "/"; return; }
    const d = await r.json().catch(() => ({}));
    err.textContent = d.detail || `Giriş başarısız (HTTP ${r.status})`;
  } catch {
    err.textContent = "Sunucuya ulaşılamadı.";
  }
});
