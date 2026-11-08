const DEFAULT_DATA = {
  storeName: "В'язаний затишок",
  category: "В'язання і хендмейд",
  tier: "Free",
  accent: "#D9643F",
  products: [
    { name: "Шапка", price: "320 ₴" },
    { name: "Шарф", price: "280 ₴" },
    { name: "Светр", price: "650 ₴" },
    { name: "Рукавички", price: "180 ₴" }
  ]
};

const LOGIN_LIMIT = 5;
const LOGIN_WINDOW = 900;

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function verifyPassword(password, stored) {
  const parts = (stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = parseInt(parts[1], 10);
  const salt = hexToBytes(parts[2]);
  const expectedHex = parts[3];
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial, 256
  );
  const gotHex = bytesToHex(new Uint8Array(bits));
  return timingSafeEqual(gotHex, expectedHex);
}

function getClientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

async function getFailCount(env, key) {
  const raw = await env.ZROZOK_STORE.get(key);
  return raw ? parseInt(raw, 10) || 0 : 0;
}

async function bumpFailCount(env, key) {
  const count = (await getFailCount(env, key)) + 1;
  await env.ZROZOK_STORE.put(key, String(count), { expirationTtl: LOGIN_WINDOW });
  return count;
}

async function clearFailCount(env, key) {
  await env.ZROZOK_STORE.delete(key);
}

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function makeSession(env) {
  const exp = Math.floor(Date.now() / 1000) + 2 * 3600;
  const secret = await env.SESSION_SECRET.get();
  const sig = await hmac(secret, String(exp));
  return `${exp}.${sig}`;
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function isAuthed(request, env) {
  const raw = getCookie(request, "zr_adm");
  if (!raw) return false;
  const [expStr, sig] = raw.split(".");
  if (!expStr || !sig) return false;
  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() / 1000 > exp) return false;
  const secret = await env.SESSION_SECRET.get();
  const expected = await hmac(secret, expStr);
  return expected === sig;
}

async function loadData(env) {
  const raw = await env.ZROZOK_STORE.get("store:main");
  if (!raw) return DEFAULT_DATA;
  try {
    const parsed = JSON.parse(raw);
    return { ...DEFAULT_DATA, ...parsed };
  } catch {
    return DEFAULT_DATA;
  }
}

async function saveData(env, data) {
  await env.ZROZOK_STORE.put("store:main", JSON.stringify(data));
}

function renderStorefront(data, authed) {
  const limit = data.tier === "Pro" ? 10 : 4;
  const products = (data.products || []).slice(0, limit);
  const cardsHtml = products.map((p) => `
        <li class="card"><div class="card-photo"><span>фото товару</span></div><div class="card-body"><div class="card-name">${esc(p.name)}</div><div class="card-price">${esc(p.price)}</div></div></li>`).join("");
  const tierNote = data.tier === "Pro"
    ? "Показано до 10 товарів. Великий каталог (до 1000) — через Базар Толока."
    : `Показано ${products.length} товари. Більше — на тарифі Pro.`;
  const storeInitial = (data.storeName || "М").trim().charAt(0).toUpperCase();
  const cornerBtn = authed
    ? `<a href="/admin" class="cart-btn" aria-label="Редагувати" style="text-decoration:none;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2A2D33" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 1 1 3 3L7 19l-4 1 1-4Z"/></svg>
      </a>`
    : `<button type="button" class="cart-btn" aria-label="Кошик">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#2A2D33" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 4h2l2.2 11.6a2 2 0 0 0 2 1.6h7.2a2 2 0 0 0 2-1.6L20 8H6"/><circle cx="9.5" cy="20" r="1.2" fill="#2A2D33" stroke="none"/><circle cx="17" cy="20" r="1.2" fill="#2A2D33" stroke="none"/></svg>
      </button>`;

  return `<!doctype html>
<html lang="uk">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(data.storeName)} — вітрина</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Neucha&family=Onest:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/assets/style.css">
<style>:root{--accent:${esc(data.accent)};}</style>
</head>
<body>
<div class="page">
  <div class="vitryna">

    <svg class="doodle" style="top:14px;left:14px;" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#2A2D33" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M18.4 5.6l-2.8 2.8M8.4 15.6l-2.8 2.8"/></svg>
    <svg class="doodle" style="top:100px;right:10px;" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#2A2D33" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20s-7-4.4-9.3-8.8C1.3 8 2.7 5 5.8 4.7c1.8-.2 3.3.8 4.2 2.2.9-1.4 2.4-2.4 4.2-2.2 3.1.3 4.5 3.3 3.1 6.5C15 15.6 12 20 12 20Z"/></svg>

    <header class="header">
      <div class="shop-id">
        <div class="avatar">${esc(storeInitial)}</div>
        <div>
          <div class="shop-name">${esc(data.storeName)}</div>
          <span class="category-pill">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20.5 11.5 12.5 3.5H5a2 2 0 0 0-2 2v7.5l10 10a2 2 0 0 0 2.8 0l5.2-5.2a2 2 0 0 0 .5-2.3Z"/><circle cx="8" cy="8" r="1.1" fill="currentColor" stroke="none"/></svg>
            ${esc(data.category)}
          </span>
        </div>
      </div>
      ${cornerBtn}
    </header>

    <section class="products">
      <ul class="grid">${cardsHtml}
      </ul>
      <p class="tier-note">${esc(tierNote)}</p>
    </section>

    <div class="pay">
      <button type="button" class="btn-pay">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2A2D33" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2.5" y="5" width="19" height="14" rx="2.5"/><path d="M2.5 9.5h19"/></svg>
        Оплатити замовлення
      </button>
    </div>

    <div class="calls">
      <div class="call-grid">
        <button type="button" class="call-btn call-audio">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2A2D33" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 4h4l2 5-2.5 2.5a11 11 0 0 0 5 5L16 14l5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2Z"/></svg>
          <span>Аудіо</span>
        </button>
        <button type="button" class="call-btn call-video">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2A2D33" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2.5" y="6.5" width="13" height="11" rx="2"/><path d="m15.5 10 5.5-3v10l-5.5-3Z"/></svg>
          <span>Відео</span>
        </button>
        <button type="button" class="call-btn call-chat">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2A2D33" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 11.5a8.4 8.4 0 0 1-1.1 4.2L21 20l-4.5-1a8.5 8.5 0 1 1 4.5-7.5Z"/></svg>
          <span>Чат</span>
        </button>
      </div>
      <p class="call-caption">через Голосник · дзвінок у браузері, без номера</p>
    </div>

    <footer class="footer">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#857a65" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v4M12 17v4M3 12h4M17 12h4"/></svg>
      <a href="https://magistral-it.com">Розроблено Магістраль-ІТ</a>
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#857a65" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v4M12 17v4M3 12h4M17 12h4"/></svg>
    </footer>

  </div>
</div>
</body>
</html>`;
}

function renderLoginPage(error) {
  return `<!doctype html>
<html lang="uk">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Вхід — zrozok</title>
<meta name="robots" content="noindex">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Neucha&family=Onest:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/assets/style.css">
</head>
<body>
<div class="page" style="display:flex;align-items:center;justify-content:center;">
  <div class="vitryna" style="padding:32px 24px;">
    <div class="shop-name" style="font-size:26px;text-align:center;margin-bottom:18px;">Вхід у вітрину</div>
    ${error ? `<p style="color:#b4432f;font-size:13px;text-align:center;margin:0 0 14px;">${esc(error)}</p>` : ""}
    <form method="POST" action="/admin/login" style="display:flex;flex-direction:column;gap:12px;">
      <label style="font-size:13px;color:var(--graphite);">
        ID Голосника
        <input type="text" name="holosnyk_id" placeholder="ГЛС-0000-XXX" required style="width:100%;margin-top:4px;padding:10px 12px;border:2px solid var(--ink);border-radius:12px;font-size:14px;box-sizing:border-box;">
      </label>
      <label style="font-size:13px;color:var(--graphite);">
        Пароль
        <input type="password" name="password" required style="width:100%;margin-top:4px;padding:10px 12px;border:2px solid var(--ink);border-radius:12px;font-size:14px;box-sizing:border-box;">
      </label>
      <button type="submit" class="btn-pay">Увійти</button>
    </form>
    <p style="font-size:11px;color:var(--muted);text-align:center;margin-top:16px;">Тимчасовий вхід. Пізніше — через Голосник.</p>
  </div>
</div>
</body>
</html>`;
}

function renderAdminForm(data, saved) {
  const productsText = (data.products || []).map((p) => `${p.name}; ${p.price}`).join("\n");
  return `<!doctype html>
<html lang="uk">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Адмінка — zrozok</title>
<meta name="robots" content="noindex">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Neucha&family=Onest:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/assets/style.css">
</head>
<body>
<div class="page">
  <div class="vitryna" style="max-width:480px;padding:28px 22px;">
    <div class="shop-name" style="font-size:24px;">Редагування вітрини</div>
    ${saved ? `<p style="color:#2f7a4d;font-size:13px;margin:10px 0 0;">Збережено.</p>` : ""}
    <form method="POST" action="/admin/save" style="display:flex;flex-direction:column;gap:14px;margin-top:16px;">
      <label style="font-size:13px;color:var(--graphite);">
        Назва магазину
        <input type="text" name="store_name" value="${esc(data.storeName)}" required style="width:100%;margin-top:4px;padding:10px 12px;border:2px solid var(--ink);border-radius:12px;font-size:14px;box-sizing:border-box;">
      </label>
      <label style="font-size:13px;color:var(--graphite);">
        Категорія
        <input type="text" name="category" value="${esc(data.category)}" required style="width:100%;margin-top:4px;padding:10px 12px;border:2px solid var(--ink);border-radius:12px;font-size:14px;box-sizing:border-box;">
      </label>
      <label style="font-size:13px;color:var(--graphite);">
        Тариф
        <select name="tier" style="width:100%;margin-top:4px;padding:10px 12px;border:2px solid var(--ink);border-radius:12px;font-size:14px;box-sizing:border-box;">
          <option value="Free" ${data.tier === "Free" ? "selected" : ""}>Free (4 товари)</option>
          <option value="Pro" ${data.tier === "Pro" ? "selected" : ""}>Pro (до 10 товарів)</option>
        </select>
      </label>
      <label style="font-size:13px;color:var(--graphite);">
        Акцентний колір
        <input type="color" name="accent" value="${esc(data.accent)}" style="display:block;margin-top:4px;width:60px;height:36px;border:2px solid var(--ink);border-radius:8px;padding:2px;">
      </label>
      <label style="font-size:13px;color:var(--graphite);">
        Товари — по одному в рядку, формат «Назва; Ціна»
        <textarea name="products_text" rows="6" style="width:100%;margin-top:4px;padding:10px 12px;border:2px solid var(--ink);border-radius:12px;font-size:13px;box-sizing:border-box;font-family:inherit;">${esc(productsText)}</textarea>
      </label>
      <button type="submit" class="btn-pay">Зберегти</button>
    </form>
    <div style="display:flex;justify-content:space-between;margin-top:18px;">
      <a href="/" style="font-size:12px;color:var(--muted);">← На вітрину</a>
      <a href="/admin/logout" style="font-size:12px;color:var(--muted);">Вийти</a>
    </div>
  </div>
</div>
</body>
</html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/admin/login" && request.method === "POST") {
      const form = await request.formData();
      const id = (form.get("holosnyk_id") || "").toString().trim();
      const pass = (form.get("password") || "").toString();
      const ip = getClientIp(request);
      const idKey = `login_fail:id:${id || "empty"}`;
      const ipKey = `login_fail:ip:${ip}`;

      const [idFails, ipFails] = await Promise.all([
        getFailCount(env, idKey),
        getFailCount(env, ipKey)
      ]);
      if (idFails >= LOGIN_LIMIT || ipFails >= LOGIN_LIMIT) {
        return new Response(renderLoginPage("Забагато спроб. Спробуйте через 15 хвилин."), {
          status: 429,
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }

      const storedId = await env.ADMIN_HOLOSNYK_ID.get();
      const storedHash = await env.ADMIN_PASSWORD_HASH.get();
      const idOk = Boolean(id) && id === storedId;
      const passOk = Boolean(pass) && (await verifyPassword(pass, storedHash));

      if (idOk && passOk) {
        await Promise.all([clearFailCount(env, idKey), clearFailCount(env, ipKey)]);
        const token = await makeSession(env);
        return new Response(null, {
          status: 303,
          headers: {
            "Location": "/admin",
            "Set-Cookie": `zr_adm=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=7200`
          }
        });
      }

      await Promise.all([bumpFailCount(env, idKey), bumpFailCount(env, ipKey)]);
      return new Response(renderLoginPage("Невірний ID або пароль."), {
        status: 401,
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    if (path === "/admin/logout") {
      return new Response(null, {
        status: 303,
        headers: {
          "Location": "/admin",
          "Set-Cookie": "zr_adm=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
        }
      });
    }

    if (path === "/admin/save" && request.method === "POST") {
      const authed = await isAuthed(request, env);
      if (!authed) {
        return new Response(null, { status: 303, headers: { "Location": "/admin" } });
      }
      const form = await request.formData();
      const productsText = (form.get("products_text") || "").toString();
      const products = productsText.split("\n").map((l) => l.trim()).filter(Boolean).map((line) => {
        const idx = line.indexOf(";");
        if (idx === -1) return { name: line.trim(), price: "" };
        return { name: line.slice(0, idx).trim(), price: line.slice(idx + 1).trim() };
      });
      const data = {
        storeName: (form.get("store_name") || "").toString().trim() || DEFAULT_DATA.storeName,
        category: (form.get("category") || "").toString().trim() || DEFAULT_DATA.category,
        tier: form.get("tier") === "Pro" ? "Pro" : "Free",
        accent: (form.get("accent") || "").toString().trim() || DEFAULT_DATA.accent,
        products
      };
      await saveData(env, data);
      return new Response(null, { status: 303, headers: { "Location": "/admin?saved=1" } });
    }

    if (path === "/admin" && (request.method === "GET" || request.method === "POST")) {
      const authed = await isAuthed(request, env);
      if (!authed) {
        return new Response(renderLoginPage(null), {
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }
      const data = await loadData(env);
      return new Response(renderAdminForm(data, url.searchParams.get("saved") === "1"), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    if (path === "/") {
      const authed = await isAuthed(request, env);
      const data = await loadData(env);
      return new Response(renderStorefront(data, authed), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    return env.ASSETS.fetch(request);
  }
};
