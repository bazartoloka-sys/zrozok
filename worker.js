const DEFAULT_DATA = {
  storeName: "В'язаний затишок",
  category: "В'язання і хендмейд",
  tier: "Free",
  accent: "#D9643F",
  avatar: "",
  slug: "",
  legal: {
    fullName: "", regNumber: "", legalAddress: "", returnAddress: "",
    email: "", phone: "", licenseInfo: ""
  },
  products: [
    { name: "Шапка", price: "320 ₴", photo: "" },
    { name: "Шарф", price: "280 ₴", photo: "" },
    { name: "Светр", price: "650 ₴", photo: "" },
    { name: "Рукавички", price: "180 ₴", photo: "" }
  ]
};

const LOGIN_LIMIT = 5;
const LOGIN_WINDOW = 900;
const SESSION_TTL = 2 * 3600;
const CODE_TTL = 86400;
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const MIN_PASSWORD = 8;
const MAX_PHOTO_BYTES = 4 * 1024 * 1024;

const PUBLIC_HOST_SUFFIXES = [".tiktok.bazar.in.ua", ".insta.bazar.in.ua"];

const RESERVED_SLUGS = new Set([
  "www", "api", "admin", "owner", "mail", "ftp", "ns1", "ns2", "app",
  "static", "assets", "test", "null", "undefined", "photos", "activate",
  "cabinet", "support", "help", "zrozok", "torg", "bazar", "magistral"
]);

const HOMOGLYPHS = {
  A: "А", B: "В", C: "С", E: "Е", H: "Н", I: "І", K: "К",
  M: "М", O: "О", P: "Р", T: "Т", X: "Х", Y: "У"
};

const TRANSLIT = {
  "а": "a", "б": "b", "в": "v", "г": "h", "ґ": "g", "д": "d", "е": "e",
  "є": "ye", "ж": "zh", "з": "z", "и": "y", "і": "i", "ї": "yi", "й": "y",
  "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p", "р": "r",
  "с": "s", "т": "t", "у": "u", "ф": "f", "х": "kh", "ц": "ts", "ч": "ch",
  "ш": "sh", "щ": "shch", "ю": "yu", "я": "ya", "ь": "", "ъ": "",
  "ы": "y", "э": "e"
};

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function normalizeId(raw) {
  const up = String(raw || "").trim().toUpperCase().replace(/\s+/g, "");
  let out = "";
  for (const ch of up) out += HOMOGLYPHS[ch] || ch;
  return out;
}

function slugify(raw) {
  const lower = String(raw || "").trim().toLowerCase();
  let out = "";
  for (const ch of lower) {
    if (TRANSLIT[ch] !== undefined) out += TRANSLIT[ch];
    else if (/[a-z0-9]/.test(ch)) out += ch;
    else out += "-";
  }
  out = out.replace(/-+/g, "-").replace(/^-+|-+$/g, "");
  return out.slice(0, 40);
}

function isValidSlug(s) {
  return /^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/.test(s) && !RESERVED_SLUGS.has(s);
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

function b64urlEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s) {
  const bin = atob(String(s).replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

async function sha256hex(text) {
  const bits = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return bytesToHex(new Uint8Array(bits));
}

async function derive(password, salt, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial, 256
  );
  return bytesToHex(new Uint8Array(bits));
}

async function hashPassword(password) {
  const iterations = 100000;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hashHex = await derive(password, salt, iterations);
  return `pbkdf2$${iterations}$${bytesToHex(salt)}$${hashHex}`;
}

async function verifyPassword(password, stored) {
  const parts = (stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = parseInt(parts[1], 10);
  const gotHex = await derive(password, hexToBytes(parts[2]), iterations);
  return timingSafeEqual(gotHex, parts[3]);
}

function makeCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let out = "";
  for (let i = 0; i < 8; i++) {
    out += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
    if (i === 3) out += "-";
  }
  return out;
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
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bytesToHex(new Uint8Array(sig));
}

async function makeSession(env, payload) {
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + SESSION_TTL };
  const encoded = b64urlEncode(JSON.stringify(body));
  const sig = await hmac(await env.SESSION_SECRET.get(), encoded);
  return `${encoded}.${sig}`;
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function readSession(request, env) {
  const raw = getCookie(request, "zr_s");
  if (!raw) return null;
  const [encoded, sig] = raw.split(".");
  if (!encoded || !sig) return null;
  const expected = await hmac(await env.SESSION_SECRET.get(), encoded);
  if (!timingSafeEqual(expected, sig)) return null;
  try {
    const body = JSON.parse(b64urlDecode(encoded));
    if (!body.exp || Date.now() / 1000 > body.exp) return null;
    return body;
  } catch {
    return null;
  }
}

function sessionCookie(token) {
  return `zr_s=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL}`;
}

const CLEAR_COOKIE = "zr_s=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";

async function loadData(env, id) {
  const raw = await env.ZROZOK_STORE.get(`store:${id}`);
  if (!raw) return DEFAULT_DATA;
  try {
    return { ...DEFAULT_DATA, ...JSON.parse(raw), legal: { ...DEFAULT_DATA.legal, ...(JSON.parse(raw).legal || {}) } };
  } catch {
    return DEFAULT_DATA;
  }
}

async function saveData(env, id, data) {
  await env.ZROZOK_STORE.put(`store:${id}`, JSON.stringify(data));
}

async function getSeller(env, id) {
  const raw = await env.ZROZOK_STORE.get(`seller:${id}`);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function html(body, status) {
  return new Response(body, {
    status: status || 200,
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}

function redirect(location, cookie) {
  const headers = { "Location": location };
  if (cookie) headers["Set-Cookie"] = cookie;
  return new Response(null, { status: 303, headers });
}

const HEAD = `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Neucha&family=Onest:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/assets/style.css">`;

const FIELD = "width:100%;margin-top:4px;padding:10px 12px;border:2px solid var(--ink);border-radius:12px;font-size:14px;box-sizing:border-box;";
const LABEL = "font-size:13px;color:var(--graphite);";

function renderKutochok(legal) {
  const regLine = legal.regNumber ? ` · Рег. номер: ${esc(legal.regNumber)}` : "";
  const returnLine = legal.returnAddress ? `Адреса для повернень: ${esc(legal.returnAddress)}<br>` : "";
  const phoneLine = legal.phone ? ` · ${esc(legal.phone)}` : "";
  const licenseBlock = legal.licenseInfo ? `<p>Дозвільний документ: ${esc(legal.licenseInfo)}</p>` : "";

  return `
    <details id="kutochok" style="margin-top:24px;padding-top:18px;border-top:2px dashed var(--ink);font-size:12px;line-height:1.55;text-align:left;color:#3a362f;">
      <summary style="cursor:pointer;font-family:'Neucha',cursive;font-size:20px;margin:0 0 10px;color:var(--ink);">Куточок покупця</summary>

      <h3 id="prodavets" style="font-size:13px;margin:12px 0 4px;">Продавець</h3>
      <p>${esc(legal.fullName)}${regLine}<br>
      Адреса реєстрації: ${esc(legal.legalAddress)}<br>
      ${returnLine}Контакти: ${esc(legal.email)}${phoneLine}</p>
      ${licenseBlock}

      <h3 id="oferta" style="font-size:13px;margin:12px 0 4px;">Публічна оферта</h3>
      <p>Розміщення товару на цій сторінці є публічною пропозицією (офертою) укласти договір купівлі-продажу дистанційно. Оформлення замовлення покупцем є прийняттям цієї пропозиції. Перед підтвердженням покупець може перевірити й виправити введені дані.</p>

      <h3 id="povernennya" style="font-size:13px;margin:12px 0 4px;">Повернення, обмін, рекламації</h3>
      <p>Товар належної якості можна повернути або обміняти протягом 14 днів з моменту отримання, попередньо узгодивши це з продавцем за контактами вище. Вартість зворотної доставки узгоджується окремо. У разі браку чи дефекту продавець забезпечує ремонт, заміну або повернення коштів відповідно до законодавства про захист прав споживачів.</p>

      <h3 id="oplata" style="font-size:13px;margin:12px 0 4px;">Оплата і доставка</h3>
      <p>Ціни на сторінці вказані в гривнях і включають усі податки та збори. Вартість доставки узгоджується з продавцем під час оформлення замовлення. Після оплати покупцю надається розрахунковий документ (фіскальний чек ПРРО/РРО або товарний чек).</p>

      <h3 id="konfidentsiinist" style="font-size:13px;margin:12px 0 4px;">Політика конфіденційності</h3>
      <p>Дані, надані під час оформлення замовлення (ім'я, контакти, адреса), використовуються лише для виконання замовлення й обробляються відповідно до Закону України «Про захист персональних даних». Сайт використовує технічні файли cookie для коректної роботи сторінки.</p>

      <h3 id="kontakty" style="font-size:13px;margin:12px 0 4px;">Контролюючий орган</h3>
      <p>У разі порушення прав споживача можна звернутися до територіального органу Держпродспоживслужби: <a href="https://dpss.gov.ua/" target="_blank" rel="noopener" style="color:inherit;">dpss.gov.ua</a></p>
    </details>`;
}

function renderStorefront(data) {
  const limit = data.tier === "Pro" ? 10 : 4;
  const products = (data.products || []).slice(0, limit);
  const cardsHtml = products.map((p) => `
        <li class="card"><div class="card-photo">${p.photo ? `<img src="/${esc(p.photo)}" alt="${esc(p.name)}" style="width:100%;height:100%;object-fit:cover;border-radius:inherit;">` : `<span>фото товару</span>`}</div><div class="card-body"><div class="card-name">${esc(p.name)}</div><div class="card-price">${esc(p.price)}</div></div></li>`).join("");
  const tierNote = data.tier === "Pro"
    ? "Показано до 10 товарів. Великий каталог (до 1000) — через Базар Толока."
    : `Показано ${products.length} товари. Більше — на тарифі Pro.`;
  const storeInitial = (data.storeName || "М").trim().charAt(0).toUpperCase();
  const avatarInner = data.avatar
    ? `<img src="/${esc(data.avatar)}" alt="" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`
    : esc(storeInitial);

  const legal = data.legal || {};
  const hasLegal = Boolean(legal.fullName && (legal.legalAddress || legal.returnAddress) && (legal.email || legal.phone));
  const kutochokHtml = hasLegal ? renderKutochok(legal) : "";
  const consentHtml = hasLegal ? `
      <label style="display:flex;gap:8px;align-items:flex-start;font-size:11px;color:var(--graphite);margin:0 0 10px;text-align:left;">
        <input type="checkbox" style="margin-top:2px;flex:none;">
        <span>Оформлюючи замовлення, я погоджуюся з умовами <a href="#oferta" style="color:inherit;">Публічної оферти</a> та <a href="#konfidentsiinist" style="color:inherit;">Політики конфіденційності</a>.</span>
      </label>` : "";
  const footerLegalLinks = hasLegal ? `
      <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:center;font-size:10px;margin-top:6px;">
        <a href="#oferta">Оферта</a><a href="#povernennya">Повернення</a><a href="#oplata">Оплата і доставка</a><a href="#konfidentsiinist">Конфіденційність</a><a href="#kontakty">Контакти</a>
      </div>` : "";

  return `<!doctype html>
<html lang="uk">
<head>
${HEAD}
<title>${esc(data.storeName)} — вітрина</title>
<style>:root{--accent:${esc(data.accent)};}</style>
</head>
<body>
<div class="page">
  <div class="vitryna">

    <svg class="doodle" style="top:14px;left:14px;" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#2A2D33" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M18.4 5.6l-2.8 2.8M8.4 15.6l-2.8 2.8"/></svg>
    <svg class="doodle" style="top:100px;right:10px;" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#2A2D33" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20s-7-4.4-9.3-8.8C1.3 8 2.7 5 5.8 4.7c1.8-.2 3.3.8 4.2 2.2.9-1.4 2.4-2.4 4.2-2.2 3.1.3 4.5 3.3 3.1 6.5C15 15.6 12 20 12 20Z"/></svg>

    <header class="header">
      <div class="shop-id">
        <div class="avatar">${avatarInner}</div>
        <div>
          <div class="shop-name">${esc(data.storeName)}</div>
          <span class="category-pill">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20.5 11.5 12.5 3.5H5a2 2 0 0 0-2 2v7.5l10 10a2 2 0 0 0 2.8 0l5.2-5.2a2 2 0 0 0 .5-2.3Z"/><circle cx="8" cy="8" r="1.1" fill="currentColor" stroke="none"/></svg>
            ${esc(data.category)}
          </span>
        </div>
      </div>
      <button type="button" class="cart-btn" aria-label="Кошик">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#2A2D33" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 4h2l2.2 11.6a2 2 0 0 0 2 1.6h7.2a2 2 0 0 0 2-1.6L20 8H6"/><circle cx="9.5" cy="20" r="1.2" fill="#2A2D33" stroke="none"/><circle cx="17" cy="20" r="1.2" fill="#2A2D33" stroke="none"/></svg>
      </button>
    </header>

    <section class="products">
      <ul class="grid">${cardsHtml}
      </ul>
      <p class="tier-note">${esc(tierNote)}</p>
    </section>

    ${consentHtml}
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

    ${kutochokHtml}

    <footer class="footer">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#857a65" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v4M12 17v4M3 12h4M17 12h4"/></svg>
      <a href="https://magistral-it.com">Розроблено Магістраль-ІТ</a>
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#857a65" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v4M12 17v4M3 12h4M17 12h4"/></svg>
      ${footerLegalLinks}
    </footer>

  </div>
</div>
</body>
</html>`;
}

function page(title, inner, maxWidth) {
  return `<!doctype html>
<html lang="uk">
<head>
${HEAD}
<title>${esc(title)}</title>
<meta name="robots" content="noindex">
</head>
<body>
<div class="page">
  <div class="vitryna" style="max-width:${maxWidth || 420}px;padding:30px 24px;margin:0 auto;">
${inner}
  </div>
</div>
</body>
</html>`;
}

function renderNotFoundStore() {
  return page("Вітрину не знайдено", `
    <div class="shop-name" style="font-size:22px;text-align:center;">Вітрину не знайдено</div>
    <p style="font-size:13px;color:var(--graphite);text-align:center;margin-top:10px;">Перевірте адресу або поверніться пізніше.</p>`);
}

function renderLoginPage(error) {
  return page("Вхід — вітрина", `
    <div class="shop-name" style="font-size:26px;text-align:center;margin-bottom:18px;">Вхід у вітрину</div>
    ${error ? `<p style="color:#b4432f;font-size:13px;text-align:center;margin:0 0 14px;">${esc(error)}</p>` : ""}
    <form method="POST" action="/admin/login" style="display:flex;flex-direction:column;gap:12px;">
      <label style="${LABEL}">
        ID Голосника
        <input type="text" name="holosnyk_id" placeholder="ГЛС-0000-ХХХ" required style="${FIELD}">
      </label>
      <label style="${LABEL}">
        Пароль
        <input type="password" name="password" required style="${FIELD}">
      </label>
      <button type="submit" class="btn-pay">Увійти</button>
    </form>
    <p style="font-size:12px;text-align:center;margin-top:16px;">
      <a href="/activate" style="color:var(--graphite);">Перший вхід або забули пароль?</a>
    </p>`);
}

function renderActivatePage(message, error, prefillId) {
  return page("Активація — вітрина", `
    <div class="shop-name" style="font-size:24px;text-align:center;margin-bottom:8px;">Активація вітрини</div>
    <p style="font-size:12px;color:var(--graphite);text-align:center;margin:0 0 16px;">Введіть свій ID Голосника, код активації та придумайте пароль.</p>
    ${error ? `<p style="color:#b4432f;font-size:13px;text-align:center;margin:0 0 14px;">${esc(error)}</p>` : ""}
    ${message ? `<p style="color:#2f7a4d;font-size:13px;text-align:center;margin:0 0 14px;">${esc(message)}</p>` : ""}
    <form method="POST" action="/activate" style="display:flex;flex-direction:column;gap:12px;">
      <label style="${LABEL}">
        ID Голосника
        <input type="text" name="holosnyk_id" value="${esc(prefillId || "")}" placeholder="ГЛС-0000-ХХХ" required style="${FIELD}">
      </label>
      <label style="${LABEL}">
        Код активації
        <input type="text" name="code" placeholder="XXXX-XXXX" required style="${FIELD}">
      </label>
      <label style="${LABEL}">
        Новий пароль (від ${MIN_PASSWORD} символів)
        <input type="password" name="password" required style="${FIELD}">
      </label>
      <label style="${LABEL}">
        Повторіть пароль
        <input type="password" name="password2" required style="${FIELD}">
      </label>
      <button type="submit" class="btn-pay">Активувати</button>
    </form>
    <p style="font-size:12px;text-align:center;margin-top:16px;">
      <a href="/admin" style="color:var(--graphite);">← До входу</a>
    </p>`);
}

function productRow(i, product) {
  const p = product || { name: "", price: "", photo: "" };
  const preview = p.photo
    ? `<img src="/${esc(p.photo)}" alt="" style="width:48px;height:48px;object-fit:cover;border-radius:8px;border:2px solid var(--ink);flex:none;">`
    : `<div style="width:48px;height:48px;border-radius:8px;border:2px dashed var(--ink);flex:none;"></div>`;
  const removeOption = p.photo
    ? `<label style="font-size:11px;color:var(--graphite);display:flex;align-items:center;gap:4px;margin-top:2px;">
        <input type="checkbox" name="remove_photo_${i}"> прибрати фото
      </label>`
    : "";
  return `
    <div style="display:flex;gap:10px;align-items:flex-start;padding:10px;border:2px solid var(--ink);border-radius:14px;">
      ${preview}
      <div style="flex:1;display:flex;flex-direction:column;gap:6px;min-width:0;">
        <input type="text" name="name_${i}" value="${esc(p.name)}" placeholder="Назва товару" style="${FIELD}margin-top:0;">
        <input type="text" name="price_${i}" value="${esc(p.price)}" placeholder="Ціна, напр. 320 ₴" style="${FIELD}margin-top:0;">
        <input type="file" name="photo_${i}" accept="image/*" style="font-size:12px;">
        <input type="hidden" name="existing_photo_${i}" value="${esc(p.photo)}">
        ${removeOption}
      </div>
    </div>`;
}

function avatarField(data) {
  const preview = data.avatar
    ? `<img src="/${esc(data.avatar)}" alt="" style="width:56px;height:56px;object-fit:cover;border-radius:50%;border:2px solid var(--ink);flex:none;">`
    : `<div style="width:56px;height:56px;border-radius:50%;border:2px dashed var(--ink);flex:none;"></div>`;
  const removeOption = data.avatar
    ? `<label style="font-size:11px;color:var(--graphite);display:flex;align-items:center;gap:4px;margin-top:4px;">
        <input type="checkbox" name="remove_avatar"> прибрати аватарку
      </label>`
    : "";
  return `
    <div style="display:flex;gap:12px;align-items:flex-start;">
      ${preview}
      <div style="flex:1;">
        <input type="file" name="avatar" accept="image/*" style="font-size:12px;">
        <input type="hidden" name="existing_avatar" value="${esc(data.avatar)}">
        ${removeOption}
      </div>
    </div>`;
}

function renderAdminForm(data, sellerId, saved, error, slugWarning) {
  const limit = data.tier === "Pro" ? 10 : 4;
  const rows = [];
  for (let i = 0; i < limit; i++) rows.push(productRow(i, (data.products || [])[i]));

  const linksBlock = data.slug ? `
    <div style="margin:10px 0 0;padding:10px 12px;border:2px dashed var(--ink);border-radius:12px;font-size:12px;">
      <p style="margin:0 0 4px;color:var(--graphite);">Ваша вітрина:</p>
      <a href="https://${esc(data.slug)}.tiktok.bazar.in.ua/" target="_blank" style="display:block;word-break:break-all;">${esc(data.slug)}.tiktok.bazar.in.ua</a>
      <a href="https://${esc(data.slug)}.insta.bazar.in.ua/" target="_blank" style="display:block;word-break:break-all;">${esc(data.slug)}.insta.bazar.in.ua</a>
    </div>` : "";

  const legal = data.legal || {};

  return page("Адмінка — вітрина", `
    <div class="shop-name" style="font-size:24px;">Редагування вітрини</div>
    <p style="font-size:11px;color:var(--graphite);margin:4px 0 0;">${esc(sellerId)}</p>
    ${saved ? `<p style="color:#2f7a4d;font-size:13px;margin:10px 0 0;">Збережено.</p>` : ""}
    ${slugWarning ? `<p style="color:#b4432f;font-size:12px;margin:6px 0 0;">Цей слаг зайнятий або некоректний (3-40 символів, латиниця/цифри/дефіс) — лишили попередній.</p>` : ""}
    ${error ? `<p style="color:#b4432f;font-size:13px;margin:10px 0 0;">${esc(error)}</p>` : ""}
    ${linksBlock}
    <form method="POST" action="/admin/save" enctype="multipart/form-data" style="display:flex;flex-direction:column;gap:14px;margin-top:16px;">

      <div>
        <p style="${LABEL}margin-bottom:8px;">Аватарка</p>
        ${avatarField(data)}
      </div>

      <label style="${LABEL}">
        Назва магазину
        <input type="text" name="store_name" value="${esc(data.storeName)}" required style="${FIELD}">
      </label>
      <label style="${LABEL}">
        Категорія
        <input type="text" name="category" value="${esc(data.category)}" required style="${FIELD}">
      </label>
      <label style="${LABEL}">
        Адреса вітрини (слаг)
        <input type="text" name="slug" value="${esc(data.slug)}" placeholder="moy-magazyn" style="${FIELD}">
      </label>
      <div style="${LABEL}">
        Тариф: <strong>${data.tier === "Pro" ? "Pro (до 10 товарів)" : "Free (4 товари)"}</strong>
        ${data.tier === "Pro"
          ? `<p style="font-size:11px;color:#2f7a4d;margin:4px 0 0;">🔒 Pro активний.</p>`
          : `<p style="font-size:11px;color:var(--graphite);margin:4px 0 0;">🔒 Pro — до 10 товарів і власний домен. Напишіть нам, щоб підключити.</p>`}
      </div>
      <label style="${LABEL}">
        Акцентний колір
        <input type="color" name="accent" value="${esc(data.accent)}" style="display:block;margin-top:4px;width:60px;height:36px;border:2px solid var(--ink);border-radius:8px;padding:2px;">
      </label>

      <div>
        <p style="${LABEL}margin-bottom:8px;">Товари (назва, ціна, фото — до 4 МБ)</p>
        <div style="display:flex;flex-direction:column;gap:10px;">
          ${rows.join("")}
        </div>
      </div>

      <div style="border-top:2px dashed var(--ink);padding-top:14px;">
        <p style="${LABEL}margin-bottom:2px;">Куточок покупця (необов'язково)</p>
        <p style="font-size:11px;color:var(--graphite);margin:0 0 10px;">Заповніть, щоб на вітрині з'явився блок із юридичною інформацією (вимога закону про дистанційну торгівлю). Можна лишити порожнім і заповнити пізніше.</p>
        <div style="display:flex;flex-direction:column;gap:10px;">
          <label style="${LABEL}">
            ПІБ ФОП або назва компанії
            <input type="text" name="legal_name" value="${esc(legal.fullName)}" style="${FIELD}">
          </label>
          <label style="${LABEL}">
            Реєстраційний номер (ЄДРПОУ/РНОКПП), за наявності
            <input type="text" name="legal_regnum" value="${esc(legal.regNumber)}" style="${FIELD}">
          </label>
          <label style="${LABEL}">
            Адреса реєстрації
            <input type="text" name="legal_address" value="${esc(legal.legalAddress)}" style="${FIELD}">
          </label>
          <label style="${LABEL}">
            Адреса для повернень (якщо відрізняється)
            <input type="text" name="legal_return_address" value="${esc(legal.returnAddress)}" style="${FIELD}">
          </label>
          <label style="${LABEL}">
            Email
            <input type="email" name="legal_email" value="${esc(legal.email)}" style="${FIELD}">
          </label>
          <label style="${LABEL}">
            Телефон
            <input type="text" name="legal_phone" value="${esc(legal.phone)}" style="${FIELD}">
          </label>
          <label style="${LABEL}">
            Ліцензія (якщо товар підлягає ліцензуванню)
            <input type="text" name="legal_license" value="${esc(legal.licenseInfo)}" style="${FIELD}">
          </label>
        </div>
      </div>

      <button type="submit" class="btn-pay">Зберегти</button>
    </form>
    <div style="display:flex;justify-content:flex-end;margin-top:18px;font-size:12px;">
      <a href="/admin/logout" style="color:var(--graphite);">Вийти</a>
    </div>`);
}

function renderOwnerLogin(error) {
  return page("Панель власника", `
    <div class="shop-name" style="font-size:24px;text-align:center;margin-bottom:18px;">Панель власника</div>
    ${error ? `<p style="color:#b4432f;font-size:13px;text-align:center;margin:0 0 14px;">${esc(error)}</p>` : ""}
    <form method="POST" action="/owner/login" style="display:flex;flex-direction:column;gap:12px;">
      <label style="${LABEL}">
        Токен власника
        <input type="password" name="token" required style="${FIELD}">
      </label>
      <button type="submit" class="btn-pay">Увійти</button>
    </form>`);
}

function renderOwnerPanel(sellers, issued, error, tierMsg) {
  const rows = sellers.length
    ? sellers.map((s) => `
      <tr>
        <td style="padding:6px 8px;border-bottom:1px solid #E0E3E7;font-size:13px;">${esc(s.id)}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #E0E3E7;font-size:12px;color:var(--graphite);">${s.active ? "активний" : "очікує активації"}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #E0E3E7;font-size:12px;color:var(--graphite);">${s.active ? (s.tier === "Pro" ? "🔒 Pro" : "Free") : "—"}</td>
      </tr>`).join("")
    : `<tr><td colspan="3" style="padding:8px;font-size:12px;color:var(--graphite);">Поки нікого немає.</td></tr>`;

  const issuedBlock = issued ? `
    <div style="margin:16px 0;padding:14px;border:2px dashed var(--ink);border-radius:14px;text-align:center;">
      <p style="font-size:12px;color:var(--graphite);margin:0 0 6px;">Код для ${esc(issued.id)} — діє 24 години:</p>
      <p style="font-family:'IBM Plex Mono',monospace;font-size:24px;letter-spacing:2px;margin:0;">${esc(issued.code)}</p>
      <p style="font-size:11px;color:var(--graphite);margin:8px 0 0;">Передайте продавцю разом із посиланням на /activate. Більше він не показується.</p>
    </div>` : "";

  const tierMsgBlock = tierMsg ? `<p style="color:#2f7a4d;font-size:13px;margin:10px 0 0;">${esc(tierMsg)}</p>` : "";

  return page("Панель власника", `
    <div class="shop-name" style="font-size:24px;">Панель власника</div>
    ${error ? `<p style="color:#b4432f;font-size:13px;margin:10px 0 0;">${esc(error)}</p>` : ""}
    ${tierMsgBlock}
    ${issuedBlock}
    <form method="POST" action="/owner/issue" style="display:flex;flex-direction:column;gap:12px;margin-top:16px;">
      <label style="${LABEL}">
        ID Голосника продавця
        <input type="text" name="holosnyk_id" placeholder="ГЛС-0000-ХХХ" required style="${FIELD}">
      </label>
      <button type="submit" class="btn-pay">Видати код активації</button>
    </form>
    <p style="font-size:11px;color:var(--graphite);margin-top:10px;">Для нового продавця — заводить акаунт. Для наявного — скидає пароль.</p>

    <form method="POST" action="/owner/set-tier" style="display:flex;flex-direction:column;gap:12px;margin-top:20px;border-top:2px dashed var(--ink);padding-top:16px;">
      <label style="${LABEL}">
        ID Голосника продавця
        <input type="text" name="holosnyk_id" placeholder="ГЛС-0000-ХХХ" required style="${FIELD}">
      </label>
      <label style="${LABEL}">
        Тариф
        <select name="tier" style="${FIELD}">
          <option value="Free">Free</option>
          <option value="Pro">Pro</option>
        </select>
      </label>
      <button type="submit" class="btn-pay">Встановити тариф</button>
    </form>

    <table style="width:100%;border-collapse:collapse;margin-top:20px;">
      <thead><tr>
        <th style="text-align:left;padding:6px 8px;font-size:11px;color:var(--graphite);border-bottom:2px solid var(--ink);">Продавець</th>
        <th style="text-align:left;padding:6px 8px;font-size:11px;color:var(--graphite);border-bottom:2px solid var(--ink);">Статус</th>
        <th style="text-align:left;padding:6px 8px;font-size:11px;color:var(--graphite);border-bottom:2px solid var(--ink);">Тариф</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <div style="display:flex;justify-content:space-between;margin-top:18px;font-size:12px;">
      <a href="/" style="color:var(--graphite);">← На вітрину</a>
      <a href="/owner/logout" style="color:var(--graphite);">Вийти</a>
    </div>`, 520);
}

async function listSellers(env) {
  const map = new Map();
  const sellers = await env.ZROZOK_STORE.list({ prefix: "seller:" });
  for (const k of sellers.keys) map.set(k.name.slice(7), { id: k.name.slice(7), active: true });
  const pending = await env.ZROZOK_STORE.list({ prefix: "activation:" });
  for (const k of pending.keys) {
    const id = k.name.slice(11);
    if (!map.has(id)) map.set(id, { id, active: false });
  }
  const list = [...map.values()].sort((a, b) => a.id.localeCompare(b.id));
  for (const s of list) {
    if (s.active) {
      const data = await loadData(env, s.id);
      s.tier = data.tier === "Pro" ? "Pro" : "Free";
    }
  }
  return list;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const ip = getClientIp(request);
    const host = (request.headers.get("Host") || "").toLowerCase();

    if (path.startsWith("/photos/")) {
      const key = decodeURIComponent(path).slice(1);
      const obj = await env.ZROZOK_PHOTOS.get(key);
      if (!obj) return env.ASSETS.fetch(request);
      const headers = new Headers();
      obj.writeHttpMetadata(headers);
      headers.set("Cache-Control", "public, max-age=31536000, immutable");
      headers.set("ETag", obj.httpEtag);
      return new Response(obj.body, { headers });
    }

    let publicSlug = null;
    for (const suffix of PUBLIC_HOST_SUFFIXES) {
      if (host.endsWith(suffix)) {
        publicSlug = host.slice(0, host.length - suffix.length);
        break;
      }
    }

    if (publicSlug !== null) {
      if (path === "/") {
        const sellerId = publicSlug ? await env.ZROZOK_STORE.get(`slug:${publicSlug}`) : null;
        if (!sellerId) return html(renderNotFoundStore(), 404);
        const data = await loadData(env, sellerId);
        return html(renderStorefront(data));
      }
      return env.ASSETS.fetch(request);
    }

    if (path === "/admin/login" && method === "POST") {
      const form = await request.formData();
      const id = normalizeId(form.get("holosnyk_id"));
      const pass = (form.get("password") || "").toString();
      const idKey = `login_fail:id:${id || "empty"}`;
      const ipKey = `login_fail:ip:${ip}`;

      const [idFails, ipFails] = await Promise.all([
        getFailCount(env, idKey), getFailCount(env, ipKey)
      ]);
      if (idFails >= LOGIN_LIMIT || ipFails >= LOGIN_LIMIT) {
        return html(renderLoginPage("Забагато спроб. Спробуйте через 15 хвилин."), 429);
      }

      const seller = id ? await getSeller(env, id) : null;
      const ok = seller && pass && (await verifyPassword(pass, seller.hash));

      if (ok) {
        await Promise.all([clearFailCount(env, idKey), clearFailCount(env, ipKey)]);
        const token = await makeSession(env, { r: "seller", id });
        return redirect("/admin", sessionCookie(token));
      }

      await Promise.all([bumpFailCount(env, idKey), bumpFailCount(env, ipKey)]);
      return html(renderLoginPage("Невірний ID або пароль."), 401);
    }

    if (path === "/admin/logout") {
      return redirect("/admin", CLEAR_COOKIE);
    }

    if (path === "/activate" && method === "GET") {
      return html(renderActivatePage(null, null, url.searchParams.get("id")));
    }

    if (path === "/activate" && method === "POST") {
      const form = await request.formData();
      const id = normalizeId(form.get("holosnyk_id"));
      const code = String(form.get("code") || "").trim().toUpperCase();
      const pass = (form.get("password") || "").toString();
      const pass2 = (form.get("password2") || "").toString();
      const failKey = `act_fail:ip:${ip}`;

      if ((await getFailCount(env, failKey)) >= LOGIN_LIMIT) {
        return html(renderActivatePage(null, "Забагато спроб. Спробуйте через 15 хвилин.", id), 429);
      }
      if (pass.length < MIN_PASSWORD) {
        return html(renderActivatePage(null, `Пароль має бути від ${MIN_PASSWORD} символів.`, id), 400);
      }
      if (pass !== pass2) {
        return html(renderActivatePage(null, "Паролі не збігаються.", id), 400);
      }

      const storedCodeHash = id ? await env.ZROZOK_STORE.get(`activation:${id}`) : null;
      const codeOk = storedCodeHash && timingSafeEqual(await sha256hex(code), storedCodeHash);

      if (!codeOk) {
        await bumpFailCount(env, failKey);
        return html(renderActivatePage(null, "Невірний ID або код активації.", id), 401);
      }

      const existing = await getSeller(env, id);
      await env.ZROZOK_STORE.put(`seller:${id}`, JSON.stringify({
        hash: await hashPassword(pass),
        created: existing?.created || new Date().toISOString(),
        updated: new Date().toISOString()
      }));
      await env.ZROZOK_STORE.delete(`activation:${id}`);
      await clearFailCount(env, failKey);
      await clearFailCount(env, `login_fail:id:${id}`);

      const token = await makeSession(env, { r: "seller", id });
      return redirect("/admin", sessionCookie(token));
    }

    if (path === "/owner/login" && method === "POST") {
      const form = await request.formData();
      const token = (form.get("token") || "").toString();
      const failKey = `owner_fail:ip:${ip}`;

      if ((await getFailCount(env, failKey)) >= LOGIN_LIMIT) {
        return html(renderOwnerLogin("Забагато спроб. Спробуйте через 15 хвилин."), 429);
      }

      const expected = await env.OWNER_TOKEN.get();
      if (token && timingSafeEqual(token, expected)) {
        await clearFailCount(env, failKey);
        return redirect("/owner", sessionCookie(await makeSession(env, { r: "owner" })));
      }

      await bumpFailCount(env, failKey);
      return html(renderOwnerLogin("Невірний токен."), 401);
    }

    if (path === "/owner/logout") {
      return redirect("/owner", CLEAR_COOKIE);
    }

    if (path === "/owner/issue" && method === "POST") {
      const session = await readSession(request, env);
      if (!session || session.r !== "owner") return redirect("/owner");

      const form = await request.formData();
      const id = normalizeId(form.get("holosnyk_id"));
      if (!id) {
        return html(renderOwnerPanel(await listSellers(env), null, "Вкажіть ID Голосника."), 400);
      }
      const code = makeCode();
      await env.ZROZOK_STORE.put(`activation:${id}`, await sha256hex(code), { expirationTtl: CODE_TTL });
      return html(renderOwnerPanel(await listSellers(env), { id, code }, null));
    }

    if (path === "/owner/set-tier" && method === "POST") {
      const session = await readSession(request, env);
      if (!session || session.r !== "owner") return redirect("/owner");

      const form = await request.formData();
      const id = normalizeId(form.get("holosnyk_id"));
      const tier = form.get("tier") === "Pro" ? "Pro" : "Free";
      if (!id) {
        return html(renderOwnerPanel(await listSellers(env), null, "Вкажіть ID Голосника."));
      }
      const seller = await getSeller(env, id);
      if (!seller) {
        return html(renderOwnerPanel(await listSellers(env), null, `Продавця ${id} не знайдено серед активних.`));
      }
      const data = await loadData(env, id);
      await saveData(env, id, { ...data, tier });
      return html(renderOwnerPanel(await listSellers(env), null, null, `Тариф для ${id} встановлено: ${tier}.`));
    }

    if (path === "/owner") {
      const session = await readSession(request, env);
      if (!session || session.r !== "owner") return html(renderOwnerLogin(null));
      return html(renderOwnerPanel(await listSellers(env), null, null));
    }

    if (path === "/admin/save" && method === "POST") {
      const session = await readSession(request, env);
      if (!session || session.r !== "seller") return redirect("/admin");

      const form = await request.formData();
      const existing = await loadData(env, session.id);
      const tier = existing.tier === "Pro" ? "Pro" : "Free";
      const limit = tier === "Pro" ? 10 : 4;

      const products = [];
      for (let i = 0; i < limit; i++) {
        const name = (form.get(`name_${i}`) || "").toString().trim();
        if (!name) continue;
        const price = (form.get(`price_${i}`) || "").toString().trim();
        const existingPhoto = (form.get(`existing_photo_${i}`) || "").toString();
        const removePhoto = Boolean(form.get(`remove_photo_${i}`));
        const file = form.get(`photo_${i}`);
        let photo = existingPhoto;

        if (file && typeof file === "object" && typeof file.arrayBuffer === "function" && file.size > 0) {
          if (file.size <= MAX_PHOTO_BYTES && file.type && file.type.startsWith("image/")) {
            const key = `photos/${session.id}/${i}`;
            await env.ZROZOK_PHOTOS.put(key, await file.arrayBuffer(), {
              httpMetadata: { contentType: file.type }
            });
            photo = key;
          }
        } else if (removePhoto && existingPhoto) {
          await env.ZROZOK_PHOTOS.delete(existingPhoto).catch(() => {});
          photo = "";
        }

        products.push({ name, price, photo });
      }
      if (existing.products && existing.products.length > limit) {
        products.push(...existing.products.slice(limit));
      }

      let avatar = (form.get("existing_avatar") || "").toString();
      const removeAvatar = Boolean(form.get("remove_avatar"));
      const avatarFile = form.get("avatar");
      if (avatarFile && typeof avatarFile === "object" && typeof avatarFile.arrayBuffer === "function" && avatarFile.size > 0) {
        if (avatarFile.size <= MAX_PHOTO_BYTES && avatarFile.type && avatarFile.type.startsWith("image/")) {
          const key = `photos/${session.id}/avatar`;
          await env.ZROZOK_PHOTOS.put(key, await avatarFile.arrayBuffer(), {
            httpMetadata: { contentType: avatarFile.type }
          });
          avatar = key;
        }
      } else if (removeAvatar && avatar) {
        await env.ZROZOK_PHOTOS.delete(avatar).catch(() => {});
        avatar = "";
      }

      const storeName = (form.get("store_name") || "").toString().trim() || DEFAULT_DATA.storeName;

      let finalSlug = existing.slug || "";
      let slugWarning = false;
      const requestedRaw = (form.get("slug") || "").toString().trim();
      let desiredSlug = slugify(requestedRaw);
      if (!desiredSlug) desiredSlug = finalSlug || slugify(storeName) || slugify(session.id);
      if (!isValidSlug(desiredSlug)) {
        if (requestedRaw) slugWarning = true;
        desiredSlug = finalSlug || slugify(storeName) || slugify(session.id);
        if (!isValidSlug(desiredSlug)) desiredSlug = `shop-${slugify(session.id)}`.slice(0, 40);
      }
      if (desiredSlug !== finalSlug) {
        const owner = await env.ZROZOK_STORE.get(`slug:${desiredSlug}`);
        if (owner && owner !== session.id) {
          slugWarning = true;
        } else {
          if (finalSlug) await env.ZROZOK_STORE.delete(`slug:${finalSlug}`);
          await env.ZROZOK_STORE.put(`slug:${desiredSlug}`, session.id);
          finalSlug = desiredSlug;
        }
      }
      if (!finalSlug) {
        const fallback = (`shop-${slugify(session.id)}` || `shop-${Date.now().toString(36)}`).slice(0, 40);
        await env.ZROZOK_STORE.put(`slug:${fallback}`, session.id);
        finalSlug = fallback;
      }

      const legal = {
        fullName: (form.get("legal_name") || "").toString().trim(),
        regNumber: (form.get("legal_regnum") || "").toString().trim(),
        legalAddress: (form.get("legal_address") || "").toString().trim(),
        returnAddress: (form.get("legal_return_address") || "").toString().trim(),
        email: (form.get("legal_email") || "").toString().trim(),
        phone: (form.get("legal_phone") || "").toString().trim(),
        licenseInfo: (form.get("legal_license") || "").toString().trim()
      };

      await saveData(env, session.id, {
        storeName,
        category: (form.get("category") || "").toString().trim() || DEFAULT_DATA.category,
        tier,
        accent: (form.get("accent") || "").toString().trim() || DEFAULT_DATA.accent,
        products,
        avatar,
        slug: finalSlug,
        legal
      });

      return redirect(`/admin?saved=1${slugWarning ? "&slugwarn=1" : ""}`);
    }

    if (path === "/admin") {
      const session = await readSession(request, env);
      if (!session || session.r !== "seller") return html(renderLoginPage(null));
      const data = await loadData(env, session.id);
      return html(renderAdminForm(
        data, session.id,
        url.searchParams.get("saved") === "1",
        null,
        url.searchParams.get("slugwarn") === "1"
      ));
    }

    if (path === "/") {
      return redirect("/admin");
    }

    return env.ASSETS.fetch(request);
  }
};
