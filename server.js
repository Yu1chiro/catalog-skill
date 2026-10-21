require("dotenv").config();
const express = require("express");
const app = express();

// ==========================================
// 1. SISTEM ANTI-CRASH VERCEL (TRY-CATCH GLOBAL)
// Jika ada typo atau error, Vercel tidak akan crash, melainkan menampilkan JSON error.
// ==========================================
try {
  process.env.TZ = "Asia/Makassar";
  const path = require("path");
  const crypto = require("crypto");
  const cookieParser = require("cookie-parser");
  const jwt = require("jsonwebtoken");
  const sanitizeHtml = require("sanitize-html");
  const rateLimit = require("express-rate-limit");
  const { neon } = require("@neondatabase/serverless");

  // Pengecekan Environment Variables
  const { DATABASE_URL, JWT_SECRET, IMAGEKIT_PRIVATE_KEY, IMAGEKIT_URL_ENDPOINT, ADMIN_WA, SETUP_KEY } = process.env;
  const IS_PROD = process.env.NODE_ENV === "production" || !!process.env.VERCEL;

  if (!DATABASE_URL || !JWT_SECRET || !IMAGEKIT_PRIVATE_KEY || !IMAGEKIT_URL_ENDPOINT) {
    throw new Error("Environment Variable wajib ada yang belum terisi.");
  }
  if (JWT_SECRET.length < 32) throw new Error("JWT_SECRET minimal 32 karakter.");

  const IK = new URL(IMAGEKIT_URL_ENDPOINT); // Akan memicu error di sini jika URL tidak valid
  if (IK.protocol !== "https:") throw new Error("IMAGEKIT_URL_ENDPOINT harus menggunakan HTTPS");

  const sql = neon(DATABASE_URL);
  const q = (t, p = []) => sql.query(t, p);

  // ==========================================
  // 2. KEAMANAN & UTILITIES
  // ==========================================
  const subKey = (info) => Buffer.from(crypto.hkdfSync("sha256", JWT_SECRET, "katalog-v1", info, 32));
  const K_AUTH = subKey("admin-jwt"), K_SUCCESS = subKey("success-jwt"), K_SUM = subKey("order-checksum");
  const ISS = "katalog";

  const bad = (m, status = 400) => { throw Object.assign(new Error(m), { status, expose: true }); };
  const finalPrice = (p, d) => Math.round((Number(p) * (100 - d)) / 100);
  const slugify = (s) => s.toLowerCase().normalize("NFKD").replace(/[^\w\s-]/g, "").trim().replace(/[\s_]+/g, "-").replace(/-+/g, "-");

  async function uniqueSlug(name, ignoreId = 0) {
    let s = slugify(name) || "produk", i = 1;
    while ((await q("SELECT 1 FROM products WHERE slug=$1 AND id<>$2", [s, ignoreId])).length) s = `${slugify(name)}-${++i}`;
    return s;
  }

  const hmac = (key, ...a) => crypto.createHmac("sha256", key).update(a.join("|")).digest("hex");
  const sig = (...a) => hmac(K_SUM, ...a);
  const safeEq = (a, b) => {
    a = Buffer.from(String(a ?? "")); b = Buffer.from(String(b ?? ""));
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  };
  const checksumOk = (o) => safeEq(o.checksum, sig(o.id, o.product_id, o.price_paid));

  const COLOR = /^(#[0-9a-f]{3,8}|rgba?\(\s*\d{1,3}\s*(,\s*[\d.]+\s*){2,3}\))$/i;
  const cleanHtml = (h) => sanitizeHtml(h || "", {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(["h1", "h2", "u", "s", "span"]),
    allowedAttributes: { "*": ["class", "style"], a: ["href", "target", "rel"] },
    allowedClasses: { "*": ["ql-*"] },
    allowedStyles: { "*": { color: [COLOR], "background-color": [COLOR] } },
    transformTags: { a: sanitizeHtml.simpleTransform("a", { rel: "noopener noreferrer", target: "_blank" }) },
  });

  const waNum = (n) => { n = String(n).replace(/\D/g, ""); return n.startsWith("0") ? "62" + n.slice(1) : n; };
  const rp = (n) => "Rp" + Number(n).toLocaleString("id-ID");
  const isUrl = (u) => { try { const s = String(u); return s.length <= 2000 && !/\s/.test(s) && ["http:", "https:"].includes(new URL(s).protocol); } catch { return false; } };

  const UPLOAD_FOLDER = "skills-catalog";
  const IK_PREFIX = IK.pathname.replace(/\/+$/, "") + "/" + UPLOAD_FOLDER + "/";
  const isProofUrl = (u) => { try { const x = new URL(u); return x.origin === IK.origin && x.pathname.startsWith(IK_PREFIX); } catch { return false; } };

  const withPrice = (p) => ({ ...p, price: Number(p.price), final_price: finalPrice(p.price, p.discount_percent) });
  const pg = (req, def = 10) => {
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || def)), page = Math.max(1, parseInt(req.query.page, 10) || 1);
    return { limit, page, offset: (page - 1) * limit };
  };
  const pages = (n, limit) => Math.max(1, Math.ceil(n / limit));

  const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k))));
  const hashPw = async (pw) => { const s = crypto.randomBytes(16).toString("hex"); return s + ":" + (await scrypt(pw, s)).toString("hex"); };
  const checkPw = async (pw, st = "") => {
    const [s, h] = String(st).split(":");
    if (!s || !/^[0-9a-f]{128}$/i.test(h || "")) return false;
    return crypto.timingSafeEqual(await scrypt(pw, s), Buffer.from(h, "hex"));
  };
  const DUMMY_HASH = "0".repeat(32) + ":" + "0".repeat(128);
  const audit = (ev, req, extra = {}) => console.log(JSON.stringify({ ts: new Date().toISOString(), audit: ev, ip: req.ip, ...extra }));

  function parseProduct(b) {
    const name = String(b.name || "").trim();
    if (name.length < 2 || name.length > 120) bad("Nama produk 2-120 karakter");
    const categories = [...new Set((Array.isArray(b.categories) ? b.categories : []).map((c) => String(c).trim()).filter(Boolean))].slice(0, 10);
    if (!["terbaru", "terlama"].includes(b.status)) bad("Status tidak valid");
    if (!isUrl(b.thumbnail_url || "")) bad("Thumbnail wajib");
    const gallery = (Array.isArray(b.gallery) ? b.gallery : []).map(String).filter(Boolean);
    if (gallery.some((g) => !isUrl(g))) bad("Link gallery tidak valid");
    const price = parseInt(b.price, 10), discount = parseInt(b.discount_percent || 0, 10), manual_buyers = Math.max(0, parseInt(b.manual_buyers || 0, 10));
    if (!(price > 0 && price <= 1e12)) bad("Harga tidak valid");
    if (!(discount >= 0 && discount <= 100)) bad("Diskon 0-100");
    const link = String(b.product_link || "").trim();
    if (link && !isUrl(link)) bad("Link produk tidak valid");
    return { name, categories, status: b.status, thumbnail_url: b.thumbnail_url, gallery, price, discount, manual_buyers, description: cleanHtml(b.description), link, active: b.is_active !== false };
  }

  // ==========================================
  // 3. MIDDLEWARE & RATE LIMITER
  // ==========================================
  app.disable("x-powered-by");
  app.set("trust proxy", IS_PROD ? 1 : false);
  app.use((req, res, next) => {
    res.set({
      "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cross-Origin-Opener-Policy": "same-origin",
      "Content-Security-Policy": "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'"
    });
    if (IS_PROD) res.set("Strict-Transport-Security", "max-age=31536000");
    next();
  });

  const jsonSmall = express.json({ limit: "200kb" });
  app.use((req, res, next) => req.path === "/api/upload" ? next() : jsonSmall(req, res, next));
  app.use(cookieParser());
  app.use((req, res, next) => { req.body ??= {}; next(); });

  const mk = (windowMs, limit, extra = {}) => rateLimit({ windowMs, limit, standardHeaders: "draft-7", legacyHeaders: false, message: { error: "Terlalu banyak permintaan" }, ...extra });
  const loginLimit = mk(15 * 60e3, 10), checkoutLimit = mk(10 * 60e3, 10), readLimit = mk(60e3, 120);

  const COOKIE = IS_PROD ? "__Host-token" : "token";
  const COOKIE_OPTS = { httpOnly: true, sameSite: "strict", secure: IS_PROD, path: "/" };
  const pv = (hash) => hmac(K_AUTH, "pv", hash).slice(0, 32);

  const readAdminToken = (req) => { try { return jwt.verify(req.cookies[COOKIE], K_AUTH, { algorithms: ["HS256"], issuer: ISS, audience: "admin" }); } catch { return null; } };
  const adminAuth = async (req, res, next) => {
    const fail = () => { res.clearCookie(COOKIE, COOKIE_OPTS); return req.originalUrl.startsWith("/api") ? res.status(401).json({ error: "Unauthorized" }) : res.redirect("/signin"); };
    const t = readAdminToken(req);
    if (!t) return fail();
    const [a] = await q("SELECT id,username,password_hash FROM admins WHERE id=$1", [Number(t.aid) || 0]);
    if (!a || !safeEq(pv(a.password_hash), t.pv)) return fail();
    req.admin = { id: a.id, u: a.username };
    next();
  };

  // ==========================================
  // 4. ROUTING PUBLIC & AUTH
  // ==========================================
  app.post("/api/auth/login", loginLimit, async (req, res) => {
    const username = String(req.body.username || "").trim().toLowerCase().slice(0, 64), password = String(req.body.password || "");
    if (!username || !password) bad("Username atau password salah", 401);
    const [a] = await q("SELECT id,username,password_hash FROM admins WHERE username=$1", [username]);
    if (!a || !(await checkPw(password, a ? a.password_hash : DUMMY_HASH))) { audit("login_fail", req, { u: username }); bad("Username atau password salah", 401); }
    const token = jwt.sign({ aid: a.id, u: a.username, pv: pv(a.password_hash) }, K_AUTH, { algorithm: "HS256", expiresIn: "8h", issuer: ISS, audience: "admin", subject: String(a.id) });
    res.cookie(COOKIE, token, { ...COOKIE_OPTS, maxAge: 8 * 3600e3 }).json({ ok: true });
  });

  app.post("/api/auth/logout", (req, res) => res.clearCookie(COOKIE, COOKIE_OPTS).json({ ok: true }));

  app.use(["/api/categories", "/api/products", "/api/payment-methods", "/api/testimonials"], readLimit);
  
  app.get("/api/products", async (req, res) => {
    const { limit, offset } = pg(req, 6);
    const rows = await q(`SELECT p.id,p.name,p.slug,p.categories,p.status,p.thumbnail_url,p.price,p.discount_percent, LEFT(regexp_replace(p.description,'<[^>]+>','','g'),120) AS short_description, ((SELECT COUNT(*) FROM orders o WHERE o.product_id=p.id AND o.status='accepted') + p.manual_buyers)::int AS buyers FROM products p WHERE p.is_active ORDER BY buyers DESC, p.created_at DESC, p.id DESC LIMIT ${limit + 1} OFFSET ${offset}`);
    res.json({ items: rows.slice(0, limit).map(withPrice), has_more: rows.length > limit });
  });

  app.get("/api/products/:slug", async (req, res) => {
    const [p] = await q(`SELECT id,name,slug,categories,status,thumbnail_url,gallery,price,discount_percent,description, ((SELECT COUNT(*) FROM orders o WHERE o.product_id=products.id AND o.status='accepted') + manual_buyers)::int AS buyers FROM products WHERE slug=$1 AND is_active`, [req.params.slug]);
    p ? res.json(withPrice(p)) : bad("Produk tidak ditemukan", 404);
  });

  app.post("/api/checkout", checkoutLimit, async (req, res) => {
    const b = req.body;
    const [p] = await q("SELECT id,name,price,discount_percent FROM products WHERE slug=$1 AND is_active", [String(b.slug || "").slice(0, 160)]);
    if (!p) bad("Produk tidak tersedia", 404);
    const [pm] = await q("SELECT id FROM payment_methods WHERE id=$1", [parseInt(b.payment_method_id, 10) || 0]);
    const name = String(b.buyer_name || "").trim(), wa = String(b.whatsapp || "").replace(/[\s-]/g, ""), proof = String(b.proof_url || "").trim();
    if (name.length < 2 || !pm || !isProofUrl(proof)) bad("Data tidak valid");
    const price = finalPrice(p.price, p.discount_percent);
    const [o] = await q(`INSERT INTO orders(product_id,product_name,price_paid,buyer_name,whatsapp,email,payment_method_id,proof_url) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, [p.id, p.name, price, name, waNum(wa), b.email || null, pm.id, proof]);
    await q("UPDATE orders SET checksum=$1 WHERE id=$2", [sig(o.id, p.id, price), o.id]);
    const t = jwt.sign({ oid: o.id }, K_SUCCESS, { algorithm: "HS256", expiresIn: "30m", issuer: ISS, audience: "success" });
    res.json({ redirect: "/success-pay?t=" + t });
  });

  app.get("/api/success", async (req, res) => {
    let d; try { d = jwt.verify(String(req.query.t || ""), K_SUCCESS, { algorithms: ["HS256"], issuer: ISS, audience: "success" }); } catch { bad("Akses kedaluwarsa", 403); }
    const [o] = await q("SELECT o.id, o.product_name, o.price_paid, o.buyer_name, p.product_link FROM orders o JOIN products p ON p.id = o.product_id WHERE o.id=$1", [Number(d.oid) || 0]);
    if (!o) bad("Order tidak ditemukan", 404);
    const text = `Halo, konfirmasi pembayaran order #${o.id} - ${o.product_name} (${rp(o.price_paid)}).`;
    res.json({ order_id: o.id, product_name: o.product_name, price_paid: Number(o.price_paid), buyer_name: o.buyer_name, wa_url: `https://wa.me/${waNum(ADMIN_WA)}?text=${encodeURIComponent(text)}` });
  });

  // ==========================================
  // 5. VIEW ENGINE & STATIC (AMAN UNTUK VERCEL)
  // Menggunakan process.cwd() agar akurat di sistem Vercel
  // ==========================================
  const publicDir = path.join(process.cwd(), "public");
  const view = (...f) => (req, res) => res.sendFile(path.join(publicDir, ...f));

  app.get("/", view("index.html"));
  app.get("/signin", view("signin.html"));
  app.get("/product/:slug", view("product", "detail-product.html"));
  app.get("/success-pay", view("success-pay.html"));
  
  app.get("/dashboard", adminAuth, view("admin", "dashboard.html"));
  app.get("/product-management", adminAuth, view("admin", "product-management.html"));
  app.get("/customer-order", adminAuth, view("admin", "customer-order.html"));
  app.get("/payment-method", adminAuth, view("admin", "payment-method.html"));
  app.get("/testimonial", adminAuth, view("admin", "testimonial.html"));

  app.use(express.static(publicDir, { index: false }));

  // ==========================================
  // 6. ERROR HANDLER GLOBAL
  // ==========================================
  app.use((req, res) => res.status(404).send("Halaman tidak ditemukan"));
  app.use((e, req, res, next) => {
    if (res.headersSent) return next(e);
    let status = e.status || 500, msg = e.expose ? e.message : "Kesalahan server";
    res.status(status).json({ error: msg });
  });

} catch (bootError) {
  // BENTENG TERAKHIR: Jika terjadi error di baris kode mana pun saat aplikasi dinyalakan, 
  // jangan crash, tapi tampilkan pesan error rapi ke browser.
  console.error("🔥 FATAL BOOT ERROR:", bootError.message);
  app.use((req, res) => {
    res.status(500).json({
      error: "Aplikasi gagal melakukan booting",
      detail: bootError.message
    });
  });
}

// ==========================================
// 7. ADAPTOR LOCALHOST & VERCEL (MAGIC HAPPENS HERE)
// ==========================================
if (process.env.VERCEL) {
  // Di Vercel, mengekspor app adalah syarat mutlak agar request bisa masuk.
  module.exports = app;
} else {
  // Di lokal (laptop), langsung jalankan listen seperti biasa!
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`🚀 Server lokal jalan di http://localhost:${port}`));
}