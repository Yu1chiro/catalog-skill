require("dotenv").config();
const express = require("express");
const app = express();

try {
  process.env.TZ = "Asia/Makassar";
  const path = require("path");
  const crypto = require("crypto");
  const cookieParser = require("cookie-parser");
  const jwt = require("jsonwebtoken");
  const sanitizeHtml = require("sanitize-html");
  const rateLimit = require("express-rate-limit");
  const { neon } = require("@neondatabase/serverless");

  const { DATABASE_URL, JWT_SECRET, IMAGEKIT_PRIVATE_KEY, IMAGEKIT_URL_ENDPOINT, ADMIN_WA } = process.env;
  const IS_PROD = process.env.NODE_ENV === "production" || !!process.env.VERCEL;

  if (!DATABASE_URL || !JWT_SECRET || !IMAGEKIT_PRIVATE_KEY || !IMAGEKIT_URL_ENDPOINT) {
    throw new Error("Environment Variable wajib ada yang belum terisi.");
  }

  const IK = new URL(IMAGEKIT_URL_ENDPOINT);
  const sql = neon(DATABASE_URL);
  const q = (t, p = []) => sql.query(t, p);

  // ==========================================
  // UTILITIES & KEAMANAN
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

  const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k))));
  const checkPw = async (pw, st = "") => {
    const [s, h] = String(st).split(":");
    if (!s || !/^[0-9a-f]{128}$/i.test(h || "")) return false;
    return crypto.timingSafeEqual(await scrypt(pw, s), Buffer.from(h, "hex"));
  };
  const DUMMY_HASH = "0".repeat(32) + ":" + "0".repeat(128);

  function parseProduct(b) {
    const name = String(b.name || "").trim();
    if (name.length < 2 || name.length > 120) bad("Nama produk minimal 2 dan maksimal 120 karakter");
    const categories = [...new Set((Array.isArray(b.categories) ? b.categories : []).map((c) => String(c).trim()).filter(Boolean))].slice(0, 10);
    if (!["terbaru", "terlama"].includes(b.status)) bad("Status urutan tidak valid");
    if (!isUrl(b.thumbnail_url || "")) bad("URL Thumbnail wajib diisi dan harus valid");
    const gallery = (Array.isArray(b.gallery) ? b.gallery : []).map(String).filter(Boolean);
    if (gallery.some((g) => !isUrl(g))) bad("Terdapat link gallery yang tidak valid");
    const price = parseInt(b.price, 10), discount = parseInt(b.discount_percent || 0, 10), manual_buyers = Math.max(0, parseInt(b.manual_buyers || 0, 10));
    if (!(price > 0 && price <= 1e12)) bad("Harga produk tidak valid");
    if (!(discount >= 0 && discount <= 100)) bad("Diskon harus berada di antara 0-100");
    const link = String(b.product_link || "").trim();
    if (link && !isUrl(link)) bad("Link akses produk eksternal tidak valid");
    return { name, categories, status: b.status, thumbnail_url: b.thumbnail_url, gallery, price, discount, manual_buyers, description: cleanHtml(b.description), link, active: b.is_active !== false };
  }

  // ==========================================
  // MIDDLEWARE
  // ==========================================
  app.disable("x-powered-by");
  app.set("trust proxy", IS_PROD ? 1 : false);
  app.use(cookieParser());
  
  // Pisahkan parser khusus untuk endpoint upload
  app.use((req, res, next) => {
    if (req.path === "/api/upload") return express.json({ limit: "5mb" })(req, res, next);
    return express.json({ limit: "200kb" })(req, res, next);
  });
  app.use((req, res, next) => { req.body ??= {}; next(); });

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
  // API AUTH & PUBLIC
  // ==========================================
  app.post("/api/auth/login", async (req, res) => {
    const username = String(req.body.username || "").trim().toLowerCase().slice(0, 64), password = String(req.body.password || "");
    if (!username || !password) bad("Username atau password salah", 401);
    const [a] = await q("SELECT id,username,password_hash FROM admins WHERE username=$1", [username]);
    if (!a || !(await checkPw(password, a ? a.password_hash : DUMMY_HASH))) bad("Username atau password salah", 401);
    const token = jwt.sign({ aid: a.id, u: a.username, pv: pv(a.password_hash) }, K_AUTH, { algorithm: "HS256", expiresIn: "8h", issuer: ISS, audience: "admin", subject: String(a.id) });
    res.cookie(COOKIE, token, { ...COOKIE_OPTS, maxAge: 8 * 3600e3 }).json({ ok: true });
  });

  app.post("/api/auth/logout", (req, res) => res.clearCookie(COOKIE, COOKIE_OPTS).json({ ok: true }));

  app.get("/api/categories", async (req, res) => {
    const rows = await q("SELECT DISTINCT unnest(categories) AS cat FROM products WHERE is_active");
    res.json(rows.map(r => r.cat));
  });

  app.get("/api/payment-methods", async (req, res) => {
    const rows = await q("SELECT * FROM payment_methods ORDER BY id ASC");
    res.json(rows);
  });

  app.get("/api/testimonials", async (req, res) => {
    const { limit, offset } = pg(req, 6);
    const rows = await q(`SELECT * FROM testimonials ORDER BY created_at DESC LIMIT ${limit + 1} OFFSET ${offset}`);
    res.json({ items: rows.slice(0, limit), has_more: rows.length > limit });
  });

  app.get("/api/products", async (req, res) => {
    const { limit, offset } = pg(req, 8);
    const cat = req.query.category, stat = req.query.status;
    let sqlQuery = "SELECT p.*, ((SELECT COUNT(*) FROM orders o WHERE o.product_id=p.id AND o.status='accepted') + p.manual_buyers)::int AS buyers FROM products p WHERE p.is_active";
    let params = [];
    if (cat) { params.push(cat); sqlQuery += ` AND $${params.length} = ANY(p.categories)`; }
    if (stat && ["terbaru", "terlama"].includes(stat)) { params.push(stat); sqlQuery += ` AND p.status=$${params.length}`; }
    sqlQuery += ` ORDER BY buyers DESC, p.created_at DESC LIMIT ${limit + 1} OFFSET ${offset}`;
    
    const rows = await q(sqlQuery, params);
    res.json({ items: rows.slice(0, limit).map(withPrice), has_more: rows.length > limit });
  });

  app.get("/api/products/:slug", async (req, res) => {
    const [p] = await q(`SELECT p.*, ((SELECT COUNT(*) FROM orders o WHERE o.product_id=p.id AND o.status='accepted') + p.manual_buyers)::int AS buyers FROM products p WHERE slug=$1 AND is_active`, [req.params.slug]);
    p ? res.json(withPrice(p)) : bad("Produk tidak ditemukan", 404);
  });

  // UPLOAD IMAGEKIT API DENGAN VALIDASI STRICT BASE64 & ANTI-XSS
  app.post("/api/upload", async (req, res) => {
    try {
      const { data, name } = req.body;
      if (!data || typeof data !== "string") bad("Data gambar tidak valid", 400);
      
      // Strict regex magic bytes untuk memastikan format adalah base64 image (PNG/JPG/WEBP)
      if (!/^data:image\/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$/.test(data)) {
         bad("Format file ditolak. Hanya menerima unggahan gambar yang valid.", 400);
      }
      
      const form = new URLSearchParams();
      form.append("file", data);
      form.append("fileName", String(name || "payment-proof.jpg").replace(/[^a-zA-Z0-9.-]/g, ""));
      form.append("folder", UPLOAD_FOLDER);

      const r = await fetch("https://upload.imagekit.io/api/v1/files/upload", {
        method: "POST",
        headers: { "Authorization": "Basic " + Buffer.from(IMAGEKIT_PRIVATE_KEY + ":").toString("base64") },
        body: form
      });
      const resJson = await r.json();
      if(!r.ok) throw new Error(resJson.message || "Gagal mengunggah foto ke server ImageKit");
      res.json({ url: resJson.url });
    } catch(e) {
      res.status(e.status || 500).json({ error: e.message });
    }
  });

  // CHECKOUT API DENGAN PERLINDUNGAN KARAKTER & BYPASS HARGA
  app.post("/api/checkout", async (req, res) => {
    const b = req.body;
    
    // Pembersihan & Limitasi String Ekstra Ketat
    const name = String(b.buyer_name || "").trim().slice(0, 100);
    const wa = String(b.whatsapp || "").replace(/[\s-]/g, "").slice(0, 20);
    const proof = String(b.proof_url || "").trim();
    const email = String(b.email || "").trim().slice(0, 150);
    
    if (name.length < 2) bad("Nama lengkap minimal 2 karakter");
    if (wa.length < 9) bad("Nomor WhatsApp tidak valid");
    if (!isProofUrl(proof)) bad("URL Bukti pembayaran tidak valid atau belum diunggah");

    // Harga mutlak diambil dari database, klien tidak bisa memanipulasi parameter
    const [p] = await q("SELECT id,name,price,discount_percent FROM products WHERE slug=$1 AND is_active", [String(b.slug || "").slice(0, 160)]);
    if (!p) bad("Produk tidak ditemukan atau tidak tersedia", 404);
    
    const [pm] = await q("SELECT id FROM payment_methods WHERE id=$1", [parseInt(b.payment_method_id, 10) || 0]);
    if (!pm) bad("Metode pembayaran tidak valid", 400);

    const price = finalPrice(p.price, p.discount_percent);
    const [o] = await q(`INSERT INTO orders(product_id,product_name,price_paid,buyer_name,whatsapp,email,payment_method_id,proof_url) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, [p.id, p.name, price, name, waNum(wa), email || null, pm.id, proof]);
    
    await q("UPDATE orders SET checksum=$1 WHERE id=$2", [sig(o.id, p.id, price), o.id]);
    const t = jwt.sign({ oid: o.id }, K_SUCCESS, { algorithm: "HS256", expiresIn: "30m", issuer: ISS, audience: "success" });
    res.json({ redirect: "/success-pay?t=" + t });
  });

  app.get("/api/success", async (req, res) => {
    let d; try { d = jwt.verify(String(req.query.t || ""), K_SUCCESS, { algorithms: ["HS256"], issuer: ISS, audience: "success" }); } catch { bad("Akses URL kedaluwarsa atau tidak valid", 403); }
    const [o] = await q("SELECT o.id, o.product_name, o.price_paid, o.buyer_name, p.product_link FROM orders o JOIN products p ON p.id = o.product_id WHERE o.id=$1", [Number(d.oid) || 0]);
    if (!o) bad("Data order tidak ditemukan", 404);
    const text = `Halo, konfirmasi pembayaran order #${o.id} - ${o.product_name} (${rp(o.price_paid)}).`;
    res.json({ order_id: o.id, product_name: o.product_name, price_paid: Number(o.price_paid), buyer_name: o.buyer_name, wa_url: `https://wa.me/${waNum(ADMIN_WA)}?text=${encodeURIComponent(text)}` });
  });

  // ==========================================
  // API ADMIN CRUD
  // ==========================================
  
  // Dashboard Stats
  app.get("/api/admin/stats", adminAuth, async (req, res) => {
    const [omzet] = await q("SELECT COALESCE(SUM(price_paid), 0) AS total FROM orders WHERE status='accepted'");
    const [buyers] = await q("SELECT COUNT(*) AS total FROM orders WHERE status='accepted'");
    const [products] = await q("SELECT COUNT(*) AS total FROM products");
    
    const daily = [{ label: "Hari ini", omzet: parseInt(omzet.total) }];
    res.json({ omzet: parseInt(omzet.total), buyers: parseInt(buyers.total), products: parseInt(products.total), daily, weekly: daily, monthly: daily });
  });

  // Admin CRUD Products
  app.get("/api/admin/products", adminAuth, async (req, res) => {
    const { limit, offset } = pg(req, 10);
    const rows = await q(`SELECT * FROM products ORDER BY created_at DESC LIMIT ${limit+1} OFFSET ${offset}`);
    res.json({ items: rows.slice(0, limit).map(withPrice), has_more: rows.length > limit, page: req.query.page || 1 });
  });
  
  app.post("/api/admin/products", adminAuth, async (req, res) => {
    const p = parseProduct(req.body);
    const slug = await uniqueSlug(p.name);
    await q(`INSERT INTO products (name, slug, categories, status, thumbnail_url, gallery, price, discount_percent, description, product_link, manual_buyers, is_active) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [p.name, slug, p.categories, p.status, p.thumbnail_url, p.gallery, p.price, p.discount, p.description, p.link, p.manual_buyers, p.active]);
    res.json({ ok: true });
  });

  app.put("/api/admin/products/:id", adminAuth, async (req, res) => {
    const p = parseProduct(req.body);
    const id = parseInt(req.params.id);
    const slug = await uniqueSlug(p.name, id);
    await q(`UPDATE products SET name=$1, slug=$2, categories=$3, status=$4, thumbnail_url=$5, gallery=$6, price=$7, discount_percent=$8, description=$9, product_link=$10, manual_buyers=$11, is_active=$12 WHERE id=$13`,
      [p.name, slug, p.categories, p.status, p.thumbnail_url, p.gallery, p.price, p.discount, p.description, p.link, p.manual_buyers, p.active, id]);
    res.json({ ok: true });
  });

  app.delete("/api/admin/products/:id", adminAuth, async (req, res) => {
    try {
      await q("DELETE FROM products WHERE id=$1", [parseInt(req.params.id)]);
      res.json({ ok: true });
    } catch(e) {
      bad("Gagal menghapus. Produk ini mungkin sudah memiliki rekaman pesanan (Order) terkait.", 409);
    }
  });

  // Admin CRUD Orders
  app.get("/api/admin/orders", adminAuth, async (req, res) => {
    const { limit, offset } = pg(req, 10);
    const status = req.query.status;
    let qStr = "SELECT * FROM orders";
    let params = [];
    if (status && ['pending','accepted','rejected'].includes(status)) { qStr += " WHERE status=$1"; params.push(status); }
    qStr += ` ORDER BY created_at DESC LIMIT ${limit+1} OFFSET ${offset}`;
    
    const rows = await q(qStr, params);
    const items = rows.slice(0, limit).map(o => ({
      ...o, price_paid: Number(o.price_paid),
      wa_url: `https://wa.me/${o.whatsapp}`,
      checksum_ok: safeEq(o.checksum, sig(o.id, o.product_id, o.price_paid))
    }));
    res.json({ items, has_more: rows.length > limit, page: req.query.page || 1 });
  });

  app.get("/api/admin/orders/:id", adminAuth, async (req, res) => {
    const [o] = await q("SELECT o.*, pm.bank_name FROM orders o LEFT JOIN payment_methods pm ON o.payment_method_id = pm.id WHERE o.id=$1", [parseInt(req.params.id)]);
    if(!o) bad("Order tidak ditemukan", 404);
    o.price_paid = Number(o.price_paid);
    res.json(o);
  });

  app.patch("/api/admin/orders/:id/status", adminAuth, async (req, res) => {
    const s = req.body.status;
    if(!['pending','accepted','rejected'].includes(s)) bad("Status tidak valid");
    await q("UPDATE orders SET status=$1 WHERE id=$2", [s, parseInt(req.params.id)]);
    res.json({ ok: true });
  });

  app.delete("/api/admin/orders/:id", adminAuth, async (req, res) => {
    await q("DELETE FROM orders WHERE id=$1", [parseInt(req.params.id)]);
    res.json({ ok: true });
  });

  // Admin CRUD Payment Methods
  app.get("/api/admin/payment-methods", adminAuth, async (req, res) => {
    const rows = await q("SELECT * FROM payment_methods ORDER BY id ASC");
    res.json(rows);
  });

  app.post("/api/admin/payment-methods", adminAuth, async (req, res) => {
    const b = req.body;
    await q("INSERT INTO payment_methods (bank_name, account_number, account_holder) VALUES ($1,$2,$3)", [b.bank_name, b.account_number, b.account_holder]);
    res.json({ ok: true });
  });

  app.put("/api/admin/payment-methods/:id", adminAuth, async (req, res) => {
    const b = req.body;
    await q("UPDATE payment_methods SET bank_name=$1, account_number=$2, account_holder=$3 WHERE id=$4", [b.bank_name, b.account_number, b.account_holder, parseInt(req.params.id)]);
    res.json({ ok: true });
  });

  app.delete("/api/admin/payment-methods/:id", adminAuth, async (req, res) => {
    await q("DELETE FROM payment_methods WHERE id=$1", [parseInt(req.params.id)]);
    res.json({ ok: true });
  });

  // Admin CRUD Testimonials
  app.get("/api/admin/testimonials", adminAuth, async (req, res) => {
    const { limit, offset } = pg(req, 10);
    const rows = await q(`SELECT * FROM testimonials ORDER BY created_at DESC LIMIT ${limit + 1} OFFSET ${offset}`);
    res.json({ items: rows.slice(0, limit), has_more: rows.length > limit, page: req.query.page || 1 });
  });

  app.post("/api/admin/testimonials", adminAuth, async (req, res) => {
    const b = req.body;
    await q("INSERT INTO testimonials (customer_name, origin, description) VALUES ($1,$2,$3)", [b.customer_name, b.origin, b.description]);
    res.json({ ok: true });
  });

  app.put("/api/admin/testimonials/:id", adminAuth, async (req, res) => {
    const b = req.body;
    await q("UPDATE testimonials SET customer_name=$1, origin=$2, description=$3 WHERE id=$4", [b.customer_name, b.origin, b.description, parseInt(req.params.id)]);
    res.json({ ok: true });
  });

  app.delete("/api/admin/testimonials/:id", adminAuth, async (req, res) => {
    await q("DELETE FROM testimonials WHERE id=$1", [parseInt(req.params.id)]);
    res.json({ ok: true });
  });

  // ==========================================
  // VIEW ENGINE & STATIC (AMAN UNTUK VERCEL)
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

  // ERROR HANDLER GLOBAL
  app.use((req, res) => res.status(404).send("Halaman tidak ditemukan"));
  app.use((e, req, res, next) => {
    if (res.headersSent) return next(e);
    let status = e.status || 500, msg = e.expose ? e.message : "Kesalahan internal server";
    res.status(status).json({ error: msg });
  });

} catch (bootError) {
  console.error("🔥 FATAL BOOT ERROR:", bootError.message);
  app.use((req, res) => {
    res.status(500).json({ error: "Aplikasi gagal melakukan booting", detail: bootError.message });
  });
}

// ADAPTOR LOCALHOST & VERCEL
if (process.env.VERCEL) {
  module.exports = app;
} else {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`🚀 Server lokal berjalan aman di http://localhost:${port}`));
}