require("dotenv").config();
process.env.TZ = "Asia/Makassar"; 
const TZ = process.env.TZ;
if (/^4\./.test(require("express/package.json").version))
  require("express-async-errors");
const path = require("path"),
  crypto = require("crypto");
const express = require("express"),
  cookieParser = require("cookie-parser"),
  jwt = require("jsonwebtoken");
const sanitizeHtml = require("sanitize-html"),
  rateLimit = require("express-rate-limit");
const { neon } = require("@neondatabase/serverless");

const {
  DATABASE_URL,
  JWT_SECRET,
  IMAGEKIT_PRIVATE_KEY,
  IMAGEKIT_URL_ENDPOINT,
  ADMIN_WA,
  SETUP_KEY, 
  LEGACY_CHECKSUM_SECRET, 
  PORT = 3000,
} = process.env;
const IS_PROD = process.env.NODE_ENV === "production" || !!process.env.VERCEL;

const missing = [
  "DATABASE_URL",
  "JWT_SECRET",
  "IMAGEKIT_PRIVATE_KEY",
  "IMAGEKIT_URL_ENDPOINT",
  "ADMIN_WA",
].filter((k) => !process.env[k]);
if (missing.length)
  throw new Error("Env wajib belum diisi: " + missing.join(", "));
if (JWT_SECRET.length < 32)
  throw new Error(
    "JWT_SECRET minimal 32 karakter. Buat dengan: node -e \"console.log(require('crypto').randomBytes(48).toString('base64url'))\"",
  );
const IK = new URL(IMAGEKIT_URL_ENDPOINT);
if (IK.protocol !== "https:")
  throw new Error("IMAGEKIT_URL_ENDPOINT harus https");
if (IS_PROD && SETUP_KEY)
  console.warn("PERINGATAN: hapus SETUP_KEY dari env production");

const subKey = (info) =>
  Buffer.from(crypto.hkdfSync("sha256", JWT_SECRET, "katalog-v1", info, 32));
const K_AUTH = subKey("admin-jwt"),
  K_SUCCESS = subKey("success-jwt"),
  K_SUM = subKey("order-checksum");
const ISS = "katalog";

const sql = neon(DATABASE_URL);
const q = (t, p = []) => sql.query(t, p);

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", IS_PROD ? 1 : false);

const bad = (m, status = 400) => {
  throw Object.assign(new Error(m), { status, expose: true });
};
const finalPrice = (p, d) => Math.round((Number(p) * (100 - d)) / 100);
const slugify = (s) =>
  s
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^\w\s-]/g, "")
    .trim()
    .replace(/[\s_]+/g, "-")
    .replace(/-+/g, "-");
async function uniqueSlug(name, ignoreId = 0) {
  const base = slugify(name) || "produk";
  let s = base,
    i = 1;
  while (
    (await q("SELECT 1 FROM products WHERE slug=$1 AND id<>$2", [s, ignoreId]))
      .length
  )
    s = `${base}-${++i}`;
  return s;
}
const hmac = (key, ...a) =>
  crypto.createHmac("sha256", key).update(a.join("|")).digest("hex");
const sig = (...a) => hmac(K_SUM, ...a);
const legacySig = (...a) => hmac(LEGACY_CHECKSUM_SECRET || JWT_SECRET, ...a); 
const safeEq = (a, b) => {
  a = Buffer.from(String(a ?? ""));
  b = Buffer.from(String(b ?? ""));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const checksumOk = (o) =>
  safeEq(o.checksum, sig(o.id, o.product_id, o.price_paid)) ||
  safeEq(o.checksum, legacySig(o.id, o.product_id, o.price_paid));
const COLOR = /^(#[0-9a-f]{3,8}|rgba?\(\s*\d{1,3}\s*(,\s*[\d.]+\s*){2,3}\))$/i;
const cleanHtml = (h) =>
  sanitizeHtml(h || "", {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat([
      "h1",
      "h2",
      "u",
      "s",
      "span",
    ]),
    allowedAttributes: {
      "*": ["class", "style"],
      a: ["href", "target", "rel"],
    },
    allowedClasses: { "*": ["ql-*"] }, 
    allowedStyles: { "*": { color: [COLOR], "background-color": [COLOR] } },
    transformTags: {
      a: sanitizeHtml.simpleTransform("a", {
        rel: "noopener noreferrer",
        target: "_blank",
      }),
    },
  });
const waNum = (n) => {
  n = String(n).replace(/\D/g, "");
  return n.startsWith("0") ? "62" + n.slice(1) : n;
};
const rp = (n) => "Rp" + Number(n).toLocaleString("id-ID");
const isUrl = (u) => {
  try {
    const s = String(u);
    return (
      s.length <= 2000 &&
      !/\s/.test(s) &&
      ["http:", "https:"].includes(new URL(s).protocol)
    );
  } catch {
    return false;
  }
};
const UPLOAD_FOLDER = "skills-catalog";
const IK_PREFIX = IK.pathname.replace(/\/+$/, "") + "/" + UPLOAD_FOLDER + "/";
const isProofUrl = (u) => {
  try {
    if (typeof u !== "string" || u.length > 500) return false;
    const x = new URL(u);
    return (
      x.origin === IK.origin &&
      !x.username &&
      !x.password &&
      x.pathname.startsWith(IK_PREFIX)
    );
  } catch {
    return false;
  }
};
const withPrice = (p) => ({
  ...p,
  price: Number(p.price),
  final_price: finalPrice(p.price, p.discount_percent),
});
const pg = (req, def = 10) => {
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || def)),
    page = Math.max(1, parseInt(req.query.page, 10) || 1);
  return { limit, page, offset: (page - 1) * limit };
};
const pages = (n, limit) => Math.max(1, Math.ceil(n / limit));

const scrypt = (pw, salt) =>
  new Promise((res, rej) =>
    crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k))),
  );
const hashPw = async (pw) => {
  const s = crypto.randomBytes(16).toString("hex");
  return s + ":" + (await scrypt(pw, s)).toString("hex");
};
const checkPw = async (pw, st = "") => {
  const [s, h] = String(st).split(":");
  if (!s || !/^[0-9a-f]{128}$/i.test(h || "")) return false;
  return crypto.timingSafeEqual(await scrypt(pw, s), Buffer.from(h, "hex"));
};
const DUMMY_HASH = "0".repeat(32) + ":" + "0".repeat(128); 

const audit = (ev, req, extra = {}) =>
  console.log(
    JSON.stringify({ ts: new Date().toISOString(), audit: ev, ip: req.ip, ...extra }),
  );

function parseProduct(b) {
  const name = String(b.name || "").trim();
  if (name.length < 2 || name.length > 120) bad("Nama produk 2-120 karakter");
  const categories = [
    ...new Set(
      (Array.isArray(b.categories) ? b.categories : [])
        .map((c) => String(c).trim())
        .filter(Boolean),
    ),
  ].slice(0, 10);
  if (!["terbaru", "terlama"].includes(b.status)) bad("Status tidak valid");
  if (!isUrl(b.thumbnail_url || "")) bad("Thumbnail wajib");
  const gallery = (Array.isArray(b.gallery) ? b.gallery : [])
    .map(String)
    .filter(Boolean);
  if (gallery.some((g) => !isUrl(g))) bad("Link gallery tidak valid");
  const price = parseInt(b.price, 10),
    discount = parseInt(b.discount_percent || 0, 10),
    manual_buyers = Math.max(0, parseInt(b.manual_buyers || 0, 10)); // <-- TAMBAHAN: Validasi manual_buyers
  if (!(price > 0 && price <= 1e12)) bad("Harga tidak valid");
  if (!(discount >= 0 && discount <= 100)) bad("Diskon 0-100");
  const link = String(b.product_link || "").trim();
  if (link && !isUrl(link)) bad("Link produk tidak valid");
  return {
    name,
    categories,
    status: b.status,
    thumbnail_url: b.thumbnail_url,
    gallery,
    price,
    discount,
    manual_buyers, // <-- TAMBAHAN: return manual_buyers
    description: cleanHtml(b.description),
    link,
    active: b.is_active !== false,
  };
}

app.use((req, res, next) => {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy":
      "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy":
      "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
  });
  if (IS_PROD) res.set("Strict-Transport-Security", "max-age=31536000");
  next();
});
app.use(
  [
    "/api/admin",
    "/api/auth",
    "/api/success",
    "/api/setup",
    "/success-pay",
    "/dashboard",
    "/product-management",
    "/customer-order",
    "/payment-method",
    "/testimonial",
  ],
  (req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
  },
);
app.use(["/success-pay", "/api/success"], (req, res, next) => {
  res.set("Referrer-Policy", "no-referrer");
  next();
});

const jsonSmall = express.json({ limit: "200kb" });
app.use((req, res, next) =>
  req.path === "/api/upload" ? next() : jsonSmall(req, res, next),
);
app.use(cookieParser());
app.use((req, res, next) => {
  req.body ??= {};
  next();
});
app.use("/api", (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const o = req.get("origin");
  if (o) {
    let ok = false;
    try {
      ok = new URL(o).host === req.get("host");
    } catch {}
    if (!ok) bad("Origin tidak diizinkan", 403);
  }
  next();
});

const mk = (windowMs, limit, extra = {}) =>
  rateLimit({
    windowMs,
    limit,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "Terlalu banyak permintaan, coba lagi nanti" },
    ...extra,
  });
const loginLimit = mk(15 * 60e3, 10);
const checkoutLimit = mk(10 * 60e3, 10);
const readLimit = mk(60e3, 120);

const COOKIE = IS_PROD ? "__Host-token" : "token"; 
const COOKIE_OPTS = {
  httpOnly: true,
  sameSite: "strict",
  secure: IS_PROD,
  path: "/",
};
const VERIFY_ADMIN = { algorithms: ["HS256"], issuer: ISS, audience: "admin" };
const pv = (hash) => hmac(K_AUTH, "pv", hash).slice(0, 32);
const readAdminToken = (req) => {
  try {
    return jwt.verify(req.cookies[COOKIE], K_AUTH, VERIFY_ADMIN);
  } catch {
    return null;
  }
};
const adminAuth = async (req, res, next) => {
  const fail = () => {
    res.clearCookie(COOKIE, COOKIE_OPTS);
    return req.originalUrl.startsWith("/api")
      ? res.status(401).json({ error: "Unauthorized" })
      : res.redirect("/signin");
  };
  const t = readAdminToken(req);
  if (!t) return fail();
  const [a] = await q(
    "SELECT id,username,password_hash FROM admins WHERE id=$1",
    [Number(t.aid) || 0],
  );
  if (!a || !safeEq(pv(a.password_hash), t.pv)) return fail();
  req.admin = { id: a.id, u: a.username };
  next();
};

let authReady;
const ensureAuthTables = () =>
  (authReady ||= (async () => {
    await q(`CREATE TABLE IF NOT EXISTS login_attempts (
      id BIGSERIAL PRIMARY KEY,
      ip TEXT NOT NULL,
      username TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
    await q(
      "CREATE INDEX IF NOT EXISTS idx_login_attempts_created ON login_attempts(created_at)",
    );
  })().catch((e) => {
    authReady = null;
    throw e;
  }));

app.post("/api/auth/login", loginLimit, async (req, res) => {
  const username = String(req.body.username || "")
      .trim()
      .toLowerCase()
      .slice(0, 64),
    password = String(req.body.password || "");
  if (!username || !password || password.length > 128)
    bad("Username atau password salah", 401);

  await ensureAuthTables();
  const ip = req.ip || "unknown";
  const [c] = await q(
    `SELECT COUNT(*) FILTER (WHERE ip=$1)::int AS by_ip,
            COUNT(*) FILTER (WHERE username=$2)::int AS by_user
     FROM login_attempts WHERE created_at > now() - interval '15 minutes'`,
    [ip, username],
  );
  if (c.by_ip >= 10 || c.by_user >= 15) {
    audit("login_locked", req, { u: username });
    res.set("Retry-After", "900");
    bad("Terlalu banyak percobaan login, coba lagi 15 menit lagi", 429);
  }

  const [a] = await q(
    "SELECT id,username,password_hash FROM admins WHERE username=$1",
    [username],
  );
  const ok = await checkPw(password, a ? a.password_hash : DUMMY_HASH);
  if (!a || !ok) {
    await q("INSERT INTO login_attempts(ip,username) VALUES($1,$2)", [
      ip,
      username,
    ]);
    if (Math.random() < 0.05)
      await q(
        "DELETE FROM login_attempts WHERE created_at < now() - interval '1 day'",
      );
    audit("login_fail", req, { u: username });
    bad("Username atau password salah", 401);
  }
  await q("DELETE FROM login_attempts WHERE username=$1", [username]);

  const token = jwt.sign(
    { aid: a.id, u: a.username, pv: pv(a.password_hash) },
    K_AUTH,
    {
      algorithm: "HS256",
      expiresIn: "8h",
      issuer: ISS,
      audience: "admin",
      subject: String(a.id),
    },
  );
  res.cookie(COOKIE, token, { ...COOKIE_OPTS, maxAge: 8 * 3600e3 });
  audit("login_ok", req, { u: a.username });
  res.json({ ok: true });
});

app.post("/api/auth/logout", (req, res) => {
  const t = readAdminToken(req);
  if (t) audit("logout", req, { u: t.u });
  res.clearCookie(COOKIE, COOKIE_OPTS).json({ ok: true });
});

if (!IS_PROD) {
  app.post("/api/setup/create-admin", loginLimit, async (req, res) => {
    const ra = req.socket.remoteAddress || "";
    if (!["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(ra))
      bad("Not found", 404);
    if (!SETUP_KEY || SETUP_KEY.length < 16) bad("Not found", 404);
    if (!safeEq(String(req.get("x-setup-key") || ""), SETUP_KEY))
      bad("Setup key salah", 403);
    const u = String(req.body.username || "")
        .trim()
        .toLowerCase(),
      pw = String(req.body.password || "");
    if (!/^[a-z0-9_.-]{3,32}$/.test(u))
      bad("Username 3-32 karakter (a-z 0-9 _ . -)");
    if (pw.length < 12 || pw.length > 128) bad("Password 12-128 karakter");
    try {
      await q("INSERT INTO admins(username,password_hash) VALUES($1,$2)", [
        u,
        await hashPw(pw),
      ]);
    } catch (e) {
      if (e.code === "23505") bad("Username sudah ada", 409);
      throw e;
    }
    audit("admin_created", req, { u });
    res.status(201).json({ ok: true, username: u });
  });
}

const IMG_TYPES = [
  {
    ext: "png",
    ok: (b) =>
      b.length > 24 &&
      b.subarray(0, 8).equals(Buffer.from("89504e470d0a1a0a", "hex")),
  },
  {
    ext: "jpg",
    ok: (b) => b.length > 4 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  },
  {
    ext: "webp",
    ok: (b) =>
      b.length > 12 &&
      b.toString("latin1", 0, 4) === "RIFF" &&
      b.toString("latin1", 8, 12) === "WEBP",
  },
];
const uploadLimit = mk(10 * 60e3, 15, { skip: (req) => !!readAdminToken(req) });
app.post(
  "/api/upload",
  uploadLimit,
  express.json({ limit: "3.5mb" }),
  async (req, res) => {
    const raw = String((req.body || {}).data || "");
    const m =
      raw.length <= 2.9e6 &&
      /^data:image\/(?:png|jpe?g|webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(raw);
    if (!m || m[1].length % 4 !== 0)
      bad("File harus gambar PNG/JPG/WEBP maks ~2MB");
    const buf = Buffer.from(m[1], "base64");
    if (buf.length > 2 * 1024 * 1024) bad("Ukuran gambar maksimal 2MB");
    const kind = IMG_TYPES.find((t) => t.ok(buf));
    if (!kind) bad("Isi file bukan gambar PNG/JPG/WEBP yang valid");

    const fd = new FormData();
    fd.append("file", buf.toString("base64"));
    fd.append(
      "fileName",
      `${Date.now()}-${crypto.randomBytes(12).toString("hex")}.${kind.ext}`,
    );
    fd.append("useUniqueFileName", "false");
    fd.append("folder", "/" + UPLOAD_FOLDER);
    let r, j;
    try {
      r = await fetch("https://upload.imagekit.io/api/v1/files/upload", {
        method: "POST",
        headers: {
          Authorization:
            "Basic " +
            Buffer.from(IMAGEKIT_PRIVATE_KEY + ":").toString("base64"),
        },
        body: fd,
        signal: AbortSignal.timeout(8000),
      });
      j = await r.json().catch(() => ({}));
    } catch (e) {
      console.error("imagekit upload error:", e.message);
      bad("Upload gagal", 502);
    }
    if (!r.ok || !j.url) {
      console.error("imagekit upload status:", r.status);
      bad("Upload gagal", 502);
    }
    res.json({ url: j.url });
  },
);

app.use(
  ["/api/categories", "/api/products", "/api/payment-methods", "/api/testimonials"],
  readLimit,
);

app.get("/api/categories", async (req, res) => {
  const rows = await q(
    "SELECT DISTINCT unnest(categories) AS c FROM products WHERE is_active ORDER BY 1",
  );
  res.json(rows.map((r) => r.c));
});

app.get("/api/products", async (req, res) => {
  const where = ["p.is_active"],
    params = [];
  const limit = Math.min(24, Math.max(1, parseInt(req.query.limit, 10) || 6)),
    offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
  if (req.query.category) {
    params.push(String(req.query.category).slice(0, 100));
    where.push(`$${params.length} = ANY(p.categories)`);
  }
  if (["terbaru", "terlama"].includes(req.query.status)) {
    params.push(req.query.status);
    where.push(`p.status=$${params.length}`);
  }
  // <-- TAMBAHAN: Menjumlahkan order 'accepted' dengan 'manual_buyers'
  const rows = await q(
    `SELECT p.id,p.name,p.slug,p.categories,p.status,p.thumbnail_url,p.price,p.discount_percent,
    LEFT(regexp_replace(p.description,'<[^>]+>','','g'),120) AS short_description,
    ((SELECT COUNT(*) FROM orders o WHERE o.product_id=p.id AND o.status='accepted') + p.manual_buyers)::int AS buyers
    FROM products p WHERE ${where.join(" AND ")} ORDER BY buyers DESC, p.created_at DESC, p.id DESC LIMIT ${limit + 1} OFFSET ${offset}`,
    params,
  );
  res.json({
    items: rows.slice(0, limit).map(withPrice),
    has_more: rows.length > limit,
  });
});

app.get("/api/products/:slug", async (req, res) => {
  if (!/^[a-z0-9_-]{1,160}$/i.test(req.params.slug))
    bad("Produk tidak ditemukan", 404);
  // <-- TAMBAHAN: Menjumlahkan order 'accepted' dengan 'manual_buyers'
  const [p] = await q(
    `SELECT id,name,slug,categories,status,thumbnail_url,gallery,price,discount_percent,description,
    ((SELECT COUNT(*) FROM orders o WHERE o.product_id=products.id AND o.status='accepted') + manual_buyers)::int AS buyers
    FROM products WHERE slug=$1 AND is_active`,
    [req.params.slug],
  ); 
  p ? res.json(withPrice(p)) : bad("Produk tidak ditemukan", 404);
});

app.get("/api/payment-methods", async (req, res) =>
  res.json(
    await q(
      "SELECT id,bank_name,account_number,account_holder FROM payment_methods ORDER BY id",
    ),
  ),
);

app.get("/api/testimonials", async (req, res) => {
  const limit = Math.min(20, Math.max(1, parseInt(req.query.limit, 10) || 5)),
    offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
  const rows = await q(
    `SELECT id,customer_name,origin,description FROM testimonials ORDER BY created_at DESC, id DESC LIMIT ${limit + 1} OFFSET ${offset}`,
  );
  res.json({ items: rows.slice(0, limit), has_more: rows.length > limit });
});

app.post("/api/checkout", checkoutLimit, async (req, res) => {
  const b = req.body;
  const [p] = await q(
    "SELECT id,name,price,discount_percent FROM products WHERE slug=$1 AND is_active",
    [String(b.slug || "").slice(0, 160)],
  );
  if (!p) bad("Produk tidak tersedia", 404);
  const [pm] = await q("SELECT id FROM payment_methods WHERE id=$1", [
    parseInt(b.payment_method_id, 10) || 0,
  ]);
  const name = String(b.buyer_name || "").trim(),
    wa = String(b.whatsapp || "").replace(/[\s-]/g, ""),
    email = String(b.email || "").trim(),
    proof = String(b.proof_url || "").trim();
  if (name.length < 2 || name.length > 100) bad("Nama pembeli tidak valid");
  if (!/^(\+?62|0)8\d{7,12}$/.test(wa)) bad("Nomor WhatsApp tidak valid");
  if (email && (email.length > 150 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)))
    bad("Email tidak valid");
  if (!pm) bad("Metode pembayaran tidak valid");
  if (!isProofUrl(proof)) bad("Bukti pembayaran tidak valid");
  if ((await q("SELECT 1 FROM orders WHERE proof_url=$1 LIMIT 1", [proof])).length)
    bad("Bukti pembayaran sudah pernah digunakan", 409);
  const price = finalPrice(p.price, p.discount_percent);
  const [o] = await q(
    `INSERT INTO orders(product_id,product_name,price_paid,buyer_name,whatsapp,email,payment_method_id,proof_url)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
    [p.id, p.name, price, name, waNum(wa), email || null, pm.id, proof],
  );
  await q("UPDATE orders SET checksum=$1 WHERE id=$2", [
    sig(o.id, p.id, price),
    o.id,
  ]);
  audit("checkout", req, { order: o.id, product: p.id, price });
  const t = jwt.sign({ oid: o.id }, K_SUCCESS, {
    algorithm: "HS256",
    expiresIn: "30m",
    issuer: ISS,
    audience: "success",
  });
  res.json({ redirect: "/success-pay?t=" + t });
});

app.get("/api/success", async (req, res) => {
  let d;
  try {
    d = jwt.verify(String(req.query.t || ""), K_SUCCESS, {
      algorithms: ["HS256"],
      issuer: ISS,
      audience: "success",
    });
  } catch {
    bad("Akses tidak valid / kedaluwarsa", 403);
  }
  
  const [o] = await q(
    "SELECT o.id, o.product_name, o.price_paid, o.buyer_name, p.product_link FROM orders o JOIN products p ON p.id = o.product_id WHERE o.id=$1",
    [Number(d.oid) || 0],
  );
  
  if (!o) bad("Order tidak ditemukan", 404);
  
  const text = `Halo, saya ${o.buyer_name}.\n\nSaya ingin mengkonfirmasi pembayaran untuk order #${o.id}.\n\n*Detail Pesanan:*\n- Nama Produk: ${o.product_name}\n- Harga: ${rp(o.price_paid)}\n- Link Produk: ${o.product_link}\n\nMohon segera diproses. Terima kasih!`;
  
  res.json({
    order_id: o.id,
    product_name: o.product_name,
    price_paid: Number(o.price_paid),
    buyer_name: o.buyer_name,
    wa_url: `https://wa.me/${waNum(ADMIN_WA)}?text=${encodeURIComponent(text)}`,
  });
});

const view =
  (...f) =>
  (req, res) =>
    res.sendFile(path.join(__dirname, "public", ...f));

app.get("/", view("index.html"));
app.get("/signin", view("signin.html"));
app.get("/product/:slug", view("product", "detail-product.html"));
app.get("/success-pay", view("success-pay.html"));

app.get("/dashboard", adminAuth, view("admin", "dashboard.html"));
app.get(
  "/product-management",
  adminAuth,
  view("admin", "product-management.html"),
);
app.get("/customer-order", adminAuth, view("admin", "customer-order.html"));
app.get("/payment-method", adminAuth, view("admin", "payment-method.html"));
app.get("/testimonial", adminAuth, view("admin", "testimonial.html"));

app.use((req, res, next) =>
  /^\/admin(\/|$)|\.html?$/i.test(req.path)
    ? res.status(404).send("Halaman tidak ditemukan")
    : next(),
);
app.use(express.static(path.join(__dirname, "public"), { index: false }));

const admin = express.Router();
admin.use(adminAuth);
admin.param("id", (req, res, next, v) => {
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 1 || n > 2147483647)
    return next(
      Object.assign(new Error("ID tidak valid"), { status: 400, expose: true }),
    );
  req.params.id = n;
  next();
});
app.use("/api/admin", admin);

admin.get("/products", async (req, res) => {
  const { limit, page, offset } = pg(req);
  const [{ n }] = await q("SELECT COUNT(*)::int AS n FROM products");
  const rows = await q(
    `SELECT * FROM products ORDER BY created_at DESC, id DESC LIMIT ${limit} OFFSET ${offset}`,
  );
  res.json({
    items: rows.map(withPrice),
    total: n,
    page,
    pages: pages(n, limit),
  });
});
admin.get("/products/:id", async (req, res) => {
  const [p] = await q("SELECT * FROM products WHERE id=$1", [req.params.id]);
  p ? res.json(withPrice(p)) : bad("Tidak ditemukan", 404);
});
admin.post("/products", async (req, res) => {
  const d = parseProduct(req.body),
    slug = await uniqueSlug(d.name);
  // <-- TAMBAHAN: manual_buyers di INSERT QUERY
  const [p] = await q(
    `INSERT INTO products(name,slug,categories,status,thumbnail_url,gallery,price,discount_percent,description,product_link,manual_buyers,is_active)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
    [
      d.name,
      slug,
      d.categories,
      d.status,
      d.thumbnail_url,
      d.gallery,
      d.price,
      d.discount,
      d.description,
      d.link,
      d.manual_buyers,
      d.active,
    ],
  );
  audit("product_create", req, { admin: req.admin.u, id: p.id });
  res.status(201).json(p);
});
admin.put("/products/:id", async (req, res) => {
  const d = parseProduct(req.body),
    id = req.params.id,
    slug = await uniqueSlug(d.name, id);
  // <-- TAMBAHAN: manual_buyers di UPDATE QUERY
  const r = await q(
    `UPDATE products SET name=$1,slug=$2,categories=$3,status=$4,thumbnail_url=$5,gallery=$6,price=$7,discount_percent=$8,
    description=$9,product_link=$10,manual_buyers=$11,is_active=$12 WHERE id=$13 RETURNING id`,
    [
      d.name,
      slug,
      d.categories,
      d.status,
      d.thumbnail_url,
      d.gallery,
      d.price,
      d.discount,
      d.description,
      d.link,
      d.manual_buyers,
      d.active,
      id,
    ],
  );
  if (!r.length) bad("Tidak ditemukan", 404);
  audit("product_update", req, { admin: req.admin.u, id });
  res.json({ ok: true });
});
admin.delete("/products/:id", async (req, res) => {
  try {
    await q("DELETE FROM products WHERE id=$1", [req.params.id]);
    audit("product_delete", req, { admin: req.admin.u, id: req.params.id });
    res.json({ ok: true });
  } catch (e) {
    if (e.code === "23503")
      bad("Produk punya riwayat order, nonaktifkan saja", 409);
    throw e;
  }
});

const orderSql = `SELECT o.*, p.product_link, p.thumbnail_url, pm.bank_name FROM orders o
  LEFT JOIN products p ON p.id=o.product_id LEFT JOIN payment_methods pm ON pm.id=o.payment_method_id`;
const shapeOrder = (o) => {
  const text =
    o.status === "accepted"
      ? `Halo ${o.buyer_name}, pembayaran order #${o.id} untuk ${o.product_name} (${rp(o.price_paid)}) sudah kami terima.\nAkses produk: ${o.product_link}`
      : `Halo ${o.buyer_name}, terkait order #${o.id} ${o.product_name} (${rp(o.price_paid)}) status: ${o.status}.`;
  return {
    ...o,
    price_paid: Number(o.price_paid),
    checksum_ok: checksumOk(o),
    wa_url: `https://wa.me/${o.whatsapp}?text=${encodeURIComponent(text)}`,
    product_link: undefined,
  };
};
admin.get("/orders", async (req, res) => {
  const { limit, page, offset } = pg(req),
    st = ["pending", "accepted", "rejected"].includes(req.query.status)
      ? req.query.status
      : null;
  const [{ n }] = await q(
    "SELECT COUNT(*)::int AS n FROM orders WHERE ($1::text IS NULL OR status=$1)",
    [st],
  );
  const rows = await q(
    orderSql +
      ` WHERE ($1::text IS NULL OR o.status=$1) ORDER BY o.created_at DESC, o.id DESC LIMIT ${limit} OFFSET ${offset}`,
    [st],
  );
  res.json({
    items: rows.map(shapeOrder),
    total: n,
    page,
    pages: pages(n, limit),
  });
});
admin.get("/orders/:id", async (req, res) => {
  const [o] = await q(orderSql + " WHERE o.id=$1", [req.params.id]);
  o ? res.json(shapeOrder(o)) : bad("Tidak ditemukan", 404);
});
admin.patch("/orders/:id/status", async (req, res) => {
  const st = req.body.status;
  if (!["accepted", "rejected"].includes(st)) bad("Status tidak valid");
  const [o] = await q(
    "SELECT id,product_id,price_paid,checksum,status FROM orders WHERE id=$1",
    [req.params.id],
  );
  if (!o) bad("Order tidak ditemukan", 404);
  if (o.status !== "pending") bad(`Order sudah berstatus ${o.status}`, 409);
  if (st === "accepted" && !checksumOk(o)) {
    audit("order_checksum_mismatch", req, { admin: req.admin.u, order: o.id });
    bad("Checksum order tidak cocok, order tidak bisa diterima", 409);
  }
  const r = await q(
    "UPDATE orders SET status=$1 WHERE id=$2 AND status='pending' RETURNING id",
    [st, o.id],
  );
  if (!r.length) bad("Status order sudah berubah", 409);
  audit("order_status", req, { admin: req.admin.u, order: o.id, to: st });
  res.json({ ok: true });
});
admin.delete("/orders/:id", async (req, res) => {
  const r = await q("DELETE FROM orders WHERE id=$1 RETURNING id", [req.params.id]);
  if (!r.length) bad("Order tidak ditemukan", 404);
  audit("order_delete", req, { admin: req.admin.u, id: req.params.id });
  res.json({ ok: true });
});

const pmBody = (b) => {
  const v = ["bank_name", "account_number", "account_holder"].map((k) =>
    String(b[k] || "").trim(),
  );
  if (v.some((x) => !x || x.length > 80)) bad("Semua field wajib diisi");
  return v;
};
admin.get("/payment-methods", async (req, res) =>
  res.json(await q("SELECT * FROM payment_methods ORDER BY id")),
);
admin.post("/payment-methods", async (req, res) => {
  const v = pmBody(req.body);
  await q(
    "INSERT INTO payment_methods(bank_name,account_number,account_holder) VALUES($1,$2,$3)",
    v,
  );
  audit("pm_create", req, { admin: req.admin.u, bank: v[0] });
  res.status(201).json({ ok: true });
});
admin.put("/payment-methods/:id", async (req, res) => {
  const r = await q(
    "UPDATE payment_methods SET bank_name=$1,account_number=$2,account_holder=$3 WHERE id=$4 RETURNING id",
    [...pmBody(req.body), req.params.id],
  );
  if (!r.length) bad("Tidak ditemukan", 404);
  audit("pm_update", req, { admin: req.admin.u, id: req.params.id });
  res.json({ ok: true });
});
admin.delete("/payment-methods/:id", async (req, res) => {
  await q("DELETE FROM payment_methods WHERE id=$1", [req.params.id]);
  audit("pm_delete", req, { admin: req.admin.u, id: req.params.id });
  res.json({ ok: true });
});

const tBody = (b) =>
  [
    ["customer_name", 80],
    ["origin", 80],
    ["description", 500],
  ].map(([k, m]) => {
    const v = String(b[k] || "").trim();
    if (!v || v.length > m) bad(`${k} wajib diisi (maks ${m} karakter)`);
    return v;
  });
admin.get("/testimonials", async (req, res) => {
  const { limit, page, offset } = pg(req);
  const [{ n }] = await q("SELECT COUNT(*)::int AS n FROM testimonials");
  const items = await q(
    `SELECT * FROM testimonials ORDER BY created_at DESC, id DESC LIMIT ${limit} OFFSET ${offset}`,
  );
  res.json({ items, total: n, page, pages: pages(n, limit) });
});
admin.post("/testimonials", async (req, res) => {
  await q(
    "INSERT INTO testimonials(customer_name,origin,description) VALUES($1,$2,$3)",
    tBody(req.body),
  );
  res.status(201).json({ ok: true });
});
admin.put("/testimonials/:id", async (req, res) => {
  await q(
    "UPDATE testimonials SET customer_name=$1,origin=$2,description=$3 WHERE id=$4",
    [...tBody(req.body), req.params.id],
  );
  res.json({ ok: true });
});
admin.delete("/testimonials/:id", async (req, res) => {
  await q("DELETE FROM testimonials WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

admin.get("/stats", async (req, res) => {
  const [t] =
    await q(`SELECT COALESCE(SUM(price_paid) FILTER (WHERE status='accepted'),0)::float8 AS omzet,
    COUNT(DISTINCT whatsapp) FILTER (WHERE status='accepted')::int AS buyers, (SELECT COUNT(*) FROM products)::int AS products FROM orders`);
  const series = (unit, span) =>
    q(`SELECT to_char(date_trunc('${unit}', created_at AT TIME ZONE '${TZ}'),'YYYY-MM-DD') AS label,
    SUM(price_paid)::float8 AS omzet, COUNT(*)::int AS orders FROM orders
    WHERE status='accepted' AND created_at > now() - interval '${span}' GROUP BY 1 ORDER BY 1`);
  const [daily, weekly, monthly] = await Promise.all([
    series("day", "30 days"),
    series("week", "12 weeks"),
    series("month", "12 months"),
  ]);
  res.json({ ...t, daily, weekly, monthly });
});

app.use("/api", (req, res) => res.status(404).json({ error: "Not found" }));
app.use((req, res) => res.status(404).send("Halaman tidak ditemukan"));
app.use((e, req, res, next) => {
  if (res.headersSent) return next(e);
  let status = 500,
    msg = "Terjadi kesalahan server";
  if (e.expose) {
    status = e.status;
    msg = e.message; 
  } else if (e.type === "entity.too.large") {
    status = 413;
    msg = "Data terlalu besar";
  } else if (e.type === "entity.parse.failed") {
    status = 400;
    msg = "Format JSON tidak valid";
  } else if (Number.isInteger(e.status) && e.status >= 400 && e.status < 500) {
    status = e.status;
    msg = "Permintaan tidak valid"; 
  }
  if (status >= 500) console.error(e);
  res.status(status).json({ error: msg });
});

module.exports = app;
if (require.main === module)
  app.listen(PORT, () => console.log("Running on http://localhost:" + PORT));