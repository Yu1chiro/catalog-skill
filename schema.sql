CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  categories TEXT[] NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'terbaru' CHECK (status IN ('terbaru','terlama')),
  thumbnail_url TEXT NOT NULL,
  gallery TEXT[] NOT NULL DEFAULT '{}',
  price BIGINT NOT NULL CHECK (price > 0),
  discount_percent INT NOT NULL DEFAULT 0 CHECK (discount_percent BETWEEN 0 AND 100),
  description TEXT NOT NULL DEFAULT '',
  product_link TEXT NOT NULL DEFAULT '',
  manual_buyers INT NOT NULL DEFAULT 0,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS payment_methods (
  id SERIAL PRIMARY KEY,
  bank_name TEXT NOT NULL,
  account_number TEXT NOT NULL,
  account_holder TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY,
  product_id INT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
  product_name TEXT NOT NULL,
  price_paid BIGINT NOT NULL,            
  buyer_name TEXT NOT NULL,
  whatsapp TEXT NOT NULL,
  email TEXT,
  payment_method_id INT REFERENCES payment_methods(id) ON DELETE SET NULL,
  proof_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','rejected')),
  checksum TEXT,                          
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_orders_product_status ON orders(product_id, status);

CREATE TABLE IF NOT EXISTS admins (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,           
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS testimonials (
  id SERIAL PRIMARY KEY,
  customer_name TEXT NOT NULL,
  origin TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_products_active_created ON products(is_active, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_testimonials_created ON testimonials(created_at DESC);