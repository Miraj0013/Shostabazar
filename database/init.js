'use strict';
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const config = require('../src/config');
const { pool, query, one } = require('../src/config/db');
const { passwordProblems } = require('../src/utils/validate');

/** Wait for MySQL (useful in Docker where the DB container starts slower). */
async function waitForDb(retries = config.db.connectRetries) {
  for (let i = 1; i <= retries; i++) {
    try {
      await query('SELECT 1');
      return;
    } catch (err) {
      if (i === retries) throw err;
      console.log(`[db] waiting for MySQL (${err.code || err.message}) ... ${i}/${retries}`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
}

/** Apply schema.sql (idempotent: CREATE TABLE IF NOT EXISTS). */
async function applySchema() {
  const sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  const statements = sql
    .split(/;\s*$/m)
    .map((s) => s.replace(/^\s*--.*$/gm, '').trim())
    .filter(Boolean);
  for (const stmt of statements) await query(stmt);
}

const DEMO_PRODUCTS = [
  ['Walton Primo Smartphone 128GB', 'Brand new, sealed box. 6.5" display, 5000mAh battery, 1 year official warranty.', 'Electronics', 18999, 5],
  ['Mechanical Keyboard (Blue Switch)', 'RGB backlit mechanical keyboard, full size, USB-C cable included.', 'Electronics', 3450, 8],
  ['Handloom Cotton Saree', 'Traditional Tangail handloom cotton saree, soft and breathable, perfect for summer.', 'Fashion', 2200, 12],
  ['Men\'s Panjabi - Eid Collection', 'Premium cotton panjabi with embroidered collar. Sizes M, L, XL.', 'Fashion', 1850, 20],
  ['Non-stick Frying Pan 26cm', 'Granite-coated non-stick pan, induction compatible, PFOA free.', 'Home', 1290, 15],
  ['Clean Code (Paperback)', 'Robert C. Martin - a handbook of agile software craftsmanship. Lightly used.', 'Books', 650, 3],
  ['The Web Application Hacker\'s Handbook', 'Classic book on finding and exploiting security flaws. Great for this course!', 'Books', 900, 2],
  ['Cricket Bat - English Willow', 'Grade 2 English willow, full size, comes with cover.', 'Sports', 7500, 4],
  ['Chinigura Aromatic Rice 5kg', 'Fresh premium chinigura rice from Dinajpur.', 'Grocery', 850, 30],
  ['USB Security Key (FIDO2)', 'Hardware security key for phishing-resistant two-factor authentication.', 'Electronics', 4200, 10],
];

async function seed() {
  const { username, email, password } = config.admin;
  let adminId = null;
  if (username && email && password) {
    const existing = await one('SELECT id FROM users WHERE username = ? OR email = ?', [username, email.toLowerCase()]);
    if (existing) {
      adminId = existing.id;
    } else {
      const problems = passwordProblems(password, { username, email });
      if (problems.length) {
        console.warn(`[seed] ADMIN_PASSWORD is too weak, admin not created: ${problems.join(' ')}`);
      } else {
        const hash = await bcrypt.hash(password, config.security.bcryptRounds);
        const r = await query(
          "INSERT INTO users (username, email, password_hash, role, password_changed_at) VALUES (?, ?, ?, 'admin', CURRENT_TIMESTAMP)",
          [username, email.toLowerCase(), hash]
        );
        adminId = r.insertId;
        console.log(`[seed] admin account "${username}" created`);
      }
    }
  } else {
    console.warn('[seed] ADMIN_USERNAME / ADMIN_EMAIL / ADMIN_PASSWORD not set - no admin created.');
  }

  if (config.seedDemoData && adminId) {
    const { n } = await one('SELECT COUNT(*) AS n FROM products');
    if (n === 0) {
      for (const [title, description, category, price, stock] of DEMO_PRODUCTS) {
        await query('INSERT INTO products (seller_id, title, description, category, price, stock) VALUES (?, ?, ?, ?, ?, ?)', [adminId, title, description, category, price, stock]);
      }
      console.log(`[seed] ${DEMO_PRODUCTS.length} demo products added`);
    }
  }
}

async function initDatabase() {
  await waitForDb();
  await applySchema();
  await seed();
}

module.exports = { initDatabase };

if (require.main === module) {
  initDatabase()
    .then(() => { console.log('[db] ready'); return pool.end(); })
    .catch((err) => { console.error('[db] init failed:', err.message); process.exit(1); });
}
