'use strict';
const express = require('express');
const { pool, query, one } = require('../config/db');
const { requireAuth } = require('../middleware/security');
const { str, toId, likePattern } = require('../utils/validate');
const { audit } = require('../services/audit');

const router = express.Router();

const CATEGORIES = ['Electronics', 'Fashion', 'Home', 'Books', 'Sports', 'Grocery', 'Other'];

// ORDER BY cannot use placeholders, so we map user input onto a fixed whitelist
// instead of ever putting it into the SQL string (SQL injection defence).
const SORTS = {
  newest: 'p.created_at DESC',
  price_asc: 'p.price ASC',
  price_desc: 'p.price DESC',
  title: 'p.title ASC',
};
const PAGE_SIZE = 12;


router.get('/', async (req, res, next) => {
  try {
    if (req.user) return res.redirect(req.user.role === 'admin' ? '/admin' : '/dashboard');
    const featured = await query(
      `SELECT p.id, p.title, p.price, p.category FROM products p
        WHERE p.is_active = 1 AND p.stock > 0 ORDER BY p.created_at DESC LIMIT 4`
    );
    res.render('index', { title: 'A Secure Online Marketplace', featured });
  } catch (err) { next(err); }
});

/* ---------------------- dashboard + search ------------------------ */
router.get('/dashboard', requireAuth, async (req, res, next) => {
  try {
    const q = str(req.query.q, 100);
    const category = CATEGORIES.includes(req.query.category) ? req.query.category : '';
    const sort = Object.hasOwn(SORTS, req.query.sort) ? req.query.sort : 'newest';
    const page = Math.min(Math.max(parseInt(req.query.page, 10) || 1, 1), 1000);

    const where = ['p.is_active = 1'];
    const params = [];
    if (q) {
      where.push('(p.title LIKE ? OR p.description LIKE ?)');
      params.push(likePattern(q), likePattern(q));
    }
    if (category) {
      where.push('p.category = ?');
      params.push(category);
    }
    const whereSql = where.join(' AND ');

    const [{ total }] = await query(`SELECT COUNT(*) AS total FROM products p WHERE ${whereSql}`, params);
    const products = await query(
      `SELECT p.id, p.title, p.price, p.category, p.stock, u.username AS seller
         FROM products p JOIN users u ON u.id = p.seller_id
        WHERE ${whereSql}
        ORDER BY ${SORTS[sort]}
        LIMIT ? OFFSET ?`,
      [...params, PAGE_SIZE, (page - 1) * PAGE_SIZE]
    );
    const stats = await one(
      `SELECT (SELECT COUNT(*) FROM products WHERE seller_id = ? AND is_active = 1) AS listings,
              (SELECT COUNT(*) FROM orders WHERE buyer_id = ?) AS orders`,
      [req.user.id, req.user.id]
    );
    if (q) await audit(req, 'SEARCH', { userId: req.user.id, username: req.user.username, details: q });

    res.render('market/dashboard', {
      title: 'Marketplace', products, q, category, sort, page, categories: CATEGORIES, stats,
      total, pages: Math.max(1, Math.ceil(total / PAGE_SIZE)),
    });
  } catch (err) { next(err); }
});

/* --------------------------- sell an item ------------------------- */
function readProduct(body) {
  const values = {
    title: str(body.title, 120),
    description: str(body.description, 2000),
    category: str(body.category, 40),
    price: str(body.price, 12),
    stock: str(body.stock, 6),
  };
  const errors = [];
  if (values.title.length < 3) errors.push('Title must be 3-120 characters.');
  if (values.description.length < 10) errors.push('Description must be 10-2000 characters.');
  if (!CATEGORIES.includes(values.category)) errors.push('Choose a valid category.');
  if (!/^\d{1,7}(\.\d{1,2})?$/.test(values.price) || Number(values.price) <= 0) errors.push('Price must be a positive amount (max 2 decimals).');
  if (!/^\d{1,5}$/.test(values.stock) || Number(values.stock) < 1) errors.push('Stock must be a whole number between 1 and 99999.');
  return { values, errors };
}

router.get('/products/new', requireAuth, (req, res) => {
  res.render('market/new', { title: 'Sell an item', values: { stock: '1' }, errors: [], categories: CATEGORIES });
});

router.post('/products', requireAuth, async (req, res, next) => {
  try {
    const { values, errors } = readProduct(req.body);
    if (errors.length) return res.status(400).render('market/new', { title: 'Sell an item', values, errors, categories: CATEGORIES });
    const result = await query(
      'INSERT INTO products (seller_id, title, description, category, price, stock) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, values.title, values.description, values.category, values.price, values.stock]
    );
    await audit(req, 'PRODUCT_CREATED', { userId: req.user.id, username: req.user.username, details: `product ${result.insertId}` });
    req.flash('success', 'Your item is now listed.');
    res.redirect(`/products/${result.insertId}`);
  } catch (err) { next(err); }
});

/* --------------------------- product page ------------------------- */
router.get('/products/:id', requireAuth, async (req, res, next) => {
  try {
    const id = toId(req.params.id);
    const product = id && await one(
      `SELECT p.*, u.username AS seller FROM products p JOIN users u ON u.id = p.seller_id
        WHERE p.id = ? AND (p.is_active = 1 OR p.seller_id = ?)`,
      [id, req.user.id]
    );
    if (!product) return res.status(404).render('error', { title: 'Not found', status: 404, message: 'That product does not exist.' });
    res.render('market/product', { title: product.title, product });
  } catch (err) { next(err); }
});

/* -------------------------------- buy ----------------------------- */
router.post('/products/:id/buy', requireAuth, async (req, res, next) => {
  const id = toId(req.params.id);
  const qty = toId(String(req.body.quantity || ''));
  if (!id) return res.redirect('/dashboard');
  if (!qty || qty > 100) {
    req.flash('danger', 'Quantity must be between 1 and 100.');
    return res.redirect(`/products/${id}`);
  }
  const conn = await pool.getConnection();
  try {
    // Transaction + row lock prevents two buyers taking the last item (race condition).
    await conn.beginTransaction();
    const [[product]] = await conn.query('SELECT id, seller_id, price, stock, is_active FROM products WHERE id = ? FOR UPDATE', [id]);
    let error = null;
    if (!product || !product.is_active) error = 'This product is no longer available.';
    else if (product.seller_id === req.user.id) error = 'You cannot buy your own item.';
    else if (product.stock < qty) error = `Only ${product.stock} left in stock.`;
    if (error) {
      await conn.rollback();
      req.flash('danger', error);
      return res.redirect(`/products/${id}`);
    }
    // Price comes from the database, never from the form (prevents price tampering).
    const total = (Number(product.price) * qty).toFixed(2);
    await conn.query('UPDATE products SET stock = stock - ? WHERE id = ?', [qty, id]);
    await conn.query('INSERT INTO orders (buyer_id, product_id, quantity, unit_price, total) VALUES (?, ?, ?, ?, ?)', [req.user.id, id, qty, product.price, total]);
    await conn.commit();
    await audit(req, 'ORDER_PLACED', { userId: req.user.id, username: req.user.username, details: `product ${id} x${qty} = ${total}` });
    req.flash('success', `Order placed! Total: ৳${total}`);
    res.redirect('/orders');
  } catch (err) {
    await conn.rollback().catch(() => {});
    next(err);
  } finally {
    conn.release();
  }
});

/* ------------------------------ delete ---------------------------- */
router.post('/products/:id/delete', requireAuth, async (req, res, next) => {
  try {
    const id = toId(req.params.id);
    const product = id && await one('SELECT id, seller_id, title FROM products WHERE id = ?', [id]);
    // Authorisation check (prevents IDOR): only the seller or an admin may delete.
    if (!product || (product.seller_id !== req.user.id && req.user.role !== 'admin')) {
      await audit(req, 'ACCESS_DENIED', { userId: req.user.id, username: req.user.username, details: `delete product ${req.params.id}` });
      return res.status(403).render('error', { title: 'Forbidden', status: 403, message: 'You can only remove your own listings.' });
    }
    await query('UPDATE products SET is_active = 0 WHERE id = ?', [id]);
    await audit(req, 'PRODUCT_REMOVED', { userId: req.user.id, username: req.user.username, details: `product ${id}` });
    req.flash('success', 'Listing removed.');
    res.redirect(req.user.role === 'admin' && product.seller_id !== req.user.id ? '/admin/products' : '/listings');
  } catch (err) { next(err); }
});

/* ------------------------ my listings / orders -------------------- */
router.get('/listings', requireAuth, async (req, res, next) => {
  try {
    const products = await query(
      'SELECT id, title, price, category, stock, is_active, created_at FROM products WHERE seller_id = ? ORDER BY created_at DESC',
      [req.user.id]
    );
    res.render('market/listings', { title: 'My listings', products });
  } catch (err) { next(err); }
});

router.get('/orders', requireAuth, async (req, res, next) => {
  try {
    const orders = await query(
      `SELECT o.id, o.quantity, o.total, o.status, o.created_at, p.id AS product_id, p.title, u.username AS seller
         FROM orders o JOIN products p ON p.id = o.product_id JOIN users u ON u.id = p.seller_id
        WHERE o.buyer_id = ? ORDER BY o.created_at DESC`,
      [req.user.id]
    );
    res.render('market/orders', { title: 'My orders', orders });
  } catch (err) { next(err); }
});

module.exports = router;
