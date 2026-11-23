'use strict';
const express = require('express');
const { query, one } = require('../config/db');
const { requireAdmin } = require('../middleware/security');
const { str, toId, likePattern } = require('../utils/validate');
const { audit } = require('../services/audit');

const router = express.Router();
router.use(requireAdmin);


const SECURITY_EVENTS = [
  'LOGIN_SUCCESS', 'LOGIN_FAILED', 'ACCOUNT_LOCKED', 'LOGIN_BLOCKED_LOCKED', 'NEW_DEVICE_LOGIN',
  'OTP_SENT', 'PASSWORD_RESET_REQUESTED', 'PASSWORD_RESET_DONE', 'PASSWORD_CHANGED', 'CSRF_BLOCKED',
  'RATE_LIMITED', 'ACCESS_DENIED', 'TOTP_ENABLED', 'TOTP_DISABLED', 'REGISTER', 'ADMIN_ACTION', 'SEARCH',
];

/* ----------------------------- overview --------------------------- */
router.get('/', async (req, res, next) => {
  try {
    const stats = await one(
      `SELECT (SELECT COUNT(*) FROM users) AS users,
              (SELECT COUNT(*) FROM users WHERE lock_until > UTC_TIMESTAMP()) AS locked,
              (SELECT COUNT(*) FROM users WHERE totp_enabled = 1) AS totp,
              (SELECT COUNT(*) FROM products WHERE is_active = 1) AS products,
              (SELECT COUNT(*) FROM orders) AS orders,
              (SELECT COALESCE(SUM(total), 0) FROM orders) AS revenue,
              (SELECT COUNT(*) FROM audit_logs WHERE event = 'LOGIN_FAILED' AND created_at > UTC_TIMESTAMP() - INTERVAL 1 DAY) AS failed24h,
              (SELECT COUNT(*) FROM audit_logs WHERE event IN ('CSRF_BLOCKED','RATE_LIMITED','ACCESS_DENIED') AND created_at > UTC_TIMESTAMP() - INTERVAL 1 DAY) AS blocked24h`
    );
    const events = await query(
      `SELECT event, username, ip, details, created_at FROM audit_logs
        WHERE event IN ('LOGIN_FAILED','ACCOUNT_LOCKED','NEW_DEVICE_LOGIN','CSRF_BLOCKED','RATE_LIMITED','ACCESS_DENIED','PASSWORD_RESET_DONE','LOGIN_BLOCKED_LOCKED')
        ORDER BY id DESC LIMIT 10`
    );
    const daily = await query(
      `SELECT DATE(created_at) AS day,
              SUM(event = 'LOGIN_SUCCESS') AS ok,
              SUM(event = 'LOGIN_FAILED') AS failed
         FROM audit_logs WHERE created_at > UTC_TIMESTAMP() - INTERVAL 7 DAY
        GROUP BY DATE(created_at) ORDER BY day`
    );
    res.render('admin/index', { title: 'Admin dashboard', stats, events, daily });
  } catch (err) { next(err); }
});

/* ------------------------------ users ----------------------------- */
router.get('/users', async (req, res, next) => {
  try {
    const q = str(req.query.q, 100);
    const params = [];
    let where = '1=1';
    if (q) {
      where = '(username LIKE ? OR email LIKE ?)';
      params.push(likePattern(q), likePattern(q));
    }
    const users = await query(
      `SELECT id, username, email, phone, role, is_active, totp_enabled, failed_attempts, lock_until, last_login_at, last_login_ip, created_at
         FROM users WHERE ${where} ORDER BY id DESC LIMIT 100`,
      params
    );
    res.render('admin/users', { title: 'Users', users, q, now: new Date() });
  } catch (err) { next(err); }
});

const USER_ACTIONS = {
  unlock: { sql: 'UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE id = ?', msg: 'Account unlocked.' },
  disable: { sql: 'UPDATE users SET is_active = 0, session_version = session_version + 1 WHERE id = ?', msg: 'Account disabled and signed out.' },
  enable: { sql: 'UPDATE users SET is_active = 1 WHERE id = ?', msg: 'Account enabled.' },
  promote: { sql: "UPDATE users SET role = 'admin' WHERE id = ?", msg: 'User promoted to admin.' },
  demote: { sql: "UPDATE users SET role = 'user', session_version = session_version + 1 WHERE id = ?", msg: 'Admin role removed.' },
  logout: { sql: 'UPDATE users SET session_version = session_version + 1 WHERE id = ?', msg: 'All sessions of this user were revoked.' },
};

router.post('/users/:id/:action', async (req, res, next) => {
  try {
    const id = toId(req.params.id);
    const action = Object.hasOwn(USER_ACTIONS, req.params.action) ? USER_ACTIONS[req.params.action] : null;
    if (!id || !action) return res.status(400).render('error', { title: 'Bad request', status: 400, message: 'Unknown action.' });
    if (id === req.user.id) {
      req.flash('warning', 'You cannot change your own account from the admin panel.');
      return res.redirect('/admin/users');
    }
    const target = await one('SELECT username FROM users WHERE id = ?', [id]);
    if (!target) return res.redirect('/admin/users');
    await query(action.sql, [id]);
    await audit(req, 'ADMIN_ACTION', { userId: req.user.id, username: req.user.username, details: `${req.params.action} user ${target.username} (#${id})` });
    req.flash('success', `${target.username}: ${action.msg}`);
    res.redirect('/admin/users');
  } catch (err) { next(err); }
});

/* ---------------------------- audit logs -------------------------- */
router.get('/logs', async (req, res, next) => {
  try {
    const q = str(req.query.q, 100);
    const event = SECURITY_EVENTS.includes(req.query.event) ? req.query.event : '';
    const where = ['1=1'];
    const params = [];
    if (q) {
      where.push('(username LIKE ? OR ip LIKE ? OR details LIKE ?)');
      params.push(likePattern(q), likePattern(q), likePattern(q));
    }
    if (event) {
      where.push('event = ?');
      params.push(event);
    }
    const logs = await query(
      `SELECT id, user_id, username, event, ip, user_agent, details, created_at FROM audit_logs
        WHERE ${where.join(' AND ')} ORDER BY id DESC LIMIT 200`,
      params
    );
    res.render('admin/logs', { title: 'Security logs', logs, q, event, events: SECURITY_EVENTS });
  } catch (err) { next(err); }
});

/* ----------------------------- products --------------------------- */
router.get('/products', async (req, res, next) => {
  try {
    const q = str(req.query.q, 100);
    const params = [];
    let where = 'p.is_active = 1';
    if (q) {
      where += ' AND (p.title LIKE ? OR u.username LIKE ?)';
      params.push(likePattern(q), likePattern(q));
    }
    const products = await query(
      `SELECT p.id, p.title, p.price, p.stock, p.category, p.created_at, u.username AS seller
         FROM products p JOIN users u ON u.id = p.seller_id WHERE ${where} ORDER BY p.id DESC LIMIT 200`,
      params
    );
    res.render('admin/products', { title: 'Products', products, q });
  } catch (err) { next(err); }
});

module.exports = router;
