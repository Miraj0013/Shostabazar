'use strict';
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const config = require('../config');
const { one } = require('../config/db');
const { randomToken, safeEqual } = require('../utils/crypto');
const { audit } = require('../services/audit');

/* ------------------------------------------------------------------ *
 * HTTP security headers (Helmet)
 *  - Content-Security-Policy: only our own scripts/styles may run -> blocks injected XSS
 *  - X-Frame-Options / frame-ancestors: clickjacking protection
 *  - X-Content-Type-Options, Referrer-Policy, HSTS (when served over HTTPS)
 * ------------------------------------------------------------------ */
const securityHeaders = helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      ...(config.cookieSecure ? { upgradeInsecureRequests: [] } : {}),
    },
  },
  hsts: config.cookieSecure ? { maxAge: 31536000, includeSubDomains: true } : false,
  referrerPolicy: { policy: 'same-origin' },
  crossOriginEmbedderPolicy: false,
});

/* ------------------------------------------------------------------ *
 * CSRF protection (synchronizer token pattern)
 * A random per-session token is embedded in every form; any state-changing
 * request without the matching token is rejected. SameSite=Strict cookies add
 * a second layer.
 * ------------------------------------------------------------------ */
function csrfToken(req, res, next) {
  if (!req.session.csrfToken) req.session.csrfToken = randomToken(32);
  res.locals.csrfToken = req.session.csrfToken;
  next();
}

async function csrfProtect(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const sent = (req.body && req.body._csrf) || req.get('x-csrf-token');
  const expected = req.session && req.session.csrfToken;
  if (typeof sent === 'string' && expected && safeEqual(sent, expected)) return next();
  await audit(req, 'CSRF_BLOCKED', { userId: req.session?.userId || null, details: `${req.method} ${req.originalUrl}` });
  return res.status(403).render('error', {
    title: 'Request blocked',
    status: 403,
    message: 'Your form expired or the request did not come from ShostaBazar (CSRF protection). Please go back, reload the page and try again.',
  });
}

/* ------------------------------------------------------------------ *
 * Flash messages (one-time notices shown after a redirect)
 * ------------------------------------------------------------------ */
function flash(req, res, next) {
  req.flash = (type, message) => { req.session.flash = { type, message }; };
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
}

/* ------------------------------------------------------------------ *
 * Session validation: loads the signed-in user on each request and enforces
 *  - absolute session lifetime (idle timeout is handled by the rolling cookie)
 *  - disabled accounts are kicked out immediately
 *  - session_version: changing/resetting the password logs out all other sessions
 * ------------------------------------------------------------------ */
async function loadUser(req, res, next) {
  if (!req.session.userId) return next();
  try {
    const user = await one(
      'SELECT id, username, email, phone, role, is_active, totp_enabled, session_version FROM users WHERE id = ?',
      [req.session.userId]
    );
    const tooOld = Date.now() - (req.session.loginAt || 0) > config.security.absoluteTimeoutHours * 3600 * 1000;
    if (!user || !user.is_active || user.session_version !== req.session.sessionVersion || tooOld) {
      const reason = !user || !user.is_active ? 'Your account is not available.' : 'Your session has ended. Please sign in again.';
      return req.session.regenerate(() => {
        req.session.flash = { type: 'warning', message: reason };
        res.redirect('/login');
      });
    }
    req.user = user;
    res.locals.currentUser = user;
    next();
  } catch (err) {
    next(err);
  }
}

function requireAuth(req, res, next) {
  if (req.user) return next();
  req.session.returnTo = req.method === 'GET' && req.originalUrl.startsWith('/') && !req.originalUrl.startsWith('//') ? req.originalUrl : undefined;
  req.flash('info', 'Please sign in to continue.');
  return res.redirect('/login');
}

/** Role-based access control: admin pages. */
async function requireAdmin(req, res, next) {
  if (!req.user) return requireAuth(req, res, next);
  if (req.user.role === 'admin') return next();
  await audit(req, 'ACCESS_DENIED', { userId: req.user.id, username: req.user.username, details: req.originalUrl });
  return res.status(403).render('error', { title: 'Forbidden', status: 403, message: 'You do not have permission to view this page.' });
}

function guestOnly(req, res, next) {
  if (req.user) return res.redirect(req.user.role === 'admin' ? '/admin' : '/dashboard');
  next();
}

/** Authenticated pages must not be cached (back button after logout shows nothing). */
function noCache(req, res, next) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  next();
}

/* ------------------------------------------------------------------ *
 * Rate limiting (brute force / credential stuffing / spam protection)
 * ------------------------------------------------------------------ */
function limiter(windowMinutes, limit, message) {
  return rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    handler: async (req, res) => {
      await audit(req, 'RATE_LIMITED', { details: `${req.method} ${req.originalUrl}` });
      res.status(429).render('error', { title: 'Too many requests', status: 429, message });
    },
  });
}

const limiters = {
  global: limiter(15, 600, 'Too many requests from your network. Please slow down.'),
  login: limiter(15, 20, 'Too many login attempts from your network. Try again in 15 minutes.'),
  otp: limiter(15, 20, 'Too many verification attempts. Try again in 15 minutes.'),
  register: limiter(60, 10, 'Too many accounts created from your network. Try again later.'),
  forgot: limiter(60, 5, 'Too many password reset requests. Try again in an hour.'),
};

module.exports = {
  securityHeaders, csrfToken, csrfProtect, flash, loadUser,
  requireAuth, requireAdmin, guestOnly, noCache, limiters,
};
