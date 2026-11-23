'use strict';
const path = require('path');
const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const cookieParser = require('cookie-parser');

const config = require('./config');
const { pool } = require('./config/db');
const sec = require('./middleware/security');

// Project root. Works for `node server.js`, Docker and the Netlify function bundle
// (which keeps the same folder layout); falls back to the working directory.
const fs = require('fs');
const ROOT = [path.resolve(__dirname, '..'), process.cwd()].find((dir) => fs.existsSync(path.join(dir, 'views'))) || path.resolve(__dirname, '..');

const app = express();

// Register EJS explicitly (a static require) so serverless bundlers such as Netlify's
// include it; Express would otherwise load it with a dynamic require() at runtime.
app.engine('ejs', require('ejs').__express);
app.set('view engine', 'ejs');
app.set('views', path.join(ROOT, 'views'));
app.disable('x-powered-by'); // do not advertise the framework
if (config.trustProxy) app.set('trust proxy', config.trustProxy); // real client IP behind a reverse proxy

/* Template defaults + view helpers (set first so even early error pages render). */
const CATEGORY_ICONS = { Electronics: '💻', Fashion: '👕', Home: '🏠', Books: '📚', Sports: '🏏', Grocery: '🛒', Other: '📦' };
app.use((req, res, next) => {
  Object.assign(res.locals, {
    appName: config.appName,
    devMailbox: config.devMailbox,
    path: req.path,
    currentUser: null,
    csrfToken: '',
    idleTimeoutSeconds: config.security.idleTimeoutMinutes * 60,
    icon: (c) => CATEGORY_ICONS[c] || '📦',
    money: (n) => `৳${Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`,
  });
  next();
});

/* 1. Security headers (CSP, clickjacking, MIME sniffing, HSTS...) */
app.use(sec.securityHeaders);

/* 2. Static files */
app.use(express.static(path.join(ROOT, 'public'), { maxAge: config.isProd ? '7d' : 0 }));

/* 3. Global rate limit + small body size limit (DoS hardening) */
app.use(sec.limiters.global);
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser(config.sessionSecret));

/* 4. Server-side sessions stored in MySQL.
 *    httpOnly: JS cannot read the cookie (XSS cannot steal it)
 *    sameSite=strict: cookie is not sent on cross-site requests (CSRF)
 *    rolling + maxAge: idle timeout (auto sign-out after inactivity) */
const sessionStore = new MySQLStore({
  createDatabaseTable: true,
  clearExpired: true,
  checkExpirationInterval: 15 * 60 * 1000,
}, pool);

app.use(session({
  name: 'sb.sid',
  secret: config.sessionSecret,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: config.cookieSecure,
    maxAge: config.security.idleTimeoutMinutes * 60 * 1000,
  },
}));

/* 5. Per-request security middleware */
app.use(sec.flash);
app.use(sec.csrfToken);
app.use(sec.csrfProtect);
app.use(sec.loadUser);
app.use(sec.noCache);

/* 6. Routes */
app.use('/', require('./routes/auth'));
app.use('/', require('./routes/market'));
app.use('/account', require('./routes/account'));
app.use('/admin', require('./routes/admin'));
if (config.devMailbox) app.use('/dev', require('./routes/dev'));

/* 7. 404 + error handler (never leak stack traces to the browser) */
app.use((req, res) => {
  res.status(404).render('error', { title: 'Not found', status: 404, message: 'The page you are looking for does not exist.' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[error]', err);
  const status = err.status || err.statusCode || 500;
  const message = status < 500 && err.expose ? err.message : 'Something went wrong on our side. Please try again.';
  res.status(status).render('error', { title: 'Error', status, message });
});

module.exports = app;
