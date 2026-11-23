'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const totp = require('../utils/totp');
const config = require('../config');
const { query, one } = require('../config/db');
const { guestOnly, limiters } = require('../middleware/security');
const { str, isUsername, isEmail, isPhone, passwordProblems } = require('../utils/validate');
const { sha256, safeEqual, randomToken, decrypt } = require('../utils/crypto');
const { audit } = require('../services/audit');
const { sendEmail } = require('../services/notify');
const auth = require('../services/auth');

const router = express.Router();
const { security } = config;

// Compared against when the username does not exist, so a response takes the same
// time whether or not the account exists (prevents user enumeration via timing).
const DUMMY_HASH = bcrypt.hashSync('timing-attack-dummy-password', security.bcryptRounds);
const PENDING_2FA_MAX_AGE = 10 * 60 * 1000;

/* ============================ REGISTER ============================ */
router.get('/register', guestOnly, (req, res) => {
  res.render('auth/register', { title: 'Create account', values: {}, errors: [] });
});

router.post('/register', guestOnly, limiters.register, async (req, res, next) => {
  try {
    const values = {
      username: str(req.body.username, 30),
      email: str(req.body.email, 254).toLowerCase(),
      phone: str(req.body.phone, 20).replace(/[\s-]/g, ''),
    };
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const confirm = typeof req.body.confirm === 'string' ? req.body.confirm : '';

    const errors = [];
    if (!isUsername(values.username)) errors.push('Username must be 3-30 characters: letters, numbers or underscore.');
    if (!isEmail(values.email)) errors.push('Please enter a valid email address.');
    if (values.phone && !isPhone(values.phone)) errors.push('Phone must be 8-15 digits, optionally starting with +.');
    errors.push(...passwordProblems(password, values));
    if (password !== confirm) errors.push('Passwords do not match.');
    if (req.body.terms !== 'on') errors.push('You must accept the terms of use.');

    if (!errors.length) {
      const taken = await one('SELECT id FROM users WHERE username = ? OR email = ?', [values.username, values.email]);
      if (taken) errors.push('That username or email is already registered.');
    }
    if (errors.length) return res.status(400).render('auth/register', { title: 'Create account', values, errors });

    const hash = await bcrypt.hash(password, security.bcryptRounds);
    const result = await query(
      'INSERT INTO users (username, email, phone, password_hash, password_changed_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)',
      [values.username, values.email, values.phone || null, hash]
    );
    await audit(req, 'REGISTER', { userId: result.insertId, username: values.username });
    await sendEmail(values.email, 'Welcome to ShostaBazar', `Hi ${values.username},\n\nYour ShostaBazar account was created. Every sign-in is protected with a one-time verification code sent to this email.\n\nHappy shopping!`);

    req.flash('success', 'Account created! Sign in - we will email you a verification code.');
    res.redirect('/login');
  } catch (err) { next(err); }
});

/* ============================== LOGIN ============================= */
router.get('/login', guestOnly, (req, res) => {
  const notice = req.query.timeout ? 'You were signed out after a period of inactivity.' : null;
  res.render('auth/login', { title: 'Sign in', error: null, notice, username: '' });
});

router.post('/login', guestOnly, limiters.login, async (req, res, next) => {
  try {
    const identifier = str(req.body.username, 254);
    const password = typeof req.body.password === 'string' ? req.body.password.slice(0, 128) : '';
    const fail = (error, status = 401) =>
      res.status(status).render('auth/login', { title: 'Sign in', error, notice: null, username: identifier });

    if (!identifier || !password) return fail('Enter your username and password.', 400);

    // Parameterised query: input is sent separately from the SQL text, so
    // `' OR '1'='1` is just treated as a (non-existent) username.
    const user = await one('SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1', [identifier, identifier.toLowerCase()]);
    if (!user) {
      await bcrypt.compare(password, DUMMY_HASH);
      await audit(req, 'LOGIN_FAILED', { username: identifier, details: 'unknown user' });
      return fail('Invalid username or password.');
    }

    const lockedFor = auth.lockRemainingMinutes(user);
    if (lockedFor > 0) {
      await audit(req, 'LOGIN_BLOCKED_LOCKED', { userId: user.id, username: user.username });
      return fail(`Too many failed attempts. This account is locked - try again in ${lockedFor} minute(s) or reset your password.`, 423);
    }
    if (!user.is_active) {
      await bcrypt.compare(password, DUMMY_HASH);
      await audit(req, 'LOGIN_BLOCKED_DISABLED', { userId: user.id, username: user.username });
      return fail('This account has been disabled. Please contact support.', 403);
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      const { locked, remaining } = await auth.registerFailure(req, user, 'wrong password');
      if (locked) return fail(`Too many failed attempts. Your account is locked for ${security.lockMinutes} minutes. We emailed you about it.`, 423);
      return fail(`Invalid username or password. ${remaining} attempt(s) left before the account is locked.`);
    }

    // Password OK -> step 2: second factor. The user is NOT signed in yet.
    const returnTo = req.session.returnTo;
    await auth.regenerateSession(req);
    req.session.returnTo = returnTo;
    req.session.pending2fa = { userId: user.id, method: user.totp_enabled ? 'totp' : 'email', at: Date.now(), lastSent: Date.now() };
    if (!user.totp_enabled) await auth.issueLoginOtp(req, user);
    else await audit(req, 'PASSWORD_OK_TOTP_REQUIRED', { userId: user.id, username: user.username });
    res.redirect('/verify-2fa');
  } catch (err) { next(err); }
});

/* ======================= TWO-FACTOR AUTH ========================== */
function getPending(req) {
  const p = req.session.pending2fa;
  if (!p || Date.now() - p.at > PENDING_2FA_MAX_AGE) return null;
  return p;
}

function maskEmail(email) {
  const [local, domain] = email.split('@');
  return `${local.slice(0, 2)}${'*'.repeat(Math.max(1, local.length - 2))}@${domain}`;
}

router.get('/verify-2fa', guestOnly, async (req, res, next) => {
  try {
    const pending = getPending(req);
    if (!pending) {
      delete req.session.pending2fa;
      req.flash('warning', 'Your verification session expired. Please sign in again.');
      return res.redirect('/login');
    }
    const user = await one('SELECT email, phone FROM users WHERE id = ?', [pending.userId]);
    res.render('auth/verify-2fa', {
      title: 'Verify sign-in', error: null, method: pending.method,
      destination: user ? maskEmail(user.email) : '', hasPhone: !!(user && user.phone),
    });
  } catch (err) { next(err); }
});

router.post('/verify-2fa', guestOnly, limiters.otp, async (req, res, next) => {
  try {
    const pending = getPending(req);
    if (!pending) {
      delete req.session.pending2fa;
      req.flash('warning', 'Your verification session expired. Please sign in again.');
      return res.redirect('/login');
    }
    const user = await one('SELECT * FROM users WHERE id = ?', [pending.userId]);
    if (!user || !user.is_active || auth.lockRemainingMinutes(user) > 0) {
      delete req.session.pending2fa;
      req.flash('danger', 'This account cannot sign in right now.');
      return res.redirect('/login');
    }

    const code = str(req.body.code, 10).replace(/\s/g, '');
    const render = (error) => res.status(401).render('auth/verify-2fa', {
      title: 'Verify sign-in', error, method: pending.method, destination: maskEmail(user.email), hasPhone: !!user.phone,
    });

    let ok = false;
    if (/^\d{6}$/.test(code)) {
      if (pending.method === 'totp' && user.totp_secret) {
        const result = await totp.verify({
          secret: decrypt(user.totp_secret), token: code, epochTolerance: 30,
          afterTimeStep: user.totp_last_step ?? undefined, // a code can be used only once
        });
        if (result.valid) {
          ok = true;
          await query('UPDATE users SET totp_last_step = ? WHERE id = ?', [result.timeStep, user.id]);
        }
      } else {
        const otp = await one(
          'SELECT * FROM otp_codes WHERE user_id = ? AND purpose = ? AND used_at IS NULL ORDER BY id DESC LIMIT 1',
          [user.id, 'login']
        );
        if (otp && new Date(otp.expires_at) > new Date() && otp.attempts < security.otpMaxAttempts) {
          ok = safeEqual(sha256(code), otp.code_hash);
          if (ok) await query('UPDATE otp_codes SET used_at = CURRENT_TIMESTAMP WHERE id = ?', [otp.id]);
          else await query('UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?', [otp.id]);
        } else if (otp) {
          return render('This code has expired. Click "Resend code" to get a new one.');
        }
      }
    }

    if (!ok) {
      const { locked, remaining } = await auth.registerFailure(req, user, 'wrong 2FA code');
      if (locked) {
        delete req.session.pending2fa;
        req.flash('danger', `Too many failed attempts. Your account is locked for ${security.lockMinutes} minutes.`);
        return res.redirect('/login');
      }
      return render(`Incorrect verification code. ${remaining} attempt(s) left.`);
    }

    delete req.session.pending2fa;
    await auth.completeLogin(req, res, user);
  } catch (err) { next(err); }
});

router.post('/verify-2fa/resend', guestOnly, limiters.otp, async (req, res, next) => {
  try {
    const pending = getPending(req);
    if (!pending || pending.method !== 'email') return res.redirect('/login');
    if (Date.now() - pending.lastSent < 60 * 1000) {
      req.flash('warning', 'Please wait a minute before requesting another code.');
      return res.redirect('/verify-2fa');
    }
    const user = await one('SELECT * FROM users WHERE id = ?', [pending.userId]);
    if (!user) return res.redirect('/login');
    await auth.issueLoginOtp(req, user);
    pending.lastSent = Date.now();
    req.flash('success', 'A new code was sent.');
    res.redirect('/verify-2fa');
  } catch (err) { next(err); }
});

/* ============================= LOGOUT ============================= */
router.post('/logout', async (req, res, next) => {
  try {
    if (req.user) await audit(req, 'LOGOUT', { userId: req.user.id, username: req.user.username });
    req.session.destroy((err) => {
      if (err) return next(err);
      res.clearCookie('sb.sid');
      res.redirect('/login');
    });
  } catch (err) { next(err); }
});

/* ======================== PASSWORD RECOVERY ======================= */
router.get('/forgot', (req, res) => {
  res.render('auth/forgot', { title: 'Forgot password', sent: false, error: null });
});

router.post('/forgot', limiters.forgot, async (req, res, next) => {
  try {
    const email = str(req.body.email, 254).toLowerCase();
    if (!isEmail(email)) return res.status(400).render('auth/forgot', { title: 'Forgot password', sent: false, error: 'Please enter a valid email address.' });

    const user = await one('SELECT id, username, email, is_active FROM users WHERE email = ?', [email]);
    if (user && user.is_active) {
      const token = randomToken(32); // 256-bit secret, only its hash is stored
      await query('DELETE FROM password_resets WHERE user_id = ?', [user.id]);
      await query('INSERT INTO password_resets (user_id, token_hash, expires_at, request_ip) VALUES (?, ?, ?, ?)', [
        user.id, sha256(token), auth.minutesFromNow(security.resetTtlMinutes), req.ip,
      ]);
      await sendEmail(
        user.email,
        'Reset your ShostaBazar password',
        `Hi ${user.username},\n\nWe received a request to reset your password from IP ${req.ip}.\nThe link below works once and expires in ${security.resetTtlMinutes} minutes.`,
        { actionUrl: `${config.appUrl}/reset/${token}`, actionLabel: 'Reset my password' }
      );
      await audit(req, 'PASSWORD_RESET_REQUESTED', { userId: user.id, username: user.username });
    } else {
      await audit(req, 'PASSWORD_RESET_UNKNOWN_EMAIL', { username: email });
    }
    // Same response either way -> attackers cannot discover which emails are registered.
    res.render('auth/forgot', { title: 'Forgot password', sent: true, error: null });
  } catch (err) { next(err); }
});

async function findResetToken(token) {
  if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) return null;
  const row = await one(
    `SELECT pr.id, pr.user_id, pr.expires_at, u.username, u.email, u.password_hash
       FROM password_resets pr JOIN users u ON u.id = pr.user_id
      WHERE pr.token_hash = ? AND pr.used_at IS NULL`,
    [sha256(token)]
  );
  if (!row || new Date(row.expires_at) < new Date()) return null;
  return row;
}

const invalidLink = (res) => res.status(400).render('error', {
  title: 'Link invalid', status: 400, message: 'This password reset link is invalid, already used or expired. Please request a new one.',
});

router.get('/reset/:token', async (req, res, next) => {
  try {
    const row = await findResetToken(req.params.token);
    if (!row) return invalidLink(res);
    res.render('auth/reset', { title: 'Choose a new password', token: req.params.token, errors: [] });
  } catch (err) { next(err); }
});

router.post('/reset/:token', limiters.forgot, async (req, res, next) => {
  try {
    const row = await findResetToken(req.params.token);
    if (!row) return invalidLink(res);
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const errors = passwordProblems(password, { username: row.username, email: row.email });
    if (password !== req.body.confirm) errors.push('Passwords do not match.');
    if (!errors.length && (await bcrypt.compare(password, row.password_hash))) errors.push('New password must be different from the old one.');
    if (errors.length) return res.status(400).render('auth/reset', { title: 'Choose a new password', token: req.params.token, errors });

    const hash = await bcrypt.hash(password, security.bcryptRounds);
    // session_version + 1 signs out every existing session of this user.
    await query(
      `UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP, failed_attempts = 0,
              lock_until = NULL, session_version = session_version + 1 WHERE id = ?`,
      [hash, row.user_id]
    );
    await query('UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE id = ?', [row.id]);
    await query('DELETE FROM password_resets WHERE user_id = ? AND id <> ?', [row.user_id, row.id]);
    await audit(req, 'PASSWORD_RESET_DONE', { userId: row.user_id, username: row.username });
    await sendEmail(row.email, 'Your ShostaBazar password was changed', `Hi ${row.username},\n\nYour password was just reset from IP ${req.ip}. All other sessions were signed out.\n\nIf you did not do this, contact support immediately.`);

    req.flash('success', 'Password updated. Please sign in with your new password.');
    res.redirect('/login');
  } catch (err) { next(err); }
});

module.exports = router;
