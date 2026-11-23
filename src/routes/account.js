'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const totp = require('../utils/totp');
const QRCode = require('qrcode');
const config = require('../config');
const { query, one } = require('../config/db');
const { requireAuth } = require('../middleware/security');
const { str, passwordProblems, toId, isPhone } = require('../utils/validate');
const { encrypt } = require('../utils/crypto');
const { audit } = require('../services/audit');
const { sendEmail } = require('../services/notify');

const router = express.Router();
router.use(requireAuth);

async function renderAccount(req, res, { errors = [], status = 200 } = {}) {
  const [devices, activity, full] = await Promise.all([
    query('SELECT id, device_label, ip, first_seen, last_seen FROM known_devices WHERE user_id = ? ORDER BY last_seen DESC', [req.user.id]),
    query('SELECT event, ip, details, created_at FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT 15', [req.user.id]),
    one('SELECT created_at, last_login_at, last_login_ip, password_changed_at FROM users WHERE id = ?', [req.user.id]),
  ]);
  res.status(status).render('account/index', { title: 'Security settings', devices, activity, info: full, errors });
}

router.get('/', async (req, res, next) => {
  try { await renderAccount(req, res); } catch (err) { next(err); }
});

/* ------------------------- change password ------------------------ */
router.post('/password', async (req, res, next) => {
  try {
    const current = typeof req.body.current === 'string' ? req.body.current : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const row = await one('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);

    const errors = [];
    if (!(await bcrypt.compare(current, row.password_hash))) errors.push('Current password is incorrect.');
    errors.push(...passwordProblems(password, req.user));
    if (password !== req.body.confirm) errors.push('New passwords do not match.');
    if (!errors.length && current === password) errors.push('New password must be different from the current one.');
    if (errors.length) {
      await audit(req, 'PASSWORD_CHANGE_FAILED', { userId: req.user.id, username: req.user.username });
      return renderAccount(req, res, { errors, status: 400 });
    }

    const hash = await bcrypt.hash(password, config.security.bcryptRounds);
    await query('UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP, session_version = session_version + 1 WHERE id = ?', [hash, req.user.id]);
    req.session.sessionVersion = req.user.session_version + 1; // keep THIS session, kill all others
    await audit(req, 'PASSWORD_CHANGED', { userId: req.user.id, username: req.user.username });
    await sendEmail(req.user.email, 'Your ShostaBazar password was changed', `Hi ${req.user.username},\n\nYour password was changed from IP ${req.ip}. Other sessions were signed out.\n\nIf this was not you, reset your password immediately.`, { actionUrl: `${config.appUrl}/forgot`, actionLabel: 'Reset password' });
    req.flash('success', 'Password changed. All other sessions have been signed out.');
    res.redirect('/account');
  } catch (err) { next(err); }
});

/* ---------------------------- phone (SMS) ------------------------- */
router.post('/phone', async (req, res, next) => {
  try {
    const phone = str(req.body.phone, 20).replace(/[\s-]/g, '');
    if (phone && !isPhone(phone)) {
      req.flash('danger', 'Phone must be 8-15 digits, optionally starting with +.');
      return res.redirect('/account');
    }
    await query('UPDATE users SET phone = ? WHERE id = ?', [phone || null, req.user.id]);
    await audit(req, 'PHONE_UPDATED', { userId: req.user.id, username: req.user.username });
    req.flash('success', phone ? 'Phone saved - you will also get SMS security alerts.' : 'Phone removed.');
    res.redirect('/account');
  } catch (err) { next(err); }
});

/* ------------------ authenticator app (TOTP) 2FA ------------------ */
router.get('/2fa/setup', async (req, res, next) => {
  try {
    if (req.user.totp_enabled) return res.redirect('/account');
    if (!req.session.pendingTotpSecret) req.session.pendingTotpSecret = totp.generateSecret();
    const secret = req.session.pendingTotpSecret;
    const uri = totp.generateURI({ issuer: config.appName, label: req.user.email, secret });
    const qr = await QRCode.toDataURL(uri, { margin: 1, width: 220 });
    res.render('account/totp-setup', { title: 'Set up authenticator', qr, secret, error: null });
  } catch (err) { next(err); }
});

router.post('/2fa/enable', async (req, res, next) => {
  try {
    const secret = req.session.pendingTotpSecret;
    if (!secret) return res.redirect('/account/2fa/setup');
    const code = str(req.body.code, 10).replace(/\s/g, '');
    const result = /^\d{6}$/.test(code) ? await totp.verify({ secret, token: code, epochTolerance: 30 }) : { valid: false };
    if (!result.valid) {
      const uri = totp.generateURI({ issuer: config.appName, label: req.user.email, secret });
      const qr = await QRCode.toDataURL(uri, { margin: 1, width: 220 });
      return res.status(400).render('account/totp-setup', { title: 'Set up authenticator', qr, secret, error: 'That code is not valid. Check your phone clock and try again.' });
    }
    await query('UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_last_step = ? WHERE id = ?', [encrypt(secret), result.timeStep, req.user.id]);
    delete req.session.pendingTotpSecret;
    await audit(req, 'TOTP_ENABLED', { userId: req.user.id, username: req.user.username });
    await sendEmail(req.user.email, 'Authenticator app enabled', `Hi ${req.user.username},\n\nAn authenticator app is now required to sign in to your ShostaBazar account.`);
    req.flash('success', 'Authenticator app enabled. You will need it on your next sign-in.');
    res.redirect('/account');
  } catch (err) { next(err); }
});

router.post('/2fa/disable', async (req, res, next) => {
  try {
    const row = await one('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    if (!(await bcrypt.compare(password, row.password_hash))) {
      await audit(req, 'TOTP_DISABLE_FAILED', { userId: req.user.id, username: req.user.username });
      req.flash('danger', 'Password incorrect - authenticator app was not removed.');
      return res.redirect('/account');
    }
    await query('UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = NULL WHERE id = ?', [req.user.id]);
    await audit(req, 'TOTP_DISABLED', { userId: req.user.id, username: req.user.username });
    await sendEmail(req.user.email, 'Authenticator app removed', `Hi ${req.user.username},\n\nThe authenticator app was removed from your account. Sign-in codes will be sent by email instead.\n\nIf this was not you, reset your password now.`, { actionUrl: `${config.appUrl}/forgot`, actionLabel: 'Reset password' });
    req.flash('success', 'Authenticator app removed. Sign-in codes will now be sent by email.');
    res.redirect('/account');
  } catch (err) { next(err); }
});

/* --------------------------- trusted devices ---------------------- */
router.post('/devices/:id/delete', async (req, res, next) => {
  try {
    const id = toId(req.params.id);
    // "AND user_id = ?" prevents IDOR: users can only remove their own devices.
    if (id) await query('DELETE FROM known_devices WHERE id = ? AND user_id = ?', [id, req.user.id]);
    await audit(req, 'DEVICE_REMOVED', { userId: req.user.id, username: req.user.username, details: `device ${id}` });
    req.flash('success', 'Device removed. It will trigger a new-device alert next time it signs in.');
    res.redirect('/account');
  } catch (err) { next(err); }
});

module.exports = router;
