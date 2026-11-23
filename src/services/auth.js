'use strict';
const config = require('../config');
const { query, one } = require('../config/db');
const { randomOtp, randomToken, sha256 } = require('../utils/crypto');
const { audit } = require('./audit');
const { sendEmail, sendSms } = require('./notify');

const { security } = config;
const DEVICE_COOKIE = 'sb_device';

function minutesFromNow(min) {
  return new Date(Date.now() + min * 60 * 1000);
}

/** Promisified session helpers. Regenerating the session ID on login prevents session fixation. */
function regenerateSession(req) {
  return new Promise((resolve, reject) => req.session.regenerate((err) => (err ? reject(err) : resolve())));
}

function lockRemainingMinutes(user) {
  if (!user.lock_until) return 0;
  const ms = new Date(user.lock_until).getTime() - Date.now();
  return ms > 0 ? Math.ceil(ms / 60000) : 0;
}

/**
 * Record a failed password / 2FA attempt. After MAX_FAILED_ATTEMPTS (default 3) failures
 * the account is locked for LOCK_MINUTES and the owner is notified by email.
 * Returns { locked, remaining }.
 */
async function registerFailure(req, user, reason) {
  await query('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?', [user.id]);
  const { failed_attempts: attempts } = await one('SELECT failed_attempts FROM users WHERE id = ?', [user.id]);

  if (attempts >= security.maxFailedAttempts) {
    await query('UPDATE users SET failed_attempts = 0, lock_until = ? WHERE id = ?', [minutesFromNow(security.lockMinutes), user.id]);
    await audit(req, 'ACCOUNT_LOCKED', { userId: user.id, username: user.username, details: `${attempts} failed attempts (${reason})` });
    await sendEmail(
      user.email,
      'Your ShostaBazar account was temporarily locked',
      `Hi ${user.username},\n\nWe noticed ${attempts} failed sign-in attempts on your account, so we locked it for ${security.lockMinutes} minutes.\n\nIP address: ${req.ip}\nDevice: ${req.get('user-agent') || 'unknown'}\nTime: ${new Date().toUTCString()}\n\nIf this was not you, reset your password now.`,
      { actionUrl: `${config.appUrl}/forgot`, actionLabel: 'Reset password' }
    );
    return { locked: true, remaining: 0 };
  }
  await audit(req, 'LOGIN_FAILED', { userId: user.id, username: user.username, details: `${reason}; attempt ${attempts}/${security.maxFailedAttempts}` });
  return { locked: false, remaining: security.maxFailedAttempts - attempts };
}

/** Create a fresh 6-digit email/SMS OTP. Only the SHA-256 hash is stored. */
async function issueLoginOtp(req, user) {
  const code = randomOtp();
  await query('DELETE FROM otp_codes WHERE user_id = ? AND purpose = ?', [user.id, 'login']);
  await query('INSERT INTO otp_codes (user_id, code_hash, purpose, expires_at) VALUES (?, ?, ?, ?)', [
    user.id, sha256(code), 'login', minutesFromNow(security.otpTtlMinutes),
  ]);
  await sendEmail(
    user.email,
    `${code} is your ShostaBazar verification code`,
    `Hi ${user.username},\n\nYour sign-in verification code is: ${code}\n\nIt expires in ${security.otpTtlMinutes} minutes. Never share this code with anyone - ShostaBazar staff will never ask for it.`
  );
  if (user.phone) await sendSms(user.phone, `ShostaBazar code: ${code} (valid ${security.otpTtlMinutes} min). Do not share it.`);
  await audit(req, 'OTP_SENT', { userId: user.id, username: user.username });
}

/** Very small user-agent summary for device labels / notifications. */
function describeDevice(ua = '') {
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Chrome\//.test(ua) ? 'Chrome'
    : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : /curl|wget|python|node/i.test(ua) ? 'Script/CLI' : 'Unknown browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS'
    : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'Unknown OS';
  return `${browser} on ${os}`;
}

/**
 * Recognise the device using a long-lived random cookie + user agent.
 * Unknown device -> store it and alert the user by email (and SMS if a phone is set).
 */
async function checkDevice(req, res, user) {
  let deviceId = req.signedCookies[DEVICE_COOKIE];
  if (typeof deviceId !== 'string' || !/^[a-f0-9]{64}$/.test(deviceId)) {
    deviceId = randomToken(32);
  }
  res.cookie(DEVICE_COOKIE, deviceId, {
    httpOnly: true, signed: true, sameSite: 'lax', secure: config.cookieSecure, maxAge: 365 * 24 * 3600 * 1000,
  });

  const ua = String(req.get('user-agent') || '').slice(0, 255);
  const deviceHash = sha256(`${deviceId}|${ua}`);
  const known = await one('SELECT id FROM known_devices WHERE user_id = ? AND device_hash = ?', [user.id, deviceHash]);
  if (known) {
    await query('UPDATE known_devices SET last_seen = CURRENT_TIMESTAMP, ip = ? WHERE id = ?', [req.ip, known.id]);
    return false;
  }

  const { n: previousDevices } = await one('SELECT COUNT(*) AS n FROM known_devices WHERE user_id = ?', [user.id]);
  const label = describeDevice(ua);
  await query('INSERT INTO known_devices (user_id, device_hash, device_label, ip) VALUES (?, ?, ?, ?)', [user.id, deviceHash, label, req.ip]);

  if (previousDevices > 0) {
    await audit(req, 'NEW_DEVICE_LOGIN', { userId: user.id, username: user.username, details: label });
    await sendEmail(
      user.email,
      'New device sign-in to your ShostaBazar account',
      `Hi ${user.username},\n\nYour account was just accessed from a new device.\n\nDevice: ${label}\nIP address: ${req.ip}\nTime: ${new Date().toUTCString()}\n\nIf this was you, no action is needed. If not, reset your password immediately - this will sign out every other session.`,
      { actionUrl: `${config.appUrl}/forgot`, actionLabel: 'Secure my account' }
    );
    if (user.phone) await sendSms(user.phone, `ShostaBazar: new sign-in from ${label} (IP ${req.ip}). Not you? Reset your password now.`);
  }
  return true;
}

/** Final step after password + 2FA succeeded. */
async function completeLogin(req, res, user) {
  const returnTo = req.session.returnTo;
  await regenerateSession(req);
  req.session.userId = user.id;
  req.session.sessionVersion = user.session_version;
  req.session.loginAt = Date.now();

  await query(
    'UPDATE users SET failed_attempts = 0, lock_until = NULL, last_login_at = CURRENT_TIMESTAMP, last_login_ip = ? WHERE id = ?',
    [req.ip, user.id]
  );
  await query('DELETE FROM otp_codes WHERE user_id = ? AND purpose = ?', [user.id, 'login']);
  const isNewDevice = await checkDevice(req, res, user);
  await audit(req, 'LOGIN_SUCCESS', { userId: user.id, username: user.username, details: isNewDevice ? 'new device' : 'known device' });

  if (isNewDevice) req.session.flash = { type: 'info', message: 'Signed in from a new device - we sent a security alert to your email.' };
  const safeReturn = typeof returnTo === 'string' && returnTo.startsWith('/') && !returnTo.startsWith('//') ? returnTo : null;
  return res.redirect(safeReturn || (user.role === 'admin' ? '/admin' : '/dashboard'));
}

module.exports = {
  regenerateSession, lockRemainingMinutes, registerFailure, issueLoginOtp, completeLogin, minutesFromNow,
};
