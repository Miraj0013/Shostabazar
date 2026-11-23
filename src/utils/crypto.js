'use strict';
const crypto = require('crypto');
const { encryptionKey } = require('../config');

/** Cryptographically secure random token (hex). */
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

/** 6-digit numeric one-time code using a CSPRNG (never Math.random). */
function randomOtp() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

/** Constant-time comparison of two strings (prevents timing attacks). */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/** AES-256-GCM encryption for secrets stored at rest (e.g. TOTP seeds). */
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv.toString('base64'), tag.toString('base64'), enc.toString('base64')].join('.');
}

function decrypt(payload) {
  const [iv, tag, enc] = String(payload).split('.').map((p) => Buffer.from(p, 'base64'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

module.exports = { randomToken, randomOtp, sha256, safeEqual, encrypt, decrypt };
