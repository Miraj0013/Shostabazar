'use strict';
/**
 * Time-based one-time passwords (TOTP, RFC 6238) for authenticator apps such as
 * Google Authenticator or Microsoft Authenticator. Built on Node's crypto module only:
 * HMAC-SHA1, 30-second steps, 6 digits (the settings every authenticator app uses).
 */
const crypto = require('crypto');

const STEP_SECONDS = 30;
const DIGITS = 6;
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = BASE32.indexOf(ch);
    if (idx === -1) throw new Error('Invalid base32 character in TOTP secret');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** New random secret (160 bits, base32) to show as a QR code / setup key. */
function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

/** otpauth:// URI that authenticator apps read from the QR code. */
function generateURI({ issuer, label, secret }) {
  const params = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: String(DIGITS), period: String(STEP_SECONDS) });
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?${params}`;
}

/** The code for one 30-second time step (HOTP with the step number as counter, RFC 4226). */
function codeForStep(key, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const hmac = crypto.createHmac('sha1', key).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = hmac.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

function currentStep(epochSeconds = Date.now() / 1000) {
  return Math.floor(epochSeconds / STEP_SECONDS);
}

/** Code for the current time (or for `epoch`, in seconds). */
function generate({ secret, epoch }) {
  return codeForStep(base32Decode(secret), currentStep(epoch));
}

/**
 * Check a code. Accepts the current step and its neighbours within `epochTolerance`
 * seconds (to allow for phone clock drift). With `afterTimeStep`, only steps AFTER the
 * last accepted one count, so the same code cannot be used twice (replay protection).
 * Returns { valid, timeStep }.
 */
function verify({ secret, token, epochTolerance = STEP_SECONDS, afterTimeStep }) {
  if (!/^\d{6}$/.test(String(token))) return { valid: false };
  const key = base32Decode(secret);
  const now = currentStep();
  const window = Math.ceil(epochTolerance / STEP_SECONDS);
  for (let step = now - window; step <= now + window; step++) {
    if (afterTimeStep != null && step <= afterTimeStep) continue;
    const expected = Buffer.from(codeForStep(key, step));
    if (crypto.timingSafeEqual(expected, Buffer.from(String(token)))) return { valid: true, timeStep: step };
  }
  return { valid: false };
}

module.exports = { generateSecret, generateURI, generate, verify, codeForStep, base32Decode };
