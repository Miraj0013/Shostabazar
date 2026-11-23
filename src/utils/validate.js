'use strict';
const { security } = require('../config');

// Server-side validation. Client-side checks are only for UX - the server never trusts them.

const USERNAME_RE = /^[A-Za-z0-9_]{3,30}$/;
const EMAIL_RE = /^[^\s@<>"']{1,64}@[A-Za-z0-9.-]{1,185}\.[A-Za-z]{2,}$/;
const PHONE_RE = /^\+?[0-9]{8,15}$/;

const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '12345678', '123456789', '1234567890', 'qwerty123',
  'qwertyuiop', 'iloveyou', 'admin123', 'welcome1', 'letmein123', 'abc12345', 'football1',
  'monkey123', 'dragon123', 'sunshine1', 'princess1', 'passw0rd', 'p@ssw0rd', 'p@ssword1',
  'bangladesh', 'bangladesh1', 'dhaka1234', 'shostabazar', 'Password@123', 'Admin@123',
]);

/** Text fields: trim, coerce to string and cap length (guards against arrays/objects in body). */
function str(value, max = 255) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, max);
}

function isUsername(v) { return USERNAME_RE.test(v); }
function isEmail(v) { return v.length <= 254 && EMAIL_RE.test(v); }
function isPhone(v) { return PHONE_RE.test(v); }

/** Returns a list of policy violations (empty list = strong enough). */
function passwordProblems(password, { username = '', email = '' } = {}) {
  const p = typeof password === 'string' ? password : '';
  const problems = [];
  if (p.length < security.passwordMinLength) problems.push(`Password must be at least ${security.passwordMinLength} characters.`);
  if (p.length > 128) problems.push('Password must be at most 128 characters.');
  if (!/[a-z]/.test(p)) problems.push('Password needs a lowercase letter.');
  if (!/[A-Z]/.test(p)) problems.push('Password needs an uppercase letter.');
  if (!/[0-9]/.test(p)) problems.push('Password needs a number.');
  if (!/[^A-Za-z0-9]/.test(p)) problems.push('Password needs a special character (e.g. ! @ # $).');
  const lower = p.toLowerCase();
  if (COMMON_PASSWORDS.has(p) || COMMON_PASSWORDS.has(lower)) problems.push('This password is too common.');
  if (username && lower.includes(username.toLowerCase())) problems.push('Password must not contain your username.');
  const local = email.split('@')[0];
  if (local && local.length >= 4 && lower.includes(local.toLowerCase())) problems.push('Password must not contain your email name.');
  return problems;
}

/** LIKE pattern for a search term, with % _ \\ escaped so they match literally. */
function likePattern(s) {
  return `%${s.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
}

/** Positive integer from route params / form (rejects "1 OR 1=1", "1e3", etc.). */
function toId(value) {
  if (typeof value !== 'string' || !/^\d{1,10}$/.test(value)) return null;
  return parseInt(value, 10);
}

module.exports = { str, isUsername, isEmail, isPhone, passwordProblems, toId, likePattern };
