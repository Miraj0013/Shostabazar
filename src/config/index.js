'use strict';
require('dotenv').config();
const crypto = require('crypto');

const env = process.env;
const isProd = env.NODE_ENV === 'production';

/**
 * TLS settings for the database connection. The server certificate is always verified.
 * Providers with their own CA (e.g. Aiven) need it via DB_SSL_CA (PEM text, "\n" allowed)
 * or DB_SSL_CA_FILE (path relative to the project root); otherwise system CAs are used.
 */
function readDbCa() {
  const fs = require('fs');
  const path = require('path');
  let ca = env.DB_SSL_CA ? env.DB_SSL_CA.replace(/\\n/g, '\n') : null;
  if (!ca && env.DB_SSL_CA_FILE) {
    const file = [path.resolve(__dirname, '../..', env.DB_SSL_CA_FILE), path.resolve(process.cwd(), env.DB_SSL_CA_FILE)]
      .find((f) => fs.existsSync(f));
    if (file) ca = fs.readFileSync(file, 'utf8');
    else console.warn(`[config] DB_SSL_CA_FILE ${env.DB_SSL_CA_FILE} not found - using system CAs.`);
  }
  return { minVersion: 'TLSv1.2', rejectUnauthorized: true, ...(ca ? { ca } : {}) };
}

function int(name, def) {
  const n = parseInt(env[name], 10);
  return Number.isFinite(n) ? n : def;
}

let sessionSecret = env.SESSION_SECRET;
if (!sessionSecret || sessionSecret.length < 32) {
  if (isProd) {
    console.error('FATAL: SESSION_SECRET must be set (at least 32 characters) in production.');
    process.exit(1);
  }
  sessionSecret = crypto.randomBytes(48).toString('hex');
  console.warn('[config] SESSION_SECRET missing/short - using a random one (sessions reset on restart).');
}

// 32-byte key for AES-256-GCM encryption of TOTP secrets.
// Derived from ENCRYPTION_KEY (or the session secret) so the raw value never needs a fixed format.
const encryptionKey = crypto
  .createHash('sha256')
  .update(env.ENCRYPTION_KEY || sessionSecret)
  .digest();

module.exports = {
  isProd,
  port: int('PORT', 3000),
  appUrl: (env.APP_URL || `http://localhost:${int('PORT', 3000)}`).replace(/\/+$/, ''),
  appName: 'ShostaBazar',
  trustProxy: int('TRUST_PROXY', 0),
  cookieSecure: env.COOKIE_SECURE === 'true',
  sessionSecret,
  encryptionKey,

  db: {
    host: env.DB_HOST || 'localhost',
    port: int('DB_PORT', 3306),
    user: env.DB_USER || 'shostabazar',
    password: env.DB_PASSWORD || '',
    database: env.DB_NAME || 'shostabazar',
    poolSize: int('DB_POOL_SIZE', 10),
    connectRetries: int('DB_CONNECT_RETRIES', 30),
    // TLS to a cloud MySQL (Aiven, TiDB Cloud, PlanetScale-compatible...).
    ssl: env.DB_SSL === 'true' ? readDbCa() : null,
  },

  security: {
    maxFailedAttempts: int('MAX_FAILED_ATTEMPTS', 3),
    lockMinutes: int('LOCK_MINUTES', 15),
    idleTimeoutMinutes: int('SESSION_IDLE_MINUTES', 15),
    absoluteTimeoutHours: int('SESSION_ABSOLUTE_HOURS', 8),
    otpTtlMinutes: int('OTP_TTL_MINUTES', 5),
    otpMaxAttempts: 5,
    resetTtlMinutes: int('RESET_TTL_MINUTES', 15),
    bcryptRounds: int('BCRYPT_ROUNDS', 12),
    passwordMinLength: int('PASSWORD_MIN_LENGTH', 8),
  },

  mail: {
    host: env.SMTP_HOST || '',
    port: int('SMTP_PORT', 587),
    secure: env.SMTP_SECURE === 'true',
    user: env.SMTP_USER || '',
    pass: env.SMTP_PASS || '',
    from: env.MAIL_FROM || 'ShostaBazar Security <no-reply@shostabazar.local>',
  },

  sms: {
    twilioSid: env.TWILIO_ACCOUNT_SID || '',
    twilioToken: env.TWILIO_AUTH_TOKEN || '',
    twilioFrom: env.TWILIO_FROM || '',
  },

  // Dev mailbox shows OTPs / reset links in the browser when no real SMTP is set up.
  devMailbox: env.DEV_MAILBOX ? env.DEV_MAILBOX === 'true' : !isProd,

  admin: {
    username: env.ADMIN_USERNAME || '',
    email: env.ADMIN_EMAIL || '',
    password: env.ADMIN_PASSWORD || '',
  },
  seedDemoData: env.SEED_DEMO_DATA !== 'false',
};
