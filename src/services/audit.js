'use strict';
const { query } = require('../config/db');

/**
 * Security audit trail. Every sensitive event (logins, lockouts, resets, admin actions,
 * blocked CSRF attempts...) is recorded with IP and user agent for later review.
 */
async function audit(req, event, { userId = null, username = null, details = null } = {}) {
  try {
    await query(
      'INSERT INTO audit_logs (user_id, username, event, ip, user_agent, details) VALUES (?, ?, ?, ?, ?, ?)',
      [
        userId,
        username ? String(username).slice(0, 254) : null,
        event,
        req ? req.ip : null,
        req ? String(req.get('user-agent') || '').slice(0, 255) : null,
        details ? String(details).slice(0, 500) : null,
      ]
    );
  } catch (err) {
    console.error('[audit] failed to write log:', err.message);
  }
}

module.exports = { audit };
