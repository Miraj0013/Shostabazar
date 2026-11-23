'use strict';
const nodemailer = require('nodemailer');
const config = require('../config');
const { query } = require('../config/db');

let transporter = null;
if (config.mail.host) {
  transporter = nodemailer.createTransport({
    host: config.mail.host,
    port: config.mail.port,
    secure: config.mail.secure,
    auth: config.mail.user ? { user: config.mail.user, pass: config.mail.pass } : undefined,
  });
}

/** HTML-escape anything user-controlled before it goes into an email body. */
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function saveToDevMailbox(channel, recipient, subject, body, actionUrl) {
  if (!config.devMailbox) return;
  try {
    await query(
      'INSERT INTO dev_mailbox (channel, recipient, subject, body, action_url) VALUES (?, ?, ?, ?, ?)',
      [channel, recipient, subject, body, actionUrl || null]
    );
  } catch (err) {
    console.error('[notify] dev mailbox write failed:', err.message);
  }
}

/**
 * Send an email. Uses SMTP when configured; in development it is also stored in the
 * dev mailbox (/dev/mailbox) so OTPs and reset links can be demonstrated offline.
 */
async function sendEmail(to, subject, text, { actionUrl, actionLabel } = {}) {
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden">
      <div style="background:#0f766e;color:#fff;padding:16px 20px;font-size:18px;font-weight:bold">ShostaBazar Security</div>
      <div style="padding:20px;color:#111827;line-height:1.5;white-space:pre-line">${esc(text)}</div>
      ${actionUrl ? `<div style="padding:0 20px 20px"><a href="${esc(actionUrl)}" style="background:#0f766e;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none">${esc(actionLabel || 'Open')}</a></div>` : ''}
      <div style="padding:12px 20px;background:#f9fafb;color:#6b7280;font-size:12px">If you did not request this, you can ignore this email or contact support.</div>
    </div>`;
  const fullText = actionUrl ? `${text}\n\n${actionLabel || 'Link'}: ${actionUrl}` : text;

  await saveToDevMailbox('email', to, subject, text, actionUrl);
  if (!transporter) {
    if (!config.isProd) console.log(`[email -> ${to}] ${subject}`);
    return;
  }
  try {
    await transporter.sendMail({ from: config.mail.from, to, subject, text: fullText, html });
  } catch (err) {
    console.error('[notify] email failed:', err.message);
  }
}

/** Send an SMS through Twilio's REST API if configured (otherwise dev mailbox only). */
async function sendSms(to, text) {
  if (!to) return;
  await saveToDevMailbox('sms', to, 'SMS', text);
  const { twilioSid, twilioToken, twilioFrom } = config.sms;
  if (!twilioSid || !twilioToken || !twilioFrom) return;
  try {
    const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(twilioSid)}/Messages.json`, {
      method: 'POST',
      headers: {
        Authorization: 'Basic ' + Buffer.from(`${twilioSid}:${twilioToken}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ To: to, From: twilioFrom, Body: text }),
    });
    if (!res.ok) console.error('[notify] sms failed with status', res.status);
  } catch (err) {
    console.error('[notify] sms failed:', err.message);
  }
}

module.exports = { sendEmail, sendSms };
