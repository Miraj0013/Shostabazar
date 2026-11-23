'use strict';
const express = require('express');
const { query } = require('../config/db');

// Development-only "inbox" that shows the emails/SMS the app would send.
// Mounted only when DEV_MAILBOX=true (never enable it on a public deployment).
const router = express.Router();

router.get('/mailbox', async (req, res, next) => {
  try {
    const messages = await query('SELECT * FROM dev_mailbox ORDER BY id DESC LIMIT 30');
    res.render('dev-mailbox', { title: 'Dev mailbox', messages });
  } catch (err) { next(err); }
});

module.exports = router;
