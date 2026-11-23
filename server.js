'use strict';
// Entry point for a normal server (npm start, Docker, any VPS).
// The Netlify entry point is netlify/functions/server.js - both use the same app in src/app.js.
const config = require('./src/config');
const app = require('./src/app');
const { initDatabase } = require('./database/init');

initDatabase()
  .then(() => {
    app.listen(config.port, () => {
      console.log(`ShostaBazar running at ${config.appUrl} (env: ${config.isProd ? 'production' : 'development'})`);
      if (config.devMailbox) console.log(`Dev mailbox (OTP codes, reset links): ${config.appUrl}/dev/mailbox`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialise the database:', err.message);
    process.exit(1);
  });
