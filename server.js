'use strict';

const { initDb } = require('./src/db/database');
const { createApp } = require('./src/app');

const PORT = Number(process.env.PORT) || 3000;

function startServer(port = PORT) {
  initDb();
  const app = createApp();
  return new Promise((resolve, reject) => {
    const server = app.listen(port, '127.0.0.1', () => {
      const actualPort = server.address().port;
      if (process.env.NODE_ENV !== 'test') {
        console.log(`[CSP Architect] Workbench running at http://localhost:${actualPort}`);
        console.log(`[CSP Architect] Built-in test fixtures mounted at http://localhost:${actualPort}/fixtures`);
      }
      resolve(server);
    });
    server.on('error', reject);
  });
}

if (require.main === module) {
  startServer().catch((err) => {
    console.error('[CSP Architect] Failed to start server:', err.message);
    process.exit(1);
  });
}

module.exports = { startServer };
