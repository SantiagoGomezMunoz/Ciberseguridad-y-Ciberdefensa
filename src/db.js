require('dotenv').config();
const fs = require('fs');
const path = require('path');

let pool;
if (process.env.DEMO_MODE === 'true') {
  // Modo demo: base de datos PostgreSQL emulada en memoria (se borra al apagar el servidor)
  const { newDb } = require('pg-mem');
  pool = new (newDb().adapters.createPg().Pool)();
  pool.ready = pool.query(fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8'));
} else {
  const { Pool } = require('pg');
  pool = new Pool({ connectionString: process.env.DATABASE_URL });
  pool.ready = Promise.resolve();
}
module.exports = pool;
