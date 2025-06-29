// db.js
const knex = require('knex');
require('dotenv').config(); // Load env vars early

const db = knex({
  client: 'pg',
  connection: {
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Needed for Render
  }
});

module.exports = db;
