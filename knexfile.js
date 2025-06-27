module.exports = {
  development: {
    client: 'sqlite3',
    connection: {
      filename: './donation.db'
    },
    useNullAsDefault: true
  },

  production: {
    client: 'pg',
    connection: process.env.DATABASE_URL,
    migrations: {
      tableName: 'knex_migrations'
    }
  }
};
