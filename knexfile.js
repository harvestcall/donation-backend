module.exports = {
  development: {
    client: 'sqlite3',
    connection: {
      filename: './donation.db'
    },
    useNullAsDefault: true
  }
};
