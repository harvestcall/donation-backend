exports.up = function(knex) {
  return knex.schema.table('staff_accounts', function(table) {
    table.boolean('disabled').defaultTo(false);
  });
};

exports.down = function(knex) {
  return knex.schema.table('staff_accounts', function(table) {
    table.dropColumn('disabled');
  });
};
