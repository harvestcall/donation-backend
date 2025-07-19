exports.up = function(knex) {
  return knex.schema.table('projects', function(table) {
    table.boolean('active').defaultTo(true);
  });
};

exports.down = function(knex) {
  return knex.schema.table('projects', function(table) {
    table.dropColumn('active');
  });
};
