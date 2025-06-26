exports.up = function(knex) {
  return knex.schema.createTable('staff', function(table) {
    table.increments('id').primary();
    table.string('name').notNullable();
    table.string('email').unique();
    table.boolean('active').defaultTo(true);
    table.timestamps(true, true); // created_at, updated_at
  });
};

exports.down = function(knex) {
  return knex.schema.dropTable('staff');
};
