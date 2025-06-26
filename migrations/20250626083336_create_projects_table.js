exports.up = function (knex) {
  return knex.schema.createTable('projects', function (table) {
    table.increments('id').primary();
    table.string('name').notNullable();
    table.text('description');
    table.timestamps(true, true);
  });
};

exports.down = function (knex) {
  return knex.schema.dropTableIfExists('projects');
};
