exports.up = function(knex) {
  return knex.schema.createTable('staff_projects', function(table) {
    table.increments('id').primary();
    table.integer('staff_id').references('id').inTable('staff').onDelete('CASCADE');
    table.integer('project_id').references('id').inTable('projects').onDelete('CASCADE');
    table.timestamp('created_at').defaultTo(knex.fn.now());
  });
};

exports.down = function(knex) {
  return knex.schema.dropTableIfExists('staff_projects');
};
