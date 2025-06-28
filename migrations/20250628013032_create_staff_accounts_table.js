exports.up = function(knex) {
  return knex.schema.createTable('staff_accounts', function(table) {
    table.increments('id').primary();
    table.string('email').unique().notNullable();
    table.string('password_hash').notNullable();
    table.integer('staff_id').unsigned().references('id').inTable('staff').onDelete('CASCADE');
    table.boolean('must_change_password').defaultTo(true);
    table.timestamps(true, true); // Adds created_at and updated_at
  });
};

exports.down = function(knex) {
  return knex.schema.dropTableIfExists('staff_accounts');
};
