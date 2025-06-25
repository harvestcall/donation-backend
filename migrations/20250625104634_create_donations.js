/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  
};

exports.up = function(knex) {
  return knex.schema.createTable('donations', function(table) {
    table.increments('id').primary();
    table.string('email');
    table.string('reference');
    table.integer('amount');
    table.string('currency');
    table.json('metadata');
    table.timestamp('created_at').defaultTo(knex.fn.now());
  });
};

exports.down = function(knex) {
  return knex.schema.dropTable('donations');
};
