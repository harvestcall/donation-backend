// migrations/YYYYMMDDHHMMSS_add_performance_indexes.js
exports.up = function(knex) {
  return knex.schema.raw(`
    -- Single-column indexes
    CREATE INDEX idx_donations_metadata_project ON donations ((metadata->>'projectId'));
    CREATE INDEX idx_donations_metadata_staff ON donations ((metadata->>'staffId'));
    CREATE INDEX idx_donations_created ON donations (created_at);
    
    -- Composite index
    CREATE INDEX idx_donations_created_project 
    ON donations (created_at, (metadata->>'projectId'));
    
    -- Partial index
    CREATE INDEX idx_active_staff ON staff (id) WHERE active = true;
  `);
};

exports.down = function(knex) {
  return knex.schema.raw(`
    DROP INDEX idx_donations_metadata_project;
    DROP INDEX idx_donations_metadata_staff;
    DROP INDEX idx_donations_created;
    DROP INDEX idx_donations_created_project;
    DROP INDEX idx_active_staff;
  `);
};