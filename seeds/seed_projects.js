/**
 * Seed the "projects" table with initial data.
 */

exports.seed = function (knex) {
  return knex('projects').del() // Deletes all existing entries
    .then(function () {
      return knex('projects').insert([
        {
          id: 1,
          name: 'Church Planting in Niger',
          description: 'Mobilizing missionaries to reach Niger Republic'
        },
        {
          id: 2,
          name: 'Rural Missionaries Support',
          description: 'Supporting full-time missionaries in underserved villages'
        },
        {
          id: 3,
          name: 'Media & Mobilization',
          description: 'Funding digital resources and mobilization campaigns'
        }
      ]);
    });
};
