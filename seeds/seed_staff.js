exports.seed = function (knex) {
  // Deletes ALL existing entries
  return knex('staff').del()
    .then(function () {
      // Inserts seed entries
      return knex('staff').insert([
        {
          id: 1,
          name: 'Gabriel & Dolapo Ojo',
          email: 'gabriel.ojo@harvestcallafrica.org'
        },
        {
          id: 2,
          name: 'Samuel & Grace Olatunji',
          email: 'samuel.olatunji@harvestcallafrica.org'
        },
        {
          id: 3,
          name: 'Mercy Yusuf',
          email: 'mercy.yusuf@harvestcallafrica.org'
        }
      ]);
    });
};
