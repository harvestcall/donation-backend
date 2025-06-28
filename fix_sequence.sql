SELECT setval(
  pg_get_serial_sequence('staff', 'id'),
  COALESCE((SELECT MAX(id) FROM staff), 0) + 1,
  false
);
