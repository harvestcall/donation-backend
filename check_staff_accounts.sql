SELECT * FROM staff_accounts;
SELECT * FROM staff;
SELECT id, email, staff_id FROM staff_accounts;
SELECT id, name, email FROM staff;
SELECT * FROM staff;
UPDATE staff_accounts
SET staff_id = 1
WHERE email = 'info@harvestcallafrica.org';
SELECT id, email, staff_id FROM staff_accounts;
SELECT id, email, staff_id, must_change_password FROM staff_accounts;
SELECT password_hash FROM staff_accounts WHERE id = 1;
SELECT id, email, staff_id, must_change_password FROM staff_accounts;
SELECT * FROM staff;
UPDATE staff_accounts
SET staff_id = 2
WHERE email = 'test@harvestcallafrica.org';
SELECT id, email, staff_id FROM staff_accounts;
SELECT * FROM staff;
SELECT setval('staff_id_seq', (SELECT MAX(id) FROM staff));
SELECT setval('staff_id_seq', (SELECT MAX(id) FROM staff));
SELECT * FROM staff;
SELECT * FROM staff_accounts;
SELECT id, email, staff_id, must_change_password FROM staff_accounts;
SELECT password_hash FROM staff_accounts WHERE id = 1;
UPDATE staff_accounts
SET staff_id = 4
WHERE email = 'noway@harvestcallafrica.org';