CREATE TABLE "session" (
  "sid" varchar NOT NULL PRIMARY KEY,
  "sess" json NOT NULL,
  "expire" timestamp(6) NOT NULL
);

CREATE INDEX "IDX_session_expire" ON "session" ("expire");
