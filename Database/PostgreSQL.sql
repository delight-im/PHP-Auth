-- PHP-Auth (https://github.com/delight-im/PHP-Auth)
-- Copyright (c) delight.im (https://www.delight.im/)
-- Licensed under the MIT License (https://opensource.org/licenses/MIT)

BEGIN;

CREATE TABLE IF NOT EXISTS "users" (
	"id" SERIAL PRIMARY KEY,
	"email" VARCHAR(249) UNIQUE NOT NULL,
	"password" VARCHAR(255) NOT NULL,
	"username" VARCHAR(100) DEFAULT NULL,
	"status" SMALLINT NOT NULL DEFAULT '0',
	"verified" SMALLINT NOT NULL DEFAULT '0',
	"resettable" SMALLINT NOT NULL DEFAULT '1',
	"roles_mask" INTEGER NOT NULL DEFAULT '0',
	"registered" INTEGER NOT NULL,
	"last_login" INTEGER DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS "users_confirmations" (
	"id" SERIAL PRIMARY KEY,
	"user_id" INTEGER NOT NULL,
	"email" VARCHAR(249) NOT NULL,
	"selector" VARCHAR(16) UNIQUE NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS "email_expires" ON "users_confirmations" ("email", "expires");

CREATE INDEX IF NOT EXISTS "user_id" ON "users_confirmations" ("user_id");

CREATE TABLE IF NOT EXISTS "users_remembered" (
	"id" BIGSERIAL PRIMARY KEY,
	"user" INTEGER NOT NULL,
	"selector" VARCHAR(24) UNIQUE NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS "user" ON "users_remembered" ("user");

CREATE TABLE IF NOT EXISTS "users_resets" (
	"id" BIGSERIAL PRIMARY KEY,
	"user" INTEGER NOT NULL,
	"selector" VARCHAR(20) UNIQUE NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS "user_expires" ON "users_resets" ("user", "expires");

CREATE TABLE IF NOT EXISTS "users_throttling" (
	"bucket" VARCHAR(44) PRIMARY KEY,
	"tokens" REAL NOT NULL,
	"replenished_at" INTEGER NOT NULL,
	"expires_at" INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS "expires_at" ON "users_throttling" ("expires_at");

COMMIT;
