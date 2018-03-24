-- PHP-Auth (https://github.com/delight-im/PHP-Auth)
-- Copyright (c) delight.im (https://www.delight.im/)
-- Licensed under the MIT License (https://opensource.org/licenses/MIT)

BEGIN;

CREATE TABLE IF NOT EXISTS "users" (
	"id" SERIAL PRIMARY KEY CHECK ("id" >= 0),
	"email" VARCHAR(249) UNIQUE NOT NULL,
	"password" VARCHAR(255) NOT NULL,
	"username" VARCHAR(100) DEFAULT NULL,
	"status" SMALLINT NOT NULL DEFAULT '0' CHECK ("status" >= 0),
	"verified" SMALLINT NOT NULL DEFAULT '0' CHECK ("verified" >= 0),
	"resettable" SMALLINT NOT NULL DEFAULT '1' CHECK ("resettable" >= 0),
	"roles_mask" INTEGER NOT NULL DEFAULT '0' CHECK ("roles_mask" >= 0),
	"registered" INTEGER NOT NULL CHECK ("registered" >= 0),
	"last_login" INTEGER DEFAULT NULL CHECK ("last_login" >= 0),
	"force_logout" INTEGER NOT NULL DEFAULT '0' CHECK ("force_logout" >= 0)
);

CREATE TABLE IF NOT EXISTS "users_confirmations" (
	"id" SERIAL PRIMARY KEY CHECK ("id" >= 0),
	"user_id" INTEGER NOT NULL CHECK ("user_id" >= 0),
	"email" VARCHAR(249) NOT NULL,
	"selector" VARCHAR(16) UNIQUE NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0)
);
CREATE INDEX IF NOT EXISTS "email_expires" ON "users_confirmations" ("email", "expires");
CREATE INDEX IF NOT EXISTS "user_id" ON "users_confirmations" ("user_id");

CREATE TABLE IF NOT EXISTS "users_remembered" (
	"id" BIGSERIAL PRIMARY KEY CHECK ("id" >= 0),
	"user" INTEGER NOT NULL CHECK ("user" >= 0),
	"selector" VARCHAR(24) UNIQUE NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0)
);
CREATE INDEX IF NOT EXISTS "user" ON "users_remembered" ("user");

CREATE TABLE IF NOT EXISTS "users_resets" (
	"id" BIGSERIAL PRIMARY KEY CHECK ("id" >= 0),
	"user" INTEGER NOT NULL CHECK ("user" >= 0),
	"selector" VARCHAR(20) UNIQUE NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0)
);
CREATE INDEX IF NOT EXISTS "user_expires" ON "users_resets" ("user", "expires");

CREATE TABLE IF NOT EXISTS "users_throttling" (
	"bucket" VARCHAR(44) PRIMARY KEY,
	"tokens" REAL NOT NULL CHECK ("tokens" >= 0),
	"replenished_at" INTEGER NOT NULL CHECK ("replenished_at" >= 0),
	"expires_at" INTEGER NOT NULL CHECK ("expires_at" >= 0)
);
CREATE INDEX IF NOT EXISTS "expires_at" ON "users_throttling" ("expires_at");

COMMIT;
