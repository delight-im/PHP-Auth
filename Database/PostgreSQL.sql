-- PHP-Auth (https://github.com/delight-im/PHP-Auth)
-- Copyright (c) delight.im (https://www.delight.im/)
-- Licensed under the MIT License (https://opensource.org/licenses/MIT)

BEGIN;

CREATE TABLE "users" (
	"id" SERIAL PRIMARY KEY,
	"email" VARCHAR(249) UNIQUE NOT NULL,
	"password" VARCHAR(255) NOT NULL COLLATE "C",
	"username" VARCHAR(100) DEFAULT NULL,
	"status" SMALLINT NOT NULL DEFAULT 0 CHECK ("status" >= 0),
	"verified" SMALLINT NOT NULL DEFAULT 0 CHECK ("verified" >= 0 AND "verified" <= 1),
	"resettable" SMALLINT NOT NULL DEFAULT 1 CHECK ("resettable" >= 0 AND "resettable" <= 1),
	"roles_mask" INTEGER NOT NULL DEFAULT 0 CHECK ("roles_mask" >= 0),
	"registered" INTEGER NOT NULL CHECK ("registered" >= 0),
	"last_login" INTEGER DEFAULT NULL CHECK ("last_login" >= 0),
	"force_logout" INTEGER NOT NULL DEFAULT 0 CHECK ("force_logout" >= 0)
);

CREATE TABLE "users_2fa" (
	"id" BIGSERIAL PRIMARY KEY,
	"user_id" INTEGER NOT NULL CHECK ("user_id" >= 0),
	"mechanism" SMALLINT NOT NULL CHECK ("mechanism" >= 0),
	"seed" VARCHAR(255) DEFAULT NULL COLLATE "C",
	"created_at" INTEGER NOT NULL CHECK ("created_at" >= 0),
	"expires_at" INTEGER DEFAULT NULL CHECK ("expires_at" >= 0)
);
CREATE UNIQUE INDEX "users_2fa_user_id_mechanism_uq" ON "users_2fa" ("user_id", "mechanism");

CREATE TABLE "users_confirmations" (
	"id" SERIAL PRIMARY KEY,
	"user_id" INTEGER NOT NULL CHECK ("user_id" >= 0),
	"email" VARCHAR(249) NOT NULL,
	"selector" VARCHAR(16) UNIQUE NOT NULL COLLATE "C",
	"token" VARCHAR(255) NOT NULL COLLATE "C",
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0)
);
CREATE INDEX "users_confirmations_email_expires_ix" ON "users_confirmations" ("email", "expires");
CREATE INDEX "users_confirmations_user_id_ix" ON "users_confirmations" ("user_id");

CREATE TABLE "users_otps" (
	"id" BIGSERIAL PRIMARY KEY,
	"user_id" INTEGER NOT NULL CHECK ("user_id" >= 0),
	"mechanism" SMALLINT NOT NULL CHECK ("mechanism" >= 0),
	"single_factor" SMALLINT NOT NULL DEFAULT 0 CHECK ("single_factor" >= 0 AND "single_factor" <= 1),
	"selector" VARCHAR(24) NOT NULL COLLATE "C",
	"token" VARCHAR(255) NOT NULL COLLATE "C",
	"expires_at" INTEGER DEFAULT NULL CHECK ("expires_at" >= 0)
);
CREATE INDEX "users_otps_user_id_mechanism_ix" ON "users_otps" ("user_id", "mechanism");
CREATE INDEX "users_otps_selector_user_id_ix" ON "users_otps" ("selector", "user_id");

CREATE TABLE "users_remembered" (
	"id" BIGSERIAL PRIMARY KEY,
	"user" INTEGER NOT NULL CHECK ("user" >= 0),
	"selector" VARCHAR(24) UNIQUE NOT NULL COLLATE "C",
	"token" VARCHAR(255) NOT NULL COLLATE "C",
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0)
);
CREATE INDEX "users_remembered_user_ix" ON "users_remembered" ("user");

CREATE TABLE "users_resets" (
	"id" BIGSERIAL PRIMARY KEY,
	"user" INTEGER NOT NULL CHECK ("user" >= 0),
	"selector" VARCHAR(20) UNIQUE NOT NULL COLLATE "C",
	"token" VARCHAR(255) NOT NULL COLLATE "C",
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0)
);
CREATE INDEX "users_resets_user_expires_ix" ON "users_resets" ("user", "expires");

CREATE TABLE "users_throttling" (
	"bucket" VARCHAR(44) PRIMARY KEY COLLATE "C",
	"tokens" REAL NOT NULL CHECK ("tokens" >= 0),
	"replenished_at" INTEGER NOT NULL CHECK ("replenished_at" >= 0),
	"expires_at" INTEGER NOT NULL CHECK ("expires_at" >= 0)
);
CREATE INDEX "users_throttling_expires_at_ix" ON "users_throttling" ("expires_at");

COMMIT;
