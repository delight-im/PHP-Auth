-- PHP-Auth (https://github.com/delight-im/PHP-Auth)
-- Copyright (c) delight.im (https://www.delight.im/)
-- Licensed under the MIT License (https://opensource.org/licenses/MIT)

PRAGMA foreign_keys = OFF;

CREATE TABLE "users" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	"email" TEXT NOT NULL COLLATE NOCASE,
	"password" TEXT NOT NULL COLLATE BINARY,
	"username" TEXT DEFAULT NULL COLLATE NOCASE,
	"status" INTEGER NOT NULL CHECK ("status" >= 0) DEFAULT 0,
	"verified" INTEGER NOT NULL CHECK ("verified" >= 0 AND "verified" <= 1) DEFAULT 0,
	"resettable" INTEGER NOT NULL CHECK ("resettable" >= 0 AND "resettable" <= 1) DEFAULT 1,
	"roles_mask" INTEGER NOT NULL CHECK ("roles_mask" >= 0) DEFAULT 0,
	"registered" INTEGER NOT NULL CHECK ("registered" >= 0),
	"last_login" INTEGER CHECK ("last_login" >= 0) DEFAULT NULL,
	"force_logout" INTEGER NOT NULL CHECK ("force_logout" >= 0) DEFAULT 0,
	CONSTRAINT "users_email_uq" UNIQUE ("email")
);

CREATE TABLE "users_2fa" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	"user_id" INTEGER NOT NULL CHECK ("user_id" >= 0),
	"mechanism" INTEGER NOT NULL CHECK ("mechanism" >= 0),
	"seed" TEXT DEFAULT NULL COLLATE BINARY,
	"created_at" INTEGER NOT NULL CHECK ("created_at" >= 0),
	"expires_at" INTEGER CHECK ("expires_at" >= 0) DEFAULT NULL,
	CONSTRAINT "users_2fa_user_id_mechanism_uq" UNIQUE ("user_id", "mechanism")
);

CREATE TABLE "users_confirmations" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	"user_id" INTEGER NOT NULL CHECK ("user_id" >= 0),
	"email" TEXT NOT NULL COLLATE NOCASE,
	"selector" TEXT NOT NULL COLLATE BINARY,
	"token" TEXT NOT NULL COLLATE BINARY,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0),
	CONSTRAINT "users_confirmations_selector_uq" UNIQUE ("selector")
);
CREATE INDEX "users_confirmations_email_expires_ix" ON "users_confirmations" ("email", "expires");
CREATE INDEX "users_confirmations_user_id_ix" ON "users_confirmations" ("user_id");

CREATE TABLE "users_otps" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	"user_id" INTEGER NOT NULL CHECK ("user_id" >= 0),
	"mechanism" INTEGER NOT NULL CHECK ("mechanism" >= 0),
	"single_factor" INTEGER NOT NULL CHECK ("single_factor" >= 0 AND "single_factor" <= 1) DEFAULT 0,
	"selector" TEXT NOT NULL COLLATE BINARY,
	"token" TEXT NOT NULL COLLATE BINARY,
	"expires_at" INTEGER CHECK ("expires_at" >= 0) DEFAULT NULL
);
CREATE INDEX "users_otps_user_id_mechanism_ix" ON "users_otps" ("user_id", "mechanism");
CREATE INDEX "users_otps_selector_user_id_ix" ON "users_otps" ("selector", "user_id");

CREATE TABLE "users_remembered" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	"user" INTEGER NOT NULL CHECK ("user" >= 0),
	"selector" TEXT NOT NULL COLLATE BINARY,
	"token" TEXT NOT NULL COLLATE BINARY,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0),
	CONSTRAINT "users_remembered_selector_uq" UNIQUE ("selector")
);
CREATE INDEX "users_remembered_user_ix" ON "users_remembered" ("user");

CREATE TABLE "users_resets" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	"user" INTEGER NOT NULL CHECK ("user" >= 0),
	"selector" TEXT NOT NULL COLLATE BINARY,
	"token" TEXT NOT NULL COLLATE BINARY,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0),
	CONSTRAINT "users_resets_selector_uq" UNIQUE ("selector")
);
CREATE INDEX "users_resets_user_expires_ix" ON "users_resets" ("user", "expires");

CREATE TABLE "users_throttling" (
	"bucket" TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
	"tokens" REAL NOT NULL CHECK ("tokens" >= 0),
	"replenished_at" INTEGER NOT NULL CHECK ("replenished_at" >= 0),
	"expires_at" INTEGER NOT NULL CHECK ("expires_at" >= 0)
);
CREATE INDEX "users_throttling_expires_at_ix" ON "users_throttling" ("expires_at");
