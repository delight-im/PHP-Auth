-- PHP-Auth (https://github.com/delight-im/PHP-Auth)
-- Copyright (c) delight.im (https://www.delight.im/)
-- Licensed under the MIT License (https://opensource.org/licenses/MIT)

PRAGMA foreign_keys = OFF;

CREATE TABLE "users" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL CHECK ("id" >= 0),
	"email" VARCHAR(249) NOT NULL,
	"password" VARCHAR(255) NOT NULL,
	"username" VARCHAR(100) DEFAULT NULL,
	"status" INTEGER NOT NULL CHECK ("status" >= 0) DEFAULT "0",
	"verified" INTEGER NOT NULL CHECK ("verified" >= 0) DEFAULT "0",
	"resettable" INTEGER NOT NULL CHECK ("resettable" >= 0) DEFAULT "1",
	"roles_mask" INTEGER NOT NULL CHECK ("roles_mask" >= 0) DEFAULT "0",
	"registered" INTEGER NOT NULL CHECK ("registered" >= 0),
	"last_login" INTEGER CHECK ("last_login" >= 0) DEFAULT NULL,
	"force_logout" INTEGER NOT NULL CHECK ("force_logout" >= 0) DEFAULT "0",
	CONSTRAINT "email" UNIQUE ("email")
);

CREATE TABLE "users_confirmations" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL CHECK ("id" >= 0),
	"user_id" INTEGER NOT NULL CHECK ("user_id" >= 0),
	"email" VARCHAR(249) NOT NULL,
	"selector" VARCHAR(16) NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0),
	CONSTRAINT "selector" UNIQUE ("selector")
);
CREATE INDEX "users_confirmations.email_expires" ON "users_confirmations" ("email", "expires");
CREATE INDEX "users_confirmations.user_id" ON "users_confirmations" ("user_id");

CREATE TABLE "users_remembered" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL CHECK ("id" >= 0),
	"user" INTEGER NOT NULL CHECK ("user" >= 0),
	"selector" VARCHAR(24) NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0),
	CONSTRAINT "selector" UNIQUE ("selector")
);
CREATE INDEX "users_remembered.user" ON "users_remembered" ("user");

CREATE TABLE "users_resets" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL CHECK ("id" >= 0),
	"user" INTEGER NOT NULL CHECK ("user" >= 0),
	"selector" VARCHAR(20) NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0),
	CONSTRAINT "selector" UNIQUE ("selector")
);
CREATE INDEX "users_resets.user_expires" ON "users_resets" ("user", "expires");

CREATE TABLE "users_throttling" (
	"bucket" VARCHAR(44) PRIMARY KEY NOT NULL,
	"tokens" REAL NOT NULL CHECK ("tokens" >= 0),
	"replenished_at" INTEGER NOT NULL CHECK ("replenished_at" >= 0),
	"expires_at" INTEGER NOT NULL CHECK ("expires_at" >= 0)
);
CREATE INDEX "users_throttling.expires_at" ON "users_throttling" ("expires_at");
