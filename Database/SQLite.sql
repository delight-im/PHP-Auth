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
	"roles_mask" INTEGER NOT NULL CHECK ("roles_mask" >= 0) DEFAULT "0",
	"registered" INTEGER NOT NULL CHECK ("registered" >= 0),
	"last_login" INTEGER CHECK ("last_login" >= 0) DEFAULT NULL,
	CONSTRAINT "email" UNIQUE ("email")
);

CREATE TABLE "users_confirmations" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL CHECK ("id" >= 0),
	"email" VARCHAR(249) NOT NULL,
	"selector" VARCHAR(16) NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0),
	CONSTRAINT "selector" UNIQUE ("selector")
);
CREATE INDEX "users_confirmations.email_expires" ON "users_confirmations" ("email", "expires");

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
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL CHECK ("id" >= 0),
	"action_type" TEXT NOT NULL CHECK ("action_type" IN ("login", "register", "confirm_email")),
	"selector" VARCHAR(44) DEFAULT NULL,
	"time_bucket" INTEGER NOT NULL CHECK ("time_bucket" >= 0),
	"attempts" INTEGER NOT NULL CHECK ("attempts" >= 0) DEFAULT "1",
	CONSTRAINT "action_type_selector_time_bucket" UNIQUE ("action_type", "selector", "time_bucket")
);
