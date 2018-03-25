# Migration

 * [General](#general)
 * [From `v7.x.x` to `v8.x.x`](#from-v7xx-to-v8xx)
 * [From `v6.x.x` to `v7.x.x`](#from-v6xx-to-v7xx)
 * [From `v5.x.x` to `v6.x.x`](#from-v5xx-to-v6xx)
 * [From `v4.x.x` to `v5.x.x`](#from-v4xx-to-v5xx)
 * [From `v3.x.x` to `v4.x.x`](#from-v3xx-to-v4xx)
 * [From `v2.x.x` to `v3.x.x`](#from-v2xx-to-v3xx)
 * [From `v1.x.x` to `v2.x.x`](#from-v1xx-to-v2xx)

## General

Update your version of this library using Composer and its `composer update` or `composer require` commands [[?]](https://github.com/delight-im/Knowledge/blob/master/Composer%20(PHP).md#how-do-i-update-libraries-or-modules-within-my-application).

## From `v7.x.x` to `v8.x.x`

 * The database schema has changed.

   * The MySQL database schema has changed. Use the statement below to update your database:

     ```sql
     ALTER TABLE users
         ADD COLUMN `force_logout` mediumint(7) unsigned NOT NULL DEFAULT '0' AFTER `last_login`;
     ```

   * The PostgreSQL database schema has changed. Use the statement below to update your database:

     ```sql
     ALTER TABLE users
         ADD COLUMN "force_logout" INTEGER NOT NULL DEFAULT '0' CHECK ("force_logout" >= 0);
     ```

   * The SQLite database schema has changed. Use the statement below to update your database:

     ```sql
     ALTER TABLE users
         ADD COLUMN "force_logout" INTEGER NOT NULL CHECK ("force_logout" >= 0) DEFAULT "0";
     ```

 * The method `logOutAndDestroySession` has been removed from class `Auth`. Instead, call the two separate methods `logOut` and `destroySession` from class `Auth` one after another for the same effect.

 * If you have been using the return values of the methods `confirmEmail` or `confirmEmailAndSignIn` from class `Auth`, these return values have changed. Instead of only returning the new email address (which has just been verified), both methods now return an array with the old email address (if any) at index zero and the new email address (which has just been verified) at index one.

## From `v6.x.x` to `v7.x.x`

 * The method `logOutButKeepSession` from class `Auth` is now simply called `logOut`. Therefore, the former method `logout` is now called `logOutAndDestroySession`.

 * The second argument of the `Auth` constructor, which was named `$useHttps`, has been removed. If you previously had it set to `true`, make sure to set the value of the `session.cookie_secure` directive to `1` now. You may do so either directly in your [PHP configuration](http://php.net/manual/en/configuration.file.php) (`php.ini`), via the `\ini_set` method or via the `\session_set_cookie_params` method. Otherwise, make sure that directive is set to `0`.

 * The third argument of the `Auth` constructor, which was named `$allowCookiesScriptAccess`, has been removed. If you previously had it set to `true`, make sure to set the value of the `session.cookie_httponly` directive to `0` now. You may do so either directly in your [PHP configuration](http://php.net/manual/en/configuration.file.php) (`php.ini`), via the `\ini_set` method or via the `\session_set_cookie_params` method. Otherwise, make sure that directive is set to `1`.

 * Only if *both* of the following two conditions are met:

   * The directive `session.cookie_domain` is set to an empty value. It may have been set directly in your [PHP configuration](http://php.net/manual/en/configuration.file.php) (`php.ini`), via the `\ini_set` method or via the `\session_set_cookie_params` method. You can check the value of that directive by executing the following statement somewhere in your application:

     ```php
     \var_dump(\ini_get('session.cookie_domain'));
     ```

   * Your application is accessed via a registered or registrable *domain name*, either by yourself during development and testing or by your visitors and users in production. That means your application is *not*, or *not only*, accessed via `localhost` or via an IP address.

   Then the domain scope for the [two cookies](README.md#cookies) used by this library has changed. You can handle this change in one of two different ways:

   * Restore the old behavior by placing the following statement as early as possible in your application, and before you create the `Auth` instance:

     ```php
     \ini_set('session.cookie_domain', \preg_replace('/^www\./', '', $_SERVER['HTTP_HOST']));
     ```

     You may also evaluate the complete second parameter and put its value directly into your [PHP configuration](http://php.net/manual/en/configuration.file.php) (`php.ini`).

   * Use the new domain scope for your application. To do so, you only need to [rename the cookies](README.md#renaming-the-librarys-cookies) used by this library in order to prevent conflicts with old cookies that have been created previously. Renaming the cookies is critically important here. We recommend a versioned name such as `session_v1` for the session cookie.

 * Only if *both* of the following two conditions are met:

   * The directive `session.cookie_domain` is set to a value that starts with the `www` subdomain. It may have been set directly in your [PHP configuration](http://php.net/manual/en/configuration.file.php) (`php.ini`), via the `\ini_set` method or via the `\session_set_cookie_params` method. You can check the value of that directive by executing the following statement somewhere in your application:

     ```php
     \var_dump(\ini_get('session.cookie_domain'));
     ```

   * Your application is accessed via a registered or registrable *domain name*, either by yourself during development and testing or by your visitors and users in production. That means your application is *not*, or *not only*, accessed via `localhost` or via an IP address.

   Then the domain scope for [one of the cookies](README.md#cookies) used by this library has changed. To make your application work correctly with the new scope, [rename the cookies](README.md#renaming-the-librarys-cookies) used by this library in order to prevent conflicts with old cookies that have been created previously. Renaming the cookies is critically important here. We recommend a versioned name such as `session_v1` for the session cookie.

 * If the directive `session.cookie_path` is set to an empty value, then the path scope for [one of the cookies](README.md#cookies) used by this library has changed. To make your application work correctly with the new scope, [rename the cookies](README.md#renaming-the-librarys-cookies) used by this library in order to prevent conflicts with old cookies that have been created previously. Renaming the cookies is critically important here. We recommend a versioned name such as `session_v1` for the session cookie.

   The directive may have been set directly in your [PHP configuration](http://php.net/manual/en/configuration.file.php) (`php.ini`), via the `\ini_set` method or via the `\session_set_cookie_params` method. You can check the value of that directive by executing the following statement somewhere in your application:

   ```php
   \var_dump(\ini_get('session.cookie_path'));
   ```

## From `v5.x.x` to `v6.x.x`

 * The database schema has changed.

   * The MySQL database schema has changed. Use the statements below to update your database:

     ```sql
     ALTER TABLE users
         ADD COLUMN roles_mask INT(10) UNSIGNED NOT NULL DEFAULT 0 AFTER verified,
         ADD COLUMN resettable TINYINT(1) UNSIGNED NOT NULL DEFAULT 1 AFTER verified;

     ALTER TABLE users_confirmations
         ADD COLUMN user_id INT(10) UNSIGNED NULL DEFAULT NULL AFTER id;

     UPDATE users_confirmations SET user_id = (
         SELECT id FROM users WHERE email = users_confirmations.email
     ) WHERE user_id IS NULL;

     ALTER TABLE users_confirmations
         CHANGE COLUMN user_id user_id INT(10) UNSIGNED NOT NULL;

     ALTER TABLE users_confirmations
         ADD INDEX user_id (user_id ASC);

     DROP TABLE users_throttling;

     CREATE TABLE users_throttling (
         bucket varchar(44) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
         tokens float unsigned NOT NULL,
         replenished_at int(10) unsigned NOT NULL,
         expires_at int(10) unsigned NOT NULL,
         PRIMARY KEY (bucket),
         KEY expires_at (expires_at)
     ) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
     ```

   * The SQLite database schema has changed. Use the statements below to update your database:

     ```sql
     ALTER TABLE users
         ADD COLUMN "roles_mask" INTEGER NOT NULL CHECK ("roles_mask" >= 0) DEFAULT "0",
         ADD COLUMN "resettable" INTEGER NOT NULL CHECK ("resettable" >= 0) DEFAULT "1";

     ALTER TABLE users_confirmations
         ADD COLUMN "user_id" INTEGER CHECK ("user_id" >= 0);

     UPDATE users_confirmations SET user_id = (
         SELECT id FROM users WHERE email = users_confirmations.email
     ) WHERE user_id IS NULL;

     CREATE INDEX "users_confirmations.user_id" ON "users_confirmations" ("user_id");

     DROP TABLE users_throttling;

     CREATE TABLE "users_throttling" (
         "bucket" VARCHAR(44) PRIMARY KEY NOT NULL,
         "tokens" REAL NOT NULL CHECK ("tokens" >= 0),
         "replenished_at" INTEGER NOT NULL CHECK ("replenished_at" >= 0),
         "expires_at" INTEGER NOT NULL CHECK ("expires_at" >= 0)
     );

     CREATE INDEX "users_throttling.expires_at" ON "users_throttling" ("expires_at");
     ```

 * The method `setThrottlingOptions` has been removed.

 * The method `changePassword` may now throw an additional `\Delight\Auth\TooManyRequestsException` if too many attempts have been made without the correct old password.

 * The two methods `confirmEmail` and `confirmEmailAndSignIn` may now throw an additional `\Delight\Auth\UserAlreadyExistsException` if an attempt has been made to change the email address to an address that has become occupied in the meantime.

 * The two methods `forgotPassword` and `resetPassword` may now throw an additional `\Delight\Auth\ResetDisabledException` if the user has disabled password resets for their account.

 * The `Base64` class is now an external module and has been moved from the namespace `Delight\Auth` to the namespace `Delight\Base64`. The interface and the return values are not compatible with those from previous versions anymore.

## From `v4.x.x` to `v5.x.x`

 * The MySQL database schema has changed. Use the statement below to update your database:

   ```sql
   ALTER TABLE `users` ADD COLUMN `status` TINYINT(2) UNSIGNED NOT NULL DEFAULT 0 AFTER `username`;
   ```

 * The two classes `Auth` and `Base64` are now `final`, i.e. they can't be extended anymore, which has never been a good idea, anyway. If you still need to wrap your own methods around these classes, consider [object composition instead of class inheritance](https://en.wikipedia.org/wiki/Composition_over_inheritance).

## From `v3.x.x` to `v4.x.x`

 * PHP 5.6.0 or higher is now required.

## From `v2.x.x` to `v3.x.x`

 * The license has been changed from the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0) to the [MIT License](https://opensource.org/licenses/MIT).

## From `v1.x.x` to `v2.x.x`

 * The MySQL schema has been changed from charset `utf8` to charset `utf8mb4` and from collation `utf8_general_ci` to collation `utf8mb4_unicode_ci`. Use the statements below to update the database schema:

   ```sql
   ALTER TABLE `users` CHANGE `email` `email` VARCHAR(249) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL;
   ALTER TABLE `users_confirmations` CHANGE `email` `email` VARCHAR(249) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL;

   -- ALTER DATABASE `<DATABASE_NAME>` CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

   ALTER TABLE `users` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ALTER TABLE `users_confirmations` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ALTER TABLE `users_remembered` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ALTER TABLE `users_resets` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ALTER TABLE `users_throttling` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

   ALTER TABLE `users` CHANGE `email` `email` VARCHAR(249) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL;
   ALTER TABLE `users` CHANGE `username` `username` VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL;

   ALTER TABLE `users_confirmations` CHANGE `email` `email` VARCHAR(249) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL;

   ALTER TABLE `users_throttling` CHANGE `action_type` `action_type` ENUM('login','register','confirm_email') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL;

   REPAIR TABLE users;
   OPTIMIZE TABLE users;
   REPAIR TABLE users_confirmations;
   OPTIMIZE TABLE users_confirmations;
   REPAIR TABLE users_remembered;
   OPTIMIZE TABLE users_remembered;
   REPAIR TABLE users_resets;
   OPTIMIZE TABLE users_resets;
   REPAIR TABLE users_throttling;
   OPTIMIZE TABLE users_throttling;
   ```
