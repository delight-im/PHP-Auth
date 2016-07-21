# Migration

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

## From `v2.x.x` to `v3.x.x`

 * The license has been changed from the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0) to the [MIT License](https://opensource.org/licenses/MIT).
