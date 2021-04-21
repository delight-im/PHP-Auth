# Auth

**Authentication for PHP. Simple, lightweight and secure.**

Written once, to be used everywhere.

Completely framework-agnostic and database-agnostic.

## Why do I need this?

 * There are [tons](https://www.troyhunt.com/whos-who-of-bad-password-practices/) [of](https://blog.codinghorror.com/password-rules-are-bullshit/) [websites](https://badpasswordpolicies.tumblr.com/) with weak authentication systems. Don’t build such a site.
 * Re-implementing a new authentication system for every PHP project is *not* a good idea.
 * Building your own authentication classes piece by piece, and copying it to every project, is *not* recommended, either.
 * A secure authentication system with an easy-to-use API should be thoroughly designed and planned.
 * Peer-review for your critical infrastructure is *a must*.

## Requirements

 * PHP 5.6.0+
   * PDO (PHP Data Objects) extension (`pdo`)
     * MySQL Native Driver (`mysqlnd`) **or** PostgreSQL driver (`pgsql`) **or** SQLite driver (`sqlite`)
   * OpenSSL extension (`openssl`)
 * MySQL 5.5.3+ **or** MariaDB 5.5.23+ **or** PostgreSQL 9.5.10+ **or** SQLite 3.14.1+ **or** [other SQL databases](Database)

## Installation

 1. Include the library via Composer [[?]](https://github.com/delight-im/Knowledge/blob/master/Composer%20(PHP).md):

    ```
    $ composer require delight-im/auth
    ```

 1. Include the Composer autoloader:

    ```php
    require __DIR__ . '/vendor/autoload.php';
    ```

 1. Set up a database and create the required tables:

    * [MariaDB](Database/MySQL.sql)
    * [MySQL](Database/MySQL.sql)
    * [PostgreSQL](Database/PostgreSQL.sql)
    * [SQLite](Database/SQLite.sql)

## Upgrading

Migrating from an earlier version of this project? See our [upgrade guide](Migration.md) for help.

## Usage

 * [Creating a new instance](#creating-a-new-instance)
 * [Registration (sign up)](#registration-sign-up)
 * [Login (sign in)](#login-sign-in)
 * [Email verification](#email-verification)
 * [Keeping the user logged in](#keeping-the-user-logged-in)
 * [Password reset (“forgot password”)](#password-reset-forgot-password)
   * [Initiating the request](#step-1-of-3-initiating-the-request)
   * [Verifying an attempt](#step-2-of-3-verifying-an-attempt)
   * [Updating the password](#step-3-of-3-updating-the-password)
 * [Changing the current user’s password](#changing-the-current-users-password)
 * [Changing the current user’s email address](#changing-the-current-users-email-address)
 * [Re-sending confirmation requests](#re-sending-confirmation-requests)
 * [Logout](#logout)
 * [Accessing user information](#accessing-user-information)
   * [Login state](#login-state)
   * [User ID](#user-id)
   * [Email address](#email-address)
   * [Display name](#display-name)
   * [Status information](#status-information)
   * [Checking whether the user was “remembered”](#checking-whether-the-user-was-remembered)
   * [IP address](#ip-address)
   * [Additional user information](#additional-user-information)
 * [Reconfirming the user’s password](#reconfirming-the-users-password)
 * [Roles (or groups)](#roles-or-groups)
   * [Checking roles](#checking-roles)
   * [Available roles](#available-roles)
   * [Permissions (or access rights, privileges or capabilities)](#permissions-or-access-rights-privileges-or-capabilities)
   * [Custom role names](#custom-role-names)
 * [Enabling or disabling password resets](#enabling-or-disabling-password-resets)
 * [Throttling or rate limiting](#throttling-or-rate-limiting)
 * [Administration (managing users)](#administration-managing-users)
   * [Creating new users](#creating-new-users)
   * [Deleting users](#deleting-users)
   * [Assigning roles to users](#assigning-roles-to-users)
   * [Taking roles away from users](#taking-roles-away-from-users)
   * [Checking roles](#checking-roles-1)
   * [Impersonating users (logging in as user)](#impersonating-users-logging-in-as-user)
   * [Changing a user’s password](#changing-a-users-password)
 * [Cookies](#cookies)
   * [Renaming the library’s cookies](#renaming-the-librarys-cookies)
   * [Defining the domain scope for cookies](#defining-the-domain-scope-for-cookies)
   * [Restricting the path where cookies are available](#restricting-the-path-where-cookies-are-available)
   * [Controlling client-side script access to cookies](#controlling-client-side-script-access-to-cookies)
   * [Configuring transport security for cookies](#configuring-transport-security-for-cookies)
 * [Utilities](#utilities)
   * [Creating a random string](#creating-a-random-string)
   * [Creating a UUID v4 as per RFC 4122](#creating-a-uuid-v4-as-per-rfc-4122)
 * [Reading and writing session data](#reading-and-writing-session-data)

### Creating a new instance

```php
// $db = new \PDO('mysql:dbname=my-database;host=localhost;charset=utf8mb4', 'my-username', 'my-password');
// or
// $db = new \PDO('pgsql:dbname=my-database;host=localhost;port=5432', 'my-username', 'my-password');
// or
// $db = new \PDO('sqlite:../Databases/my-database.sqlite');

// or

// $db = \Delight\Db\PdoDatabase::fromDsn(new \Delight\Db\PdoDsn('mysql:dbname=my-database;host=localhost;charset=utf8mb4', 'my-username', 'my-password'));
// or
// $db = \Delight\Db\PdoDatabase::fromDsn(new \Delight\Db\PdoDsn('pgsql:dbname=my-database;host=localhost;port=5432', 'my-username', 'my-password'));
// or
// $db = \Delight\Db\PdoDatabase::fromDsn(new \Delight\Db\PdoDsn('sqlite:../Databases/my-database.sqlite'));

$auth = new \Delight\Auth\Auth($db);
```

If you have an open `PDO` connection already, just re-use it. The database user (e.g. `my-username`) needs at least the privileges `SELECT`, `INSERT`, `UPDATE` and `DELETE` for the tables used by this library (or their parent database).

If your web server is behind a proxy server and `$_SERVER['REMOTE_ADDR']` only contains the proxy’s IP address, you must pass the user’s real IP address to the constructor in the second argument, which is named `$ipAddress`. The default is the usual remote IP address received by PHP.

Should your database tables for this library need a common prefix, e.g. `my_users` instead of `users` (and likewise for the other tables), pass the prefix (e.g. `my_`) as the third parameter to the constructor, which is named `$dbTablePrefix`. This is optional and the prefix is empty by default.

During development, you may want to disable the request limiting or throttling performed by this library. To do so, pass `false` to the constructor as the fourth argument, which is named `$throttling`. The feature is enabled by default.

During the lifetime of a session, some user data may be changed remotely, either by a client in another session or by an administrator. That means this information must be regularly resynchronized with its authoritative source in the database, which this library does automatically. By default, this happens every five minutes. If you want to change this interval, pass a custom interval in seconds to the constructor as the fifth argument, which is named `$sessionResyncInterval`.

If all your database tables need a common database name, schema name, or other qualifier that must be specified explicitly, you can optionally pass that qualifier to the constructor as the sixth parameter, which is named `$dbSchema`.

If you want to use a `PdoDatabase` instance (e.g. `$db`) independently as well, please refer to the [documentation of the database library](https://github.com/delight-im/PHP-DB).

### Registration (sign up)

```php
try {
    $userId = $auth->register($_POST['email'], $_POST['password'], $_POST['username'], function ($selector, $token) {
        echo 'Send ' . $selector . ' and ' . $token . ' to the user (e.g. via email)';
    });

    echo 'We have signed up a new user with the ID ' . $userId;
}
catch (\Delight\Auth\InvalidEmailException $e) {
    die('Invalid email address');
}
catch (\Delight\Auth\InvalidPasswordException $e) {
    die('Invalid password');
}
catch (\Delight\Auth\UserAlreadyExistsException $e) {
    die('User already exists');
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    die('Too many requests');
}
```

**Note:** The anonymous callback function is a [closure](https://www.php.net/manual/functions.anonymous.php). Thus, besides its own parameters, only [superglobals](https://www.php.net/manual/language.variables.superglobals.php) like `$_GET`, `$_POST`, `$_COOKIE` and `$_SERVER` are available inside. For any other variable from the parent scope, you need to explicitly make a copy available inside by adding a `use` clause after the parameter list.

The username in the third parameter is optional. You can pass `null` there if you don’t want to manage usernames.

If you want to enforce unique usernames, on the other hand, simply call `registerWithUniqueUsername` instead of `register`, and be prepared to catch the `DuplicateUsernameException`.

**Note:** When accepting and managing usernames, you may want to exclude non-printing control characters and certain printable special characters, as in the character class `[\x00-\x1f\x7f\/:\\]`. In order to do so, you could wrap the call to `Auth#register` or `Auth#registerWithUniqueUsername` inside a conditional branch, for example by only accepting usernames when the following condition is satisfied:

```php
if (\preg_match('/[\x00-\x1f\x7f\/:\\\\]/', $username) === 0) {
    // ...
}
```

For email verification, you should build an URL with the selector and token and send it to the user, e.g.:

```php
$url = 'https://www.example.com/verify_email?selector=' . \urlencode($selector) . '&token=' . \urlencode($token);
```

If you don’t want to perform email verification, just omit the last parameter to `Auth#register`. The new user will be active immediately, then.

Need to store additional user information? Read on [here](#additional-user-information).

**Note:** When sending an email to the user, please note that the (optional) username, at this point, has not yet been confirmed as acceptable to the owner of the (new) email address. It could contain offensive or misleading language chosen by someone who is not actually the owner of the address.

### Login (sign in)

```php
try {
    $auth->login($_POST['email'], $_POST['password']);

    echo 'User is logged in';
}
catch (\Delight\Auth\InvalidEmailException $e) {
    die('Wrong email address');
}
catch (\Delight\Auth\InvalidPasswordException $e) {
    die('Wrong password');
}
catch (\Delight\Auth\EmailNotVerifiedException $e) {
    die('Email not verified');
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    die('Too many requests');
}
```

If you want to sign in with usernames on the other hand, either in addition to the login via email address or as a replacement, that’s possible as well. Simply call the method `loginWithUsername` instead of method `login`. Then, instead of catching `InvalidEmailException`, make sure to catch both `UnknownUsernameException` and `AmbiguousUsernameException`. You may also want to read the notes about the uniqueness of usernames in the section that explains how to [sign up new users](#registration-sign-up).

### Email verification

Extract the selector and token from the URL that the user clicked on in the verification email.

```php
try {
    $auth->confirmEmail($_GET['selector'], $_GET['token']);

    echo 'Email address has been verified';
}
catch (\Delight\Auth\InvalidSelectorTokenPairException $e) {
    die('Invalid token');
}
catch (\Delight\Auth\TokenExpiredException $e) {
    die('Token expired');
}
catch (\Delight\Auth\UserAlreadyExistsException $e) {
    die('Email address already exists');
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    die('Too many requests');
}
```

If you want the user to be automatically signed in after successful confirmation, just call `confirmEmailAndSignIn` instead of `confirmEmail`. That alternative method also supports [persistent logins](#keeping-the-user-logged-in) via its optional third parameter.

On success, the two methods `confirmEmail` and `confirmEmailAndSignIn` both return an array with the user’s new email address, which has just been verified, at index one. If the confirmation was for an address change instead of a simple address verification, the user’s old email address will be included in the array at index zero.

### Keeping the user logged in

The third parameter to the `Auth#login` and `Auth#confirmEmailAndSignIn` methods controls whether the login is persistent with a long-lived cookie. With such a persistent login, users may stay authenticated for a long time, even when the browser session has already been closed and the session cookies have expired. Typically, you’ll want to keep the user logged in for weeks or months with this feature, which is known as “remember me” or “keep me logged in”. Many users will find this more convenient, but it may be less secure if they leave their devices unattended.

```php
if ($_POST['remember'] == 1) {
    // keep logged in for one year
    $rememberDuration = (int) (60 * 60 * 24 * 365.25);
}
else {
    // do not keep logged in after session ends
    $rememberDuration = null;
}

// ...

$auth->login($_POST['email'], $_POST['password'], $rememberDuration);

// ...
```

*Without* the persistent login, which is the *default* behavior, a user will only stay logged in until they close their browser, or as long as configured via `session.cookie_lifetime` and `session.gc_maxlifetime` in PHP.

Omit the third parameter or set it to `null` to disable the feature. Otherwise, you may ask the user whether they want to enable “remember me”. This is usually done with a checkbox in your user interface. Use the input from that checkbox to decide between `null` and a pre-defined duration in seconds here, e.g. `60 * 60 * 24 * 365.25` for one year.

### Password reset (“forgot password”)

#### Step 1 of 3: Initiating the request

```php
try {
    $auth->forgotPassword($_POST['email'], function ($selector, $token) {
        echo 'Send ' . $selector . ' and ' . $token . ' to the user (e.g. via email)';
    });

    echo 'Request has been generated';
}
catch (\Delight\Auth\InvalidEmailException $e) {
    die('Invalid email address');
}
catch (\Delight\Auth\EmailNotVerifiedException $e) {
    die('Email not verified');
}
catch (\Delight\Auth\ResetDisabledException $e) {
    die('Password reset is disabled');
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    die('Too many requests');
}
```

**Note:** The anonymous callback function is a [closure](https://www.php.net/manual/functions.anonymous.php). Thus, besides its own parameters, only [superglobals](https://www.php.net/manual/language.variables.superglobals.php) like `$_GET`, `$_POST`, `$_COOKIE` and `$_SERVER` are available inside. For any other variable from the parent scope, you need to explicitly make a copy available inside by adding a `use` clause after the parameter list.

You should build an URL with the selector and token and send it to the user, e.g.:

```php
$url = 'https://www.example.com/reset_password?selector=' . \urlencode($selector) . '&token=' . \urlencode($token);
```

If the default lifetime of the password reset requests does not work for you, you can use the third parameter of `Auth#forgotPassword` to specify a custom interval in seconds after which the requests should expire.

#### Step 2 of 3: Verifying an attempt

As the next step, users will click on the link that they received. Extract the selector and token from the URL.

If the selector/token pair is valid, let the user choose a new password:

```php
try {
    $auth->canResetPasswordOrThrow($_GET['selector'], $_GET['token']);

    echo 'Put the selector into a "hidden" field (or keep it in the URL)';
    echo 'Put the token into a "hidden" field (or keep it in the URL)';

    echo 'Ask the user for their new password';
}
catch (\Delight\Auth\InvalidSelectorTokenPairException $e) {
    die('Invalid token');
}
catch (\Delight\Auth\TokenExpiredException $e) {
    die('Token expired');
}
catch (\Delight\Auth\ResetDisabledException $e) {
    die('Password reset is disabled');
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    die('Too many requests');
}
```

Alternatively, if you don’t need any error messages but only want to check the validity, you can use the slightly simpler version:

```php
if ($auth->canResetPassword($_GET['selector'], $_GET['token'])) {
    echo 'Put the selector into a "hidden" field (or keep it in the URL)';
    echo 'Put the token into a "hidden" field (or keep it in the URL)';

    echo 'Ask the user for their new password';
}
```

#### Step 3 of 3: Updating the password

Now when you have the new password for the user (and still have the other two pieces of information), you can reset the password:

```php
try {
    $auth->resetPassword($_POST['selector'], $_POST['token'], $_POST['password']);

    echo 'Password has been reset';
}
catch (\Delight\Auth\InvalidSelectorTokenPairException $e) {
    die('Invalid token');
}
catch (\Delight\Auth\TokenExpiredException $e) {
    die('Token expired');
}
catch (\Delight\Auth\ResetDisabledException $e) {
    die('Password reset is disabled');
}
catch (\Delight\Auth\InvalidPasswordException $e) {
    die('Invalid password');
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    die('Too many requests');
}
```

Do you want to have the respective user signed in automatically when their password reset succeeds? Simply use `Auth#resetPasswordAndSignIn` instead of `Auth#resetPassword` to log in the user immediately.

If you need the user’s ID or email address, e.g. for sending them a notification that their password has successfully been reset, just use the return value of `Auth#resetPassword`, which is an array containing two entries named `id` and `email`.

### Changing the current user’s password

If a user is currently logged in, they may change their password.

```php
try {
    $auth->changePassword($_POST['oldPassword'], $_POST['newPassword']);

    echo 'Password has been changed';
}
catch (\Delight\Auth\NotLoggedInException $e) {
    die('Not logged in');
}
catch (\Delight\Auth\InvalidPasswordException $e) {
    die('Invalid password(s)');
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    die('Too many requests');
}
```

Asking the user for their current (and soon *old*) password and requiring it for verification is the recommended way to handle password changes. This is shown above.

If you’re sure that you don’t need that confirmation, however, you may call `changePasswordWithoutOldPassword` instead of `changePassword` and drop the first parameter from that method call (which would otherwise contain the old password).

In any case, after the user’s password has been changed, you should send an email to their account’s primary email address as an out-of-band notification informing the account owner about this critical change.

### Changing the current user’s email address

If a user is currently logged in, they may change their email address.

```php
try {
    if ($auth->reconfirmPassword($_POST['password'])) {
        $auth->changeEmail($_POST['newEmail'], function ($selector, $token) {
            echo 'Send ' . $selector . ' and ' . $token . ' to the user (e.g. via email to the *new* address)';
        });

        echo 'The change will take effect as soon as the new email address has been confirmed';
    }
    else {
        echo 'We can\'t say if the user is who they claim to be';
    }
}
catch (\Delight\Auth\InvalidEmailException $e) {
    die('Invalid email address');
}
catch (\Delight\Auth\UserAlreadyExistsException $e) {
    die('Email address already exists');
}
catch (\Delight\Auth\EmailNotVerifiedException $e) {
    die('Account not verified');
}
catch (\Delight\Auth\NotLoggedInException $e) {
    die('Not logged in');
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    die('Too many requests');
}
```

**Note:** The anonymous callback function is a [closure](https://www.php.net/manual/functions.anonymous.php). Thus, besides its own parameters, only [superglobals](https://www.php.net/manual/language.variables.superglobals.php) like `$_GET`, `$_POST`, `$_COOKIE` and `$_SERVER` are available inside. For any other variable from the parent scope, you need to explicitly make a copy available inside by adding a `use` clause after the parameter list.

For email verification, you should build an URL with the selector and token and send it to the user, e.g.:

```php
$url = 'https://www.example.com/verify_email?selector=' . \urlencode($selector) . '&token=' . \urlencode($token);
```

**Note:** When sending an email to the user, please note that the (optional) username, at this point, has not yet been confirmed as acceptable to the owner of the (new) email address. It could contain offensive or misleading language chosen by someone who is not actually the owner of the address.

After the request to change the email address has been made, or even better, after the change has been confirmed by the user, you should send an email to their account’s *previous* email address as an out-of-band notification informing the account owner about this critical change.

**Note:** Changes to a user’s email address take effect in the local session immediately, as expected. In other sessions (e.g. on other devices), the changes may need up to five minutes to take effect, though. This increases performance and usually poses no problem. If you want to change this behavior, nevertheless, simply decrease (or perhaps increase) the value that you pass to the [`Auth` constructor](#creating-a-new-instance) as the argument named `$sessionResyncInterval`.

### Re-sending confirmation requests

If an earlier confirmation request could not be delivered to the user, or if the user missed that request, or if they just don’t want to wait any longer, you may re-send an earlier request like this:

```php
try {
    $auth->resendConfirmationForEmail($_POST['email'], function ($selector, $token) {
        echo 'Send ' . $selector . ' and ' . $token . ' to the user (e.g. via email)';
    });

    echo 'The user may now respond to the confirmation request (usually by clicking a link)';
}
catch (\Delight\Auth\ConfirmationRequestNotFound $e) {
    die('No earlier request found that could be re-sent');
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    die('There have been too many requests -- try again later');
}
```

If you want to specify the user by their ID instead of by their email address, this is possible as well:

```php
try {
    $auth->resendConfirmationForUserId($_POST['userId'], function ($selector, $token) {
        echo 'Send ' . $selector . ' and ' . $token . ' to the user (e.g. via email)';
    });

    echo 'The user may now respond to the confirmation request (usually by clicking a link)';
}
catch (\Delight\Auth\ConfirmationRequestNotFound $e) {
    die('No earlier request found that could be re-sent');
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    die('There have been too many requests -- try again later');
}
```

**Note:** The anonymous callback function is a [closure](https://www.php.net/manual/functions.anonymous.php). Thus, besides its own parameters, only [superglobals](https://www.php.net/manual/language.variables.superglobals.php) like `$_GET`, `$_POST`, `$_COOKIE` and `$_SERVER` are available inside. For any other variable from the parent scope, you need to explicitly make a copy available inside by adding a `use` clause after the parameter list.

Usually, you should build an URL with the selector and token and send it to the user, e.g. as follows:

```php
$url = 'https://www.example.com/verify_email?selector=' . \urlencode($selector) . '&token=' . \urlencode($token);
```

**Note:** When sending an email to the user, please note that the (optional) username, at this point, has not yet been confirmed as acceptable to the owner of the (new) email address. It could contain offensive or misleading language chosen by someone who is not actually the owner of the address.

### Logout

```php
$auth->logOut();

// or

try {
    $auth->logOutEverywhereElse();
}
catch (\Delight\Auth\NotLoggedInException $e) {
    die('Not logged in');
}

// or

try {
    $auth->logOutEverywhere();
}
catch (\Delight\Auth\NotLoggedInException $e) {
    die('Not logged in');
}
```

Additionally, if you store custom information in the session as well, and if you want that information to be deleted, you can destroy the entire session by calling a second method:

```php
$auth->destroySession();
```

**Note:** Global logouts take effect in the local session immediately, as expected. In other sessions (e.g. on other devices), the changes may need up to five minutes to take effect, though. This increases performance and usually poses no problem. If you want to change this behavior, nevertheless, simply decrease (or perhaps increase) the value that you pass to the [`Auth` constructor](#creating-a-new-instance) as the argument named `$sessionResyncInterval`.

### Accessing user information

#### Login state

```php
if ($auth->isLoggedIn()) {
    echo 'User is signed in';
}
else {
    echo 'User is not signed in yet';
}
```

A shorthand/alias for this method is `$auth->check()`.

#### User ID

```php
$id = $auth->getUserId();
```

If the user is not currently signed in, this returns `null`.

A shorthand/alias for this method is `$auth->id()`.

#### Email address

```php
$email = $auth->getEmail();
```

If the user is not currently signed in, this returns `null`.

#### Display name

```php
$username = $auth->getUsername();
```

Remember that usernames are optional and there is only a username if you supplied it during registration.

If the user is not currently signed in, this returns `null`.

#### Status information

```php
if ($auth->isNormal()) {
    echo 'User is in default state';
}

if ($auth->isArchived()) {
    echo 'User has been archived';
}

if ($auth->isBanned()) {
    echo 'User has been banned';
}

if ($auth->isLocked()) {
    echo 'User has been locked';
}

if ($auth->isPendingReview()) {
    echo 'User is pending review';
}

if ($auth->isSuspended()) {
    echo 'User has been suspended';
}
```

#### Checking whether the user was “remembered”

```php
if ($auth->isRemembered()) {
    echo 'User did not sign in but was logged in through their long-lived cookie';
}
else {
    echo 'User signed in manually';
}
```

If the user is not currently signed in, this returns `null`.

#### IP address

```php
$ip = $auth->getIpAddress();
```

#### Additional user information

In order to preserve this library’s suitability for all purposes as well as its full re-usability, it doesn’t come with additional bundled columns for user information. But you don’t have to do without additional user information, of course:

Here’s how to use this library with your own tables for custom user information in a maintainable and re-usable way:

 1. Add any number of custom database tables where you store custom user information, e.g. a table named `profiles`.
 1. Whenever you call the `register` method (which returns the new user’s ID), add your own logic afterwards that fills your custom database tables.
 1. If you need the custom user information only rarely, you may just retrieve it as needed. If you need it more frequently, however, you’d probably want to have it in your session data. The following method is how you can load and access your data in a reliable way:

    ```php
    function getUserInfo(\Delight\Auth\Auth $auth) {
        if (!$auth->isLoggedIn()) {
            return null;
        }

        if (!isset($_SESSION['_internal_user_info'])) {
            // TODO: load your custom user information and assign it to the session variable below
            // $_SESSION['_internal_user_info'] = ...
        }

        return $_SESSION['_internal_user_info'];
    }
    ```

### Reconfirming the user’s password

Whenever you want to confirm the user’s identity again, e.g. before the user is allowed to perform some “dangerous” action, you should verify their password again to confirm that they actually are who they claim to be.

For example, when a user has been remembered by a long-lived cookie and thus `Auth#isRemembered` returns `true`, this means that the user probably has not entered their password for quite some time anymore. You may want to reconfirm their password in that case.

```php
try {
    if ($auth->reconfirmPassword($_POST['password'])) {
        echo 'The user really seems to be who they claim to be';
    }
    else {
        echo 'We can\'t say if the user is who they claim to be';
    }
}
catch (\Delight\Auth\NotLoggedInException $e) {
    die('The user is not signed in');
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    die('Too many requests');
}
```

### Roles (or groups)

Every user can have any number of roles, which you can use to implement authorization and to refine your access controls.

Users may have no role at all (which they do by default), exactly one role, or any arbitrary combination of roles.

#### Checking roles

```php
if ($auth->hasRole(\Delight\Auth\Role::SUPER_MODERATOR)) {
    echo 'The user is a super moderator';
}

// or

if ($auth->hasAnyRole(\Delight\Auth\Role::DEVELOPER, \Delight\Auth\Role::MANAGER)) {
    echo 'The user is either a developer, or a manager, or both';
}

// or

if ($auth->hasAllRoles(\Delight\Auth\Role::DEVELOPER, \Delight\Auth\Role::MANAGER)) {
    echo 'The user is both a developer and a manager';
}
```

While the method `hasRole` takes exactly one role as its argument, the two methods `hasAnyRole` and `hasAllRoles` can take any number of roles that you would like to check for.

Alternatively, you can get a list of all the roles that have been assigned to the user:

```php
$auth->getRoles();
```

#### Available roles

```php
\Delight\Auth\Role::ADMIN;
\Delight\Auth\Role::AUTHOR;
\Delight\Auth\Role::COLLABORATOR;
\Delight\Auth\Role::CONSULTANT;
\Delight\Auth\Role::CONSUMER;
\Delight\Auth\Role::CONTRIBUTOR;
\Delight\Auth\Role::COORDINATOR;
\Delight\Auth\Role::CREATOR;
\Delight\Auth\Role::DEVELOPER;
\Delight\Auth\Role::DIRECTOR;
\Delight\Auth\Role::EDITOR;
\Delight\Auth\Role::EMPLOYEE;
\Delight\Auth\Role::MAINTAINER;
\Delight\Auth\Role::MANAGER;
\Delight\Auth\Role::MODERATOR;
\Delight\Auth\Role::PUBLISHER;
\Delight\Auth\Role::REVIEWER;
\Delight\Auth\Role::SUBSCRIBER;
\Delight\Auth\Role::SUPER_ADMIN;
\Delight\Auth\Role::SUPER_EDITOR;
\Delight\Auth\Role::SUPER_MODERATOR;
\Delight\Auth\Role::TRANSLATOR;
```

You can use any of these roles and ignore those that you don’t need. The list above can also be retrieved programmatically, in one of three formats:

```php
\Delight\Auth\Role::getMap();
// or
\Delight\Auth\Role::getNames();
// or
\Delight\Auth\Role::getValues();
```

#### Permissions (or access rights, privileges or capabilities)

The permissions of each user are encoded in the way that role requirements are specified throughout your code base. If those requirements are evaluated with a specific user’s set of roles, implicitly checked permissions are the result.

For larger projects, it is often recommended to maintain the definition of permissions in a single place. You then don’t check for *roles* in your business logic, but you check for *individual permissions*. You could implement that concept as follows:

```php
function canEditArticle(\Delight\Auth\Auth $auth) {
    return $auth->hasAnyRole(
        \Delight\Auth\Role::MODERATOR,
        \Delight\Auth\Role::SUPER_MODERATOR,
        \Delight\Auth\Role::ADMIN,
        \Delight\Auth\Role::SUPER_ADMIN
    );
}

// ...

if (canEditArticle($auth)) {
    echo 'The user can edit articles here';
}

// ...

if (canEditArticle($auth)) {
    echo '... and here';
}

// ...

if (canEditArticle($auth)) {
    echo '... and here';
}
```

As you can see, the permission of whether a certain user can edit an article is stored at a central location. This implementation has two major advantages:

If you *want to know* which users can edit articles, you don’t have to check your business logic in various places, but you only have to look where the specific permission is defined. And if you want to *change* who can edit an article, you only have to do this in one single place as well, not throughout your whole code base.

But this also comes with slightly more overhead when implementing the access restrictions for the first time, which may or may not be worth it for your project.

#### Custom role names

If the names of the included roles don’t work for you, you can alias any number of roles using your own identifiers, e.g. like this:

```php
namespace My\Namespace;

final class MyRole {

    const CUSTOMER_SERVICE_AGENT = \Delight\Auth\Role::REVIEWER;
    const FINANCIAL_DIRECTOR = \Delight\Auth\Role::COORDINATOR;

    private function __construct() {}

}
```

The example above would allow you to use

```php
\My\Namespace\MyRole::CUSTOMER_SERVICE_AGENT;
// and
\My\Namespace\MyRole::FINANCIAL_DIRECTOR;
```

instead of

```php
\Delight\Auth\Role::REVIEWER;
// and
\Delight\Auth\Role::COORDINATOR;
```

Just remember *not* to alias a *single* included role to *multiple* roles with custom names.

### Enabling or disabling password resets

While password resets via email are a convenient feature that most users find helpful from time to time, the availability of this feature implies that accounts on your service are only ever as secure as the user’s associated email account.

You may provide security-conscious (and experienced) users with the possibility to disable password resets for their accounts (and to enable them again later) for enhanced security:

```php
try {
    if ($auth->reconfirmPassword($_POST['password'])) {
        $auth->setPasswordResetEnabled($_POST['enabled'] == 1);

        echo 'The setting has been changed';
    }
    else {
        echo 'We can\'t say if the user is who they claim to be';
    }
}
catch (\Delight\Auth\NotLoggedInException $e) {
    die('The user is not signed in');
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    die('Too many requests');
}
```

In order to check the current value of this setting, use the return value from

```php
$auth->isPasswordResetEnabled();
```

for the correct default option in your user interface. You don’t need to check this value for restrictions of the feature, which are enforced automatically.

### Throttling or rate limiting

All methods provided by this library are *automatically* protected against excessive numbers of requests from clients. If the need arises, you can (temporarily) disable this protection using the [`$throttling` parameter](#creating-a-new-instance) passed to the constructor.

If you would like to throttle or rate limit *external* features or methods as well, e.g. those in your own code, you can make use of the built-in helper method for throttling and rate limiting:

```php
try {
    // throttle the specified resource or feature to *3* requests per *60* seconds
    $auth->throttle([ 'my-resource-name' ], 3, 60);

    echo 'Do something with the resource or feature';
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    // operation cancelled

    \http_response_code(429);
    exit;
}
```

If the protection of the resource or feature should additionally depend on another attribute, e.g. to track something separately per IP address, just add more data to the resource description, such as:

```php
[ 'my-resource-name', $_SERVER['REMOTE_ADDR'] ]
// instead of
// [ 'my-resource-name' ]
```

Allowing short bursts of activity during peak demand is possible by specifying a burst factor as the fourth argument. A value of `5`, for example, would permit temporary bursts of fivefold activity, compared to the generally accepted level.

In some cases, you may just want to *simulate* the throttling or rate limiting. This lets you check whether an action would be permitted without actually modifying the activity tracker. To do so, simply pass `true` as the fifth argument.

**Note:** When you disable throttling on the instance (using the [`$throttling` parameter](#creating-a-new-instance) passed to the constructor), this turns off both the automatic internal protection and the effect of any calls to `Auth#throttle` in your own application code – unless you also set the optional `$force` parameter to `true` in specific `Auth#throttle` calls.

### Administration (managing users)

The administrative interface is available via `$auth->admin()`. You can call various method on this interface, as documented below.

Do not forget to implement secure access control before exposing access to this interface. For example, you may provide access to this interface to logged in users with the administrator role only, or use the interface in private scripts only.

#### Creating new users

```php
try {
    $userId = $auth->admin()->createUser($_POST['email'], $_POST['password'], $_POST['username']);

    echo 'We have signed up a new user with the ID ' . $userId;
}
catch (\Delight\Auth\InvalidEmailException $e) {
    die('Invalid email address');
}
catch (\Delight\Auth\InvalidPasswordException $e) {
    die('Invalid password');
}
catch (\Delight\Auth\UserAlreadyExistsException $e) {
    die('User already exists');
}
```

The username in the third parameter is optional. You can pass `null` there if you don’t want to manage usernames.

If you want to enforce unique usernames, on the other hand, simply call `createUserWithUniqueUsername` instead of `createUser`, and be prepared to catch the `DuplicateUsernameException`.

#### Deleting users

Deleting users by their ID:

```php
try {
    $auth->admin()->deleteUserById($_POST['id']);
}
catch (\Delight\Auth\UnknownIdException $e) {
    die('Unknown ID');
}
```

Deleting users by their email address:

```php
try {
    $auth->admin()->deleteUserByEmail($_POST['email']);
}
catch (\Delight\Auth\InvalidEmailException $e) {
    die('Unknown email address');
}
```

Deleting users by their username:

```php
try {
    $auth->admin()->deleteUserByUsername($_POST['username']);
}
catch (\Delight\Auth\UnknownUsernameException $e) {
    die('Unknown username');
}
catch (\Delight\Auth\AmbiguousUsernameException $e) {
    die('Ambiguous username');
}
```

#### Retrieving a list of registered users

When fetching a list of all users, the requirements vary greatly between projects and use cases, and customization is common. For example, you might want to fetch different columns, join related tables, filter by certain criteria, change how results are sorted (in varying direction), and limit the number of results (while providing an offset).

That’s why it’s easier to use a single custom SQL query. Start with the following:

```sql
SELECT id, email, username, status, verified, roles_mask, registered, last_login FROM users;
```

#### Assigning roles to users

```php
try {
    $auth->admin()->addRoleForUserById($userId, \Delight\Auth\Role::ADMIN);
}
catch (\Delight\Auth\UnknownIdException $e) {
    die('Unknown user ID');
}

// or

try {
    $auth->admin()->addRoleForUserByEmail($userEmail, \Delight\Auth\Role::ADMIN);
}
catch (\Delight\Auth\InvalidEmailException $e) {
    die('Unknown email address');
}

// or

try {
    $auth->admin()->addRoleForUserByUsername($username, \Delight\Auth\Role::ADMIN);
}
catch (\Delight\Auth\UnknownUsernameException $e) {
    die('Unknown username');
}
catch (\Delight\Auth\AmbiguousUsernameException $e) {
    die('Ambiguous username');
}
```

**Note:** Changes to a user’s set of roles may need up to five minutes to take effect. This increases performance and usually poses no problem. If you want to change this behavior, nevertheless, simply decrease (or perhaps increase) the value that you pass to the [`Auth` constructor](#creating-a-new-instance) as the argument named `$sessionResyncInterval`.

#### Taking roles away from users

```php
try {
    $auth->admin()->removeRoleForUserById($userId, \Delight\Auth\Role::ADMIN);
}
catch (\Delight\Auth\UnknownIdException $e) {
    die('Unknown user ID');
}

// or

try {
    $auth->admin()->removeRoleForUserByEmail($userEmail, \Delight\Auth\Role::ADMIN);
}
catch (\Delight\Auth\InvalidEmailException $e) {
    die('Unknown email address');
}

// or

try {
    $auth->admin()->removeRoleForUserByUsername($username, \Delight\Auth\Role::ADMIN);
}
catch (\Delight\Auth\UnknownUsernameException $e) {
    die('Unknown username');
}
catch (\Delight\Auth\AmbiguousUsernameException $e) {
    die('Ambiguous username');
}
```

**Note:** Changes to a user’s set of roles may need up to five minutes to take effect. This increases performance and usually poses no problem. If you want to change this behavior, nevertheless, simply decrease (or perhaps increase) the value that you pass to the [`Auth` constructor](#creating-a-new-instance) as the argument named `$sessionResyncInterval`.

#### Checking roles

```php
try {
    if ($auth->admin()->doesUserHaveRole($userId, \Delight\Auth\Role::ADMIN)) {
        echo 'The specified user is an administrator';
    }
    else {
        echo 'The specified user is not an administrator';
    }
}
catch (\Delight\Auth\UnknownIdException $e) {
    die('Unknown user ID');
}
```

Alternatively, you can get a list of all the roles that have been assigned to the user:

```php
$auth->admin()->getRolesForUserById($userId);
```

#### Impersonating users (logging in as user)

```php
try {
    $auth->admin()->logInAsUserById($_POST['id']);
}
catch (\Delight\Auth\UnknownIdException $e) {
    die('Unknown ID');
}
catch (\Delight\Auth\EmailNotVerifiedException $e) {
    die('Email address not verified');
}

// or

try {
    $auth->admin()->logInAsUserByEmail($_POST['email']);
}
catch (\Delight\Auth\InvalidEmailException $e) {
    die('Unknown email address');
}
catch (\Delight\Auth\EmailNotVerifiedException $e) {
    die('Email address not verified');
}

// or

try {
    $auth->admin()->logInAsUserByUsername($_POST['username']);
}
catch (\Delight\Auth\UnknownUsernameException $e) {
    die('Unknown username');
}
catch (\Delight\Auth\AmbiguousUsernameException $e) {
    die('Ambiguous username');
}
catch (\Delight\Auth\EmailNotVerifiedException $e) {
    die('Email address not verified');
}
```

#### Changing a user’s password

```php
try {
    $auth->admin()->changePasswordForUserById($_POST['id'], $_POST['newPassword']);
}
catch (\Delight\Auth\UnknownIdException $e) {
    die('Unknown ID');
}
catch (\Delight\Auth\InvalidPasswordException $e) {
    die('Invalid password');
}

// or

try {
    $auth->admin()->changePasswordForUserByUsername($_POST['username'], $_POST['newPassword']);
}
catch (\Delight\Auth\UnknownUsernameException $e) {
    die('Unknown username');
}
catch (\Delight\Auth\AmbiguousUsernameException $e) {
    die('Ambiguous username');
}
catch (\Delight\Auth\InvalidPasswordException $e) {
    die('Invalid password');
}
```

### Cookies

This library uses two cookies to keep state on the client: The first, whose name you can retrieve using

```php
\session_name();
```

is the general (mandatory) session cookie. The second (optional) cookie is only used for [persistent logins](#keeping-the-user-logged-in) and its name can be retrieved as follows:

```php
\Delight\Auth\Auth::createRememberCookieName();
```

#### Renaming the library’s cookies

You can rename the session cookie used by this library through one of the following means, in order of recommendation:

 * In the [PHP configuration](https://www.php.net/manual/configuration.file.php) (`php.ini`), find the line with the `session.name` directive and change its value to something like `session_v1`, as in:

   ```
   session.name = session_v1
   ```

 * As early as possible in your application, and before you create the `Auth` instance, call `\ini_set` to change `session.name` to something like `session_v1`, as in:

   ```php
   \ini_set('session.name', 'session_v1');
   ```

   For this to work, `session.auto_start` must be set to `0` in the [PHP configuration](https://www.php.net/manual/configuration.file.php) (`php.ini`).

 * As early as possible in your application, and before you create the `Auth` instance, call `\session_name` with an argument like `session_v1`, as in:

   ```php
   \session_name('session_v1');
   ```

   For this to work, `session.auto_start` must be set to `0` in the [PHP configuration](https://www.php.net/manual/configuration.file.php) (`php.ini`).

The name of the cookie for [persistent logins](#keeping-the-user-logged-in) will change as well – automatically – following your change of the session cookie’s name.

#### Defining the domain scope for cookies

A cookie’s `domain` attribute controls which domain (and which subdomains) the cookie will be valid for, and thus where the user’s session and authentication state will be available.

The recommended default is an empty string, which means that the cookie will only be valid for the *exact* current host, *excluding* any subdomains that may exist. You should only use a different value if you need to share cookies between different subdomains. Often, you’ll want to share cookies between the bare domain and the `www` subdomain, but you might also want to share them between any other set of subdomains.

Whatever set of subdomains you choose, you should set the cookie’s attribute to the *most specific* domain name that still includes all your required subdomains. For example, to share cookies between `example.com` and `www.example.com`, you would set the attribute to `example.com`. But if you wanted to share cookies between `sub1.app.example.com` and `sub2.app.example.com`, you should set the attribute to `app.example.com`. Any explicitly specified domain name will always *include* all subdomains that may exist.

You can change the attribute through one of the following means, in order of recommendation:

 * In the [PHP configuration](https://www.php.net/manual/configuration.file.php) (`php.ini`), find the line with the `session.cookie_domain` directive and change its value as desired, e.g.:

   ```
   session.cookie_domain = example.com
   ```

 * As early as possible in your application, and before you create the `Auth` instance, call `\ini_set` to change the value of the `session.cookie_domain` directive as desired, e.g.:

   ```php
   \ini_set('session.cookie_domain', 'example.com');
   ```

   For this to work, `session.auto_start` must be set to `0` in the [PHP configuration](https://www.php.net/manual/configuration.file.php) (`php.ini`).

#### Restricting the path where cookies are available

A cookie’s `path` attribute controls which directories (and subdirectories) the cookie will be valid for, and thus where the user’s session and authentication state will be available.

In most cases, you’ll want to make cookies available for all paths, i.e. any directory and file, starting in the root directory. That is what a value of `/` for the attribute does, which is also the recommended default. You should only change this attribute to a different value, e.g. `/path/to/subfolder`, if you want to restrict which directories your cookies will be available in, e.g. to host multiple applications side-by-side, in different directories, under the same domain name.

You can change the attribute through one of the following means, in order of recommendation:

 * In the [PHP configuration](https://www.php.net/manual/configuration.file.php) (`php.ini`), find the line with the `session.cookie_path` directive and change its value as desired, e.g.:

   ```
   session.cookie_path = /
   ```

 * As early as possible in your application, and before you create the `Auth` instance, call `\ini_set` to change the value of the `session.cookie_path` directive as desired, e.g.:

   ```php
   \ini_set('session.cookie_path', '/');
   ```

   For this to work, `session.auto_start` must be set to `0` in the [PHP configuration](https://www.php.net/manual/configuration.file.php) (`php.ini`).

#### Controlling client-side script access to cookies

Using the `httponly` attribute, you can control whether client-side scripts, i.e. JavaScript, should be able to access your cookies or not. For security reasons, it is best to *deny* script access to your cookies, which reduces the damage that successful XSS attacks against your application could do, for example.

Thus, you should always set `httponly` to `1`, except for the rare cases where you really need access to your cookies from JavaScript and can’t find any better solution. In those cases, set the attribute to `0`, but be aware of the consequences.

You can change the attribute through one of the following means, in order of recommendation:

 * In the [PHP configuration](https://www.php.net/manual/configuration.file.php) (`php.ini`), find the line with the `session.cookie_httponly` directive and change its value as desired, e.g.:

   ```
   session.cookie_httponly = 1
   ```

 * As early as possible in your application, and before you create the `Auth` instance, call `\ini_set` to change the value of the `session.cookie_httponly` directive as desired, e.g.:

   ```php
   \ini_set('session.cookie_httponly', 1);
   ```

   For this to work, `session.auto_start` must be set to `0` in the [PHP configuration](https://www.php.net/manual/configuration.file.php) (`php.ini`).

#### Configuring transport security for cookies

Using the `secure` attribute, you can control whether cookies should be sent over *any* connection, including plain HTTP, or whether a secure connection, i.e. HTTPS (with SSL/TLS), should be required. The former (less secure) mode can be chosen by setting the attribute to `0`, and the latter (more secure) mode can be chosen by setting the attribute to `1`.

Obviously, this solely depends on whether you are able to serve *all* pages exclusively via HTTPS. If you can, you should set the attribute to `1` and possibly combine it with HTTP redirects to the secure protocol and HTTP Strict Transport Security (HSTS). Otherwise, you may have to keep the attribute set to `0`.

You can change the attribute through one of the following means, in order of recommendation:

 * In the [PHP configuration](https://www.php.net/manual/configuration.file.php) (`php.ini`), find the line with the `session.cookie_secure` directive and change its value as desired, e.g.:

   ```
   session.cookie_secure = 1
   ```

 * As early as possible in your application, and before you create the `Auth` instance, call `\ini_set` to change the value of the `session.cookie_secure` directive as desired, e.g.:

   ```php
   \ini_set('session.cookie_secure', 1);
   ```

   For this to work, `session.auto_start` must be set to `0` in the [PHP configuration](https://www.php.net/manual/configuration.file.php) (`php.ini`).

### Utilities

#### Creating a random string

```php
$length = 24;
$randomStr = \Delight\Auth\Auth::createRandomString($length);
```

#### Creating a UUID v4 as per RFC 4122

```php
$uuid = \Delight\Auth\Auth::createUuid();
```

### Reading and writing session data

For detailed information on how to read and write session data conveniently, please refer to [the documentation of the session library](https://github.com/delight-im/PHP-Cookie#reading-and-writing-session-data), which is included by default.

## Frequently asked questions

### What about password hashing?

Any password or authentication token is automatically hashed using the [“bcrypt”](https://en.wikipedia.org/wiki/Bcrypt) function, which is based on the [“Blowfish” cipher](https://en.wikipedia.org/wiki/Blowfish_(cipher)) and (still) considered one of the strongest password hash functions today. “bcrypt” is used with 1,024 iterations, i.e. a “cost” factor of 10. A random [“salt”](https://en.wikipedia.org/wiki/Salt_(cryptography)) is applied automatically as well.

You can verify this configuration by looking at the hashes in your database table `users`. If the above is true with your setup, all password hashes in your `users` table should start with the prefix `$2$10$`, `$2a$10$` or `$2y$10$`.

When new algorithms (such as [Argon2](https://en.wikipedia.org/wiki/Argon2)) may be introduced in the future, this library will automatically take care of “upgrading” your existing password hashes whenever a user signs in or changes their password.

### How can I implement custom password requirements?

Enforcing a minimum length for passwords is usually a good idea. Apart from that, you may want to look up whether a potential password is in some blacklist, which you could manage in a database or in a file, in order to prevent dictionary words or commonly used passwords from being used in your application.

To allow for maximum flexibility and ease of use, this library has been designed so that it does *not* contain any further checks for password requirements itself, but instead allows you to wrap your own checks around the relevant calls to library methods. Example:

```php
function isPasswordAllowed($password) {
    if (\strlen($password) < 8) {
        return false;
    }

    $blacklist = [ 'password1', '123456', 'qwerty' ];

    if (\in_array($password, $blacklist)) {
        return false;
    }

    return true;
}

if (isPasswordAllowed($password)) {
    $auth->register($email, $password);
}
```

### Why are there problems when using other libraries that work with sessions?

You might try loading this library first, and creating the `Auth` instance first, *before* loading the other libraries. Apart from that, there’s probably not much we can do here.

### Why are other sites not able to frame or embed my site?

If you want to let others include your site in a `<frame>`, `<iframe>`, `<object>`, `<embed>` or `<applet>` element, you have to disable the default clickjacking prevention:

```php
\header_remove('X-Frame-Options');
```

## Exceptions

This library throws two types of exceptions to indicate problems:

   * `AuthException` and its subclasses are thrown whenever a method does not complete successfully. You should *always* catch these exceptions as they carry the normal error responses that you must react to.
   * `AuthError` and its subclasses are thrown whenever there is an internal problem or the library has not been installed correctly. You should *not* catch these exceptions.

## General advice

 * Serve *all* pages over HTTPS only, i.e. using SSL/TLS for every single request.
 * You should enforce a minimum length for passwords, e.g. 10 characters, but *never* any maximum length, at least not anywhere below 100 characters. Moreover, you should *not* restrict the set of allowed characters.
 * Whenever a user was remembered through the “remember me” feature enabled or disabled during sign in, which means that they did not log in by typing their password, you should require re-authentication for critical features.
 * Encourage users to use pass*phrases*, i.e. combinations of words or even full sentences, instead of single pass*words*.
 * Do not prevent users' password managers from working correctly. Thus, use the standard form fields only and do not prevent copy and paste.
 * Before executing sensitive account operations (e.g. changing a user’s email address, deleting a user’s account), you should always require re-authentication, i.e. require the user to verify their login credentials once more.
 * You should not offer an online password reset feature (“forgot password”) for high-security applications.
 * For high-security applications, you should not use email addresses as identifiers. Instead, choose identifiers that are specific to the application and secret, e.g. an internal customer number.

## Contributing

All contributions are welcome! If you wish to contribute, please create an issue first so that your feature, problem or question can be discussed.

## License

This project is licensed under the terms of the [MIT License](https://opensource.org/licenses/MIT).
