# Auth

Authentication for PHP. Simple, lightweight and secure.

Written once, to be used everywhere.

Completely framework-agnostic and database-agnostic.

## Why do I need this?

 * There are [tons](http://www.troyhunt.com/2011/01/whos-who-of-bad-password-practices.html) [of](http://www.jeremytunnell.com/posts/swab-password-policies-and-two-factor-authentication-a-comedy-of-errors) [websites](http://badpasswordpolicies.tumblr.com/) with weak authentication systems. Don't build such a site.
 * Re-implementing a new authentication system for every PHP project is *not* a good idea.
 * Building your own authentication classes piece by piece, and copying it to every project, is *not* recommended, either.
 * A secure authentication system with an easy-to-use API should be thoroughly designed and planned.
 * Peer-review for your critical infrastructure is *a must*.

## Requirements

 * PHP 5.6.0+
   * PDO (PHP Data Objects) extension (`pdo`)
     * MySQL Native Driver (`mysqlnd`)
   * OpenSSL extension (`openssl`)
 * MySQL 5.5.3+ **or** MariaDB 5.5.23+ **or** other SQL databases that you create the [schema](Database) for

## Installation

 1. Include the library via [Composer](https://getcomposer.org/):

    ```
    $ composer require delight-im/auth
    ```

 1. Include the Composer autoloader:

    ```php
    require __DIR__ . '/vendor/autoload.php';
    ```

 1. Set up a database and create the required tables:

    * [MySQL](Database/MySQL.sql)

## Upgrading

Migrating from an earlier version of this project? See our [upgrade guide](Migration.md) for help.

## Usage

 * [Creating a new instance](#creating-a-new-instance)
 * [Registration (sign up)](#registration-sign-up)
 * [Login (sign in)](#login-sign-in)
 * [Email verification](#email-verification)
 * [Keeping the user logged in](#keeping-the-user-logged-in)
 * [Password reset ("forgot password")](#password-reset-forgot-password)
 * [Changing the current user's password](#changing-the-current-users-password)
 * [Logout](#logout)
 * [Accessing user information](#accessing-user-information)
   * [Login state](#login-state)
   * [User ID](#user-id)
   * [Email address](#email-address)
   * [Display name](#display-name)
   * [Checking whether the user was "remembered"](#checking-whether-the-user-was-remembered)
   * [IP address](#ip-address)
   * [Additional user information](#additional-user-information)
 * [Administration (managing users)](#administration-managing-users)
   * [Creating new users](#creating-new-users)
   * [Deleting users](#deleting-users)
 * [Utilities](#utilities)
   * [Creating a random string](#creating-a-random-string)
   * [Creating a UUID v4 as per RFC 4122](#creating-a-uuid-v4-as-per-rfc-4122)
 * [Reading and writing session data](#reading-and-writing-session-data)

### Creating a new instance

```php
// $db = new PDO('mysql:dbname=my-database;host=localhost;charset=utf8mb4', 'my-username', 'my-password');
// or
// $db = new \Delight\Db\PdoDsn('mysql:dbname=my-database;host=localhost;charset=utf8mb4', 'my-username', 'my-password');

$auth = new \Delight\Auth\Auth($db);
```

If you have an open `PDO` connection already, just re-use it.

If you do enforce HTTPS on your site, pass `true` as the second parameter to the constructor. This is optional and the default is `false`.

Only in the very rare case that you need access to your cookies from JavaScript, pass `true` as the third argument to the constructor. This is optional and the default is `false`. There is almost always a *better* solution than enabling this, however.

If your web server is behind a proxy server and `$_SERVER['REMOTE_ADDR']` only contains the proxy's IP address, you must pass the user's real IP address to the constructor in the fourth argument. The default is `null`.

### Registration (sign up)

```php
try {
    $userId = $auth->register($_POST['email'], $_POST['password'], $_POST['username'], function ($selector, $token) {
        // send `$selector` and `$token` to the user (e.g. via email)
    });

    // we have signed up a new user with the ID `$userId`
}
catch (\Delight\Auth\InvalidEmailException $e) {
    // invalid email address
}
catch (\Delight\Auth\InvalidPasswordException $e) {
    // invalid password
}
catch (\Delight\Auth\UserAlreadyExistsException $e) {
    // user already exists
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    // too many requests
}
```

The username in the third parameter is optional. You can pass `null` there if you don't want to manage usernames.

If you want to enforce unique usernames, on the other hand, simply call `registerWithUniqueUsername` instead of `register`, and be prepared to catch the `DuplicateUsernameException`.

For email verification, you should build an URL with the selector and token and send it to the user, e.g.:

```php
$url = 'https://www.example.com/verify_email?selector='.urlencode($selector).'&token='.urlencode($token);
```

If you don't want to perform email verification, just omit the last parameter to `Auth#register`. The new user will be active immediately, then.

### Login (sign in)

```php
try {
    $auth->login($_POST['email'], $_POST['password']);

    // user is logged in
}
catch (\Delight\Auth\InvalidEmailException $e) {
    // wrong email address
}
catch (\Delight\Auth\InvalidPasswordException $e) {
    // wrong password
}
catch (\Delight\Auth\EmailNotVerifiedException $e) {
    // email not verified
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    // too many requests
}
```

If you want to sign in with usernames on the other hand, either in addition to the login via email address or as a replacement, that's possible as well. Simply call the method `loginWithUsername` instead of method `login`. Then, instead of catching `InvalidEmailException`, make sure to catch both `UnknownUsernameException` and `AmbiguousUsernameException`. You may also want to read the notes about the uniqueness of usernames in the section that explains how to [sign up new users](#registration-sign-up).

### Email verification

Extract the selector and token from the URL that the user clicked on in the verification email.

```php
try {
    $auth->confirmEmail($_GET['selector'], $_GET['token']);

    // email address has been verified
}
catch (\Delight\Auth\InvalidSelectorTokenPairException $e) {
    // invalid token
}
catch (\Delight\Auth\TokenExpiredException $e) {
    // token expired
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    // too many requests
}
```

### Keeping the user logged in

The third parameter to the `Auth#login` method controls whether the login is persistent with a long-lived cookie. With such a persistent login, users may stay authenticated for a long time, even when the browser session has already been closed and the session cookies have expired. Typically, you'll want to keep the user logged in for weeks or months with this feature, which is known as "remember me" or "keep me logged in". Many users will find this more convenient, but it may be less secure if they leave their devices unattended.

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

Omit the third parameter or set it to `null` to disable the feature. Otherwise, you may ask the user whether they want to enable "remember me". This is usually done with a checkbox in your user interface. Use the input from that checkbox to decide between `null` and a pre-defined duration in seconds here, e.g. `60 * 60 * 24 * 365.25` for one year.

### Password reset ("forgot password")

```php
try {
    $auth->forgotPassword($_POST['email'], function ($selector, $token) {
        // send `$selector` and `$token` to the user (e.g. via email)
    });

    // request has been generated
}
catch (\Delight\Auth\InvalidEmailException $e) {
    // invalid email address
}
catch (\Delight\Auth\EmailNotVerifiedException $e) {
    // email not verified
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    // too many requests
}
```

You should build an URL with the selector and token and send it to the user, e.g.:

```php
$url = 'https://www.example.com/reset_password?selector='.urlencode($selector).'&token='.urlencode($token);
```

As the next step, users will click on the link that they received. Extract the selector and token from the URL.

If the selector/token pair is valid, let the user choose a new password:

```php
if ($auth->canResetPassword($_POST['selector'], $_POST['token'])) {
    // put the selector into a `hidden` field (or keep it in the URL)
    // put the token into a `hidden` field (or keep it in the URL)

    // ask the user for their new password
}
```

Now when you have the new password for the user (and still have the other two pieces of information), you can reset the password:

```php
try {
    $auth->resetPassword($_POST['selector'], $_POST['token'], $_POST['password']);

    // password has been reset
}
catch (\Delight\Auth\InvalidSelectorTokenPairException $e) {
    // invalid token
}
catch (\Delight\Auth\TokenExpiredException $e) {
    // token expired
}
catch (\Delight\Auth\InvalidPasswordException $e) {
    // invalid password
}
catch (\Delight\Auth\TooManyRequestsException $e) {
    // too many requests
}
```

### Changing the current user's password

If a user is currently logged in, they may change their password.

```php
try {
    $auth->changePassword($_POST['oldPassword'], $_POST['newPassword']);

    // password has been changed
}
catch (\Delight\Auth\NotLoggedInException $e) {
    // not logged in
}
catch (\Delight\Auth\InvalidPasswordException $e) {
    // invalid password(s)
}
```

### Logout

```php
$auth->logout();

// user has been signed out
```

### Accessing user information

#### Login state

```php
if ($auth->isLoggedIn()) {
    // user is signed in
}
else {
    // user is *not* signed in yet
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
$email = $auth->getUsername();
```

Remember that usernames are optional and there is only a username if you supplied it during registration.

If the user is not currently signed in, this returns `null`.

#### Status information

```php
if ($auth->isNormal()) {
    // user is in default state
}

if ($auth->isArchived()) {
    // user has been archived
}

if ($auth->isBanned()) {
    // user has been banned
}

if ($auth->isLocked()) {
    // user has been locked
}

if ($auth->isPendingReview()) {
    // user is pending review
}

if ($auth->isSuspended()) {
    // user has been suspended
}
```

#### Checking whether the user was "remembered"

```php
if ($auth->isRemembered()) {
    // user did not sign in but was logged in through their long-lived cookie
}
else {
    // user signed in manually
}
```

If the user is not currently signed in, this returns `null`.

#### IP address

```php
$ip = $auth->getIpAddress();
```

#### Additional user information

In order to preserve this library's suitability for all purposes as well as its full re-usability, it doesn't come with additional bundled columns for user information. But you don't have to do without additional user information, of course:

Here's how to use this library with your own tables for custom user information in a maintainable and re-usable way:

 1. Add any number of custom database tables where you store custom user information, e.g. a table named `profiles`.
 1. Whenever you call the `register` method (which returns the new user's ID), add your own logic afterwards that fills your custom database tables.
 1. If you need the custom user information only rarely, you may just retrieve it as needed. If you need it more frequently, however, you'd probably want to have it in your session data. The following method is how you can load and access your data in a reliable way:

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

### Administration (managing users)

The administrative interface is available via `$auth->admin()`. You can call various method on this interface, as documented below.

Do not forget to implement secure access control before exposing access to this interface. For example, you may provide access to this interface to logged in users with the administrator role only, or use the interface in private scripts only.

#### Creating new users

```php
try {
    $userId = $auth->admin()->createUser($_POST['email'], $_POST['password'], $_POST['username']);

    // we have signed up a new user with the ID `$userId`
}
catch (\Delight\Auth\InvalidEmailException $e) {
    // invalid email address
}
catch (\Delight\Auth\InvalidPasswordException $e) {
    // invalid password
}
catch (\Delight\Auth\UserAlreadyExistsException $e) {
    // user already exists
}
```

The username in the third parameter is optional. You can pass `null` there if you don't want to manage usernames.

If you want to enforce unique usernames, on the other hand, simply call `createUserWithUniqueUsername` instead of `createUser`, and be prepared to catch the `DuplicateUsernameException`.

#### Deleting users

Deleting users by their ID:

```php
try {
    $auth->admin()->deleteUserById($_POST['id']);
}
catch (\Delight\Auth\UnknownIdException $e) {
    // unknown ID
}
```

Deleting users by their email address:

```php
try {
    $auth->admin()->deleteUserByEmail($_POST['email']);
}
catch (\Delight\Auth\InvalidEmailException $e) {
    // unknown email address
}
```

Deleting users by their username:

```php
try {
    $auth->admin()->deleteUserByUsername($_POST['username']);
}
catch (\Delight\Auth\UnknownUsernameException $e) {
    // unknown username
}
catch (\Delight\Auth\AmbiguousUsernameException $e) {
    // ambiguous username
}
```

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

## Features

 * registration
   * secure password storage using the bcrypt algorithm
   * email verification through message with confirmation link
   * assurance of unique email addresses
   * customizable password requirements and enforcement
   * optional usernames with customizable restrictions
 * login
   * keeping the user logged in for a long time (beyond expiration of browser session) via secure long-lived token ("remember me")
 * account management
   * change password
   * tracking the time of sign up and last login
   * check if user has been logged in via "remember me" cookie
 * logout
   * full and reliable destruction of session
 * session management
   * protection against session hijacking via cross-site scripting (XSS)
     * do *not* permit script-based access to cookies
     * restrict cookies to HTTPS to prevent session hijacking via non-secure HTTP
   * protection against session fixation attacks
   * protection against cross-site request forgery (CSRF)
     * works automatically (i.e. no need for CSRF tokens everywhere)
     * do *not* use HTTP `GET` requests for "dangerous" operations
 * throttling
   * per IP address
   * per account
 * enhanced HTTP security
   * prevents clickjacking
   * prevent content sniffing (MIME sniffing)
   * disables caching of potentially sensitive data
 * miscellaneous
   * ready for both IPv4 and IPv6
   * works behind proxy servers as well
   * privacy-friendly (e.g. does *not* save readable IP addresses)

## Exceptions

This library throws two types of exceptions to indicate problems:

   * `AuthException` and its subclasses are thrown whenever a method does not complete successfully. You should *always* catch these exceptions as they carry the normal error responses that you must react to.
   * `AuthError` and its subclasses are thrown whenever there is an internal problem or the library has not been installed correctly. You should *not* catch these exceptions.

## General advice

 * Serve *all* pages over HTTPS only, i.e. using SSL/TLS for every single request.
 * You should enforce a minimum length for passwords, e.g. 10 characters, but *never* any maximum length, at least not anywhere below 100 characters. Moreover, you should *not* restrict the set of allowed characters.
 * Whenever a user was remembered through the "remember me" feature enabled or disabled during sign in, which means that they did not log in by typing their password, you should require re-authentication for critical features.
 * Encourage users to use pass*phrases*, i.e. combinations of words or even full sentences, instead of single pass*words*.
 * Do not prevent users' password managers from working correctly. Thus, use the standard form fields only and do not prevent copy and paste.
 * Before executing sensitive account operations (e.g. changing a user's email address, deleting a user's account), you should always require re-authentication, i.e. require the user to verify their login credentials once more.
 * You should not offer an online password reset feature ("forgot password") for high-security applications.
 * For high-security applications, you should not use email addresses as identifiers. Instead, choose identifiers that are specific to the application and secret, e.g. an internal customer number.

## Contributing

All contributions are welcome! If you wish to contribute, please create an issue first so that your feature, problem or question can be discussed.

## License

This project is licensed under the terms of the [MIT License](https://opensource.org/licenses/MIT).
