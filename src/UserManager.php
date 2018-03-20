<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

use Delight\Base64\Base64;
use Delight\Cookie\Session;
use Delight\Db\PdoDatabase;
use Delight\Db\PdoDsn;
use Delight\Db\Throwable\Error;
use Delight\Db\Throwable\IntegrityConstraintViolationException;

require_once __DIR__ . '/Exceptions.php';

/**
 * Abstract base class for components implementing user management
 *
 * @internal
 */
abstract class UserManager {

	/** @var string session field for whether the client is currently signed in */
	const SESSION_FIELD_LOGGED_IN = 'auth_logged_in';
	/** @var string session field for the ID of the user who is currently signed in (if any) */
	const SESSION_FIELD_USER_ID = 'auth_user_id';
	/** @var string session field for the email address of the user who is currently signed in (if any) */
	const SESSION_FIELD_EMAIL = 'auth_email';
	/** @var string session field for the display name (if any) of the user who is currently signed in (if any) */
	const SESSION_FIELD_USERNAME = 'auth_username';
	/** @var string session field for the status of the user who is currently signed in (if any) as one of the constants from the {@see Status} class */
	const SESSION_FIELD_STATUS = 'auth_status';
	/** @var string session field for the roles of the user who is currently signed in (if any) as a bitmask using constants from the {@see Role} class */
	const SESSION_FIELD_ROLES = 'auth_roles';
	/** @var string session field for whether the user who is currently signed in (if any) has been remembered (instead of them having authenticated actively) */
	const SESSION_FIELD_REMEMBERED = 'auth_remembered';
	/** @var string session field for the UNIX timestamp in seconds of the session data's last resynchronization with its authoritative source in the database */
	const SESSION_FIELD_LAST_RESYNC = 'auth_last_resync';

	/** @var PdoDatabase the database connection to operate on */
	protected $db;
	/** @var string the prefix for the names of all database tables used by this component */
	protected $dbTablePrefix;

	/**
	 * Creates a random string with the given maximum length
	 *
	 * With the default parameter, the output should contain at least as much randomness as a UUID
	 *
	 * @param int $maxLength the maximum length of the output string (integer multiple of 4)
	 * @return string the new random string
	 */
	public static function createRandomString($maxLength = 24) {
		// calculate how many bytes of randomness we need for the specified string length
		$bytes = \floor((int) $maxLength / 4) * 3;

		// get random data
		$data = \openssl_random_pseudo_bytes($bytes);

		// return the Base64-encoded result
		return Base64::encodeUrlSafe($data);
	}

	/**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection the database connection to operate on
	 * @param string|null $dbTablePrefix (optional) the prefix for the names of all database tables used by this component
	 */
	protected function __construct($databaseConnection, $dbTablePrefix = null) {
		if ($databaseConnection instanceof PdoDatabase) {
			$this->db = $databaseConnection;
		}
		elseif ($databaseConnection instanceof PdoDsn) {
			$this->db = PdoDatabase::fromDsn($databaseConnection);
		}
		elseif ($databaseConnection instanceof \PDO) {
			$this->db = PdoDatabase::fromPdo($databaseConnection, true);
		}
		else {
			$this->db = null;

			throw new \InvalidArgumentException('The database connection must be an instance of either `PdoDatabase`, `PdoDsn` or `PDO`');
		}

		$this->dbTablePrefix = (string) $dbTablePrefix;
	}

	/**
	 * Creates a new user
	 *
	 * If you want the user's account to be activated by default, pass `null` as the callback
	 *
	 * If you want to make the user verify their email address first, pass an anonymous function as the callback
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to verify their email address as a next step, both pieces will be required again
	 *
	 * @param bool $requireUniqueUsername whether it must be ensured that the username is unique
	 * @param string $email the email address to register
	 * @param string $password the password for the new account
	 * @param string|null $username (optional) the username that will be displayed
	 * @param callable|null $callback (optional) the function that sends the confirmation email to the user
	 * @return int the ID of the user that has been created (if any)
	 * @throws InvalidEmailException if the email address has been invalid
	 * @throws InvalidPasswordException if the password has been invalid
	 * @throws UserAlreadyExistsException if a user with the specified email address already exists
	 * @throws DuplicateUsernameException if it was specified that the username must be unique while it was *not*
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see confirmEmail
	 * @see confirmEmailAndSignIn
	 */
	protected function createUserInternal($requireUniqueUsername, $email, $password, $username = null, callable $callback = null) {
		\ignore_user_abort(true);

		$email = self::validateEmailAddress($email);
		$password = self::validatePassword($password);

		$username = isset($username) ? \trim($username) : null;

		// if the supplied username is the empty string or has consisted of whitespace only
		if ($username === '') {
			// this actually means that there is no username
			$username = null;
		}

		// if the uniqueness of the username is to be ensured
		if ($requireUniqueUsername) {
			// if a username has actually been provided
			if ($username !== null) {
				// count the number of users who do already have that specified username
				$occurrencesOfUsername = $this->db->selectValue(
					'SELECT COUNT(*) FROM ' . $this->dbTablePrefix . 'users WHERE username = ?',
					[ $username ]
				);

				// if any user with that username does already exist
				if ($occurrencesOfUsername > 0) {
					// cancel the operation and report the violation of this requirement
					throw new DuplicateUsernameException();
				}
			}
		}

		$password = \password_hash($password, \PASSWORD_DEFAULT);
		$verified = \is_callable($callback) ? 0 : 1;

		try {
			$this->db->insert(
				$this->dbTablePrefix . 'users',
				[
					'email' => $email,
					'password' => $password,
					'username' => $username,
					'verified' => $verified,
					'registered' => \time()
				]
			);
		}
		// if we have a duplicate entry
		catch (IntegrityConstraintViolationException $e) {
			throw new UserAlreadyExistsException();
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		$newUserId = (int) $this->db->getLastInsertId();

		if ($verified === 0) {
			$this->createConfirmationRequest($newUserId, $email, $callback);
		}

		return $newUserId;
	}

	/**
	 * Updates the given user's password by setting it to the new specified password
	 *
	 * @param int $userId the ID of the user whose password should be updated
	 * @param string $newPassword the new password
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	protected function updatePasswordInternal($userId, $newPassword) {
		$newPassword = \password_hash($newPassword, \PASSWORD_DEFAULT);

		try {
			$this->db->update(
				$this->dbTablePrefix . 'users',
				[ 'password' => $newPassword ],
				[ 'id' => $userId ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}
	}

	/**
	 * Called when a user has successfully logged in
	 *
	 * This may happen via the standard login, via the "remember me" feature, or due to impersonation by administrators
	 *
	 * @param int $userId the ID of the user
	 * @param string $email the email address of the user
	 * @param string $username the display name (if any) of the user
	 * @param int $status the status of the user as one of the constants from the {@see Status} class
	 * @param int $roles the roles of the user as a bitmask using constants from the {@see Role} class
	 * @param bool $remembered whether the user has been remembered (instead of them having authenticated actively)
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	protected function onLoginSuccessful($userId, $email, $username, $status, $roles, $remembered) {
		// re-generate the session ID to prevent session fixation attacks (requests a cookie to be written on the client)
		Session::regenerate(true);

		// save the user data in the session variables maintained by this library
		$_SESSION[self::SESSION_FIELD_LOGGED_IN] = true;
		$_SESSION[self::SESSION_FIELD_USER_ID] = (int) $userId;
		$_SESSION[self::SESSION_FIELD_EMAIL] = $email;
		$_SESSION[self::SESSION_FIELD_USERNAME] = $username;
		$_SESSION[self::SESSION_FIELD_STATUS] = (int) $status;
		$_SESSION[self::SESSION_FIELD_ROLES] = (int) $roles;
		$_SESSION[self::SESSION_FIELD_REMEMBERED] = $remembered;
		$_SESSION[self::SESSION_FIELD_LAST_RESYNC] = \time();
	}

	/**
	 * Returns the requested user data for the account with the specified username (if any)
	 *
	 * You must never pass untrusted input to the parameter that takes the column list
	 *
	 * @param string $username the username to look for
	 * @param array $requestedColumns the columns to request from the user's record
	 * @return array the user data (if an account was found unambiguously)
	 * @throws UnknownUsernameException if no user with the specified username has been found
	 * @throws AmbiguousUsernameException if multiple users with the specified username have been found
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	protected function getUserDataByUsername($username, array $requestedColumns) {
		try {
			$projection = \implode(', ', $requestedColumns);

			$users = $this->db->select(
				'SELECT ' . $projection . ' FROM ' . $this->dbTablePrefix . 'users WHERE username = ? LIMIT 2 OFFSET 0',
				[ $username ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		if (empty($users)) {
			throw new UnknownUsernameException();
		}
		else {
			if (\count($users) === 1) {
				return $users[0];
			}
			else {
				throw new AmbiguousUsernameException();
			}
		}
	}

	/**
	 * Validates an email address
	 *
	 * @param string $email the email address to validate
	 * @return string the sanitized email address
	 * @throws InvalidEmailException if the email address has been invalid
	 */
	protected static function validateEmailAddress($email) {
		if (empty($email)) {
			throw new InvalidEmailException();
		}

		$email = \trim($email);

		if (!\filter_var($email, \FILTER_VALIDATE_EMAIL)) {
			throw new InvalidEmailException();
		}

		return $email;
	}

	/**
	 * Validates a password
	 *
	 * @param string $password the password to validate
	 * @return string the sanitized password
	 * @throws InvalidPasswordException if the password has been invalid
	 */
	protected static function validatePassword($password) {
		if (empty($password)) {
			throw new InvalidPasswordException();
		}

		$password = \trim($password);

		if (\strlen($password) < 1) {
			throw new InvalidPasswordException();
		}

		return $password;
	}

	/**
	 * Creates a request for email confirmation
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to verify their email address as a next step, both pieces will be required again
	 *
	 * @param int $userId the user's ID
	 * @param string $email the email address to verify
	 * @param callable $callback the function that sends the confirmation email to the user
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	protected function createConfirmationRequest($userId, $email, callable $callback) {
		$selector = self::createRandomString(16);
		$token = self::createRandomString(16);
		$tokenHashed = \password_hash($token, \PASSWORD_DEFAULT);
		$expires = \time() + 60 * 60 * 24;

		try {
			$this->db->insert(
				$this->dbTablePrefix . 'users_confirmations',
				[
					'user_id' => (int) $userId,
					'email' => $email,
					'selector' => $selector,
					'token' => $tokenHashed,
					'expires' => $expires
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		if (\is_callable($callback)) {
			$callback($selector, $token);
		}
		else {
			throw new MissingCallbackError();
		}
	}

}
