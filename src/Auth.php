<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

use Delight\Cookie\Cookie;
use Delight\Cookie\Session;
use Delight\Db\PdoDatabase;
use Delight\Db\PdoDsn;
use Delight\Db\Throwable\Error;
use Delight\Db\Throwable\IntegrityConstraintViolationException;

require __DIR__.'/Base64.php';
require __DIR__.'/Exceptions.php';

/** Base class that provides all methods, properties and utilities for secure authentication */
class Auth {

	const SESSION_FIELD_LOGGED_IN = 'auth_logged_in';
	const SESSION_FIELD_USER_ID = 'auth_user_id';
	const SESSION_FIELD_EMAIL = 'auth_email';
	const SESSION_FIELD_USERNAME = 'auth_username';
	const SESSION_FIELD_REMEMBERED = 'auth_remembered';
	const COOKIE_CONTENT_SEPARATOR = '~';
	const COOKIE_NAME_REMEMBER = 'auth_remember';
	const IP_ADDRESS_HASH_ALGORITHM = 'sha256';
	const THROTTLE_ACTION_LOGIN = 'login';
	const THROTTLE_ACTION_REGISTER = 'register';
	const THROTTLE_ACTION_CONSUME_TOKEN = 'confirm_email';
	const HTTP_STATUS_CODE_TOO_MANY_REQUESTS = 429;

	/** @var PdoDatabase the database connection that will be used */
	private $db;
	/** @var boolean whether HTTPS (TLS/SSL) will be used (recommended) */
	private $useHttps;
	/** @var boolean whether cookies should be accessible via client-side scripts (*not* recommended) */
	private $allowCookiesScriptAccess;
	/** @var string the user's current IP address */
	private $ipAddress;
	/** @var int the number of actions allowed (in throttling) per time bucket */
	private $throttlingActionsPerTimeBucket;
	/** @var int the size of the time buckets (used for throttling) in seconds */
	private $throttlingTimeBucketSize;

	/**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection the database connection that will be used
	 * @param bool $useHttps whether HTTPS (TLS/SSL) will be used (recommended)
	 * @param bool $allowCookiesScriptAccess whether cookies should be accessible via client-side scripts (*not* recommended)
	 * @param string $ipAddress the IP address that should be used instead of the default setting (if any), e.g. when behind a proxy
	 */
	public function __construct($databaseConnection, $useHttps = false, $allowCookiesScriptAccess = false, $ipAddress = null) {
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
			throw new \InvalidArgumentException('The database connection must be an instance of either `PdoDatabase`, `PdoDsn` or `PDO`');
		}

		$this->useHttps = $useHttps;
		$this->allowCookiesScriptAccess = $allowCookiesScriptAccess;
		$this->ipAddress = empty($ipAddress) ? $_SERVER['REMOTE_ADDR'] : $ipAddress;
		$this->throttlingActionsPerTimeBucket = 20;
		$this->throttlingTimeBucketSize = 3600;

		$this->initSession();
		$this->enhanceHttpSecurity();

		$this->processRememberDirective();
	}

	/** Initializes the session and sets the correct configuration */
	private function initSession() {
		// use cookies to store session IDs
		ini_set('session.use_cookies', 1);
		// use cookies only (do not send session IDs in URLs)
		ini_set('session.use_only_cookies', 1);
		// do not send session IDs in URLs
		ini_set('session.use_trans_sid', 0);

		// get our cookie settings
		$params = $this->createCookieSettings();
		// define our new cookie settings
		session_set_cookie_params($params['lifetime'], $params['path'], $params['domain'], $params['secure'], $params['httponly']);

		// start the session
		@Session::start();
	}

	/** Improves the application's security over HTTP(S) by setting specific headers */
	private function enhanceHttpSecurity() {
		// remove exposure of PHP version (at least where possible)
		header_remove('X-Powered-By');

		// if the user is signed in
		if ($this->isLoggedIn()) {
			// prevent clickjacking
			header('X-Frame-Options: sameorigin');
			// prevent content sniffing (MIME sniffing)
			header('X-Content-Type-Options: nosniff');

			// disable caching of potentially sensitive data
			header('Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0', true);
			header('Expires: Thu, 19 Nov 1981 00:00:00 GMT', true);
			header('Pragma: no-cache', true);
		}
	}

	/** Checks if there is a "remember me" directive set and handles the automatic login (if appropriate) */
	private function processRememberDirective() {
		// if the user is not signed in yet
		if (!$this->isLoggedIn()) {
			// if a remember cookie is set
			if (isset($_COOKIE[self::COOKIE_NAME_REMEMBER])) {
				// split the cookie's content into selector and token
				$parts = explode(self::COOKIE_CONTENT_SEPARATOR, $_COOKIE[self::COOKIE_NAME_REMEMBER], 2);
				// if both selector and token were found
				if (isset($parts[0]) && isset($parts[1])) {
					try {
						$rememberData = $this->db->selectRow(
							'SELECT a.user, a.token, a.expires, b.email, b.username FROM users_remembered AS a JOIN users AS b ON a.user = b.id WHERE a.selector = ?',
							[ $parts[0] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError();
					}

					if (!empty($rememberData)) {
						if ($rememberData['expires'] >= time()) {
							if (password_verify($parts[1], $rememberData['token'])) {
								$this->onLoginSuccessful($rememberData['user'], $rememberData['email'], $rememberData['username'], true);
							}
						}
					}
				}
			}
		}
	}

	/**
	 * Attempts to sign up a user
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
	 * @param string $email the email address to register
	 * @param string $password the password for the new account
	 * @param string|null $username (optional) the username that will be displayed
	 * @param callable|null $callback (optional) the function that sends the confirmation email to the user
	 * @return int the ID of the user that has been created (if any)
	 * @throws InvalidEmailException if the email address was invalid
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws UserAlreadyExistsException if a user with the specified email address already exists
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function register($email, $password, $username = null, callable $callback = null) {
		return $this->createUserInternal(false, $email, $password, $username, $callback);
	}

	/**
	 * Attempts to sign up a user while ensuring that the username is unique
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
	 * @param string $email the email address to register
	 * @param string $password the password for the new account
	 * @param string|null $username (optional) the username that will be displayed
	 * @param callable|null $callback (optional) the function that sends the confirmation email to the user
	 * @return int the ID of the user that has been created (if any)
	 * @throws InvalidEmailException if the email address was invalid
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws UserAlreadyExistsException if a user with the specified email address already exists
	 * @throws DuplicateUsernameException if the specified username wasn't unique
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function registerWithUniqueUsername($email, $password, $username = null, callable $callback = null) {
		return $this->createUserInternal(true, $email, $password, $username, $callback);
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
	 * @param string $email the email address to verify
	 * @param callable $callback the function that sends the confirmation email to the user
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function createConfirmationRequest($email, callable $callback) {
		$selector = self::createRandomString(16);
		$token = self::createRandomString(16);
		$tokenHashed = password_hash($token, PASSWORD_DEFAULT);

		// the request shall be valid for one day
		$expires = time() + 60 * 60 * 24;

		try {
			$this->db->insert(
				'users_confirmations',
				[
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

		if (isset($callback) && is_callable($callback)) {
			$callback($selector, $token);
		}
		else {
			throw new MissingCallbackError();
		}
	}

	/**
	 * Attempts to sign in a user
	 *
	 * @param string $email the user's email address
	 * @param string $password the user's password
	 * @param int|bool|null $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
	 * @throws InvalidEmailException if the email address was invalid or could not be found
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function login($email, $password, $rememberDuration = null) {
		$this->authenticateUserInternal($password, $email, $rememberDuration);
	}

	/**
	 * Validates an email address
	 *
	 * @param string $email the email address to validate
	 * @return string the email address if it's valid
	 * @throws InvalidEmailException if the email address was invalid
	 */
	private static function validateEmailAddress($email) {
		if (empty($email)) {
			throw new InvalidEmailException();
		}

		$email = trim($email);

		if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
			throw new InvalidEmailException();
		}

		return $email;
	}

	/**
	 * Validates a password
	 *
	 * @param string $password the password to validate
	 * @return string the password if it's valid
	 * @throws InvalidPasswordException if the password was invalid
	 */
	private static function validatePassword($password) {
		if (empty($password)) {
			throw new InvalidPasswordException();
		}

		$password = trim($password);

		if (strlen($password) < 1) {
			throw new InvalidPasswordException();
		}

		return $password;
	}

	/**
	 * Creates a new directive keeping the user logged in ("remember me")
	 *
	 * @param int $userId the user ID to keep signed in
	 * @param int $duration the duration in seconds
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function createRememberDirective($userId, $duration) {
		$selector = self::createRandomString(24);
		$token = self::createRandomString(32);
		$tokenHashed = password_hash($token, PASSWORD_DEFAULT);
		$expires = time() + ((int) $duration);

		try {
			$this->db->insert(
				'users_remembered',
				[
					'user' => $userId,
					'selector' => $selector,
					'token' => $tokenHashed,
					'expires' => $expires
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		$this->setRememberCookie($selector, $token, $expires);
	}

	/**
	 * Clears an existing directive that keeps the user logged in ("remember me")
	 *
	 * @param int $userId the user ID that shouldn't be kept signed in anymore
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function deleteRememberDirective($userId) {
		try {
			$this->db->delete(
				'users_remembered',
				[ 'user' => $userId ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		$this->setRememberCookie(null, null, time() - 3600);
	}

	/**
	 * Sets or updates the cookie that manages the "remember me" token
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @param int $expires the interval in seconds after which the token should expire
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function setRememberCookie($selector, $token, $expires) {
		// get our cookie settings
		$params = $this->createCookieSettings();

		if (isset($selector) && isset($token)) {
			$content = $selector . self::COOKIE_CONTENT_SEPARATOR . $token;
		}
		else {
			$content = '';
		}

		// set the cookie with the selector and token
		$cookie = new Cookie(self::COOKIE_NAME_REMEMBER);
		$cookie->setValue($content);
		$cookie->setExpiryTime($expires);
		if (!empty($params['path'])) {
			$cookie->setPath($params['path']);
		}
		if (!empty($params['domain'])) {
			$cookie->setDomain($params['domain']);
		}
		$cookie->setHttpOnly($params['httponly']);
		$cookie->setSecureOnly($params['secure']);
		$result = $cookie->save();

		if ($result === false) {
			throw new HeadersAlreadySentError();
		}
	}

	/**
	 * Called when the user has successfully logged in (via standard login or "remember me")
	 *
	 * @param int $userId the ID of the user who has just logged in
	 * @param string $email the email address of the user who has just logged in
	 * @param string $username the username (if any)
	 * @param bool $remembered whether the user was remembered ("remember me") or logged in actively
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function onLoginSuccessful($userId, $email, $username, $remembered) {
		try {
			$this->db->update(
				'users',
				[ 'last_login' => time() ],
				[ 'id' => $userId ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		// re-generate the session ID to prevent session fixation attacks
		Session::regenerate(true);

		// save the user data in the session
		$this->setLoggedIn(true);
		$this->setUserId($userId);
		$this->setEmail($email);
		$this->setUsername($username);
		$this->setRemembered($remembered);
	}

	/**
	 * Logs out the user and destroys all session data
	 *
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function logout() {
		// if the user has been signed in
		if ($this->isLoggedIn()) {
			// get the user's ID
			$userId = $this->getUserId();
			// if a user ID was set
			if (isset($userId)) {
				// delete any existing remember directives
				$this->deleteRememberDirective($userId);
			}
		}

		// unset the session variables
		$_SESSION = array();

		// delete the cookie
		$this->deleteSessionCookie();

		// destroy the session
		session_destroy();
	}

	/**
	 * Deletes the session cookie on the client
	 *
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function deleteSessionCookie() {
		// get our cookie settings
		$params = $this->createCookieSettings();

		// cause the session cookie to be deleted
		$cookie = new Cookie(session_name());
		if (!empty($params['path'])) {
			$cookie->setPath($params['path']);
		}
		if (!empty($params['domain'])) {
			$cookie->setDomain($params['domain']);
		}
		$cookie->setHttpOnly($params['httponly']);
		$cookie->setSecureOnly($params['secure']);
		$result = $cookie->delete();

		if ($result === false) {
			throw new HeadersAlreadySentError();
		}
	}

	/**
	 * Confirms an email address and activates the account by supplying the correct selector/token pair
	 *
	 * The selector/token pair must have been generated previously by registering a new account
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function confirmEmail($selector, $token) {
		$this->throttle(self::THROTTLE_ACTION_CONSUME_TOKEN);
		$this->throttle(self::THROTTLE_ACTION_CONSUME_TOKEN, $selector);

		try {
			$confirmationData = $this->db->selectRow(
				'SELECT id, email, token, expires FROM users_confirmations WHERE selector = ?',
				[ $selector ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		if (!empty($confirmationData)) {
			if (password_verify($token, $confirmationData['token'])) {
				if ($confirmationData['expires'] >= time()) {
					try {
						$this->db->update(
							'users',
							[ 'verified' => 1 ],
							[ 'email' => $confirmationData['email'] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError();
					}

					try {
						$this->db->delete(
							'users_confirmations',
							[ 'id' => $confirmationData['id'] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError();
					}
				}
				else {
					throw new TokenExpiredException();
				}
			}
			else {
				throw new InvalidSelectorTokenPairException();
			}
		}
		else {
			throw new InvalidSelectorTokenPairException();
		}
	}

	/**
	 * Changes the (currently logged-in) user's password
	 *
	 * @param string $oldPassword the old password to verify account ownership
	 * @param string $newPassword the new password that should be used
	 * @throws NotLoggedInException if the user is not currently logged in
	 * @throws InvalidPasswordException if either the old password was wrong or the new password was invalid
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function changePassword($oldPassword, $newPassword) {
		if ($this->isLoggedIn()) {
			$oldPassword = self::validatePassword($oldPassword);
			$newPassword = self::validatePassword($newPassword);

			$userId = $this->getUserId();

			try {
				$passwordInDatabase = $this->db->selectValue(
					'SELECT password FROM users WHERE id = ?',
					[ $userId ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError();
			}

			if (!empty($passwordInDatabase)) {
				if (password_verify($oldPassword, $passwordInDatabase)) {
					// update the password in the database
					$this->updatePassword($userId, $newPassword);

					// delete any remaining remember directives
					$this->deleteRememberDirective($userId);
				}
				else {
					throw new InvalidPasswordException();
				}
			}
			else {
				throw new NotLoggedInException();
			}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Updates the given user's password by setting it to the new specified password
	 *
	 * @param int $userId the ID of the user whose password should be updated
	 * @param string $newPassword the new password
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function updatePassword($userId, $newPassword) {
		$newPassword = password_hash($newPassword, PASSWORD_DEFAULT);

		try {
			$this->db->update(
				'users',
				[ 'password' => $newPassword ],
				[ 'id' => $userId ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}
	}

	/**
	 * Initiates a password reset request for the user with the specified email address
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to proceed to the second step of the password reset, both pieces will be required again
	 *
	 * @param string $email the email address of the user who wants to request the password reset
	 * @param callable $callback the function that sends the password reset information to the user
	 * @param int|null $requestExpiresAfter (optional) the interval in seconds after which the request should expire
	 * @param int|null $maxOpenRequests (optional) the maximum number of unexpired and unused requests per user
	 * @throws InvalidEmailException if the email address was invalid or could not be found
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function forgotPassword($email, callable $callback, $requestExpiresAfter = null, $maxOpenRequests = null) {
		$email = self::validateEmailAddress($email);

		if ($requestExpiresAfter === null) {
			// use six hours as the default
			$requestExpiresAfter = 60 * 60 * 6;
		}
		else {
			$requestExpiresAfter = (int) $requestExpiresAfter;
		}

		if ($maxOpenRequests === null) {
			// use two requests per user as the default
			$maxOpenRequests = 2;
		}
		else {
			$maxOpenRequests = (int) $maxOpenRequests;
		}

		$userData = $this->getUserDataByEmailAddress(
			$email,
			[ 'id', 'verified' ]
		);

		// ensure that the account has been verified before initiating a password reset
		if ($userData['verified'] !== 1) {
			throw new EmailNotVerifiedException();
		}

		$openRequests = (int) $this->getOpenPasswordResetRequests($userData['id']);

		if ($openRequests < $maxOpenRequests) {
			$this->createPasswordResetRequest($userData['id'], $requestExpiresAfter, $callback);
		}
		else {
			self::onTooManyRequests($requestExpiresAfter);
		}
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
	 * @throws InvalidEmailException if the email address was invalid
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws UserAlreadyExistsException if a user with the specified email address already exists
	 * @throws DuplicateUsernameException if it was specified that the username must be unique while it was *not*
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function createUserInternal($requireUniqueUsername, $email, $password, $username = null, callable $callback = null) {
		$this->throttle(self::THROTTLE_ACTION_REGISTER);

		ignore_user_abort(true);

		$email = self::validateEmailAddress($email);
		$password = self::validatePassword($password);

		$username = isset($username) ? trim($username) : null;

		// if the uniqueness of the username is to be ensured
		if ($requireUniqueUsername) {
			// count the number of users who do already have that specified username
			$occurrencesOfUsername = $this->db->selectValue(
				'SELECT COUNT(*) FROM users WHERE username = ?',
				[ $username ]
			);

			// if any user with that username does already exist
			if ($occurrencesOfUsername > 0) {
				// cancel the operation and report the violation of this requirement
				throw new DuplicateUsernameException();
			}
		}

		$password = password_hash($password, PASSWORD_DEFAULT);
		$verified = isset($callback) && is_callable($callback) ? 0 : 1;

		try {
			$this->db->insert(
				'users',
				[
					'email' => $email,
					'password' => $password,
					'username' => $username,
					'verified' => $verified,
					'registered' => time()
				]
			);
		}
		catch (IntegrityConstraintViolationException $e) {
			// if we have a duplicate entry
			throw new UserAlreadyExistsException();
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		$newUserId = (int) $this->db->getLastInsertId();

		if ($verified === 0) {
			$this->createConfirmationRequest($email, $callback);
		}

		return $newUserId;
	}

	/**
	 * Authenticates an existing user
	 *
	 * @param string $password the user's password
	 * @param string $email the user's email address
	 * @param int|bool|null $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
	 * @throws InvalidEmailException if the email address was invalid or could not be found
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function authenticateUserInternal($password, $email, $rememberDuration = null) {
		$email = self::validateEmailAddress($email);

		try {
			$userData = $this->db->selectRow(
				'SELECT id, password, verified, username FROM users WHERE email = ?',
				[ $email ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		if (!empty($userData)) {
			$password = self::validatePassword($password);

			if (password_verify($password, $userData['password'])) {
				// if the password needs to be re-hashed to keep up with improving password cracking techniques
				if (password_needs_rehash($userData['password'], PASSWORD_DEFAULT)) {
					// create a new hash from the password and update it in the database
					$this->updatePassword($userData['id'], $password);
				}

				if ($userData['verified'] === 1) {
					$this->onLoginSuccessful($userData['id'], $email, $userData['username'], false);

					// continue to support the old parameter format
					if ($rememberDuration === true) {
						$rememberDuration = 60 * 60 * 24 * 28;
					}
					elseif ($rememberDuration === false) {
						$rememberDuration = null;
					}

					if ($rememberDuration !== null) {
						$this->createRememberDirective($userData['id'], $rememberDuration);
					}

					return;
				}
				else {
					throw new EmailNotVerifiedException();
				}
			}
			else {
				$this->throttle(self::THROTTLE_ACTION_LOGIN);
				$this->throttle(self::THROTTLE_ACTION_LOGIN, $email);

				throw new InvalidPasswordException();
			}
		}
		else {
			$this->throttle(self::THROTTLE_ACTION_LOGIN);
			$this->throttle(self::THROTTLE_ACTION_LOGIN, $email);

			throw new InvalidEmailException();
		}
	}

	/**
	 * Returns the requested user data for the account with the specified email address (if any)
	 *
	 * You must never pass untrusted input to the parameter that takes the column list
	 *
	 * @param string $email the email address to look for
	 * @param array $requestColumns the columns to request from the user's record
	 * @return array the user data (if an account was found)
	 * @throws InvalidEmailException if the email address could not be found
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function getUserDataByEmailAddress($email, array $requestColumns) {
		try {
			$projection = implode(', ', $requestColumns);
			$userData = $this->db->selectRow(
				'SELECT ' . $projection . ' FROM users WHERE email = ?',
				[ $email ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		if (!empty($userData)) {
			return $userData;
		}
		else {
			throw new InvalidEmailException();
		}
	}

	/**
	 * Returns the number of open requests for a password reset by the specified user
	 *
	 * @param int $userId the ID of the user to check the requests for
	 * @return int the number of open requests for a password reset
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function getOpenPasswordResetRequests($userId) {
		try {
			$requests = $this->db->selectValue(
				'SELECT COUNT(*) FROM users_resets WHERE user = ? AND expires > ?',
				[
					$userId,
					time()
				]
			);

			if (!empty($requests)) {
				return $requests;
			}
			else {
				return 0;
			}
		}
		catch (Error $e) {
			throw new DatabaseError();
		}
	}

	/**
	 * Creates a new password reset request
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to proceed to the second step of the password reset, both pieces will be required again
	 *
	 * @param int $userId the ID of the user who requested the reset
	 * @param int $expiresAfter the interval in seconds after which the request should expire
	 * @param callable $callback the function that sends the password reset information to the user
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function createPasswordResetRequest($userId, $expiresAfter, callable $callback) {
		$selector = self::createRandomString(20);
		$token = self::createRandomString(20);
		$tokenHashed = password_hash($token, PASSWORD_DEFAULT);
		$expiresAt = time() + $expiresAfter;

		try {
			$this->db->insert(
				'users_resets',
				[
					'user' => $userId,
					'selector' => $selector,
					'token' => $tokenHashed,
					'expires' => $expiresAt
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		if (isset($callback) && is_callable($callback)) {
			$callback($selector, $token);
		}
		else {
			throw new MissingCallbackError();
		}
	}

	/**
	 * Resets the password for a particular account by supplying the correct selector/token pair
	 *
	 * The selector/token pair must have been generated previously by calling `Auth#forgotPassword(...)`
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @param string $newPassword the new password to set for the account
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws InvalidPasswordException if the new password was invalid
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function resetPassword($selector, $token, $newPassword) {
		$this->throttle(self::THROTTLE_ACTION_CONSUME_TOKEN);
		$this->throttle(self::THROTTLE_ACTION_CONSUME_TOKEN, $selector);

		try {
			$resetData = $this->db->selectRow(
				'SELECT id, user, token, expires FROM users_resets WHERE selector = ?',
				[ $selector ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		if (!empty($resetData)) {
			if (password_verify($token, $resetData['token'])) {
				if ($resetData['expires'] >= time()) {
					$newPassword = self::validatePassword($newPassword);

					// update the password in the database
					$this->updatePassword($resetData['user'], $newPassword);

					// delete any remaining remember directives
					$this->deleteRememberDirective($resetData['user']);

					try {
						$this->db->delete(
							'users_resets',
							[ 'id' => $resetData['id'] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError();
					}
				}
				else {
					throw new TokenExpiredException();
				}
			}
			else {
				throw new InvalidSelectorTokenPairException();
			}
		}
		else {
			throw new InvalidSelectorTokenPairException();
		}
	}

	/**
	 * Check if the supplied selector/token pair can be used to reset a password
	 *
	 * The selector/token pair must have been generated previously by calling `Auth#forgotPassword(...)`
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @return bool whether the password can be reset using the supplied information
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function canResetPassword($selector, $token) {
		try {
			// pass an invalid password intentionally to force an expected error
			$this->resetPassword($selector, $token, null);

			// we should already be in the `catch` block now so this is not expected
			throw new AuthError();
		}
		// if the password is the only thing that's invalid
		catch (InvalidPasswordException $e) {
			// the password can be reset
			return true;
		}
		// if some other things failed (as well)
		catch (AuthException $e) {
			return false;
		}
	}

	/**
	 * Sets whether the user is currently logged in and updates the session
	 *
	 * @param bool $loggedIn whether the user is logged in or not
	 */
	private function setLoggedIn($loggedIn) {
		$_SESSION[self::SESSION_FIELD_LOGGED_IN] = $loggedIn;
	}

	/**
	 * Returns whether the user is currently logged in by reading from the session
	 *
	 * @return boolean whether the user is logged in or not
	 */
	public function isLoggedIn() {
		return isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_LOGGED_IN]) && $_SESSION[self::SESSION_FIELD_LOGGED_IN] === true;
	}

	/**
	 * Shorthand/alias for ´isLoggedIn()´
	 *
	 * @return boolean
	 */
	public function check() {
		return $this->isLoggedIn();
	}

	/**
	 * Sets the currently signed-in user's ID and updates the session
	 *
	 * @param int $userId the user's ID
	 */
	private function setUserId($userId) {
		$_SESSION[self::SESSION_FIELD_USER_ID] = intval($userId);
	}

	/**
	 * Returns the currently signed-in user's ID by reading from the session
	 *
	 * @return int the user ID
	 */
	public function getUserId() {
		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_USER_ID])) {
			return $_SESSION[self::SESSION_FIELD_USER_ID];
		}
		else {
			return null;
		}
	}

	/**
	 * Shorthand/alias for `getUserId()`
	 *
	 * @return int
	 */
	public function id() {
		return $this->getUserId();
	}

	/**
	 * Sets the currently signed-in user's email address and updates the session
	 *
	 * @param string $email the email address
	 */
	private function setEmail($email) {
		$_SESSION[self::SESSION_FIELD_EMAIL] = $email;
	}

	/**
	 * Returns the currently signed-in user's email address by reading from the session
	 *
	 * @return string the email address
	 */
	public function getEmail() {
		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_EMAIL])) {
			return $_SESSION[self::SESSION_FIELD_EMAIL];
		}
		else {
			return null;
		}
	}

	/**
	 * Sets the currently signed-in user's display name and updates the session
	 *
	 * @param string $username the display name
	 */
	private function setUsername($username) {
		$_SESSION[self::SESSION_FIELD_USERNAME] = $username;
	}

	/**
	 * Returns the currently signed-in user's display name by reading from the session
	 *
	 * @return string the display name
	 */
	public function getUsername() {
		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_USERNAME])) {
			return $_SESSION[self::SESSION_FIELD_USERNAME];
		}
		else {
			return null;
		}
	}

	/**
	 * Sets whether the currently signed-in user has been remembered by a long-lived cookie
	 *
	 * @param bool $remembered whether the user was remembered
	 */
	private function setRemembered($remembered) {
		$_SESSION[self::SESSION_FIELD_REMEMBERED] = $remembered;
	}

	/**
	 * Returns whether the currently signed-in user has been remembered by a long-lived cookie
	 *
	 * @return bool whether they have been remembered
	 */
	public function isRemembered() {
		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_REMEMBERED])) {
			return $_SESSION[self::SESSION_FIELD_REMEMBERED];
		}
		else {
			return null;
		}
	}

	/**
	 * Hashes the supplied data
	 *
	 * @param mixed $data the data to hash
	 * @return string the hash in Base64-encoded format
	 */
	private static function hash($data) {
		$hashRaw = hash(self::IP_ADDRESS_HASH_ALGORITHM, $data, true);

		return base64_encode($hashRaw);
	}

	/**
	 * Returns the user's current IP address
	 *
	 * @return string the IP address (IPv4 or IPv6)
	 */
	public function getIpAddress() {
		return $this->ipAddress;
	}

	/**
	 * Returns the current time bucket that is used for throttling purposes
	 *
	 * @return int the time bucket
	 */
	private function getTimeBucket() {
		return (int) (time() / $this->throttlingTimeBucketSize);
	}

	/**
	 * Throttles the specified action for the user to protect against too many requests
	 *
	 * @param string $actionType one of the `THROTTLE_ACTION_*` constants
	 * @param mixed|null $customSelector a custom selector to use for throttling (if any), otherwise the IP address will be used
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function throttle($actionType, $customSelector = null) {
		// if a custom selector has been provided (e.g. username, user ID or confirmation token)
		if (isset($customSelector)) {
			// use the provided selector for throttling
			$selector = self::hash($customSelector);
		}
		// if no custom selector was provided
		else {
			// throttle by the user's IP address
			$selector = self::hash($this->getIpAddress());
		}

		// get the time bucket that we do the throttling for
		$timeBucket = self::getTimeBucket();

		try {
			$this->db->insert(
				'users_throttling',
				[
					'action_type' => $actionType,
					'selector' => $selector,
					'time_bucket' => $timeBucket,
					'attempts' => 1
				]
			);
		}
		catch (IntegrityConstraintViolationException $e) {
			// if we have a duplicate entry, update the old entry
			try {
				$this->db->exec(
					'UPDATE users_throttling SET attempts = attempts+1 WHERE action_type = ? AND selector = ? AND time_bucket = ?',
					[
						$actionType,
						$selector,
						$timeBucket
					]
				);
			}
			catch (Error $e) {
				throw new DatabaseError();
			}
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		try {
			$attempts = $this->db->selectValue(
				'SELECT attempts FROM users_throttling WHERE action_type = ? AND selector = ? AND time_bucket = ?',
				[
					$actionType,
					$selector,
					$timeBucket
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		if (!empty($attempts)) {
			// if the number of attempts has acceeded our accepted limit
			if ($attempts > $this->throttlingActionsPerTimeBucket) {
				self::onTooManyRequests($this->throttlingTimeBucketSize);
			}
		}
	}

	/**
	 * Called when there have been too many requests for some action or object
	 *
	 * @param int|null $retryAfterInterval (optional) the interval in seconds after which the client should retry
	 * @throws TooManyRequestsException to inform any calling method about this problem
	 */
	private static function onTooManyRequests($retryAfterInterval = null) {
		// if no interval has been provided after which the client should retry
		if ($retryAfterInterval === null) {
			// use one day as the default
			$retryAfterInterval = 60 * 60 * 24;
		}

		// send an appropriate HTTP status code
		http_response_code(self::HTTP_STATUS_CODE_TOO_MANY_REQUESTS);
		// tell the client when they should try again
		@header('Retry-After: '.$retryAfterInterval);
		// throw an exception
		throw new TooManyRequestsException();
	}

	/**
	 * Customizes the throttling options
	 *
	 * @param int $actionsPerTimeBucket the number of allowed attempts/requests per time bucket
	 * @param int $timeBucketSize the size of the time buckets in seconds
	 */
	public function setThrottlingOptions($actionsPerTimeBucket, $timeBucketSize) {
		$this->throttlingActionsPerTimeBucket = intval($actionsPerTimeBucket);

		if (isset($timeBucketSize)) {
			$this->throttlingTimeBucketSize = intval($timeBucketSize);
		}
	}

	/**
	 * Creates the cookie settings that will be used to create and update cookies on the client
	 *
	 * @return array the cookie settings
	 */
	private function createCookieSettings() {
		// get the default cookie settings
		$params = session_get_cookie_params();

		// check if we want to send cookies via SSL/TLS only
		$params['secure'] = $params['secure'] || $this->useHttps;
		// check if we want to send cookies via HTTP(S) only
		$params['httponly'] = $params['httponly'] || !$this->allowCookiesScriptAccess;

		// return the modified settings
		return $params;
	}

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
		$bytes = floor(intval($maxLength) / 4) * 3;
		// get random data
		$data = openssl_random_pseudo_bytes($bytes);

		// return the Base64-encoded result
		return Base64::encode($data, true);
	}

	/**
	 * Creates a UUID v4 as per RFC 4122
	 *
	 * The UUID contains 128 bits of data (where 122 are random), i.e. 36 characters
	 *
	 * @return string the UUID
	 * @author Jack @ Stack Overflow
	 */
	public static function createUuid() {
		$data = openssl_random_pseudo_bytes(16);

		// set the version to 0100
		$data[6] = chr(ord($data[6]) & 0x0f | 0x40);
		// set bits 6-7 to 10
		$data[8] = chr(ord($data[8]) & 0x3f | 0x80);

		return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
	}

}
