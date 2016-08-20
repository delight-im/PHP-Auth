<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

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

	/** @var \PDO the database connection that will be used */
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
	 * @param \PDO $databaseConnection the database connection that will be used
	 * @param bool $useHttps whether HTTPS (TLS/SSL) will be used (recommended)
	 * @param bool $allowCookiesScriptAccess whether cookies should be accessible via client-side scripts (*not* recommended)
	 * @param string $ipAddress the IP address that should be used instead of the default setting (if any), e.g. when behind a proxy
	 */
	public function __construct(\PDO $databaseConnection, $useHttps = false, $allowCookiesScriptAccess = false, $ipAddress = null) {
		$this->db = $databaseConnection;
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
		@\Delight\Cookie\Session::start();
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
					$stmt = $this->db->prepare("SELECT a.user, a.token, a.expires, b.email, b.username FROM users_remembered AS a JOIN users AS b ON a.user = b.id WHERE a.selector = :selector");
					$stmt->bindValue(':selector', $parts[0], \PDO::PARAM_STR);
					if ($stmt->execute()) {
						$rememberData = $stmt->fetch(\PDO::FETCH_ASSOC);
						if ($rememberData !== false) {
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
	}

	/**
	 * Attempts to sign up a user
	 *
	 * If you want accounts to be activated by default, pass `null` as the callback
	 *
	 * If you want to perform email verification, pass an anonymous function as the callback
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
		$this->throttle(self::THROTTLE_ACTION_REGISTER);

		$email = self::validateEmailAddress($email);
		$password = self::validatePassword($password);

		$username = isset($username) ? trim($username) : null;
		$password = password_hash($password, PASSWORD_DEFAULT);
		$verified = isset($callback) && is_callable($callback) ? 0 : 1;

		$stmt = $this->db->prepare("INSERT INTO users (email, password, username, verified, registered) VALUES (:email, :password, :username, :verified, :registered)");
		$stmt->bindValue(':email', $email, \PDO::PARAM_STR);
		$stmt->bindValue(':password', $password, \PDO::PARAM_STR);
		$stmt->bindValue(':username', $username, \PDO::PARAM_STR);
		$stmt->bindValue(':verified', $verified, \PDO::PARAM_INT);
		$stmt->bindValue(':registered', time(), \PDO::PARAM_INT);

		try {
			$result = $stmt->execute();
		}
		catch (\PDOException $e) {
			// if we have a duplicate entry
			if ($e->getCode() == '23000') {
				throw new UserAlreadyExistsException();
			}
			// if we have another error
			else {
				// throw an exception
				throw new DatabaseError(null, null, $e);
			}
		}

		// if creating the new user was successful
		if ($result) {
			// get the ID of the user that we've just created
			$stmt = $this->db->prepare("SELECT id FROM users WHERE email = :email");
			$stmt->bindValue(':email', $email, \PDO::PARAM_STR);

			if ($result = $stmt->execute()) {
				$newUserId = $stmt->fetchColumn();
			}
			else {
				$newUserId = null;
			}

			if ($verified === 1) {
				return $newUserId;
			}
			else {
				$this->createConfirmationRequest($email, $callback);

				return $newUserId;
			}
		}
		else {
			throw new DatabaseError();
		}
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
		$expires = time() + 3600 * 24;

		$stmt = $this->db->prepare("INSERT INTO users_confirmations (email, selector, token, expires) VALUES (:email, :selector, :token, :expires)");
		$stmt->bindValue(':email', $email, \PDO::PARAM_STR);
		$stmt->bindValue(':selector', $selector, \PDO::PARAM_STR);
		$stmt->bindValue(':token', $tokenHashed, \PDO::PARAM_STR);
		$stmt->bindValue(':expires', $expires, \PDO::PARAM_INT);

		if ($stmt->execute()) {
			if (isset($callback) && is_callable($callback)) {
				$callback($selector, $token);
			}
			else {
				throw new MissingCallbackError();
			}

			return;
		}
		else {
			throw new DatabaseError();
		}
	}

	/**
	 * Attempts to sign in a user
	 *
	 * @param string $email the user's email address
	 * @param string $password the user's password
	 * @param bool $remember whether to keep the user logged in ("remember me") or not
	 * @throws InvalidEmailException if the email address was invalid or could not be found
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function login($email, $password, $remember = false) {
		$email = self::validateEmailAddress($email);
		$password = self::validatePassword($password);

		$stmt = $this->db->prepare("SELECT id, password, verified, username FROM users WHERE email = :email");
		$stmt->bindValue(':email', $email, \PDO::PARAM_STR);
		if ($stmt->execute()) {
			$userData = $stmt->fetch(\PDO::FETCH_ASSOC);
			if ($userData !== false) {
				if (password_verify($password, $userData['password'])) {
					// if the password needs to be re-hashed to keep up with improving password cracking techniques
					if (password_needs_rehash($userData['password'], PASSWORD_DEFAULT)) {
						// create a new hash from the password and update it in the database
						$this->updatePassword($userData['id'], $password);
					}

					if ($userData['verified'] == 1) {
						$this->onLoginSuccessful($userData['id'], $email, $userData['username'], false);

						if ($remember) {
							$this->createRememberDirective($userData['id']);
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
		else {
			throw new DatabaseError();
		}
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
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function createRememberDirective($userId) {
		$selector = self::createRandomString(24);
		$token = self::createRandomString(24);
		$tokenHashed = password_hash($token, PASSWORD_DEFAULT);
		$expires = time() + 3600 * 24 * 28;

		$stmt = $this->db->prepare("INSERT INTO users_remembered (user, selector, token, expires) VALUES (:user, :selector, :token, :expires)");
		$stmt->bindValue(':user', $userId, \PDO::PARAM_INT);
		$stmt->bindValue(':selector', $selector, \PDO::PARAM_STR);
		$stmt->bindValue(':token', $tokenHashed, \PDO::PARAM_STR);
		$stmt->bindValue(':expires', $expires, \PDO::PARAM_INT);

		if ($stmt->execute()) {
			$this->setRememberCookie($selector, $token, $expires);

			return;
		}
		else {
			throw new DatabaseError();
		}
	}

	/**
	 * Clears an existing directive that keeps the user logged in ("remember me")
	 *
	 * @param int $userId the user ID that shouldn't be kept signed in anymore
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function deleteRememberDirective($userId) {
		$stmt = $this->db->prepare("DELETE FROM users_remembered WHERE user = :user");
		$stmt->bindValue(':user', $userId, \PDO::PARAM_INT);

		if ($stmt->execute()) {
			$this->setRememberCookie(null, null, time() - 3600);

			return;
		}
		else {
			throw new DatabaseError();
		}
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
		$cookie = new \Delight\Cookie\Cookie(self::COOKIE_NAME_REMEMBER);
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
	 */
	private function onLoginSuccessful($userId, $email, $username, $remembered) {
		$stmt = $this->db->prepare("UPDATE users SET last_login = :lastLogin WHERE id = :id");
		$stmt->bindValue(':lastLogin', time(), \PDO::PARAM_INT);
		$stmt->bindValue(':id', $userId, \PDO::PARAM_INT);
		$stmt->execute();

		// re-generate the session ID to prevent session fixation attacks
		\Delight\Cookie\Session::regenerate(true);

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
		$cookie = new \Delight\Cookie\Cookie(session_name());
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

		$stmt = $this->db->prepare("SELECT id, email, token, expires FROM users_confirmations WHERE selector = :selector");
		$stmt->bindValue(':selector', $selector, \PDO::PARAM_STR);
		if ($stmt->execute()) {
			$confirmationData = $stmt->fetch(\PDO::FETCH_ASSOC);
			if ($confirmationData !== false) {
				if (password_verify($token, $confirmationData['token'])) {
					if ($confirmationData['expires'] >= time()) {
						$stmt = $this->db->prepare("UPDATE users SET verified = :verified WHERE email = :email");
						$stmt->bindValue(':verified', 1, \PDO::PARAM_INT);
						$stmt->bindValue(':email', $confirmationData['email'], \PDO::PARAM_STR);
						if ($stmt->execute()) {
							$stmt = $this->db->prepare("DELETE FROM users_confirmations WHERE id = :id");
							$stmt->bindValue(':id', $confirmationData['id'], \PDO::PARAM_INT);
							if ($stmt->execute()) {
								return;
							}
							else {
								throw new DatabaseError();
							}
						}
						else {
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
		else {
			throw new DatabaseError();
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

			$stmt = $this->db->prepare("SELECT password FROM users WHERE id = :userId");
			$stmt->bindValue(':userId', $userId, \PDO::PARAM_INT);
			if ($stmt->execute()) {
				$passwordInDatabase = $stmt->fetchColumn();
				if (password_verify($oldPassword, $passwordInDatabase)) {
					$this->updatePassword($userId, $newPassword);

					return;
				}
				else {
					throw new InvalidPasswordException();
				}
			}
			else {
				throw new DatabaseError();
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
	 */
	private function updatePassword($userId, $newPassword) {
		$newPassword = password_hash($newPassword, PASSWORD_DEFAULT);

		$stmt = $this->db->prepare("UPDATE users SET password = :password WHERE id = :userId");
		$stmt->bindValue(':password', $newPassword, \PDO::PARAM_STR);
		$stmt->bindValue(':userId', $userId, \PDO::PARAM_INT);
		$stmt->execute();
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

		$userId = $this->getUserIdByEmailAddress($email);
		$openRequests = (int) $this->getOpenPasswordResetRequests($userId);

		if ($openRequests < $maxOpenRequests) {
			$this->createPasswordResetRequest($userId, $requestExpiresAfter, $callback);
		}
		else {
			self::onTooManyRequests($requestExpiresAfter);
		}
	}

	/**
	 * Returns the user ID for the account with the specified email address (if any)
	 *
	 * @param string $email the email address to look for
	 * @return string the user ID (if an account was found)
	 * @throws InvalidEmailException if the email address could not be found
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function getUserIdByEmailAddress($email) {
		$stmt = $this->db->prepare("SELECT id FROM users WHERE email = :email");
		$stmt->bindValue(':email', $email, \PDO::PARAM_STR);

		if ($stmt->execute()) {
			$userId = $stmt->fetchColumn();

			if ($userId !== false) {
				return $userId;
			}
			else {
				throw new InvalidEmailException();
			}
		}
		else {
			throw new DatabaseError();
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
		$stmt = $this->db->prepare("SELECT COUNT(*) FROM users_resets WHERE user = :userId AND expires > :expiresAfter");
		$stmt->bindValue(':userId', $userId, \PDO::PARAM_INT);
		$stmt->bindValue(':expiresAfter', time(), \PDO::PARAM_INT);

		if ($stmt->execute()) {
			return $stmt->fetchColumn();
		}
		else {
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

		$stmt = $this->db->prepare("INSERT INTO users_resets (user, selector, token, expires) VALUES (:userId, :selector, :token, :expires)");
		$stmt->bindValue(':userId', $userId, \PDO::PARAM_INT);
		$stmt->bindValue(':selector', $selector, \PDO::PARAM_STR);
		$stmt->bindValue(':token', $tokenHashed, \PDO::PARAM_STR);
		$stmt->bindValue(':expires', $expiresAt, \PDO::PARAM_INT);

		if ($stmt->execute()) {
			if (isset($callback) && is_callable($callback)) {
				$callback($selector, $token);
			}
			else {
				throw new MissingCallbackError();
			}

			return;
		}
		else {
			throw new DatabaseError();
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

		$stmt = $this->db->prepare("SELECT id, user, token, expires FROM users_resets WHERE selector = :selector");
		$stmt->bindValue(':selector', $selector, \PDO::PARAM_STR);
		if ($stmt->execute()) {
			$resetData = $stmt->fetch(\PDO::FETCH_ASSOC);

			if ($resetData !== false) {
				if (password_verify($token, $resetData['token'])) {
					if ($resetData['expires'] >= time()) {
						$newPassword = self::validatePassword($newPassword);

						$this->updatePassword($resetData['user'], $newPassword);

						$stmt = $this->db->prepare("DELETE FROM users_resets WHERE id = :id");
						$stmt->bindValue(':id', $resetData['id'], \PDO::PARAM_INT);

						if ($stmt->execute()) {
							return;
						}
						else {
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
		else {
			throw new DatabaseError();
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

		$stmt = $this->db->prepare('INSERT INTO users_throttling (action_type, selector, time_bucket, attempts) VALUES (:actionType, :selector, :timeBucket, 1)');
		$stmt->bindValue(':actionType', $actionType, \PDO::PARAM_STR);
		$stmt->bindValue(':selector', $selector, \PDO::PARAM_STR);
		$stmt->bindValue(':timeBucket', $timeBucket, \PDO::PARAM_INT);
		try {
			$stmt->execute();
		}
		catch (\PDOException $e) {
			// if we have a duplicate entry
			if ($e->getCode() == '23000') {
				// update the old entry
				$stmt = $this->db->prepare('UPDATE users_throttling SET attempts = attempts+1 WHERE action_type = :actionType AND selector = :selector AND time_bucket = :timeBucket');
				$stmt->bindValue(':actionType', $actionType, \PDO::PARAM_STR);
				$stmt->bindValue(':selector', $selector, \PDO::PARAM_STR);
				$stmt->bindValue(':timeBucket', $timeBucket, \PDO::PARAM_INT);
				$stmt->execute();
			}
			// if we have another error
			else {
				// throw an exception
				throw new DatabaseError(null, null, $e);
			}
		}

		$stmt = $this->db->prepare('SELECT attempts FROM users_throttling WHERE action_type = :actionType AND selector = :selector AND time_bucket = :timeBucket');
		$stmt->bindValue(':actionType', $actionType, \PDO::PARAM_STR);
		$stmt->bindValue(':selector', $selector, \PDO::PARAM_STR);
		$stmt->bindValue(':timeBucket', $timeBucket, \PDO::PARAM_INT);
		if ($stmt->execute()) {
			$attempts = $stmt->fetchColumn();

			if ($attempts !== false) {
				// if the number of attempts has acceeded our accepted limit
				if ($attempts > $this->throttlingActionsPerTimeBucket) {
					self::onTooManyRequests($this->throttlingTimeBucketSize);
				}
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
