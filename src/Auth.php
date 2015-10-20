<?php

/**
 * Copyright 2015 delight.im <info@delight.im>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Delight\Auth;

require __DIR__.'/Base64.php';
require __DIR__.'/Exceptions.php';

/** Secure authentication for PHP, once and for all, really simple to use */
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
	const THROTTLE_ACTION_CONFIRM_EMAIL = 'confirm_email';
	const THROTTLE_HTTP_RESPONSE_CODE = 429;

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
		@session_start();
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
					$stmt->bindParam(':selector', $parts[0], \PDO::PARAM_STR);
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
	 * If you want accounts to be activated by default, pass `null` as the fourth argument
	 *
	 * If you want to perform email verification, pass `function ($selector, $token) {}` as the fourth argument
	 *
	 * @param string $email the email address to register
	 * @param string $password the password for the new account
	 * @param string|null $username (optional) the username that will be displayed
	 * @param callable|null $emailConfirmationCallback (optional) the function that sends the confirmation email
	 * @return int the ID of the user that has been created (if any)
	 * @throws InvalidEmailException if the email address was invalid
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws UserAlreadyExistsException if a user with the specified email address already exists
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function register($email, $password, $username = null, callable $emailConfirmationCallback = null) {
		$this->throttle(self::THROTTLE_ACTION_REGISTER);

		$email = isset($email) ? trim($email) : null;
		if (empty($email)) {
			throw new InvalidEmailException();
		}
		if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
			throw new InvalidEmailException();
		}

		$password = isset($password) ? trim($password) : null;
		if (empty($password)) {
			throw new InvalidPasswordException();
		}

		$username = isset($username) ? trim($username) : null;
		$registered = time();
		$password = password_hash($password, PASSWORD_DEFAULT);
		$verified = isset($emailConfirmationCallback) && is_callable($emailConfirmationCallback) ? 0 : 1;

		$stmt = $this->db->prepare("INSERT INTO users (email, password, username, verified, registered) VALUES (:email, :password, :username, :verified, :registered)");
		$stmt->bindParam(':email', $email, \PDO::PARAM_STR);
		$stmt->bindParam(':password', $password, \PDO::PARAM_STR);
		$stmt->bindParam(':username', $username, \PDO::PARAM_STR);
		$stmt->bindParam(':verified', $verified, \PDO::PARAM_INT);
		$stmt->bindParam(':registered', $registered, \PDO::PARAM_INT);

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
			$stmt->bindParam(':email', $email, \PDO::PARAM_STR);

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
				$this->createConfirmationRequest($email, $emailConfirmationCallback);

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
	 * @param string $email the email address to verify
	 * @param callable $emailConfirmationCallback the function that sends the confirmation email
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function createConfirmationRequest($email, callable $emailConfirmationCallback) {
		$selector = self::createRandomString(16);
		$token = self::createRandomString(16);
		$tokenHashed = password_hash($token, PASSWORD_DEFAULT);
		$expires = time() + 3600 * 24;

		$stmt = $this->db->prepare("INSERT INTO users_confirmations (email, selector, token, expires) VALUES (:email, :selector, :token, :expires)");
		$stmt->bindParam(':email', $email, \PDO::PARAM_STR);
		$stmt->bindParam(':selector', $selector, \PDO::PARAM_STR);
		$stmt->bindParam(':token', $tokenHashed, \PDO::PARAM_STR);
		$stmt->bindParam(':expires', $expires, \PDO::PARAM_INT);

		if ($stmt->execute()) {
			if (isset($emailConfirmationCallback) && is_callable($emailConfirmationCallback)) {
				$emailConfirmationCallback($selector, $token);
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
	 * @throws InvalidPasswordException if the password was invalid or didn't match the email address
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function login($email, $password, $remember = false) {
		$this->throttle(self::THROTTLE_ACTION_LOGIN);
		$this->throttle(self::THROTTLE_ACTION_LOGIN, $email);

		$email = isset($email) ? trim($email) : null;
		if (empty($email)) {
			throw new InvalidEmailException();
		}
		if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
			throw new InvalidEmailException();
		}

		$password = isset($password) ? trim($password) : null;
		if (empty($password)) {
			throw new InvalidPasswordException();
		}

		$stmt = $this->db->prepare("SELECT id, password, verified, username FROM users WHERE email = :email");
		$stmt->bindParam(':email', $email, \PDO::PARAM_STR);
		if ($stmt->execute()) {
			$userData = $stmt->fetch(\PDO::FETCH_ASSOC);
			if ($userData !== false) {
				if (password_verify($password, $userData['password'])) {
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
					throw new InvalidPasswordException();
				}
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
		$stmt->bindParam(':user', $userId, \PDO::PARAM_INT);
		$stmt->bindParam(':selector', $selector, \PDO::PARAM_STR);
		$stmt->bindParam(':token', $tokenHashed, \PDO::PARAM_STR);
		$stmt->bindParam(':expires', $expires, \PDO::PARAM_INT);

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
		$stmt->bindParam(':user', $userId, \PDO::PARAM_INT);

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
	 * @param int $expires timestamp (in seconds) when the token expires
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
		$result = setcookie(self::COOKIE_NAME_REMEMBER, $content, $expires, $params['path'], $params['domain'], $params['secure'], $params['httponly']);

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
		$lastLogin = time();

		$stmt = $this->db->prepare("UPDATE users SET last_login = :lastLogin WHERE id = :id");
		$stmt->bindParam(':lastLogin', $lastLogin, \PDO::PARAM_INT);
		$stmt->bindParam(':id', $userId, \PDO::PARAM_INT);
		$stmt->execute();

		// re-generate the session ID to prevent session fixation attacks
		session_regenerate_id(true);

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

		// set the cookie with the selector and token
		$result = setcookie(session_name(), '', time() - 3600, $params['path'], $params['domain'], $params['secure'], $params['httponly']);

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
		$this->throttle(self::THROTTLE_ACTION_CONFIRM_EMAIL);
		$this->throttle(self::THROTTLE_ACTION_CONFIRM_EMAIL, $selector);

		$stmt = $this->db->prepare("SELECT id, email, token, expires FROM users_confirmations WHERE selector = :selector");
		$stmt->bindParam(':selector', $selector, \PDO::PARAM_STR);
		if ($stmt->execute()) {
			$confirmationData = $stmt->fetch(\PDO::FETCH_ASSOC);
			if ($confirmationData !== false) {
				if (password_verify($token, $confirmationData['token'])) {
					if ($confirmationData['expires'] >= time()) {
						$verified = 1;

						$stmt = $this->db->prepare("UPDATE users SET verified = :verified WHERE email = :email");
						$stmt->bindParam(':verified', $verified, \PDO::PARAM_INT);
						$stmt->bindParam(':email', $confirmationData['email'], \PDO::PARAM_STR);
						if ($stmt->execute()) {
							$stmt = $this->db->prepare("DELETE FROM users_confirmations WHERE id = :id");
							$stmt->bindParam(':id', $confirmationData['id'], \PDO::PARAM_INT);
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
			$oldPassword = isset($oldPassword) ? trim($oldPassword) : null;
			if (empty($oldPassword)) {
				throw new InvalidPasswordException();
			}

			$newPassword = isset($newPassword) ? trim($newPassword) : null;
			if (empty($newPassword)) {
				throw new InvalidPasswordException();
			}

			$userId = $this->getUserId();

			$stmt = $this->db->prepare("SELECT password FROM users WHERE id = :userId");
			$stmt->bindParam(':userId', $userId, \PDO::PARAM_INT);
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
		$stmt->bindParam(':password', $newPassword, \PDO::PARAM_STR);
		$stmt->bindParam(':userId', $userId, \PDO::PARAM_INT);
		$stmt->execute();
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
	public function throttle($actionType, $customSelector = null) {
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
		$stmt->bindParam(':actionType', $actionType, \PDO::PARAM_STR);
		$stmt->bindParam(':selector', $selector, \PDO::PARAM_STR);
		$stmt->bindParam(':timeBucket', $timeBucket, \PDO::PARAM_INT);
		try {
			$stmt->execute();
		}
		catch (\PDOException $e) {
			// if we have a duplicate entry
			if ($e->getCode() == '23000') {
				// update the old entry
				$stmt = $this->db->prepare('UPDATE users_throttling SET attempts = attempts+1 WHERE action_type = :actionType AND selector = :selector AND time_bucket = :timeBucket');
				$stmt->bindParam(':actionType', $actionType, \PDO::PARAM_STR);
				$stmt->bindParam(':selector', $selector, \PDO::PARAM_STR);
				$stmt->bindParam(':timeBucket', $timeBucket, \PDO::PARAM_INT);
				$stmt->execute();
			}
			// if we have another error
			else {
				// throw an exception
				throw new DatabaseError(null, null, $e);
			}
		}

		$stmt = $this->db->prepare('SELECT attempts FROM users_throttling WHERE action_type = :actionType AND selector = :selector AND time_bucket = :timeBucket');
		$stmt->bindParam(':actionType', $actionType, \PDO::PARAM_STR);
		$stmt->bindParam(':selector', $selector, \PDO::PARAM_STR);
		$stmt->bindParam(':timeBucket', $timeBucket, \PDO::PARAM_INT);
		if ($stmt->execute()) {
			$attempts = $stmt->fetchColumn();

			if ($attempts !== false) {
				// if the number of attempts has acceeded our accepted limit
				if ($attempts > $this->throttlingActionsPerTimeBucket) {
					// send a HTTP status code that indicates active throttling
					http_response_code(self::THROTTLE_HTTP_RESPONSE_CODE);
					// tell the client when they should try again
					@header('Retry-After: '.$this->throttlingTimeBucketSize);
					// throw an exception
					throw new TooManyRequestsException();
				}
			}
		}
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

		// optimize the cookie domain
		$params['domain'] = self::optimizeCookieDomain($params['domain']);
		// check if we want to send cookies via SSL/TLS only
		$params['secure'] = $params['secure'] || $this->useHttps;
		// check if we want to send cookies via HTTP(S) only
		$params['httponly'] = $params['httponly'] || !$this->allowCookiesScriptAccess;

		// return the modified settings
		return $params;
	}

	/**
	 * Optimizes the specified cookie domain
	 *
	 * @param string $domain the supplied cookie domain
	 * @return string the optimized cookie domain
	 */
	private static function optimizeCookieDomain($domain) {
		// if no domain has been explicitly provided
		if (empty($domain)) {
			// use the current hostname as a default
			$domain = $_SERVER['SERVER_NAME'];
		}

		// if the domain name starts with the `www` subdomain
		if (substr($domain, 0, 4) === 'www.') {
			// strip the subdomain
			$domain = substr($domain, 4);
		}

		// count the dots in the domain name
		$numDots = substr_count($domain, '.');

		// if there is no dot at all (usually `localhost`) or only a single dot (no subdomain)
		if ($numDots < 2) {
			// if the domain doesn't already start with a dot
			if (substr($domain, 0, 1) !== '.') {
				// prepend a dot to allow all subdomains
				$domain = '.'.$domain;
			}
		}

		// return the optimized domain name
		return $domain;
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
