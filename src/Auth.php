<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

use Delight\Base64\Base64;
use Delight\Cookie\Cookie;
use Delight\Cookie\Session;
use Delight\Db\PdoDatabase;
use Delight\Db\PdoDsn;
use Delight\Db\Throwable\Error;
use Delight\Db\Throwable\IntegrityConstraintViolationException;

require_once __DIR__ . '/Exceptions.php';

/** Component that provides all features and utilities for secure authentication of individual users */
final class Auth extends UserManager {

	const SESSION_FIELD_LOGGED_IN = 'auth_logged_in';
	const SESSION_FIELD_USER_ID = 'auth_user_id';
	const SESSION_FIELD_EMAIL = 'auth_email';
	const SESSION_FIELD_USERNAME = 'auth_username';
	const SESSION_FIELD_STATUS = 'auth_status';
	const SESSION_FIELD_ROLES = 'auth_roles';
	const SESSION_FIELD_REMEMBERED = 'auth_remembered';
	const COOKIE_CONTENT_SEPARATOR = '~';
	const COOKIE_NAME_REMEMBER = 'auth_remember';

	/** @var boolean whether HTTPS (TLS/SSL) will be used (recommended) */
	private $useHttps;
	/** @var boolean whether cookies should be accessible via client-side scripts (*not* recommended) */
	private $allowCookiesScriptAccess;
	/** @var string the user's current IP address */
	private $ipAddress;

	/**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection the database connection to operate on
	 * @param bool $useHttps whether HTTPS (TLS/SSL) will be used (recommended)
	 * @param bool $allowCookiesScriptAccess whether cookies should be accessible via client-side scripts (*not* recommended)
	 * @param string $ipAddress the IP address that should be used instead of the default setting (if any), e.g. when behind a proxy
	 * @param string|null $dbTablePrefix (optional) the prefix for the names of all database tables used by this component
	 */
	public function __construct($databaseConnection, $useHttps = false, $allowCookiesScriptAccess = false, $ipAddress = null, $dbTablePrefix = null) {
		parent::__construct($databaseConnection, $dbTablePrefix);

		$this->useHttps = $useHttps;
		$this->allowCookiesScriptAccess = $allowCookiesScriptAccess;
		$this->ipAddress = empty($ipAddress) ? $_SERVER['REMOTE_ADDR'] : $ipAddress;

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
			header('Cache-Control: no-store, no-cache, must-revalidate', true);
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
							'SELECT a.user, a.token, a.expires, b.email, b.username, b.status, b.roles_mask FROM ' . $this->dbTablePrefix . 'users_remembered AS a JOIN ' . $this->dbTablePrefix . 'users AS b ON a.user = b.id WHERE a.selector = ?',
							[ $parts[0] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError();
					}

					if (!empty($rememberData)) {
						if ($rememberData['expires'] >= time()) {
							if (password_verify($parts[1], $rememberData['token'])) {
								$this->onLoginSuccessful($rememberData['user'], $rememberData['email'], $rememberData['username'], $rememberData['status'], $rememberData['roles_mask'], true);
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
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see confirmEmail
	 * @see confirmEmailAndSignIn
	 */
	public function register($email, $password, $username = null, callable $callback = null) {
		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);
		$this->throttle([ 'createNewAccount', $this->getIpAddress() ], 1, (60 * 60 * 12), 5, true);

		$newUserId = $this->createUserInternal(false, $email, $password, $username, $callback);

		$this->throttle([ 'createNewAccount', $this->getIpAddress() ], 1, (60 * 60 * 12), 5, false);

		return $newUserId;
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
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see confirmEmail
	 * @see confirmEmailAndSignIn
	 */
	public function registerWithUniqueUsername($email, $password, $username = null, callable $callback = null) {
		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);
		$this->throttle([ 'createNewAccount', $this->getIpAddress() ], 1, (60 * 60 * 12), 5, true);

		$newUserId = $this->createUserInternal(true, $email, $password, $username, $callback);

		$this->throttle([ 'createNewAccount', $this->getIpAddress() ], 1, (60 * 60 * 12), 5, false);

		return $newUserId;
	}

	/**
	 * Attempts to sign in a user with their email address and password
	 *
	 * @param string $email the user's email address
	 * @param string $password the user's password
	 * @param int|null $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
	 * @param callable|null $onBeforeSuccess (optional) a function that receives the user's ID as its single parameter and is executed before successful authentication; must return `true` to proceed or `false` to cancel
	 * @throws InvalidEmailException if the email address was invalid or could not be found
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws AttemptCancelledException if the attempt has been cancelled by the supplied callback that is executed before success
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function login($email, $password, $rememberDuration = null, callable $onBeforeSuccess = null) {
		$this->throttle([ 'attemptToLogin', 'email', $email ], 500, (60 * 60 * 24), null, true);

		$this->authenticateUserInternal($password, $email, null, $rememberDuration, $onBeforeSuccess);
	}

	/**
	 * Attempts to sign in a user with their username and password
	 *
	 * When using this method to authenticate users, you should ensure that usernames are unique
	 *
	 * Consistently using {@see registerWithUniqueUsername} instead of {@see register} can be helpful
	 *
	 * @param string $username the user's username
	 * @param string $password the user's password
	 * @param int|null $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
	 * @param callable|null $onBeforeSuccess (optional) a function that receives the user's ID as its single parameter and is executed before successful authentication; must return `true` to proceed or `false` to cancel
	 * @throws UnknownUsernameException if the specified username does not exist
	 * @throws AmbiguousUsernameException if the specified username is ambiguous, i.e. there are multiple users with that name
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws AttemptCancelledException if the attempt has been cancelled by the supplied callback that is executed before success
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function loginWithUsername($username, $password, $rememberDuration = null, callable $onBeforeSuccess = null) {
		$this->throttle([ 'attemptToLogin', 'username', $username ], 500, (60 * 60 * 24), null, true);

		$this->authenticateUserInternal($password, null, $username, $rememberDuration, $onBeforeSuccess);
	}

	/**
	 * Attempts to confirm the currently signed-in user's password again
	 *
	 * Whenever you want to confirm the user's identity again, e.g. before
	 * the user is allowed to perform some "dangerous" action, you should
	 * use this method to confirm that the user is who they claim to be.
	 *
	 * For example, when a user has been remembered by a long-lived cookie
	 * and thus {@see isRemembered} returns `true`, this means that the
	 * user has not entered their password for quite some time anymore.
	 *
	 * @param string $password the user's password
	 * @return bool whether the supplied password has been correct
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function reconfirmPassword($password) {
		if ($this->isLoggedIn()) {
			try {
				$password = self::validatePassword($password);
			}
			catch (InvalidPasswordException $e) {
				return false;
			}

			$this->throttle([ 'reconfirmPassword', $this->getIpAddress() ], 3, (60 * 60), 4, true);

			try {
				$expectedHash = $this->db->selectValue(
					'SELECT password FROM ' . $this->dbTablePrefix . 'users WHERE id = ?',
					[ $this->getUserId() ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError();
			}

			if (!empty($expectedHash)) {
				$validated = \password_verify($password, $expectedHash);

				if (!$validated) {
					$this->throttle([ 'reconfirmPassword', $this->getIpAddress() ], 3, (60 * 60), 4, false);
				}

				return $validated;
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
				$this->dbTablePrefix . 'users_remembered',
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
				$this->dbTablePrefix . 'users_remembered',
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
	 * @param int $status the status as one of the constants from the {@see Status} class
	 * @param int $roles the bitmask containing the roles of the user
	 * @param bool $remembered whether the user was remembered ("remember me") or logged in actively
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function onLoginSuccessful($userId, $email, $username, $status, $roles, $remembered) {
		try {
			$this->db->update(
				$this->dbTablePrefix . 'users',
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
		$this->setStatus($status);
		$this->setRoles($roles);
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
	 * Confirms an email address (and activates the account) by supplying the correct selector/token pair
	 *
	 * The selector/token pair must have been generated previously by registering a new account
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @return string the email address that has successfully been verified
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws UserAlreadyExistsException if an attempt has been made to change the email address to a (now) occupied address
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function confirmEmail($selector, $token) {
		$this->throttle([ 'confirmEmail', $this->getIpAddress() ], 5, (60 * 60), 10);
		$this->throttle([ 'confirmEmail', 'selector', $selector ], 3, (60 * 60), 10);
		$this->throttle([ 'confirmEmail', 'token', $token ], 3, (60 * 60), 10);

		try {
			$confirmationData = $this->db->selectRow(
				'SELECT id, user_id, email, token, expires FROM ' . $this->dbTablePrefix . 'users_confirmations WHERE selector = ?',
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
							$this->dbTablePrefix . 'users',
							[
								'email' => $confirmationData['email'],
								'verified' => 1
							],
							[ 'id' => $confirmationData['user_id'] ]
						);
					}
					catch (IntegrityConstraintViolationException $e) {
						throw new UserAlreadyExistsException();
					}
					catch (Error $e) {
						throw new DatabaseError();
					}

					// if the user is currently signed in
					if ($this->isLoggedIn()) {
						// if the user has just confirmed an email address for their own account
						if ($this->getUserId() === $confirmationData['user_id']) {
							// immediately update the email address in the current session as well
							$this->setEmail($confirmationData['email']);
						}
					}

					try {
						$this->db->delete(
							$this->dbTablePrefix . 'users_confirmations',
							[ 'id' => $confirmationData['id'] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError();
					}

					return $confirmationData['email'];
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
	 * Confirms an email address and activates the account by supplying the correct selector/token pair
	 *
	 * The selector/token pair must have been generated previously by registering a new account
	 *
	 * The user will be automatically signed in if this operation is successful
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @param int|null $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
	 * @return string the email address that has successfully been verified
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws UserAlreadyExistsException if an attempt has been made to change the email address to a (now) occupied address
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function confirmEmailAndSignIn($selector, $token, $rememberDuration = null) {
		$verifiedEmail = $this->confirmEmail($selector, $token);

		if (!$this->isLoggedIn()) {
			if ($verifiedEmail !== null) {
				$verifiedEmail = self::validateEmailAddress($verifiedEmail);

				$userData = $this->getUserDataByEmailAddress(
					$verifiedEmail,
					[ 'id', 'email', 'username', 'status', 'roles_mask' ]
				);

				$this->onLoginSuccessful($userData['id'], $userData['email'], $userData['username'], $userData['status'], $userData['roles_mask'], true);

				if ($rememberDuration !== null) {
					$this->createRememberDirective($userData['id'], $rememberDuration);
				}
			}
		}

		return $verifiedEmail;
	}

	/**
	 * Changes the currently signed-in user's password while requiring the old password for verification
	 *
	 * @param string $oldPassword the old password to verify account ownership
	 * @param string $newPassword the new password that should be set
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws InvalidPasswordException if either the old password has been wrong or the desired new one has been invalid
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function changePassword($oldPassword, $newPassword) {
		if ($this->reconfirmPassword($oldPassword)) {
			$this->changePasswordWithoutOldPassword($newPassword);
		}
		else {
			throw new InvalidPasswordException();
		}
	}

	/**
	 * Changes the currently signed-in user's password without requiring the old password for verification
	 *
	 * @param string $newPassword the new password that should be set
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws InvalidPasswordException if the desired new password has been invalid
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function changePasswordWithoutOldPassword($newPassword) {
		if ($this->isLoggedIn()) {
			$newPassword = self::validatePassword($newPassword);
			$userId = $this->getUserId();
			$this->updatePassword($userId, $newPassword);
			$this->deleteRememberDirective($userId);
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
	 * Attempts to change the email address of the currently signed-in user (which requires confirmation)
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to verify their email address as a next step, both pieces will be required again
	 *
	 * @param string $newEmail the desired new email address
	 * @param callable $callback the function that sends the confirmation email to the user
	 * @throws InvalidEmailException if the desired new email address is invalid
	 * @throws UserAlreadyExistsException if a user with the desired new email address already exists
	 * @throws EmailNotVerifiedException if the current (old) email address has not been verified yet
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see confirmEmail
	 * @see confirmEmailAndSignIn
	 */
	public function changeEmail($newEmail, callable $callback) {
		if ($this->isLoggedIn()) {
			$newEmail = self::validateEmailAddress($newEmail);

			$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);

			try {
				$existingUsersWithNewEmail = $this->db->selectValue(
					'SELECT COUNT(*) FROM ' . $this->dbTablePrefix . 'users WHERE email = ?',
					[ $newEmail ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError();
			}

			if ((int) $existingUsersWithNewEmail !== 0) {
				throw new UserAlreadyExistsException();
			}

			try {
				$verified = $this->db->selectValue(
					'SELECT verified FROM ' . $this->dbTablePrefix . 'users WHERE id = ?',
					[ $this->getUserId() ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError();
			}

			// ensure that at least the current (old) email address has been verified before proceeding
			if ((int) $verified !== 1) {
				throw new EmailNotVerifiedException();
			}

			$this->throttle([ 'requestEmailChange', $this->getIpAddress() ], 1, (60 * 60 * 24), 3);
			$this->throttle([ 'requestEmailChange', 'user', $this->getUserId() ], 1, (60 * 60 * 24), 3);

			$this->createConfirmationRequest($this->getUserId(), $newEmail, $callback);
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Attempts to re-send an earlier confirmation request for the user with the specified email address
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to verify their email address as a next step, both pieces will be required again
	 *
	 * @param string $email the email address of the user to re-send the confirmation request for
	 * @param callable $callback the function that sends the confirmation request to the user
	 * @throws ConfirmationRequestNotFound if no previous request has been found that could be re-sent
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 */
	public function resendConfirmationForEmail($email, callable $callback) {
		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);

		$this->resendConfirmationForColumnValue('email', $email, $callback);
	}

	/**
	 * Attempts to re-send an earlier confirmation request for the user with the specified ID
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to verify their email address as a next step, both pieces will be required again
	 *
	 * @param int $userId the ID of the user to re-send the confirmation request for
	 * @param callable $callback the function that sends the confirmation request to the user
	 * @throws ConfirmationRequestNotFound if no previous request has been found that could be re-sent
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 */
	public function resendConfirmationForUserId($userId, callable $callback) {
		$this->resendConfirmationForColumnValue('user_id', $userId, $callback);
	}

	/**
	 * Attempts to re-send an earlier confirmation request
	 *
	 * The callback function must have the following signature:
	 *
	 * `function ($selector, $token)`
	 *
	 * Both pieces of information must be sent to the user, usually embedded in a link
	 *
	 * When the user wants to verify their email address as a next step, both pieces will be required again
	 *
	 * You must never pass untrusted input to the parameter that takes the column name
	 *
	 * @param string $columnName the name of the column to filter by
	 * @param mixed $columnValue the value to look for in the selected column
	 * @param callable $callback the function that sends the confirmation request to the user
	 * @throws ConfirmationRequestNotFound if no previous request has been found that could be re-sent
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function resendConfirmationForColumnValue($columnName, $columnValue, callable $callback) {
		try {
			$latestAttempt = $this->db->selectRow(
				'SELECT user_id, email, expires FROM ' . $this->dbTablePrefix . 'users_confirmations WHERE ' . $columnName . ' = ? ORDER BY id DESC LIMIT 1 OFFSET 0',
				[ $columnValue ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		if ($latestAttempt === null) {
			throw new ConfirmationRequestNotFound();
		}

		$retryAt = $latestAttempt['expires'] - 0.75 * self::CONFIRMATION_REQUESTS_TTL_IN_SECONDS;

		if ($retryAt > \time()) {
			throw new TooManyRequestsException('', $retryAt - \time());
		}

		$this->throttle([ 'resendConfirmation', $this->getIpAddress() ], 4, (60 * 60 * 24 * 7), 2);
		$this->throttle([ 'resendConfirmation', 'user', $latestAttempt['user_id'] ], 4, (60 * 60 * 24 * 7), 2);

		$this->createConfirmationRequest(
			$latestAttempt['user_id'],
			$latestAttempt['email'],
			$callback
		);
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
	 * @throws ResetDisabledException if the user has explicitly disabled password resets for their account
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function forgotPassword($email, callable $callback, $requestExpiresAfter = null, $maxOpenRequests = null) {
		$email = self::validateEmailAddress($email);

		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);

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
			[ 'id', 'verified', 'resettable' ]
		);

		// ensure that the account has been verified before initiating a password reset
		if ((int) $userData['verified'] !== 1) {
			throw new EmailNotVerifiedException();
		}

		// do not allow a password reset if the user has explicitly disabled this feature
		if ((int) $userData['resettable'] !== 1) {
			throw new ResetDisabledException();
		}

		$openRequests = (int) $this->getOpenPasswordResetRequests($userData['id']);

		if ($openRequests < $maxOpenRequests) {
			$this->throttle([ 'requestPasswordReset', $this->getIpAddress() ], 4, (60 * 60 * 24 * 7), 2);
			$this->throttle([ 'requestPasswordReset', 'user', $userData['id'] ], 4, (60 * 60 * 24 * 7), 2);

			$this->createPasswordResetRequest($userData['id'], $requestExpiresAfter, $callback);
		}
		else {
			throw new TooManyRequestsException('', $requestExpiresAfter);
		}
	}

	/**
	 * Authenticates an existing user
	 *
	 * @param string $password the user's password
	 * @param string|null $email (optional) the user's email address
	 * @param string|null $username (optional) the user's username
	 * @param int|null $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
	 * @param callable|null $onBeforeSuccess (optional) a function that receives the user's ID as its single parameter and is executed before successful authentication; must return `true` to proceed or `false` to cancel
	 * @throws InvalidEmailException if the email address was invalid or could not be found
	 * @throws UnknownUsernameException if an attempt has been made to authenticate with a non-existing username
	 * @throws AmbiguousUsernameException if an attempt has been made to authenticate with an ambiguous username
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws AttemptCancelledException if the attempt has been cancelled by the supplied callback that is executed before success
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function authenticateUserInternal($password, $email = null, $username = null, $rememberDuration = null, callable $onBeforeSuccess = null) {
		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);
		$this->throttle([ 'attemptToLogin', $this->getIpAddress() ], 4, (60 * 60), 5, true);

		$columnsToFetch = [ 'id', 'email', 'password', 'verified', 'username', 'status', 'roles_mask' ];

		if ($email !== null) {
			$email = self::validateEmailAddress($email);

			// attempt to look up the account information using the specified email address
			$userData = $this->getUserDataByEmailAddress(
				$email,
				$columnsToFetch
			);
		}
		elseif ($username !== null) {
			$username = trim($username);

			// attempt to look up the account information using the specified username
			$userData = $this->getUserDataByUsername(
				$username,
				$columnsToFetch
			);
		}
		// if neither an email address nor a username has been provided
		else {
			// we can't do anything here because the method call has been invalid
			throw new EmailOrUsernameRequiredError();
		}

		$password = self::validatePassword($password);

		if (password_verify($password, $userData['password'])) {
			// if the password needs to be re-hashed to keep up with improving password cracking techniques
			if (password_needs_rehash($userData['password'], PASSWORD_DEFAULT)) {
				// create a new hash from the password and update it in the database
				$this->updatePassword($userData['id'], $password);
			}

			if ((int) $userData['verified'] === 1) {
				if (!isset($onBeforeSuccess) || (\is_callable($onBeforeSuccess) && $onBeforeSuccess($userData['id']) === true)) {
					$this->onLoginSuccessful($userData['id'], $userData['email'], $userData['username'], $userData['status'], $userData['roles_mask'], false);

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
					$this->throttle([ 'attemptToLogin', $this->getIpAddress() ], 4, (60 * 60), 5, false);

					if (isset($email)) {
						$this->throttle([ 'attemptToLogin', 'email', $email ], 500, (60 * 60 * 24), null, false);
					}
					elseif (isset($username)) {
						$this->throttle([ 'attemptToLogin', 'username', $username ], 500, (60 * 60 * 24), null, false);
					}

					throw new AttemptCancelledException();
				}
			}
			else {
				throw new EmailNotVerifiedException();
			}
		}
		else {
			$this->throttle([ 'attemptToLogin', $this->getIpAddress() ], 4, (60 * 60), 5, false);

			if (isset($email)) {
				$this->throttle([ 'attemptToLogin', 'email', $email ], 500, (60 * 60 * 24), null, false);
			}
			elseif (isset($username)) {
				$this->throttle([ 'attemptToLogin', 'username', $username ], 500, (60 * 60 * 24), null, false);
			}

			// we cannot authenticate the user due to the password being wrong
			throw new InvalidPasswordException();
		}
	}

	/**
	 * Returns the requested user data for the account with the specified email address (if any)
	 *
	 * You must never pass untrusted input to the parameter that takes the column list
	 *
	 * @param string $email the email address to look for
	 * @param array $requestedColumns the columns to request from the user's record
	 * @return array the user data (if an account was found)
	 * @throws InvalidEmailException if the email address could not be found
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function getUserDataByEmailAddress($email, array $requestedColumns) {
		try {
			$projection = implode(', ', $requestedColumns);
			$userData = $this->db->selectRow(
				'SELECT ' . $projection . ' FROM ' . $this->dbTablePrefix . 'users WHERE email = ?',
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
				'SELECT COUNT(*) FROM ' . $this->dbTablePrefix . 'users_resets WHERE user = ? AND expires > ?',
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
				$this->dbTablePrefix . 'users_resets',
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
	 * @throws ResetDisabledException if the user has explicitly disabled password resets for their account
	 * @throws InvalidPasswordException if the new password was invalid
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function resetPassword($selector, $token, $newPassword) {
		$this->throttle([ 'resetPassword', $this->getIpAddress() ], 5, (60 * 60), 10);
		$this->throttle([ 'resetPassword', 'selector', $selector ], 3, (60 * 60), 10);
		$this->throttle([ 'resetPassword', 'token', $token ], 3, (60 * 60), 10);

		try {
			$resetData = $this->db->selectRow(
				'SELECT a.id, a.user, a.token, a.expires, b.resettable FROM ' . $this->dbTablePrefix . 'users_resets AS a JOIN ' . $this->dbTablePrefix . 'users AS b ON b.id = a.user WHERE a.selector = ?',
				[ $selector ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		if (!empty($resetData)) {
			if ((int) $resetData['resettable'] === 1) {
				if (password_verify($token, $resetData['token'])) {
					if ($resetData['expires'] >= time()) {
						$newPassword = self::validatePassword($newPassword);

						// update the password in the database
						$this->updatePassword($resetData['user'], $newPassword);

						// delete any remaining remember directives
						$this->deleteRememberDirective($resetData['user']);

						try {
							$this->db->delete(
								$this->dbTablePrefix . 'users_resets',
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
				throw new ResetDisabledException();
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
	 * Sets whether password resets should be permitted for the account of the currently signed-in user
	 *
	 * @param bool $enabled whether password resets should be enabled for the user's account
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function setPasswordResetEnabled($enabled) {
		$enabled = (bool) $enabled;

		if ($this->isLoggedIn()) {
			try {
				$this->db->update(
					$this->dbTablePrefix . 'users',
					[
						'resettable' => $enabled ? 1 : 0
					],
					[
						'id' => $this->getUserId()
					]
				);
			}
			catch (Error $e) {
				throw new DatabaseError();
			}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Returns whether password resets are permitted for the account of the currently signed-in user
	 *
	 * @return bool
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function isPasswordResetEnabled() {
		if ($this->isLoggedIn()) {
			try {
				$enabled = $this->db->selectValue(
					'SELECT resettable FROM ' . $this->dbTablePrefix . 'users WHERE id = ?',
					[ $this->getUserId() ]
				);

				return (int) $enabled === 1;
			}
			catch (Error $e) {
				throw new DatabaseError();
			}
		}
		else {
			throw new NotLoggedInException();
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
	 * Sets the currently signed-in user's status and updates the session
	 *
	 * @param int $status the status as one of the constants from the {@see Status} class
	 */
	private function setStatus($status) {
		$_SESSION[self::SESSION_FIELD_STATUS] = (int) $status;
	}

	/**
	 * Sets the currently signed-in user's roles and updates the session
	 *
	 * @param int $roles the bitmask containing the roles
	 */
	private function setRoles($roles) {
		$_SESSION[self::SESSION_FIELD_ROLES] = (int) $roles;
	}

	/**
	 * Returns the currently signed-in user's status by reading from the session
	 *
	 * @return int the status as one of the constants from the {@see Status} class
	 */
	public function getStatus() {
		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_STATUS])) {
			return $_SESSION[self::SESSION_FIELD_STATUS];
		}
		else {
			return null;
		}
	}

	/**
	 * Returns whether the currently signed-in user is in "normal" state
	 *
	 * @return bool
	 *
	 * @see Status
	 * @see Auth::getStatus
	 */
	public function isNormal() {
		return $this->getStatus() === Status::NORMAL;
	}

	/**
	 * Returns whether the currently signed-in user is in "archived" state
	 *
	 * @return bool
	 *
	 * @see Status
	 * @see Auth::getStatus
	 */
	public function isArchived() {
		return $this->getStatus() === Status::ARCHIVED;
	}

	/**
	 * Returns whether the currently signed-in user is in "banned" state
	 *
	 * @return bool
	 *
	 * @see Status
	 * @see Auth::getStatus
	 */
	public function isBanned() {
		return $this->getStatus() === Status::BANNED;
	}

	/**
	 * Returns whether the currently signed-in user is in "locked" state
	 *
	 * @return bool
	 *
	 * @see Status
	 * @see Auth::getStatus
	 */
	public function isLocked() {
		return $this->getStatus() === Status::LOCKED;
	}

	/**
	 * Returns whether the currently signed-in user is in "pending review" state
	 *
	 * @return bool
	 *
	 * @see Status
	 * @see Auth::getStatus
	 */
	public function isPendingReview() {
		return $this->getStatus() === Status::PENDING_REVIEW;
	}

	/**
	 * Returns whether the currently signed-in user is in "suspended" state
	 *
	 * @return bool
	 *
	 * @see Status
	 * @see Auth::getStatus
	 */
	public function isSuspended() {
		return $this->getStatus() === Status::SUSPENDED;
	}

	/**
	 * Returns whether the currently signed-in user has the specified role
	 *
	 * @param int $role the role as one of the constants from the {@see Role} class
	 * @return bool
	 *
	 * @see Role
	 */
	public function hasRole($role) {
		$role = (int) $role;

		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_ROLES])) {
			return (((int) $_SESSION[self::SESSION_FIELD_ROLES]) & $role) === $role;
		}
		else {
			return false;
		}
	}

	/**
	 * Returns whether the currently signed-in user has *any* of the specified roles
	 *
	 * @param int[] ...$roles the roles as constants from the {@see Role} class
	 * @return bool
	 *
	 * @see Role
	 */
	public function hasAnyRole(...$roles) {
		foreach ($roles as $role) {
			if ($this->hasRole($role)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Returns whether the currently signed-in user has *all* of the specified roles
	 *
	 * @param int[] ...$roles the roles as constants from the {@see Role} class
	 * @return bool
	 *
	 * @see Role
	 */
	public function hasAllRoles(...$roles) {
		foreach ($roles as $role) {
			if (!$this->hasRole($role)) {
				return false;
			}
		}

		return true;
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
	 * Returns the user's current IP address
	 *
	 * @return string the IP address (IPv4 or IPv6)
	 */
	public function getIpAddress() {
		return $this->ipAddress;
	}

	/**
	 * Performs throttling or rate limiting using the token bucket algorithm (inverse leaky bucket algorithm)
	 *
	 * @param array $criteria the individual criteria that together describe the resource that is being throttled
	 * @param int $supply the number of units to provide per interval (>= 1)
	 * @param int $interval the interval (in seconds) for which the supply is provided (>= 5)
	 * @param int|null $burstiness (optional) the permitted degree of variation or unevenness during peaks (>= 1)
	 * @param bool|null $simulated (optional) whether to simulate a dry run instead of actually consuming the requested units
	 * @param int|null $cost (optional) the number of units to request (>= 1)
	 * @return float the number of units remaining from the supply
	 * @throws TooManyRequestsException if the actual demand has exceeded the designated supply
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function throttle(array $criteria, $supply, $interval, $burstiness = null, $simulated = null, $cost = null) {
		// generate a unique key for the bucket (consisting of 44 or fewer ASCII characters)
		$key = Base64::encodeUrlSafeWithoutPadding(
			\hash(
				'sha256',
				\implode("\n", $criteria),
				true
			)
		);

		// validate the supplied parameters and set appropriate defaults where necessary
		$burstiness = ($burstiness !== null) ? (int) $burstiness : 1;
		$simulated = ($simulated !== null) ? (bool) $simulated : false;
		$cost = ($cost !== null) ? (int) $cost : 1;

		$now = \time();

		// determine the volume of the bucket
		$capacity = $burstiness * (int) $supply;

		// calculate the rate at which the bucket is refilled (per second)
		$bandwidthPerSecond = (int) $supply / (int) $interval;

		try {
			$bucket = $this->db->selectRow(
				'SELECT tokens, replenished_at FROM ' . $this->dbTablePrefix . 'users_throttling WHERE bucket = ?',
				[ $key ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		if ($bucket === null) {
			$bucket = [];
		}

		// initialize the number of tokens in the bucket
		$bucket['tokens'] = isset($bucket['tokens']) ? (float) $bucket['tokens'] : (float) $capacity;
		// initialize the last time that the bucket has been refilled (as a Unix timestamp in seconds)
		$bucket['replenished_at'] = isset($bucket['replenished_at']) ? (int) $bucket['replenished_at'] : $now;

		// replenish the bucket as appropriate
		$secondsSinceLastReplenishment = \max(0, $now - $bucket['replenished_at']);
		$tokensToAdd = $secondsSinceLastReplenishment * $bandwidthPerSecond;
		$bucket['tokens'] = \min((float) $capacity, $bucket['tokens'] + $tokensToAdd);
		$bucket['replenished_at'] = $now;

		$accepted = $bucket['tokens'] >= $cost;

		if (!$simulated) {
			if ($accepted) {
				// remove the requested number of tokens from the bucket
				$bucket['tokens'] = \max(0, $bucket['tokens'] - $cost);
			}

			// set the earliest time after which the bucket *may* be deleted (as a Unix timestamp in seconds)
			$bucket['expires_at'] = $now + \floor($capacity / $bandwidthPerSecond * 2);

			// merge the updated bucket into the database
			try {
				$affected = $this->db->update(
					$this->dbTablePrefix . 'users_throttling',
					$bucket,
					[ 'bucket' => $key ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError();
			}

			if ($affected === 0) {
				$bucket['bucket'] = $key;

				try {
					$this->db->insert(
						$this->dbTablePrefix . 'users_throttling',
						$bucket
					);
				}
				catch (IntegrityConstraintViolationException $ignored) {}
				catch (Error $e) {
					throw new DatabaseError();
				}
			}
		}

		if ($accepted) {
			return $bucket['tokens'];
		}
		else {
			$tokensMissing = $cost - $bucket['tokens'];
			$estimatedWaitingTimeSeconds = \ceil($tokensMissing / $bandwidthPerSecond);

			throw new TooManyRequestsException('', $estimatedWaitingTimeSeconds);
		}
	}

	/**
	 * Returns the component that can be used for administrative tasks
	 *
	 * You must offer access to this interface to authorized users only (restricted via your own access control)
	 *
	 * @return Administration
	 */
	public function admin() {
		return new Administration($this->db, $this->dbTablePrefix);
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
