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

/** Component that provides all features and utilities for secure authentication of individual users */
final class Auth extends UserManager {

	const COOKIE_PREFIXES = [ Cookie::PREFIX_SECURE, Cookie::PREFIX_HOST ];
	const COOKIE_CONTENT_SEPARATOR = '~';
	const TWO_FACTOR_MECHANISM_TOTP = 1;
	const TWO_FACTOR_MECHANISM_SMS = 2;
	const TWO_FACTOR_MECHANISM_EMAIL = 3;

	/** @var string the user's current IP address */
	private $ipAddress;
	/** @var bool whether throttling should be enabled (e.g. in production) or disabled (e.g. during development) */
	private $throttling;
	/** @var int the interval in seconds after which to resynchronize the session data with its authoritative source in the database */
	private $sessionResyncInterval;
	/** @var string the name of the cookie used for the 'remember me' feature */
	private $rememberCookieName;

	/**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection the database connection to operate on
	 * @param string|null $ipAddress (optional) the IP address that should be used instead of the default setting (if any), e.g. when behind a proxy
	 * @param string|null $dbTablePrefix (optional) the prefix for the names of all database tables used by this component
	 * @param bool|null $throttling (optional) whether throttling should be enabled (e.g. in production) or disabled (e.g. during development)
	 * @param int|null $sessionResyncInterval (optional) the interval in seconds after which to resynchronize the session data with its authoritative source in the database
	 * @param string|null $dbSchema (optional) the schema name for all database tables used by this component
	 */
	public function __construct($databaseConnection, $ipAddress = null, $dbTablePrefix = null, $throttling = null, $sessionResyncInterval = null, $dbSchema = null) {
		parent::__construct($databaseConnection, $dbTablePrefix, $dbSchema);

		$this->ipAddress = !empty($ipAddress) ? $ipAddress : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null);
		$this->throttling = isset($throttling) ? (bool) $throttling : true;
		$this->sessionResyncInterval = isset($sessionResyncInterval) ? ((int) $sessionResyncInterval) : (60 * 5);
		$this->rememberCookieName = self::createRememberCookieName();

		$this->initSessionIfNecessary();
		$this->enhanceHttpSecurity();

		$this->processRememberDirective();
		$this->resyncSessionIfNecessary();
	}

	/** Initializes the session and sets the correct configuration */
	private function initSessionIfNecessary() {
		if (\session_status() === \PHP_SESSION_NONE) {
			// use cookies to store session IDs
			\ini_set('session.use_cookies', 1);
			// use cookies only (do not send session IDs in URLs)
			\ini_set('session.use_only_cookies', 1);
			// do not send session IDs in URLs
			\ini_set('session.use_trans_sid', 0);

			// start the session (requests a cookie to be written on the client)
			@Session::start();
		}
	}

	/** Improves the application's security over HTTP(S) by setting specific headers */
	private function enhanceHttpSecurity() {
		// remove exposure of PHP version (at least where possible)
		\header_remove('X-Powered-By');

		// if the user is signed in
		if ($this->isLoggedIn()) {
			// prevent clickjacking
			\header('X-Frame-Options: sameorigin');
			// prevent content sniffing (MIME sniffing)
			\header('X-Content-Type-Options: nosniff');

			// disable caching of potentially sensitive data
			\header('Cache-Control: no-store, no-cache, must-revalidate', true);
			\header('Expires: Thu, 19 Nov 1981 00:00:00 GMT', true);
			\header('Pragma: no-cache', true);
		}
	}

	/** Checks if there is a "remember me" directive set and handles the automatic login (if appropriate) */
	private function processRememberDirective() {
		// if the user is not signed in yet
		if (!$this->isLoggedIn()) {
			// if there is currently no cookie for the 'remember me' feature
			if (!isset($_COOKIE[$this->rememberCookieName])) {
				// if an old cookie for that feature from versions v1.x.x to v6.x.x has been found
				if (isset($_COOKIE['auth_remember'])) {
					// use the value from that old cookie instead
					$_COOKIE[$this->rememberCookieName] = $_COOKIE['auth_remember'];
				}
			}

			// if a remember cookie is set
			if (isset($_COOKIE[$this->rememberCookieName])) {
				// assume the cookie and its contents to be invalid until proven otherwise
				$valid = false;

				// split the cookie's content into selector and token
				$parts = \explode(self::COOKIE_CONTENT_SEPARATOR, $_COOKIE[$this->rememberCookieName], 2);

				// if both selector and token were found
				if (!empty($parts[0]) && !empty($parts[1])) {
					try {
						$rememberData = $this->db->selectRow(
							'SELECT a.user, a.token, a.expires, b.email, b.username, b.status, b.roles_mask, b.force_logout FROM ' . $this->makeTableName('users_remembered') . ' AS a JOIN ' . $this->makeTableName('users') . ' AS b ON a.user = b.id WHERE a.selector = ?',
							[ $parts[0] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}

					if (!empty($rememberData)) {
						if ($rememberData['expires'] >= \time()) {
							if (\password_verify($parts[1], $rememberData['token'])) {
								// the cookie and its contents have now been proven to be valid
								$valid = true;

								$this->onLoginSuccessful($rememberData['user'], $rememberData['email'], $rememberData['username'], $rememberData['status'], $rememberData['roles_mask'], $rememberData['force_logout'], true);
							}
						}
					}
				}

				// if the cookie or its contents have been invalid
				if (!$valid) {
					// mark the cookie as such to prevent any further futile attempts
					$this->setRememberCookie('', '', \time() + 60 * 60 * 24 * 365.25);
				}
			}
		}
	}

	private function resyncSessionIfNecessary() {
		// if the user is signed in
		if ($this->isLoggedIn()) {
			// the following session field may not have been initialized for sessions that had already existed before the introduction of this feature
			if (!isset($_SESSION[self::SESSION_FIELD_LAST_RESYNC])) {
				$_SESSION[self::SESSION_FIELD_LAST_RESYNC] = 0;
			}

			// if it's time for resynchronization
			if (($_SESSION[self::SESSION_FIELD_LAST_RESYNC] + $this->sessionResyncInterval) <= \time()) {
				// fetch the authoritative data from the database again
				try {
					$authoritativeData = $this->db->selectRow(
						'SELECT email, username, status, roles_mask, force_logout FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
						[ $this->getUserId() ]
					);
				}
				catch (Error $e) {
					throw new DatabaseError($e->getMessage());
				}

				// if the user's data has been found
				if (!empty($authoritativeData)) {
					// the following session field may not have been initialized for sessions that had already existed before the introduction of this feature
					if (!isset($_SESSION[self::SESSION_FIELD_FORCE_LOGOUT])) {
						$_SESSION[self::SESSION_FIELD_FORCE_LOGOUT] = 0;
					}

					// if the counter that keeps track of forced logouts has been incremented
					if ($authoritativeData['force_logout'] > $_SESSION[self::SESSION_FIELD_FORCE_LOGOUT]) {
						// the user must be signed out
						$this->logOut();
					}
					// if the counter that keeps track of forced logouts has remained unchanged
					else {
						// the session data needs to be updated
						$_SESSION[self::SESSION_FIELD_EMAIL] = $authoritativeData['email'];
						$_SESSION[self::SESSION_FIELD_USERNAME] = $authoritativeData['username'];
						$_SESSION[self::SESSION_FIELD_STATUS] = (int) $authoritativeData['status'];
						$_SESSION[self::SESSION_FIELD_ROLES] = (int) $authoritativeData['roles_mask'];

						// remember that we've just performed the required resynchronization
						$_SESSION[self::SESSION_FIELD_LAST_RESYNC] = \time();
					}
				}
				// if no data has been found for the user
				else {
					// their account may have been deleted so they should be signed out
					$this->logOut();
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
	 * @param callable|null $onBeforeSuccess (optional) deprecated
	 * @throws InvalidEmailException if the email address was invalid or could not be found
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws AttemptCancelledException deprecated
	 * @throws SecondFactorRequiredException if a second factor needs to be provided for authentification
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
	 * @param callable|null $onBeforeSuccess (optional) deprecated
	 * @throws UnknownUsernameException if the specified username does not exist
	 * @throws AmbiguousUsernameException if the specified username is ambiguous, i.e. there are multiple users with that name
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws AttemptCancelledException deprecated
	 * @throws SecondFactorRequiredException if a second factor needs to be provided for authentification
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
					'SELECT password FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
					[ $this->getUserId() ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			if (!empty($expectedHash)) {
				$validated = PasswordHash::verify($password, $expectedHash);

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
	 * Logs the user out
	 *
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function logOut() {
		// if the user has been signed in
		if ($this->isLoggedIn()) {
			// retrieve any locally existing remember directive
			$rememberDirectiveSelector = $this->getRememberDirectiveSelector();

			// if such a remember directive exists
			if (isset($rememberDirectiveSelector)) {
				// delete the local remember directive
				$this->deleteRememberDirectiveForUserById(
					$this->getUserId(),
					$rememberDirectiveSelector
				);
			}

			// remove all session variables maintained by this library
			unset($_SESSION[self::SESSION_FIELD_LOGGED_IN]);
			unset($_SESSION[self::SESSION_FIELD_USER_ID]);
			unset($_SESSION[self::SESSION_FIELD_EMAIL]);
			unset($_SESSION[self::SESSION_FIELD_USERNAME]);
			unset($_SESSION[self::SESSION_FIELD_STATUS]);
			unset($_SESSION[self::SESSION_FIELD_ROLES]);
			unset($_SESSION[self::SESSION_FIELD_REMEMBERED]);
			unset($_SESSION[self::SESSION_FIELD_LAST_RESYNC]);
			unset($_SESSION[self::SESSION_FIELD_FORCE_LOGOUT]);
			unset($_SESSION[self::SESSION_FIELD_AWAITING_2FA_UNTIL]);
			unset($_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID]);
			unset($_SESSION[self::SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION]);
		}
	}

	/**
	 * Logs the user out in all other sessions (except for the current one)
	 *
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function logOutEverywhereElse() {
		if (!$this->isLoggedIn()) {
			throw new NotLoggedInException();
		}

		// determine the expiry date of any locally existing remember directive
		$previousRememberDirectiveExpiry = $this->getRememberDirectiveExpiry();

		// schedule a forced logout in all sessions
		$this->forceLogoutForUserById($this->getUserId());

		// the following session field may not have been initialized for sessions that had already existed before the introduction of this feature
		if (!isset($_SESSION[self::SESSION_FIELD_FORCE_LOGOUT])) {
			$_SESSION[self::SESSION_FIELD_FORCE_LOGOUT] = 0;
		}

		// ensure that we will simply skip or ignore the next forced logout (which we have just caused) in the current session
		$_SESSION[self::SESSION_FIELD_FORCE_LOGOUT]++;

		// re-generate the session ID to prevent session fixation attacks (requests a cookie to be written on the client)
		Session::regenerate(true);

		// if there had been an existing remember directive previously
		if (isset($previousRememberDirectiveExpiry)) {
			// restore the directive with the old expiry date but new credentials
			$this->createRememberDirective(
				$this->getUserId(),
				$previousRememberDirectiveExpiry - \time()
			);
		}
	}

	/**
	 * Logs the user out in all sessions
	 *
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function logOutEverywhere() {
		if (!$this->isLoggedIn()) {
			throw new NotLoggedInException();
		}

		// schedule a forced logout in all sessions
		$this->forceLogoutForUserById($this->getUserId());
		// and immediately apply the logout locally
		$this->logOut();
	}

	/**
	 * Destroys all session data
	 *
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function destroySession() {
		// remove all session variables without exception
		$_SESSION = [];
		// delete the session cookie
		$this->deleteSessionCookie();
		// let PHP destroy the session
		\session_destroy();
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
		$tokenHashed = \password_hash($token, \PASSWORD_DEFAULT);
		$expires = \time() + ((int) $duration);

		try {
			$this->db->insert(
				$this->makeTableNameComponents('users_remembered'),
				[
					'user' => $userId,
					'selector' => $selector,
					'token' => $tokenHashed,
					'expires' => $expires
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		$this->setRememberCookie($selector, $token, $expires);
	}

	protected function deleteRememberDirectiveForUserById($userId, $selector = null) {
		parent::deleteRememberDirectiveForUserById($userId, $selector);

		$this->setRememberCookie(null, null, \time() - 3600);
	}

	/**
	 * Sets or updates the cookie that manages the "remember me" token
	 *
	 * @param string|null $selector the selector from the selector/token pair
	 * @param string|null $token the token from the selector/token pair
	 * @param int $expires the UNIX time in seconds which the token should expire at
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function setRememberCookie($selector, $token, $expires) {
		$params = \session_get_cookie_params();

		if (isset($selector) && isset($token)) {
			$content = $selector . self::COOKIE_CONTENT_SEPARATOR . $token;
		}
		else {
			$content = '';
		}

		// save the cookie with the selector and token (requests a cookie to be written on the client)
		$cookie = new Cookie($this->rememberCookieName);
		$cookie->setValue($content);
		$cookie->setExpiryTime($expires);
		$cookie->setPath($params['path']);
		$cookie->setDomain($params['domain']);
		$cookie->setHttpOnly($params['httponly']);
		$cookie->setSecureOnly($params['secure']);
		$result = $cookie->save();

		if ($result === false) {
			throw new HeadersAlreadySentError();
		}

		// if we've been deleting the cookie above
		if (!isset($selector) || !isset($token)) {
			// attempt to delete a potential old cookie from versions v1.x.x to v6.x.x as well (requests a cookie to be written on the client)
			$cookie = new Cookie('auth_remember');
			$cookie->setPath((!empty($params['path'])) ? $params['path'] : '/');
			$cookie->setDomain($params['domain']);
			$cookie->setHttpOnly($params['httponly']);
			$cookie->setSecureOnly($params['secure']);
			$cookie->delete();
		}
	}

	protected function onLoginSuccessful($userId, $email, $username, $status, $roles, $forceLogout, $remembered) {
		// update the timestamp of the user's last login
		try {
			$this->db->update(
				$this->makeTableNameComponents('users'),
				[ 'last_login' => \time() ],
				[ 'id' => $userId ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		parent::onLoginSuccessful($userId, $email, $username, $status, $roles, $forceLogout, $remembered);
	}

	/**
	 * Deletes the session cookie on the client
	 *
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function deleteSessionCookie() {
		$params = \session_get_cookie_params();

		// ask for the session cookie to be deleted (requests a cookie to be written on the client)
		$cookie = new Cookie(\session_name());
		$cookie->setPath($params['path']);
		$cookie->setDomain($params['domain']);
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
	 * @return string[] an array with the old email address (if any) at index zero and the new email address (which has just been verified) at index one
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
				'SELECT a.id, a.user_id, a.email AS new_email, a.token, a.expires, b.email AS old_email FROM ' . $this->makeTableName('users_confirmations') . ' AS a JOIN ' . $this->makeTableName('users') . ' AS b ON b.id = a.user_id WHERE a.selector = ?',
				[ $selector ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (!empty($confirmationData)) {
			if (\password_verify($token, $confirmationData['token'])) {
				if ($confirmationData['expires'] >= \time()) {
					// invalidate any potential outstanding password reset requests
					try {
						$this->db->delete(
							$this->makeTableNameComponents('users_resets'),
							[ 'user' => $confirmationData['user_id'] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}

					// mark the email address as verified (and possibly update it to the new address given)
					try {
						$this->db->update(
							$this->makeTableNameComponents('users'),
							[
								'email' => $confirmationData['new_email'],
								'verified' => 1
							],
							[ 'id' => $confirmationData['user_id'] ]
						);
					}
					catch (IntegrityConstraintViolationException $e) {
						throw new UserAlreadyExistsException();
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}

					// if the user is currently signed in
					if ($this->isLoggedIn()) {
						// if the user has just confirmed an email address for their own account
						if ($this->getUserId() === ((int) $confirmationData['user_id'])) {
							// immediately update the email address in the current session as well
							$_SESSION[self::SESSION_FIELD_EMAIL] = $confirmationData['new_email'];
						}
					}

					// consume the token just being used for confirmation
					try {
						$this->db->delete(
							$this->makeTableNameComponents('users_confirmations'),
							[ 'id' => $confirmationData['id'] ]
						);
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}

					// if the email address has not been changed but simply been verified
					if ($confirmationData['old_email'] === $confirmationData['new_email']) {
						// the output should not contain any previous email address
						$confirmationData['old_email'] = null;
					}

					return [
						$confirmationData['old_email'],
						$confirmationData['new_email']
					];
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
	 * @return string[] an array with the old email address (if any) at index zero and the new email address (which has just been verified) at index one
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws UserAlreadyExistsException if an attempt has been made to change the email address to a (now) occupied address
	 * @throws SecondFactorRequiredException if a second factor needs to be provided for authentification
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function confirmEmailAndSignIn($selector, $token, $rememberDuration = null) {
		$emailBeforeAndAfter = $this->confirmEmail($selector, $token);

		if (!$this->isLoggedIn()) {
			if ($emailBeforeAndAfter[1] !== null) {
				$emailBeforeAndAfter[1] = self::validateEmailAddress($emailBeforeAndAfter[1]);

				$userData = $this->getUserDataByEmailAddress(
					$emailBeforeAndAfter[1],
					[ 'id', 'email', 'username', 'status', 'roles_mask', 'force_logout' ]
				);

				$this->finishSingleFactorOrThrow(
					$userData['id'], $userData['email'], $userData['username'], $userData['status'], $userData['roles_mask'], $userData['force_logout'], true, $rememberDuration
				);
			}
		}

		return $emailBeforeAndAfter;
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
			$newPassword = self::validatePassword($newPassword, true);
			$this->updatePasswordInternal($this->getUserId(), $newPassword);

			try {
				$this->logOutEverywhereElse();
			}
			catch (NotLoggedInException $ignored) {}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Provides a one-time password as the second factor of authentification after the first factor has already been completed previously
	 *
	 * Two-factor authentification would previously have been enabled by calling {@see prepareTwoFactorViaTotp}, {@see prepareTwoFactorViaSms} or {@see prepareTwoFactorViaEmail}, and then {@see enableTwoFactorViaTotp}, {@see enableTwoFactorViaSms} or {@see enableTwoFactorViaEmail}
	 *
	 * @param string $otpValue a one-time password (OTP) that has just been entered by the user, with or without spaces and special characters
	 * @throws InvalidOneTimePasswordException if the one-time password provided by the user is not valid
	 * @throws NotLoggedInException if the user has not completed the first factor of authentification recently
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function provideOneTimePasswordAsSecondFactor($otpValue) {
		if (empty($_SESSION[self::SESSION_FIELD_AWAITING_2FA_UNTIL]) || $_SESSION[self::SESSION_FIELD_AWAITING_2FA_UNTIL] < \time()) {
			throw new NotLoggedInException();
		}

		if (empty($_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID])) {
			throw new NotLoggedInException();
		}

		$_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID] = (int) $_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID];
		$otpValue = !empty($otpValue) ? self::sanitizeOtpValue((string) $otpValue) : '';

		if (empty($otpValue)) {
			throw new InvalidOneTimePasswordException();
		}

		$this->throttle([ 'provideOneTimePasswordAsSecondFactor', $_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID] ], 2, 60 * 15, 3);
		$this->throttle([ 'provideOneTimePasswordAsSecondFactor', $this->getIpAddress() ], 5, 60 * 15, 3);

		$otpValueSelector = self::createSelectorForOneTimePassword($otpValue, $_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID]);
		$otpValueToken = \password_hash($otpValue, \PASSWORD_DEFAULT);

		try {
			$otpRecords = $this->db->select(
				'SELECT id, mechanism, token, expires_at FROM ' . $this->makeTableName('users_otps') . ' WHERE selector = ? AND user_id = ?',
				[ $otpValueSelector, $_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID] ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		$success = false;
		$performTotpVerification = true;

		if (!empty($otpRecords)) {
			foreach ($otpRecords as $otpRecord) {
				if (!empty($otpRecord)) {
					if (\password_verify($otpValue, $otpRecord['token'])) {
						// if the mechanism for this one-time password was time-based (TOTP)
						if (!empty($otpRecord['mechanism']) && ((int) $otpRecord['mechanism']) === self::TWO_FACTOR_MECHANISM_TOTP) {
							// if the one-time password had an expiry time and that time has passed recently
							if (isset($otpRecord['expires_at']) && $otpRecord['expires_at'] > (\time() - 60 * 15) && $otpRecord['expires_at'] < \time()) {
								// the one-time password was in fact a TOTP value on our denylist to prevent replay attacks
								$performTotpVerification = false;

								continue;
							}
						}

						// if the one-time password had no expiry time, i.e. it was valid indefinitely, or if the expiry time has not passed yet
						if (!isset($otpRecord['expires_at']) || $otpRecord['expires_at'] >= \time()) {
							// remove the one-time password from the database to prevent repeated usages
							try {
								$this->db->delete(
									$this->makeTableNameComponents('users_otps'),
									[ 'id' => $otpRecord['id'] ]
								);
							}
							catch (Error $e) {
								throw new DatabaseError($e->getMessage());
							}

							// remember that we have successfully verified the one-time password now
							$success = true;

							break;
						}
					}
				}
			}
		}

		// if the one-time password couldn't be verified yet by looking it up in the database
		if (!$success) {
			// if we are still supposed to interpret and verify the one-time password as TOTP
			if ($performTotpVerification) {
				try {
					$totpSecret = $this->db->selectValue(
						'SELECT seed FROM ' . $this->makeTableName('users_2fa') . ' WHERE user_id = ? AND mechanism = ? AND expires_at IS NULL',
						[
							$_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID],
							self::TWO_FACTOR_MECHANISM_TOTP,
						]
					);
				}
				catch (Error $e) {
					throw new DatabaseError($e->getMessage());
				}

				if (!empty($totpSecret)) {
					if (\Delight\Otp\Otp::verifyTotp($totpSecret, $otpValue)) {
						// insert the TOTP value into our denylist to prevent replay attacks
						try {
							$this->db->insert(
								$this->makeTableNameComponents('users_otps'),
								[
									'user_id' => $_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID],
									'mechanism' => self::TWO_FACTOR_MECHANISM_TOTP,
									'single_factor' => 0,
									'selector' => $otpValueSelector,
									'token' => $otpValueToken,
									'expires_at' => \time() - 5
								]
							);
						}
						catch (Error $e) {
							throw new DatabaseError($e->getMessage());
						}

						// remember that we have successfully verified the one-time password now
						$success = true;
					}
				}
			}
		}

		if ($success) {
			try {
				$userData = $this->db->selectRow(
					'SELECT email, username, status, roles_mask, force_logout FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
					[ $_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID] ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			if (!empty($userData)) {
				$this->onLoginSuccessful(
					$_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID], $userData['email'], $userData['username'], $userData['status'], $userData['roles_mask'], $userData['force_logout'], false
				);

				if (isset($_SESSION[self::SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION])) {
					$this->createRememberDirective(
						$_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID], $_SESSION[self::SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION]
					);
				}

				return;
			}
		}

		throw new InvalidOneTimePasswordException();
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
					'SELECT COUNT(*) FROM ' . $this->makeTableName('users') . ' WHERE email = ?',
					[ $newEmail ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			if ((int) $existingUsersWithNewEmail !== 0) {
				throw new UserAlreadyExistsException();
			}

			try {
				$verified = $this->db->selectValue(
					'SELECT verified FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
					[ $this->getUserId() ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			// ensure that at least the current (old) email address has been verified before proceeding
			if ((int) $verified !== 1) {
				throw new EmailNotVerifiedException();
			}

			$this->throttle([ 'requestEmailChange', 'userId', $this->getUserId() ], 1, (60 * 60 * 24));
			$this->throttle([ 'requestEmailChange', $this->getIpAddress() ], 1, (60 * 60 * 24), 3);

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
				'SELECT user_id, email FROM ' . $this->makeTableName('users_confirmations') . ' WHERE ' . $columnName . ' = ? ORDER BY id DESC LIMIT 1 OFFSET 0',
				[ $columnValue ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if ($latestAttempt === null) {
			throw new ConfirmationRequestNotFound();
		}

		$this->throttle([ 'resendConfirmation', 'userId', $latestAttempt['user_id'] ], 1, (60 * 60 * 6));
		$this->throttle([ 'resendConfirmation', $this->getIpAddress() ], 4, (60 * 60 * 24 * 7), 2);

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
	 *
	 * @see canResetPasswordOrThrow
	 * @see canResetPassword
	 * @see resetPassword
	 * @see resetPasswordAndSignIn
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

		$openRequests = $this->throttling ? (int) $this->getOpenPasswordResetRequests($userData['id']) : 0;

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
	 * @param callable|null $onBeforeSuccess (optional) deprecated
	 * @throws InvalidEmailException if the email address was invalid or could not be found
	 * @throws UnknownUsernameException if an attempt has been made to authenticate with a non-existing username
	 * @throws AmbiguousUsernameException if an attempt has been made to authenticate with an ambiguous username
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws EmailNotVerifiedException if the email address has not been verified yet via confirmation email
	 * @throws AttemptCancelledException deprecated
	 * @throws SecondFactorRequiredException if a second factor needs to be provided for authentification
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function authenticateUserInternal($password, $email = null, $username = null, $rememberDuration = null, callable $onBeforeSuccess = null) {
		$this->throttle([ 'enumerateUsers', $this->getIpAddress() ], 1, (60 * 60), 75);
		$this->throttle([ 'attemptToLogin', $this->getIpAddress() ], 4, (60 * 60), 5, true);

		$columnsToFetch = [ 'id', 'email', 'password', 'verified', 'username', 'status', 'roles_mask', 'force_logout' ];

		if ($email !== null) {
			$email = self::validateEmailAddress($email);

			// attempt to look up the account information using the specified email address
			$userData = $this->getUserDataByEmailAddress(
				$email,
				$columnsToFetch
			);
		}
		elseif ($username !== null) {
			$username = \trim($username);

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

		if (PasswordHash::verify($password, $userData['password'])) {
			// if the password needs to be re-hashed to keep up with improving password cracking techniques
			if (PasswordHash::needsRehash($userData['password'])) {
				// create a new hash from the password and update it in the database
				$this->updatePasswordInternal($userData['id'], $password);
			}

			if ((int) $userData['verified'] === 1) {
				if (!isset($onBeforeSuccess) || (\is_callable($onBeforeSuccess) && $onBeforeSuccess($userData['id']) === true)) {
					// continue to support the old parameter format
					if ($rememberDuration === true) {
						$rememberDuration = 60 * 60 * 24 * 28;
					}
					elseif ($rememberDuration === false) {
						$rememberDuration = null;
					}

					$this->finishSingleFactorOrThrow(
						$userData['id'], $userData['email'], $userData['username'], $userData['status'], $userData['roles_mask'], $userData['force_logout'], false, $rememberDuration
					);

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
	 * Either finishes single-factor authentification (if two-factor authentification is not set up), or throws an exception (otherwise)
	 *
	 * @throws SecondFactorRequiredException if a second factor needs to be provided for authentification
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see provideOneTimePasswordAsSecondFactor
	 */
	private function finishSingleFactorOrThrow($userId, $email, $username, $status, $roles, $forceLogout, $remembered, $rememberDuration = null) {
		try {
			$twoFactorMethods = $this->db->select(
				'SELECT mechanism, seed FROM ' . $this->makeTableName('users_2fa') . ' WHERE user_id = ? AND expires_at IS NULL',
				[ $userId ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		// if any mechanism for two-factor authentification has been set up for this user
		if (!empty($twoFactorMethods)) {
			$secondFactorRequiredException = new SecondFactorRequiredException();
			$throttled = false;

			foreach ($twoFactorMethods as $twoFactorMethod) {
				if (!empty($twoFactorMethod) && !empty($twoFactorMethod['mechanism'])) {
					// if the specific mechanism requires that we generate a one-time password randomly now
					if (((int) $twoFactorMethod['mechanism']) === self::TWO_FACTOR_MECHANISM_SMS || ((int) $twoFactorMethod['mechanism']) === self::TWO_FACTOR_MECHANISM_EMAIL) {
						if (!$throttled) {
							$this->throttle([ 'generateOtp', $userId ], 1, 60 * 5, 2);
							$throttled = true;
						}

						$otpValue = $this->generateAndStoreRandomOneTimePassword($userId, $twoFactorMethod['mechanism']);

						if (((int) $twoFactorMethod['mechanism']) === self::TWO_FACTOR_MECHANISM_SMS) {
							$secondFactorRequiredException->addSmsOption($otpValue, $twoFactorMethod['seed'], \Delight\Auth\PhoneNumber::mask($twoFactorMethod['seed']));
						}
						elseif (((int) $twoFactorMethod['mechanism']) === self::TWO_FACTOR_MECHANISM_EMAIL) {
							$secondFactorRequiredException->addEmailOption($otpValue, $twoFactorMethod['seed'], \Delight\Auth\EmailAddress::mask($twoFactorMethod['seed']));
						}
						else {
							throw new InvalidStateError();
						}
					}
					// if the specific mechanism mandates that the one-time password is generated on the client side
					elseif (((int) $twoFactorMethod['mechanism']) === self::TWO_FACTOR_MECHANISM_TOTP) {
						$secondFactorRequiredException->addTotpOption();
					}
					else {
						throw new InvalidStateError();
					}
				}
			}

			// allow for the second factor to be completed within five minutes, and consider the first factor to be completed and valid until then
			$_SESSION[self::SESSION_FIELD_AWAITING_2FA_UNTIL] = \time() + 60 * 5;
			// remember which user it is that has completed the first factor and is now expected to complete the second factor
			$_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID] = $userId;
			// remember the "remember me" duration that the user just requested to be kept after signing in
			$_SESSION[self::SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION] = $rememberDuration;

			// cancel/pause the login attempt for now
			throw $secondFactorRequiredException;
		}

		$this->onLoginSuccessful($userId, $email, $username, $status, $roles, $forceLogout, $remembered);

		if ($rememberDuration !== null) {
			$this->createRememberDirective($userId, $rememberDuration);
		}
	}

	private function generateAndStoreRandomOneTimePassword($userId, $mechanism) {
		// generate a random one-time password

		$otpValue = null;

		if (\PHP_VERSION_ID >= 70000) {
			try {
				$otpValue = \random_int(0, 999999);
				$otpValue = \sprintf('%06d', $otpValue);
			}
			catch (\Exception $e) {
				$otpValue = null;
			}
		}

		if (empty($otpValue)) {
			$otpValue = \Delight\Otp\Otp::createSecret(\Delight\Otp\Otp::SHARED_SECRET_STRENGTH_LOW);
			$otpValue = \substr($otpValue, 0, 6);
			$otpValue = \strtoupper($otpValue);
		}

		// create a selector/token pair from the generated one-time password
		$otpValueSelector = self::createSelectorForOneTimePassword($otpValue, $userId);
		$otpValueToken = \password_hash($otpValue, \PASSWORD_DEFAULT);

		// store the generated one-time password for the user and define it to expire after ten minutes
		try {
			$this->db->insert(
				$this->makeTableNameComponents('users_otps'),
				[
					'user_id' => $userId,
					'mechanism' => $mechanism,
					'single_factor' => 0,
					'selector' => $otpValueSelector,
					'token' => $otpValueToken,
					'expires_at' => \time() + 60 * 10,
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		// delete any old one-time passwords for the user that have expired at least 15 minutes ago
		try {
			$this->db->exec(
				'DELETE FROM ' . $this->makeTableName('users_otps') . ' WHERE user_id = ? AND expires_at < ?',
				[ $userId, \time() - 60 * 15 ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		return $otpValue;
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
			$projection = \implode(', ', $requestedColumns);
			$userData = $this->db->selectRow(
				'SELECT ' . $projection . ' FROM ' . $this->makeTableName('users') . ' WHERE email = ?',
				[ $email ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
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
				'SELECT COUNT(*) FROM ' . $this->makeTableName('users_resets') . ' WHERE user = ? AND expires > ?',
				[
					$userId,
					\time()
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (!empty($requests)) {
			return $requests;
		}
		else {
			return 0;
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
		$tokenHashed = \password_hash($token, \PASSWORD_DEFAULT);
		$expiresAt = \time() + $expiresAfter;

		try {
			$this->db->insert(
				$this->makeTableNameComponents('users_resets'),
				[
					'user' => $userId,
					'selector' => $selector,
					'token' => $tokenHashed,
					'expires' => $expiresAt
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (\is_callable($callback)) {
			$callback($selector, $token);
		}
		else {
			throw new MissingCallbackError();
		}
	}

	/**
	 * Resets the password for a particular account by supplying the correct selector/token pair
	 *
	 * The selector/token pair must have been generated previously by calling {@see forgotPassword}
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @param string $newPassword the new password to set for the account
	 * @return string[] an array with the user's ID at index `id` and the user's email address at index `email`
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws ResetDisabledException if the user has explicitly disabled password resets for their account
	 * @throws InvalidPasswordException if the new password was invalid
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see forgotPassword
	 * @see canResetPasswordOrThrow
	 * @see canResetPassword
	 * @see resetPasswordAndSignIn
	 */
	public function resetPassword($selector, $token, $newPassword) {
		$this->throttle([ 'resetPassword', $this->getIpAddress() ], 5, (60 * 60), 10);
		$this->throttle([ 'resetPassword', 'selector', $selector ], 3, (60 * 60), 10);
		$this->throttle([ 'resetPassword', 'token', $token ], 3, (60 * 60), 10);

		try {
			$resetData = $this->db->selectRow(
				'SELECT a.id, a.user, a.token, a.expires, b.email, b.resettable FROM ' . $this->makeTableName('users_resets') . ' AS a JOIN ' . $this->makeTableName('users') . ' AS b ON b.id = a.user WHERE a.selector = ?',
				[ $selector ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
		}

		if (!empty($resetData)) {
			if ((int) $resetData['resettable'] === 1) {
				if (\password_verify($token, $resetData['token'])) {
					if ($resetData['expires'] >= \time()) {
						$newPassword = self::validatePassword($newPassword, true);
						$this->updatePasswordInternal($resetData['user'], $newPassword);
						$this->forceLogoutForUserById($resetData['user']);

						try {
							$this->db->delete(
								$this->makeTableNameComponents('users_resets'),
								[ 'id' => $resetData['id'] ]
							);
						}
						catch (Error $e) {
							throw new DatabaseError($e->getMessage());
						}

						return [
							'id' => $resetData['user'],
							'email' => $resetData['email']
						];
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
	 * Resets the password for a particular account by supplying the correct selector/token pair
	 *
	 * The selector/token pair must have been generated previously by calling {@see forgotPassword}
	 *
	 * The user will be automatically signed in if this operation is successful
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @param string $newPassword the new password to set for the account
	 * @param int|null $rememberDuration (optional) the duration in seconds to keep the user logged in ("remember me"), e.g. `60 * 60 * 24 * 365.25` for one year
	 * @return string[] an array with the user's ID at index `id` and the user's email address at index `email`
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws ResetDisabledException if the user has explicitly disabled password resets for their account
	 * @throws InvalidPasswordException if the new password was invalid
	 * @throws SecondFactorRequiredException if a second factor needs to be provided for authentification
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see forgotPassword
	 * @see canResetPasswordOrThrow
	 * @see canResetPassword
	 * @see resetPassword
	 */
	public function resetPasswordAndSignIn($selector, $token, $newPassword, $rememberDuration = null) {
		$idAndEmail = $this->resetPassword($selector, $token, $newPassword);

		if (!$this->isLoggedIn()) {
			$idAndEmail['email'] = self::validateEmailAddress($idAndEmail['email']);

			$userData = $this->getUserDataByEmailAddress(
				$idAndEmail['email'],
				[ 'username', 'status', 'roles_mask', 'force_logout' ]
			);

			$this->finishSingleFactorOrThrow(
				$idAndEmail['id'], $idAndEmail['email'], $userData['username'], $userData['status'], $userData['roles_mask'], $userData['force_logout'], true, $rememberDuration
			);
		}

		return $idAndEmail;
	}

	/**
	 * Check if the supplied selector/token pair can be used to reset a password
	 *
	 * The password can be reset using the supplied information if this method does *not* throw any exception
	 *
	 * The selector/token pair must have been generated previously by calling {@see forgotPassword}
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @throws InvalidSelectorTokenPairException if either the selector or the token was not correct
	 * @throws TokenExpiredException if the token has already expired
	 * @throws ResetDisabledException if the user has explicitly disabled password resets for their account
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see forgotPassword
	 * @see canResetPassword
	 * @see resetPassword
	 * @see resetPasswordAndSignIn
	 */
	public function canResetPasswordOrThrow($selector, $token) {
		try {
			// pass an invalid password intentionally to force an expected error
			$this->resetPassword($selector, $token, null);

			// we should already be in one of the `catch` blocks now so this is not expected
			throw new AuthError();
		}
		// if the password is the only thing that's invalid
		catch (InvalidPasswordException $ignored) {
			// the password can be reset
		}
		// if some other things failed (as well)
		catch (AuthException $e) {
			// re-throw the exception
			throw $e;
		}
	}

	/**
	 * Check if the supplied selector/token pair can be used to reset a password
	 *
	 * The selector/token pair must have been generated previously by calling {@see forgotPassword}
	 *
	 * @param string $selector the selector from the selector/token pair
	 * @param string $token the token from the selector/token pair
	 * @return bool whether the password can be reset using the supplied information
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see forgotPassword
	 * @see canResetPasswordOrThrow
	 * @see resetPassword
	 * @see resetPasswordAndSignIn
	 */
	public function canResetPassword($selector, $token) {
		try {
			$this->canResetPasswordOrThrow($selector, $token);

			return true;
		}
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
					$this->makeTableNameComponents('users'),
					[
						'resettable' => $enabled ? 1 : 0
					],
					[
						'id' => $this->getUserId()
					]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
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
					'SELECT resettable FROM ' . $this->makeTableName('users') . ' WHERE id = ?',
					[ $this->getUserId() ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			return ((int) $enabled) === 1;
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Prepares the setup of two-factor authentification via time-based one-time passwords (TOTP)
	 *
	 * After performing this step, the user will be able to add the service or application to their authenticator application
	 *
	 * When the user has entered a one-time password from their authenticator application afterwards, call {@see enableTwoFactorViaTotp} with that one-time password
	 *
	 * @param string|null $serviceName (optional) the name of the service or application that the user interacts with, often the domain name or application title
	 * @return string[] an array with the key URI (which can be encoded as a QR code) at index zero and the secret string (for manual input) at index one
	 * @throws TwoFactorMechanismAlreadyEnabledException if this method of two-factor authentification has already been enabled
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function prepareTwoFactorViaTotp($serviceName = null) {
		$serviceName = !empty($serviceName) ? (string) $serviceName : (!empty($_SERVER['SERVER_NAME']) ? (string) $_SERVER['SERVER_NAME'] : (string) $_SERVER['SERVER_ADDR']);

		return $this->prepareTwoFactor(self::TWO_FACTOR_MECHANISM_TOTP, $serviceName, null);
	}

	/**
	 * Prepares the setup of two-factor authentification with one-time passwords sent via SMS
	 *
	 * After performing this step, a one-time password will have to be delivered to the user via SMS and then be requested from the user for verification
	 *
	 * When the user has entered the one-time password from the text message afterwards, call {@see enableTwoFactorViaSms} with that one-time password
	 *
	 * @param string $phoneNumber the phone number to send the one-time passwords to
	 * @return string[] an array with the phone number at index zero and the one-time password to be sent (but not otherwise displayed to the user) at index one
	 * @throws InvalidPhoneNumberException if no valid phone number has been provided
	 * @throws TwoFactorMechanismAlreadyEnabledException if this method of two-factor authentification has already been enabled
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function prepareTwoFactorViaSms($phoneNumber) {
		$phoneNumber = !empty($phoneNumber) ? \trim((string) $phoneNumber) : '';

		if (\strlen($phoneNumber) < 3) {
			throw new InvalidPhoneNumberException();
		}

		$this->prepareTwoFactor(self::TWO_FACTOR_MECHANISM_SMS, null, $phoneNumber);
		$otpValue = $this->generateAndStoreRandomOneTimePassword($this->getUserId(), self::TWO_FACTOR_MECHANISM_SMS);

		return [ $phoneNumber, $otpValue ];
	}

	/**
	 * Prepares the setup of two-factor authentification with one-time passwords sent via email
	 *
	 * After performing this step, a one-time password will have to be delivered to the user via email and then be requested from the user for verification
	 *
	 * When the user has entered the one-time password from the email afterwards, call {@see enableTwoFactorViaEmail} with that one-time password
	 *
	 * @return string[] an array with the email address at index zero and the one-time password to be sent (but not otherwise displayed to the user) at index one
	 * @throws TwoFactorMechanismAlreadyEnabledException if this method of two-factor authentification has already been enabled
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function prepareTwoFactorViaEmail() {
		$this->prepareTwoFactor(self::TWO_FACTOR_MECHANISM_EMAIL, null, null);
		$otpValue = $this->generateAndStoreRandomOneTimePassword($this->getUserId(), self::TWO_FACTOR_MECHANISM_EMAIL);

		return [ $this->getEmail(), $otpValue ];
	}

	/**
	 * Prepares the setup of two-factor authentification via a specified mechanism
	 *
	 * @param int $mechanism the specific mechanism to be used for two-factor authentification, as one of the `TWO_FACTOR_MECHANISM_*` constants from this class
	 * @param string|null $serviceName (optional) the name of the service or application that the user interacts with, only used with TOTP 2FA
	 * @param string|null $phoneNumber (optional) the phone number to send the one-time passwords to, only used with SMS 2FA
	 * @return string[] an array with the TOTP configuration, if applicable, namely the key URI at index zero and the secret string at index one, or otherwise an empty array
	 * @throws TwoFactorMechanismAlreadyEnabledException if the specified method of two-factor authentification has already been enabled
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function prepareTwoFactor($mechanism, $serviceName = null, $phoneNumber = null) {
		if (empty($mechanism)) {
			throw new InvalidStateError();
		}

		if ($mechanism !== self::TWO_FACTOR_MECHANISM_TOTP && $mechanism !== self::TWO_FACTOR_MECHANISM_SMS && $mechanism !== self::TWO_FACTOR_MECHANISM_EMAIL) {
			throw new InvalidStateError();
		}

		if ($this->isLoggedIn()) {
			$this->throttle([ 'prepareTwoFactor', 'mechanism', $mechanism, 'userId', $this->getUserId() ], 2, (60 * 60), 2);
			$this->throttle([ 'prepareTwoFactor', 'mechanism', $mechanism, $this->getIpAddress() ], 3, (60 * 60), 3);

			try {
				$existingConfig = $this->db->selectRow(
					'SELECT id, expires_at FROM ' . $this->makeTableName('users_2fa') . ' WHERE user_id = ? AND mechanism = ?',
					[
						$this->getUserId(),
						$mechanism,
					]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			// if an existing configuration has been found
			if (!empty($existingConfig)) {
				// if the existing configuration has not been completed/enabled yet
				if (!empty($existingConfig['expires_at'])) {
					// delete the existing (incomplete) configuration
					try {
						$this->db->delete(
							$this->makeTableNameComponents('users_2fa'),
							[
								'id' => $existingConfig['id'],
								'user_id' => $this->getUserId(),
								'mechanism' => $mechanism,
								'expires_at' => $existingConfig['expires_at'],
							]
						);
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}

					// delete any one-time passwords for the user that were for (verification of) the old configuration
					try {
						$this->db->exec(
							'DELETE FROM ' . $this->makeTableName('users_otps') . ' WHERE user_id = ? AND mechanism = ? AND expires_at IS NOT NULL',
							[
								$this->getUserId(),
								$mechanism,
							]
						);
					}
					catch (Error $e) {
						throw new DatabaseError($e->getMessage());
					}
				}
				// if the existing configuration has been completed/enabled already
				else {
					throw new TwoFactorMechanismAlreadyEnabledException();
				}
			}

			// create a new configuration

			if ($mechanism === self::TWO_FACTOR_MECHANISM_TOTP) {
				$seed = \Delight\Otp\Otp::createSecret(\Delight\Otp\Otp::SHARED_SECRET_STRENGTH_HIGH);
				$totpKeyUri = \Delight\Otp\Otp::createTotpKeyUriForQrCode($serviceName, $this->getEmail(), $seed);
				$otpConfig = [ $totpKeyUri, $seed ];
			}
			elseif ($mechanism === self::TWO_FACTOR_MECHANISM_SMS) {
				$seed = $phoneNumber;
				$otpConfig = [];
			}
			elseif ($mechanism === self::TWO_FACTOR_MECHANISM_EMAIL) {
				$seed = $this->getEmail();
				$otpConfig = [];
			}
			else {
				throw new InvalidStateError();
			}

			try {
				$this->db->insert(
					$this->makeTableNameComponents('users_2fa'),
					[
						'user_id' => $this->getUserId(),
						'mechanism' => $mechanism,
						'seed' => $seed,
						'created_at' => \time(),
						'expires_at' => \time() + 60 * 30,
					]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			return $otpConfig;
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Completes the previously started setup of two-factor authentification via time-based one-time passwords (TOTP)
	 *
	 * Initially providing a valid one-time password here once is what proves that the setup was successful on the client side
	 *
	 * In order to let the user set up their authenticator application, call {@see prepareTwoFactorViaTotp} as a first step
	 *
	 * @param string $otpValue a one-time password (OTP) that has just been entered by the user, with or without spaces and special characters
	 * @return string[] a few recovery codes that can be used instead of one-time passwords from the authenticator application in case the user loses access to their TOTP source
	 * @throws InvalidOneTimePasswordException if the one-time password provided by the user is not valid
	 * @throws TwoFactorMechanismNotInitializedException if this method of two-factor authentification has not been initialized before or if the initialization has expired
	 * @throws TwoFactorMechanismAlreadyEnabledException if this method of two-factor authentification has already been enabled
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function enableTwoFactorViaTotp($otpValue) {
		return $this->enableTwoFactor(self::TWO_FACTOR_MECHANISM_TOTP, $otpValue);
	}

	/**
	 * Completes the previously started setup of two-factor authentification with one-time passwords sent via SMS
	 *
	 * Initially providing a valid one-time password here once is what proves that the setup was successful on the client side
	 *
	 * In order to let the user set up their phone number for OTPs via SMS, call {@see prepareTwoFactorViaSms} as a first step
	 *
	 * @param string $otpValue a one-time password (OTP) that has just been entered by the user, with or without spaces and special characters
	 * @return string[] a few recovery codes that can be used instead of one-time passwords from text messages in case the user loses access to their phone (number)
	 * @throws InvalidOneTimePasswordException if the one-time password provided by the user is not valid
	 * @throws TwoFactorMechanismNotInitializedException if this method of two-factor authentification has not been initialized before or if the initialization has expired
	 * @throws TwoFactorMechanismAlreadyEnabledException if this method of two-factor authentification has already been enabled
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function enableTwoFactorViaSms($otpValue) {
		return $this->enableTwoFactor(self::TWO_FACTOR_MECHANISM_SMS, $otpValue);
	}

	/**
	 * Completes the previously started setup of two-factor authentification with one-time passwords sent via email
	 *
	 * Initially providing a valid one-time password here once is what proves that the setup was successful on the client side
	 *
	 * In order to let the user set up their email address for OTPs via email, call {@see prepareTwoFactorViaEmail} as a first step
	 *
	 * @param string $otpValue a one-time password (OTP) that has just been entered by the user, with or without spaces and special characters
	 * @return string[] a few recovery codes that can be used instead of one-time passwords from emails in case the user loses access to their email (address)
	 * @throws InvalidOneTimePasswordException if the one-time password provided by the user is not valid
	 * @throws TwoFactorMechanismNotInitializedException if this method of two-factor authentification has not been initialized before or if the initialization has expired
	 * @throws TwoFactorMechanismAlreadyEnabledException if this method of two-factor authentification has already been enabled
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function enableTwoFactorViaEmail($otpValue) {
		return $this->enableTwoFactor(self::TWO_FACTOR_MECHANISM_EMAIL, $otpValue);
	}

	/**
	 * Completes the previously started setup of two-factor authentification via a specified mechanism
	 *
	 * Initially providing a valid one-time password here once is what proves that the setup was successful on the client side
	 *
	 * In order to let the user start the setup on the client side, call {@see prepareTwoFactorViaTotp}, {@see prepareTwoFactorViaSms} or {@see prepareTwoFactorViaEmail} as a first step
	 *
	 * @param int $mechanism the specific mechanism to be used for two-factor authentification, as one of the `TWO_FACTOR_MECHANISM_*` constants from this class
	 * @param string $otpValue a one-time password (OTP) that has just been entered by the user, with or without spaces and special characters
	 * @return string[] a few recovery codes that can be used instead of one-time passwords from the configured source in case the user loses access to their source
	 * @throws InvalidOneTimePasswordException if the one-time password provided by the user is not valid
	 * @throws TwoFactorMechanismNotInitializedException if the specified method of two-factor authentification has not been initialized before or if the initialization has expired
	 * @throws TwoFactorMechanismAlreadyEnabledException if the specified method of two-factor authentification has already been enabled
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function enableTwoFactor($mechanism, $otpValue) {
		if (empty($mechanism)) {
			throw new InvalidStateError();
		}

		if ($mechanism !== self::TWO_FACTOR_MECHANISM_TOTP && $mechanism !== self::TWO_FACTOR_MECHANISM_SMS && $mechanism !== self::TWO_FACTOR_MECHANISM_EMAIL) {
			throw new InvalidStateError();
		}

		if ($this->isLoggedIn()) {
			$this->throttle([ 'enableTwoFactor', 'mechanism', $mechanism, 'userId', $this->getUserId() ], 2, (60 * 60), 2);
			$this->throttle([ 'enableTwoFactor', 'mechanism', $mechanism, $this->getIpAddress() ], 3, (60 * 60), 3);

			$otpValue = !empty($otpValue) ? self::sanitizeOtpValue((string) $otpValue) : '';

			if (empty($otpValue)) {
				throw new InvalidOneTimePasswordException();
			}

			try {
				$existingConfig = $this->db->selectRow(
					'SELECT id, seed, expires_at FROM ' . $this->makeTableName('users_2fa') . ' WHERE user_id = ? AND mechanism = ?',
					[
						$this->getUserId(),
						$mechanism,
					]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			// if no existing configuration has been found
			if (empty($existingConfig)) {
				throw new TwoFactorMechanismNotInitializedException();
			}

			// if an existing configuration had already been completed/enabled
			if (empty($existingConfig['expires_at'])) {
				throw new TwoFactorMechanismAlreadyEnabledException();
			}

			// if the existing prepared configuration has already expired
			if ($existingConfig['expires_at'] < \time()) {
				throw new TwoFactorMechanismNotInitializedException();
			}

			// check if the one-time password provided by the user is valid

			if ($mechanism === self::TWO_FACTOR_MECHANISM_TOTP) {
				$otpValueVerified = \Delight\Otp\Otp::verifyTotp($existingConfig['seed'], $otpValue);
			}
			elseif ($mechanism === self::TWO_FACTOR_MECHANISM_SMS || $mechanism === self::TWO_FACTOR_MECHANISM_EMAIL) {
				$otpValueVerified = false;

				try {
					$otpRecords = $this->db->select(
						'SELECT id, token FROM ' . $this->makeTableName('users_otps') . ' WHERE selector = ? AND user_id = ? AND mechanism = ? AND expires_at >= ?',
						[
							self::createSelectorForOneTimePassword($otpValue, $this->getUserId()),
							$this->getUserId(),
							$mechanism,
							\time(),
						]
					);
				}
				catch (Error $e) {
					throw new DatabaseError($e->getMessage());
				}

				if (!empty($otpRecords)) {
					foreach ($otpRecords as $otpRecord) {
						if (!empty($otpRecord)) {
							if (\password_verify($otpValue, $otpRecord['token'])) {
								$otpValueVerified = true;

								// remove the one-time password from the database to prevent repeated usages
								try {
									$this->db->delete(
										$this->makeTableNameComponents('users_otps'),
										[ 'id' => $otpRecord['id'] ]
									);
								}
								catch (Error $e) {
									throw new DatabaseError($e->getMessage());
								}

								break;
							}
						}
					}
				}
			}
			else {
				throw new InvalidStateError();
			}

			// fail if the one-time password provided by the user has been invalid
			if (!$otpValueVerified) {
				throw new InvalidOneTimePasswordException();
			}

			// now that we know the one-time password has been valid

			// generate and store recovery codes that are to be presented to the user *once*

			$recoveryCodes = [];

			for ($i = 0; $i < 6; $i++) {
				$recoveryCode = \strtoupper(\Delight\Otp\Otp::createSecret(\Delight\Otp\Otp::SHARED_SECRET_STRENGTH_LOW));
				$recoveryCodeSelector = self::createSelectorForOneTimePassword($recoveryCode, $this->getUserId());
				$recoveryCodeToken = \password_hash($recoveryCode, \PASSWORD_DEFAULT);

				try {
					$this->db->insert(
						$this->makeTableNameComponents('users_otps'),
						[
							'user_id' => $this->getUserId(),
							'mechanism' => $mechanism,
							'single_factor' => 0,
							'selector' => $recoveryCodeSelector,
							'token' => $recoveryCodeToken,
							'expires_at' => null
						]
					);
				}
				catch (Error $e) {
					throw new DatabaseError($e->getMessage());
				}

				$recoveryCodes[] = $recoveryCode;
			}

			// update the existing (incomplete) configuration to complete/enable it
			try {
				$this->db->update(
					$this->makeTableNameComponents('users_2fa'),
					[
						'expires_at' => null,
					],
					[
						'id' => $existingConfig['id'],
						'user_id' => $this->getUserId(),
						'mechanism' => $mechanism,
						'expires_at' => $existingConfig['expires_at'],
					]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			return $recoveryCodes;
		}
		else {
			throw new NotLoggedInException();
		}
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
	 * Shorthand/alias for {@see getUserId}
	 *
	 * @return int
	 */
	public function id() {
		return $this->getUserId();
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
		if (empty($role) || !\is_numeric($role)) {
			return false;
		}

		if (isset($_SESSION) && isset($_SESSION[self::SESSION_FIELD_ROLES])) {
			$role = (int) $role;

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
	 * Returns an array of the user's roles, mapping the numerical values to their descriptive names
	 *
	 * @return array
	 */
	public function getRoles() {
		return \array_filter(
			Role::getMap(),
			[ $this, 'hasRole' ],
			\ARRAY_FILTER_USE_KEY
		);
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
	 * Returns whether the currently signed-in user has enabled two-factor authentification
	 *
	 * @return bool
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function hasTwoFactor() {
		if ($this->isLoggedIn()) {
			try {
				$enabled = $this->db->selectValue(
					'SELECT COUNT(*) FROM ' . $this->makeTableName('users_2fa') . ' WHERE user_id = ? AND expires_at IS NULL',
					[ $this->getUserId() ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			return ((int) $enabled) > 0;
		}
		else {
			return false;
		}
	}

	/**
	 * Returns whether the currently signed-in user has enabled two-factor authentification via time-based one-time passwords (TOTP)
	 *
	 * @return bool
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function hasTwoFactorViaTotp() {
		if ($this->isLoggedIn()) {
			try {
				$enabled = $this->db->selectValue(
					'SELECT COUNT(*) FROM ' . $this->makeTableName('users_2fa') . ' WHERE user_id = ? AND mechanism = ? AND expires_at IS NULL',
					[ $this->getUserId(), self::TWO_FACTOR_MECHANISM_TOTP ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			return ((int) $enabled) > 0;
		}
		else {
			return false;
		}
	}

	/**
	 * Returns whether the currently signed-in user has enabled two-factor authentification with one-time passwords sent via SMS
	 *
	 * @return bool
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function hasTwoFactorViaSms() {
		if ($this->isLoggedIn()) {
			try {
				$enabled = $this->db->selectValue(
					'SELECT COUNT(*) FROM ' . $this->makeTableName('users_2fa') . ' WHERE user_id = ? AND mechanism = ? AND expires_at IS NULL',
					[ $this->getUserId(), self::TWO_FACTOR_MECHANISM_SMS ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			return ((int) $enabled) > 0;
		}
		else {
			return false;
		}
	}

	/**
	 * Returns whether the currently signed-in user has enabled two-factor authentification with one-time passwords sent via email
	 *
	 * @return bool
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function hasTwoFactorViaEmail() {
		if ($this->isLoggedIn()) {
			try {
				$enabled = $this->db->selectValue(
					'SELECT COUNT(*) FROM ' . $this->makeTableName('users_2fa') . ' WHERE user_id = ? AND mechanism = ? AND expires_at IS NULL',
					[ $this->getUserId(), self::TWO_FACTOR_MECHANISM_EMAIL ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			return ((int) $enabled) > 0;
		}
		else {
			return false;
		}
	}

	/**
	 * Returns whether we are waiting for the user to complete the second factor of (two-factor) authentification, them having successfully completed the first factor before
	 *
	 * @return bool
	 */
	public function isWaitingForSecondFactor() {
		return !empty($_SESSION[self::SESSION_FIELD_AWAITING_2FA_UNTIL]) && $_SESSION[self::SESSION_FIELD_AWAITING_2FA_UNTIL] >= \time();
	}

	/**
	 * Disables two-factor authentification via time-based one-time passwords (TOTP) for the currently signed-in user
	 *
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function disableTwoFactorViaTotp() {
		if ($this->isLoggedIn()) {
			try {
				$this->db->exec(
					'DELETE FROM ' . $this->makeTableName('users_2fa') . ' WHERE user_id = ? AND mechanism = ? AND expires_at IS NULL',
					[ $this->getUserId(), self::TWO_FACTOR_MECHANISM_TOTP ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Disables two-factor authentification with one-time passwords sent via SMS for the currently signed-in user
	 *
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function disableTwoFactorViaSms() {
		if ($this->isLoggedIn()) {
			try {
				$this->db->exec(
					'DELETE FROM ' . $this->makeTableName('users_2fa') . ' WHERE user_id = ? AND mechanism = ? AND expires_at IS NULL',
					[ $this->getUserId(), self::TWO_FACTOR_MECHANISM_SMS ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Disables two-factor authentification with one-time passwords sent via email for the currently signed-in user
	 *
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function disableTwoFactorViaEmail() {
		if ($this->isLoggedIn()) {
			try {
				$this->db->exec(
					'DELETE FROM ' . $this->makeTableName('users_2fa') . ' WHERE user_id = ? AND mechanism = ? AND expires_at IS NULL',
					[ $this->getUserId(), self::TWO_FACTOR_MECHANISM_EMAIL ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}
		}
		else {
			throw new NotLoggedInException();
		}
	}

	/**
	 * Disables two-factor authentification by any method for the currently signed-in user
	 *
	 * @throws NotLoggedInException if the user is not currently signed in
	 * @throws TooManyRequestsException if the number of allowed attempts/requests has been exceeded
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function disableTwoFactor() {
		if ($this->isLoggedIn()) {
			try {
				$this->db->exec(
					'DELETE FROM ' . $this->makeTableName('users_2fa') . ' WHERE user_id = ? AND expires_at IS NULL',
					[ $this->getUserId() ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}
		}
		else {
			throw new NotLoggedInException();
		}
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
	 * @param bool|null $force (optional) whether to apply throttling locally (with this call) even when throttling has been disabled globally (on the instance, via the constructor option)
	 * @return float the number of units remaining from the supply
	 * @throws TooManyRequestsException if the actual demand has exceeded the designated supply
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function throttle(array $criteria, $supply, $interval, $burstiness = null, $simulated = null, $cost = null, $force = null) {
		// validate the supplied parameters and set appropriate defaults where necessary
		$force = ($force !== null) ? (bool) $force : false;

		if (!$this->throttling && !$force) {
			return $supply;
		}

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
				'SELECT tokens, replenished_at FROM ' . $this->makeTableName('users_throttling') . ' WHERE bucket = ?',
				[ $key ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError($e->getMessage());
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
					$this->makeTableNameComponents('users_throttling'),
					$bucket,
					[ 'bucket' => $key ]
				);
			}
			catch (Error $e) {
				throw new DatabaseError($e->getMessage());
			}

			if ($affected === 0) {
				$bucket['bucket'] = $key;

				try {
					$this->db->insert(
						$this->makeTableNameComponents('users_throttling'),
						$bucket
					);
				}
				catch (IntegrityConstraintViolationException $ignored) {}
				catch (Error $e) {
					throw new DatabaseError($e->getMessage());
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
		return new Administration($this->db, $this->dbTablePrefix, $this->dbSchema);
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
		$data = \openssl_random_pseudo_bytes(16);

		// set the version to 0100
		$data[6] = \chr(\ord($data[6]) & 0x0f | 0x40);
		// set bits 6-7 to 10
		$data[8] = \chr(\ord($data[8]) & 0x3f | 0x80);

		return \vsprintf('%s%s-%s-%s-%s-%s%s%s', \str_split(\bin2hex($data), 4));
	}

	/**
	 * Generates a unique cookie name for the given descriptor based on the supplied seed
	 *
	 * @param string $descriptor a short label describing the purpose of the cookie, e.g. 'session'
	 * @param string|null $seed (optional) the data to deterministically generate the name from
	 * @return string
	 */
	public static function createCookieName($descriptor, $seed = null) {
		// use the supplied seed or the current UNIX time in seconds
		$seed = ($seed !== null) ? $seed : \time();

		foreach (self::COOKIE_PREFIXES as $cookiePrefix) {
			// if the seed contains a certain cookie prefix
			if (\strpos($seed, $cookiePrefix) === 0) {
				// prepend the same prefix to the descriptor
				$descriptor = $cookiePrefix . $descriptor;
			}
		}

		// generate a unique token based on the name(space) of this library and on the seed
		$token = Base64::encodeUrlSafeWithoutPadding(
			\md5(
				__NAMESPACE__ . "\n" . $seed,
				true
			)
		);

		return $descriptor . '_' . $token;
	}

	/**
	 * Generates a unique cookie name for the 'remember me' feature
	 *
	 * @param string|null $sessionName (optional) the session name that the output should be based on
	 * @return string
	 */
	public static function createRememberCookieName($sessionName = null) {
		return self::createCookieName(
			'remember',
			($sessionName !== null) ? $sessionName : \session_name()
		);
	}

	private static function createSelectorForOneTimePassword($otpValue, $userId = null) {
		$userId = !empty($userId) ? (int) $userId : 0;
		$key = $userId . '#' . $otpValue;

		return \substr(\sha1($key, false), 0, 24);
	}

	/**
	 * Returns the selector of a potential locally existing remember directive
	 *
	 * @return string|null
	 */
	private function getRememberDirectiveSelector() {
		if (isset($_COOKIE[$this->rememberCookieName])) {
			$selectorAndToken = \explode(self::COOKIE_CONTENT_SEPARATOR, $_COOKIE[$this->rememberCookieName], 2);

			return $selectorAndToken[0];
		}
		else {
			return null;
		}
	}

	/**
	 * Returns the expiry date of a potential locally existing remember directive
	 *
	 * @return int|null
	 */
	private function getRememberDirectiveExpiry() {
		// if the user is currently signed in
		if ($this->isLoggedIn()) {
			// determine the selector of any currently existing remember directive
			$existingSelector = $this->getRememberDirectiveSelector();

			// if there is currently a remember directive whose selector we have just retrieved
			if (isset($existingSelector)) {
				// fetch the expiry date for the given selector
				$existingExpiry = $this->db->selectValue(
					'SELECT expires FROM ' . $this->makeTableName('users_remembered') . ' WHERE selector = ? AND user = ?',
					[
						$existingSelector,
						$this->getUserId()
					]
				);

				// if an expiration date has been found
				if (isset($existingExpiry)) {
					// return the date
					return (int) $existingExpiry;
				}
			}
		}

		return null;
	}

	private static function sanitizeOtpValue($otpValue) {
		$otpValue = \trim($otpValue);
		$otpValue = \preg_replace('/[^A-Za-z0-9]/', '', $otpValue);
		$otpValue = \strtoupper($otpValue);

		return $otpValue;
	}

}
