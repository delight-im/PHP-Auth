<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

use Delight\Db\PdoDatabase;
use Delight\Db\Throwable\Error;

require_once __DIR__ . '/Exceptions.php';

/** Component that can be used for administrative tasks by privileged and authorized users */
final class Administration extends UserManager {

	/**
	 * @param PdoDatabase $databaseConnection the database connection to operate on
	 */
	public function __construct(PdoDatabase $databaseConnection) {
		parent::__construct($databaseConnection);
	}

	/**
	 * Creates a new user
	 *
	 * @param string $email the email address to register
	 * @param string $password the password for the new account
	 * @param string|null $username (optional) the username that will be displayed
	 * @return int the ID of the user that has been created (if any)
	 * @throws InvalidEmailException if the email address was invalid
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws UserAlreadyExistsException if a user with the specified email address already exists
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function createUser($email, $password, $username = null) {
		return $this->createUserInternal(false, $email, $password, $username, null);
	}

	/**
	 * Creates a new user while ensuring that the username is unique
	 *
	 * @param string $email the email address to register
	 * @param string $password the password for the new account
	 * @param string|null $username (optional) the username that will be displayed
	 * @return int the ID of the user that has been created (if any)
	 * @throws InvalidEmailException if the email address was invalid
	 * @throws InvalidPasswordException if the password was invalid
	 * @throws UserAlreadyExistsException if a user with the specified email address already exists
	 * @throws DuplicateUsernameException if the specified username wasn't unique
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function createUserWithUniqueUsername($email, $password, $username = null) {
		return $this->createUserInternal(true, $email, $password, $username, null);
	}

	protected function throttle($actionType, $customSelector = null) {}

	/**
	 * Deletes all existing users where the column with the specified name has the given value
	 *
	 * You must never pass untrusted input to the parameter that takes the column name
	 *
	 * @param string $columnName the name of the column to filter by
	 * @param mixed $columnValue the value to look for in the selected column
	 * @return int the number of deleted users
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	private function deleteUsersByColumnValue($columnName, $columnValue) {
		try {
			return $this->db->delete(
				'users',
				[
					$columnName => $columnValue
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}
	}

}
