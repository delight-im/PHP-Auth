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
	 * @internal
	 *
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

	/**
	 * Deletes the user with the specified ID
	 *
	 * This action cannot be undone
	 *
	 * @param int $id the ID of the user to delete
	 * @throws UnknownIdException if no user with the specified ID has been found
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function deleteUserById($id) {
		$numberOfDeletedUsers = $this->deleteUsersByColumnValue('id', (int) $id);

		if ($numberOfDeletedUsers === 0) {
			throw new UnknownIdException();
		}
	}

	/**
	 * Deletes the user with the specified email address
	 *
	 * This action cannot be undone
	 *
	 * @param string $email the email address of the user to delete
	 * @throws InvalidEmailException if no user with the specified email address has been found
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function deleteUserByEmail($email) {
		$email = self::validateEmailAddress($email);

		$numberOfDeletedUsers = $this->deleteUsersByColumnValue('email', $email);

		if ($numberOfDeletedUsers === 0) {
			throw new InvalidEmailException();
		}
	}

	/**
	 * Deletes the user with the specified username
	 *
	 * This action cannot be undone
	 *
	 * @param string $username the username of the user to delete
	 * @throws UnknownUsernameException if no user with the specified username has been found
	 * @throws AmbiguousUsernameException if multiple users with the specified username have been found
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 */
	public function deleteUserByUsername($username) {
		$userData = $this->getUserDataByUsername(
			trim($username),
			[ 'id' ]
		);

		$this->deleteUsersByColumnValue('id', (int) $userData['id']);
	}

	protected function throttle($actionType, $customSelector = null) {
		// do nothing
	}

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
