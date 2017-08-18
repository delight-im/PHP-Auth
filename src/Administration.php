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
	 * @param string|null $dbTablePrefix (optional) the prefix for the names of all database tables used by this component
	 */
	public function __construct(PdoDatabase $databaseConnection, $dbTablePrefix = null) {
		parent::__construct($databaseConnection, $dbTablePrefix);
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

	/**
	 * Assigns the specified role to the user with the given ID
	 *
	 * A user may have any number of roles (i.e. no role at all, a single role, or any combination of roles)
	 *
	 * @param int $userId the ID of the user to assign the role to
	 * @param int $role the role as one of the constants from the {@see Role} class
	 * @throws UnknownIdException if no user with the specified ID has been found
	 *
	 * @see Role
	 */
	public function addRoleForUserById($userId, $role) {
		$userFound = $this->addRoleForUserByColumnValue(
			'id',
			(int) $userId,
			$role
		);

		if ($userFound === false) {
			throw new UnknownIdException();
		}
	}

	/**
	 * Assigns the specified role to the user with the given email address
	 *
	 * A user may have any number of roles (i.e. no role at all, a single role, or any combination of roles)
	 *
	 * @param string $userEmail the email address of the user to assign the role to
	 * @param int $role the role as one of the constants from the {@see Role} class
	 * @throws InvalidEmailException if no user with the specified email address has been found
	 *
	 * @see Role
	 */
	public function addRoleForUserByEmail($userEmail, $role) {
		$userEmail = self::validateEmailAddress($userEmail);

		$userFound = $this->addRoleForUserByColumnValue(
			'email',
			$userEmail,
			$role
		);

		if ($userFound === false) {
			throw new InvalidEmailException();
		}
	}

	/**
	 * Assigns the specified role to the user with the given username
	 *
	 * A user may have any number of roles (i.e. no role at all, a single role, or any combination of roles)
	 *
	 * @param string $username the username of the user to assign the role to
	 * @param int $role the role as one of the constants from the {@see Role} class
	 * @throws UnknownUsernameException if no user with the specified username has been found
	 * @throws AmbiguousUsernameException if multiple users with the specified username have been found
	 *
	 * @see Role
	 */
	public function addRoleForUserByUsername($username, $role) {
		$userData = $this->getUserDataByUsername(
			\trim($username),
			[ 'id' ]
		);

		$this->addRoleForUserByColumnValue(
			'id',
			(int) $userData['id'],
			$role
		);
	}

	/**
	 * Takes away the specified role from the user with the given ID
	 *
	 * A user may have any number of roles (i.e. no role at all, a single role, or any combination of roles)
	 *
	 * @param int $userId the ID of the user to take the role away from
	 * @param int $role the role as one of the constants from the {@see Role} class
	 * @throws UnknownIdException if no user with the specified ID has been found
	 *
	 * @see Role
	 */
	public function removeRoleForUserById($userId, $role) {
		$userFound = $this->removeRoleForUserByColumnValue(
			'id',
			(int) $userId,
			$role
		);

		if ($userFound === false) {
			throw new UnknownIdException();
		}
	}

	/**
	 * Takes away the specified role from the user with the given email address
	 *
	 * A user may have any number of roles (i.e. no role at all, a single role, or any combination of roles)
	 *
	 * @param string $userEmail the email address of the user to take the role away from
	 * @param int $role the role as one of the constants from the {@see Role} class
	 * @throws InvalidEmailException if no user with the specified email address has been found
	 *
	 * @see Role
	 */
	public function removeRoleForUserByEmail($userEmail, $role) {
		$userEmail = self::validateEmailAddress($userEmail);

		$userFound = $this->removeRoleForUserByColumnValue(
			'email',
			$userEmail,
			$role
		);

		if ($userFound === false) {
			throw new InvalidEmailException();
		}
	}

	/**
	 * Takes away the specified role from the user with the given username
	 *
	 * A user may have any number of roles (i.e. no role at all, a single role, or any combination of roles)
	 *
	 * @param string $username the username of the user to take the role away from
	 * @param int $role the role as one of the constants from the {@see Role} class
	 * @throws UnknownUsernameException if no user with the specified username has been found
	 * @throws AmbiguousUsernameException if multiple users with the specified username have been found
	 *
	 * @see Role
	 */
	public function removeRoleForUserByUsername($username, $role) {
		$userData = $this->getUserDataByUsername(
			\trim($username),
			[ 'id' ]
		);

		$this->removeRoleForUserByColumnValue(
			'id',
			(int) $userData['id'],
			$role
		);
	}

	/**
	 * Returns whether the user with the given ID has the specified role
	 *
	 * @param int $userId the ID of the user to check the roles for
	 * @param int $role the role as one of the constants from the {@see Role} class
	 * @return bool
	 * @throws UnknownIdException if no user with the specified ID has been found
	 *
	 * @see Role
	 */
	public function doesUserHaveRole($userId, $role) {
		$userId = (int) $userId;
		$role = (int) $role;

		$rolesBitmask = $this->db->selectValue(
			'SELECT roles_mask FROM ' . $this->dbTablePrefix . 'users WHERE id = ?',
			[ $userId ]
		);

		if ($rolesBitmask === null) {
			throw new UnknownIdException();
		}

		return ($rolesBitmask & $role) === $role;
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
				$this->dbTablePrefix . 'users',
				[
					$columnName => $columnValue
				]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}
	}

	/**
	 * Modifies the roles for the user where the column with the specified name has the given value
	 *
	 * You must never pass untrusted input to the parameter that takes the column name
	 *
	 * @param string $columnName the name of the column to filter by
	 * @param mixed $columnValue the value to look for in the selected column
	 * @param callable $modification the modification to apply to the existing bitmask of roles
	 * @return bool whether any user with the given column constraints has been found
	 * @throws AuthError if an internal problem occurred (do *not* catch)
	 *
	 * @see Role
	 */
	private function modifyRolesForUserByColumnValue($columnName, $columnValue, callable $modification) {
		try {
			$userData = $this->db->selectRow(
				'SELECT id, roles_mask FROM ' . $this->dbTablePrefix . 'users WHERE ' . $columnName . ' = ?',
				[ $columnValue ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}

		if ($userData === null) {
			return false;
		}

		$newRolesBitmask = $modification($userData['roles_mask']);

		try {
			$this->db->exec(
				'UPDATE ' . $this->dbTablePrefix . 'users SET roles_mask = ? WHERE id = ?',
				[
					$newRolesBitmask,
					(int) $userData['id']
				]
			);

			return true;
		}
		catch (Error $e) {
			throw new DatabaseError();
		}
	}

	/**
	 * Assigns the specified role to the user where the column with the specified name has the given value
	 *
	 * You must never pass untrusted input to the parameter that takes the column name
	 *
	 * @param string $columnName the name of the column to filter by
	 * @param mixed $columnValue the value to look for in the selected column
	 * @param int $role the role as one of the constants from the {@see Role} class
	 * @return bool whether any user with the given column constraints has been found
	 *
	 * @see Role
	 */
	private function addRoleForUserByColumnValue($columnName, $columnValue, $role) {
		$role = (int) $role;

		return $this->modifyRolesForUserByColumnValue(
			$columnName,
			$columnValue,
			function ($oldRolesBitmask) use ($role) {
				return $oldRolesBitmask | $role;
			}
		);
	}

	/**
	 * Takes away the specified role from the user where the column with the specified name has the given value
	 *
	 * You must never pass untrusted input to the parameter that takes the column name
	 *
	 * @param string $columnName the name of the column to filter by
	 * @param mixed $columnValue the value to look for in the selected column
	 * @param int $role the role as one of the constants from the {@see Role} class
	 * @return bool whether any user with the given column constraints has been found
	 *
	 * @see Role
	 */
	private function removeRoleForUserByColumnValue($columnName, $columnValue, $role) {
		$role = (int) $role;

		return $this->modifyRolesForUserByColumnValue(
			$columnName,
			$columnValue,
			function ($oldRolesBitmask) use ($role) {
				return $oldRolesBitmask & ~$role;
			}
		);
	}

}
