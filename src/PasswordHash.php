<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

final class PasswordHash {

	const HASH_ALGORITHM_IDENTIFIER = \PASSWORD_DEFAULT;

	/**
	 * Creates a computationally expensive hash from a password
	 *
	 * @param string $passwordText
	 * @return string|bool
	 */
	public static function from($passwordText) {
		return \password_hash($passwordText, self::HASH_ALGORITHM_IDENTIFIER);
	}

	/**
	 * Verifies whether a password matches a computationally expensive hash
	 *
	 * @param string $passwordText
	 * @param string $expectedHash
	 * @return bool
	 */
	public static function verify($passwordText, $expectedHash) {
		return \password_verify($passwordText, $expectedHash);
	}

	/**
	 * Checks whether a computationally expensive hash needs to be updated to match a desired algorithm and set of options
	 *
	 * @param string $existingHash
	 * @return bool
	 */
	public static function needsRehash($existingHash) {
		return \password_needs_rehash($existingHash, self::HASH_ALGORITHM_IDENTIFIER);
	}

}
