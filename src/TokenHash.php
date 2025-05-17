<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

final class TokenHash {

	const HASH_ALGORITHM_IDENTIFIER = \PASSWORD_DEFAULT;

	/**
	 * Creates a computationally expensive hash from a token
	 *
	 * @param string $tokenText
	 * @return string|bool
	 */
	public static function from($tokenText) {
		return \password_hash($tokenText, self::HASH_ALGORITHM_IDENTIFIER);
	}

	/**
	 * Verifies whether a token matches a computationally expensive hash
	 *
	 * @param string $tokenText
	 * @param string $expectedHash
	 * @return bool
	 */
	public static function verify($tokenText, $expectedHash) {
		return \password_verify($tokenText, $expectedHash);
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
