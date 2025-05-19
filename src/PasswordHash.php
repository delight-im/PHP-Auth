<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

final class PasswordHash {

	const HASH_ALGORITHM_IDENTIFIER = \PASSWORD_DEFAULT;
	const PEPPER_HMAC_SHA_512_PREHASH = 'bec95beffb3afd078df7cbfd4c4617ba214ac4641a157c1ca64106e7544c9fb4cef6e99b0a8f0b63e96328c09943ce96b9b8899ff54fa7ea57b622675442dbbf';
	const PREFIX_BCRYPT_WITH_HMAC_SHA_512_PREHASH = '$pa01';
	const PREFIX_LENGTH = 5;

	/**
	 * Creates a computationally expensive hash from a password
	 *
	 * @param string $passwordText
	 * @return string|bool
	 */
	public static function from($passwordText) {
		// if the bcrypt algorithm will be used for computationally expensive hashing
		if (self::HASH_ALGORITHM_IDENTIFIER === \PASSWORD_BCRYPT || self::HASH_ALGORITHM_IDENTIFIER === null) {
			// pre-hash the password to support passwords with more than 72 bytes (i.e. more than 18-72 characters) and passwords containing null bytes
			$passwordText = self::prehash($passwordText);
			// use 72 out of the ~88 bytes from the prehash in bcrypt later and denote this in a custom hash prefix
			$outputPrefix = self::PREFIX_BCRYPT_WITH_HMAC_SHA_512_PREHASH;
		}
		else {
			$outputPrefix = '';
		}

		return $outputPrefix . \password_hash($passwordText, self::HASH_ALGORITHM_IDENTIFIER);
	}

	/**
	 * Verifies whether a password matches a computationally expensive hash
	 *
	 * @param string $passwordText
	 * @param string $expectedHash
	 * @return bool
	 */
	public static function verify($passwordText, $expectedHash) {
		// if the expected hash has a custom prefix that indicates a prehash has been used
		if (\substr($expectedHash, 0, self::PREFIX_LENGTH) === self::PREFIX_BCRYPT_WITH_HMAC_SHA_512_PREHASH) {
			// pre-hash the password here as well to allow for a possible match
			$passwordText = self::prehash($passwordText);
			// and drop the custom prefix from the expected hash
			$expectedHash = \substr($expectedHash, self::PREFIX_LENGTH);
		}

		return \password_verify($passwordText, $expectedHash);
	}

	/**
	 * Checks whether a computationally expensive hash needs to be updated to match a desired algorithm and set of options
	 *
	 * @param string $existingHash
	 * @return bool
	 */
	public static function needsRehash($existingHash) {
		// if the existing hash has a custom prefix indicating that a prehash has been used
		if (\substr($existingHash, 0, self::PREFIX_LENGTH) === self::PREFIX_BCRYPT_WITH_HMAC_SHA_512_PREHASH) {
			// drop that custom prefix from the existing hash
			$existingHash = \substr($existingHash, self::PREFIX_LENGTH);
		}
		/*// if the existing hash has no custom prefix denoting a prehash
		else {
			// if the existing hash used the bcrypt algorithm
			if (\preg_match('/^\$2[abxy]?\$/', $existingHash) === 1) {
				// the prehash needs to be applied
				return true;
			}
		}*/

		return \password_needs_rehash($existingHash, self::HASH_ALGORITHM_IDENTIFIER);
	}

	private static function prehash($passwordText) {
		$pepperBinary = \hex2bin(self::PEPPER_HMAC_SHA_512_PREHASH);

		// do not just use SHA-512 but apply an HMAC with a (semi-public) pepper to avoid breach correlation or "password shucking"
		$hmacBinary = \hash_hmac('sha512', $passwordText, $pepperBinary, true);

		if (empty($hmacBinary)) {
			throw new AuthError('Could not generate HMAC');
		}

		// encode the prehash using Base64 to avoid passing null bytes to the main hash function later (which could truncate the input)
		return \base64_encode($hmacBinary);
	}

}
