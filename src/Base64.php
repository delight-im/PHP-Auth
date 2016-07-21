<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

class Base64 {

	const SPECIAL_CHARS_ORIGINAL = '+/=';
	const SPECIAL_CHARS_SAFE = '._-';

	public static function encode($data, $safeChars = false) {
		$result = base64_encode($data);

		if ($safeChars) {
			$result = strtr($result, self::SPECIAL_CHARS_ORIGINAL, self::SPECIAL_CHARS_SAFE);
		}

		return $result;
	}

	public static function decode($data) {
		$data = strtr($data, self::SPECIAL_CHARS_SAFE, self::SPECIAL_CHARS_ORIGINAL);

		$result = base64_decode($data, true);

		return $result;
	}

}
