<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

final class PhoneNumber {

	/**
	 * Returns a masked version of the given phone number that can be used for privacy reasons and data safety reasons
	 *
	 * @param string $phoneNumber
	 * @return string
	 */
	public static function mask($phoneNumber) {
		if (empty($phoneNumber)) {
			return '';
		}

		$phoneNumber = \preg_replace('/[^0-9A-Za-z+]+/', '', $phoneNumber);

		if (empty($phoneNumber)) {
			return '';
		}

		$hasLeadingPlus = \mb_substr($phoneNumber, 0, 1) === '+';

		if ($hasLeadingPlus) {
			$phoneNumber = \mb_substr($phoneNumber, 1);
		}

		$significantCharsLength = \mb_strlen($phoneNumber);

		if ($significantCharsLength >= 7) {
			$phoneNumber = \mb_substr($phoneNumber, 0, 2) . '***' . \mb_substr($phoneNumber, -2);
		}
		elseif ($significantCharsLength === 6) {
			$phoneNumber = \mb_substr($phoneNumber, 0, 2) . '**' . \mb_substr($phoneNumber, -2);
		}
		elseif ($significantCharsLength === 5) {
			$phoneNumber = \mb_substr($phoneNumber, 0, 1) . '**' . \mb_substr($phoneNumber, -2);
		}
		elseif ($significantCharsLength === 4) {
			$phoneNumber = \mb_substr($phoneNumber, 0, 1) . '**' . \mb_substr($phoneNumber, -1);
		}
		elseif ($significantCharsLength === 3) {
			$phoneNumber = '**' . \mb_substr($phoneNumber, -1);
		}
		elseif ($significantCharsLength === 2) {
			$phoneNumber = '**';
		}
		else {
			$phoneNumber = '*';
		}

		if ($hasLeadingPlus) {
			$phoneNumber = '+' . $phoneNumber;
		}

		return $phoneNumber;
	}

}
