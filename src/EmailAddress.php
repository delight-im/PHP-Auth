<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

final class EmailAddress {

	/**
	 * Returns a masked version of the given email address that can be used for privacy reasons and data safety reasons
	 *
	 * @param string $emailAddress
	 * @return string
	 */
	public static function mask($emailAddress) {
		if (empty($emailAddress)) {
			return $emailAddress;
		}

		// split the email address into local part and domain part and then split the domain part into individual segments
		$emailAddress = \trim((string) $emailAddress);
		$partsSeparatedByAtSymbol = \explode('@', $emailAddress);
		$domainPart = \array_pop($partsSeparatedByAtSymbol);
		$localPart = \implode('@', $partsSeparatedByAtSymbol);
		$localPart = \str_replace('"', '', $localPart);
		$localPart = \str_replace("'", "", $localPart);
		$parts = \explode('.', $domainPart);
		\array_unshift($parts, $localPart);

		// mask the individual parts of the address one by one
		for ($i = 0; $i < \count($parts); $i++) {
			$parts[$i] = \trim($parts[$i]);

			if (\mb_strlen($parts[$i]) >= 5) {
				$parts[$i] = \mb_substr($parts[$i], 0, 1) . '***' . \mb_substr($parts[$i], -1);
			}
			elseif (\mb_strlen($parts[$i]) === 4) {
				$parts[$i] = \mb_substr($parts[$i], 0, 1) . '**' . \mb_substr($parts[$i], -1);
			}
			elseif (\mb_strlen($parts[$i]) === 3 && $i <= 1) {
				$parts[$i] = \mb_substr($parts[$i], 0, 1) . '*' . \mb_substr($parts[$i], -1);
			}
			elseif (\mb_strlen($parts[$i]) === 2 && $i <= 1) {
				$parts[$i] = \mb_substr($parts[$i], 0, 1) . '*';
			}
			elseif (\mb_strlen($parts[$i]) === 1 && $i <= 1) {
				$parts[$i] = '*';
			}
		}

		// join the individual parts back together
		return \array_shift($parts) . '@' . \implode('.', $parts);
	}

}
