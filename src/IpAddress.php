<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

final class IpAddress {

	const IPV4_LENGTH_BITS = 32;
	const IPV4_LENGTH_BYTES = 4;
	const IPV6_LENGTH_BITS = 128;
	const IPV6_LENGTH_BYTES = 16;

	/**
	 * Returns a masked version of the given IP address (IPv4 or IPv6) that can be used for privacy reasons and data safety reasons
	 *
	 * For IPv4-mapped IPv6 addresses, only the embedded IPv4 portion is masked (like an IPv4 address) and returned as IPv6 again
	 *
	 * @param string $ip the IP address (IPv4 or IPv6), e.g. '192.0.2.128' or '2001:db8:be4d:fbe0:c0af:b298:1242:33e4'
	 * @param int|null $maskBitsIpv4 (optional) the number of bits to zero out from the right in IPv4 addresses
	 * @param int|null $maskBitsIpv6 (optional) the number of bits to zero out from the right in IPv6 addresses
	 * @param bool|null $includePrefixLength (optional) whether to include the prefix length (e.g. '/24' at the end) or not
	 * @return string|null
	 */
	public static function mask($ip, $maskBitsIpv4 = null, $maskBitsIpv6 = null, $includePrefixLength = null) {
		$maskBitsIpv4 = isset($maskBitsIpv4) ? \max(0, \min(self::IPV4_LENGTH_BITS, (int) $maskBitsIpv4)) : 8;
		$maskBitsIpv6 = isset($maskBitsIpv6) ? \max(0, \min(self::IPV6_LENGTH_BITS, (int) $maskBitsIpv6)) : 80;
		$packedIp = @\inet_pton($ip);

		if ($packedIp === false) {
			return null;
		}

		$ipLengthInBytes = \strlen($packedIp);

		// for IPv4 addresses
		if ($ipLengthInBytes === self::IPV4_LENGTH_BYTES) {
			if ($maskBitsIpv4 === 0) {
				return $ip;
			}
			elseif ($maskBitsIpv4 === self::IPV4_LENGTH_BITS) {
				return '0.0.0.0';
			}

			// unpack to a 32-bit unsigned integer in network byte order
			$ipInt32 = unpack('N', $packedIp)[1];

			// create a bitmask (like 0xFFFFFF00 to mask 8 bits or 0xFFFF0000 to mask 16 bits) using a bitwise right shift and then left shift
			$mask = (0xFFFFFFFF >> $maskBitsIpv4) << $maskBitsIpv4;

			$packedIp = \pack('N', $ipInt32 & $mask);

			$prefixLength = self::IPV4_LENGTH_BITS - $maskBitsIpv4;
		}
		// for IPv6 addresses
		elseif ($ipLengthInBytes === self::IPV6_LENGTH_BYTES) {
			// if the IP address is an IPv4-mapped IPv6 address
			if (\substr($packedIp, 0, 12) === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff") {
				// the last 4 bytes are the IPv4 address, so mask bits as per IPv4 option
				$maskBitsIpv6 = $maskBitsIpv4;
			}

			if ($maskBitsIpv6 === 0) {
				return $ip;
			}
			elseif ($maskBitsIpv6 === self::IPV6_LENGTH_BITS) {
				return '::';
			}

			$maskBytesIpv6 = (int) \ceil($maskBitsIpv6 / 8);
			$maskBitsInFirstByteIpv6 = $maskBitsIpv6 % 8;

			// work byte by byte for IPv6 due to lack of 128-bit integers

			for ($i = 0; $i < $maskBytesIpv6; $i++) {
				// start from the rightmost byte
				$byteIndex = $ipLengthInBytes - $i - 1;

				// if we are at the first byte and it should only be masked partially (i.e. masking 1-7 bits there)
				if ($i === ($maskBytesIpv6 - 1) && $maskBitsInFirstByteIpv6 !== 0) {
					$firstByteMask = (0xFF >> $maskBitsInFirstByteIpv6) << $maskBitsInFirstByteIpv6;
					$packedIp[$byteIndex] = \chr(\ord($packedIp[$byteIndex]) & $firstByteMask);
				}
				// when masking a full first byte or any byte after the first byte
				else {
					 $packedIp[$byteIndex] = "\x00";
				}
			}

			$prefixLength = self::IPV6_LENGTH_BITS - $maskBitsIpv6;
		}
		// for addresses with invalid lengths in bytes
		else {
			return null;
		}

		$ip = \inet_ntop($packedIp);

		if ($includePrefixLength) {
			return $ip . '/' . $prefixLength;
		}
		else {
			return $ip;
		}
	}

}
