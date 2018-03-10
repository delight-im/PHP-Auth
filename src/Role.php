<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

final class Role {

	const ADMIN = 1;
	const AUTHOR = 2;
	const COLLABORATOR = 4;
	const CONSULTANT = 8;
	const CONSUMER = 16;
	const CONTRIBUTOR = 32;
	const COORDINATOR = 64;
	const CREATOR = 128;
	const DEVELOPER = 256;
	const DIRECTOR = 512;
	const EDITOR = 1024;
	const EMPLOYEE = 2048;
	const MAINTAINER = 4096;
	const MANAGER = 8192;
	const MODERATOR = 16384;
	const PUBLISHER = 32768;
	const REVIEWER = 65536;
	const SUBSCRIBER = 131072;
	const SUPER_ADMIN = 262144;
	const SUPER_EDITOR = 524288;
	const SUPER_MODERATOR = 1048576;
	const TRANSLATOR = 2097152;
	// const XYZ = 4194304;
	// const XYZ = 8388608;
	// const XYZ = 16777216;
	// const XYZ = 33554432;
	// const XYZ = 67108864;
	// const XYZ = 134217728;
	// const XYZ = 268435456;
	// const XYZ = 536870912;

	/**
	 * Returns an array mapping the numerical role values to their descriptive names
	 *
	 * @return array
	 */
	public static function getMap() {
		$reflectionClass = new \ReflectionClass(static::class);

		return \array_flip($reflectionClass->getConstants());
	}

	/**
	 * Returns the descriptive role names
	 *
	 * @return string[]
	 */
	public static function getNames() {
		$reflectionClass = new \ReflectionClass(static::class);

		return \array_keys($reflectionClass->getConstants());
	}

	/**
	 * Returns the numerical role values
	 *
	 * @return int[]
	 */
	public static function getValues() {
		$reflectionClass = new \ReflectionClass(static::class);

		return \array_values($reflectionClass->getConstants());
	}

	private function __construct() {}

}
