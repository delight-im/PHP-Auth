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
	// const XXX = 4194304;
	// const XXX = 8388608;
	// const XXX = 16777216;
	// const XXX = 33554432;
	// const XXX = 67108864;
	// const XXX = 134217728;
	// const XXX = 268435456;
	// const XXX = 536870912;

	private function __construct() {}

}
