<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

use Delight\Db\PdoDatabase;

require_once __DIR__ . '/Exceptions.php';

/** Component that can be used for administrative tasks by privileged and authorized users */
final class Administration extends UserManager {

	/**
	 * @param PdoDatabase $databaseConnection the database connection to operate on
	 */
	public function __construct(PdoDatabase $databaseConnection) {
		parent::__construct($databaseConnection);
	}

	protected function throttle($actionType, $customSelector = null) {}

}
