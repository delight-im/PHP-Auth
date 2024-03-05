<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

/** Exception that is thrown when a one-time password (OTP) provided by the user is not valid */
class InvalidOneTimePasswordException extends AuthException {}
