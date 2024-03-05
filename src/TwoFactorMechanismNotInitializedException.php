<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

/** Exception that is thrown when a given mechanism for two-factor authentification has not been initialized yet or the prior initialization is not valid anymore */
class TwoFactorMechanismNotInitializedException extends AuthException {}
