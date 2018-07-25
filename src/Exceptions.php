<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

class AuthException extends \Exception {}

class UnknownIdException extends AuthException {}

class InvalidEmailException extends AuthException {}

class UnknownUsernameException extends AuthException {}

class InvalidPasswordException extends AuthException {}

class EmailNotVerifiedException extends AuthException {}

class UserAlreadyExistsException extends AuthException {}

class NotLoggedInException extends AuthException {}

class InvalidSelectorTokenPairException extends AuthException {}

class TokenExpiredException extends AuthException {}

class TooManyRequestsException extends AuthException {}

class DuplicateUsernameException extends AuthException {}

class AmbiguousUsernameException extends AuthException {}

class AttemptCancelledException extends AuthException {}

class ResetDisabledException extends AuthException {}

class ConfirmationRequestNotFound extends AuthException {}

class AuthError extends \Exception {}

class DatabaseError extends AuthError {}

class MissingCallbackError extends AuthError {}

class HeadersAlreadySentError extends AuthError {}

class EmailOrUsernameRequiredError extends AuthError {}
