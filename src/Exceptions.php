<?php

/**
 * Copyright 2015 delight.im <info@delight.im>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Delight\Auth;

class AuthException extends \Exception {}

class InvalidEmailException extends AuthException {}

class InvalidPasswordException extends AuthException {}

class EmailNotVerifiedException extends AuthException {}

class UserAlreadyExistsException extends AuthException {}

class NotLoggedInException extends AuthException {}

class InvalidSelectorTokenPairException extends AuthException {}

class TokenExpiredException extends AuthException {}

class TooManyRequestsException extends AuthException {}

class AuthError extends \Exception {}

class DatabaseError extends AuthError {}

class MissingCallbackError extends AuthError {}

class HeadersAlreadySentError extends AuthError {}
