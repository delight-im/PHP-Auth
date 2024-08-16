<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

/** Exception that is thrown when a first factor has been successfully provided for authentification but a second one is still required */
class SecondFactorRequiredException extends AuthException {

	protected $totp;
	protected $smsRecipient;
	protected $smsOtpValue;
	protected $emailRecipient;
	protected $emailOtpValue;

	public function hasTotpOption() {
		return !empty($this->totp);
	}

	public function hasSmsOption() {
		return !empty($this->smsRecipient) && !empty($this->smsOtpValue);
	}

	public function getSmsRecipient() {
		return $this->smsRecipient;
	}

	public function getSmsOtpValue() {
		return $this->smsOtpValue;
	}

	public function hasEmailOption() {
		return !empty($this->emailRecipient) && !empty($this->emailOtpValue);
	}

	public function getEmailRecipient() {
		return $this->emailRecipient;
	}

	public function getEmailOtpValue() {
		return $this->emailOtpValue;
	}

	public function addTotpOption() {
		$this->totp = true;
	}

	public function addSmsOption($otpValue, $recipient) {
		$this->smsOtpValue = !empty($otpValue) ? (string) $otpValue : null;
		$this->smsRecipient = !empty($recipient) ? (string) $recipient : null;
	}

	public function addEmailOption($otpValue, $recipient) {
		$this->emailOtpValue = !empty($otpValue) ? (string) $otpValue : null;
		$this->emailRecipient = !empty($recipient) ? (string) $recipient : null;
	}

}
