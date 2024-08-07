package otp

import (
	"fmt"
	"math"
	"time"
)

type TOTP struct {
	code   int64
	digits int
}

// Code returns the raw code used for calculating the OTP.
func (totp TOTP) Code() any {
	return totp.code
}

// Digits returns the character/digit length of the OTP.
func (totp TOTP) Digits() int {
	return totp.digits
}

// String returns the calculated OTP
// used to authenticate with a service.
func (totp TOTP) String() string {
	var code int = int(totp.code % int64(math.Pow10(totp.digits)))

	// Create a dynamic format to pad with zeroes up to the digit length. ex. %05d
	var codeFormat string = fmt.Sprintf("%%0%dd", totp.digits)

	return fmt.Sprintf(codeFormat, code)
}

// Generates a TOTP for the current time
func GenerateTOTP(secret []byte, algo string, digits int, period int64) (TOTP, error) {
	return GenerateTOTPAt(secret, algo, digits, period, time.Now().Unix())
}

// Generates a TOTP at the specified time in seconds
func GenerateTOTPAt(secret []byte, algo string, digits int, period int64, seconds int64) (TOTP, error) {
	var counter int64 = int64(math.Floor(float64(seconds) / float64(period)))

	secretHash, err := getHash(secret, algo, counter)
	if err != nil {
		return TOTP{}, err
	}

	// Truncate the hash to get the [H/T]OTP value
	//
	// https://tools.ietf.org/html/rfc4226#section-5.4
	// https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/java/com/beemdevelopment/aegis/crypto/otp/HOTP.java#L20
	offset := secretHash[len(secretHash)-1] & 0xf
	otp := int64(((int(secretHash[offset]) & 0x7f) << 24) |
		((int(secretHash[offset+1] & 0xff)) << 16) |
		((int(secretHash[offset+2] & 0xff)) << 8) |
		(int(secretHash[offset+3]) & 0xff))

	return TOTP{code: otp, digits: digits}, nil
}
