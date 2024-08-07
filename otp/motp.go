package otp

import (
	"encoding/hex"
	"strconv"
	"time"
)

type MOTP struct {
	code   string
	digits int
}

// Code returns the raw code used for calculating the OTP.
func (motp MOTP) Code() any {
	return motp.code
}

// Digits returns the character/digit length of the OTP.
func (motp MOTP) Digits() int {
	return motp.digits
}

// String returns the calculated OTP
// used to authenticate with a service.
func (motp MOTP) String() string {
	return motp.code[0:motp.digits]
}

// Generates an MOTP for the current time
func GenerateMOTP(secret []byte, algo string, digits int, period int64, pin string) (MOTP, error) {
	return GenerateMOTPAt(secret, algo, digits, period, pin, time.Now().Unix())
}

// Generates an MOTP at the specified time in seconds
func GenerateMOTPAt(secret []byte, algo string, digits int, period int64, pin string, sec int64) (MOTP, error) {
	var timeCounter int64 = sec / period
	var secretStr string = hex.EncodeToString(secret)
	var toDigest string = strconv.FormatInt(timeCounter, 10) + secretStr + pin

	digest, err := getDigest(algo, []byte(toDigest))
	if err != nil {
		return MOTP{}, err
	}

	var code string = hex.EncodeToString(digest)

	return MOTP{code: code, digits: digits}, nil
}
