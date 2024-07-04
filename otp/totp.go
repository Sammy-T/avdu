package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"time"
)

type TOTP struct {
	code   int64
	digits int
}

func (totp TOTP) GetCode() any {
	return totp.code
}

func (totp TOTP) GetDigits() int {
	return totp.digits
}

func (totp TOTP) String() string {
	var codeInt int = int(totp.code % int64(math.Pow10(totp.digits)))

	// Create a dynamic format to pad with zeroes up to the digit length. ex. %05d
	var codeFormat string = fmt.Sprintf("%%0%dd", totp.digits)

	return fmt.Sprintf(codeFormat, codeInt)
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

// getHash hashes the counter using the secret and specified algo
// then returns the hash.
func getHash(secret []byte, algo string, counter int64) ([]byte, error) {
	var counterBytes []byte = make([]byte, 8)

	// Encode counter in big endian
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))

	var mac hash.Hash

	// Use the specified algorithm
	switch algo {
	case "SHA1":
		mac = hmac.New(sha1.New, secret)
	case "SHA256":
		mac = hmac.New(sha256.New, secret)
	case "SHA512":
		mac = hmac.New(sha512.New, secret)
	default:
		return nil, errors.New("unsupported algo")
	}

	// Calculate the hash of the counter
	_, err := mac.Write(counterBytes)
	if err != nil {
		return nil, err
	}

	// Returned the hashed result
	return mac.Sum(nil), nil
}
