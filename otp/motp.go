package otp

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"time"
)

type MOTP struct {
	code   string
	digits int
}

func (motp MOTP) GetCode() any {
	return motp.code
}

func (motp MOTP) GetDigits() int {
	return motp.digits
}

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

	code, err := getDigest(algo, []byte(toDigest))
	if err != nil {
		return MOTP{}, err
	}

	return MOTP{code: code, digits: digits}, nil
}

// getDigest hashes the data using the specified algo
// then returns the hex encoded hash.
func getDigest(algo string, toDigest []byte) (string, error) {
	var md hash.Hash

	// Use the specified algorithm
	switch algo {
	case "MD5":
		md = md5.New()
	default:
		return "", fmt.Errorf(`unsupported algo "%v"`, algo)
	}

	// Calculate the hash
	_, err := md.Write(toDigest)
	if err != nil {
		return "", err
	}

	var digest []byte = md.Sum(nil) // Get the hashed result

	return hex.EncodeToString(digest), nil
}
