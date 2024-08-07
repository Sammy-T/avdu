// Package otp provides functionality for generating and reading
// One-Time Passwords.
package otp

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
)

type OTP interface {
	Code() any
	Digits() int
	String() string
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
	case "MD5":
		mac = hmac.New(md5.New, secret)
	default:
		return nil, fmt.Errorf("unsupported algo %q", algo)
	}

	// Calculate the hash of the counter
	_, err := mac.Write(counterBytes)
	if err != nil {
		return nil, err
	}

	// Returned the hashed result
	return mac.Sum(nil), nil
}

// getDigest hashes the data using the specified algo
// then returns hash.
func getDigest(algo string, toDigest []byte) ([]byte, error) {
	var md hash.Hash

	// Use the specified algorithm
	switch algo {
	case "SHA1":
		md = sha1.New()
	case "SHA256":
		md = sha256.New()
	case "SHA512":
		md = sha512.New()
	case "MD5":
		md = md5.New()
	default:
		return nil, fmt.Errorf("unsupported algo %q", algo)
	}

	// Calculate the hash
	_, err := md.Write(toDigest)
	if err != nil {
		return nil, err
	}

	return md.Sum(nil), nil
}
