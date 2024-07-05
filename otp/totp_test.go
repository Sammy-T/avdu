package otp_test

import (
	"fmt"
	"testing"

	"github.com/sammy-t/avdu/otp"
)

type vectorTOTP struct {
	time int64
	algo string
	otp  string
}

var vectorsTOTP []vectorTOTP = []vectorTOTP{
	{time: 59, algo: "SHA1", otp: "94287082"},
	{time: 59, algo: "SHA256", otp: "46119246"},
	{time: 59, algo: "SHA512", otp: "90693936"},
	{time: 1111111109, algo: "SHA1", otp: "07081804"},
	{time: 1111111109, algo: "SHA256", otp: "68084774"},
	{time: 1111111109, algo: "SHA512", otp: "25091201"},
	{time: 1111111111, algo: "SHA1", otp: "14050471"},
	{time: 1111111111, algo: "SHA256", otp: "67062674"},
	{time: 1111111111, algo: "SHA512", otp: "99943326"},
	{time: 1234567890, algo: "SHA1", otp: "89005924"},
	{time: 1234567890, algo: "SHA256", otp: "91819424"},
	{time: 1234567890, algo: "SHA512", otp: "93441116"},
	{time: 2000000000, algo: "SHA1", otp: "69279037"},
	{time: 2000000000, algo: "SHA256", otp: "90698825"},
	{time: 2000000000, algo: "SHA512", otp: "38618901"},
	{time: 20000000000, algo: "SHA1", otp: "65353130"},
	{time: 20000000000, algo: "SHA256", otp: "77737706"},
	{time: 20000000000, algo: "SHA512", otp: "47863826"},
}

var seed []byte = []byte{
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
}

var seed32 []byte = []byte{
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
	0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
}

var seed64 []byte = []byte{
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
	0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
}

func TestTOTP(t *testing.T) {
	for i, vector := range vectorsTOTP {
		s := getSeed(t, vector.algo)

		totp, err := otp.GenerateTOTPAt(s, vector.algo, 8, 30, vector.time)

		if err != nil || totp.String() != vector.otp {
			t.Fatalf(`[%v] GenerateTOTPAt() = %v, %v, want match for %v, nil`, i, totp, err, vector.otp)
		}
	}
}

func getSeed(t *testing.T, algo string) []byte {
	var s []byte

	switch algo {
	case "SHA1":
		s = seed
	case "SHA256":
		s = seed32
	case "SHA512":
		s = seed64
	default:
		t.Fatal(fmt.Errorf(`unsupported algo "%v"`, algo))
	}

	return s
}
