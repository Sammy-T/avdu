package otp_test

import (
	"encoding/hex"
	"testing"

	"github.com/sammy-t/avdu/otp"
)

type vectorMOTP struct {
	time   int64
	pin    string
	secret string
	otp    string
}

var vectorsMOTP []vectorMOTP = []vectorMOTP{
	{time: 165892298, pin: "1234", secret: "e3152afee62599c8", otp: "e7d8b6"},
	{time: 123456789, pin: "1234", secret: "e3152afee62599c8", otp: "4ebfb2"},
	{time: 165954002 * 10, pin: "9999", secret: "bbb1912bb5c515be", otp: "ced7b1"},
	{time: 165954002*10 + 2, pin: "9999", secret: "bbb1912bb5c515be", otp: "ced7b1"},
	{time: 165953987 * 10, pin: "9999", secret: "bbb1912bb5c515be", otp: "1a14f8"},
	{time: 165953987*10 + 8, pin: "9999", secret: "bbb1912bb5c515be", otp: "1a14f8"},
}

func TestMOTP(t *testing.T) {
	for i, vector := range vectorsMOTP {
		s, err := hex.DecodeString(vector.secret)
		if err != nil {
			t.Fatal(err)
		}

		motp, err := otp.GenerateMOTPAt(s, "MD5", 6, 10, vector.pin, vector.time)

		if err != nil || motp.String() != vector.otp {
			t.Fatalf("[%v] GenerateMOTPAt() = %v, %v; want match for %v, nil", i, motp, err, vector.otp)
		}
	}
}
