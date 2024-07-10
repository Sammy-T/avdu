package otp_test

import (
	"encoding/base32"
	"testing"

	"github.com/sammy-t/avdu/otp"
)

type vectorYAOTP struct {
	time   int64
	pin    string
	secret string
	otp    string
}

var vectorsYAOTP []vectorYAOTP = []vectorYAOTP{
	{time: 1641559648, pin: "5239", secret: "6SB2IKNM6OBZPAVBVTOHDKS4FAAAAAAADFUTQMBTRY", otp: "umozdicq"},
	{time: 1581064020, pin: "7586", secret: "LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI", otp: "oactmacq"},
	{time: 1581090810, pin: "7586", secret: "LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI", otp: "wemdwrix"},
	{time: 1581091469, pin: "5210481216086702", secret: "JBGSAU4G7IEZG6OY4UAXX62JU4AAAAAAHTSG4HXU3M", otp: "dfrpywob"},
	{time: 1581093059, pin: "5210481216086702", secret: "JBGSAU4G7IEZG6OY4UAXX62JU4AAAAAAHTSG4HXU3M", otp: "vunyprpd"},
}

func TestYAOTP(t *testing.T) {
	var errored bool

	for i, vector := range vectorsYAOTP {
		s, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(vector.secret)
		if err != nil {
			t.Fatal(err)
		}

		yaotp, err := otp.GenerateYAOTPAt(s, "SHA256", 8, 30, vector.pin, vector.time)

		if err != nil || yaotp.String() != vector.otp {
			errored = true
			t.Logf("[%v] GenerateYAOTPAt() = %v, %v; want match for %v, nil", i, yaotp, err, vector.otp)

			// t.Fatalf(`[%v] GenerateYAOTPAt() = %v, %v, want match for %v, nil`, i, yaotp, err, vector.otp)
		}
	}

	if errored {
		t.Fatal("...yep")
	}
}
