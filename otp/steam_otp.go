package otp

import (
	"strings"
	"time"
)

const steamAlpha string = "23456789BCDFGHJKMNPQRTVWXY"

type SteamOTP struct {
	code   int64
	digits int
}

func (sotp SteamOTP) GetCode() any {
	return sotp.code
}

func (sotp SteamOTP) GetDigits() int {
	return sotp.digits
}

func (sotp SteamOTP) String() string {
	var steamAlphabet []rune = []rune(steamAlpha)
	var alphabetLen int = len(steamAlphabet)

	var code int = int(sotp.code)

	var builder strings.Builder

	for i := 0; i < sotp.digits; i++ {
		var char rune = steamAlphabet[code%alphabetLen]

		builder.WriteRune(char)

		code /= alphabetLen
	}

	return builder.String()
}

// Generates a Steam OTP for the current time
func GenerateSteamOTP(secret []byte, algo string, digits int, period int64) (SteamOTP, error) {
	return GenerateSteamOTPAt(secret, algo, digits, period, time.Now().Unix())
}

// Generates a Steam OTP at the specified time in seconds
func GenerateSteamOTPAt(secret []byte, algo string, digits int, period int64, seconds int64) (SteamOTP, error) {
	totp, err := GenerateTOTPAt(secret, algo, digits, period, seconds)
	if err != nil {
		return SteamOTP{}, err
	}

	return SteamOTP(totp), nil
}
