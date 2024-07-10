package otp

import (
	"encoding/binary"
	"math"
	"time"
)

const enAlphaLen int64 = 26

type YAOTP struct {
	code   int64
	digits int
}

func (yaotp YAOTP) GetCode() any {
	return yaotp.code
}

func (yaotp YAOTP) GetDigits() int {
	return yaotp.digits
}

func (yaotp YAOTP) String() string {
	var code int64 = yaotp.code % int64(math.Pow(float64(enAlphaLen), float64(yaotp.digits)))

	var chars []rune = make([]rune, yaotp.digits)

	for i := yaotp.digits - 1; i >= 0; i-- {
		chars[i] = rune('a' + (code % enAlphaLen))
		code /= enAlphaLen
	}

	return string(chars)
}

func GenerateYAOTP(secret []byte, algo string, digits int, period int64, pin string) (YAOTP, error) {
	return GenerateYAOTPAt(secret, algo, digits, period, pin, time.Now().Unix())
}

// NEEDS FIXING?!
//
// It looks the same as Aegis' implementation as far as I can tell
// but it doesn't pass tests.
//
// see: https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/java/com/beemdevelopment/aegis/crypto/otp/YAOTP.java
func GenerateYAOTPAt(secret []byte, algo string, digits int, period int64, pin string, sec int64) (YAOTP, error) {
	var pinWithHash []byte = append([]byte(pin), secret...)

	keyHash, err := getDigest("SHA256", pinWithHash)
	if err != nil {
		return YAOTP{}, err
	}

	if keyHash[0] == 0 {
		keyHash = keyHash[1:]
	}

	var counter int64 = int64(math.Floor(float64(sec) / float64(period)))

	periodHash, err := getHash(keyHash, algo, counter)
	if err != nil {
		return YAOTP{}, err
	}

	offset := periodHash[len(periodHash)-1] & 0xf
	periodHash[offset] &= 0x7f

	var code int64 = int64(binary.BigEndian.Uint64(periodHash[offset : offset+8]))

	return YAOTP{code: code, digits: digits}, nil
}
