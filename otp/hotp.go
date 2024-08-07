package otp

// HOTP is not implemented due to syncing concerns.
//
// This is a placeholder that doesn't contain real data.
type HOTP struct {
	code   int64
	digits int
}

// Code returns the raw code used for calculating the OTP.
func (hotp HOTP) Code() any {
	return hotp.code
}

// Digits returns the character/digit length of the OTP.
func (hotp HOTP) Digits() int {
	return hotp.digits
}

// String returns the calculated OTP
// used to authenticate with a service.
func (hotp HOTP) String() string {
	return "<!HOTP>"
}
