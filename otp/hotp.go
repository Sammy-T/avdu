package otp

// HOTP is not implemented due to syncing concerns.
//
// This is a placeholder that doesn't contain real data.
type HOTP struct {
	code   int64
	digits int
}

func (hotp HOTP) GetCode() any {
	return hotp.code
}

func (hotp HOTP) GetDigits() int {
	return hotp.digits
}

func (hotp HOTP) String() string {
	return "<!HOTP>"
}
