package otp

type OTP interface {
	GetCode() any
	GetDigits() int
	String() string
}
