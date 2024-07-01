package avdu

import (
	"encoding/base32"
	"errors"

	"github.com/sammy-t/avdu/otp"
	"github.com/sammy-t/avdu/vault"
)

// GetOTP generates an OTP from the provided entry data.
func GetOTP(entry vault.Entry) (otp.OTP, error) {
	if entry.Type != "totp" {
		return nil, errors.New("unsupported otp type")
	}

	secretData, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(entry.Info.Secret)
	if err != nil {
		return nil, err
	}

	totp, err := otp.GenerateTOTP(secretData, entry.Info.Algo, entry.Info.Digits, int64(entry.Info.Period))
	if err != nil {
		return nil, err
	}

	return totp, nil
}

// GetOTPs generates OTPs for the entries in the vault
// and returns a map matching each entry's uuid and OTP.
func GetOTPs(vaultData *vault.Vault) (map[string]otp.OTP, error) {
	var entries []vault.Entry = vaultData.Db.Entries

	var otps map[string]otp.OTP = make(map[string]otp.OTP)

	var err error

	for _, entry := range entries {
		if entry.Type != "totp" {
			continue
		}

		totp, err := GetOTP(entry)
		if err != nil {
			break
		}

		otps[entry.Uuid] = totp
	}

	return otps, err
}
