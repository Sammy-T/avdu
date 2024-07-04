package avdu

import (
	"encoding/base32"
	"fmt"

	"github.com/sammy-t/avdu/otp"
	"github.com/sammy-t/avdu/vault"
)

// GetOTP generates an OTP from the provided entry data.
func GetOTP(entry vault.Entry) (otp.OTP, error) {
	secretData, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(entry.Info.Secret)
	if err != nil {
		return nil, err
	}

	var pass otp.OTP

	switch entry.Type {
	case "totp":
		pass, err = otp.GenerateTOTP(secretData, entry.Info.Algo, entry.Info.Digits, int64(entry.Info.Period))
	case "hotp":
		pass = otp.HOTP{}
	case "steam":
		pass, err = otp.GenerateSteamOTP(secretData, entry.Info.Algo, entry.Info.Digits, int64(entry.Info.Period))
	case "motp":
		pass, err = otp.GenerateMOTP(secretData, entry.Info.Algo, entry.Info.Digits, int64(entry.Info.Period), entry.Info.Pin)
	default:
		err = fmt.Errorf(`unsupported otp type "%v"`, entry.Type)
	}

	return pass, err
}

// GetOTPs generates OTPs for the entries in the vault
// and returns a map matching each entry's uuid and OTP.
//
// If there's an error, the successfully generated OTPs will
// be returned along with the error.
func GetOTPs(vaultData *vault.Vault) (map[string]otp.OTP, error) {
	var entries []vault.Entry = vaultData.Db.Entries

	var otps map[string]otp.OTP = make(map[string]otp.OTP)
	var err error

	for _, entry := range entries {
		pass, passErr := GetOTP(entry)
		if passErr != nil {
			err = passErr
			continue
		}

		otps[entry.Uuid] = pass
	}

	return otps, err
}
