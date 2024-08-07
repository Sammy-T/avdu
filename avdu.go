// Package avdu provides functionality for reading Aegis Authenticator
// vault files and outputting One-Time Passwords.
package avdu

import (
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"time"

	"github.com/sammy-t/avdu/otp"
	"github.com/sammy-t/avdu/vault"
)

const defPeriod int64 = 30 // The default TOTP refresh interval

// FindVaultPath returns the most recently modified
// vault's filepath.
func FindVaultPath(vaultDir string) (string, error) {
	var vaultPath string

	files, err := os.ReadDir(vaultDir)
	if err != nil || len(files) == 0 {
		return vaultPath, err
	}

	vaultFile, err := LastModified(files)
	if err != nil {
		return vaultPath, err
	}

	if vaultFile == nil {
		return vaultPath, errors.New("no vault backup or export file found")
	}

	vaultPath = fmt.Sprintf("%v/%v", vaultDir, vaultFile.Name())

	return vaultPath, nil
}

// ReadVaultFile parses the json file at the path
// and returns a plaintext vault.
func ReadVaultFile(filePath string) (*vault.Vault, error) {
	var vault vault.Vault

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &vault)

	return &vault, err
}

// ReadVaultFileEnc parses the json file at the path
// and returns an encrypted vault.
func ReadVaultFileEnc(filePath string) (*vault.VaultEncrypted, error) {
	var vault vault.VaultEncrypted

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &vault)

	return &vault, err
}

// ReadAndDecryptVaultFile parses the json file at the path,
// decrypts the vault content, and returns a plaintext vault.
func ReadAndDecryptVaultFile(filePath string, pwd string) (*vault.Vault, error) {
	vaultDataEnc, err := ReadVaultFileEnc(filePath)
	if err != nil {
		return nil, err
	}

	masterKey, err := vaultDataEnc.FindMasterKey(pwd)
	if err != nil {
		return nil, err
	}

	vaultDataPlain, err := vaultDataEnc.DecryptVault(masterKey)
	if err != nil {
		return nil, err
	}

	return vaultDataPlain, nil
}

// LastModified finds the most recent vault file.
func LastModified(files []fs.DirEntry) (fs.DirEntry, error) {
	vaultFileRE := regexp.MustCompile(`^aegis-(backup|export)-\d+(-\d+)*\.json$`)

	var vaultFile fs.DirEntry
	var err error

	for _, file := range files {
		// Ignore directories and non-vault files
		if file.IsDir() || !vaultFileRE.MatchString(file.Name()) {
			continue
		}

		if vaultFile == nil {
			vaultFile = file
			continue
		}

		vaultFile, err = lastModTime(file, vaultFile)
		if err != nil {
			return nil, err
		}
	}

	return vaultFile, nil
}

// LastModTime is a helper to compare the last modified time.
func lastModTime(file1 fs.DirEntry, file2 fs.DirEntry) (fs.DirEntry, error) {
	info1, err := file1.Info()
	if err != nil {
		return nil, err
	}

	info2, err := file2.Info()
	if err != nil {
		return nil, err
	}

	if info2.ModTime().After(info1.ModTime()) {
		return file2, nil
	}

	return file1, nil
}

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
		secretData, err = hex.DecodeString(entry.Info.Secret)
		if err != nil {
			return nil, err
		}

		pass, err = otp.GenerateMOTP(secretData, entry.Info.Algo, entry.Info.Digits, int64(entry.Info.Period), entry.Info.Pin)
	default:
		err = fmt.Errorf("unsupported otp type %q", entry.Type)
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

// GetTTN calculates the time in millis until the next OTP refresh using the default period.
func GetTTN() int64 {
	return GetTTNPer(defPeriod)
}

// GetTTNPer calculates the time in millis until the next OTP refresh using the provided period.
func GetTTNPer(period int64) int64 {
	var p int64 = period * 1000

	return p - (time.Now().UnixMilli() % p)
}
