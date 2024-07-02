package vault

import (
	"encoding/json"
	"io/fs"
	"os"
	"regexp"
)

// ReadVaultFile parses the json file at the path
// and returns a vault.
func ReadVaultFile(filePath string) (*Vault, error) {
	var vault Vault

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &vault)

	return &vault, err
}

// ReadVaultFileEnc parses the json file at the path
// and returns an encrypted vault.
func ReadVaultFileEnc(filePath string) (*VaultEncrypted, error) {
	var vault VaultEncrypted

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &vault)

	return &vault, err
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
