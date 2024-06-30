package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/scrypt"
)

// FindMasterKey uses the password to decrypt the master key
// from the vault and returns the master key's bytes.
func (vaultData *VaultEncrypted) FindMasterKey(pwd string) ([]byte, error) {
	var key []byte
	var masterKey []byte

	for _, slot := range vaultData.Header.Slots {
		// Ignore slots that aren't using the password type
		if slot.Type != 1 {
			continue
		}

		salt, err := hex.DecodeString(slot.Salt)
		if err != nil {
			return nil, err
		}

		// Create a key using the slot values and provided password
		key, err = scrypt.Key([]byte(pwd), salt, slot.N, slot.R, slot.P, 32)
		if err != nil {
			return nil, err
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		nonce, err := hex.DecodeString(slot.KeyParams.Nonce)
		if err != nil {
			return nil, err
		}

		tag, err := hex.DecodeString(slot.KeyParams.Tag)
		if err != nil {
			return nil, err
		}

		slotKey, err := hex.DecodeString(slot.Key)
		if err != nil {
			return nil, err
		}

		var keyData []byte = append(slotKey, tag...)

		// Attempt to decrypt the master key
		masterKey, err = aesgcm.Open(nil, nonce, keyData, nil)
		if err == nil {
			break
		}
	}

	if len(masterKey) == 0 {
		return nil, errors.New("no master key found")
	}

	return masterKey, nil
}

// DecryptContents uses the master key to decrypt the vault's contents
// and returns the content's bytes.
func (vaultData *VaultEncrypted) DecryptContents(masterKey []byte) ([]byte, error) {
	var db string = vaultData.Db
	var params Params = vaultData.Header.Params

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := hex.DecodeString(params.Nonce)
	if err != nil {
		return nil, err
	}

	tag, err := hex.DecodeString(params.Tag)
	if err != nil {
		return nil, err
	}

	dbData, err := base64.StdEncoding.DecodeString(db)
	if err != nil {
		return nil, err
	}

	var database []byte = append(dbData, tag...)

	// Attempt to decrypt the vault content
	content, err := aesgcm.Open(nil, nonce, database, nil)
	if err != nil {
		return nil, err
	}

	return content, nil
}

// DecryptVault decrypts the vault's contents
// and returns a plaintext version of the vault.
func (vaultData *VaultEncrypted) DecryptVault(masterKey []byte) (*Vault, error) {
	content, err := vaultData.DecryptContents(masterKey)
	if err != nil {
		return nil, err
	}

	var db Db

	err = json.Unmarshal(content, &db)
	if err != nil {
		return nil, err
	}

	var vaultDataPlain Vault = Vault{
		Version: vaultData.Version,
		Header:  vaultData.Header,
		Db:      db,
	}

	return &vaultDataPlain, nil
}
