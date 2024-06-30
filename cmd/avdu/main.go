package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"

	"github.com/sammy-t/avdu/vault"
	"golang.org/x/crypto/scrypt"
)

func main() {
	vaultData, err := vault.ReadVaultFile("./test/data/aegis_plain.json")
	if err != nil {
		log.Fatal(err)
	}

	vaultDataEnc, err := vault.ReadVaultFileEnc("./test/data/aegis_encrypted.json")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("\n%v\n\n", vaultData)
	log.Printf("\n%v\n\n", vaultDataEnc)

	masterKey, err := findMasterKey(vaultDataEnc.Header.Slots, "test")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Found master key: %v", masterKey)

	content, err := decryptContents(vaultDataEnc.Db, vaultDataEnc.Header.Params, masterKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Decrypted:\n\n%v", string(content))
}

func findMasterKey(slots []vault.Slot, pwd string) ([]byte, error) {
	var key []byte
	var masterKey []byte

	for _, slot := range slots {
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

func decryptContents(db string, params vault.Params, masterKey []byte) ([]byte, error) {
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
