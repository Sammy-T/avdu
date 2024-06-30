package main

import (
	"crypto/aes"
	"crypto/cipher"
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
			log.Fatal(err)
		}

		// Create a key using the slot values and provided password
		key, err = scrypt.Key([]byte(pwd), salt, slot.N, slot.R, slot.P, 32)
		if err != nil {
			log.Fatal(err)
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			log.Fatal(err)
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			log.Fatal(err)
		}

		nonce, err := hex.DecodeString(slot.KeyParams.Nonce)
		if err != nil {
			log.Fatal(err)
		}

		tag, err := hex.DecodeString(slot.KeyParams.Tag)
		if err != nil {
			log.Fatal(err)
		}

		slotKey, err := hex.DecodeString(slot.Key)
		if err != nil {
			log.Fatal(err)
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
