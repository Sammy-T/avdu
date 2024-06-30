package main

import (
	"log"

	"github.com/sammy-t/avdu/vault"
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

	masterKey, err := vaultDataEnc.FindMasterKey("test")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Found master key: %v", masterKey)

	content, err := vaultDataEnc.DecryptContents(masterKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Decrypted content:\n\n%v", string(content))

	vaultDataPlain, err := vaultDataEnc.DecryptVault(masterKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Decrypted vault:\n\n%v", vaultDataPlain)
}
