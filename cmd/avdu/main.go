package main

import (
	"log"

	"github.com/sammy-t/avdu/internal/vault"
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
}
