package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/sammy-t/avdu/internal/vault"
)

func main() {
	readVault("./test/data/aegis_plain.json")
	readVaultEncrypted("./test/data/aegis_encrypted.json")
}

func readVault(filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(data))

	var vault vault.Vault

	err = json.Unmarshal(data, &vault)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(vault)
}

func readVaultEncrypted(filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(data))

	var vault vault.VaultEncrypted

	err = json.Unmarshal(data, &vault)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(vault)
}
