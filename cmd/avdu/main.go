package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/sammy-t/avdu/internal/vault"
)

func main() {
	readVault()
}

func readVault() {
	data, err := os.ReadFile("./test/data/aegis_plain.json")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(data))

	var vault vault.Vault

	err = json.Unmarshal(data, &vault)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(vault)
}
