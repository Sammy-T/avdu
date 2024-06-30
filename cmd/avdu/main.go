package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	readFile()
}

func readFile() {
	data, err := os.ReadFile("./test/data/aegis_plain.json")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(data))
}
