package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/sammy-t/avdu"
	"github.com/sammy-t/avdu/vault"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:   "avdu",
		Usage:  "Read an Aegis vault backup or export file.",
		Action: rootAction,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func rootAction(ctx *cli.Context) error {
	// const workingDir string = "."
	const workingDir string = "./test/data/exports" //// TODO: TEMP
	files, err := os.ReadDir(workingDir)
	if err != nil || len(files) == 0 {
		return err
	}

	vaultFile, err := vault.LastModified(files)
	if err != nil {
		return err
	}

	if vaultFile == nil {
		return errors.New("no vault backup or export file found")
	}

	var vaultPath string = fmt.Sprintf("%v/%v", workingDir, vaultFile.Name())

	vaultData, err := vault.ReadVaultFile(vaultPath)
	if err != nil {
		return fmt.Errorf(`cannot read vault "%v"`, vaultFile.Name())
	}

	fmt.Printf("Read file %v\n", vaultFile.Name())

	otps, err := avdu.GetOTPs(vaultData)
	if err != nil {
		log.Println(err)
	}

	var builder strings.Builder

	builder.WriteString("\n- OTPs -\n")

	for _, entry := range vaultData.Db.Entries {
		fmt.Fprintf(&builder, "\n%v (%v)\n%v\n", entry.Issuer, entry.Name, otps[entry.Uuid])
	}

	fmt.Println(builder.String())

	return nil
}
