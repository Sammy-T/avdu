package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/sammy-t/avdu"
	"github.com/sammy-t/avdu/vault"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "avdu",
		Usage: "Read an Aegis vault backup or export file.",
		Flags: []cli.Flag{
			&cli.PathFlag{
				Name:    "path",
				Aliases: []string{"p"},
				Value:   ".",
				Usage:   "the path to the vault file or directory",
			},
		},
		Action: rootAction,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func rootAction(ctx *cli.Context) error {
	var path string = ctx.Path("path")

	isFilePath, err := regexp.MatchString(`.json`, path)
	if err != nil {
		return err
	}

	var vaultPath string

	if isFilePath {
		vaultPath = path
	} else {
		vaultPath, err = findVaultPath(path)
	}

	if err != nil {
		return err
	}

	vaultData, err := vault.ReadVaultFile(vaultPath)
	if err != nil {
		return fmt.Errorf(`cannot read vault "%v"`, vaultPath)
	}

	fmt.Printf("Read file %v\n", vaultPath)

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

// findVaultPath is a helper that returns the most recently modified
// vault's filepath.
func findVaultPath(workingDir string) (string, error) {
	var vaultPath string

	files, err := os.ReadDir(workingDir)
	if err != nil || len(files) == 0 {
		return vaultPath, err
	}

	vaultFile, err := vault.LastModified(files)
	if err != nil {
		return vaultPath, err
	}

	if vaultFile == nil {
		return vaultPath, errors.New("no vault backup or export file found")
	}

	vaultPath = fmt.Sprintf("%v/%v", workingDir, vaultFile.Name())

	return vaultPath, nil
}
