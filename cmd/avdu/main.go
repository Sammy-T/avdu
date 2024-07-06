package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sammy-t/avdu"
	"github.com/sammy-t/avdu/vault"
	"github.com/urfave/cli/v2"
)

const timeFmt string = "2006/01/02 15:04:05"
const refreshLimit int = 10

var refreshes int

func main() {
	app := &cli.App{
		Name:    "avdu",
		Usage:   "Generate one-time passwords from an Aegis vault backup or export file.",
		Version: "0.1.0",
		Flags: []cli.Flag{
			&cli.PathFlag{
				Name:    "path",
				Aliases: []string{"p"},
				Usage:   "specify the path to the vault file or directory",
				Value:   ".",
			},
			&cli.StringFlag{
				Name:    "pass",
				Aliases: []string{"pwd", "k"},
				Usage:   "specify the password used to decrypt the vault",
			},
			&cli.BoolFlag{
				Name:    "refresh",
				Aliases: []string{"r"},
				Usage:   "automatically refreshes the OTP display [experimental]",
			},
		},
		Action: cliAction,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func cliAction(ctx *cli.Context) error {
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

	var pwd string = ctx.String("pass")

	var vaultData *vault.Vault

	if pwd == "" {
		vaultData, err = avdu.ReadVaultFile(vaultPath)
	} else {
		vaultData, err = avdu.ReadAndDecryptVaultFile(vaultPath, pwd)
	}

	if err != nil {
		return fmt.Errorf("cannot read vault %q: %w", vaultPath, err)
	}

	fmt.Printf("%v Read file: %v\n", time.Now().Format(timeFmt), vaultPath)

	displayOTPs(vaultData)

	var refresh bool = ctx.Bool("refresh")

	if !refresh {
		fmt.Printf("OTPs valid for %vs\n", float32(avdu.GetTTN())/1000)
	}

	var ch chan int = make(chan int)

	for refresh && refreshes < refreshLimit {
		go displayCountdown(ch)
		<-ch // Block progression by waiting to receive data on the channel

		log.Println("Refreshed OTPs")
		displayOTPs(vaultData)

		refreshes++
	}

	return nil
}

// displayOTPs is a helper to output the OTP data.
func displayOTPs(vaultData *vault.Vault) {
	otps, err := avdu.GetOTPs(vaultData)
	if err != nil {
		log.Println(err)
	}

	var builder strings.Builder

	builder.WriteString("\n- OTPs -\n")

	for _, entry := range vaultData.Db.Entries {
		fmt.Fprintf(&builder, "\n%v (%v)\n%v\n", entry.Issuer, entry.Name, otps[entry.Uuid])
	}

	fmt.Printf("%v %v\n", time.Now().Format(timeFmt), builder.String())
}

// displayCountdown is a helper that outputs a countdown to the same line
// then transmits data to the channel when the coundown finishes.
func displayCountdown(ch chan int) {
	var ttn int64 = avdu.GetTTN()

	for ttn > 1000 {
		ttn = avdu.GetTTN()

		fmt.Printf("\rRefreshes in %vs ", float32(ttn)/1000)

		time.Sleep(1 * time.Second)
	}

	fmt.Println() // Ensure there's a fresh line for additional output

	ch <- 0 // Return arbitrary data to free up the channel
}

// findVaultPath is a helper that returns the most recently modified
// vault's filepath.
func findVaultPath(vaultDir string) (string, error) {
	var vaultPath string

	files, err := os.ReadDir(vaultDir)
	if err != nil || len(files) == 0 {
		return vaultPath, err
	}

	vaultFile, err := avdu.LastModified(files)
	if err != nil {
		return vaultPath, err
	}

	if vaultFile == nil {
		return vaultPath, errors.New("no vault backup or export file found")
	}

	vaultPath = fmt.Sprintf("%v/%v", vaultDir, vaultFile.Name())

	return vaultPath, nil
}
