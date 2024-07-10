package main

import (
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
		vaultPath, err = avdu.FindVaultPath(path)
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
	} else {
		var ch chan int = make(chan int)

		go countdownOTPs(vaultData, ch)

		// Block progression by waiting to receive data on the channel.
		// (This isn't necessary if I remove the goroutine but I'll keep it.)
		<-ch
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

// countdownOTPs outputs a countdown and displays the current OTPs
// after each countdown reset.
func countdownOTPs(vaultData *vault.Vault, ch chan int) {
	displayOTPs(vaultData)

	for refreshes < refreshLimit {
		ttn := avdu.GetTTN()

		if ttn > 29000 {
			fmt.Println() // Ensure there's a fresh line

			displayOTPs(vaultData)

			refreshes++
		}

		// Use `\r` to display the countdown on the same line
		fmt.Printf("\rRefreshes in %vs ", float32(ttn)/1000)

		time.Sleep(1 * time.Second)
	}

	ch <- 0 // Return arbitrary data to free up the channel
}
