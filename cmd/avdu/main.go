package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/sammy-t/avdu"
	"github.com/sammy-t/avdu/vault"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

const timeFmt string = "2006/01/02 15:04:05"
const refreshLimit int = 10

var refreshes int

func main() {
	app := &cli.App{
		Name:    "avdu",
		Usage:   "Generate one-time passwords from an Aegis Authenticator vault backup or export file.",
		Version: "0.4.5",
		Flags: []cli.Flag{
			&cli.PathFlag{
				Name:    "path",
				Aliases: []string{"p"},
				Usage:   "specify the path to the vault file or directory",
				Value:   ".",
			},
			&cli.BoolFlag{
				Name:    "encrypted",
				Aliases: []string{"enc", "e"},
				Usage:   "enables password input for decrypting the vault",
			},
			&cli.BoolFlag{
				Name:    "refresh",
				Aliases: []string{"r"},
				Usage:   "automatically refreshes the OTP display [experimental]",
			},
		},
		Action: cliAction,
		Commands: []*cli.Command{
			{
				Name:  "decrypt",
				Usage: "Decrypt an encrypted vault file to plaintext format",
				Flags: []cli.Flag{
					&cli.PathFlag{
						Name:     "path",
						Aliases:  []string{"p"},
						Usage:    "path to the encrypted vault file",
						Required: true,
					},
					&cli.PathFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "output path for decrypted vault (defaults to stdout)",
					},
				},
				Action: decryptAction,
			},
		},
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

	var encrypted bool = ctx.Bool("encrypted")
	var pwd string

	if encrypted {
		fmt.Print("Enter password: ")

		pwdBytes, err := term.ReadPassword(int(syscall.Stdin))
		pwd = string(pwdBytes)

		fmt.Println() // Ensure there's a newline for the next output

		if err != nil {
			return fmt.Errorf("cannot read password input %q: %w", pwd, err)
		}
	}

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

	builder.WriteString("- OTPs -\n")

	for _, entry := range vaultData.Db.Entries {
		fmt.Fprintf(&builder, "%v (%v): %v\n", entry.Issuer, entry.Name, otps[entry.Uuid])
	}

	fmt.Printf("%v\n%v\n", time.Now().Format(timeFmt), builder.String())
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

func decryptAction(ctx *cli.Context) error {
	path := ctx.Path("path")
	outputPath := ctx.Path("output")

	fmt.Fprint(os.Stderr, "Enter password: ")

	pwdBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("cannot read password input: %w", err)
	}
	pwd := string(pwdBytes)

	fmt.Fprintln(os.Stderr) // Newline after password input

	vaultData, err := avdu.ReadAndDecryptVaultFile(path, pwd)
	if err != nil {
		return fmt.Errorf("cannot decrypt vault %q: %w", path, err)
	}

	// Marshal with indentation to match Aegis export format
	output, err := json.MarshalIndent(vaultData, "", "    ")
	if err != nil {
		return fmt.Errorf("cannot marshal vault: %w", err)
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, output, 0600); err != nil {
			return fmt.Errorf("cannot write to %q: %w", outputPath, err)
		}
		fmt.Fprintf(os.Stderr, "Decrypted vault written to %s\n", outputPath)
	} else {
		fmt.Println(string(output))
	}

	return nil
}
