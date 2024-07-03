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
const defPeriod int64 = 30 // The default TOTP refresh interval
const refreshLimit int = 50

var refreshed int

func main() {
	app := &cli.App{
		Name:    "avdu",
		Usage:   "Read an Aegis vault backup or export file.",
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
				Usage:   "automatically refreshes the OTP display",
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
		vaultData, err = vault.ReadVaultFile(vaultPath)
	} else {
		vaultData, err = vault.ReadAndDecryptVaultFile(vaultPath, pwd)
	}

	if err != nil {
		return fmt.Errorf(`cannot read vault "%v"`, vaultPath)
	}

	fmt.Printf("%v Read file: %v\n", time.Now().Format(timeFmt), vaultPath)

	displayOTPs(vaultData)

	var ch chan int = make(chan int)

	for ctx.Bool("refresh") && refreshed < refreshLimit {
		go displayCountdown(ch)
		<-ch // Block progression by waiting to receive data on the channel

		log.Println("Refreshed OTPs")
		displayOTPs(vaultData)
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
	var p int64 = defPeriod * 1000

	// Calculate the time til next refresh
	var ttn int64 = p - (time.Now().UnixMilli() % p)

	for ttn > 1000 {
		fmt.Printf("\rRefreshes in %vs ", float32(ttn)/1000)

		ttn = p - (time.Now().UnixMilli() % p)

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

	vaultFile, err := vault.LastModified(files)
	if err != nil {
		return vaultPath, err
	}

	if vaultFile == nil {
		return vaultPath, errors.New("no vault backup or export file found")
	}

	vaultPath = fmt.Sprintf("%v/%v", vaultDir, vaultFile.Name())

	return vaultPath, nil
}
