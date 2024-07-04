# avdu

Aegis Vault Desktop Utility is a Go module and basic command line interface for generating 
one-time passwords from an [Aegis](https://github.com/beemdevelopment/Aegis) vault backup or export file.

> [!NOTE]
> - HOTP is not implemented due to syncing concerns.
> - Steam OTP is implemented but untested.

## CLI

```bash
avdu -h
```

> [!CAUTION]
> Some terminals persist command history after the terminal window is closed.
>
> It's advisable to clear the command history when the CLI is used with the password flag.
>
> Command Prompt doesn't require clearing since it doesn't persist command history after closing.

## Development

### Run the CLI

```bash
# Run in the current directory
go run ./cmd/avdu

# Run using the plaintext test file
go run ./cmd/avdu -p test/data/aegis_plain.json

# Run using the encrypted test file
go run ./cmd/avdu -p test/data/aegis_encrypted.json -k test
```

### Build the CLI

```bash
go build -C ./cmd/avdu
```

The binary will output to the `cmd/avdu/` directory.

### Install the CLI

```bash
go install ./cmd/avdu
```
