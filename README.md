# avdu

Aegis Vault Desktop Utility is a Go module and basic command line interface for generating 
one-time passwords from an [Aegis Authenticator](https://github.com/beemdevelopment/Aegis) vault backup or export file.

The desktop app version can be found at <https://github.com/Sammy-T/avda>.

> [!NOTE]
> HOTP is not implemented due to syncing concerns.

## CLI

```bash
avdu -h
```

## Import the module

Import into go file(s)

```go
import "github.com/sammy-t/avdu"
```

Update modules

```bash
go mod tidy
```

## Development

### Run the CLI

```bash
# Run in the current directory.
go run ./cmd/avdu

# Run using the plaintext test file.
go run ./cmd/avdu -p test/data/aegis_plain.json

# Run using the encrypted test file. (Enter password "test" when prompted.)
go run ./cmd/avdu -p test/data/aegis_encrypted.json -e
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
