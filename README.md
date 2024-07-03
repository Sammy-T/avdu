# avdu

Aegis Vault Desktop Utility (WIP)

## Run dev app

```bash
go run ./cmd/avdu
```

## Build

Build the command binary to the same directory.

```bash
go build -C ./cmd/avdu
```

> [!CAUTION]
> Some terminals persist command history after the terminal window is closed.
>
> It's advisable to clear the command history when the cli is used with the password flag.
>
> Command Prompt doesn't require clearing since it doesn't persist command history 
> after the terminal window is closed.
