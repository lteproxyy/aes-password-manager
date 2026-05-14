# AES Password Manager

A local command-line password manager written in C++.

The program stores entries in an encrypted vault file, protects the vault with a master password, and includes a password generator. The implementation uses Botan 3.11.1, which is vendored in this repository.

## Features

- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 key derivation
- Master password protected vault
- Random salt and nonce on every save
- Password generator
- Local vault file
- Makefile build

## Build

```bash
cd AES
make
```

Requires a C++20 compiler and `make`.

## Usage

```bash
./passmgr init
./passmgr add github -u yourname --url https://github.com --generate
./passmgr list
./passmgr get github --show
./passmgr gen 32
```

By default, the tool uses `vault.cpm` in the current directory. Use `--file` to choose another vault file.

## Repository

```text
AES/
├── passmgr.cpp
├── Makefile
├── README.md
└── vendor/botan/
```

Vault files like `vault.cpm` and the compiled `passmgr` binary are intentionally ignored by Git.

## Security Note

This project has not been professionally audited.

## License

This project is MIT licensed. Botan keeps its own BSD license in `AES/vendor/botan`.
