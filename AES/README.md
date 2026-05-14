# AES Password Manager

A local command-line password manager written in C++.

It stores entries in an encrypted vault file, protects the vault with a master password, and includes a password generator. Botan 3.11.1 is vendored in `vendor/botan`.

## Build

```bash
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
./passmgr remove github
./passmgr change-master
```

By default, the tool uses `vault.cpm` in the current directory. Use `--file` to choose another vault file.

## Security

- AES-256-GCM
- Random nonce on every save
- 256-bit salt on every save
- PBKDF2-HMAC-SHA256 with 600000 iterations
- Botan 3.11.1
- Atomic writes with `0600` permissions on POSIX systems
- Master password is not stored
- Password output requires `--show`

## Security Note

This project has not been professionally audited.
