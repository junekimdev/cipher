# Cipher

Cipher algorithms in Golang

[![PkgGoDev](https://pkg.go.dev/badge/github.com/junekimdev/cipher)](https://pkg.go.dev/github.com/junekimdev/cipher)
[![Go Report Card](https://goreportcard.com/badge/github.com/junekimdev/cipher)](https://goreportcard.com/report/github.com/junekimdev/cipher)
![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/junekimdev/cipher)
![GitHub](https://img.shields.io/github/license/junekimdev/cipher)

---

## Getting Started

### Prerequisite

Create `.env` file in your root directory and add below variables

- CIPHER_PASSWORD
- CIPHER_SALT

Note: Rotate password/salt pair regularly

> When encryption runs more than 2^32 times, Nonce is at the risk of a repeat

### Installing

go get it (pun intended :smile_cat:)

```shell
go get github.com/junekimdev/cipher
```

## Usage

```golang
package main

import (
  "log"

  "github.com/junekimdev/cipher"
)


func main() {
  // text to encrypt
  encrypted, err := cipher.Encrypt(text)

  // encrypted text to decrypt
  decrypted, err := cipher.Decrypt(string(encrypted))
  ////---- decrypted == text

  // a file to encrypt
  cipher.EncryptFile(plainTextFile1, encryptedFile)

  // encrypted text to decrypt
  cipher.DecryptFile(encryptedFile, plainTextFile2)
  ////---- plainTextFile1 == plainTextFile2
}
```
