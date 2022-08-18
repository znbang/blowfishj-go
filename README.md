# blowfishj-go

blowfishj-go ports CTS encryption and decryption from blowfishj.

# Install

    go get github.com/znbang/blowfishj-go 

# Usage

```go
package main

import (
	"fmt"
	
	"github.com/znbang/blowfishj-go"
)

const (
	Password = "Pa$$w0rd"
	PlainText = "Text to encrypt"
)

func main() {
	encryptedText := blowfishj.Encrypt(Password, PlainText)
	fmt.Println("Encrypted text:", encryptedText)
	decryptedText, err := blowfishj.Decrypt(Password, encryptedText)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted text:", decryptedText)
}
```