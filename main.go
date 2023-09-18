package main

import (
	"fmt"
	"tpm-go/string_encryption"
)

func main() {
	fmt.Printf("\n1 - Generate key\n")
	fmt.Printf("2 - Encrypt string\n")
	fmt.Printf("3 - Decrypt string\n")

	var option string
	fmt.Printf("\nChoose an option: ")
	fmt.Scan(&option)

	if option == "1" {
		string_encryption.GenerateKey()
	} else if option == "2" {
		var stringToEncrypt string
		fmt.Printf("\nInput string: ")
		fmt.Scanln(&stringToEncrypt)
		string_encryption.EncryptString(stringToEncrypt)
	} else if option == "3" {
		var sizeString int
		fmt.Printf("\nSize string: ")
		fmt.Scanln(&sizeString)
		string_encryption.DecryptString(sizeString)
	} else {
		fmt.Printf("\nInvalid option!\n")
	}
}
