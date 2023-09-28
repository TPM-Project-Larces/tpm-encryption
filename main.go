package main

import (
	"fmt"
	"tpm-go/string_encryption"
)

func main() {
	fmt.Printf("\n1 - Generate key\n")
	fmt.Printf("2 - Encrypt file\n")
	fmt.Printf("3 - Decrypt file\n")

	var option string
	fmt.Printf("\nChoose an option: ")
	fmt.Scan(&option)

	if option == "1" {
		string_encryption.GenerateKey()
	} else if option == "2" {
		var fileToEncrypt string
		fmt.Printf("\nWrite a File to encrypt: ")
		fmt.Scanln(&fileToEncrypt)
		string_encryption.EncryptString(fileToEncrypt)
	} else if option == "3" {
		var fileToDecrypt string
		fmt.Printf("\nWrite a encrypt File to decrypt: ")
		fmt.Scanln(&fileToDecrypt)
		string_encryption.DecryptString(fileToDecrypt)
	} else {
		fmt.Printf("\nInvalid option!\n")
	}
}
