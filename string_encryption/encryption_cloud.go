package string_encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
)

func EncryptString(stringToEncrypt string) {

	// Open public key file
	filePath := "./string_encryption/public_key.pem"
	filePublicKey, err := os.Open(filePath)
	handleError("Error opening public key file", err)
	defer filePublicKey.Close()

	// Reads public key file
	publicKeyData, err := ioutil.ReadAll(filePublicKey)
	handleError("Error reading public key file", err)

	blockPublicKey, _ := pem.Decode(publicKeyData)
	handleError("Error deconding public key to block", err)

	publicKeyData = blockPublicKey.Bytes

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyData)
	handleError("Error converting public key bytes to public key object", err)
	log.Printf("\nPublic Key: %s\n", publicKey)

	publicKeyRsa := publicKey.(*rsa.PublicKey)

	// Encrypt data
	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, publicKeyRsa, []byte(stringToEncrypt))
	handleError("Error encrypting string", err)

	// Saves encrypt data in file
	fileEncryptedDataPath := "./string_encryption/encrypted_data.txt"
	err = ioutil.WriteFile(fileEncryptedDataPath, encryptedData, 0644)
	handleError("Error writing file", err)

	log.Printf("\nData saved to %s\n", fileEncryptedDataPath)
}
