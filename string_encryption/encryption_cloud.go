package string_encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func EncryptString(filetoEncrypt string) {

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

	publicKeyRsa := publicKey.(*rsa.PublicKey)

	// Crie um arquivo de saída e um escritor para ele

	inputFile := "./string_encryption/" + filetoEncrypt
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Println("Erro ao ler o arquivo de entrada:", err)
		return
	}

	// Dividir os dados em blocos menores (tamanho máximo de bloco para criptografia RSA)
	maxBlockSize := 245
	var encryptedBlocks []byte
	for len(data) > 0 {
		blockSize := len(data)
		if blockSize > maxBlockSize {
			blockSize = maxBlockSize
		}

		// Criptografar o bloco e adicionar à lista de blocos criptografados
		encryptedBlock, err := rsa.EncryptPKCS1v15(rand.Reader, publicKeyRsa, data[:blockSize])
		if err != nil {
			fmt.Println("Erro ao criptografar o bloco:", err)
			return
		}
		encryptedBlocks = append(encryptedBlocks, encryptedBlock...)
		data = data[blockSize:]
	}

	outputFile := "./string_encryption/EncryptedAP01Calculo03.pdf"
	err = ioutil.WriteFile(outputFile, encryptedBlocks, 0644)
	if err != nil {
		fmt.Println("Erro ao escrever o arquivo criptografado:", err)
		return
	}

	fmt.Println("Arquivo criptografado com sucesso!")
}
