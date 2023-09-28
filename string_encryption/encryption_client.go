package string_encryption

import (
	"fmt"
	"github.com/google/go-tpm/legacy/tpm2"
	"io"
	"os"
)

func DecryptString(encryptfile string) {

	// Open the TPM device.
	tpmDevice := "/dev/tpmrm0"
	tpm, err := tpm2.OpenTPM(tpmDevice)
	handleError("Error opening TPM device", err)
	defer tpm.Close()

	// Creates primary key template
	keyTemplate := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedParent | tpm2.FlagFixedTPM | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagDecrypt,
		AuthPolicy: nil,
		RSAParameters: &tpm2.RSAParams{
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	// Creates the primary key in the TPM.
	keyHandle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", keyTemplate)
	handleError("Error creating primary key", err)
	defer tpm2.FlushContext(tpm, keyHandle)

	// Abra o arquivo cifrado
	encryptedFile, err := os.Open("./string_encryption/" + encryptfile)
	if err != nil {
		fmt.Println("Erro ao abrir o arquivo cifrado:", err)
		return
	}
	defer encryptedFile.Close()

	decryptedFile, err := os.Create("./string_encryption/decryptedAP01C3.pdf")
	if err != nil {
		fmt.Println("Erro ao criar o arquivo descriptografado:", err)
		return
	}
	defer decryptedFile.Close()
	buffer := make([]byte, 256)

	for {
		// Leia exatamente 256 bytes do arquivo cifrado
		n, err := io.ReadFull(encryptedFile, buffer)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// Se chegamos ao final do arquivo, saia do loop
			break
		}
		if err != nil {
			fmt.Println("Erro ao ler o arquivo cifrado:", err)
			return
		}

		// Descriptografar o bloco
		decData, err := tpm2.RSADecrypt(tpm, keyHandle, "", buffer[:n], nil, "")
		if err != nil {
			fmt.Println("Erro ao descriptografar o bloco:", err)
			return
		}

		_, err = decryptedFile.Write(decData[11:])
		if err != nil {
			fmt.Println("Erro ao escrever no arquivo descriptografado:", err)
			return
		}
	}

	fmt.Println("Arquivo descriptografado com sucesso!")
}
