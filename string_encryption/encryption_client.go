package string_encryption

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
)

func DecryptString(sizeString int) {

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

	// Open encrypted data file
	fileEncryptedDataPath := "./string_encryption/encrypted_data.txt"
	fileEncryptedDataFile, err := os.Open(fileEncryptedDataPath)
	handleError("Error opening encrypted data file", err)
	defer fileEncryptedDataFile.Close()

	// Reads encrypted data file
	encryptedData, err := ioutil.ReadAll(fileEncryptedDataFile)
	handleError("Error reading encrypted data file", err)

	// Creates the primary key in the TPM.
	keyHandle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", keyTemplate)
	handleError("Error creating primary key", err)
	defer tpm2.FlushContext(tpm, keyHandle)

	// Decrypt data
	decData, err := tpm2.RSADecrypt(tpm, keyHandle, "", encryptedData, nil, "")
	handleError("Error decrypting data", err)

	fmt.Printf("\nDecrypted data: %x\n", decData[len(decData)-sizeString:]) //starts printing after the padding (the size of the data minus the size of the word)
	fmt.Printf("\nDecrypted data (string): %s\n", string(decData[len(decData)-sizeString:]))
}
