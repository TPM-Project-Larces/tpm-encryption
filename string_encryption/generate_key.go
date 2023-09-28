package string_encryption

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
)

func GenerateKey() {

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
	keyHandle, outPublic, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", keyTemplate)
	handleError("Error creating primary key", err)
	defer tpm2.FlushContext(tpm, keyHandle)

	// Read key public part
	fmt.Println(tpm2.ReadPublic(tpm, keyHandle))
	fmt.Println("\nPublic part: \n", outPublic)

	// Converts outPublic type to bytes
	publicKey, err := x509.MarshalPKIXPublicKey(outPublic)
	handleError("Error marshaling primary key", err)
	// Creates block public key
	blockPublicKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKey,
	}

	// Creates public key file
	filePath := "./string_encryption/public_key.pem"
	filePublicKey, err := os.Create(filePath)
	handleError("Error creating file public key in PEM format", err)
	defer filePublicKey.Close()

	// Loads public key in file
	err = pem.Encode(filePublicKey, blockPublicKey)
	handleError("Error enconding block public key in PEM file", err)
}
