package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	aesgcm "github.com/hbakhtiyor/openssl_gcm"
)

// DecryptFile decrypts the file at the specified path using GCM.
func DecryptFile(inFilePath, outFilePath string, key, iv, aad []byte) error {
	stat, err := os.Stat(inFilePath)
	if os.IsNotExist(err) {
		return fmt.Errorf("A file does not exist at %s", inFilePath)
	} else if err != nil {
		return err
	}

	inFile, err := os.Open(inFilePath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	r, err := aesgcm.NewGcmDecryptReader(inFile, key, iv, aad, stat.Size())
	if err != nil {
		return err
	}

	_, err = io.Copy(outFile, r)
	return err
}

func main() {
	inFilePath := "testdata.enc"
	outFilePath := "testdata"
	key, _ := hex.DecodeString("81be5e09c111576103a8507658d47891")
	iv, _ := hex.DecodeString("81be5e09c111576103a85076")

	if err := DecryptFile(inFilePath, outFilePath, key, iv, nil); err != nil {
		panic(err)
	}
}
