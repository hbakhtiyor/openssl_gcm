package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// EncryptFile encrypts the file at the specified path using GCM.
func EncryptFile(inFilePath, outFilePath string, key, iv, aad []byte) error {
	if _, err := os.Stat(inFilePath); os.IsNotExist(err) {
		return fmt.Errorf("A file does not exist at %s", inFilePath)
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

	r, err := NewGcmEncryptReader(inFile, key, iv, aad)
	if err != nil {
		return err
	}

	_, err = io.Copy(outFile, r)
	return err
}

// DecryptFile decrypts the file at the specified path using GCM.
func DecryptFile(inFilePath, outFilePath string, key, iv, aad []byte) error {
	if _, err := os.Stat(inFilePath); os.IsNotExist(err) {
		return fmt.Errorf("A file does not exist at %s", inFilePath)
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

	r, err := NewGcmDecryptReader(inFile, key, iv, aad)
	if err != nil {
		return err
	}

	_, err = io.Copy(outFile, r)
	return err
}

func main() {
	inFilePath := "testdata"
	outFilePath := "testdata.enc"
	outNewFilePath := "newtestdata"
	key, _ := hex.DecodeString("81be5e09c111576103a8507658d47891")
	iv, _ := hex.DecodeString("81be5e09c111576103a85076")

	if err := EncryptFile(inFilePath, outFilePath, key, iv, nil); err != nil {
		panic(err)
	}
	if err := DecryptFile(outFilePath, outNewFilePath, key, iv, nil); err != nil {
		panic(err)
	}
}
