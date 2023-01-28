package main

import (
	"os"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// padData pads the data to a multiple of the block size.
func padData(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// Encrypt encrypts the data with the given passphrase.
func Encrypt(data []byte, passphrase string) (error) {
	// Create the key from the passphrase
	hasher := sha256.New()
	hasher.Write([]byte(passphrase))
	key := hasher.Sum(nil)

	// Pad the data to a multiple of the block size
	data = padData(data, aes.BlockSize)

	// Generate a new random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// Encrypt the data
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(data, data)

	// Return the encrypted data as a base64-encoded string

	encrypted := base64.StdEncoding.EncodeToString(append(iv, data...))

	f, err := os.Create("encrypted.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	_, err = f.Write([]byte(encrypted))
	if err != nil {
		panic(err)
	}

	return nil
}

// Decrypt decrypts the data with the given passphrase.
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	// Decode the base64-encoded data
	data, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	// Extract the IV from the data
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	// Create the key from the passphrase
	hasher := sha256.New()
	hasher.Write([]byte(passphrase))
	key := hasher.Sum(nil)

	// Decrypt the data
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	// Return the decrypted data
	return data, nil
}

func main() {
	// Encrypt some data
	data := []byte("secret data")
	passphrase := "my passphrase"
	err := Encrypt(data, passphrase)
	if err != nil {
		panic(err)
	}

	f, err := os.Open("encrypted.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// read the file
	buf := make([]byte, 1024)
	n, err := f.Read(buf)
	if err != nil {
		panic(err)
	}

	// convert to string
	encryptedBuf := buf[:n]
	
	// Decrypt the data
	decrypted, err := Decrypt(encryptedBuf, passphrase)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", string(decrypted))
}
