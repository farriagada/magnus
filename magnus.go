package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
)

func generatePEM(filename string, header string, key *rsa.PrivateKey, typekey string) {
	switch typekey {
	case "private":
		pemPrivateKey, err := os.Create(filename)
		if err != nil {
			log.Fatal(err)
		}
		// Let's create a PEM space block to write the info.
		var pemPrivateBlock = &pem.Block{
			Type:  header,
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}
		// Finally, we create the PEM file using both the key and the PEM Block.
		err = pem.Encode(pemPrivateKey, pemPrivateBlock)
		if err != nil {
			log.Fatal(err)
		}
		// Closing the file
		pemPrivateKey.Close()

	case "public":
		// The same thing happens for a public PEM certificate.
		pemPublicKey, err := os.Create(filename)
		if err != nil {
			log.Fatal(err)
		}

		var pemPublicBlock = &pem.Block{
			Type:  header,
			Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
		}
		err = pem.Encode(pemPublicKey, pemPublicBlock)
		if err != nil {
			log.Fatal(err)
		}
		pemPublicKey.Close()
	default:
		log.Fatal("Error, this is not a valid switch case")
	}

}

func generateRSAKeyPair() *rsa.PrivateKey {
	//Let's first generate a random RSA 4096bit key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}
	//Then, we call the same function twice, to create a physical PEM private and public key.
	generatePEM("private_key.pem", "RSA PRIVATE KEY", privateKey, "private")
	generatePEM("public_key.pem", "RSA PUBLIC KEY", privateKey, "public")

	return privateKey
}

func importPEMPrivate(filename string) *rsa.PrivateKey {
	privateKeyFile, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()

	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return privateKeyImported
}

func importPEMPublic(filename string) *rsa.PublicKey {
	publicKeyFile, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	pemfileinfo, _ := publicKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	publicKeyFile.Close()

	publicKeyImported, err := x509.ParsePKCS1PublicKey(data.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return publicKeyImported
}

func encryptWithRSA(key *rsa.PublicKey, AESKey string) string {
	// We encrypt the AES Key with RSA, using SHA-256 as a hash function and of course the RSA public key.
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		key,
		[]byte(AESKey),
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(encryptedBytes)
}

func decryptWithRSA(key *rsa.PrivateKey, encryptedMSG string) string {
	encryptedBytes, err := hex.DecodeString(encryptedMSG)
	if err != nil {
		log.Fatal(err)
	}
	decryptedBytes, err := key.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		log.Fatal(err)
	}
	return string(decryptedBytes)
}

func pad(message []byte, blockSize int) []byte {
	padding := blockSize - len(message)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(message, padtext...)
}

// unpad removes padding from the end of the message
func unpad(message []byte, blockSize int) []byte {
	length := len(message)
	unpadding := int(message[length-1])
	return message[:(length - unpadding)]
}

func EncryptAESCBC256(key []byte, plaintext string) string {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	// Let's create a CBC Mode for encryption.
	aesMode := cipher.NewCBCEncrypter(c, make([]byte, aes.BlockSize))
	// In order to encrypt any message, we first have to pad it.
	paddedPt := pad([]byte(plaintext), aes.BlockSize)
	// Let's allocate a memory block the size of the padded message.
	ciphertext := make([]byte, len(paddedPt))
	// Encryption!
	aesMode.CryptBlocks(ciphertext, []byte(paddedPt))
	return hex.EncodeToString(ciphertext)
}

func DecryptAESCBC256(key []byte, hexcipher string) string {
	ciphertext, _ := hex.DecodeString(hexcipher)

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	aesMode := cipher.NewCBCDecrypter(c, make([]byte, aes.BlockSize))
	plaintext := make([]byte, len(ciphertext))
	aesMode.CryptBlocks(plaintext, ciphertext)
	unpaddedPlaintext := unpad(plaintext, aes.BlockSize)

	return string(unpaddedPlaintext)
}

func main() {
	runFunction := flag.String("f", "default", "Function to run")
	RSAPubKey := flag.String("rsapub", "default", "RSA Public Key Name")
	RSAPrivateKey := flag.String("rsapriv", "default", "RSA Private Key Name")
	message := flag.String("m", "default", "message")
	AESKey := flag.String("k", "default", "AES 256 Key to use for encryption")
	EncryptedAESKey := flag.String("e", "default", "Encrypted AES 256 Key to use for encryption")
	ciphertext := flag.String("c", "default", "Ciphertext to decrypt using AES-256")

	flag.Parse()

	switch *runFunction {
	case "genRSAKeyPair":
		generateRSAKeyPair()
		fmt.Println("All Done!")
	case "genAESKey":
		randomKey := make([]byte, 32)
		_, err := rand.Read(randomKey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Here's your AES-256 Key:", hex.EncodeToString(randomKey))
	case "RSAEncrypt":
		if (*RSAPubKey == "default") || (*AESKey == "default") {
			log.Fatal("You need to enter both a valid RSA Public Key, and the AES Key")
		}
		var pubkey = importPEMPublic(*RSAPubKey)
		fmt.Println("Your encrypted AES-256 Key:", encryptWithRSA(pubkey, *AESKey))
	case "RSADecrypt":

		if (*RSAPrivateKey == "default") || (*EncryptedAESKey == "default") {
			log.Fatal("You need to enter both the RSA Private Key for decryption, and the AES Encrypted Key")
		}
		var privkey = importPEMPrivate(*RSAPrivateKey)
		fmt.Println("Your AES-256 Key: ", decryptWithRSA(privkey, *EncryptedAESKey))

	case "encryptMessage":

		if (*message == "default") || (*AESKey == "default") {
			log.Fatal("You need to enter both a message to encrypt, and the AES-256 Key")
		}
		k, err := hex.DecodeString(*AESKey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Your encrypted message: ", EncryptAESCBC256(k, *message))
	case "decryptMessage":

		if (*ciphertext == "default") || (*AESKey == "default") {
			log.Fatal("You need to enter both the ciphertext to decrypt, and the AES-256 Key")
		}
		k, err := hex.DecodeString(*AESKey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Your decrypted message: ", DecryptAESCBC256(k, *ciphertext))
	default:
		log.Fatal("You need to enter a valid function")
	}
}
