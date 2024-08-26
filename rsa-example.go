package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "fmt"
    "log"
)


func encryptDecryptExample() {
    // Generate RSA key pair
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatalf("Error generating RSA key: %v", err)
    }

    publicKey := &privateKey.PublicKey

    // Message to be encrypted
    message := []byte("Hello, RSA!")

    // Encrypt the message using OAEP
    encryptedMessage, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
    if err != nil {
        log.Fatalf("Error encrypting message: %v", err)
    }

    fmt.Printf("Encrypted message: %x\n", encryptedMessage)

    // Decrypt the message using the private key
    decryptedMessage, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedMessage, nil)
    if err != nil {
        log.Fatalf("Error decrypting message: %v", err)
    }

    fmt.Printf("Decrypted message: %s\n", decryptedMessage)
}

