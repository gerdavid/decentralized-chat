package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
)

const (
	keySize = 2048
	port    = ":8080"
)

// Message represents a chat message
type Message struct {
	From    string
	Content string
}

// Peer represents a peer in the network
type Peer struct {
	Address    string
	PublicKey  rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

// GenerateKeyPair generates a new RSA key pair
func GenerateKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keySize)
}

// EncryptMessage encrypts the message with the recipient's public key
func EncryptMessage(publicKey rsa.PublicKey, message []byte) ([]byte, error) {
	hash := sha256.New()
	return rsa.EncryptOAEP(hash, rand.Reader, &publicKey, message, nil)
}

// DecryptMessage decrypts the message with the recipient's private key
func DecryptMessage(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	hash := sha256.New()
	return rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, nil)
}

// HandleConnection handles incoming peer connections
func HandleConnection(conn net.Conn, peer *Peer) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	var encryptedMessage []byte
	if err := decoder.Decode(&encryptedMessage); err != nil {
		fmt.Println("Error decoding message:", err)
		return
	}

	// Decrypt the message
	decryptedMessage, err := DecryptMessage(peer.PrivateKey, encryptedMessage)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}

	var message Message
	if err := json.Unmarshal(decryptedMessage, &message); err != nil {
		fmt.Println("Error unmarshalling message:", err)
		return
	}

	fmt.Printf("[%s]: %s\n", message.From, message.Content)
}

// ListenForConnections starts listening for incoming connections
func ListenForConnections(peer *Peer) {
	listener, err := net.Listen("tcp", port)
	if err != nil {
		fmt.Println("Error setting up listener:", err)
		return
	}
	defer listener.Close()

	fmt.Println("Listening for incoming connections on", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go HandleConnection(conn, peer)
	}
}

// ConnectAndSendMessage connects to a peer and sends a message
func ConnectAndSendMessage(address string, peer *Peer, message Message) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("Error connecting to peer:", err)
		return
	}
	defer conn.Close()

	// Serialize the message
	messageBytes, err := json.Marshal(message)
	if err != nil {
		fmt.Println("Error marshalling message:", err)
		return
	}

	// Encrypt the message
	encryptedMessage, err := EncryptMessage(peer.PublicKey, messageBytes)
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	// Send the encrypted message
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(&encryptedMessage); err != nil {
		fmt.Println("Error sending message:", err)
		return
	}
}

func main() {
	// Generate RSA key pair for the peer
	privateKey, err := GenerateKeyPair()
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}

	peer := &Peer{
		Address:    "localhost" + port,
		PublicKey:  privateKey.PublicKey,
		PrivateKey: privateKey,
	}

	go ListenForConnections(peer)

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("Enter the peer address (localhost:8080) and message (or type 'exit' to quit): ")
		if !scanner.Scan() {
			break
		}
		input := scanner.Text()
		if input == "exit" {
			break
		}

		// Example input: "localhost:8080 Hello, World!"
		var peerAddress, messageContent string
		fmt.Sscanf(input, "%s %s", &peerAddress, &messageContent)

		message := Message{
			From:    peer.Address,
			Content: messageContent,
		}

		ConnectAndSendMessage(peerAddress, peer, message)
	}
}
