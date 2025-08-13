package server

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/SanthoshCheemala/Crypto/asymmetric/ecdh25519"
	"github.com/SanthoshCheemala/Crypto/asymmetric/signature"
	"github.com/SanthoshCheemala/Crypto/kdf/hkdf"
	hmac_kdf "github.com/SanthoshCheemala/Crypto/kdf/hmac"
	tls "github.com/SanthoshCheemala/Crypto/protocol/TLS"
	"github.com/joho/godotenv"
)

var serverSigningPrivKey *signature.PrivateKey
var serverSigningPubKey *signature.PublicKey

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: Error loading .env file:", err)
	}

	pub, priv, err := loadOrGenerateSigningKey()
	if err != nil {
		log.Fatalf("Error loading or generating signing key: %v", err)
		os.Exit(1)
	}
	serverSigningPubKey = &pub
	serverSigningPrivKey = &priv

	pubKeyEnv := os.Getenv("SERVER_PUB_KEY")
	if pubKeyEnv == "" {
		pubKeyBytes := make([]byte, 64)
		serverSigningPubKey.X.FillBytes(pubKeyBytes[:32])
		serverSigningPubKey.Y.FillBytes(pubKeyBytes[32:])

		pubKeyFile := os.Getenv("SERVER_PUBKEY_SAVE_PATH")
		if pubKeyFile == "" {
			pubKeyFile = "server_pub_key.hex"
		}

		err = os.WriteFile(pubKeyFile, []byte(hex.EncodeToString(pubKeyBytes)), 0644)
		if err != nil {
			log.Printf("Warning: Could not save server public key to file: %v", err)
		}

		log.Printf("Server public key: %s", hex.EncodeToString(pubKeyBytes))
	}
}

func Server() {
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal("Error starting server: ", err)
	}
	defer listener.Close()
	fmt.Println("Server listening on :" + port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection: ", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Printf("New client connected: %s\n", conn.RemoteAddr())

	writeKeys, readKeys, err := handshake(conn)
	if err != nil {
		log.Printf("Handshake with %s failed: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("Handshake with %s successful. Secure channel established.", conn.RemoteAddr())

	go readLoop(conn, readKeys)
	writeLoop(conn, writeKeys)
}

func handshake(conn net.Conn) (writeKeys, readKeys tls.TrafficKeys, err error) {
	var ch tls.ClientHello
	if err = tls.Decode(conn, &ch); err != nil {
		return
	}
	clientHelloBytes, _ := json.Marshal(ch)

	serverPriv, err := ecdh25519.GenerateKey()
	if err != nil {
		return
	}
	serverPub := serverPriv.Public()

	r, s, err := signature.Sign(rand.Reader, serverSigningPrivKey, serverPub.ToBytes())
	if err != nil {
		return
	}

	sigBytes := make([]byte, 64)
	r.FillBytes(sigBytes[:32])
	s.FillBytes(sigBytes[32:])
	sh := tls.ServerHello{PublicKey: *serverPub, Signature: sigBytes}
	if err = tls.Encode(conn, &sh); err != nil {
		return
	}
	serverHelloBytes, _ := json.Marshal(sh)

	sharedSecret, err := serverPriv.ComputeSecret(&ch.PublicKey)
	if err != nil {
		return
	}

	transcript := tls.Transcript(clientHelloBytes, serverHelloBytes)
	readKeys, writeKeys, err = tls.DeriveKeys(sharedSecret, transcript)
	if err != nil {
		return
	}

	masterSecret, _ := hkdf.New(sharedSecret, nil, []byte("master_secret"), tls.KeyLength)
	clientFinishedKey, serverFinishedKey, err := tls.DeriveFinishedKeys(masterSecret)
	if err != nil {
		return
	}

	var clientFinishedMsg tls.Finished
	if err = tls.Decode(conn, &clientFinishedMsg); err != nil {
		return
	}
	if !hmac_kdf.HMAC_Verify(clientFinishedKey, transcript, clientFinishedMsg.VerifyData) {
		err = fmt.Errorf("client finished message verification failed")
		return
	}

	serverFinishedMsg := tls.Finished{VerifyData: hmac_kdf.HMAC_Sign(serverFinishedKey, transcript)}
	if err = tls.Encode(conn, &serverFinishedMsg); err != nil {
		return
	}

	return
}

func readLoop(conn net.Conn, keys tls.TrafficKeys) {
	for {
		decrypted, err := tls.DecodeAndDecrypt(conn, keys, nil)
		if err != nil {
			if err == io.EOF {
				log.Printf("Client %s disconnected.", conn.RemoteAddr())
			} else {
				log.Printf("Read error from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}
		fmt.Printf("Message from %s: %s\n", conn.RemoteAddr(), string(decrypted))
	}
}

func writeLoop(conn net.Conn, keys tls.TrafficKeys) {
	scanner := bufio.NewScanner(os.Stdin)
	var sequence uint64
	fmt.Print("Server: ")
	for scanner.Scan() {
		msg := scanner.Text()
		if strings.ToLower(msg) == "exit" {
			fmt.Println("Shutting down server...")
			return
		}

		err := tls.EncryptAndEncode(conn, keys, sequence, []byte(msg))
		if err != nil {
			log.Printf("Write error to %s: %v", conn.RemoteAddr(), err)
			return
		}
		sequence++
		fmt.Print("Server: ")
	}
}