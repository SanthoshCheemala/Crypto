package client

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"

	"github.com/SanthoshCheemala/Crypto/asymmetric/ecdh25519"
	"github.com/SanthoshCheemala/Crypto/asymmetric/signature"
	"github.com/SanthoshCheemala/Crypto/kdf/hkdf"
	hmac_kdf "github.com/SanthoshCheemala/Crypto/kdf/hmac"
	tls "github.com/SanthoshCheemala/Crypto/protocol/TLS"
	"github.com/glycerine/fast-elliptic-curve-p256/elliptic"
	"github.com/joho/godotenv"
)

const serverPubKeyFile = "server_pub_key.hex"

var ServerSigningPubKey *signature.PublicKey

func init() {

    
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: Error loading .env file:", err)
	}

	
	pubKeyHex := os.Getenv("SERVER_PUB_KEY")
	if pubKeyHex == "" {
		pubKeyFile := os.Getenv("SERVER_PUBKEY_FILE")
		if pubKeyFile == "" {
			pubKeyFile = serverPubKeyFile
		}

		hexKey, err := os.ReadFile(pubKeyFile)
		if err != nil {
			log.Fatalf("FATAL: Could not read server public key from %s and SERVER_PUB_KEY env var is not set. Error: %v", pubKeyFile, err)
			os.Exit(1)
		}
		pubKeyHex = strings.TrimSpace(string(hexKey))
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		log.Fatalf("FATAL: Could not decode server public key: %v", err)
		os.Exit(1)
	}

	if len(pubKeyBytes) < 64 {
		log.Fatalf("FATAL: Server public key too short")
		os.Exit(1)
	}

	curve := elliptic.P256()
	x := new(big.Int).SetBytes(pubKeyBytes[:32])
	y := new(big.Int).SetBytes(pubKeyBytes[32:64])

	ServerSigningPubKey = &signature.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
}

func Client() {
	serverAddress := os.Getenv("SERVER_ADDRESS")
	if serverAddress == "" {
		serverAddress = "localhost:8080"
	}

	conn, err := net.Dial("tcp", serverAddress)
	if err != nil {
		log.Fatal("Error connecting to server: ", err)
	}
	defer conn.Close()
	fmt.Printf("Connected to server at %s.\n", serverAddress)

	writeKeys, readKeys, err := handshake(conn)
	if err != nil {
		fmt.Printf("Handshake failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Handshake successful. Secure channel established.")

	go readLoop(conn, readKeys)
	writeLoop(conn, writeKeys)
}

func handshake(conn net.Conn) (writeKeys, readKeys tls.TrafficKeys, err error) {
	clientPriv, err := ecdh25519.GenerateKey()
	if err != nil {
		return
	}
	clientPub := clientPriv.Public()

	ch := tls.ClientHello{PublicKey: *clientPub}
	if err = tls.Encode(conn, &ch); err != nil {
		return
	}
	clientHelloBytes, _ := json.Marshal(ch)

	var sh tls.ServerHello
	if err = tls.Decode(conn, &sh); err != nil {
		return
	}
	serverHelloBytes, _ := json.Marshal(sh)

	if len(sh.Signature) < 64 {
		err = fmt.Errorf("invalid server signature length")
		return
	}

	r := new(big.Int).SetBytes(sh.Signature[:32])
	s := new(big.Int).SetBytes(sh.Signature[32:64])

	if !signature.Verify(ServerSigningPubKey, sh.PublicKey.ToBytes(), r, s) {
		err = fmt.Errorf("server signature verification failed")
		return
	}

	sharedSecret, err := clientPriv.ComputeSecret(&sh.PublicKey)
	if err != nil {
		return
	}

	transcript := tls.Transcript(clientHelloBytes, serverHelloBytes)
	writeKeys, readKeys, err = tls.DeriveKeys(sharedSecret, transcript)
	if err != nil {
		return
	}

	masterSecret, _ := hkdf.New(sharedSecret, nil, []byte("master_secret"), tls.KeyLength)
	clientFinishedKey, serverFinishedKey, err := tls.DeriveFinishedKeys(masterSecret)
	if err != nil {
		return
	}

	clientFinishedMsg := tls.Finished{VerifyData: hmac_kdf.HMAC_Sign(clientFinishedKey, transcript)}
	if err = tls.Encode(conn, &clientFinishedMsg); err != nil {
		return
	}

	var serverFinishedMsg tls.Finished
	if err = tls.Decode(conn, &serverFinishedMsg); err != nil {
		return
	}
	if !hmac_kdf.HMAC_Verify(serverFinishedKey, transcript, serverFinishedMsg.VerifyData) {
		err = fmt.Errorf("server finished message verification failed")
		return
	}

	return
}

func readLoop(conn net.Conn, keys tls.TrafficKeys) {
	for {
		decrypted, err := tls.DecodeAndDecrypt(conn, keys, nil)
		if err != nil {
			if err == io.EOF {
				log.Println("Server closed the connection.")
			} else {
				log.Printf("Read error: %v", err)
			}
			os.Exit(1)
		}
		fmt.Printf("\nMessage from server: %s\nYou: ", string(decrypted))
	}
}

func writeLoop(conn net.Conn, keys tls.TrafficKeys) {
	scanner := bufio.NewScanner(os.Stdin)
	var sequence uint64
	fmt.Print("You: ")
	for scanner.Scan() {
		msg := scanner.Text()
		if strings.ToLower(msg) == "exit" {
			fmt.Println("Disconnecting...")
			return
		}

		err := tls.EncryptAndEncode(conn, keys, sequence, []byte(msg))
		if err != nil {
			log.Printf("Write error: %v", err)
			return
		}
		sequence++
		fmt.Print("You: ")
	}
}