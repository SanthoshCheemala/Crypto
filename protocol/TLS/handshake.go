package tls

import (
	"encoding/json"
	"io"

	"github.com/SanthoshCheemala/Crypto/asymmetric/ecdh25519"
)

// ClientHello contains the client's public key
type ClientHello struct {
	PublicKey ecdh25519.PublicKey `json:"public_key"`
}

// ServerHello contains the server's public key and a signature
type ServerHello struct {
	PublicKey ecdh25519.PublicKey `json:"public_key"`
	Signature []byte              `json:"signature"`
}

// Finished is a message used to verify handshake integrity.
type Finished struct {
	VerifyData []byte `json:"verify_data"`
}

// Record represents an encrypted message sent over the wire
type Record struct {
	IV         []byte `json:"iv"`
	Ciphertext []byte `json:"ciphertext"`
	Tag        []byte `json:"tag"`
}

// Encode writes the JSON representation of v to the writer.
func Encode(w io.Writer, v interface{}) error {
	return json.NewEncoder(w).Encode(v)
}

// Decode reads the JSON representation from the reader into v.
func Decode(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}