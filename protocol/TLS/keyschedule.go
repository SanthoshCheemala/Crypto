package tls

import (
	"github.com/SanthoshCheemala/Crypto/kdf/hkdf"
)

const (
	// KeyLength is the desired length for AES-256 keys.
	KeyLength = 32
	// IVLength is the desired length for AES-GCM nonce/IV.
	IVLength = 12
)

// TrafficKeys holds the symmetric keys for one direction of communication.
type TrafficKeys struct {
	Key []byte
	IV  []byte
}

// DeriveKeys uses HKDF to derive client and server traffic keys from a shared secret.
func DeriveKeys(sharedSecret, transcriptHash []byte) (clientKeys, serverKeys TrafficKeys, err error) {
	// Derive a master secret from the shared secret
	masterSecret, err := hkdf.New(sharedSecret, nil, []byte("master_secret"), KeyLength)
	if err != nil {
		return
	}

	// Derive client keys
	clientKey, err := hkdf.New(masterSecret, transcriptHash, []byte("client_key"), KeyLength)
	if err != nil {
		return
	}
	clientIV, err := hkdf.New(masterSecret, transcriptHash, []byte("client_iv"), IVLength)
	if err != nil {
		return
	}
	clientKeys = TrafficKeys{Key: clientKey, IV: clientIV}

	// Derive server keys
	serverKey, err := hkdf.New(masterSecret, transcriptHash, []byte("server_key"), KeyLength)
	if err != nil {
		return
	}
	serverIV, err := hkdf.New(masterSecret, transcriptHash, []byte("server_iv"), IVLength)
	if err != nil {
		return
	}
	serverKeys = TrafficKeys{Key: serverKey, IV: serverIV}

	return
}

// DeriveFinishedKeys derives the keys for the Finished message MAC.
func DeriveFinishedKeys(masterSecret []byte) (clientFinishedKey, serverFinishedKey []byte, err error) {
	clientFinishedKey, err = hkdf.New(masterSecret, nil, []byte("client_finished"), KeyLength)
	if err != nil {
		return
	}
	serverFinishedKey, err = hkdf.New(masterSecret, nil, []byte("server_finished"), KeyLength)
	return
}