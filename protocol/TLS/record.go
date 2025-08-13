package tls

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/SanthoshCheemala/Crypto/symmetric/aes"
)

// EncryptAndEncode encrypts a message, packages it into a Record, and encodes it to the writer.
// The sequence number ensures a unique IV for each message.
func EncryptAndEncode(w io.Writer, keys TrafficKeys, sequence uint64, plaintext []byte) error {
	aes, err := aes.NewAes(keys.Key)
	if err != nil {
		return err
	}

	// Create a unique IV for this message using the base IV and a sequence number.
	iv := make([]byte, IVLength)
	copy(iv, keys.IV)
	binary.BigEndian.PutUint64(iv[4:], sequence) // XOR sequence into the last 8 bytes

	cipher, tag := aes.EncryptGCM(plaintext, iv, nil, 16)

	record := Record{
		IV:         iv,
		Ciphertext: cipher,
		Tag:        tag,
	}
	return Encode(w, record)
}

// DecodeAndDecrypt decodes a Record from the reader and decrypts its content.
func DecodeAndDecrypt(r io.Reader, keys TrafficKeys, plaintextBuffer []byte) ([]byte, error) {
	var record Record
	if err := Decode(r, &record); err != nil {
		return nil, err
	}

	aes, err := aes.NewAes(keys.Key)
	if err != nil {
		return nil, err
	}

	decryptedMsg := aes.DecryptGCM(record.Ciphertext, record.IV, nil, record.Tag)
	if decryptedMsg == nil {
		return nil, fmt.Errorf("decryption failed (authentication tag mismatch)")
	}
	return decryptedMsg, nil
}