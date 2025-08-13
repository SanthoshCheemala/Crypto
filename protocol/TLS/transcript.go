package tls

import (
	"github.com/SanthoshCheemala/Crypto/hash"
)

// Transcript hashes a series of handshake messages to create a unique session hash.
func Transcript(transcripts...[]byte) ([]byte) {
	H := hash.NewSHA256State()

	for _,t := range transcripts {
		H.Sha256(t)
	}
	return H.Sum()
}