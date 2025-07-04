package tls


import (
		"github.com/SanthoshCheemala/Crypto/hash"
)

func transcript(transcripts...string) ([]byte) {
	H := hash.NewSHA256State()

	for _,transcript := range transcripts {
		H.Sha256([]byte(transcript))
	}
	return H.Sum()
}