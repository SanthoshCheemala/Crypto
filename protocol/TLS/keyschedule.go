package tls

import (
	"github.com/SanthoshCheemala/Crypto/kdf/hkdf"
)

func GeneratePseudoRandom(secret []byte,nonce []byte,info []byte,keyLength int) ([]byte,error) {
	psrng,err := hkdf.New(secret,nonce,info,keyLength)
	if err != nil {
		return  nil,err
	}
	return psrng,nil
}