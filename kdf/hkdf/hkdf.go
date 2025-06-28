package hkdf

import (
	"errors"
	"github.com/SanthoshCheemala/Crypto/kdf/hmac"
)



func extract(secret, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte,32)
	}
	return hmac.HMAC_Sign(salt,secret) 
}


func New(secret, salt, info []byte,length int) ([]byte,error) {
	prk := extract(secret,salt)
	return expand(prk,info,length)
}

func expand(prk []byte, info []byte,length int) ([]byte,error) {
	
	if length > 255*32 {
		return nil,errors.New("hkdf: output length is too large")
	}

	var okm []byte
	var previous []byte
	counter := byte(1)

	for len(okm) < length {
		input := append(append(previous, info...),counter)
		mac := hmac.HMAC_Sign(prk,input)
		okm = append(okm, mac...)
		previous = mac
		counter++
	}
	return okm[:length], nil
}

