package hkdf

import (
	"crypto/sha256"
	"errors"

	"github.com/SanthoshCheemala/Crypto/kdf/hmac"
)

const hashLen = sha256.Size

func extract(secret, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, hashLen)
	}
	return hmac.HMAC_Sign(salt, secret)
}


func New(secret, salt, info []byte,length int) ([]byte,error) {
	prk := extract(secret,salt)
	return expand(prk,info,length)
}

func expand(prk []byte, info []byte, length int) ([]byte, error) {
	
	if length > 255*hashLen {
		return nil, errors.New("hkdf: output length is too large")
	}

	var okm []byte
	var t []byte
	counter := byte(1)

	for len(okm) < length {
		bufCap := len(t) + len(info) + 1
		input := make([]byte, 0, bufCap)
		input = append(input, t...)
		input = append(input, info...)
		input = append(input, counter)
		t = hmac.HMAC_Sign(prk, input)
		okm = append(okm, t...)
		counter++
	}
	return okm[:length], nil
}

