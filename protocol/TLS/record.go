package tls

import (
	"github.com/SanthoshCheemala/Crypto/symmetric/aes"
)

func Encrypt(in []byte, key []byte,iv []byte,Auth []byte,tagLen int) ([]byte,[]byte,error) {
	aes,err := aes.NewAes(key)

	if err != nil {
		return nil,nil,err
	}

	cipher,tag := aes.EncryptGCM(in,iv,Auth,tagLen)
	return  cipher,tag,nil
}

func Decrypt(in []byte, key []byte,iv []byte,tag []byte,Auth []byte) ([]byte,error) {
	aes,err := aes.NewAes(key)

	if err != nil {
		return nil,err
	}

	decryptedMsg := aes.DecryptGCM(in,iv,Auth,tag)
	return  decryptedMsg,nil
}