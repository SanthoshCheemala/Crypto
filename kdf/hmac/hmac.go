package hmac

import (
	"crypto/hmac"
	"github.com/SanthoshCheemala/Crypto/hash"
)

func HMAC_Sign(k []byte,msg []byte) []byte{
	// step 1: Shorten the key if needed
	if len(k) > 64 {
		hashedKey := hash.NewSHA256State()
		hashedKey.Sha256(k)
		k = hashedKey.Sum()
	}

	// step 2: pad the if needed
	if len(k) < 64 {
		padding := make([]byte,64-len(k))
		k = append(k, padding...)
	}

	// step3: create ipad and opad
	k_ipad := make([]byte,64)
	k_opad := make([]byte,64)

	for i := 0; i < 64; i++{
		k_ipad[i] = k[i] ^ 0x36
	}
	for i := 0; i < 64; i++{
		k_opad[i] = k[i] ^ 0x5c
	}

	// step 4: Inner Hash
	innerHash := hash.NewSHA256State()
	innerHash.Sha256(append(k_ipad, msg...))

	// step 5: Outer Hash
	outerHash := hash.NewSHA256State()
	outerHash.Sha256(append(k_opad,innerHash.Sum()...))
	return outerHash.Sum()
}

func HMAC_Verify(k ,msg ,expectedMac []byte) bool {
	computedMac := HMAC_Sign(k,msg)
	// fmt.Println(computedMac,expectedMac)
	return hmac.Equal(computedMac,expectedMac) // to avoid timing attacks
}