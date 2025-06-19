package signature

import (
	"crypto"
	"crypto/internal/entropy"
	"encoding/asn1"
	"io"
	"math/big"

	"github.com/SanthoshCheemala/Crypto/hash"
	"github.com/SanthoshCheemala/Crypto/symmetric/aes"
	"github.com/glycerine/fast-elliptic-curve-p256/elliptic"
)


type invertible interface{
	Inverse(k *big.Int) *big.Int
}

type combinedMult interface{
	combinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x,y *big.Int)
}

const (
	aesIV = "something new to aes gcm block"
)

type PublicKey struct{
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct{
	PublicKey
	D *big.Int
}

type ecdsaSignature struct{
	R, S *big.Int
}

func (priv *PrivateKey) Public() crypto.PublicKey{
	return  &priv.PublicKey;
}

func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error){
	r, s , err := Sign(rand, priv, msg)

	if err != nil{
		return nil,err
	}

	return asn1.Marshal(ecdsaSignature{r,s})
}

var one = new(big.Int).SetInt64(1)

func randFeildElement(c elliptic.Curve, rand io.Reader) (k *big.Int,err error){
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)

	_,err = io.ReadFull(rand,b)

	if err != nil{
		return 
	}

	k = new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N,one)
	k.Mod(k,n)
	k.Add(k,one)
	return
}

func GenerateKey(c elliptic.Curve, rand io.Reader) (priv *PrivateKey,err error) {
	k, err := randFeildElement(c,rand)

	if err != nil{
		return
	}
	priv = new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return
}

func hashToInt(hash []byte,c elliptic.Curve) *big.Int{
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits+7) / 8
	if len(hash) > orderBytes{
		hash = hash[:orderBytes]
	}
	ret := new(big.Int).SetBytes(hash)

	excess := len(hash)*8 - orderBits
	if excess > 0{
		ret.Rsh(ret,uint(excess))
	}
	return ret
}

func fermentInverse(k, N *big.Int) *big.Int{
	two := new(big.Int).SetInt64(2)
	nMinus2 := new(big.Int).Sub(N,two)
	return new(big.Int).Exp(k,nMinus2,N)
}

func Sign(rand io.Reader, priv *PrivateKey,hash []byte) (r,s *big.Int,err error){
	entropyLen := (priv.Curve.Params().BitSize+7)/16

	if entropyLen > 32 {
		entropyLen = 32
	}
	entropy := make([]byte,entropyLen)
	_ , err = io.ReadFull(rand, entropy)

	if err != nil{
		return 
	}

	md := hash.NewSHA256State()
}




