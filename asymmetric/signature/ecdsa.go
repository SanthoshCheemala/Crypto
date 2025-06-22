package signature

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/asn1"
	"encoding/binary"
	"io"
	"math/big"

	"github.com/SanthoshCheemala/Crypto/hash"
	"github.com/glycerine/fast-elliptic-curve-p256/elliptic"
)


type invertible interface{
	Inverse(k *big.Int) *big.Int
}

type combinedMult interface{
	combinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x,y *big.Int)
}

const (
	aesIV = "IV for ECDSA CTR"
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

	k = new(big.Int).SetBytes(b)
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

func Sign(rand io.Reader, priv *PrivateKey,has []byte) (r,s *big.Int,err error){
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
	md.Sha256(priv.D.Bytes())
	md.Sha256(entropy)
	md.Sha256(has)
	key := make([]byte,len(md.State)*4)
	for i := 0; i < len(md.State); i ++{
		binary.BigEndian.PutUint32(key[i*4:i*4+4],md.State[i])
	}

	block, err := aes.NewCipher(key)


	if err != nil{
		return nil,nil,err
	}

	csprng := cipher.StreamReader{
		R : zeroReader,
		S : cipher.NewCTR(block,[]byte(aesIV)),
	}
	c := priv.PublicKey.Curve
	N := c.Params().N

	var k, KInv *big.Int

	for {
		for {
			k , err = randFeildElement(c,csprng)
			
			if err != nil{
				r = nil
				return nil, nil, err
			}
			if an, ok := priv.Curve.(invertible); ok {
				KInv = an.Inverse(k)
			} else {
				KInv = fermentInverse(k,N)
			}
			r , _ = priv.Curve.ScalarBaseMult(k.Bytes())

			r.Mod(r, N)

			if r.Sign() != 0{
				break
			}
	
		}
		e := hashToInt(has,c)
		s = new(big.Int).Mul(priv.D,r)
		s.Add(s, e)
		s.Mul(s, KInv)
		s.Mod(s,N)
		if s.Sign() != 0{
			break
		}
	}
	return r, s, nil
}

func Verify(pub *PublicKey,hash []byte,r, s *big.Int) bool{
	c := pub.Curve
	N := c.Params().N
	if r.Sign() == 0 || s.Sign() == 0 {
		return false
	}

	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}  

	e := hashToInt(hash,c)

	var w *big.Int
	if in,ok := c.(invertible); ok {
		w = in.Inverse(s)
	} else {
		w = new(big.Int).ModInverse(s,N)
	}
	u1 := e.Mul(e,w)
	u1.Mod(u1,N)
	u2 := w.Mul(r,w)
	u2.Mod(u2,N)

	var x,y *big.Int

	if opt,ok := c.(combinedMult); ok {
		x,y = opt.combinedMult(pub.X,pub.Y,u1.Bytes(),u2.Bytes())
	} else {
		x1,y1 := c.ScalarBaseMult(u1.Bytes()) 
		x2,y2 := c.ScalarMult(pub.X,pub.Y,u2.Bytes())

		x,y = c.Add(x1,y1,x2,y2)
	}

	if x.Sign() == 0 && y.Sign() == 0{
		return false
	}

	x.Mod(x,N)
	return x.Cmp(r) == 0
}

type zr struct {
	io.Reader
}

func (z *zr) Read(dst []byte) (n int, err error){
	for i := range dst{
		dst[i] = 0
	}
	return len(dst),nil
}


var zeroReader = &zr{}



