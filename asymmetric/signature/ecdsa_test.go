package signature

import (
	// "bufio"
	// "compress/bzip2"
	"crypto/rand"

	// "github.com/SanthoshCheemala/Crypto/hash"
	// "io"
	// "math/big"
	// "os"
	// "strings"
	"testing"

	"github.com/glycerine/fast-elliptic-curve-p256/elliptic"
)


func testKeyGeneration(t *testing.T, c elliptic.Curve, tag string){
	priv,err := GenerateKey(c,rand.Reader)

	if err != nil{
		t.Errorf("%s: error %s", tag, err)
		return
	}

	if !c.IsOnCurve(priv.PublicKey.X,priv.PublicKey.Y) {
		t.Errorf("%s: Public key Invalid: %s",tag,err)
	}
}

func TestKeyGeneration(t *testing.T) {
	testKeyGeneration(t,elliptic.P224(),"p224")
	if testing.Short(){
		return
	}
	testKeyGeneration(t,elliptic.P256(),"p256")
	testKeyGeneration(t,elliptic.P384(),"P384")
	testKeyGeneration(t,elliptic.P521(),"P521")
}

func BenchmarkSignP256(b *testing.B) {
	
	p256 := elliptic.P256()
	priv,_ := GenerateKey(p256,rand.Reader)
	hashed := []byte("testing")

	
	for b.Loop(){
		_,_,_ = Sign(rand.Reader,priv,hashed)
	}
}


func BenchmarkVerifyP256(b *testing.B) {
	
	p256 := elliptic.P256()
	priv,_ := GenerateKey(p256,rand.Reader)
	hashed := []byte("testing")
	r,s,_ := Sign(rand.Reader,priv,hashed)
	for i := 0; i < b.N; i++{
		Verify(&priv.PublicKey,hashed,r,s)
	}
}
