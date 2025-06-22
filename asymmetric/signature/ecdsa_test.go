package signature

import (
	"bufio"
	"compress/bzip2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"math/big"
	"os"
	"strings"
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

func BenchmarkKeyGeneration(b *testing.B) {
	b.ResetTimer()

	p256 := elliptic.P256()
	
	b.ResetTimer()
	for i := 0; i < b.N;i++ {
		GenerateKey(p256,rand.Reader)
	}
}

func testSignAndVerify(t *testing.T,c elliptic.Curve,tag string) {
	priv,_ := GenerateKey(c,rand.Reader)

	hashed := []byte("testing")
	r,s,err := Sign(rand.Reader,priv,hashed)
	
	if err != nil{
		t.Errorf("%s: Error Siging: %s",tag,err)
		return
	}

	if !Verify(&priv.PublicKey,hashed,r,s){
		t.Errorf("%s: verified Failed",tag)
	}
	hashed[0] ^= 0xff

	if Verify(&priv.PublicKey,hashed,r,s){
		t.Errorf("%s: Verify always works!",tag)
	}
}

func TestSignAndVerify(t *testing.T) {
	testSignAndVerify(t,elliptic.P224(),"p224")
	if testing.Short(){
		return
	}
	testSignAndVerify(t,elliptic.P256(),"p256")
	testSignAndVerify(t,elliptic.P384(),"P384")
	testSignAndVerify(t,elliptic.P521(),"P521")
}

func testNounceSafety(t *testing.T,c elliptic.Curve,tag string) {
	priv,_ := GenerateKey(c,rand.Reader)

	hashed := []byte("testing")

	r0,s0,err := Sign(rand.Reader,priv,hashed)

	if err != nil{
		t.Errorf("%s: Signing Failed %s",tag,err)
	}

	hashed = []byte("testing.")
	r1,s1,err := Sign(rand.Reader,priv,hashed)
	
	if err != nil {
		t.Errorf("%s: Siging Failed %s",tag,err)
	}

	if s0.Cmp(s1) == 0 {
		t.Errorf("%s: Signature on two different messages were same",tag)
	}

	if r0.Cmp(r1) == 0 {
		t.Errorf("%s: Nounces used for two different messages was the same",tag)
	}
}

func TestNounceSafety(t *testing.T) {
	testNounceSafety(t,elliptic.P224(),"p224")
	if testing.Short(){
		return
	}
	testNounceSafety(t,elliptic.P256(),"p256")
	testNounceSafety(t,elliptic.P384(),"P384")
	testNounceSafety(t,elliptic.P521(),"P521")
}

func testINDCCA(t *testing.T,c elliptic.Curve, tag string) {
	priv,_ := GenerateKey(c,rand.Reader)

	hashed := []byte("testing")

	r0,s0,err := Sign(rand.Reader,priv,hashed)

	if err != nil{
		t.Errorf("%s: Signing Failed %s",tag,err)
	}
	r1,s1,err := Sign(rand.Reader,priv,hashed)
	
	if err != nil {
		t.Errorf("%s: Siging Failed %s",tag,err)
	}

	if s0.Cmp(s1) == 0 {
		t.Errorf("%s: two signatures of the same message produced same results",tag)
	}

	if r0.Cmp(r1) == 0 {
		t.Errorf("%s: two signatures of the same message produced same nounces",tag)
	}
}

func TestINDCCA(t *testing.T) {
	testINDCCA(t,elliptic.P224(),"p224")
	if testing.Short(){
		return
	}
	testINDCCA(t,elliptic.P256(),"p256")
	testINDCCA(t,elliptic.P384(),"P384")
	testINDCCA(t,elliptic.P521(),"P521")
}

func fromHex(s string) *big.Int{
	r,ok := new(big.Int).SetString(s,16)

	if !ok {
		panic("bad hex")
	}
	return r
}

func TestVectors(t *testing.T) {
	if testing.Short() {
		return
	}

	f,err := os.Open("testData/SigVer.rsp.bz2") 

	if err != nil {
		t.Fatal(err)
	}

	buf := bufio.NewReader(bzip2.NewReader(f))

	lineNo := 1
	var h hash.Hash
	var msg []byte
	var hashed []byte
	var r,s *big.Int
	pub := new(PublicKey)

	for {
		line,err := buf.ReadString('\n')
		
		if err != nil {
			t.Fatal(err)
		}
		line = line[:len(line)-2]
		
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if line[0] == '[' {
			line = line[1:len(line)-1]
			parts := strings.SplitN(line,",",2)

			switch parts[0] {
			case "p-224":
				pub.Curve = elliptic.P224()
			case "p-256":
				pub.Curve = elliptic.P256()
			case "p-384":
				pub.Curve = elliptic.P384()
			case "p-521":
				pub.Curve = elliptic.P521()
			default:
				pub.Curve = nil
			}
			switch parts[1] {
			case "sha-1":
				h = sha1.New()
			case "sha-224":
				h = sha256.New224()
			case "sha-256":
				h = sha256.New()
			case "sha-384":
				h = sha512.New384()
			case "sha-512":
				h = sha512.New()
			default:
				h = nil
			}
			continue
		}
		if h == nil || pub.Curve == nil {
			continue
		}

		switch {
		case strings.HasPrefix(line,"msg = "):
			if msg,err = hex.DecodeString(line[6:]); err != nil {
				t.Fatalf("failed to decode msg on line %d: %s",lineNo,err)
			}
		case strings.HasPrefix(line,"Qx = "):
			pub.X = fromHex(line[5:])
		case strings.HasPrefix(line,"Qy = "):
			pub.Y = fromHex(line[5:])
		case strings.HasPrefix(line,"R = "):
			pub.Y = fromHex(line[4:])
		case strings.HasPrefix(line,"s = "):
			pub.Y = fromHex(line[4:])
		case strings.HasPrefix(line,"Result = "):
			expected := line[9] == 'p'
			h.Reset()
			h.Write(msg)
			hashed = h.Sum(hashed[:0])
			if Verify(pub, hashed,r,s) != expected{
				t.Fatalf("incorrect result on line %d",lineNo)
			}
		default:
			t.Fatalf("unknown variable on line %d: %s",lineNo,line)
		}
	}
}