package aes

import (
	"crypto/internal/utils"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)
type AES struct{
	nr int
	nk int 
	nb int
	len int
	key []byte
	roundkeys []uint32;
}

var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

var inv_sbox = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

var rcon = [10]uint32{
	0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
	0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
}

// newAes initializes a new AES encryption/decryption context with the provided key
// It sets up the block cipher with appropriate parameters based on the key length
// and generates the round keys needed for encryption and decryption operations
func newAes(key []byte)(*AES,error){
	aes := AES{
		nr:10,            // Number of rounds (10 for AES-128)
		nk:4,             // Key length in 32-bit words (4 words = 16 bytes = 128 bits)
		nb:4,             // Block size in 32-bit words (always 4 words = 16 bytes = 128 bits)
		len: 16,          // Block length in bytes
		key: key,         // Store the original encryption key
	}
	aes.roundkeys = aes.keyExpansion()  // Generate round keys for the cipher
	return &aes,nil;
}

// keyExpansion generates the round keys used in each round of encryption/decryption
// It expands the original encryption key into a larger key schedule
func (a *AES) keyExpansion()([]uint32){
	var w []uint32;
	// First, copy the original key into the round key array
	for i := 0; i < a.nk; i++{
		w = append(w, binary.BigEndian.Uint32(a.key[4*i:4*i+4]))
	}
	// Expand the key to generate remaining round keys
	for r := a.nk; r < a.nb*(a.nr+1); r++{
		tmpW := make([]byte,4);
		binary.BigEndian.PutUint32(tmpW,w[r-1])
		
		// Apply special transformations at specific intervals
		if r%a.nk == 0{
			rootword(tmpW);              // Rotate word (byte rotation)
			a.subBytes(tmpW);            // Apply S-box substitution
			tempRcon := make([] byte,4);
			binary.BigEndian.PutUint32(tempRcon,rcon[r/a.nk-1])  // Add round constant
			xor(tmpW,tempRcon)           // XOR with round constant
		}
		
		// Each new round key word is the XOR of the previous round key word
		// and the word a.nk positions earlier
		w = append(w, w[r-a.nk]^binary.BigEndian.Uint32(tmpW))
	}
	// mute debugging
	utils.DumpWords("KeyExpansion: ", w);
	return w;
}

// EncryptCBC encrypts data using AES in CBC mode with provided initialization vector
func (a *AES) EncryptCBC(in []byte, iv []byte,pad utils.PaddingFunc)[]byte{
	in = pad(in,a.len)
	ivTmp := make([]byte, len(iv));
	copy(ivTmp,iv)
	for i := 0; i < len(in); i+= a.len{
		xor(in[i:i+a.len],ivTmp)
		a.encryptBlock(in[i:i+a.len],a.roundkeys)
		copy(ivTmp,in[i:i+a.len])
	}
	fmt.Printf("aes_impl-%d CBC encrypted cipher:",a.nk*32)
	utils.Dumpbytes("",in)
	return in
}

// DecryptCBC decrypts data using AES in CBC mode with provided initialization vector
func (a *AES) DecryptCBC(in []byte, iv []byte,unpad utils.UnpaddingFunc)([]byte){
	ivTmp := make([]byte,len(iv));
	copy(ivTmp,iv)
	reg := make([]byte,a.len);
	for i := 0; i < len(in); i += a.len{
		if i+a.len > len(in) {
            break
        }
        
		copy(reg,in[i:i+a.len])
		xor(in[i:i+a.len],ivTmp)
		a.DecryptBlock(in[i:i+a.len],a.roundkeys)
		copy(ivTmp,reg);
	}
	fmt.Printf("aes_impl-%d CBC decrypted cipher:",a.nk*32)
	utils.Dumpbytes("",in)
	return in;
}

func gHash(x []byte,H []byte)([]byte){
	y := make([]byte,16)

	for i := 0; i < len(x); i+= 16{
		xor(y,x[i:i+16]);
		mulBlock(y,H)
	}
	return y;
}

func (a *AES) EncryptGCTR(in []byte,ICB []byte)([]byte){
	if in == nil {
		return in
	}

	plainTmp := make([]byte, len(in))
	copy(plainTmp, in)
	xorBlock := make([]byte, 16*int(math.Ceil(float64(len(plainTmp))/16.0)))

	// The variable cbi(i 'th counter block) is used to preserve the state.
	cbi := make([]byte, 16)
	cbi1 := make([]byte, 16)
	copy(cbi, ICB)
	copy(cbi1, ICB)
	for i := 0; i < len(plainTmp); i += a.len {
		a.encryptBlock(cbi1, a.roundkeys)
		copy(xorBlock[i:i+a.len], cbi1)
		cbi = inc32(cbi)
		copy(cbi1, cbi)
	}

	xor(plainTmp, xorBlock)
	return plainTmp
}

func (a *AES) EncryptGCM(in []byte,iv []byte,auth []byte, tagLen int)([]byte,[]byte){
	H := make([]byte,16)
	a.encryptBlock(H,a.roundkeys)
	var J0 []byte
	if len(iv) == 12{
		J0 = append(iv, []byte{0x00,0x00,0x00,0x01}...)
	} else {
		sPlus64Zeros := make([]byte,16*int(math.Ceil(float64(8*len(iv))/128.0))-len(iv)+8)
		lenIV := make([]byte,0)
		big.NewInt(int64(8 * len(iv))).FillBytes(lenIV)
		J0 = gHash(append(append(iv, sPlus64Zeros...),lenIV...),H)

	}
	J0Temp := make([]byte,len(J0))
	copy(J0Temp,J0)

	cipher := a.EncryptGCTR(in,inc32(J0))
	vZeros := make([]byte, 16*int(math.Ceil(float64(8*len(auth))/128.0))-len(auth)+8)
	uZeros := make([]byte, 16*int(math.Ceil(float64(8*len(cipher))/128.0))-len(cipher)+8)

	lenA := make([]byte,8)
	lenC := make([]byte,8)
	big.NewInt(int64(8 * len(auth))).FillBytes(lenA)
	big.NewInt(int64(8 * len(cipher))).FillBytes(lenC)
	S := gHash(append(append(append(append(append(auth,vZeros...),cipher...),uZeros...),lenA...),lenC...),H)
	T := a.EncryptGCTR(S,J0Temp)
	fmt.Printf("aes-impl-%d GCM Encrypted cipherText",a.nk*32)
	utils.Dumpbytes("",cipher)
	utils.Dumpbytes("Tag",T[:tagLen])
	return cipher,T[:tagLen]
}

// addRoundkey XORs the state with the round key
func (a *AES) addRoundkey(state []byte,w []uint32){
	tmp := make([]byte,a.len);
	for i := 0; i < len(w); i++{
		binary.BigEndian.PutUint32(tmp[4*i:4*i+4],w[i])
	}
	xor(state,tmp)
}

// subBytes substitutes each byte in the state with its corresponding value in the S-box
func (a *AES) subBytes(state []byte){
	for i,v := range state{
		state[i] = sbox[v];
	}
}

// invsubBytes reverses the subBytes operation using inverse S-box
func (a *AES) invsubBytes(state []byte){
	for i,v := range state{
		state[i] = inv_sbox[v]
	}
}

// shiftRow shifts a row by n positions
func (a* AES) shiftRow(in []byte,i int,n int){
	in[i],in[i+4*1],in[i+4*2],in[i+4*3] = in[i+4*(n%4)],in[i+4*((n+1)%4)],in[i+4*((n+2)%4)],in[i+4*((n+3)%4)]
}


// shiftRows performs the ShiftRows step of AES encryption
func (a *AES) shiftRows(state []byte){
	a.shiftRow(state,1,1)
	a.shiftRow(state,2,2)
	a.shiftRow(state,3,3)
}


// invshiftRows reverses the shiftRows operation for decryption
func (a *AES) invshiftRows(state []byte){
	a.shiftRow(state,1,3)
	a.shiftRow(state,2,2)
	a.shiftRow(state,3,1)
}


// rootword rotates a 4-byte word left by one byte
func rootword(in []byte){
	in[0],in[1],in[2],in[3] = in[1],in[2],in[3],in[0]
}
func xor(m []byte,n []byte){
	if len(n) >= len(m){
		for i := 0; i < len(m); i++{
			m[i] = m[i] ^ n[i];
		}
	}
}

func xtime(in byte) byte{
	return (in << 1) ^ (((in >> 7) & 1) * 0x1b)
}

func xtimes(in byte, t int)(byte){
	for t > 0 {
		in  = xtime(in)
		t--;
	}
	return in;
}

func mulByte(x byte,y byte)byte{
	return (((y >> 0) & 0x01)*xtimes(x,0))^
	(((y >> 1) & 0x01)*xtimes(x,1))^
	(((y >> 2) & 0x01)*xtimes(x,2))^
	(((y >> 3) & 0x01)*xtimes(x,3))^
	(((y >> 4) & 0x01)*xtimes(x,4))^
	(((y >> 5) & 0x01)*xtimes(x,5))^
	(((y >> 6) & 0x01)*xtimes(x,6))^
	(((y >> 7) & 0x01)*xtimes(x,7))
}

func mulWord(x []byte,y []byte){
	tmp := make([]byte,4);
	copy(tmp,x);
	x[0] = mulByte(tmp[0],y[3])^mulByte(tmp[1],y[0])^mulByte(tmp[2],y[1])^mulByte(tmp[3],y[2])
	x[1] = mulByte(tmp[0],y[2])^mulByte(tmp[1],y[3])^mulByte(tmp[2],y[0])^mulByte(tmp[3],y[1])
	x[2] = mulByte(tmp[0],y[1])^mulByte(tmp[1],y[2])^mulByte(tmp[2],y[3])^mulByte(tmp[3],y[0])
	x[3] = mulByte(tmp[0],y[0])^mulByte(tmp[1],y[1])^mulByte(tmp[2],y[2])^mulByte(tmp[3],y[3])
}


func (a *AES) mixCols(state []byte){
	s := []byte{0x03,0x01,0x01,0x02}
	for i := 0; i < len(state);i+=4{
		mulWord(state[i:i+4],s)
	}
}

func (a *AES) invmixCols(state []byte){
	s := []byte{0x0b,0x0d,0x09,0x0e}
	for i := 0; i < len(state); i+=4{
		mulWord(state[i:i+4],s)
	}
}

// encryptBlock encrypts a single block of plaintext
func (a *AES) encryptBlock(state []byte,roundKeys []uint32){
	a.addRoundkey(state,roundKeys[0:4]);
	for round := 1; round < a.nr; round++{
		a.subBytes(state)
		a.shiftRows(state)
		a.mixCols(state)
		a.addRoundkey(state,roundKeys[4*round:4*round+4])
	}
	a.subBytes(state)
	a.shiftRows(state)
	a.addRoundkey(state,roundKeys[a.nr*4:a.nr*4+4])
}

// DecryptBlock decrypts a single block of ciphertext
func (a *AES) DecryptBlock(state []byte,roundKeys []uint32){
	a.addRoundkey(state,roundKeys[a.nr*4:a.nr*4+4])
	a.invsubBytes(state)
	a.invshiftRows(state)
	for round := a.nr-1; round > 0; round--{
		a.invmixCols(state)
		a.addRoundkey(state,roundKeys[4*round:4*round+4])
		a.invsubBytes(state)
		a.invshiftRows(state)
	}
	a.addRoundkey(state,roundKeys[0:4]);
}

func inc32(X []byte)([] byte){
	lsb32 := binary.BigEndian.Uint32(X[len(X)-4:]) + 1
	binary.BigEndian.PutUint32(X[len(X)-4:],lsb32)
	return X
}

func mulBlock(x []byte,y []byte){
	tmp := big.NewInt(0).SetBytes([]byte{0xe1})

	R := tmp.Lsh(tmp,120);
	X := big.NewInt(0).SetBytes(x)
	Z := big.NewInt(0)
	V := big.NewInt(0).SetBytes(y)

	for i := 0; i < 128; i++{
		if X.Bit(127-i) == 1{
			Z.Xor(Z,V)
		} 
		if V.Bit(0) == 0{
			V.Rsh(V,1)
		} else {
			V.Xor(V.Rsh(V,1),R)
		}
	}
	Z.FillBytes(x)
}