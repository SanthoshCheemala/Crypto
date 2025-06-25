package hash

import (
	"encoding/binary"

	"github.com/SanthoshCheemala/Crypto/internal/utils"
)

type SHA256State struct{
	State []uint32
}

var k = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}


func NewSHA256State() *SHA256State {
    return &SHA256State{
        State: []uint32{
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        },
    }
}

func (s *SHA256State) Sha256(msg []byte) *SHA256State{
	in := []byte(msg)
	paddedMessage := utils.MDPadding(in)
	for i := 0; i < len(paddedMessage); i += 64{
		s.processBlock(paddedMessage[i:i+64])
	}
	return s
}

func (s *SHA256State) processBlock(block []byte){
	currentStateCopy := make([]uint32,len(s.State))
	copy(currentStateCopy,s.State)
	newHash := compressFun(block, currentStateCopy)
	for i := 0; i < 8; i++ {
		s.State[i] = newHash[i]
	}
}

func compressFun(block []byte, hash []uint32) []uint32 {
	w := make([]uint32,64)

	for i := 0; i < 16; i ++{
		w[i] = binary.BigEndian.Uint32(block[i*4:i*4+4])
	}

	for i := 16; i < len(w); i++{
		w[i] = w[i-16] + sigma0(w[i-15]) + w[i-7] + sigma1(w[i-2])
	}

    a, b, c, d, e, f, g, h := hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]

	for i := 0; i < 64;i++{
		t1 := h + w[i] + k[i] + ch(e,f,g) +  Σ1(e)
		t2 := Ma(a,b,c) + Σ0(a)
		h = g
		g = f
		f = e
		e = t1 + d
		d = c
		c = b
		b = a
		a = t1 + t2
	}
	hash[0] += a
    hash[1] += b
    hash[2] += c
    hash[3] += d
    hash[4] += e
    hash[5] += f
    hash[6] += g
    hash[7] += h
	return hash
}

func (s *SHA256State) Sum() []byte{
	result := make([]byte,len(s.State)*4)
	for i := 0; i < len(s.State); i ++{
		binary.BigEndian.PutUint32(result[i*4:i*4+4],s.State[i])
	}
	return result
}



func Σ1(e uint32) uint32 {
	return ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25)
}

func Σ0(a uint32) uint32 {
		return ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22)
}

func Ma(a, b, c uint32) uint32 {
	return (a & b) ^ (a & c) ^ (b & c)
}

func ch(e, f, g uint32) uint32 {
	return (e & f) ^ ((^e) & g)
}

func sigma0(u uint32) uint32 {
	return ROTR(u,7) ^ ROTR(u,18) ^ SHR(u,3)
}
func sigma1(u uint32) uint32 {
	return ROTR(u,17) ^ ROTR(u,19) ^ SHR(u,10)
}


func SHR(u uint32, i int) uint32 {
	return u>>i
}

func ROTR(u uint32, i int) uint32 {
	return (u >> i) | (u << (32 - i))
}

