package hash

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/SanthoshCheemala/Crypto/internal/utils"
)

type SHA256State struct{
	State []byte
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


func NewSHA256State() *SHA256State{

	iv := []byte{
		0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
        0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
        0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
        0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
	}
	return &SHA256State{
		State: iv,
	}
}

func Sha256(msg string, iv []byte) *SHA256State{
	in := []byte(msg)
	fmt.Println(in)
	paddedMessage := utils.MDPadding(in)
	state := &SHA256State{
		State: make([]byte, len(iv)),
	}
	copy(state.State,iv)
	for i := 0; i < len(paddedMessage); i += 64{
		state.ProcessBlock(paddedMessage[i:i+64])
	}
	return state
}
func (s *SHA256State) ProcessBlock(block []byte){
	tmp := make([]byte,len(s.State))
	copy(tmp,s.State)
	s.State = compressFun(block,tmp)
	s.State = addMod32(s.State,tmp)
}



func  addMod32(b []byte, tmp []byte) []byte {
	if len(b) != len(tmp) || len(b)%4==0{
		panic("invalid input length")
	}
	for i := 0; i < len(b); i += 4{
		var tmp1 uint32
		var tmp2 uint32
		tmp1 = binary.BigEndian.Uint32(b[i:i+4])
		tmp2 = binary.BigEndian.Uint32(tmp[i:i+4])
		tmp3 := tmp1 + tmp2
		binary.BigEndian.PutUint32(b[i:i+4],tmp3)
	}
	return b
}


func compressFun(block []byte, hash []byte) []byte {
	tmp := make([]uint32,8)
	w := make([]uint32,64)
	for i := 0; i < 8; i++{
		tmp[i] = binary.BigEndian.Uint32(hash[i*4:i*4+4])
	}
	for i := 0; i < 16; i ++{
		w[i] = binary.BigEndian.Uint32(block[i*4:i*4+4])
	}
	for i := 16; i < len(w); i++{
		w[i] = w[i-16] + sigma0(w[i-15]) + w[i-7] + sigma1(w[i-2])
	}
    a, b, c, d, e, f, g, h := tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7]
	for i := 0; i < 64;i++{
		a, b, c, d, e, f, g, h = roundFunc(w[i],[8]uint32{a, b, c, d, e, f, g, h},k[i])
	}
	tmp[0] += a
    tmp[1] += b
    tmp[2] += c
    tmp[3] += d
    tmp[4] += e
    tmp[5] += f
    tmp[6] += g
    tmp[7] += h
	for i := 0; i < 8; i++{
		binary.BigEndian.PutUint32(hash[i*4:i*4+4],tmp[i])
	}
	return hash
}

func roundFunc(u1 uint32, u2 [8]uint32, u3 uint32) (uint32, uint32, uint32, uint32, uint32, uint32, uint32, uint32) {
	panic("unimplemented")
}

func sigma1(u uint32) uint32 {
	panic("unimplemented")
}

func sigma0(u uint32) uint32 {
	panic("unimplemented")
}


