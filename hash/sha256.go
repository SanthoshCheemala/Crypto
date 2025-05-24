package hash

import (
	"fmt"
	"github.com/SanthoshCheemala/Crypto/internal/utils"
)

type SHA256State struct{
	State []byte
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
	s.compressFun(block,tmp)
	s.addBytes(s.State,tmp)
}



func (s *SHA256State) addBytes(b []byte, tmp []byte) {
	panic("unimplemented")
}

func (s *SHA256State) compressFun(b []byte, tmp []byte) {
	panic("unimplemented")
}


