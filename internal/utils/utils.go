package utils

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)


type PaddingFunc func([]byte,int)([]byte)

type UnpaddingFunc func([]byte)([]byte)

func MustDecodeHex(s string) []byte{
	b,err := hex.DecodeString(s)
	if err != nil{
		panic(err)
	}
	return b;
}

func GCD(i, b int) int {
	if b == 0 {
		return i;
	}
	return GCD(b,i%b);
}

func DumpWords(note string,in []uint32){
	fmt.Printf("%s",note)
	for i,v := range in{
		if i%4 == 0{
			fmt.Printf("\nword[%02d]: %.8x",i/4,v)
		} else {
			fmt.Printf("\n %.8x",v)
		}
	}
	fmt.Printf("\n")
}

func Dumpbytes(note string,in []byte){
	fmt.Printf("%s",note)
	for i,v := range in{
		if i%16 == 0{
			fmt.Printf("\nblock[%d]: %02x",i/16,v)
		} else {
			if i%4 == 0{
				fmt.Printf(" %02x",v)
			} else {
				fmt.Printf("%02x",v)
			}
		}
	}
	fmt.Printf("\n")
}


func PKCS7Padding(in []byte,blockLen int)([] byte){
	tmp := make([]byte,len(in));
	copy(tmp,in);
	rmd := len(in) % blockLen;
	for i := 0; i < blockLen-rmd; i++{
		tmp = append(tmp, byte(blockLen-rmd))
	}
	return tmp
}

func PKCS7UnPadding(in []byte)([] byte){
	last := int(in[len(in)-1])
	tmp := make([]byte,len(in)-last);
	copy(tmp,in[:len(in)-last])
	return tmp;
}


func MDPadding(in []byte)([] byte){
	messageLenBits := uint64(len(in)) * 8

	padded := append(in, 0x80)

	for len(padded)%64 != 56 {
		padded = append(padded, 0x00)
	}

	lenBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBytes, messageLenBits)
	padded = append(padded, lenBytes...)

	return padded
}
