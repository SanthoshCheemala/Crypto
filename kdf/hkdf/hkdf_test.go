package hkdf

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

func decodeHex(s string) []byte {
	b,_ := hex.DecodeString(s)
	return b
}

func TestHKDF(t *testing.T) {
	ikm := decodeHex("0b0b0b0b0b0b0b0b0b0b0b")
	salt := decodeHex("000102030405060708090a0b0c")
	info := decodeHex("f0f1f2f3f4f5f6f7f8f9")
	length := 16

	okmExpected := decodeHex("d307356a0d2609a15cfaf24245b6c84b")
	okm,err := New(ikm,salt,info,length)
	if err != nil {
		t.Errorf("HKDF failed! %v",err)
	}
	if  !reflect.DeepEqual(okm,okmExpected) {
		fmt.Println(hex.EncodeToString(okm))
		t.Errorf("Hkdf failed! okmExpected is not equal to okm")
	}
}

func TestHKDF_EmptySalt(t *testing.T) {
	ikm := decodeHex("0b0b0b0b0b0b0b0b0b0b0b")
	salt := decodeHex("")
	info := decodeHex("f0f1f2f3f4f5f6f7f8f9")
	length := 16

	okmExpected := decodeHex("582d277ad9fdf7ac8361301b5e3edd62")
	okm,err := New(ikm,salt,info,length)
	if err != nil {
		t.Errorf("HKDF failed! %v",err)
	}
	if  !reflect.DeepEqual(okm,okmExpected) {
		fmt.Println(hex.EncodeToString(okm))
		t.Errorf("Hkdf failed! okmExpected is not equal to okm")
	}
}

func TestHKDF_TooLong(t *testing.T) {
	ikm := decodeHex("0b0b0b0b0b0b0b0b0b0b0b")
	info := decodeHex("f0f1f2f3f4f5f6f7f8f9")
	length := 255*32 + 1

	_,err := New(ikm,nil,info,length)
	if err == nil {
		t.Errorf("expected error due to excessive length, but got nil")
	}
}


func BenchmarkHKDF_32Bytes(b *testing.B) {
	ikm := decodeHex("0b0b0b0b0b0b0b0b0b0b0b")
	salt := decodeHex("000102030405060708090a0b0c")
	info := decodeHex("f0f1f2f3f4f5f6f7f8f9")
	length := 32

	for i := 0; i < b.N; i++ {
		New(ikm,salt,info,length)
	}
}


func BenchmarkHKDF_512Bytes(b *testing.B) {
	ikm := decodeHex("0b0b0b0b0b0b0b0b0b0b0b")
	salt := decodeHex("000102030405060708090a0b0c")
	info := decodeHex("f0f1f2f3f4f5f6f7f8f9")
	length := 512

	for i := 0; i < b.N; i++ {
		New(ikm,salt,info,length)
	}
}

func BenchmarkHKDF_4096Bytes(b *testing.B) {
	ikm := decodeHex("0b0b0b0b0b0b0b0b0b0b0b")
	salt := decodeHex("000102030405060708090a0b0c")
	info := decodeHex("f0f1f2f3f4f5f6f7f8f9")
	length := 4096

	for i := 0; i < b.N; i++ {
		New(ikm,salt,info,length)
	}
}

func BenchmarkHKDF_Bytes(b *testing.B) {
	ikm := decodeHex("0b0b0b0b0b0b0b0b0b0b0b")
	salt := decodeHex("000102030405060708090a0b0c")
	info := decodeHex("f0f1f2f3f4f5f6f7f8f9")
	length := 8160

	for i := 0; i < b.N; i++ {
		New(ikm,salt,info,length)
	}
}