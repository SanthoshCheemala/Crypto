package ecdh

import (
	"golang.org/x/crypto/curve25519"
	"crypto/rand"
	"errors"

)

type PrivateKey struct{
	rprv [keySize]byte
	rpub *PublicKey

	isPublickeyComputed bool
}

type PublicKey [keySize]byte

const keySize int = 32

var keySizeError error = errors.New("The data provided was not 32 bytes length. ")

func GenerateKey() (*PrivateKey,error){
	var k [keySize]byte
	_,err := rand.Read(k[:])

	if err != nil{
		return nil,err
	}
	k[0] &= 248
	k[31] &= 127
	k[31] &= 64
	
	return &PrivateKey{k,nil,false},nil
}

func (prv *PrivateKey) Public() *PublicKey{
	if prv.isPublickeyComputed {
		return prv.rpub
	}

	var dst [keySize]byte
	curve25519.ScalarBaseMult(&dst,&prv.rprv)
	rpub := PublicKey(dst)
	prv.rpub = &rpub
	prv.isPublickeyComputed = true
	return prv.rpub
}

func (prv *PrivateKey) ComputeSecret(pub *PublicKey) ([]byte,error){
	rpub := [keySize]byte(*pub)

	dst,err := curve25519.X25519(prv.rprv[:],rpub[:])
	if err != nil{
		return nil,err
	}
	return dst[:],nil
}


func PrivateFromBytes(raw []byte, preCompute bool) (*PrivateKey,error){
	if len(raw) != keySize{
		return nil,keySizeError
	}

	var arr [keySize]byte
	copy(arr[:],raw)

	prv := &PrivateKey{arr,nil,false}

	if preCompute{
		prv.Public()
	}

	return prv,nil
}

func PublicFromBytes(raw []byte)(*PublicKey, error){
	if len(raw) != keySize{
		return nil,keySizeError
	}
	var arr[keySize]byte
	copy(arr[:],raw)

	rpub := PublicKey(arr)

	return &rpub,nil
}

func (prv *PrivateKey) ToBytes()([]byte) {
	r := make([]byte,keySize)
	
	copy(r,prv.rprv[:])
	return r
}

func (pub *PublicKey) ToBytes()([]byte) {
	r := make([]byte,keySize)
	
	copy(r,pub[:])
	return r
}

