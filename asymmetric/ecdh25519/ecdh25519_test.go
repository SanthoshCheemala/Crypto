package ecdh25519

import (
	"bytes"
	"reflect"
	"testing"
)


func TestGenrateKey(t *testing.T){
	prv1, err := GenerateKey()
	if err != nil {
		t.Error(err)
	}
	
	raw := prv1.ToBytes()
	prv2, err := PrivateFromBytes(raw, false)

	if err != nil{
		t.Error(err)
	}

	prv3, err := PrivateFromBytes(raw, true)
	
	if err != nil{
		t.Error(err)
	}

	if prv2.isPublickeyComputed || !prv3.isPublickeyComputed {
		t.Errorf("Publice Key Precomutation Failed: \nprv2: %v, Prv3: %v ",prv2.isPublickeyComputed,prv3.isPublickeyComputed)
	}


}

func TestComputeSecret(t *testing.T){
	prv1,err := GenerateKey()
	if err != nil{
		t.Error(err)
	}
	rpub1 := prv1.Public()

	prv2,err := GenerateKey()
	if err != nil{
		t.Error(err)
	}
	rpub2 := prv2.Public()

	sharedSecret1,err := prv1.ComputeSecret(rpub2)
	if err != nil{
		t.Error(err)
	}
	sharedSecret2,err := prv2.ComputeSecret(rpub1)
	if err != nil{
		t.Error(err)
	}
	if !reflect.DeepEqual(sharedSecret1,sharedSecret2){
		t.Fatalf("Secret Dont match")
	}
}

func TestMarshal(t *testing.T){
	prv1,err := GenerateKey()

	if err != nil{
		t.Error(err)
		return
	}

	pub1 := prv1.Public()

	rawPrv := prv1.ToBytes()
	rawPub := pub1.ToBytes()

	prv2,err := PrivateFromBytes(rawPrv,false)
	if err != nil{
		t.Error(err)
		return
	}
	pub2,err := PublicFromBytes(rawPub)
	if err != nil{
		t.Error(err)
		return
	}

	pubarr1 := [keySize]byte(*pub1)
	pubarr2 := [keySize]byte(*pub2)
	pubarr3 := [keySize]byte(*prv2.Public())

	prvc := bytes.Compare(prv2.rprv[:],prv1.rprv[:])
	pubc1 := bytes.Compare(pubarr2[:],pubarr1[:])
	pubc2 := bytes.Compare(pubarr3[:],pubarr2[:])

	if prvc != 0 || pubc1 != 0 || pubc2 != 0 {
		t.Errorf("Key Marshalling test failed")
	}


}

