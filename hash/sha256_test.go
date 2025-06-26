package hash

import (
	"encoding/hex"
	"reflect"
	"testing"
)


func TestSha256(t *testing.T){
	var (
		msg = "this is message.Please hash this value"
		hexhashmsg = "da64e014912667baead7f1d5dc4262b28bbf547e00cb3b5a9171f43e8bf8f006"
	)

	h := NewSHA256State()
	h.Sha256([]byte(msg))
	if !reflect.DeepEqual(hex.EncodeToString(h.Sum()),hexhashmsg){
		t.Fatalf("hashing failed")
	}
}

func BenchmarkSHA256(b *testing.B) {
	msg := "this is message.Please hash this value"

	for i := 0; i < b.N; i++ {
		NewSHA256State().Sha256([]byte(msg))
	}
	
}