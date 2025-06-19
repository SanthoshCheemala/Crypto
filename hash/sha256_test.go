package hash

import (
	"reflect"
	"testing"
)


func TestSha256(t *testing.T){
	var (
		msg = "this is message.Please hash this value"
		hexhashmsg = "da64e014912667baead7f1d5dc4262b28bbf547e00cb3b5a9171f43e8bf8f006"
	)

	h := NewSHA256State()
	h.Sha256(msg)
	if  !reflect.DeepEqual(h.Sum(),hexhashmsg){
		t.Fatalf("hashing failed")
	}
}