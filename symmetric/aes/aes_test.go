package aes

import (
	// "crypto/internal/utils"
	"testing"
	"reflect"
)

func TestKeyExpansion(t *testing.T){
	var keyExpansionTests = []struct {
		key       []byte   // key
		roundKeys []uint32 // expected roundkeys
	}{
		{
			key: []byte{
				0x69, 0x61, 0x6D, 0x53, 0x74, 0x61, 0x65, 0x76,
				0x96, 0xC6, 0xCC, 0x6C, 0x69, 0x6E, 0x67, 0x77,
			},
			roundKeys: []uint32{
				0x69616d53, 0x74616576, 0x96c6cc6c, 0x696e6777,
				0xf7e498aa, 0x8385fddc, 0x154331b0, 0x7c2d56c7,
				0x2d555eba, 0xaed0a366, 0xbb9392d6, 0xc7bec411,
				0x8749dc7c, 0x29997f1a, 0x920aedcc, 0x55b429dd,
				0x02ec1d80, 0x2b75629a, 0xb97f8f56, 0xeccba68b,
				0x0dc8204e, 0x26bd42d4, 0x9fc2cd82, 0x73096b09,
				0x2cb721c1, 0x0a0a6315, 0x95c8ae97, 0xe6c1c59e,
				0x14112a4f, 0x1e1b495a, 0x8bd3e7cd, 0x6d122253,
				0x5d82c773, 0x43998e29, 0xc84a69e4, 0xa5584bb7,
				0x2c316e75, 0x6fa8e05c, 0xa7e289b8, 0x02bac20f,
				0xee141802, 0x81bcf85e, 0x265e71e6, 0x24e4b3e9,
			},
		},

	}
	for _,tuple := range keyExpansionTests{
		a, err := newAes(tuple.key);
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a.roundkeys,tuple.roundKeys){
			t.Fatalf("Key Expansion Test failed with %d key Length", 8*(a.len))
		}
	}

}