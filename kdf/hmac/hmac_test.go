package hmac

import (
	// "encoding/hex"
	// "fmt"
	"testing"
)

func TestVerifySign(t *testing.T) {
	var (
		message = "hello this message is in verification"
		key = "key is secret"
	)

	computed_mac := HMAC_Sign([]byte(key),[]byte(message))
	if !HMAC_Verify([]byte(key),[]byte(message),computed_mac){
		t.Fatalf("Verfy Failed")
	}
}

func testVaryKeyLength(t *testing.T,key []byte) {
	message := "hello this message is in verification"

	computed_mac := HMAC_Sign([]byte(key),[]byte(message))
	if !HMAC_Verify([]byte(key),[]byte(message),computed_mac){
		t.Fatalf("Verfy Failed")
	}
}

func TestVaryKeyLength(t *testing.T) {
	testVaryKeyLength(t,[]byte("")) // 0 bits

	if testing.Short() {
		return
	}
	testVaryKeyLength(t,[]byte("hello")) // < 256 bits
	testVaryKeyLength(t,[]byte("Time flies when coding in Go.")) // == 256 bits
	testVaryKeyLength(t,[]byte("This key have size greater than 256 bits")) // > 256 bits
}

func testVaryMessageLength(t *testing.T,message []byte) {
	key := "Time flies when coding in Go."

	computed_mac := HMAC_Sign([]byte(key),[]byte(message))
	if !HMAC_Verify([]byte(key),[]byte(message),computed_mac){
		t.Fatalf("Verfy Failed")
	}
}

func TestVaryMessageLength(t *testing.T) {
	testVaryMessageLength(t,[]byte("")) // 0 bits

	if testing.Short() {
		return
	}
	testVaryMessageLength(t,[]byte("hello")) // < 256 bits
	testVaryMessageLength(t,[]byte("Time flies when coding in Go.")) // == 256 bits
	testVaryMessageLength(t,[]byte("This message have bit size greater than 256 bits")) // > 256 bits
}

func TestMalformedKeyAndMessage(t *testing.T) {
		var (
			message = "hello this message is in verification"
			key = "key is secret"
		)
	
		computed_mac := HMAC_Sign([]byte(key),[]byte(message))
		// if HMAC_Verify([]byte("key is secret."),[]byte(message),computed_mac){
		// 	t.Fatalf("Two signatures should be different for different keys")
		// }
		if HMAC_Verify([]byte(key),[]byte("hello this message is different"),computed_mac) {
			t.Fatalf("Two signatures should be different for different message")
		}
}