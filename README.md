# Crypto

A Go implementation of cryptographic algorithms and hash functions.

## Overview

This project provides pure Go implementations of various cryptographic primitives and hash functions. The goal is to provide educational and usable implementations of common cryptographic algorithms for learning and practical purposes.

## Features

- Hash functions: SHA-256
- Symmetric encryption: AES (CBC, GCM modes)
- Classical ciphers: Caesar, Affine, Vigenere, One-time pad, Columnar
- Key derivation: HMAC, HKDF
- Digital signatures: ECDSA
- Key exchange: Curve25519 ECDH

## Installation

```bash
go get github.com/SanthoshCheemala/Crypto
```

## Usage Examples

### Hash Functions

#### SHA-256

```go
package main

import (
    "fmt"
    "encoding/hex"
    
    "github.com/SanthoshCheemala/Crypto/hash"
)

func main() {
    // Create a new SHA-256 state
    s := hash.NewSHA256State()
    
    // Hash some data
    data := []byte("your data here")
    s.Sha256(data)
    
    // Get the hash value
    fmt.Printf("Hash: %x\n", s.Sum())
    
    // You can continue updating the same hash state
    moreData := []byte("more data")
    s.Sha256(moreData)
    fmt.Printf("Updated hash: %x\n", s.Sum())
}
```

### Symmetric Encryption

#### AES-CBC Mode

```go
package main

import (
    "fmt"
    
    "github.com/SanthoshCheemala/Crypto/symmetric/aes"
    "github.com/SanthoshCheemala/Crypto/internal/utils"
)

func main() {
    // Initialize AES with a 128-bit key
    key := []byte{
        0x69, 0x61, 0x6D, 0x53, 0x74, 0x61, 0x65, 0x76,
        0x96, 0xC6, 0xCC, 0x6C, 0x69, 0x6E, 0x67, 0x77,
    }
    
    // Initialization vector for CBC mode
    iv := []byte{
        0x50, 0x72, 0x65, 0x6E, 0x74, 0x69, 0x63, 0x65,
        0x48, 0x61, 0x6C, 0x6C, 0x49, 0x6E, 0x63, 0x2E,
    }
    
    // Create a new AES cipher
    cipher, err := aes.NewAes(key)
    if err != nil {
        panic(err)
    }
    
    // Data to encrypt
    plaintext := []byte("This is a secret message")
    
    // Encrypt with CBC mode
    ciphertext := cipher.EncryptCBC(plaintext, iv, utils.PKCS7Padding)
    fmt.Printf("Ciphertext: %x\n", ciphertext)
    
    // Decrypt with CBC mode
    decrypted := cipher.DecryptCBC(ciphertext, iv, utils.PKCS7UnPadding)
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

#### AES-GCM Mode

```go
package main

import (
    "fmt"
    
    "github.com/SanthoshCheemala/Crypto/symmetric/aes"
)

func main() {
    // Initialize AES with a 128-bit key
    key := []byte{
        0x69, 0x61, 0x6D, 0x53, 0x74, 0x61, 0x65, 0x76,
        0x96, 0xC6, 0xCC, 0x6C, 0x69, 0x6E, 0x67, 0x77,
    }
    
    // Nonce for GCM mode
    nonce := []byte{
        0x50, 0x72, 0x65, 0x6E, 0x74, 0x69, 0x63, 0x65,
        0x48, 0x61, 0x6C, 0x6C,
    }
    
    // Additional authenticated data
    aad := []byte("Additional data to authenticate")
    
    // Create a new AES cipher
    cipher, err := aes.NewAes(key)
    if err != nil {
        panic(err)
    }
    
    // Data to encrypt
    plaintext := []byte("This is a secret message")
    
    // Encrypt with GCM mode
    ciphertext, tag := cipher.EncryptGCM(plaintext, nonce, aad, 16)
    fmt.Printf("Ciphertext: %x\n", ciphertext)
    fmt.Printf("Auth Tag: %x\n", tag)
    
    // Decrypt with GCM mode
    decrypted := cipher.DecryptGCM(ciphertext, nonce, aad, tag)
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

### Classical Ciphers

#### Caesar Cipher

```go
package main

import (
    "fmt"
    
    "github.com/SanthoshCheemala/Crypto/symmetric/classical"
)

func main() {
    plaintext := "HELLO WORLD"
    key := 3 // shift by 3 positions
    
    // Encrypt
    ciphertext, err := classical.Caesar(plaintext, key)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Caesar Encrypted: %s\n", ciphertext)
    
    // Decrypt (shift in the opposite direction)
    decrypted, err := classical.Caesar(ciphertext, -key)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Caesar Decrypted: %s\n", decrypted)
}
```

#### Vigenere Cipher

```go
package main

import (
    "fmt"
    
    "github.com/SanthoshCheemala/Crypto/symmetric/classical"
)

func main() {
    plaintext := "HELLO WORLD"
    key := "KEY"
    
    // Encrypt
    ciphertext, err := classical.Vigenere(plaintext, key)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Vigenere Encrypted: %s\n", ciphertext)
    
    // To decrypt, you would need to implement a separate function or
    // modify the Vigenere function to support decryption
}
```

### Key Derivation Functions

#### HMAC

```go
package main

import (
    "fmt"
    "encoding/hex"
    
    "github.com/SanthoshCheemala/Crypto/kdf/hmac"
)

func main() {
    key := []byte("secret key")
    message := []byte("message to authenticate")
    
    // Generate HMAC
    mac := hmac.HMAC_Sign(key, message)
    fmt.Printf("HMAC: %x\n", mac)
    
    // Verify HMAC
    isValid := hmac.HMAC_Verify(key, message, mac)
    fmt.Printf("HMAC Valid: %t\n", isValid)
    
    // Verify with tampered message
    tamperedMessage := []byte("tampered message")
    isValidTampered := hmac.HMAC_Verify(key, tamperedMessage, mac)
    fmt.Printf("Tampered HMAC Valid: %t\n", isValidTampered) // Should be false
}
```

### Digital Signatures

#### ECDSA

```go
package main

import (
    "crypto/rand"
    "fmt"
    
    "github.com/SanthoshCheemala/Crypto/asymmetric/signature"
    "github.com/glycerine/fast-elliptic-curve-p256/elliptic"
)

func main() {
    // Generate key pair
    privateKey, err := signature.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        panic(err)
    }
    
    // Message to sign
    message := []byte("message to sign")
    
    // Sign message
    r, s, err := signature.Sign(rand.Reader, privateKey, message)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Signature (r, s): %x, %x\n", r, s)
    
    // Verify signature
    valid := signature.Verify(&privateKey.PublicKey, message, r, s)
    fmt.Printf("Signature Valid: %t\n", valid)
    
    // Verify with tampered message
    tamperedMessage := []byte("tampered message")
    validTampered := signature.Verify(&privateKey.PublicKey, tamperedMessage, r, s)
    fmt.Printf("Tampered Signature Valid: %t\n", validTampered) // Should be false
}
```

### Key Exchange

#### Curve25519 ECDH

```go
package main

import (
    "fmt"
    "encoding/hex"
    
    "github.com/SanthoshCheemala/Crypto/asymmetric/ecdh25519"
)

func main() {
    // Generate key pair for Alice
    alicePrivate, err := ecdh25519.GenerateKey()
    if err != nil {
        panic(err)
    }
    alicePublic := alicePrivate.Public()
    
    // Generate key pair for Bob
    bobPrivate, err := ecdh25519.GenerateKey()
    if err != nil {
        panic(err)
    }
    bobPublic := bobPrivate.Public()
    
    // Alice computes shared secret
    aliceSharedSecret, err := alicePrivate.ComputeSecret(bobPublic)
    if err != nil {
        panic(err)
    }
    
    // Bob computes shared secret
    bobSharedSecret, err := bobPrivate.ComputeSecret(alicePublic)
    if err != nil {
        panic(err)
    }
    
    // The shared secrets should be identical
    fmt.Printf("Alice's shared secret: %x\n", aliceSharedSecret)
    fmt.Printf("Bob's shared secret: %x\n", bobSharedSecret)
    
    // Verify they match
    match := hex.EncodeToString(aliceSharedSecret) == hex.EncodeToString(bobSharedSecret)
    fmt.Printf("Shared secrets match: %t\n", match) // Should be true
}
```

## Implementation Details

This library implements various cryptographic algorithms following their respective standards:

- SHA-256: Follows FIPS PUB 180-4
- AES: Implements the Advanced Encryption Standard (FIPS 197)
- HMAC: Follows RFC 2104
- ECDSA: Implements Elliptic Curve Digital Signature Algorithm
- Curve25519: Implements the X25519 key exchange as specified in RFC 7748

All implementations are in pure Go, making them suitable for educational purposes and understanding the underlying algorithms.

## Security Note

While this library aims to implement cryptographic algorithms correctly, it is primarily intended for educational purposes. For production applications, consider using Go's standard crypto packages or other well-audited cryptographic libraries.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
