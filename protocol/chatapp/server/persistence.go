package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/SanthoshCheemala/Crypto/asymmetric/signature"
	"github.com/glycerine/fast-elliptic-curve-p256/elliptic"
)

func loadOrGenerateSigningKey() (signature.PublicKey, signature.PrivateKey, error) {
    privKeyHex := os.Getenv("SERVER_PRIV_KEY")
    
    if privKeyHex != "" {
        log.Println("Using server signing key from environment variable")
        keyBytes, err := hex.DecodeString(strings.TrimSpace(privKeyHex))
        if err != nil {
            return signature.PublicKey{}, signature.PrivateKey{}, fmt.Errorf("failed to decode private key from env: %w", err)
        }
        
        curve := elliptic.P256()
        d := new(big.Int).SetBytes(keyBytes)
        x, y := curve.ScalarBaseMult(d.Bytes())
        
        priv := signature.PrivateKey{
            PublicKey: signature.PublicKey{
                Curve: curve,
                X:     x,
                Y:     y,
            },
            D: d,
        }
        
        return priv.PublicKey, priv, nil
    }
    
    serverKeyFilePath := os.Getenv("SERVER_KEY_FILE")
    
    if _, err := os.Stat(serverKeyFilePath); os.IsNotExist(err) {
        log.Println("No key file found. Generating new server signing key...")
        priv, err := signature.GenerateKey(elliptic.P256(), rand.Reader)
        if err != nil {
            return signature.PublicKey{}, signature.PrivateKey{}, err
        }
        
        privKeyBytes := priv.D.Bytes()
        err = os.WriteFile(serverKeyFilePath, []byte(hex.EncodeToString(privKeyBytes)), 0600)
        if err != nil {
            return signature.PublicKey{}, signature.PrivateKey{}, err
        }
        log.Printf("New key saved to %s", serverKeyFilePath)
        return priv.PublicKey, *priv, nil
    }

    log.Printf("Loading server signing key from %s...", serverKeyFilePath)
    hexKey, err := os.ReadFile(serverKeyFilePath)
    if err != nil {
        return signature.PublicKey{}, signature.PrivateKey{}, err
    }
    keyBytes, err := hex.DecodeString(strings.TrimSpace(string(hexKey)))
    if err != nil {
        return signature.PublicKey{}, signature.PrivateKey{}, err
    }
    
    curve := elliptic.P256()
    d := new(big.Int).SetBytes(keyBytes)
    x, y := curve.ScalarBaseMult(d.Bytes())
    
    priv := signature.PrivateKey{
        PublicKey: signature.PublicKey{
            Curve: curve,
            X:     x,
            Y:     y,
        },
        D: d,
    }
    
    return priv.PublicKey, priv, nil
}