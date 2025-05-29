package main

import (
	"fmt"

	"github.com/SanthoshCheemala/Crypto/hash"
)


func main(){
	s := hash.NewSHA256State()
	s.Sha256("2")
	fmt.Println(s.State)
	fmt.Println(s.Sum())
}