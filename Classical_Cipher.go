package main

import (
	"crypto/utils"
	"errors"
	"fmt"
)

func ceaser(s string,key int)(string){
	var cipherText string;
	for i := 0; i < len(s); i++{
		char := s[i];
		if char >= 'A' && char <= 'Z'{
			cipherText += string((int(char - 'A') + key) % 26 + 'A')
		} else if char >= 'a' && char <= 'z'{
			cipherText += string((int(char - 'a') +  key)% 26 + 'a')
		} else {
			cipherText += string(char)
		}

	}
	return cipherText;
}
func affine(s string,a int,b int)(string,error){
	var cipherText string;
	fmt.Println(utils.GCD(26,b))
	if(utils.GCD(26,b) != 1){
		return "",errors.New("invalid multiplication key, key must coprime with 26")
	}
	for i := 0; i < len(s); i++{
		char := s[i];
		if char >= 'A' && char <= 'Z'{
			cipherText += string(((int(char - 'A') + a)*b) % 26 + 'A')
		} else if char >= 'a' && char <= 'z'{
			cipherText += string(((int(char - 'a') +  a)*b)% 26 + 'a')
		} else {
			cipherText += string(char)
		}

	}
	return cipherText,nil
}

func vignere(s string, key string)(string,error){
	
}

func main(){
	fmt.Println(affine("Hello",5,13))
}