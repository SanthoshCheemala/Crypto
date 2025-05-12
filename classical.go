package main

import (
	"crypto/utils"
	"errors"
	"fmt"
	"strings"
)

func shiftChar(char byte,shift int,base byte) byte{
	return byte((int(char-base) + shift) % 26 + int(base))
}

func ceaser(inputText string,key int)(string){
	var cipherText string
	for i := 0; i < len(inputText); i++{
		char := inputText[i];
		if char >= 'A' && char <= 'Z'{
			cipherText += string(shiftChar(char,key,'A'))
		} else if char >= 'a' && char <= 'z'{
			cipherText += string(shiftChar(char, key , 'a'))
		} else {
			cipherText += string(char)
		}

	}
	return cipherText;
}
func affine(inputText string,a int,b int)(string,error){
	var cipherText string
	fmt.Println(utils.GCD(26,b))
	if(utils.GCD(26,b) != 1){
		return "",errors.New("invalid multiplication key, key must coprime with 26")
	}
	for i := 0; i < len(inputText); i++{
		char := inputText[i];
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

func vignere(inputText string, key string)(string,error){
	var cipherText string
	key = strings.ToLower(key)
	keyLen := len(key);
	for i := 0; i < len(inputText); i++{
		char := inputText[i];
		if char >= 'A' && char <= 'Z'{
			cipherText += string((int(char - 'A') + (int(key[i%keyLen] - 'a'))%26) + 'A')
		} else if char >= 'a' && char <= 'z'{
			cipherText += string((int(char - 'a') + (int(key[i%keyLen] - 'a'))%26) + 'a')
		} else {
			cipherText += string(char)
		}
	}
	return cipherText,nil
}

func main(){
	cipherText,err := vignere("Hello this is santhosh", "cipher")
	if err != nil{
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Cipher Text: ",cipherText)
	}
	fmt.Println()
}