package main

import (
	"crypto/utils"
	"errors"
	"fmt"
	"strings"
	"sort"
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
	fmt.Println(utils.GCD(26,b))
	if(utils.GCD(26,b) != 1){
		return "",errors.New("invalid multiplication key, key must coprime with 26")
	}
	var builder 
	for i := 0; i < len(inputText); i++{
		char := inputText[i];
		if char >= 'A' && char <= 'Z'{
			cipherText += string(((int(shiftChar(char,a,'A')))*b) % 26 + 'A')
		} else if char >= 'a' && char <= 'z'{
			cipherText += string(((int(shiftChar(char,a,'a')))*b)% 26 + 'a')
		} else {
			cipherText += string(char)
		}

	}
	return cipherText,nil
}

func vignere(inputText string, key string)(string,error){
	key = strings.ToLower(key)
	keyLen := len(key);
	var builder strings.Builder;
	for i := 0; i < len(inputText); i++{
		char := inputText[i];
		if char >= 'A' && char <= 'Z'{
			builder.WriteByte((((shiftChar(char,int(key[i%keyLen] - 'a'),'A'))%26) + 'A'))
		} else if char >= 'a' && char <= 'z'{
			builder.WriteByte(((shiftChar(char,int(key[i%keyLen] - 'a'),'a'))%26) + 'a')
		} else {
			builder.WriteByte((char))
		}
	}
	return builder.String(),nil
}

func one_time_pad(inputText string, key string)(string,error){
	if len(inputText) != len(key){
		return "",errors.New("key length must be same as message length")
	}
	var builder strings.Builder
	for i := range len(key){
		char1 := key[i]
		char2 := inputText[i]
		builder.WriteByte(byte(int(char1 - 'a') ^ int(char2 - 'a'))%26 + 'a')
	}
	return builder.String(),nil;
}


func columner(inputText string, key string)(string,error){

	if (len(inputText) == 0 || len(key) == 0){
		return "",errors.New("plaintext and length must be non empty")
	}
	if (len(inputText) % len(key) != 0){
		return "",errors.New("inputText Length must be divisible by key length")
	}
	rows := len(inputText) / len(key)
	cols := len(key)
	matrix := make([][]byte,rows)

	for i := range matrix{
		matrix[i] = make([]byte, cols)
	}

	charIndex := 0
	for i := range rows{
		for j := 0; j < cols; j++{
			matrix[i][j] = inputText[charIndex]
			charIndex++
		}
	}
	columnOrder := make([]int,cols)

	for i := range cols{
		columnOrder[i] = i
	}
	sort.Slice(columnOrder, func(i, j int) bool{
		return key[columnOrder[i]] < key[columnOrder[j]]
	})
	var builder strings.Builder
	builder.Grow(len(inputText))
	for j := 0; j < cols; j++{
		col := columnOrder[j]
		for i := 0; i < rows; i++{
			builder.WriteByte(matrix[i][col])
		}
	}
	return builder.String(),nil
}

func main(){
	fmt.Println(columner("santhosh","keys"))
}