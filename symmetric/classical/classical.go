package classical

import (
	"crypto/internal/utils"
	"errors"
	"fmt"
	"strings"
	"sort"
)

func shiftChar(char byte,shift int,base byte) byte{
	return byte((int(char-base) + shift) % 26 + int(base))
}

func Caesar(inputText string,key int)(string,error){
	if len(inputText) == 0{
		return "",errors.New("plainText should be non-empty")
	}
	var builder strings.Builder;
	for i := 0; i < len(inputText); i++{
		char := inputText[i];
		if char >= 'A' && char <= 'Z'{
			builder.WriteByte(shiftChar(char,key,'A'))
		} else if char >= 'a' && char <= 'z'{
			builder.WriteByte(shiftChar(char, key , 'a'))
		} else {
			builder.WriteByte(char)
		}

	}
	return builder.String(),nil;
}
func Affine(inputText string,a int,b int)(string,error){
	fmt.Println(utils.GCD(26,b))
	if(utils.GCD(26,b) != 1){
		return "",errors.New("invalid multiplication key, key must coprime with 26")
	}
	var builder strings.Builder;
	for i := 0; i < len(inputText); i++{
		char := inputText[i];
		if char >= 'A' && char <= 'Z'{
			builder.WriteByte(byte((a * int(char - 'A') + b)% 26 + 'A' ))
		} else if char >= 'a' && char <= 'z'{
			builder.WriteByte(byte((a * int(char - 'a') + b)% 26 + 'a'))
		} else {
			builder.WriteByte(char)
		}

	}
	return builder.String(),nil
}

func Vigenere(inputText string, key string)(string,error){
	key = strings.ToLower(key)
	keyLen := len(key);
	var builder strings.Builder;
	for i := 0; i < len(inputText); i++{
		char := inputText[i];
		if char >= 'A' && char <= 'Z'{
			builder.WriteByte(shiftChar(char,int(key[i%keyLen] - 'a'),'A'))
		} else if char >= 'a' && char <= 'z'{
			builder.WriteByte(shiftChar(char,int(key[i%keyLen] - 'a'),'a'))
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
	for i := 0; i <  len(key); i++{
		char1 := key[i]
		char2 := inputText[i]
		builder.WriteByte(byte(int(char1 - 'a') ^ int(char2 - 'a'))%26 + 'a')
	}
	return builder.String(),nil;
}


func Columnar(inputText string, key string)(string,error){

	if (len(inputText) == 0 || len(key) == 0){
		return "",errors.New("plain Text and length must be non empty")
	}
	if (len(inputText) % len(key) != 0){
		return "",errors.New("plain Text Length must be divisible by key length")
	}
	rows := len(inputText) / len(key)
	cols := len(key)
	matrix := make([][]byte,rows)

	for i := range matrix{
		matrix[i] = make([]byte, cols)
	}

	charIndex := 0
	for i := 0; i < rows; i++{
		for j := 0; j < cols; j++{
			matrix[i][j] = inputText[charIndex]
			charIndex++
		}
	}
	columnOrder := make([]int,cols)

	for i := 0; i <  cols; i++{
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

