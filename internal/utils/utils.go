package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func GCD(i, b int) int {
	if b == 0 {
		return i;
	}
	return GCD(b,i%b);
}

func DumpWords(note string,in []uint32){
	fmt.Printf("%s",note)
	for i,v := range in{
		if i%4 == 0{
			fmt.Printf("\nword[%02d]: %.8x",i/4,v)
		} else {
			fmt.Printf("\n %.8x",v)
		}
	}
	fmt.Println("\n")
}

func Dumpbytes(note string,in []byte){
	fmt.Printf("%s",note)
	for i,v := range in{
		if i%16 == 0{
			fmt.Printf("\nblock[%d]: %02x",i/16,v)
		} else {
			if i%4 == 0{
				fmt.Printf(" %02x",v)
			} else {
				fmt.Printf("%02x",v)
			}
		}
	}
	fmt.Println("\n")
}
