package client

import (
	"fmt"
	"log"
	"net"
)


func Client() {
	conn , err := net.Dial("tcp","localhost:8080")
	if err != nil{
		log.Println("error: ",err)
	}
	defer conn.Close()
	flag := 1;
	for {
		msg := "";
		fmt.Printf("enter your message")
		fmt.Scanln(&msg)
		_,err := conn.Write([]byte(msg))
		if err != nil {
			log.Println(err)
		}
		buffer := make([]byte,1024)
		n,err := conn.Read(buffer)

		if err != nil {
			log.Println("read Error: ",err)
		}
		fmt.Printf("Messaged Received: %s",string(buffer[:n]))

		fmt.Println("do you want to continue ")
		fmt.Scan(&flag)
		if flag == 0 {
			break
		}
	}
}