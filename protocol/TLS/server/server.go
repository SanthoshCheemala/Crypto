package server

import (
	"fmt"
	"io"
	"log"
	"net"
)

func Server() {
	l,err := net.Listen("tcp","8080")
	if err != nil {
		log.Println("error: ",err)
	}

	defer l.Close()

	for {
		conn, err := l.Accept()

		if err != nil {
			log.Println("error: %v",err)
			continue
		}
		go handleConnection(conn)
		
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte,1024)

	for {
		n, err := conn.Read(buffer)

		if err != nil {
			if err != io.EOF {
				log.Println("read error: ",err)
			}
			return
		}
		message := string(buffer[:n])
		
		fmt.Printf("message received: %s",message)
		msg := ""
		fmt.Printf("Enter Your Message: ")
		fmt.Scanln(&msg)
		_,err = conn.Write([]byte(msg))

		if err != nil {
			log.Printf("write error: %v",err)
			return
		}

	}
}