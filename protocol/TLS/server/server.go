package server

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

func Server() {
	l, err := net.Listen("tcp", ":8080") 
	if err != nil {
		log.Fatal("Error starting server: ", err) 
	}

	defer l.Close()
	fmt.Println("Server started on :8080")
	
	serverInput := make(chan string)
	go readServerInput(serverInput)

	clients := make(map[net.Conn]bool)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println("Error accepting connection: ", err)
			continue
		}

		clients[conn] = true
		go handleConnection(conn, serverInput, clients)
	}
}

func readServerInput(input chan<- string) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Broadcast message: ")
		message, err := reader.ReadString('\n')
		if err != nil {
			log.Println("Error reading input:", err)
			continue
		}
		input <- strings.TrimSpace(message)
	}
}

func handleConnection(conn net.Conn, serverInput <-chan string, clients map[net.Conn]bool) {
	defer func() {
		conn.Close()
		delete(clients, conn)
		fmt.Printf("Client %s disconnected\n", conn.RemoteAddr())
	}()

	fmt.Printf("New client connected: %s\n", conn.RemoteAddr())

	go func() {
		for msg := range serverInput {
			// Send the message to all clients
			for client := range clients {
				_, err := client.Write([]byte(msg + "\n"))
				if err != nil {
					log.Printf("Error sending to client %s: %v", client.RemoteAddr(), err)
				}
			}
		}
	}()

	buffer := make([]byte, 1024)

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Println("Read error: ", err)
			}
			return
		}

		message := strings.TrimSpace(string(buffer[:n]))
		fmt.Printf("Message from %s: %s\n", conn.RemoteAddr(), message)

		_, err = conn.Write([]byte("Server received: " + message + "\n"))
		if err != nil {
			log.Printf("Write error: %v", err)
			return
		}
	}
}