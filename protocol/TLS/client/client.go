package client

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

func Client() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		log.Fatal("Error connecting to server: ", err)
	}
	defer conn.Close()

	fmt.Println("Connected to server at localhost:8080")

	// Start a goroutine to read server responses
	go func() {
		reader := bufio.NewReader(conn)
		for {
			message, err := reader.ReadString('\n')
			if err != nil {
				log.Println("Server disconnected: ", err)
				os.Exit(1)
			}
			fmt.Print("\nServer: ", message)
			fmt.Print("You: ") // Re-print the prompt
		}
	}()

	// Read user input and send to server
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("You: ")
	for scanner.Scan() {
		message := scanner.Text()

		if strings.ToLower(message) == "exit" {
			fmt.Println("Disconnecting from server...")
			return
		}

		_, err := conn.Write([]byte(message + "\n"))
		if err != nil {
			log.Println("Error sending message: ", err)
			return
		}

		fmt.Print("You: ")
	}

	if err := scanner.Err(); err != nil {
		log.Println("Error reading input: ", err)
	}
}