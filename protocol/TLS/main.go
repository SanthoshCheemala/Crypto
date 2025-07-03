package main

import (
	"fmt"
	"os"

	"github.com/SanthoshCheemala/Crypto/protocol/TLS/client"
	"github.com/SanthoshCheemala/Crypto/protocol/TLS/server"
)



func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go [server|client]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		server.Server()
	case "client":
		client.Client()
	default:
		fmt.Println("Invalid argument. Use 'server' or 'client'")
		os.Exit(1)
	}
}