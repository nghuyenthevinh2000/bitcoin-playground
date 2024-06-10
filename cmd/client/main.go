package main

import (
	"fmt"
	"net"
)

func main() {
	// Open a TCP connection to an IP and port
	conn, err := net.Dial("tcp", "45.144.112.208:8333")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()

	fmt.Printf("Connected to %s\n", conn.RemoteAddr())

	// # 1. Send Version Message
	// # 2. Receive Version Message
	// # 3. Receive Verack Message
	// # 4. Send Verack Message

	// 	────────────┼──────────────┼───────────────┼───────┼─────────────────────────────────────┤
	// │ Magic Bytes │              │ bytes         │     4 │ F9 BE B4 D9                         │
	// │ Command     │ "version"    │ ascii bytes   │    12 │ 76 65 72 73 69 6F 6E 00 00 00 00 00 │
	// │ Size        │ 85           │ little-endian │     4 │ 55 00 00 00                         │
	// │ Checksum    │              │ bytes         │     4 │ F7 63 9C 60

	versionMessage := []byte{
		0xf9, 0xbe, 0xb4, 0xd9, // Magic bytes
		0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, // Command
		0x55, 0x00, 0x00, 0x00, // Size
		0xf7, 0x63, 0x9c, 0x60, // Checksum
	}

	n, err := conn.Write(versionMessage)
	if err != nil {
		fmt.Println("Error writing to server:", err)
		return
	}

	fmt.Printf("Sent %d bytes\n", n)

	for {
		magicBytes := make([]byte, 24)
		n, err := conn.Read(magicBytes)
		if err != nil {
			fmt.Println("Error reading from server:", err)
			return
		}

		fmt.Printf("Received %d bytes\n", n)
		fmt.Printf("Received: %x\n", magicBytes)

		// command     = socket.read(12)

		command := make([]byte, 12)
		n, err = conn.Read(command)
		if err != nil {
			fmt.Println("Error reading from server:", err)
			return
		}

		fmt.Printf("Received %d bytes\n", n)
		fmt.Printf("Received: %x\n", command)

		// size        = socket.read(4)
		// checksum    = socket.read(4)

		size := make([]byte, 4)
		n, err = conn.Read(size)
		if err != nil {
			fmt.Println("Error reading from server:", err)
			return
		}

		fmt.Printf("Received %d bytes\n", n)
		fmt.Printf("Received: %x\n", size)

		checksum := make([]byte, 4)
		n, err = conn.Read(checksum)
		if err != nil {
			fmt.Println("Error reading from server:", err)
			return
		}

		fmt.Printf("Received %d bytes\n", n)
		fmt.Printf("Received: %x\n", checksum)

	}
}
