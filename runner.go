package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func RunInteractive(req ParsedRequest, attackerDomain string) {
	scanner := bufio.NewScanner(os.Stdin)
	total := len(Payloads)

	for i, payload := range Payloads {
		modified := payload.Apply(req, attackerDomain)

		fmt.Printf("\n--- Payload %d/%d — %s ---\n", i+1, total, payload.Name)
		fmt.Printf("Description: %s\n", payload.Description)
		fmt.Printf("Mode: %s\n\n", payload.Mode)
		fmt.Println("Request to send:")
		PrintRequest(modified)

		fmt.Print("\n[*] Press Enter to send, q to quit: ")
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())
		if input == "q" {
			fmt.Println("Quitting...")
			return
		}

		// sending logic goes here later
		fmt.Println("[*] Sent. Response code: (not implemented yet)")

		fmt.Print("Result (y/n/q with optional notes after dot): ")
		scanner.Scan()
		input = strings.TrimSpace(scanner.Text())

		if input == "q" {
			fmt.Println("Quitting...")
			return
		}

		var result, notes string

		if strings.HasPrefix(strings.ToLower(input), "y") {
			result = "interesting"
		} else {
			result = "no-impact"
		}

		if idx := strings.Index(input, "."); idx != -1 {
			notes = strings.TrimSpace(input[idx+1:])
		}

		fmt.Printf("[*] Logged: %s", result)
		if notes != "" {
			fmt.Printf(" - %s", notes)
		}

		fmt.Println()
	}
}
