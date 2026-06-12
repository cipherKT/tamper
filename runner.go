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

	reporter, err := NewReporter(req)
	if err != nil {
		fmt.Println("Error creating report:", err)
		return
	}

	interesting := 0
	noImpact := 0

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
			reporter.Finalize(i, interesting, noImpact)
			return
		}

		statusCode, respBody, err := SendRequest(modified)
		if err != nil {
			fmt.Println("Error sending request:", err)
			continue
		}

		fmt.Printf("[*] Response: %d\n", statusCode)
		fmt.Printf("[*] Body: %s\n", respBody)

		fmt.Print("Result (y/n/q with optional notes after dot): ")
		scanner.Scan()
		input = strings.TrimSpace(scanner.Text())
		if input == "q" {
			fmt.Println("Quitting...")
			reporter.Finalize(i, interesting, noImpact)
			return
		}

		var result, notes string
		if strings.HasPrefix(strings.ToLower(input), "y") {
			result = "interesting"
			interesting++
		} else {
			result = "no-impact"
			noImpact++
		}

		if idx := strings.Index(input, "."); idx != -1 {
			notes = strings.TrimSpace(input[idx+1:])
		}

		fmt.Printf("[*] Logged: %s", result)
		if notes != "" {
			fmt.Printf(" - %s", notes)
		}
		fmt.Println()

		reporter.AppendEntry(Entry{
			Index:        i + 1,
			PayloadName:  payload.Name,
			Mode:         payload.Mode,
			FullRequest:  FormatRequest(modified),
			StatusCode:   statusCode,
			ResponseBody: respBody,
			Notes:        notes,
			Result:       result,
		})
	}

	reporter.Finalize(total, interesting, noImpact)
}
