package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func RunInteractive(req ParsedRequest, attackerDomain string, payloads []Payload, verbose bool) {
	scanner := bufio.NewScanner(os.Stdin)
	total := len(payloads)

	reporter, err := NewReporter(req)
	if err != nil {
		fmt.Println("Error creating report:", err)
		return
	}

	interesting := 0
	noImpact := 0

	for i, payload := range payloads {
		modified := payload.Apply(req, attackerDomain)

		printBanner()
		fmt.Printf(" Target : %s %s://%s%s\n", req.Method, req.Scheme, req.Host, req.Path)
		fmt.Printf(" Domain : %s\n", attackerDomain)
		fmt.Println(strings.Repeat("─", 58))
		fmt.Printf("\n [%d/%d] %s (%s)\n", i+1, total, payload.Name, payload.Mode)
		fmt.Printf(" %s\n\n", payload.Description)

		if verbose {
			fmt.Println(strings.Repeat("─", 58))
			fmt.Println(" Request:")
			fmt.Println(strings.Repeat("─", 58))
			PrintRequest(modified)
			fmt.Println(strings.Repeat("─", 58))
		}

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
			fmt.Println(" Error sending request:", err)
			continue
		}

		printBanner()
		fmt.Printf(" Target : %s %s://%s%s\n", req.Method, req.Scheme, req.Host, req.Path)
		fmt.Printf(" Domain : %s\n", attackerDomain)
		fmt.Println(strings.Repeat("─", 58))
		fmt.Printf("\n [%d/%d] %s (%s)\n\n", i+1, total, payload.Name, payload.Mode)
		fmt.Printf(" Response : %d\n", statusCode)
		fmt.Printf(" Body     : %s\n\n", respBody)

		fmt.Print(" Result (y/n/q with optional notes after dot): ")
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

		fmt.Printf(" [*] Logged: %s", result)
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
