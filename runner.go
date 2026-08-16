package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func RunInteractive(req ParsedRequest, attackerDomain, attackerEmail string, payloads []Payload, verbose bool) {
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
		// Copy fields before each Apply so mutations in one payload
		// don't bleed into subsequent payloads (maps are reference types).
		reqCopy := req
		reqCopy.Fields = DeepCopyFields(req.Fields)
		modified := payload.Apply(reqCopy, attackerDomain, attackerEmail)

		printBanner()
		fmt.Printf(" Target  : %s %s://%s%s\n", req.Method, req.Scheme, req.Host, req.Path)
		fmt.Printf(" Domain  : %s", attackerDomain)
		if attackerEmail != "" {
			fmt.Printf("   Email : %s", attackerEmail)
		}
		fmt.Println()
		fmt.Printf(" Tally   : \033[32m✔ %d interesting\033[0m  │  \033[31m✘ %d no-impact\033[0m\n", interesting, noImpact)
		fmt.Println(drawProgress(i, total))
		fmt.Println(strings.Repeat("─", 58))
		fmt.Printf("\n [%d/%d] %s (%s)\n", i+1, total, payload.Name, payload.Mode)
		fmt.Printf(" %s\n", payload.Description)

		// Show what exactly will change before sending
		if payload.Preview != nil {
			fmt.Println()
			fmt.Println(" \033[2mPayload preview:\033[0m")
			fmt.Println(payload.Preview(req, attackerDomain, attackerEmail))
		}
		fmt.Println()

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

		start := time.Now()
		statusCode, respHeaders, respBody, err := SendRequest(modified)
		elapsed := time.Since(start).Milliseconds()
		if err != nil {
			fmt.Println(" Error sending request:", err)
			continue
		}

		printBanner()
		fmt.Printf(" Target  : %s %s://%s%s\n", req.Method, req.Scheme, req.Host, req.Path)
		fmt.Printf(" Domain  : %s", attackerDomain)
		if attackerEmail != "" {
			fmt.Printf("   Email : %s", attackerEmail)
		}
		fmt.Println()
		fmt.Printf(" Tally   : \033[32m✔ %d interesting\033[0m  │  \033[31m✘ %d no-impact\033[0m\n", interesting, noImpact)
		fmt.Println(drawProgress(i+1, total))
		fmt.Println(strings.Repeat("─", 58))
		fmt.Printf("\n [%d/%d] %s (%s)\n\n", i+1, total, payload.Name, payload.Mode)

		// Always show key response headers
		fmt.Printf(" Response      : %s  (%d ms)\n", colorStatus(statusCode), elapsed)
		printKeyHeaders(respHeaders)

		// Show full response body only in verbose mode
		if verbose {
			fmt.Println()
			fmt.Println(strings.Repeat("─", 58))
			fmt.Println(" Full Response:")
			fmt.Println(strings.Repeat("─", 58))
			printAllHeaders(respHeaders)
			fmt.Println()
			fmt.Println(respBody)
			fmt.Println(strings.Repeat("─", 58))
		}

		fmt.Println()

		// Two-step result prompt
		fmt.Print(" ▶  Mark result:  [y] interesting   [n] no impact   [q] quit\n    Choice: ")
		scanner.Scan()
		input = strings.TrimSpace(scanner.Text())
		if input == "q" {
			fmt.Println("Quitting...")
			reporter.Finalize(i+1, interesting, noImpact)
			return
		}

		var result string
		if strings.HasPrefix(strings.ToLower(input), "y") {
			result = "interesting"
			interesting++
		} else {
			result = "no-impact"
			noImpact++
		}

		fmt.Print("    Notes (Enter to skip): ")
		scanner.Scan()
		notes := strings.TrimSpace(scanner.Text())

		fmt.Printf(" [*] Logged: %s", result)
		if notes != "" {
			fmt.Printf(" — %s", notes)
		}
		fmt.Println()

		reporter.AppendEntry(Entry{
			Index:        i + 1,
			PayloadName:  payload.Name,
			Description:  payload.Description,
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

// printKeyHeaders prints the important response headers in a compact table.
func printKeyHeaders(h http.Header) {
	keys := []string{"Content-Type", "Content-Length", "Location", "Set-Cookie"}
	for _, k := range keys {
		v := h.Get(k)
		if v == "" {
			v = "(none)"
		}
		fmt.Printf(" %-14s : %s\n", k, v)
	}
}

// printAllHeaders prints every response header for verbose mode.
func printAllHeaders(h http.Header) {
	for k, vals := range h {
		fmt.Printf(" %s: %s\n", k, strings.Join(vals, ", "))
	}
}
