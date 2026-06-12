package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	requestFile := flag.String("r", "", "path to request file")
	attackerDomain := flag.String("d", "evil.ktcipher.com", "attacker domain for header injection")
	mode := flag.Int("mode", 0, "attack mode: 1=header, 2=body, 3=both (default: all)")
	dry := flag.Bool("dry", false, "print payloads without sending")
	verbose := flag.Bool("v", false, "verbose — print full request before sending")

	flag.Parse()
	printBanner()

	if *requestFile == "" {
		fmt.Println(" usage: tamper -r request.txt [-d attacker.com] [--mode 1|2|3] [--dry] [-v]")
		os.Exit(1)
	}

	req, err := ParseRequestFile(*requestFile)
	if err != nil {
		fmt.Println(" error:", err)
		os.Exit(1)
	}

	fmt.Printf(" Target : %s %s://%s%s\n", req.Method, req.Scheme, req.Host, req.Path)
	fmt.Printf(" Body   : %s\n", req.BodyType)
	fmt.Printf(" Fields : %v\n", req.Fields)
	fmt.Printf(" Domain : %s\n\n", *attackerDomain)

	filtered := filterPayloads(*mode)
	if len(filtered) == 0 {
		fmt.Println(" no payloads matched selected mode")
		os.Exit(1)
	}

	if *dry {
		fmt.Printf(" [dry run] %d payloads queued:\n\n", len(filtered))
		for i, p := range filtered {
			fmt.Printf("  %d. [%s] %s — %s\n", i+1, p.Mode, p.Name, p.Description)
		}
		return
	}

	RunInteractive(req, *attackerDomain, filtered, *verbose)
}

func filterPayloads(mode int) []Payload {
	if mode == 0 {
		return Payloads
	}
	var result []Payload
	for _, p := range Payloads {
		switch mode {
		case 1:
			if p.Mode == "header" {
				result = append(result, p)
			}
		case 2:
			if p.Mode == "body" {
				result = append(result, p)
			}
		case 3:
			result = append(result, p)
		}
	}
	return result
}
