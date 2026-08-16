package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func RebuildBody(req ParsedRequest) string {
	switch req.BodyType {
	case "json":
		b, err := json.Marshal(req.Fields)
		if err != nil {
			return ""
		}
		return string(b)
	case "form":
		values := url.Values{}
		for k, v := range req.Fields {
			values.Set(k, fmt.Sprintf("%v", v))
		}
		return values.Encode()
	default:
		return ""
	}
}

func UpdateContentLength(req *ParsedRequest, body string) {
	req.Headers["Content-Length"] = []string{strconv.Itoa(len(body))}
}

func FormatRequest(req ParsedRequest) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s %s\n", req.Method, req.Path, req.Proto))
	sb.WriteString(fmt.Sprintf("Host: %s\n", req.Host))
	for k, v := range req.Headers {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	sb.WriteString(fmt.Sprintf("\n%s", req.Body))
	return sb.String()
}

func PrintRequest(req ParsedRequest) {
	fmt.Println(FormatRequest(req))
}

// colorStatus wraps a status code in ANSI color:
//   - 2xx → green
//   - 3xx → yellow
//   - 4xx/5xx → red
func colorStatus(code int) string {
	s := strconv.Itoa(code)
	switch {
	case code >= 200 && code < 300:
		return "\033[32m" + s + "\033[0m" // green
	case code >= 300 && code < 400:
		return "\033[33m" + s + "\033[0m" // yellow
	default:
		return "\033[31m" + s + "\033[0m" // red
	}
}

// drawProgress renders a visual progress bar line, e.g.:
//
//	━━━━━━━━━━━━━━━━━━━━━━░░░░░░░░░░  [7 / 30]  23 remaining
func drawProgress(current, total int) string {
	const width = 30
	filled := 0
	if total > 0 {
		filled = current * width / total
	}
	bar := strings.Repeat("━", filled) + strings.Repeat("░", width-filled)
	remaining := total - current
	return fmt.Sprintf(" %s  [%d / %d]  %d remaining", bar, current, total, remaining)
}

// InjectValue returns the appropriate attacker value for a body field key.
// If the key looks like an email field and attackerEmail is set, it returns attackerEmail.
// Otherwise it falls back to "evil@<attackerDomain>".
func InjectValue(key, attackerEmail, attackerDomain string) string {
	k := strings.ToLower(key)
	if attackerEmail != "" && (strings.Contains(k, "email") || strings.Contains(k, "mail")) {
		return attackerEmail
	}
	if attackerEmail != "" {
		return attackerEmail
	}
	return "evil@" + attackerDomain
}

