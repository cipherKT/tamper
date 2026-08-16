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
			// If the value is a slice (e.g. from Array injection), encode each
			// element as a separate key=value pair instead of stringifying the slice.
			if slice, ok := v.([]any); ok {
				for _, elem := range slice {
					values.Add(k, anyToString(elem))
				}
			} else {
				values.Set(k, anyToString(v))
			}
		}
		return values.Encode()
	default:
		return ""
	}
}

// ── Preview helpers ───────────────────────────────────────────────────────────

// PreviewHeader formats a header injection as:
//   adding   X-Forwarded-Host: evil.com
//   replacing  Host: original.com  →  Host: evil.com
func PreviewHeader(action, key, before, after string) string {
	arrow := "\033[33m→\033[0m"
	dim := "\033[2m"
	reset := "\033[0m"
	bold := "\033[1m"
	switch action {
	case "add":
		return fmt.Sprintf("  %s+%s %s%s%s: %s", bold, reset, dim, key, reset, after)
	case "replace":
		return fmt.Sprintf("  %s~%s %s%s%s: %s  %s  %s", bold, reset, dim, key, reset, before, arrow, after)
	case "append":
		return fmt.Sprintf("  %s~%s %s%s%s: %s  %s  %s", bold, reset, dim, key, reset, before, arrow, after)
	default:
		return fmt.Sprintf("  %s: %s  %s  %s", key, before, arrow, after)
	}
}

// PreviewBodyFields formats body field changes as a compact diff.
// Each changed field is shown as:
//   field: original  →  new_value
// or for arrays:
//   field: original  →  [original, evil@attacker.com]
func PreviewBodyFields(original map[string]any, modified map[string]any) string {
	arrow := "\033[33m→\033[0m"
	dim := "\033[2m"
	reset := "\033[0m"
	bold := "\033[1m"

	var lines []string
	for k, newVal := range modified {
		origVal := anyToString(original[k])
		var newStr string
		if slice, ok := newVal.([]any); ok {
			parts := make([]string, len(slice))
			for i, e := range slice {
				parts[i] = anyToString(e)
			}
			newStr = strings.Join(parts, ", ")
		} else if m, ok := newVal.(map[string]any); ok {
			b, _ := json.Marshal(m)
			newStr = string(b)
		} else {
			newStr = anyToString(newVal)
		}
		if origVal == newStr {
			continue // skip unchanged fields
		}
		lines = append(lines, fmt.Sprintf("  %s~%s %s%s%s: %s  %s  %s", bold, reset, dim, k, reset, origVal, arrow, newStr))
	}
	// Also show any brand-new keys that weren't in original
	for k, newVal := range modified {
		if _, existed := original[k]; !existed {
			newStr := anyToString(newVal)
			lines = append(lines, fmt.Sprintf("  %s+%s %s%s%s: %s", bold, reset, dim, k, reset, newStr))
		}
	}
	if len(lines) == 0 {
		return "  (no field changes)"
	}
	return strings.Join(lines, "\n")
}
// anyToString converts any field value to its string representation.
// nil becomes an empty string (not "<nil>") for clean form/JSON encoding.
func anyToString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func UpdateContentLength(req *ParsedRequest, body string) {
	req.Headers["Content-Length"] = []string{strconv.Itoa(len(body))}
}

// DeepCopyFields returns a copy of the fields map so each payload Apply
// receives the original values and cannot bleed mutations into subsequent payloads.
func DeepCopyFields(fields map[string]any) map[string]any {
	cp := make(map[string]any, len(fields))
	for k, v := range fields {
		cp[k] = v
	}
	return cp
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

// isEmailField returns true if the field key looks like it carries an email address.
// Email-injection payloads use this to skip unrelated fields like token, password, username.
func isEmailField(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "email") || strings.Contains(k, "mail")
}

// detectScheme returns "http" for localhost/127.0.0.1 targets,
// and "https" for everything else.
func detectScheme(host string) string {
	h := strings.ToLower(host)
	// Strip port if present
	if idx := strings.LastIndex(h, ":"); idx != -1 {
		h = h[:idx]
	}
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return "http"
	}
	return "https"
}
