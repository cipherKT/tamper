package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type ParsedRequest struct {
	Method   string
	Scheme   string
	Host     string
	Path     string
	Proto    string // "HTTP/1.1" or "HTTP/2"
	Headers  map[string][]string
	Body     string
	BodyType string
	Fields   map[string]any
}

func ParseRequestFile(path string) (ParsedRequest, error) {
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		return ParsedRequest{}, fmt.Errorf("reading file: %w", err)
	}
	raw := string(rawBytes)

	// Detect the original protocol version from the request line,
	// then normalize to HTTP/1.1 so http.ReadRequest can parse it.
	proto := "HTTP/1.1"
	raw = normalizeProto(raw, &proto)

	// Handle HTTP/2 pseudo-headers exported by Burp Suite.
	// These look like regular headers but start with ":".
	// Extract them and convert to standard HTTP/1.1 format.
	raw = convertPseudoHeaders(raw, &proto)

	// http.ReadRequest requires Content-Length for body parsing.
	// If missing, inject it so the body is read properly.
	parts := strings.SplitN(raw, "\n\n", 2)
	if len(parts) == 2 {
		bodyPart := strings.TrimSpace(parts[1])
		if bodyPart != "" && !strings.Contains(parts[0], "Content-Length:") && !strings.Contains(parts[0], "content-length:") {
			raw = parts[0] + "\nContent-Length: " + strconv.Itoa(len(bodyPart)) + "\n\n" + bodyPart
		}
	}

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return ParsedRequest{}, fmt.Errorf("parsing request: %w", err)
	}

	parsedRequest := new(ParsedRequest)

	parsedRequest.Method = req.Method
	parsedRequest.Scheme = "https"
	parsedRequest.Host = req.Host
	parsedRequest.Path = req.URL.Path
	parsedRequest.Proto = proto
	parsedRequest.Headers = req.Header

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return ParsedRequest{}, fmt.Errorf("reading body: %w", err)
	}
	parsedRequest.Body = string(bodyBytes)

	contentType := req.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		parsedRequest.BodyType = "json"

		var bodyMap map[string]any
		err = json.Unmarshal([]byte(parsedRequest.Body), &bodyMap)
		if err != nil {
			return ParsedRequest{}, err
		}
		parsedRequest.Fields = make(map[string]any)
		for k, v := range bodyMap {
			parsedRequest.Fields[k] = fmt.Sprintf("%v", v)
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		parsedRequest.BodyType = "form"

		formValues, err := url.ParseQuery(parsedRequest.Body)
		if err != nil {
			return ParsedRequest{}, err
		}
		parsedRequest.Fields = make(map[string]any)
		for k, v := range formValues {
			parsedRequest.Fields[k] = v[0]
		}
	} else {
		parsedRequest.BodyType = "none"
	}

	return *parsedRequest, nil
}

// normalizeProto detects HTTP/2 in the request line and rewrites it
// to HTTP/1.1 so http.ReadRequest can parse the raw text.
// The original proto is stored via the pointer for later use.
func normalizeProto(raw string, proto *string) string {
	// Find end of first line (request line).
	idx := strings.IndexAny(raw, "\r\n")
	if idx == -1 {
		return raw
	}
	requestLine := raw[:idx]

	// Match HTTP/2 variants: "HTTP/2", "HTTP/2.0"
	if strings.HasSuffix(requestLine, " HTTP/2") ||
		strings.HasSuffix(requestLine, " HTTP/2.0") {
		*proto = "HTTP/2"
		// Replace the version token on the request line only.
		normalized := strings.TrimSuffix(requestLine, " HTTP/2")
		normalized = strings.TrimSuffix(normalized, " HTTP/2.0")
		return normalized + " HTTP/1.1" + raw[idx:]
	}
	return raw
}

// convertPseudoHeaders handles HTTP/2 pseudo-header style requests
// that Burp Suite exports. These have no traditional request line;
// instead they use pseudo-headers like :method, :path, :authority, :scheme.
//
// Example Burp HTTP/2 export:
//
//	:method: POST
//	:path: /forgot-password
//	:authority: example.com
//	:scheme: https
//	Content-Type: application/x-www-form-urlencoded
//
//	username=carlos
//
// This function detects that format and synthesizes a standard HTTP/1.1
// request line + Host header so http.ReadRequest can parse it.
func convertPseudoHeaders(raw string, proto *string) string {
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return raw
	}

	// Quick check: if the first non-empty line starts with ":" it's a
	// pseudo-header format.
	firstLine := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(firstLine, ":") {
		return raw
	}

	*proto = "HTTP/2"

	var (
		method    = "GET"
		path      = "/"
		authority = ""
		scheme    = "https"
		remaining []string
	)

	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if strings.HasPrefix(trimmed, ":method:") {
			method = strings.TrimSpace(strings.TrimPrefix(trimmed, ":method:"))
		} else if strings.HasPrefix(trimmed, ":path:") {
			path = strings.TrimSpace(strings.TrimPrefix(trimmed, ":path:"))
		} else if strings.HasPrefix(trimmed, ":authority:") {
			authority = strings.TrimSpace(strings.TrimPrefix(trimmed, ":authority:"))
		} else if strings.HasPrefix(trimmed, ":scheme:") {
			scheme = strings.TrimSpace(strings.TrimPrefix(trimmed, ":scheme:"))
			_ = scheme // stored but we already default to https
		} else {
			remaining = append(remaining, line)
		}
	}

	// Build a standard request with synthesized request line.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", method, path))
	if authority != "" {
		sb.WriteString(fmt.Sprintf("Host: %s\n", authority))
	}
	for _, line := range remaining {
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	return sb.String()
}
