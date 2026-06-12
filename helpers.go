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
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", req.Method, req.Path))
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
