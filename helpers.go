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

func PrintRequest(req ParsedRequest) {
	fmt.Printf("%s %s HTTP/1.1\n", req.Method, req.Path)
	fmt.Printf("Host: %s\n", req.Host)
	for k, v := range req.Headers {
		fmt.Printf("%s: %s\n", k, strings.Join(v, ", "))
	}
	fmt.Printf("\n%s\n", req.Body)
}
