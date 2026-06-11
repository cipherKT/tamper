package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
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
