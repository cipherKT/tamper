package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func SendRequest(req ParsedRequest) (int, string, error) {
	fullURL := req.Scheme + "://" + req.Host + req.Path

	httpReq, err := http.NewRequest(req.Method, fullURL, strings.NewReader(req.Body))
	if err != nil {
		return 0, "", fmt.Errorf("building request: %w", err)
	}

	for k, vals := range req.Headers {
		for _, v := range vals {
			httpReq.Header.Set(k, v)
		}
	}

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, "", fmt.Errorf("sending request %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", fmt.Errorf("reading response %w", err)
	}

	return resp.StatusCode, string(bodyBytes), nil
}
