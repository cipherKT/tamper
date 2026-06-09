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
	Headers  map[string][]string
	Body     string
	BodyType string
	Fields   map[string]string
}

func ParseRequestFile(path string) (ParsedRequest, error) {
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		return ParsedRequest{}, fmt.Errorf("reading file: %w", err)
	}
	raw := string(rawBytes)

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
	parsedRequest.Headers = req.Header

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return ParsedRequest{}, fmt.Errorf("reading body: %w", err)
	}
	parsedRequest.Body = string(bodyBytes)

	contentType := req.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		parsedRequest.BodyType = "json"

		var bodyMap map[string]interface{}
		err = json.Unmarshal([]byte(parsedRequest.Body), &bodyMap)
		if err != nil {
			return ParsedRequest{}, err
		}
		parsedRequest.Fields = make(map[string]string)
		for k, v := range bodyMap {
			parsedRequest.Fields[k] = fmt.Sprintf("%v", v)
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		parsedRequest.BodyType = "form"

		formValues, err := url.ParseQuery(parsedRequest.Body)
		if err != nil {
			return ParsedRequest{}, err
		}
		parsedRequest.Fields = make(map[string]string)
		for k, v := range formValues {
			parsedRequest.Fields[k] = v[0]
		}
	} else {
		parsedRequest.BodyType = "none"
	}

	return *parsedRequest, nil
}

func main() {
	req, err := ParseRequestFile("test.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Method:", req.Method)
	fmt.Println("Scheme:", req.Scheme)
	fmt.Println("Host:", req.Host)
	fmt.Println("Path:", req.Path)
	fmt.Println("BodyType:", req.BodyType)
	fmt.Println("Fields:", req.Fields)
	fmt.Println("Body:", req.Body)
}
