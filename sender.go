package main

import (
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/http2"
)

// h2Transport is a reusable HTTP/2-only transport.
// It negotiates TLS with ALPN "h2" and speaks HTTP/2 directly.
var h2Transport = &http2.Transport{
	TLSClientConfig: &tls.Config{
		NextProtos: []string{"h2"},
	},
}

// h1Transport is the default HTTP/1.1 transport.
var h1Transport = http.DefaultTransport

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

	// Strip brotli from Accept-Encoding since we don't have a decoder.
	// Keep gzip and deflate which we can decompress natively.
	sanitizeAcceptEncoding(httpReq)

	// Pick transport based on the original protocol version.
	var transport http.RoundTripper
	if req.Proto == "HTTP/2" {
		transport = h2Transport
	} else {
		transport = h1Transport
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, "", fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	// Decompress the response body based on Content-Encoding.
	// http2.Transport does not auto-decompress like http.Transport,
	// and Burp exports typically include Accept-Encoding headers
	// that cause the server to send compressed responses.
	body, err := decompressBody(resp)
	if err != nil {
		return 0, "", fmt.Errorf("reading response: %w", err)
	}

	return resp.StatusCode, string(body), nil
}

// decompressBody reads the response body and decompresses it
// based on the Content-Encoding header (gzip, deflate).
func decompressBody(resp *http.Response) ([]byte, error) {
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))

	var reader io.ReadCloser
	var err error

	switch encoding {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip decoder: %w", err)
		}
		defer reader.Close()
	case "deflate":
		reader = flate.NewReader(resp.Body)
		defer reader.Close()
	default:
		reader = resp.Body
	}

	return io.ReadAll(reader)
}

// sanitizeAcceptEncoding removes encodings we can't decompress (brotli)
// from the Accept-Encoding header so the server sends a format we handle.
func sanitizeAcceptEncoding(req *http.Request) {
	ae := req.Header.Get("Accept-Encoding")
	if ae == "" {
		return
	}

	var supported []string
	for _, enc := range strings.Split(ae, ",") {
		enc = strings.TrimSpace(enc)
		// Keep gzip, deflate, identity — drop br (brotli) and zstd.
		name := strings.SplitN(enc, ";", 2)[0]
		name = strings.TrimSpace(strings.ToLower(name))
		if name == "br" || name == "zstd" {
			continue
		}
		supported = append(supported, enc)
	}

	if len(supported) == 0 {
		req.Header.Del("Accept-Encoding")
	} else {
		req.Header.Set("Accept-Encoding", strings.Join(supported, ", "))
	}
}

