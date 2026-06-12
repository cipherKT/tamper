package main

import (
	"fmt"
	"os"
	"time"
)

type Entry struct {
	Index        int
	PayloadName  string
	Mode         string
	FullRequest  string
	StatusCode   int
	ResponseBody string
	Notes        string
	Result       string
}

type Reporter struct {
	filepath string
	file     *os.File
}

func NewReporter(req ParsedRequest) (*Reporter, error) {
	filename := fmt.Sprintf("report_%s.md", time.Now().Format("20060102_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("creating report: %w", err)
	}

	// write header
	fmt.Fprintf(file, "# tamper report\n")
	fmt.Fprintf(file, "**Target:** %s %s://%s%s\n", req.Method, req.Scheme, req.Host, req.Path)
	fmt.Fprintf(file, "**Date:** %s\n", time.Now().Format("2006-01-02 15:04"))
	fmt.Fprintf(file, "**Tool:** tamper v0.1.0\n\n---\n\n")

	return &Reporter{filepath: filename, file: file}, nil
}

func (r *Reporter) AppendEntry(e Entry) error {
	icon := "❌"
	if e.Result == "interesting" {
		icon = "✅"
	}

	fmt.Fprintf(r.file, "## Payload %d — %s\n", e.Index, e.PayloadName)
	fmt.Fprintf(r.file, "**Result:** %s %s\n", icon, e.Result)
	fmt.Fprintf(r.file, "**Mode:** %s\n", e.Mode)
	fmt.Fprintf(r.file, "**Description:** %s\n\n", e.PayloadName)
	fmt.Fprintf(r.file, "**Request:**\n```http\n%s\n```\n\n", e.FullRequest)
	fmt.Fprintf(r.file, "**Response:** %d\n```\n%s\n```\n\n", e.StatusCode, e.ResponseBody)
	fmt.Fprintf(r.file, "**Notes:** %s\n\n---\n\n", e.Notes)

	return nil
}

func (r *Reporter) Finalize(total, interesting, noImpact int) {
	fmt.Fprintf(r.file, "## Summary\n")
	fmt.Fprintf(r.file, "- Total: %d\n", total)
	fmt.Fprintf(r.file, "- Interesting: %d\n", interesting)
	fmt.Fprintf(r.file, "- No impact: %d\n", noImpact)
	r.file.Close()
	fmt.Printf("\n[*] Report saved: %s\n", r.filepath)
}
