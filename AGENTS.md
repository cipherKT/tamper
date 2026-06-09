# tamper

HTTP request file parser (Go). Reads raw HTTP request files (e.g. from Burp Suite) and extracts method, host, path, headers, body, and structured fields.

## Commands

- `go run parser.go` — runs with `test2.txt` as input (edit `main()` to change)
- `go build -o tamper` — build binary
- `go mod tidy` — after any dependency change

## Key gotchas

- `http.ReadRequest` **requires `Content-Length`** to read the request body. The parser auto-injects `Content-Length` if missing (common for hand-crafted request files), so both `test.txt` (JSON with Content-Length) and `test2.txt` (form-urlencoded without Content-Length) work.
- Content-Type header is checked with `strings.Contains`, so `application/json;charset=UTF-8` matches as JSON.
- Only two content types supported: `application/json` and `application/x-www-form-urlencoded`. Everything else is `BodyType: "none"`.
- `ParsedRequest.Fields` is a flat `map[string]string` — nested JSON values are stringified with `%v`.

## Structure

- `parser.go` — single-file, stdlib-only (no external deps)
- `test.txt` / `test2.txt` — sample request files for testing
- `go.mod` — module `github.com/cipherKT/tamper`
