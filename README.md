<div align="center">

```
 ████████╗ █████╗ ███╗   ███╗██████╗ ███████╗██████╗
 ╚══██╔══╝██╔══██╗████╗ ████║██╔══██╗██╔════╝██╔══██╗
    ██║   ███████║██╔████╔██║██████╔╝█████╗  ██████╔╝
    ██║   ██╔══██║██║╚██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗
    ██║   ██║  ██║██║ ╚═╝ ██║██║     ███████╗██║  ██║
    ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

**Interactive request manipulation tool for testing sensitive account-update flows**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![HTTP/2](https://img.shields.io/badge/HTTP%2F2-supported-success?style=flat-square)]()
[![Author](https://img.shields.io/badge/author-r00t3d_kt-blueviolet?style=flat-square)](https://twitter.com/r00t3d_kt)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey?style=flat-square)]()

</div>

---

## what is tamper?

`tamper` is a single-binary CLI tool for testing account-update endpoints — email change, password reset, username update, mobile number change, or anything with a similar request/confirmation flow. Supports both **HTTP/1.1** and **HTTP/2** targets out of the box.

You give it a raw HTTP request file (from Burp or Caido), pick an attack mode, and it walks you through payloads one at a time — sending each request, showing the response, and waiting for you to check your inbox and log the result. Everything gets written to a markdown report automatically.

No Python virtualenvs. No bloated frameworks. Just `go install` and go.

---

## who is this for?

Bug bounty hunters who want a fast, repeatable way to test:

- Host header injection in reset/confirmation emails
- JSON and form body manipulation (type confusion, array injection, duplicate keys, extra fields)
- Email header injection via CRLF
- IP spoofing headers for rate limit bypass
- Parameter pollution in form-encoded endpoints

---

## install

```bash
go install github.com/cipherKT/tamper@latest
```

or build from source:

```bash
git clone https://github.com/cipherKT/tamper
cd tamper
go build -o tamper
```

---

## usage

```
tamper -r <request file> [flags]
```

| flag | default | description |
|---|---|---|
| `-r` | required | path to raw request file (Burp / Caido format) |
| `-d` | `evil.ktcipher.com` | attacker domain for header injection and email construction |
| `-e` | — | attacker email for body payloads — required for `--mode 2` / `3` |
| `--mode` | `3` | `1` = header only · `2` = body only · `3` = both |
| `--dry` | false | preview all payloads without sending |
| `-v` | false | verbose — print full request before sending and full response after |

---

## quickstart

**1. Export a raw request from Burp or Caido and save it:**

```
POST /api/account/email HTTP/1.1
Host: target.com
Content-Type: application/json

{"email":"victim@gmail.com"}
```

HTTP/2 requests work too — both formats are auto-detected:

```
POST /api/account/email HTTP/2
Host: target.com
Content-Type: application/json

{"email":"victim@gmail.com"}
```

**2. Preview what tamper will test:**

```bash
tamper -r request.txt --dry
```

**3. Run header injection payloads only:**

```bash
tamper -r request.txt --mode 1 -d your.burpcollaborator.net
```

**4. Run everything verbosely:**

```bash
tamper -r request.txt -e evil@attacker.com -v
```

---

## interactive flow

```
 ██████████████████████████████████████████████████████████
  Target : POST https://target.com/api/account/email
  Domain : evil.ktcipher.com
 ──────────────────────────────────────────────────────────

  [4/35] Duplicate keys (body)
  repeat each field key with attacker value second

  Payload preview:
  ~ email: victim@gmail.com  →  victim@gmail.com, evil@evil.com

 [*] Press Enter to send, q to quit:

  Response      : 200  (43 ms)
  Content-Type  : application/json
  Content-Length: 33
  Location      : (none)

  ▶  Mark result:  [y] interesting   [n] no impact   [q] quit
     Notes (Enter to skip): link unchanged
  [*] Logged: no-impact
```

Each payload clears the screen and re-renders the banner so you always know where you are. Between send and result logging you have time to check your inbox, Collaborator, or any out-of-band channel.

---

## payloads

### host header injection (16)

| # | name | what it does |
|---|---|---|
| 1 | X-Forwarded-Host | classic host header poison |
| 2 | X-Original-Host | alternate header variant |
| 3 | X-Host | alternate header variant |
| 4 | Forwarded | RFC 7239 forwarded host |
| 5 | X-Forwarded-Server | server override |
| 6 | X-HTTP-Host-Override | override via custom header |
| 7 | Host override | replaces Host directly |
| 8 | Host append | `target.com.evil.com` |
| 9 | Host fragment | `evil.com#target.com` |
| 10 | X-Forwarded-Proto | proto header injection |
| 11 | Referer header | token leak via referer |
| 12 | Origin header | origin header injection |
| 13 | X-Forwarded-For spoof | IP spoof for rate limit bypass |
| 14 | X-Real-IP spoof | IP spoof for rate limit bypass |
| 15 | Client-IP spoof | IP spoof for rate limit bypass |
| 16 | True-Client-IP spoof | IP spoof for rate limit bypass |

### body manipulation (19)

| # | name | what it does |
|---|---|---|
| 1 | Array injection | wraps all email fields as `["original", "evil@attacker.com"]` |
| 2 | Null confusion | all fields set to `null` |
| 3 | Int confusion | all fields set to `0` |
| 4 | Bool confusion | all fields set to `true` |
| 5 | Duplicate keys | `{"email":"victim","email":"attacker"}` |
| 6 | HTML injection | `<b>value</b>` — tests unsanitized email rendering |
| 7 | redirectUrl field | replaces existing `redirectUrl` with attacker domain |
| 8 | callbackUrl field | replaces existing `callbackUrl` with attacker domain |
| 9 | next field | replaces existing `next` with attacker domain |
| 10 | returnUrl field | replaces existing `returnUrl` with attacker domain |
| 11 | callback field | replaces existing `callback` with attacker domain |
| 12 | redirect field | replaces existing `redirect` with attacker domain |
| 13 | Nested object | `{"field": {"value": "orig", "email": "evil"}}` |
| 14 | Comma separated | `"victim@x.com,evil@attacker.com"` |
| 15 | Pipe separated | `"victim@x.com\|evil@attacker.com"` |
| 16 | CRLF injection | `value%0aBcc:evil@attacker.com` |
| 17 | backup_email field | adds `backup_email` key with attacker value |
| 18 | Nested user.email | adds `"user": {"email": "evil@attacker.com"}` |
| 19 | Parameter pollution | form-encoded only — `email=a&email=evil` duplicate params |

The redirect/url payloads (7–12) are presence-gated: each one only runs when that exact field already exists in the request — they never inject new keys. Because they're gated, the total queued payload count varies per request. Same for Parameter pollution (19), which only appears on `application/x-www-form-urlencoded` requests.

---

## report

Every session generates a markdown report automatically:

```
report_20260612_143022.md
```

Each payload gets its own entry:

```markdown
## Payload 4 — Duplicate keys
**Result:** ❌ no-impact
**Mode:** body

**Request:**
POST /api/account/email HTTP/1.1
Host: target.com
...

**Response:** 200
{"success":true}

**Notes:** link unchanged in inbox
```

With a summary at the end:

```markdown
## Summary
- Total: 35
- Interesting: 2
- No impact: 29
```

---

## supported flows

tamper is endpoint-agnostic. Works on any flow with a similar request/confirmation pattern:

- ✅ Email change
- ✅ Password reset
- ✅ Username change
- ✅ Mobile number update
- ✅ Any account-update endpoint with out-of-band confirmation

---

## request file format

Standard raw HTTP format exported from Burp Suite or Caido. Blank line between headers and body is required.

**HTTP/1.1:**

```
POST /reset HTTP/1.1
Host: target.com
Content-Type: application/json
Cookie: session=abc123

{"email":"victim@gmail.com"}
```

**HTTP/2 (standard):**

```
POST /reset HTTP/2
Host: target.com
Content-Type: application/json
Cookie: session=abc123

{"email":"victim@gmail.com"}
```

**HTTP/2 (Burp pseudo-header format):**

```
:method: POST
:path: /reset
:authority: target.com
:scheme: https
Content-Type: application/json
Cookie: session=abc123

{"email":"victim@gmail.com"}
```

All three formats are auto-detected. Both JSON and `application/x-www-form-urlencoded` bodies are supported. Fields are auto-detected — no configuration needed.

Compressed responses (`gzip`, `deflate`) are automatically decompressed.

---

## project structure

```
tamper/
├── main.go       — entrypoint, flags, payload filtering
├── parser.go     — raw HTTP request file → ParsedRequest (HTTP/1.1 + HTTP/2)
├── payloads.go   — all payload definitions
├── runner.go     — interactive send loop
├── sender.go     — HTTP/1.1 and HTTP/2 client with response decompression
├── reporter.go   — markdown report writer
├── helpers.go    — RebuildBody, FormatRequest, UpdateContentLength
└── banner.go     — ASCII banner, screen clear
```

---

## author

**cipherKT** — bug bounty hunter

[![Twitter](https://img.shields.io/badge/twitter-@r00t3d_kt-1DA1F2?style=flat-square&logo=twitter)](https://twitter.com/r00t3d_kt)
[![GitHub](https://img.shields.io/badge/github-cipherKT-181717?style=flat-square&logo=github)](https://github.com/cipherKT)

---

<div align="center">
<sub>built for personal use — use responsibly on programs you are authorized to test</sub>
</div>
