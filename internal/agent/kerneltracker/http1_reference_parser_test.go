package kerneltracker

// Go reference implementation of the in-eBPF HTTP/1 request-line + Host
// parse (internal/agent/bpf/http_helpers.bpf.h parse_http1_request). The C
// parser cannot be driven by `go test` / `go test -fuzz`, so this mirror
// pins the parse semantics — keep the two implementations in lockstep.

import (
	"strings"
	"testing"
)

const (
	refHTTP1PrefixLen = 256 // HTTP1_PREFIX_LEN
	refHTTPPathLen    = 256 // HTTP_PATH_LEN
	refHTTPHostLen    = 256 // HTTP_HOST_LEN
	refMinRequestLine = 14  // HTTP_MIN_REQUEST_LINE ("GET / HTTP/1.0")
)

// refHTTP1Request mirrors the parsed fields of struct http_request_sample.
type refHTTP1Request struct {
	Method string
	Path   string
	Host   string
}

// refMethodLen mirrors http_method_len: known token + trailing space at the
// start of b (CONNECT intentionally absent — authority-form never passes the
// origin-form check).
func refMethodLen(b []byte) int {
	for _, token := range []string{"GET ", "PUT ", "POST ", "HEAD ", "PATCH ", "TRACE ", "DELETE ", "OPTIONS "} {
		if len(b) >= len(token) && string(b[:len(token)]) == token {
			return len(token) - 1
		}
	}
	return 0
}

func refIsCtrl(c byte) bool {
	return c < 0x20 || c == 0x7f
}

// parseHTTP1RequestReference mirrors parse_http1_request. It returns the
// parsed fields and whether the sample would be submitted.
func parseHTTP1RequestReference(data []byte) (refHTTP1Request, bool) {
	var out refHTTP1Request
	if len(data) > refHTTP1PrefixLen {
		data = data[:refHTTP1PrefixLen]
	}
	dataLen := len(data)
	if dataLen < refMinRequestLine {
		return out, false
	}

	mlen := refMethodLen(data)
	if mlen == 0 {
		return out, false
	}
	out.Method = string(data[:mlen])

	pos := mlen + 1
	if data[pos] != '/' {
		return out, false
	}

	// Request-line scan: copy path until ' ' / '?' / the path cap.
	var path []byte
	afterSpace := 0
	copying := true
	idx := pos
	for ; idx < dataLen; idx++ {
		c := data[idx]
		if c == ' ' {
			afterSpace = idx + 1
			break
		}
		if refIsCtrl(c) {
			return refHTTP1Request{}, false
		}
		if c == '?' {
			copying = false
		}
		if copying && len(path) < refHTTPPathLen-1 {
			path = append(path, c)
		}
	}
	out.Path = string(path)

	if afterSpace == 0 {
		// Request line ran past the captured prefix: emit the captured path.
		return out, true
	}

	vOK := afterSpace+7 <= dataLen && string(data[afterSpace:afterSpace+7]) == "HTTP/1."
	if afterSpace+9 <= dataLen {
		// Validate the minor digit and the request-line CR so "HTTP/1.Xjunk"
		// is not accepted as HTTP.
		if !vOK || data[afterSpace+7] < '0' || data[afterSpace+7] > '9' ||
			data[afterSpace+8] != '\r' {
			return refHTTP1Request{}, false
		}
	} else if afterSpace+7 <= dataLen {
		if !vOK {
			return refHTTP1Request{}, false
		}
		return out, true
	} else {
		// Version token cut at the prefix boundary: emit, headers unseen.
		return out, true
	}

	// Header scan: "\r\nHost:" (case-insensitive name) or "\r\n\r\n".
	hostVal := 0
	headersDone := false
	for p := afterSpace; p+1 < dataLen; p++ {
		if data[p] != '\r' || data[p+1] != '\n' {
			continue
		}
		if p+3 < dataLen && data[p+2] == '\r' && data[p+3] == '\n' {
			headersDone = true
			break
		}
		if p+6 >= dataLen {
			break
		}
		if data[p+2]|0x20 == 'h' && data[p+3]|0x20 == 'o' &&
			data[p+4]|0x20 == 's' && data[p+5]|0x20 == 't' && data[p+6] == ':' {
			hostVal = p + 7
			break
		}
	}

	if hostVal == 0 {
		// No Host found (or it lives past the prefix / in a later write):
		// emit with an empty host.
		_ = headersDone
		return out, true
	}

	// Leading/trailing OWS is NOT skipped here — the kernel copies it verbatim
	// and userspace (handleHTTPRequestSample) trims it. This mirror reflects
	// the raw in-kernel parse.

	// A host value is used only when its CR/LF terminator is inside the prefix:
	// a silently cut host must not feed host-prefix rules. The terminator is
	// CR/LF only (not any control byte) — see http_step_hostlen.
	var host []byte
	hostTerminated := false
	for i := range refHTTPHostLen {
		p := hostVal + i
		if p >= dataLen {
			break
		}
		c := data[p]
		if c == '\r' || c == '\n' {
			hostTerminated = true
			break
		}
		if len(host) >= refHTTPHostLen-1 {
			break
		}
		host = append(host, c)
	}
	if !hostTerminated {
		// Unterminated (or oversize) host value within the prefix: emit empty.
		host = nil
	}
	// The raw host is normalized in userspace, not re-implemented here:
	// TestNormalizeHTTPHost pins normalizeHTTPHost's OWS/case/control-byte
	// rules directly, and this mirror delegates to the same function so the
	// two never drift. (An embedded NUL is a decode-boundary matter —
	// TestDecodeHTTPRequestSample — and does not reach normalizeHTTPHost.)
	out.Host = normalizeHTTPHost(string(host))
	return out, true
}

func TestParseHTTP1RequestReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    string
		want    refHTTP1Request
		wantOK  bool
		comment string
	}{
		{
			name:   "happy: basic GET with host",
			data:   "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want:   refHTTP1Request{Method: "GET", Path: "/index.html", Host: "example.com"},
			wantOK: true,
		},
		{
			name:   "happy: POST with body ignored",
			data:   "POST /api/upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\ndata",
			want:   refHTTP1Request{Method: "POST", Path: "/api/upload", Host: "api.example.com"},
			wantOK: true,
		},
		{
			name:   "query stripped at question mark",
			data:   "GET /search?q=secret+token HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want:   refHTTP1Request{Method: "GET", Path: "/search", Host: "example.com"},
			wantOK: true,
		},
		{
			name:   "cased host header name matched",
			data:   "GET / HTTP/1.1\r\nHOST: example.com\r\n\r\n",
			want:   refHTTP1Request{Method: "GET", Path: "/", Host: "example.com"},
			wantOK: true,
		},
		{
			name:    "host value flows through userspace normalization",
			data:    "GET / HTTP/1.1\r\nHost:   \tAPI.Example.COM\r\n\r\n",
			want:    refHTTP1Request{Method: "GET", Path: "/", Host: "api.example.com"},
			wantOK:  true,
			comment: "kernel copies OWS/case verbatim (CR/LF-only terminator); the raw value reaches normalizeHTTPHost — see TestNormalizeHTTPHost for the full rule table",
		},
		{
			name:    "authorization value never in output",
			data:    "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer sk_secret\r\n\r\n",
			want:    refHTTP1Request{Method: "GET", Path: "/", Host: "example.com"},
			wantOK:  true,
			comment: "redaction: only the three fields exist in the output shape",
		},
		{
			name:    "host absent with complete headers",
			data:    "GET / HTTP/1.0\r\nUser-Agent: x\r\n\r\n",
			want:    refHTTP1Request{Method: "GET", Path: "/"},
			wantOK:  true,
			comment: "\\r\\n\\r\\n proves an HTTP/1.0-style request really has no Host",
		},
		{
			name:    "host in a later write yields empty host",
			data:    "GET / HTTP/1.1\r\nUser-Agent: x\r\n",
			want:    refHTTP1Request{Method: "GET", Path: "/"},
			wantOK:  true,
			comment: "split-write gap: headers incomplete, Host may follow",
		},
		{
			name:    "missing CRLF after version emits path only",
			data:    "GET /aaaaaaa HTTP/1.1",
			want:    refHTTP1Request{Method: "GET", Path: "/aaaaaaa"},
			wantOK:  true,
			comment: "no header block seen at all",
		},
		{
			// The prefix is 256B and the path starts at byte 4, so a path
			// running to the prefix end is truncated before any space is
			// seen. want is the bytes captured within the first 256: "/" +
			// 251 'a' (4 header bytes + 252 path bytes = 256).
			name:    "request line past prefix boundary emits captured path",
			data:    "GET /" + strings.Repeat("a", 1100),
			want:    refHTTP1Request{Method: "GET", Path: "/" + strings.Repeat("a", 251)},
			wantOK:  true,
			comment: "prefix-boundary truncation: method + '/' is a strong HTTP signal",
		},
		{
			name:    "long query past prefix boundary keeps complete path",
			data:    "GET /short?" + strings.Repeat("q", 1100),
			want:    refHTTP1Request{Method: "GET", Path: "/short"},
			wantOK:  true,
			comment: "path completed at '?'; only the unseen headers are flagged",
		},
		{
			name:    "host value cut by prefix end is emptied",
			data:    "GET / HTTP/1.1\r\nHost: " + strings.Repeat("a", 1100),
			want:    refHTTP1Request{Method: "GET", Path: "/"},
			wantOK:  true,
			comment: "an unterminated host must not feed host-prefix rules",
		},
		{
			name:    "oversized host value is emptied",
			data:    "GET / HTTP/1.1\r\nHost: " + strings.Repeat("a", 300) + "\r\n\r\n",
			want:    refHTTP1Request{Method: "GET", Path: "/"},
			wantOK:  true,
			comment: "a >255-byte host is bogus; empty + flag, not a silent cut",
		},
		{
			name:   "error: connect authority form rejected",
			data:   "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantOK: false,
		},
		{
			name:   "error: options asterisk form rejected",
			data:   "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantOK: false,
		},
		{
			name:   "error: absolute form rejected",
			data:   "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantOK: false,
		},
		{
			name:   "error: unknown method rejected",
			data:   "BREW /coffee HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantOK: false,
		},
		{
			name:    "error: version mismatch rejected",
			data:    "GET / HTTP/2.0\r\nHost: example.com\r\n\r\n",
			wantOK:  false,
			comment: "space-separated tokens that are not HTTP/1",
		},
		{
			name:    "error: non-digit minor version rejected",
			data:    "GET / HTTP/1.Xjunk\r\nHost: example.com\r\n\r\n",
			wantOK:  false,
			comment: "\"HTTP/1.\" prefix is not enough; the minor must be a digit",
		},
		{
			name:    "error: junk after minor version rejected",
			data:    "GET / HTTP/1.1junk\r\nHost: example.com\r\n\r\n",
			wantOK:  false,
			comment: "the request line must end in CR right after the version",
		},
		{
			name:    "error: control byte in request line rejected",
			data:    "GET /a\x00b HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantOK:  false,
			comment: "a valid HTTP/1 request line has no control bytes",
		},
		{
			name:    "error: bare LF line ending rejected",
			data:    "GET /x\nHost: example.com\n\n",
			wantOK:  false,
			comment: "LF hit inside the request line before any space",
		},
		{
			name:   "error: too short rejected",
			data:   "GET / HTTP",
			wantOK: false,
		},
		{
			name:   "error: empty rejected",
			data:   "",
			wantOK: false,
		},
		{
			name:    "error: TLS record byte rejected",
			data:    "\x16\x03\x01\x02\x00" + strings.Repeat("x", 20),
			wantOK:  false,
			comment: "ciphertext can never match a method token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := parseHTTP1RequestReference([]byte(tt.data))
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tt.wantOK, got)
			}
			if !ok {
				return
			}
			if got != tt.want {
				t.Fatalf("parse = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// FuzzParseHTTP1RequestReference asserts the parse never panics and that
// every accepted output honors the field invariants the eBPF parse enforces.
func FuzzParseHTTP1RequestReference(f *testing.F) {
	f.Add([]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("POST /a?b=c HTTP/1.1\r\nhost:\tx.example\r\nAuthorization: Bearer s\r\n\r\n"))
	f.Add([]byte("OPTIONS * HTTP/1.1\r\n\r\n"))
	f.Add([]byte("\x16\x03\x01\x02\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, ok := parseHTTP1RequestReference(data)
		if !ok {
			return
		}
		if refMethodLen([]byte(got.Method+" ")) == 0 {
			t.Fatalf("accepted unknown method %q", got.Method)
		}
		if !strings.HasPrefix(got.Path, "/") {
			t.Fatalf("accepted non-origin-form path %q", got.Path)
		}
		if strings.ContainsRune(got.Path, '?') {
			t.Fatalf("query leaked into path %q", got.Path)
		}
		if len(got.Path) > refHTTPPathLen-1 || len(got.Host) > refHTTPHostLen-1 {
			t.Fatalf("field over cap: path=%d host=%d", len(got.Path), len(got.Host))
		}
		for _, field := range []string{got.Method, got.Path, got.Host} {
			for _, c := range []byte(field) {
				if refIsCtrl(c) {
					t.Fatalf("control byte in output field %q", field)
				}
			}
		}
	})
}
