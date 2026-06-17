package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLocalRefererPath verifies that localRefererPath only honors absolute,
// same-host http(s) Referers and always reduces them to a rooted, host-less
// relative path, so the Referer header cannot be abused as an open redirect.
func TestLocalRefererPath(t *testing.T) {
	const host = "app.example.com"

	tests := []struct {
		name     string
		referer  string
		wantOK   bool
		wantDest string
	}{
		// Accepted: absolute, same-host Referers (what browsers actually send).
		{name: "same host simple path", referer: "https://app.example.com/servers/abc", wantOK: true, wantDest: "/servers/abc"},
		{name: "same host with query", referer: "https://app.example.com/servers/abc?tab=logs", wantOK: true, wantDest: "/servers/abc?tab=logs"},
		{name: "same host root no path", referer: "https://app.example.com", wantOK: true, wantDest: "/"},
		{name: "same host case-insensitive", referer: "https://APP.Example.com/profiles/x", wantOK: true, wantDest: "/profiles/x"},
		{name: "same host http scheme", referer: "http://app.example.com/servers/abc", wantOK: true, wantDest: "/servers/abc"},

		// Rejected: cross-host and open-redirect tricks.
		{name: "cross host", referer: "https://evil.com/x"},
		{name: "cross host with same-host prefix", referer: "https://app.example.com.evil.com/x"},
		{name: "protocol relative", referer: "//evil.com"},
		{name: "backslash protocol relative", referer: `/\evil.com`},
		{name: "double backslash", referer: `\/\/evil.com`},
		{name: "leading backslash", referer: `\evil.com`},
		{name: "userinfo at attacker host", referer: "https://app.example.com@evil.com/x"},
		{name: "userinfo with same host", referer: "https://evil.com@app.example.com/x"},
		{name: "malformed single slash host", referer: "https:/evil.com"},
		{name: "malformed triple slash host", referer: "https:///evil.com"},
		{name: "javascript scheme", referer: "javascript:alert(1)"},
		{name: "data scheme", referer: "data:text/html,<script>alert(1)</script>"},
		{name: "mailto scheme", referer: "mailto:a@example.com"},
		{name: "relative path referer", referer: "/servers/abc"},
		{name: "leading space", referer: " https://app.example.com/x"},
		{name: "trailing space", referer: "https://app.example.com/x "},
		{name: "embedded tab", referer: "https://app.example.com/x\ty"},
		{name: "embedded newline", referer: "https://app.example.com/x\ny"},
		{name: "crlf header injection", referer: "https://app.example.com/x\r\nSet-Cookie: a=b"},
		{name: "embedded DEL control", referer: "https://app.example.com/x\x7fy"},
		{name: "empty", referer: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://app.example.com/servers/abc/start", nil)
			r.Host = host

			dest, ok := localRefererPath(r, tt.referer)
			if ok != tt.wantOK {
				t.Fatalf("localRefererPath(%q) ok = %v, want %v (dest=%q)", tt.referer, ok, tt.wantOK, dest)
			}
			if ok && dest != tt.wantDest {
				t.Errorf("localRefererPath(%q) dest = %q, want %q", tt.referer, dest, tt.wantDest)
			}
			// An accepted destination must always be a rooted, host-less path.
			if ok {
				if len(dest) == 0 || dest[0] != '/' || (len(dest) > 1 && dest[1] == '/') {
					t.Errorf("accepted dest %q is not a rooted host-less path", dest)
				}
			}
		})
	}
}
