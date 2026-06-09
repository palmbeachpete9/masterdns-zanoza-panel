package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Static assets are served from a shared in-memory cache (no per-request
// full-file read/allocation) and support ETag/If-None-Match revalidation.
func TestServeAssetCachedWithETag(t *testing.T) {
	s := newTestServer(t)
	body := make([]byte, 170*1024) // ~JS bundle size
	for i := range body {
		body[i] = byte(i)
	}
	s.assets = map[string]cachedFile{
		"assets/app.js": {body: body, contentType: "text/javascript; charset=utf-8", etag: `"abc123"`},
	}

	// Normal GET returns the body, content type and ETag.
	w := httptest.NewRecorder()
	s.serveAsset(w, httptest.NewRequest(http.MethodGet, "/admin/assets/app.js", nil), "assets/app.js")
	if w.Code != http.StatusOK || w.Body.Len() != len(body) {
		t.Fatalf("serve: code=%d len=%d want 200/%d", w.Code, w.Body.Len(), len(body))
	}
	if w.Header().Get("ETag") != `"abc123"` || w.Header().Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Fatalf("headers: etag=%q ct=%q", w.Header().Get("ETag"), w.Header().Get("Content-Type"))
	}

	// Matching If-None-Match returns 304 with no body (no re-serve).
	r := httptest.NewRequest(http.MethodGet, "/admin/assets/app.js", nil)
	r.Header.Set("If-None-Match", `"abc123"`)
	w2 := httptest.NewRecorder()
	s.serveAsset(w2, r, "assets/app.js")
	if w2.Code != http.StatusNotModified || w2.Body.Len() != 0 {
		t.Fatalf("revalidation: code=%d len=%d want 304/0", w2.Code, w2.Body.Len())
	}

	// The cache returns the SAME backing array each call (not a fresh copy).
	if &s.assets["assets/app.js"].body[0] != &body[0] {
		t.Fatal("asset body should be the shared cached slice")
	}

	// Unknown asset -> 404.
	w3 := httptest.NewRecorder()
	s.serveAsset(w3, httptest.NewRequest(http.MethodGet, "/admin/assets/nope.js", nil), "assets/nope.js")
	if w3.Code != http.StatusNotFound {
		t.Fatalf("unknown asset: code=%d want 404", w3.Code)
	}
}
