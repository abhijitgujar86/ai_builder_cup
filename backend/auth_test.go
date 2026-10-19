package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func withAuth(t *testing.T) http.Handler {
	offline(t)
	h, err := hashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_USER", "demo")
	t.Setenv("APP_PASSWORD_HASH", h)
	t.Setenv("SESSION_SECRET", "test-secret")
	failMu.Lock()
	fails = map[string][]time.Time{}
	failMu.Unlock()
	return newServer()
}

func TestSafeNextRejectsOffsite(t *testing.T) {
	for _, p := range []string{"", "evil.com", "//evil.com", "/\\evil.com", "/\t/evil.com", "/\n/evil.com", "/ /evil.com", "https://evil.com"} {
		if got := safeNext(p); got != "/" {
			t.Errorf("safeNext(%q) = %q", p, got)
		}
	}
	if got := safeNext("/check?x=1"); got != "/check?x=1" {
		t.Errorf("same-site path changed: %q", got)
	}
}

func TestClientIPUsesLastForwardedEntry(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("got %q", got)
	}
}

func TestPagesRedirectToLogin(t *testing.T) {
	h := withAuth(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 303 || !strings.HasPrefix(rec.Header().Get("Location"), "/login") {
		t.Fatalf("got %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestAPIRequiresAuth(t *testing.T) {
	rec, _ := postJSON(t, withAuth(t), "/v1/check/json", map[string]string{"text": "hi"})
	if rec.Code != 401 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestPublicPathsOpen(t *testing.T) {
	h := withAuth(t)
	for _, p := range []string{"/health", "/login", "/static/style.css"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != 200 {
			t.Fatalf("%s: %d", p, rec.Code)
		}
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	rec, _ := postForm(t, withAuth(t), "/login", url.Values{"username": {"demo"}, "password": {"nope"}})
	if !strings.Contains(rec.Header().Get("Location"), "error=1") || len(rec.Result().Cookies()) > 0 {
		t.Fatalf("got %s", rec.Header().Get("Location"))
	}
}

func TestCookieLoginFlow(t *testing.T) {
	h := withAuth(t)
	rec, _ := postForm(t, h, "/login", url.Values{"username": {"demo"}, "password": {"correct horse"}, "next": {"/#paid"}})
	if rec.Code != 303 || rec.Header().Get("Location") != "/#paid" {
		t.Fatalf("got %d %s", rec.Code, rec.Header().Get("Location"))
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly {
		t.Fatal("expected one HttpOnly session cookie")
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookies[0])
	r2 := httptest.NewRecorder()
	h.ServeHTTP(r2, req)
	if r2.Code != 200 {
		t.Fatalf("home with cookie: %d", r2.Code)
	}
}

func TestOpenRedirectBlocked(t *testing.T) {
	rec, _ := postForm(t, withAuth(t), "/login", url.Values{"username": {"demo"}, "password": {"correct horse"}, "next": {"//evil.example"}})
	if rec.Header().Get("Location") != "/" {
		t.Fatalf("got %s", rec.Header().Get("Location"))
	}
}

func TestBearerTokenLogin(t *testing.T) {
	h := withAuth(t)
	_, r := postJSON(t, h, "/v1/auth/login", map[string]string{"username": "demo", "password": "correct horse"})
	tok, _ := r["token"].(string)
	if r["expires_in"].(float64) < 5*365*24*3600 {
		t.Fatalf("expires_in %v", r["expires_in"])
	}
	for suffix, want := range map[string]int{"": 200, "x": 401} {
		req := httptest.NewRequest("POST", "/v1/events/device", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+tok+suffix)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("token%q: got %d want %d", suffix, rec.Code, want)
		}
	}
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	h := withAuth(t)
	for i := 0; i < maxFails; i++ {
		postJSON(t, h, "/v1/auth/login", map[string]string{"username": "demo", "password": "bad"})
	}
	rec, _ := postJSON(t, h, "/v1/auth/login", map[string]string{"username": "demo", "password": "correct horse"})
	if rec.Code != 429 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestTokenFromOtherSecretRejected(t *testing.T) {
	withAuth(t)
	tok := makeToken(60)
	t.Setenv("SESSION_SECRET", "rotated")
	if checkToken(tok) {
		t.Fatal("token accepted after secret rotation")
	}
}

func TestPythonHashFormatStillVerifies(t *testing.T) {
	// Made by the previous Python backend; the live Secret Manager hash uses this format.
	const py = "pbkdf2_sha256$310000$Ge4QDhWbttlS9iFgcUA3tQ==$Yj53NEWEnnSGYIijeNq39M6B3bUwq7duD9G9OpS+g7U="
	if !verifyPassword("correct horse", py) || verifyPassword("wrong", py) {
		t.Fatal("python hash not verified")
	}
	h, _ := hashPassword("correct horse")
	if !verifyPassword("correct horse", h) {
		t.Fatal("round trip failed")
	}
}
