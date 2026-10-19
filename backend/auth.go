package main

// Single-user login for the prototype.
// APP_USER + APP_PASSWORD_HASH (pbkdf2_sha256$iterations$salt$hash) + SESSION_SECRET come from Secret Manager
// via Cloud Run env. Auth is off when unset (local dev, tests).

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cookieName = "sv_session"
	cookieTTL  = 12 * 3600
	bearerTTL  = 10 * 365 * 24 * 3600 // phone stays signed in until Sign out; rotating SESSION_SECRET revokes
	maxFails   = 5
	failWindow = 15 * 60
)

var (
	failMu         sync.Mutex
	fails          = map[string][]time.Time{}
	fallbackSecret = randomHex(32) // per instance; set SESSION_SECRET so sessions survive restarts
)

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func authCfg() (user, pwHash string, secret []byte) {
	env := func(k string) string { return strings.TrimSpace(os.Getenv(k)) } // shells can add a trailing newline
	s := env("SESSION_SECRET")
	if s == "" {
		s = fallbackSecret
	}
	return env("APP_USER"), env("APP_PASSWORD_HASH"), []byte(s)
}

func authEnabled() bool {
	u, h, _ := authCfg()
	return u != "" && h != ""
}

func hashPassword(password string) (string, error) {
	const iterations = 310_000
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", iterations, base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(dk)), nil
}

func verifyPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	iters, err1 := strconv.Atoi(parts[1])
	salt, err2 := base64.StdEncoding.DecodeString(parts[2])
	want, err3 := base64.StdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || err3 != nil || iters <= 0 {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, iters, len(want))
	return err == nil && hmac.Equal(dk, want)
}

func checkCredentials(username, password string) bool {
	user, pwHash, _ := authCfg()
	okUser := subtle.ConstantTimeCompare([]byte(username), []byte(user)) == 1
	okPw := verifyPassword(password, pwHash) // always run: no timing hint about the username
	return okUser && okPw
}

func makeToken(ttl int) string {
	user, _, secret := authCfg()
	payload := []byte(fmt.Sprintf("%s|%d", user, time.Now().Unix()+int64(ttl)))
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(mac.Sum(nil))
}

func checkToken(token string) bool {
	p, s, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	enc := base64.RawURLEncoding
	payload, err1 := enc.DecodeString(p)
	sig, err2 := enc.DecodeString(s)
	if err1 != nil || err2 != nil {
		return false
	}
	user, _, secret := authCfg()
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	tokUser, expStr, ok := strings.Cut(string(payload), "|")
	exp, err := strconv.ParseInt(expStr, 10, 64)
	return ok && err == nil && tokUser == user && exp > time.Now().Unix()
}

func lockedOut(ip string) bool {
	failMu.Lock()
	defer failMu.Unlock()
	cutoff := time.Now().Add(-failWindow * time.Second)
	recent := fails[ip][:0]
	for _, t := range fails[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	fails[ip] = recent
	return len(recent) >= maxFails
}

func recordFailure(ip string) {
	failMu.Lock()
	defer failMu.Unlock()
	fails[ip] = append(fails[ip], time.Now())
}

func clearFailures(ip string) {
	failMu.Lock()
	defer failMu.Unlock()
	delete(fails, ip)
}

// safeNext allows only same-site relative paths, so the login form can't redirect elsewhere.
// Browsers drop tabs/newlines and treat \ as /, so "/\t/evil.com" would become "//evil.com".
func safeNext(path string) string {
	bad := strings.IndexFunc(path, func(c rune) bool { return c <= ' ' || c == 0x7f || c == '\\' }) >= 0
	if bad || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return "/"
	}
	return path
}
