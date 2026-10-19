// Dhaal API + web app (Cloud Run).
package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

//go:embed static
var staticFS embed.FS

const (
	maxImage = 7 << 20
	maxAudio = 15 << 20
	maxBody  = 40 << 20
)

var audioExt = set(".opus", ".ogg", ".m4a", ".mp3", ".wav", ".aac", ".amr", ".3gp", ".webm", ".flac", ".mp4")
var publicPaths = set("/login", "/logout", "/health", "/v1/auth/login", "/static/style.css")

func main() {
	// `dhaal hash-password` reads SV_NEW_PASSWORD (env, not argv or stdin) and prints the stored hash.
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		h, err := hashPassword(os.Getenv("SV_NEW_PASSWORD"))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(h)
		return
	}
	port := envOr("PORT", "8080")
	log.Printf("dhaal listening on :%s (gemini=%v auth=%v)", port, geminiConfigured(), authEnabled())
	log.Fatal(http.ListenAndServe(":"+port, newServer()))
}

func newServer() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("GET /{$}", servePage("index.html"))
	mux.HandleFunc("GET /login", servePage("login.html"))
	mux.HandleFunc("POST /login", loginSubmit)
	mux.HandleFunc("GET /logout", logout)
	// Not /healthz: Cloud Run's front end reserves paths ending in "z".
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "gemini": geminiConfigured(), "webrisk": webRiskEnabled(),
			"models": map[string]string{"fast": modelFast, "deep": modelDeep}})
	})
	mux.HandleFunc("POST /v1/auth/login", apiLogin)
	mux.HandleFunc("GET /v1/kb", knowledgeBase)
	mux.HandleFunc("POST /v1/check", check)
	mux.HandleFunc("POST /v1/check/json", checkJSON)
	mux.HandleFunc("POST /v1/check/number", checkNumberHandler)
	mux.HandleFunc("POST /v1/check/upi", checkUPIHandler)
	mux.HandleFunc("POST /v1/check/link", checkLinkHandler)
	mux.HandleFunc("POST /v1/check/qr", checkQRHandler)
	mux.HandleFunc("POST /v1/before-pay", beforePay)
	mux.HandleFunc("POST /v1/events/device", deviceEvent)
	mux.HandleFunc("POST /v1/report", report)
	mux.HandleFunc("POST /v1/paid-guide", paidGuideHandler)
	registerCommunityRoutes(mux)
	return requireLogin(mux)
}

func servePage(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := staticFS.ReadFile("static/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	}
}

// ---------- auth ----------

// Last X-Forwarded-For entry: Cloud Run's front end appends it; earlier entries are client-supplied.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	return r.RemoteAddr
}

func requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authEnabled() || publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		token := ""
		if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
			token = h[7:]
		} else if c, err := r.Cookie(cookieName); err == nil {
			token = c.Value
		}
		if checkToken(token) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			writeErr(w, 401, "Sign in required")
			return
		}
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
	})
}

func loginSubmit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ip := clientIP(r)
	target := safeNext(r.PostFormValue("next"))
	q := "&next=" + url.QueryEscape(target)
	if lockedOut(ip) {
		http.Redirect(w, r, "/login?error=locked"+q, http.StatusSeeOther)
		return
	}
	if !checkCredentials(r.PostFormValue("username"), r.PostFormValue("password")) {
		recordFailure(ip)
		http.Redirect(w, r, "/login?error=1"+q, http.StatusSeeOther)
		return
	}
	clearFailures(ip)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: makeToken(cookieTTL), Path: "/", MaxAge: cookieTTL,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"})
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func apiLogin(w http.ResponseWriter, r *http.Request) {
	var body struct{ Username, Password string }
	if !readJSON(w, r, &body) {
		return
	}
	ip := clientIP(r)
	if lockedOut(ip) {
		writeErr(w, 429, "Too many attempts. Try again in 15 minutes.")
		return
	}
	if !checkCredentials(body.Username, body.Password) {
		recordFailure(ip)
		writeErr(w, 401, "Wrong username or password")
		return
	}
	clearFailures(ip)
	writeJSON(w, 200, map[string]any{"token": makeToken(bearerTTL), "expires_in": bearerTTL})
}

// ---------- checks ----------

func knowledgeBase(w http.ResponseWriter, r *http.Request) {
	cats := []map[string]string{}
	for _, id := range categoryOrder {
		c := Categories[id]
		cats = append(cats, map[string]string{"id": id, "lever": c.Lever, "name": c.Name})
	}
	writeJSON(w, 200, map[string]any{"levers": Levers, "categories": cats, "red_flags": RedFlags,
		"official_facts": OfficialFacts, "helplines": Helplines, "remote_access_apps": RemoteAccessApps})
}

// parseForm accepts multipart (app, web uploads) and urlencoded bodies.
func parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	var err error
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		err = r.ParseMultipartForm(16 << 20)
	} else {
		err = r.ParseForm()
	}
	if err != nil {
		writeErr(w, 400, "Could not read the form")
		return false
	}
	return true
}

func readUpload(fh *multipart.FileHeader) ([]byte, error) {
	f, err := fh.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func splitUploads(w http.ResponseWriter, r *http.Request) (images, audio []Media, ok bool) {
	if r.MultipartForm == nil {
		return nil, nil, true
	}
	total := 0
	for _, fh := range r.MultipartForm.File["files"] {
		data, err := readUpload(fh)
		if err != nil || len(data) == 0 {
			continue
		}
		ct := strings.ToLower(fh.Header.Get("Content-Type"))
		ext := strings.ToLower(filepath.Ext(fh.Filename))
		switch {
		case strings.HasPrefix(ct, "image/"):
			if len(data) > maxImage {
				writeErr(w, 413, "Image too large (max 7 MB)")
				return nil, nil, false
			}
			images = append(images, Media{data, ct})
		case strings.HasPrefix(ct, "audio/") || strings.HasPrefix(ct, "video/") || audioExt[ext] || ct == "application/ogg":
			total += len(data)
			if total > maxAudio {
				writeErr(w, 413, "Audio too large (max 15 MB)")
				return nil, nil, false
			}
			audio = append(audio, toGeminiAudio(r.Context(), data, firstNonEmpty(ct, "audio/ogg"), fh.Filename))
		default:
			writeErr(w, 415, "Unsupported file type: "+firstNonEmpty(ct, ext))
			return nil, nil, false
		}
	}
	return images, audio, true
}

func check(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	text, ctxText := r.FormValue("text"), r.FormValue("context")
	if len(text) > 8000 || len(ctxText) > 4000 {
		writeErr(w, 413, "Text too long")
		return
	}
	images, audio, ok := splitUploads(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(text) == "" && strings.TrimSpace(ctxText) == "" && len(images) == 0 && len(audio) == 0 {
		writeErr(w, 400, "Send text, an image or an audio file")
		return
	}
	writeJSON(w, 200, analyze(r.Context(), text, images, audio, firstNonEmpty(r.FormValue("source"), "manual"),
		firstNonEmpty(r.FormValue("lang"), "auto"), ctxText))
}

func checkJSON(w http.ResponseWriter, r *http.Request) {
	body := struct {
		Text, Source, Lang string
		Sender             *string
	}{Source: "notification", Lang: "auto"}
	if !readJSON(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.Text) == "" || len(body.Text) > 8000 {
		writeErr(w, 400, "text required (max 8000 chars)")
		return
	}
	ctxText := ""
	if body.Sender != nil && *body.Sender != "" {
		ctxText = "Sender: " + *body.Sender
	}
	writeJSON(w, 200, analyze(r.Context(), body.Text, nil, nil, body.Source, body.Lang, ctxText))
}

type valueBody struct {
	Value, Context, Lang string
}

var simpleMsg = map[string]map[string]string{
	"en": {"LOW": "No scam reports or warning signs found. That does not prove it is safe: never pay or share an OTP because a caller says so.",
		"CAUTION":  "Some warning signs. Verify through an official number before you do anything.",
		"HIGH":     "Strong warning signs. Do not pay or share anything.",
		"CRITICAL": "This is very likely a scam. Do not pay, scan or share anything."},
	"hi": {"LOW": "कोई रिपोर्ट या चेतावनी संकेत नहीं मिला। इसका मतलब यह नहीं कि यह सुरक्षित है: किसी कॉलर के कहने पर पैसे या OTP न दें।",
		"CAUTION":  "कुछ चेतावनी संकेत हैं। कुछ भी करने से पहले आधिकारिक नंबर से जांचें।",
		"HIGH":     "मज़बूत चेतावनी संकेत। पैसे न भेजें, कुछ भी न बताएं।",
		"CRITICAL": "यह लगभग निश्चित रूप से धोखा है। पैसे न भेजें, स्कैन न करें, कुछ न बताएं।"},
}

func simpleVerdict(sigs []Signal, override bool, lang string, extra map[string]any) map[string]any {
	s := score(sigs, override)
	lvl := level(s)
	lk := "en"
	if strings.HasPrefix(strings.ToLower(lang), "hi") {
		lk = "hi"
	}
	if sigs == nil {
		sigs = []Signal{}
	}
	out := map[string]any{"score": s, "level": lvl, "message": simpleMsg[lk][lvl], "signals": sigs,
		"verify_at": "cybercrime.gov.in (Report & Check Suspect)"}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func readValue(w http.ResponseWriter, r *http.Request) (valueBody, bool) {
	b := valueBody{Lang: "en"}
	ok := readJSON(w, r, &b)
	return b, ok
}

func checkNumberHandler(w http.ResponseWriter, r *http.Request) {
	b, ok := readValue(w, r)
	if !ok {
		return
	}
	e164 := normalizePhone(b.Value)
	sigs := append(repSignals("number", e164), checkNumber(e164, b.Context)...)
	writeJSON(w, 200, simpleVerdict(sigs, false, b.Lang, map[string]any{"value": e164, "reports": repLookup("number", e164)}))
}

func checkUPIHandler(w http.ResponseWriter, r *http.Request) {
	b, ok := readValue(w, r)
	if !ok {
		return
	}
	v := strings.TrimSpace(b.Value)
	sigs := append(repSignals("upi", v), checkUPI(v, b.Context)...)
	writeJSON(w, 200, simpleVerdict(sigs, false, b.Lang, map[string]any{"value": v, "reports": repLookup("upi", v)}))
}

func checkLinkHandler(w http.ResponseWriter, r *http.Request) {
	b, ok := readValue(w, r)
	if !ok {
		return
	}
	u := strings.TrimSpace(b.Value)
	sigs := append(append(checkURL(u), repSignals("url", u)...), webRiskCheck(r.Context(), u)...)
	writeJSON(w, 200, simpleVerdict(sigs, false, b.Lang, map[string]any{"value": u, "webrisk_checked": webRiskEnabled()}))
}

// checkQRHandler takes a QR payload decoded on the phone (ML Kit).
func checkQRHandler(w http.ResponseWriter, r *http.Request) {
	b, ok := readValue(w, r)
	if !ok {
		return
	}
	res := checkQR(strings.TrimSpace(b.Value), b.Context)
	sigs := append([]Signal{}, res.Signals...)
	for _, v := range res.UPIIDs {
		sigs = append(append(sigs, repSignals("upi", v)...), checkUPI(v, b.Context)...)
	}
	for _, u := range res.URLs {
		sigs = append(append(sigs, checkURL(u)...), repSignals("url", u)...)
	}
	out := simpleVerdict(sigs, res.OverrideCritical, b.Lang, map[string]any{"qr": res.QR})
	if len(res.QR) > 0 && res.QR[0].IsPayRequest {
		out["message"] = res.Flags["F05"] + " " + out["message"].(string)
		out["official_fact"] = OfficialFacts["OF11"]
	}
	writeJSON(w, 200, out)
}

func beforePay(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Amount         string `json:"amount"`
		Payee          string `json:"payee"`
		Reason         string `json:"reason"`
		Lang           string `json:"lang"`
		AskedByCaller  *bool  `json:"asked_by_caller"`
		KeepSecret     *bool  `json:"keep_secret"`
		ToReceiveMoney *bool  `json:"to_receive_money"`
		OnCallNow      *bool  `json:"on_call_now"`
		BreakFDOrLoan  *bool  `json:"break_fd_or_loan"`
	}
	b.Lang = "auto"
	if !readJSON(w, r, &b) {
		return
	}
	text := fmt.Sprintf("I am about to pay %s to %s. Reason: %s.", firstNonEmpty(b.Amount, "some money"),
		firstNonEmpty(b.Payee, "someone"), firstNonEmpty(b.Reason, "not given"))
	qs := []struct {
		q string
		v *bool
	}{
		{"Did someone on a call or message ask you to make this payment?", b.AskedByCaller},
		{"Were you told to keep it secret or not tell the bank?", b.KeepSecret},
		{"Is this payment so that you can receive money (prize, refund, job, buyer payment)?", b.ToReceiveMoney},
		{"Are you on a call right now?", b.OnCallNow},
		{"Are you breaking a fixed deposit, taking a loan or selling gold for this?", b.BreakFDOrLoan},
	}
	var lines []string
	for _, q := range qs {
		if q.v != nil {
			ans := "No"
			if *q.v {
				ans = "Yes"
			}
			lines = append(lines, q.q+" "+ans)
		}
	}
	res := analyze(r.Context(), text, nil, nil, "before_pay", b.Lang, strings.Join(lines, "\n"))
	// Yes-answers are explicit user statements: guarantee they show as flags even if the model skipped them.
	have := map[string]bool{}
	for _, f := range res.RedFlags {
		have[f.FlagID] = true
	}
	for _, x := range []struct {
		yes *bool
		fid string
	}{{b.KeepSecret, "F01"}, {b.ToReceiveMoney, "F04"}, {b.BreakFDOrLoan, "F09"}} {
		if x.yes != nil && *x.yes && !have[x.fid] {
			res.RedFlags = append(res.RedFlags, FlagOut{FlagID: x.fid, Label: RedFlags[x.fid], Evidence: "Your answer: Yes", Source: "user"})
		}
	}
	writeJSON(w, 200, res)
}

func deviceEvent(w http.ResponseWriter, r *http.Request) {
	e := defaultDeviceEvent()
	if !readJSON(w, r, &e) {
		return
	}
	writeJSON(w, 200, evaluateDevice(e))
}

func report(w http.ResponseWriter, r *http.Request) {
	var b struct{ Type, Value, Category string }
	if !readJSON(w, r, &b) {
		return
	}
	if b.Type != "number" && b.Type != "upi" && b.Type != "url" {
		writeErr(w, 422, "type must be number, upi or url")
		return
	}
	if _, ok := Categories[b.Category]; !ok {
		b.Category = ""
	}
	row := repReport(b.Type, b.Value, b.Category)
	writeJSON(w, 200, map[string]any{"ok": true, "reports": row.Count, "also_report_at": "sancharsaathi.gov.in (Chakshu)"})
}

func paidGuideHandler(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	d := PaidDetails{Amount: r.FormValue("amount"), Method: r.FormValue("method"), Bank: r.FormValue("bank"),
		Payee: r.FormValue("payee"), TxnID: r.FormValue("txn_id"), When: r.FormValue("when"), WhatHappened: r.FormValue("what_happened")}
	if v, err := strconv.Atoi(r.FormValue("minutes_ago")); err == nil {
		d.MinutesAgo = &v
	}
	var shot *Media
	if r.MultipartForm != nil {
		if fhs := r.MultipartForm.File["screenshot"]; len(fhs) > 0 {
			data, err := readUpload(fhs[0])
			if err == nil && len(data) > 0 {
				if len(data) > maxImage {
					writeErr(w, 413, "Image too large (max 7 MB)")
					return
				}
				shot = &Media{data, firstNonEmpty(fhs[0].Header.Get("Content-Type"), "image/jpeg")}
			}
		}
	}
	writeJSON(w, 200, paidGuide(r.Context(), d, firstNonEmpty(r.FormValue("lang"), "en"), shot))
}

// ---------- JSON helpers ----------

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, 422, "Invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"detail": msg})
}
