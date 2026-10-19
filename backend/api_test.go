package main

// Rules-only API tests (Gemini disabled), so they run offline and in CI.

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func offline(t *testing.T) {
	for _, k := range []string{"GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI", "WEBRISK_API_KEY", "APP_USER", "APP_PASSWORD_HASH"} {
		t.Setenv(k, "")
	}
}

func do(t *testing.T, h http.Handler, req *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func postJSON(t *testing.T, h http.Handler, path string, v any) (*httptest.ResponseRecorder, map[string]any) {
	b, _ := json.Marshal(v)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	return do(t, h, req)
}

func postForm(t *testing.T, h http.Handler, path string, form url.Values) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return do(t, h, req)
}

func checkText(t *testing.T, h http.Handler, text string) map[string]any {
	t.Helper()
	rec, v := postForm(t, h, "/v1/check", url.Values{"text": {text}})
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	return v
}

func flagIDs(v map[string]any) map[string]bool {
	out := map[string]bool{}
	flags, _ := v["red_flags"].([]any)
	for _, f := range flags {
		out[f.(map[string]any)["flag_id"].(string)] = true
	}
	return out
}

func signalNames(v map[string]any) map[string]bool {
	out := map[string]bool{}
	sigs, _ := v["signals"].([]any)
	for _, s := range sigs {
		out[s.(map[string]any)["name"].(string)] = true
	}
	return out
}

func TestDigitalArrestIsCritical(t *testing.T) {
	offline(t)
	v := checkText(t, newServer(), "CBI officer on video call says my Aadhaar is in a money laundering case. "+
		"Send 5 lakh to RBI verification account, kisi ko mat batana.")
	if v["level"] != "CRITICAL" || v["verdict"] != "SCAM" {
		t.Fatalf("got %v %v", v["level"], v["verdict"])
	}
	if v["category"].(map[string]any)["id"] != "C01" {
		t.Fatalf("category %v", v["category"])
	}
	ids := flagIDs(v)
	if !ids["F01"] || !ids["F03"] {
		t.Fatalf("flags %v", ids)
	}
	pb := v["playbook"].(map[string]any)["steps"].([]any)
	if v["degraded"] != true || len(pb) == 0 {
		t.Fatal("expected degraded rules-only answer with playbook")
	}
}

func TestGenuineOTPSMSNotFlagged(t *testing.T) {
	offline(t)
	v := checkText(t, newServer(), "123456 is your OTP for login. Do not share OTP with anyone. -SBI")
	if flagIDs(v)["F08"] {
		t.Fatal("negated OTP advice flagged as F08")
	}
	if v["level"] != "LOW" && v["level"] != "CAUTION" || v["verdict"] == "SCAM" {
		t.Fatalf("got %v %v", v["level"], v["verdict"])
	}
}

func TestHindiInputGetsHindiFallback(t *testing.T) {
	offline(t)
	v := checkText(t, newServer(), "आपकी बिजली कट जाएगी, तुरंत इस नंबर पर कॉल करें")
	if v["lang"] != "hi-IN" {
		t.Fatalf("lang %v", v["lang"])
	}
}

func TestQRPayWithReceiveContextIsCritical(t *testing.T) {
	offline(t)
	_, v := postJSON(t, newServer(), "/v1/check/qr", map[string]string{
		"value": "upi://pay?pa=armyofficer.posted@okaxis&pn=Army%20Officer&am=5000", "context": "buyer says scan to receive advance"})
	if v["level"] != "CRITICAL" || !strings.Contains(v["message"].(string), "SENDS") {
		t.Fatalf("got %v %v", v["level"], v["message"])
	}
}

func TestAPKLinkFlagged(t *testing.T) {
	offline(t)
	_, v := postJSON(t, newServer(), "/v1/check/link", map[string]string{"value": "http://sbi-rewards.top/SBI_REWARD.apk"})
	n := signalNames(v)
	if !n["apk_download"] || !n["brand_lookalike"] || (v["level"] != "HIGH" && v["level"] != "CRITICAL") {
		t.Fatalf("got %v %v", n, v["level"])
	}
}

func TestSeededNumberReported(t *testing.T) {
	offline(t)
	_, v := postJSON(t, newServer(), "/v1/check/number", map[string]string{"value": "98765 00001"})
	if v["value"] != "+919876500001" || v["level"] == "LOW" {
		t.Fatalf("got %v %v", v["value"], v["level"])
	}
}

func TestReportIncrements(t *testing.T) {
	offline(t)
	h := newServer()
	_, a := postJSON(t, h, "/v1/report", map[string]string{"type": "upi", "value": "newscam@ybl"})
	_, b := postJSON(t, h, "/v1/report", map[string]string{"type": "upi", "value": "newscam@ybl"})
	if b["reports"].(float64) != a["reports"].(float64)+1 {
		t.Fatalf("%v then %v", a["reports"], b["reports"])
	}
}

func TestDeviceCallPlusPayment(t *testing.T) {
	offline(t)
	_, v := postJSON(t, newServer(), "/v1/events/device", map[string]any{"on_call": true, "call_type": "phone",
		"caller_known": false, "payment_app_foreground": true, "payment_app": "PhonePe"})
	if v["show_fullscreen"] != true || !strings.Contains(v["message"].(string), "PhonePe") {
		t.Fatalf("got %v", v)
	}
}

func TestDeviceOTPDuringUnknownCallIsCritical(t *testing.T) {
	offline(t)
	_, v := postJSON(t, newServer(), "/v1/events/device", map[string]any{"on_call": true, "caller_known": false, "otp_received_during_call": true})
	if v["level"] != "CRITICAL" {
		t.Fatalf("got %v", v["level"])
	}
}

func TestDeviceQuiet(t *testing.T) {
	offline(t)
	_, v := postJSON(t, newServer(), "/v1/events/device", map[string]any{})
	if v["level"] != "LOW" || v["show_fullscreen"] != false {
		t.Fatalf("got %v", v)
	}
}

func TestBeforePayYesAnswersBecomeFlags(t *testing.T) {
	offline(t)
	_, v := postJSON(t, newServer(), "/v1/before-pay", map[string]any{"amount": "200000", "payee": "x@ybl",
		"reason": "prize GST", "keep_secret": true, "to_receive_money": true})
	ids := flagIDs(v)
	if !ids["F01"] || !ids["F04"] || (v["verdict"] != "LIKELY_SCAM" && v["verdict"] != "SCAM") {
		t.Fatalf("got %v %v", ids, v["verdict"])
	}
}

func TestPaidGuideFallbackStartsWith1930(t *testing.T) {
	offline(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("amount", "50000")
	_ = mw.WriteField("minutes_ago", "10")
	_ = mw.WriteField("lang", "en")
	mw.Close()
	req := httptest.NewRequest("POST", "/v1/paid-guide", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	_, g := do(t, newServer(), req)
	steps := g["steps"].([]any)
	if !strings.Contains(steps[0].(string), "1930") || !strings.Contains(g["urgency"].(string), "first hour") {
		t.Fatalf("got %v", g)
	}
}

func TestIndexServed(t *testing.T) {
	offline(t)
	rec := httptest.NewRecorder()
	newServer().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Dhaal") {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestDegradedAnswerHasNullModel(t *testing.T) {
	offline(t)
	v := checkText(t, newServer(), "Your KBC lottery of 25 lakh is approved. Pay GST to claim")
	if v["model"] != nil || v["degraded"] != true {
		t.Fatalf("model %v degraded %v", v["model"], v["degraded"])
	}
}

// Live regression: Gemini tagged a genuine bank OTP SMS's "Do not share it" as F08 and the override made it CRITICAL.
func TestModelNegatedOTPAdviceIgnored(t *testing.T) {
	input := "483920 is your OTP to log in to SBI YONO. Do not share it with anyone."
	mv := &ModelVerdict{Verdict: "SCAM", PScam: 0.2, CategoryID: "C31", Lang: "en-IN",
		RedFlags: []RedFlagOut{{FlagID: "F08", Evidence: "Do not share it with anyone"}}}
	r := analyzeText(input)
	resp := buildResponse(r, gatherSignals(t.Context(), r), mv, false, "test", "auto", input, false, 0)
	for _, f := range resp.RedFlags {
		if f.FlagID == "F08" {
			t.Fatal("negated advice kept as F08")
		}
	}
	if resp.Level == "CRITICAL" || resp.Verdict == "SCAM" {
		t.Fatalf("level %s verdict %s", resp.Level, resp.Verdict)
	}
	// Same SMS, model quotes the OTP line itself (live run 2): no request word, so not F08.
	mv.RedFlags = []RedFlagOut{{FlagID: "F08", Evidence: "483920 is your OTP to log in to SBI YONO"}}
	mv.PScam = 0.9
	if resp := buildResponse(r, gatherSignals(t.Context(), r), mv, false, "test", "auto", input, false, 0); resp.Level == "CRITICAL" {
		t.Fatalf("OTP line kept as request: level %s", resp.Level)
	}
	// A real OTP request still counts.
	scam := "Bank officer here, please tell me the OTP you just received to stop the block."
	mv2 := &ModelVerdict{Verdict: "SCAM", PScam: 0.9, CategoryID: "C31", Lang: "en-IN",
		RedFlags: []RedFlagOut{{FlagID: "F08", Evidence: "please tell me the OTP"}}}
	r2 := analyzeText(scam)
	if resp2 := buildResponse(r2, gatherSignals(t.Context(), r2), mv2, false, "test", "auto", scam, false, 0); resp2.Level != "CRITICAL" {
		t.Fatalf("real OTP request level %s", resp2.Level)
	}
}

// Live regression: the AI timed out on a recording and the rules-only answer said "No usual scam signs found".
func TestUnreadableMediaIsNeverNoSigns(t *testing.T) {
	offline(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("source", "recording")
	fw, _ := mw.CreateFormFile("files", "call.wav")
	_, _ = fw.Write([]byte("RIFF....WAVEfmt fake audio"))
	mw.Close()
	req := httptest.NewRequest("POST", "/v1/check", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec, v := do(t, newServer(), req)
	if rec.Code != 200 || v["verdict"] != "UNSURE" || v["level"] != "CAUTION" ||
		!strings.Contains(v["summary"].(string), "couldn't check") {
		t.Fatalf("got %d %v %v %v", rec.Code, v["verdict"], v["level"], v["summary"])
	}
}

func TestEmailIsNotUPI(t *testing.T) {
	_, _, upis := extractEntities("mail me at someone@gmail.com or pay rbi.verification@ybl")
	if len(upis) != 1 || upis[0] != "rbi.verification@ybl" {
		t.Fatalf("got %v", upis)
	}
}
