package main

// Community learning tests run offline: embeddings fall back to the lexical space and fingerprints to rules.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func cmOffline(t *testing.T) {
	for _, k := range []string{"GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI", "WEBRISK_API_KEY"} {
		t.Setenv(k, "")
	}
}

// withCommunity swaps in a fresh store for one test and lets rules fingerprints stand in for Gemini.
func withCommunity(t *testing.T, seeds bool) *communityStore {
	cmOffline(t)
	old, oldRules := community, allowRulesLearning
	community, allowRulesLearning = newCommunityStore(seeds), true
	t.Cleanup(func() { community, allowRulesLearning = old, oldRules })
	return community
}

func communityMux() *http.ServeMux {
	mux := http.NewServeMux()
	registerCommunityRoutes(mux)
	return mux
}

// reportAs reports from a device on its own /24.
func reportAs(t *testing.T, device, text string) (int, map[string]any) {
	n := 0
	for _, c := range device {
		n = (n*31 + int(c)) % 250
	}
	return reportFrom(t, device, fmt.Sprintf("198.51.%d.7", n), text)
}

func reportFrom(t *testing.T, device, ip, text string) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"text": text, "lang": "en"})
	req := httptest.NewRequest("POST", "/v1/community/report", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Dhaal-Device", device)
	req.Header.Set("X-Forwarded-For", "10.9.9.9, "+ip) // first hop is client-supplied and must be ignored
	rec := httptest.NewRecorder()
	communityMux().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

const censusHinglish = "Census office se call aaya, bole aapka ghar census mein register nahi hai, link pe form bharo aur OTP batao warna ration card band ho jayega"

func TestVectorJSONRoundTrip(t *testing.T) {
	in := vector{0.25, -0.5, 1}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out vector
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[0] != 0.25 || out[1] != -0.5 || out[2] != 1 {
		t.Fatalf("round trip: %v", out)
	}
}

func TestSeedsLoadWithEmbeddings(t *testing.T) {
	s := newCommunityStore(true)
	status := map[string]string{}
	for _, p := range s.patterns {
		status[p.ID] = p.Status
		for _, e := range p.Exemplars {
			if len(e.Vec) != embedDims || e.Model != vertexTag() || len(e.lex) != lexicalDims {
				t.Fatalf("%s exemplar not ready: vec=%d model=%q lex=%d", p.ID, len(e.Vec), e.Model, len(e.lex))
			}
		}
		if p.ReporterN != len(p.ReporterKeys) || p.Reports < p.ReporterN {
			t.Fatalf("%s counts inconsistent: %d reporters, %d keys, %d reports", p.ID, p.ReporterN, len(p.ReporterKeys), p.Reports)
		}
	}
	if status["cp-census"] != "active" || status["cp-recovery"] != "active" || status["cp-smart-meter"] != "watching" {
		t.Fatalf("seed statuses: %v", status)
	}
}

func TestSeedVectorsSeparateScams(t *testing.T) {
	s := newCommunityStore(true)
	census, power := s.get("cp-census"), s.get("cp-power-sms")
	same := dot(census.Exemplars[0].Vec, census.Exemplars[1].Vec)
	diff := dot(census.Exemplars[0].Vec, power.Exemplars[0].Vec)
	if same < vertexTh.match || diff >= vertexTh.match {
		t.Fatalf("same-scam %.3f, different-scam %.3f, threshold %.3f", same, diff, vertexTh.match)
	}
}

func TestCheckMatchesLivePattern(t *testing.T) {
	withCommunity(t, true)
	ctx := context.Background()
	j := startCommunityMatch(ctx, "A man called from the census office, said my family is not registered in the census and I must fill the form at the link and tell the OTP or our ration card will be cancelled")
	sigs := j.signals(ctx, nil)
	if len(sigs) != 1 || sigs[0].Source != "community" || sigs[0].Weight < 0.3 {
		t.Fatalf("signals: %+v hits: %+v", sigs, j.hits)
	}
	if p := j.prompt(time.Second); !strings.Contains(p, "Fake digital census registration") {
		t.Fatalf("prompt: %s", p)
	}
	resp := &CheckResponse{ID: "chk1", Verdict: "LIKELY_SCAM", Lang: "hi-IN"}
	vs := j.attach(resp, censusHinglish)
	if len(vs) == 0 || vs[0].ID != "cp-census" || !strings.Contains(vs[0].Title, "जनगणना") {
		t.Fatalf("views: %+v", vs)
	}
}

func TestUnrelatedAndWatchingPatternsDoNotMatch(t *testing.T) {
	withCommunity(t, true)
	ctx := context.Background()
	if j := startCommunityMatch(ctx, "Hi beta, dinner at 8 tonight, bring curd on the way home."); len(j.signals(ctx, nil)) != 0 {
		t.Fatalf("family message matched: %+v", j.hits)
	}
	// Exact text of a pattern that is still being watched: not enough reporters to warn anyone yet.
	meter := community.get("cp-smart-meter").Exemplars[0].Text
	for _, h := range startCommunityMatch(ctx, meter).wait() {
		if h.id == "cp-smart-meter" {
			t.Fatal("watching pattern matched a check")
		}
	}
}

func TestThreeDistinctReportersPromoteANewPattern(t *testing.T) {
	withCommunity(t, false)
	reports := []struct{ device, text string }{
		{"device-aaaa-1", "Your gas connection KYC is pending. Pay 99 rupees verification fee to the agent UPI ID today or the LPG cylinder booking will be stopped."},
		{"device-aaaa-1", "Gas connection KYC pending, pay the 99 rupees verification fee to the agent on UPI or LPG cylinder booking stops."},
		{"device-bbbb-2", "LPG gas connection KYC pending: pay the verification fee to the agent UPI ID or the cylinder booking will be stopped today."},
	}
	for i, r := range reports {
		code, out := reportAs(t, r.device, r.text)
		if code != 200 || out["accepted"] != true || out["promoted"] == true {
			t.Fatalf("report %d: %d %v", i, code, out)
		}
	}
	if n := len(community.patterns); n != 1 {
		t.Fatalf("expected one clustered pattern, got %d", n)
	}
	p := community.patterns[0]
	if p.Status != "watching" || p.ReporterN != 2 || p.Reports != 3 {
		t.Fatalf("after two reporters: status=%s reporters=%d reports=%d", p.Status, p.ReporterN, p.Reports)
	}
	code, out := reportAs(t, "device-cccc-3", "Agent asked me to pay a gas connection KYC verification fee on UPI, said my LPG cylinder booking will be stopped otherwise.")
	if code != 200 || out["promoted"] != true {
		t.Fatalf("third reporter should promote: %d %v", code, out)
	}
	if p.Status != "active" || p.How == "" || p.ActivatedAt == nil {
		t.Fatalf("promoted pattern incomplete: %+v", p)
	}
	ctx := context.Background()
	j := startCommunityMatch(ctx, "They said my LPG gas connection KYC is pending and I should send a verification fee by UPI or cylinder booking will stop")
	if sigs := j.signals(ctx, nil); len(sigs) != 1 {
		t.Fatalf("learned pattern did not protect the next check: %+v", j.hits)
	}
}

func TestOneDeviceCannotPromoteAlone(t *testing.T) {
	withCommunity(t, false)
	for i := 0; i < 4; i++ {
		if code, out := reportAs(t, "device-solo-1", "Pay the 1450 rupees smart meter installation charge on UPI today or the electricity supply will be cut"); code != 200 || out["promoted"] == true {
			t.Fatalf("report %d: %d %v", i, code, out)
		}
	}
	if len(community.patterns) != 1 {
		t.Fatalf("expected one pattern, got %d", len(community.patterns))
	}
	if p := community.patterns[0]; p.Status != "watching" || p.ReporterN != 1 || p.Reports != 4 {
		t.Fatalf("one device moved the pattern: status=%s reporters=%d reports=%d", p.Status, p.ReporterN, p.Reports)
	}
}

func TestReportPromotesWatchedSeed(t *testing.T) {
	withCommunity(t, true)
	code, out := reportAs(t, "device-demo-1", "Bijli office se call aaya, kal smart meter lagega, installation charge 1450 rupaye abhi UPI pe bhejo warna light kat jayegi")
	if code != 200 || out["promoted"] != true {
		t.Fatalf("third distinct reporter should promote the watched seed: %d %v", code, out)
	}
	pat, _ := out["pattern"].(map[string]any)
	if pat["id"] != "cp-smart-meter" || pat["status"] != "active" {
		t.Fatalf("pattern: %v", pat)
	}
}

func TestReportRateLimited(t *testing.T) {
	withCommunity(t, false)
	for i := 0; i < reportsPerDevice; i++ {
		if code, _ := reportAs(t, "device-spam-1", "Pay a fee to unlock your prize money now, lottery winner"); code != 200 {
			t.Fatalf("report %d rejected early: %d", i, code)
		}
	}
	if code, _ := reportAs(t, "device-spam-1", "Pay a fee to unlock your prize money now, lottery winner"); code != 429 {
		t.Fatalf("expected 429, got %d", code)
	}
}

func TestReportByCheckIDNeedsNoResend(t *testing.T) {
	withCommunity(t, false)
	community.rememberCheck(&CheckResponse{ID: "chk-42", Summary: "Caller asked for a fee"}, "Pay 500 rupees release fee to get your lost money back from the cyber cell")
	b, _ := json.Marshal(map[string]string{"check_id": "chk-42"})
	req := httptest.NewRequest("POST", "/v1/community/report", bytes.NewReader(b))
	req.Header.Set("X-Dhaal-Device", "device-chk-42")
	rec := httptest.NewRecorder()
	communityMux().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"accepted":true`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if code, _ := reportAs(t, "device-chk-43", ""); code != 400 {
		t.Fatalf("empty report should be rejected, got %d", code)
	}
}

// Audit COM-4: rules cannot tell the scammer's IDs from the victim's own, so they never reach the reputation list.
func TestRulesReportsNeverTouchReputation(t *testing.T) {
	withCommunity(t, false)
	reportAs(t, "device-rep-1", "I paid from my own UPI sunita.d@okaxis to refund.desk@ybl after a call from +919812300077")
	for kind, v := range map[string]string{"upi": "sunita.d@okaxis", "number": "+919812300077"} {
		if r := repLookup(kind, v); r != nil {
			t.Fatalf("%s %s reached reputation from a rules fingerprint", kind, v)
		}
	}
}

// Audit COM-1: without Gemini a report is not verified, so it is not learned at all.
func TestUnverifiedReportsAreNotLearned(t *testing.T) {
	withCommunity(t, false)
	allowRulesLearning = false
	for _, d := range []string{"attacker-dev-01", "attacker-dev-02", "attacker-dev-03"} {
		if code, out := reportAs(t, d, "Bill received, thank you for your payment of Rs 450."); code != 200 || out["accepted"] == true {
			t.Fatalf("unverified report accepted: %d %v", code, out)
		}
	}
	if len(community.patterns) != 0 {
		t.Fatalf("patterns opened from unverified reports: %d", len(community.patterns))
	}
}

// Audit COM-1/COM-2: three made-up devices behind one network (and a spoofed first X-Forwarded-For hop) stay watching.
func TestFakeDevicesOnOneNetworkDoNotPromote(t *testing.T) {
	withCommunity(t, false)
	for i, d := range []string{"attacker-dev-01", "attacker-dev-02", "attacker-dev-03", "attacker-dev-04"} {
		if code, out := reportFrom(t, d, "203.0.113."+fmt.Sprint(10+i), "Pay the 99 rupees gas KYC verification fee on UPI or LPG cylinder booking stops"); code != 200 || out["promoted"] == true {
			t.Fatalf("report %d: %d %v", i, code, out)
		}
	}
	if p := community.patterns[0]; p.Status != "watching" || p.ReporterN != 4 || len(p.NetworkKeys) != 1 {
		t.Fatalf("one network promoted a pattern: status=%s reporters=%d networks=%d", p.Status, p.ReporterN, len(p.NetworkKeys))
	}
}

// Audit COM-8: repeats from one device do not inflate the trend.
func TestTrendCountsPeopleNotRepeats(t *testing.T) {
	withCommunity(t, false)
	for i := 0; i < 5; i++ {
		reportAs(t, "device-repeat-1", "Pay the 1450 rupees smart meter installation charge on UPI today or the supply will be cut")
	}
	if p := community.patterns[0]; p.Daily[dayKey(time.Now())] != 1 || p.Reports != 5 {
		t.Fatalf("daily=%v reports=%d", p.Daily, p.Reports)
	}
}

func TestBlockedPatternStopsWarning(t *testing.T) {
	withCommunity(t, true)
	block := func(token string) int {
		req := httptest.NewRequest("POST", "/v1/community/patterns/cp-census/block", nil)
		req.Header.Set("X-Admin-Token", token)
		rec := httptest.NewRecorder()
		communityMux().ServeHTTP(rec, req)
		return rec.Code
	}
	t.Setenv("COMMUNITY_ADMIN_TOKEN", "")
	if code := block(""); code != 403 {
		t.Fatalf("blocking with moderation off: %d", code)
	}
	t.Setenv("COMMUNITY_ADMIN_TOKEN", "test-admin-token")
	if code := block("wrong"); code != 403 {
		t.Fatalf("wrong token accepted: %d", code)
	}
	if code := block("test-admin-token"); code != 200 {
		t.Fatalf("block with token: %d", code)
	}
	if hits := startCommunityMatch(context.Background(), censusHinglish).wait(); len(hits) != 0 {
		t.Fatalf("blocked pattern still matches: %+v", hits)
	}
}

// Audit COM-1: with no model opinion the community signal alone stays at CAUTION.
func TestCommunityAloneStaysAtCaution(t *testing.T) {
	withCommunity(t, true)
	ctx := context.Background()
	j := startCommunityMatch(ctx, censusHinglish) // identical to a seed exemplar: the strongest possible match
	sigs := j.signals(ctx, &ModelVerdict{PScam: 0.1})
	if len(sigs) != 1 || sigs[0].Weight > 0.30 {
		t.Fatalf("community alone weighed %+v", sigs)
	}
	if sigs = startCommunityMatch(ctx, censusHinglish).signals(ctx, &ModelVerdict{PScam: 0.9}); sigs[0].Weight <= 0.30 {
		t.Fatalf("agreeing model should keep full weight: %+v", sigs)
	}
}

func TestOverviewListsLivePatterns(t *testing.T) {
	withCommunity(t, true)
	rec := httptest.NewRecorder()
	communityMux().ServeHTTP(rec, httptest.NewRequest("GET", "/v1/community/patterns?lang=hi", nil))
	var out struct {
		Patterns []PatternView `json:"patterns"`
		Watching int           `json:"watching"`
		Promote  int           `json:"promote_after"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 {
		t.Fatalf("%d %v %s", rec.Code, err, rec.Body.String())
	}
	if len(out.Patterns) != 3 || out.Watching != 1 || out.Promote != promoteReporters {
		t.Fatalf("overview: %d live, %d watching", len(out.Patterns), out.Watching)
	}
	for _, p := range out.Patterns {
		if len(p.Trend) != 14 || p.Last7d == 0 || p.Title == "" {
			t.Fatalf("bad card: %+v", p)
		}
		if p.ID == "cp-census" && (!p.Novel || !strings.Contains(p.Title, "जनगणना")) {
			t.Fatalf("census card: %+v", p)
		}
	}
}

func TestCheckThenOneTapReportThroughServer(t *testing.T) {
	withCommunity(t, true)
	t.Setenv("APP_USER", "")
	t.Setenv("APP_PASSWORD_HASH", "")
	srv := newServer()
	req := httptest.NewRequest("POST", "/v1/check", strings.NewReader(url.Values{"text": {censusHinglish}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var v struct {
		ID        string        `json:"id"`
		Verdict   string        `json:"verdict"`
		Community []PatternView `json:"community"`
		Signals   []Signal      `json:"signals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 {
		t.Fatalf("%d %v %s", rec.Code, err, rec.Body.String())
	}
	hasSignal := false
	for _, s := range v.Signals {
		hasSignal = hasSignal || s.Source == "community"
	}
	if len(v.Community) == 0 || v.Community[0].ID != "cp-census" || !hasSignal || v.Verdict == "NO_SIGNS_FOUND" {
		t.Fatalf("check did not use community reports: %s", rec.Body.String())
	}
	b, _ := json.Marshal(map[string]string{"check_id": v.ID})
	req = httptest.NewRequest("POST", "/v1/community/report", bytes.NewReader(b))
	req.Header.Set("X-Dhaal-Device", "device-e2e-0001")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var r LearnResult
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || rec.Code != 200 || !r.Accepted || r.Pattern.ID != "cp-census" || r.Pattern.Reporters != 15 {
		t.Fatalf("one-tap report: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/community/patterns", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "cp-census") {
		t.Fatalf("patterns: %d", rec.Code)
	}
}

func TestScrubAndCardText(t *testing.T) {
	s := scrub("Call +91 98765 43210 or pay ramesh.k@okaxis at http://bad.xyz/claim, account 123456789012")
	for _, leak := range []string{"98765", "ramesh", "bad.xyz", "123456789012"} {
		if strings.Contains(s, leak) {
			t.Fatalf("scrub leaked %q: %s", leak, s)
		}
	}
	c := cardText("Call 1930 or visit cybercrime.gov.in, not http://x.top/a or 9876543210.")
	if !strings.Contains(c, "1930") || !strings.Contains(c, "cybercrime.gov.in") || strings.Contains(c, "x.top") || strings.Contains(c, "9876543210") {
		t.Fatalf("card text: %s", c)
	}
}
