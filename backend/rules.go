package main

// Deterministic checks: keyword flags, QR, links, numbers, UPI IDs.
// Runs before Gemini (sets a risk floor) and alone when Gemini is unavailable.

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Lowercased substrings; English, Hinglish and Hindi.
var flagTriggers = map[string][]string{
	"F01": {"don't tell", "do not tell", "dont tell", "keep it secret", "keep this secret", "confidential",
		"kisi ko mat", "kisi ko na", "kisi ko bhi mat", "kisi se mat", "kisi ko nahi batana",
		"किसी को मत", "किसी को न", "गोपनीय"},
	"F02": {"stay on the call", "don't cut the call", "do not disconnect", "don't disconnect", "keep the camera on",
		"call mat kaat", "phone mat kaat", "call cut mat", "camera on rakh", "video on rakh",
		"कॉल मत काट", "फोन मत काट"},
	"F03": {"safe account", "secure account", "verification account", "rbi account", "supervision account",
		"escrow", "returned in 30 minutes", "will be refunded after verification", "surakshit khate",
		"सुरक्षित खात", "वेरिफिकेशन"},
	"F04": {"processing fee", "registration fee", "clearance fee", "customs duty", "pay gst", "gst charges",
		"withdrawal tax", "unlock your", "to claim your prize", "release fee", "token amount to receive"},
	"F05": {"scan to receive", "scan this qr to receive", "scan the qr to receive", "enter pin to receive",
		"enter your pin to receive", "qr scan karke paise", "पैसे प्राप्त करने के लिए स्कैन"},
	"F06": {"anydesk", "teamviewer", "quicksupport", "quick support", "airdroid", "rustdesk", ".apk",
		"install this app", "download this app", "screen share", "share your screen"},
	"F07": {"merge the call", "merge call", "call merge", "add this call"},
	"F08": {"share the otp", "share otp", "tell me the otp", "otp batao", "otp bataiye", "otp bata do",
		"upi pin", "your pin", "cvv", "ओटीपी बताएं", "ओटीपी बताओ"},
	"F09": {"break your fd", "break the fd", "close your fd", "fd tod", "fd todkar", "fixed deposit tod",
		"take a loan and", "sell your gold"},
	"F10": {"skype", "whatsapp video call from police", "video call verification"},
	"F11": {"arrest warrant", "you will be arrested", "giraftaar", "गिरफ्तार", "digital arrest", "डिजिटल अरेस्ट",
		"will be disconnected", "disconnected tonight", "bijli kat", "बिजली कट", "power will be cut",
		"account will be blocked", "account blocked", "legal action", "non-bailable"},
	"F12": {"new number", "naya number", "नया नंबर", "hi mum", "hi mom", "hi papa", "guess who", "pehchana"},
	"F13": {"guaranteed return", "assured return", "double your money", "daily profit", "100% profit",
		"stock tips", "ipo allotment", "vip group"},
	"F14": {"sent by mistake", "galti se", "गलती से", "wrong transfer", "please return the money", "refund the extra"},
	"F16": {"tell the bank it is", "say it is for", "bank ko mat batana", "bank staff ko mat"},
	"F18": {"update kyc", "kyc update", "kyc pending", "kyc expired", "pan update", "aadhaar update",
		"reward points", "bill not updated", "update your bill"},
	"F19": {"arrest warrant", "supreme court order", "court order", "rbi letter", "seizure order"},
	"F20": {"transferring your call", "connecting you to", "cbi", "ncb", "enforcement directorate", "ed officer",
		"customs officer", "cyber crime branch", "crime branch", "trai", "ats officer", "mumbai police"},
}

// Genuine bank SMS say "do not share OTP"; a negated instruction is advice, not a red flag.
var negatable = set("F05", "F06", "F07", "F08")
var negations = []string{"not ", "never ", "n't ", "dont ", "mat ", "na ", "nahi ", "नहीं ", "न ", "मत "}

var (
	urlRE   = regexp.MustCompile(`(?i)(?:https?://|www\.)[^\s<>"']+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:apk|xyz|top|icu|click|live|online|site|in|com|net|org|info|link)(?:/[^\s<>"']*)?`)
	phoneRE = regexp.MustCompile(`\+?\d[\d\s-]{8,14}\d`)
	upiRE   = regexp.MustCompile(`\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b`)
	spaceRE = regexp.MustCompile(`[\s-]`)
)

var shorteners = set("bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "t.ly", "is.gd", "shorturl.at", "goo.su", "tiny.cc", "ow.ly", "s.id")
var riskyTLDs = set("xyz", "top", "icu", "click", "live", "online", "site", "shop", "buzz", "cfd", "sbs", "rest", "lol", "quest")
var brandWords = []string{"sbi", "hdfc", "icici", "axis", "kotak", "pnb", "rbi", "npci", "paytm", "phonepe", "gpay", "indiapost",
	"fedex", "dhl", "bluedart", "parivahan", "echallan", "challan", "incometax", "uidai", "aadhaar",
	"kyc", "bses", "mahadiscom", "tneb", "electricity", "lpg", "indane", "bharatgas", "epfo", "pension"}
var officialDomains = []string{"gov.in", "nic.in", "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com",
	"kotak.com", "pnbindia.in", "rbi.org.in", "npci.org.in", "paytm.com", "phonepe.com", "indiapost.gov.in",
	"fedex.com", "dhl.com", "bluedart.com", "incometax.gov.in", "uidai.gov.in", "epfindia.gov.in",
	"bsesdelhi.com", "mahadiscom.in", "indane.co.in", "ebharatgas.com", "google.com", "youtube.com"}

// Countries where scam compounds operate or frequent spoof sources; order matters (longest codes first where they overlap).
var riskyCountryCodes = []struct{ code, country string }{
	{"92", "Pakistan"}, {"84", "Vietnam"}, {"855", "Cambodia"}, {"856", "Laos"}, {"95", "Myanmar"},
	{"880", "Bangladesh"}, {"62", "Indonesia"}, {"63", "Philippines"}, {"234", "Nigeria"},
}
var authorityWords = []string{"police", "cbi", "ed ", "rbi", "trai", "customs", "court", "income tax", "cyber", "bank", "government", "govt"}

type Signal struct {
	Source string  `json:"source"` // rules | gemini | webrisk | reputation | device | qr
	Name   string  `json:"name"`
	Weight float64 `json:"-"`
	Detail string  `json:"detail"`
	FlagID string  `json:"-"`
}

type QRInfo struct {
	Payload      string `json:"payload"`
	IsPayRequest bool   `json:"is_pay_request"`
	PayeeVPA     string `json:"payee_vpa,omitempty"`
	PayeeName    string `json:"payee_name,omitempty"`
	Amount       string `json:"amount,omitempty"`
	Note         string `json:"note,omitempty"`
}

type RuleResult struct {
	Signals          []Signal
	Flags            map[string]string // flag id -> evidence
	CategoryHint     string
	OverrideCritical bool
	QR               []QRInfo
	URLs, Phones     []string
	UPIIDs           []string
}

func newRuleResult() *RuleResult {
	return &RuleResult{Flags: map[string]string{}, QR: []QRInfo{}, URLs: []string{}, Phones: []string{}, UPIIDs: []string{}}
}

func snippet(text string, idx, length int) string {
	start, end := idx-30, idx+length+30
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	// Keep the cut on rune boundaries (Hindi text).
	for start > 0 && !isRuneStart(text[start]) {
		start--
	}
	for end < len(text) && !isRuneStart(text[end]) {
		end++
	}
	return strings.TrimSpace(text[start:end])
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

func negated(low string, idx int) bool {
	start := idx - 14
	if start < 0 {
		start = 0
	}
	for start > 0 && !isRuneStart(low[start]) {
		start--
	}
	window := low[start:idx]
	for _, n := range negations {
		if strings.Contains(window, n) {
			return true
		}
	}
	return false
}

// keywordFlags: byte offsets index both text and its lowercase copy because strings.ToLower keeps ASCII and Devanagari lengths.
func keywordFlags(text string) map[string]string {
	low := strings.ToLower(text)
	found := map[string]string{}
	for _, fid := range flagOrder {
		for _, p := range flagTriggers[fid] {
			pl := strings.ToLower(p)
			i := strings.Index(low, pl)
			for i >= 0 && negatable[fid] && negated(low, i) {
				next := strings.Index(low[i+1:], pl)
				if next < 0 {
					i = -1
				} else {
					i = i + 1 + next
				}
			}
			if i >= 0 {
				if len(low) == len(text) {
					found[fid] = snippet(text, i, len(pl))
				} else {
					found[fid] = snippet(low, i, len(pl))
				}
				break
			}
		}
	}
	return found
}

func guessCategory(text string) string {
	low := strings.ToLower(text)
	best, bestHits := "", 0
	for _, id := range categoryOrder {
		hits := 0
		for _, t := range Categories[id].Triggers {
			if strings.Contains(low, t) {
				hits++
			}
		}
		if hits > bestHits {
			best, bestHits = id, hits
		}
	}
	return best
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func extractEntities(text string) (urls, phones, upis []string) {
	urls, phones, upis = []string{}, []string{}, []string{}
	for _, u := range urlRE.FindAllString(text, -1) {
		urls = appendUnique(urls, strings.TrimRight(u, ".,)"))
	}
	for _, m := range phoneRE.FindAllStringIndex(text, -1) {
		if (m[0] > 0 && isDigit(text[m[0]-1])) || (m[1] < len(text) && isDigit(text[m[1]])) {
			continue
		}
		phones = appendUnique(phones, spaceRE.ReplaceAllString(text[m[0]:m[1]], ""))
	}
	for _, m := range upiRE.FindAllStringIndex(text, -1) {
		if m[1] < len(text) && text[m[1]] == '.' { // an email address, not a UPI ID
			continue
		}
		upis = appendUnique(upis, text[m[0]:m[1]])
	}
	return
}

func parseUPIQR(payload string) *QRInfo {
	if !strings.HasPrefix(strings.ToLower(payload), "upi://") {
		return nil
	}
	info := &QRInfo{Payload: payload, IsPayRequest: strings.HasPrefix(strings.ToLower(payload), "upi://pay")}
	if u, err := url.Parse(payload); err == nil {
		q := u.Query()
		info.PayeeVPA, info.PayeeName, info.Amount, info.Note = q.Get("pa"), q.Get("pn"), q.Get("am"), q.Get("tn")
	}
	return info
}

var receiveWords = []string{"receive", "refund", "prize", "payment for", "buyer", "milega", "paise aayenge", "advance", "cashback"}

func checkQR(payload, context string) *RuleResult {
	r := newRuleResult()
	info := parseUPIQR(payload)
	if info == nil {
		r.QR = append(r.QR, QRInfo{Payload: payload})
		if strings.HasPrefix(payload, "http://") || strings.HasPrefix(payload, "https://") {
			r.URLs = append(r.URLs, payload)
		}
		return r
	}
	r.QR = append(r.QR, *info)
	if info.IsPayRequest {
		amt := "money "
		if info.Amount != "" {
			amt = "₹" + info.Amount + " "
		}
		who := firstNonEmpty(info.PayeeName, info.PayeeVPA, "someone")
		detail := fmt.Sprintf("Scanning this QR SENDS %sto %s (%s). You never scan a QR to receive money.", amt, who, info.PayeeVPA)
		r.Signals = append(r.Signals, Signal{Source: "qr", Name: "upi_pay_qr", Weight: 0.5, Detail: detail, FlagID: "F05"})
		r.Flags["F05"] = detail
		if containsAny(strings.ToLower(context), receiveWords) {
			r.OverrideCritical = true
			r.CategoryHint = "C22"
		}
		if info.PayeeVPA != "" {
			r.UPIIDs = append(r.UPIIDs, info.PayeeVPA)
		}
	}
	return r
}

func checkURL(raw string) []Signal {
	out := []Signal{}
	u := raw
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	p, err := url.Parse(u)
	if err != nil {
		return out
	}
	host := strings.ToLower(p.Hostname())
	path := strings.ToLower(p.Path)
	if host == "" {
		return out
	}
	if shorteners[host] {
		out = append(out, Signal{Source: "rules", Name: "link_shortener", Weight: 0.3, Detail: host + " hides the real address"})
	}
	if strings.Contains(path, ".apk") {
		out = append(out, Signal{Source: "rules", Name: "apk_download", Weight: 0.7, Detail: "Link downloads an app file (.apk)", FlagID: "F06"})
	}
	if net.ParseIP(host) != nil {
		out = append(out, Signal{Source: "rules", Name: "ip_address_host", Weight: 0.5, Detail: "Link uses a bare IP address"})
	}
	if strings.HasPrefix(host, "xn--") || strings.Contains(host, ".xn--") {
		out = append(out, Signal{Source: "rules", Name: "punycode", Weight: 0.5, Detail: "Lookalike characters in the address"})
	}
	tld := host[strings.LastIndex(host, ".")+1:]
	if riskyTLDs[tld] {
		out = append(out, Signal{Source: "rules", Name: "risky_tld", Weight: 0.3, Detail: "." + tld + " addresses are common in scams"})
	}
	official := false
	for _, d := range officialDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			official = true
			break
		}
	}
	if !official {
		for _, b := range brandWords {
			if strings.Contains(host, b) {
				out = append(out, Signal{Source: "rules", Name: "brand_lookalike", Weight: 0.6, Detail: "Uses '" + b + "' but is not the official site", FlagID: "F18"})
				break
			}
		}
		if containsAny(host, []string{"gov", "govt", "sarkar", "yojana"}) && !strings.HasSuffix(host, ".gov.in") && !strings.HasSuffix(host, ".nic.in") {
			out = append(out, Signal{Source: "rules", Name: "fake_government_domain", Weight: 0.6, Detail: "Claims to be government but is not .gov.in"})
		}
	}
	return out
}

var nonPhoneChars = regexp.MustCompile(`[^\d+]`)

func normalizePhone(raw string) string {
	d := nonPhoneChars.ReplaceAllString(raw, "")
	if strings.HasPrefix(d, "00") {
		d = "+" + d[2:]
	}
	if !strings.HasPrefix(d, "+") {
		t := strings.TrimLeft(d, "0")
		switch {
		case len(t) == 10:
			return "+91" + t
		case len(t) == 12 && strings.HasPrefix(t, "91"):
			return "+" + t
		default:
			return "+" + t
		}
	}
	return d
}

var indianMobileRE = regexp.MustCompile(`^\+91[6-9]\d{9}$`)

func checkNumber(raw, context string) []Signal {
	out := []Signal{}
	e164 := normalizePhone(raw)
	cc := ""
	if len(e164) > 1 {
		cc = e164[1:min(4, len(e164))]
	}
	if !strings.HasPrefix(e164, "+91") {
		for _, rc := range riskyCountryCodes {
			if strings.HasPrefix(cc, rc.code) {
				out = append(out, Signal{Source: "rules", Name: "international_number", Weight: 0.4, Detail: fmt.Sprintf("Number is from %s (+%s)", rc.country, rc.code)})
				break
			}
		}
	}
	if context != "" && containsAny(strings.ToLower(context), authorityWords) {
		if !strings.HasPrefix(e164, "+91") {
			out = append(out, Signal{Source: "rules", Name: "foreign_number_claims_authority", Weight: 0.6, Detail: "A foreign number claiming to be Indian police, bank or government"})
		} else if indianMobileRE.MatchString(e164) {
			out = append(out, Signal{Source: "rules", Name: "mobile_claims_authority", Weight: 0.3, Detail: "A personal mobile number claiming to be police, bank or government"})
		}
	}
	return out
}

func checkUPI(vpa, context string) []Signal {
	out := []Signal{}
	v := strings.ToLower(vpa)
	if containsAny(v, []string{"refund", "kyc", "lottery", "prize", "cbi", "police", "rbi", "govt", "customs", "reward", "army"}) {
		out = append(out, Signal{Source: "rules", Name: "suspicious_upi_name", Weight: 0.5, Detail: "'" + vpa + "' imitates an official or refund account", FlagID: "F15"})
	}
	if context != "" && containsAny(strings.ToLower(context), []string{"fee", "fine", "challan", "customs", "government", "police", "court", "tax"}) {
		out = append(out, Signal{Source: "rules", Name: "personal_upi_for_official_fee", Weight: 0.4, Detail: "Official fees are never paid to a personal UPI ID", FlagID: "F15"})
	}
	return out
}

func analyzeText(text string) *RuleResult {
	r := newRuleResult()
	if text == "" {
		return r
	}
	r.Flags = keywordFlags(text)
	for _, fid := range flagOrder {
		ev, ok := r.Flags[fid]
		if !ok {
			continue
		}
		w := 0.25
		if CoreFlags[fid] {
			w = 0.5
		}
		r.Signals = append(r.Signals, Signal{Source: "rules", Name: "keyword_" + fid, Weight: w, Detail: ev, FlagID: fid})
	}
	r.CategoryHint = guessCategory(text)
	r.URLs, r.Phones, r.UPIIDs = extractEntities(text)
	for _, u := range r.URLs {
		r.Signals = append(r.Signals, checkURL(u)...)
	}
	for _, v := range r.UPIIDs {
		r.Signals = append(r.Signals, checkUPI(v, text)...)
	}
	for _, ph := range r.Phones {
		r.Signals = append(r.Signals, checkNumber(ph, text)...)
	}
	_, f20 := r.Flags["F20"]
	_, f11 := r.Flags["F11"]
	_, f03 := r.Flags["F03"]
	_, f08 := r.Flags["F08"]
	_, f06 := r.Flags["F06"]
	_, f02 := r.Flags["F02"]
	if (f20 || f11) && f03 {
		r.OverrideCritical = true
	}
	if f08 || (f06 && f02) {
		r.OverrideCritical = true
	}
	return r
}

// score fuses signals with a noisy-OR; overrides force at least 90.
func score(signals []Signal, override bool) int {
	prod := 1.0
	for _, s := range signals {
		prod *= 1 - math.Max(0, math.Min(1, s.Weight))
	}
	v := int(math.Round(100 * (1 - prod)))
	if override && v < 90 {
		return 90
	}
	return v
}

func level(s int) string {
	switch {
	case s >= 80:
		return "CRITICAL"
	case s >= 60:
		return "HIGH"
	case s >= 30:
		return "CAUTION"
	}
	return "LOW"
}

func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
