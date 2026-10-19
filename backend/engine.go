package main

// Check engine: rules pre-layer + Gemini structured verdict + KB validation + risk fusion.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/genai"
)

var (
	modelFast    = envOr("GEMINI_MODEL_FAST", "gemini-3.5-flash-lite")
	modelDeep    = envOr("GEMINI_MODEL_DEEP", "gemini-3.8-flash")
	timeoutText  = envSeconds("GEMINI_TIMEOUT_TEXT", 12)
	timeoutMedia = envSeconds("GEMINI_TIMEOUT_MEDIA", 75)
)

type Media struct {
	Data []byte
	MIME string
}

type RedFlagOut struct {
	FlagID   string `json:"flag_id"`
	Evidence string `json:"evidence"`
	Why      string `json:"why"`
}

type ModelVerdict struct {
	Verdict          string       `json:"verdict"`
	PScam            float64      `json:"p_scam"`
	CategoryID       string       `json:"category_id"`
	Summary          string       `json:"summary"`
	RedFlags         []RedFlagOut `json:"red_flags"`
	OfficialFactID   string       `json:"official_fact_id"`
	DoNow            string       `json:"do_now"`
	NextSteps        []string     `json:"next_steps"`
	SayThis          string       `json:"say_this"`
	ReadAloud        string       `json:"read_aloud"`
	Clarify          []string     `json:"clarify"`
	MoneyAlreadySent bool         `json:"money_already_sent"`
	Lang             string       `json:"lang"`
	Extracted        struct {
		Phones     []string `json:"phones"`
		UPIIDs     []string `json:"upi_ids"`
		URLs       []string `json:"urls"`
		Amounts    []string `json:"amounts"`
		ClaimedOrg string   `json:"claimed_org"`
	} `json:"extracted"`
}

func jsStr() map[string]any                { return map[string]any{"type": "string"} }
func jsArr(items any) map[string]any       { return map[string]any{"type": "array", "items": items} }
func jsEnum(vals ...string) map[string]any { return map[string]any{"type": "string", "enum": vals} }
func jsObj(props map[string]any) map[string]any {
	req := make([]string, 0, len(props))
	for k := range props {
		req = append(req, k)
	}
	sort.Strings(req)
	return map[string]any{"type": "object", "properties": props, "required": req}
}

var verdictSchema = jsObj(map[string]any{
	"verdict":            jsEnum("SCAM", "LIKELY_SCAM", "UNSURE", "NO_SIGNS_FOUND"),
	"p_scam":             map[string]any{"type": "number"},
	"category_id":        jsStr(),
	"summary":            jsStr(),
	"red_flags":          jsArr(jsObj(map[string]any{"flag_id": jsStr(), "evidence": jsStr(), "why": jsStr()})),
	"official_fact_id":   jsStr(),
	"do_now":             jsStr(),
	"next_steps":         jsArr(jsStr()),
	"say_this":           jsStr(),
	"read_aloud":         jsStr(),
	"clarify":            jsArr(jsStr()),
	"money_already_sent": map[string]any{"type": "boolean"},
	"lang":               jsStr(),
	"extracted": jsObj(map[string]any{
		"phones": jsArr(jsStr()), "upi_ids": jsArr(jsStr()), "urls": jsArr(jsStr()),
		"amounts": jsArr(jsStr()), "claimed_org": jsStr(),
	}),
})

var systemInstruction = `You are Dhaal, a calm scam-safety assistant for ordinary people in India, many of them elderly.
You judge whether a message, call, document, QR code, link, payment request or question shows signs of a scam
in which someone talks the user into paying or handing over access.

How to judge:
- Look first for what the user is being TOLD TO DO (the red flags F01-F20), not who is calling. Scam stories change; instructions do not.
- Map the situation to one category id from the knowledge base, or "NEW" if none fits.
- Use only ids that exist in the knowledge base for category_id, flag_id and official_fact_id ("" if no fact applies).
- evidence must quote the input exactly (same language and script). For audio, quote the words spoken. Max 80 characters.
- A bank's or app's own OTP or alert message that tells the user NOT to share it is normal, not a scam.
  F05-F08 apply only when someone asks the user to scan, install, merge or share.
- Any core flag (F01-F08) means at least LIKELY_SCAM. F03, F05, F06 or F08 with money involved or a call in progress means SCAM.
- Never say something is safe. The lowest verdict is NO_SIGNS_FOUND.
- p_scam is your probability (0-1) that this is a scam.
- If the user says money was already sent, an OTP shared or an app installed, set money_already_sent=true and do_now must be to call 1930 now.
- SYSTEM CHECKS in the prompt are trusted results from link, QR and number checks. Use them.

How to answer (all user-facing text in the user's language and script; Hinglish is fine if they wrote Hinglish):
- summary: one plain sentence on what is happening.
- do_now: one action, at most 10 words.
- next_steps: at most 3 short steps.
- say_this: one short line the user can say to end the conversation, or "".
- read_aloud: at most 60 words, simple words, starting with the equivalent of "You did the right thing by asking."
  If a call may be in progress, say they can hang up and nothing bad will happen.
- clarify: at most 2 yes/no questions, only when the verdict is UNSURE.
- Calm and warm. Never blame or shame the user. No lists of tips.
- Never write any phone number, website or helpline except those in HELPLINES.
- lang: BCP-47 code of the language you answered in (e.g. hi-IN, en-IN, mr-IN).

KNOWLEDGE BASE
` + promptBlock()

type template struct {
	Open, Scam, Signs, None, Hangup string
	CantCheck, CantDoNow            string
	DoNow                           map[string]string
}

var templates = map[string]template{
	"en": {
		Open: "You did the right thing by asking.", Scam: "This matches a known scam pattern: %s.",
		Signs: "I see warning signs of a scam.", None: "I don't see the usual scam signs.",
		Hangup:    "You can hang up. Nothing bad will happen.",
		CantCheck: "I couldn't check this recording or picture right now.",
		CantDoNow: "Don't pay or share anything. Try again in a minute.",
		DoNow: map[string]string{"CRITICAL": "Stop. Do not pay or share any code.", "HIGH": "Do not pay. Check with someone you trust.",
			"CAUTION": "Pause and verify before you act.", "LOW": "If anyone asks for money, an OTP or an app, ask me again."},
	},
	"hi": {
		Open: "आपने पूछकर बिल्कुल सही किया।", Scam: "यह एक जाने-पहचाने धोखे जैसा है: %s।",
		Signs: "मुझे धोखे के संकेत दिख रहे हैं।", None: "मुझे आम धोखे के संकेत नहीं दिखे।",
		Hangup:    "आप फोन काट सकते हैं। कुछ बुरा नहीं होगा।",
		CantCheck: "मैं अभी यह रिकॉर्डिंग या तस्वीर जांच नहीं पाया।",
		CantDoNow: "पैसे न भेजें, कुछ न बताएं। एक मिनट बाद फिर कोशिश करें।",
		DoNow: map[string]string{"CRITICAL": "रुकिए। पैसे न भेजें, कोई कोड न बताएं।", "HIGH": "पैसे न भेजें। किसी भरोसेमंद व्यक्ति से बात करें।",
			"CAUTION": "कुछ भी करने से पहले जांच लें।", "LOW": "अगर कोई पैसे, OTP या ऐप मांगे, तो मुझसे फिर पूछें।"},
	},
}

var verdictLabels = map[string]string{"SCAM": "Scam", "LIKELY_SCAM": "Likely scam", "UNSURE": "Not sure yet",
	"NO_SIGNS_FOUND": "No usual scam signs found"}
var verdictRank = map[string]int{"NO_SIGNS_FOUND": 0, "UNSURE": 1, "LIKELY_SCAM": 2, "SCAM": 3}

var (
	clientMu  sync.Mutex
	gemClient *genai.Client
)

func geminiConfigured() bool {
	v := strings.ToLower(os.Getenv("GOOGLE_GENAI_USE_VERTEXAI"))
	return os.Getenv("GEMINI_API_KEY") != "" || os.Getenv("GOOGLE_API_KEY") != "" || v == "1" || v == "true"
}

// geminiClient reads backend, project and location from the environment (Vertex AI on Cloud Run).
func geminiClient() (*genai.Client, error) {
	clientMu.Lock()
	defer clientMu.Unlock()
	if gemClient != nil {
		return gemClient, nil
	}
	c, err := genai.NewClient(context.Background(), &genai.ClientConfig{})
	if err != nil {
		return nil, err
	}
	gemClient = c
	return c, nil
}

func callGemini(ctx context.Context, model string, parts []*genai.Part, timeout time.Duration, system string, schema any, out any) error {
	c, err := geminiClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	temp := float32(0.2)
	cfg := &genai.GenerateContentConfig{
		Temperature:        &temp,
		ResponseMIMEType:   "application/json",
		ResponseJsonSchema: schema,
	}
	if system != "" {
		cfg.SystemInstruction = genai.NewContentFromText(system, genai.RoleUser)
	}
	resp, err := c.Models.GenerateContent(ctx, model, []*genai.Content{genai.NewContentFromParts(parts, genai.RoleUser)}, cfg)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(resp.Text()), out)
}

var (
	devanagariRE = regexp.MustCompile(`[\x{0900}-\x{097F}]`)
	otherIndicRE = regexp.MustCompile(`[\x{0980}-\x{0D7F}]`) // Bengali .. Malayalam
	hinglishRE   = regexp.MustCompile(`(?i)\b(hai|hain|mat|karo|karna|bhejo|bhej|paise|paisa|nahi|nahin|aap|mera|meri|mujhe|wale|kya|kisi|batana|abhi|jaldi|beta|bol|rahe|raha|kaat|hoga|jayega|sahab|ji)\b`)
	phoneishRE   = regexp.MustCompile(`\+?\d[\d\s-]{6,14}\d`)
	wsRE         = regexp.MustCompile(`\s+`)
	nonDigitRE   = regexp.MustCompile(`\D`)
)

// replyLanguage returns (instruction for Gemini, BCP-47 code). Hindi uses Devanagari so hi-IN text-to-speech reads it well.
func replyLanguage(lang, text string) (string, string) {
	lo := strings.ToLower(lang)
	hindi := "Hindi in Devanagari script, simple everyday words"
	switch {
	case strings.HasPrefix(lo, "hi"):
		return hindi, "hi-IN"
	case strings.HasPrefix(lo, "en"):
		return "English (simple Indian English)", "en-IN"
	case devanagariRE.MatchString(text):
		return "the same language as the input (Hindi or Marathi) in Devanagari script", "hi-IN"
	case otherIndicRE.MatchString(text):
		return "the same language as the input, in its own script", ""
	case len(hinglishRE.FindAllString(text, -1)) >= 2:
		return hindi, "hi-IN"
	}
	return "English (simple Indian English)", "en-IN"
}

func langKey(lang, text string) string {
	_, code := replyLanguage(lang, text)
	lo := strings.ToLower(lang)
	if code == "hi-IN" || strings.HasPrefix(lo, "hi") || strings.HasPrefix(lo, "mr") {
		return "hi"
	}
	return "en"
}

func stripNumbers(s string, allowed map[string]bool) string {
	return phoneishRE.ReplaceAllStringFunc(s, func(m string) string {
		d := nonDigitRE.ReplaceAllString(m, "")
		if AllowedNumbers[d] || allowed[d] {
			return m
		}
		return "[number removed]"
	})
}

func norm(s string) string { return strings.ToLower(strings.TrimSpace(wsRE.ReplaceAllString(s, " "))) }

var adviceRE = regexp.MustCompile(`(?i)\b(do not|don't|dont|never|not to)\b|मत |नहीं|\bmat\b|\bnahi\b`)

func negatedAdvice(evidence string) bool { return adviceRE.MatchString(evidence) }

// Words that turn a mention of an OTP/QR/app/call into a request to act on it.
var requestWords = map[string][]string{
	"F05": {"scan", "pin", "स्कैन"},
	"F06": {"install", "download", "open", "click", "anydesk", "teamviewer", "quicksupport", "quick support", "rustdesk",
		"airdroid", ".apk", "इंस्टॉल", "डाउनलोड"},
	"F07": {"merge", "conference", "add the call", "मर्ज"},
	"F08": {"tell", "share", "send", "give", "read", "say", "forward", "enter", "batao", "bataiye", "bata do", "bhejo", "bolo",
		"बताओ", "बताएं", "बताइए", "भेजो", "भेजें", "दे दो"},
}

// isRiskyRequest keeps a model-claimed F05-F08 only if its quote asks for the act and is not "do not" advice.
func isRiskyRequest(fid, evidence string, r *RuleResult) bool {
	if negatedAdvice(evidence) {
		return false
	}
	if _, ok := r.Flags[fid]; ok {
		return true
	}
	return containsAny(strings.ToLower(evidence), requestWords[fid])
}

func gatherSignals(ctx context.Context, r *RuleResult) []Signal {
	sigs := append([]Signal{}, r.Signals...)
	for _, ph := range r.Phones {
		sigs = append(sigs, repSignals("number", ph)...)
	}
	for _, v := range r.UPIIDs {
		sigs = append(sigs, repSignals("upi", v)...)
	}
	for _, u := range r.URLs {
		sigs = append(sigs, repSignals("url", u)...)
	}
	if len(r.URLs) > 0 && webRiskEnabled() {
		urls := r.URLs
		if len(urls) > 5 {
			urls = urls[:5]
		}
		results := make([][]Signal, len(urls))
		var wg sync.WaitGroup
		for i, u := range urls {
			wg.Add(1)
			go func(i int, u string) {
				defer wg.Done()
				results[i] = webRiskCheck(ctx, u)
			}(i, u)
		}
		wg.Wait()
		for _, res := range results {
			sigs = append(sigs, res...)
		}
	}
	return sigs
}

func mergeRuleResults(base, extra *RuleResult) {
	base.Signals = append(base.Signals, extra.Signals...)
	for k, v := range extra.Flags {
		if _, ok := base.Flags[k]; !ok {
			base.Flags[k] = v
		}
	}
	base.QR = append(base.QR, extra.QR...)
	for _, u := range extra.URLs {
		base.URLs = appendUnique(base.URLs, u)
	}
	for _, u := range extra.UPIIDs {
		base.UPIIDs = appendUnique(base.UPIIDs, u)
	}
	base.OverrideCritical = base.OverrideCritical || extra.OverrideCritical
	if base.CategoryHint == "" {
		base.CategoryHint = extra.CategoryHint
	}
}

var trustedSignalNames = set("apk_download", "brand_lookalike", "fake_government_domain", "foreign_number_claims_authority")

func systemChecksText(r *RuleResult, sigs []Signal) string {
	var lines []string
	for _, q := range r.QR {
		if q.IsPayRequest {
			amt := firstNonEmpty(q.Amount, "unspecified")
			lines = append(lines, fmt.Sprintf("- QR code decoded: UPI PAY request to %s %s amount %s. Scanning it SENDS money.", q.PayeeName, q.PayeeVPA, amt))
		} else {
			p := q.Payload
			if len(p) > 120 {
				p = p[:120]
			}
			lines = append(lines, "- QR code decoded: "+p)
		}
	}
	for _, s := range sigs {
		if s.Source == "webrisk" || s.Source == "reputation" || trustedSignalNames[s.Name] {
			lines = append(lines, "- "+s.Detail)
		}
	}
	if len(lines) == 0 {
		return "- none"
	}
	return strings.Join(lines, "\n")
}

func analyze(ctx context.Context, text string, images, audio []Media, source, lang, contextText string) *CheckResponse {
	t0 := time.Now()
	fullText := strings.Join(nonEmpty(text, contextText), "\n")
	cm := startCommunityMatch(ctx, fullText) // patterns other users reported (community.go)

	r := analyzeText(fullText)
	imgBytes := make([][]byte, len(images))
	for i, m := range images {
		imgBytes[i] = m.Data
	}
	for _, payload := range decodeQRImages(imgBytes) {
		mergeRuleResults(r, checkQR(payload, fullText))
	}
	sigs := gatherSignals(ctx, r)

	var mv *ModelVerdict
	degraded, modelUsed := true, ""
	hasMedia := len(images) > 0 || len(audio) > 0
	if geminiConfigured() && (text != "" || contextText != "" || hasMedia) {
		var timeout time.Duration
		modelUsed, timeout = modelFast, timeoutText
		if hasMedia {
			modelUsed, timeout = modelDeep, timeoutMedia
		}
		replyLang, _ := replyLanguage(lang, fullText)
		var p strings.Builder
		fmt.Fprintf(&p, "SOURCE: %s\nREPLY LANGUAGE: %s. Write summary, do_now, next_steps, say_this, read_aloud and clarify "+
			"only in this language. If the input is audio or an image, use the language spoken or written in it.\nSYSTEM CHECKS:\n%s\n",
			source, replyLang, systemChecksText(r, sigs))
		p.WriteString(cm.prompt(communityPromptBudget))
		if len(audio) > 0 {
			p.WriteString("The audio is a recorded call or voice note. Judge what the speakers tell the user to do.\n")
		}
		if len(images) > 0 {
			p.WriteString("The image(s) are screenshots, photos, documents or QR codes the user received.\n")
		}
		fmt.Fprintf(&p, "USER INPUT:\n<<<\n%s\n>>>\n", firstNonEmpty(text, "(see attached media)"))
		if contextText != "" {
			fmt.Fprintf(&p, "ADDITIONAL ANSWERS FROM USER:\n%s\n", contextText)
		}
		parts := []*genai.Part{genai.NewPartFromText(p.String())}
		for _, m := range images {
			parts = append(parts, genai.NewPartFromBytes(m.Data, m.MIME))
		}
		for _, m := range audio {
			parts = append(parts, genai.NewPartFromBytes(m.Data, m.MIME))
		}
		var v ModelVerdict
		if err := callGemini(ctx, modelUsed, parts, timeout, systemInstruction, verdictSchema, &v); err != nil {
			log.Printf("gemini failed (%s): %v", modelUsed, err) // fall back to rules
		} else {
			mv, degraded = &v, false
		}
	}
	sigs = append(sigs, cm.signals(ctx, mv)...)
	resp := buildResponse(r, sigs, mv, degraded, modelUsed, lang, fullText, hasMedia, time.Since(t0).Milliseconds())
	resp.Community = cm.attach(resp, fullText)
	return resp
}

type FlagOut struct {
	FlagID   string `json:"flag_id"`
	Label    string `json:"label"`
	Evidence string `json:"evidence"`
	Why      string `json:"why"`
	Source   string `json:"source"`
}

type CategoryOut struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Lever     string   `json:"lever"`
	LeverName string   `json:"lever_name"`
	Facts     []string `json:"facts"`
	Playbook  *string  `json:"playbook"`
}

type IDText struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

type PlaybookOut struct {
	ID    string   `json:"id"`
	Steps []string `json:"steps"`
}

type CheckResponse struct {
	ID               string            `json:"id"`
	Score            int               `json:"score"`
	Level            string            `json:"level"`
	Verdict          string            `json:"verdict"`
	VerdictLabel     string            `json:"verdict_label"`
	Category         *CategoryOut      `json:"category"`
	Summary          string            `json:"summary"`
	RedFlags         []FlagOut         `json:"red_flags"`
	OfficialFact     *IDText           `json:"official_fact"`
	DoNow            string            `json:"do_now"`
	NextSteps        []string          `json:"next_steps"`
	SayThis          string            `json:"say_this"`
	ReadAloud        string            `json:"read_aloud"`
	Clarify          []string          `json:"clarify"`
	MoneyAlreadySent bool              `json:"money_already_sent"`
	Playbook         *PlaybookOut      `json:"playbook"`
	QR               []QRInfo          `json:"qr"`
	Signals          []Signal          `json:"signals"`
	Community        []PatternView     `json:"community"`
	Extracted        map[string]any    `json:"extracted"`
	Helplines        map[string]string `json:"helplines"`
	Lang             string            `json:"lang"`
	Degraded         bool              `json:"degraded"`
	Model            *string           `json:"model"`
	LatencyMs        int64             `json:"latency_ms"`
}

func buildResponse(r *RuleResult, sigs []Signal, mv *ModelVerdict, degraded bool, modelUsed, lang, input string,
	hasMedia bool, latency int64) *CheckResponse {
	lk := langKey(lang, input)
	if mv != nil {
		lk = langKey(mv.Lang, input)
	}
	T := templates[lk]

	flags := map[string]FlagOut{}
	for fid, ev := range r.Flags {
		flags[fid] = FlagOut{FlagID: fid, Label: RedFlags[fid], Evidence: ev, Source: "rules"}
	}
	categoryID := r.CategoryHint
	if mv != nil {
		p := math.Max(0, math.Min(1, mv.PScam))
		sigs = append(sigs, Signal{Source: "gemini", Name: "p_scam", Weight: 0.6 * p, Detail: fmt.Sprintf("AI estimate %.2f", mv.PScam)})
		normIn := norm(input)
		for _, f := range mv.RedFlags {
			if _, ok := RedFlags[f.FlagID]; !ok {
				continue
			}
			if !hasMedia && f.Evidence != "" && !strings.Contains(normIn, norm(f.Evidence)) {
				continue // unsupported quote: drop rather than invent
			}
			if negatable[f.FlagID] && !isRiskyRequest(f.FlagID, f.Evidence, r) {
				continue // "483920 is your OTP" or "do not share it" is a bank message, not a request
			}
			flags[f.FlagID] = FlagOut{FlagID: f.FlagID, Label: RedFlags[f.FlagID], Evidence: f.Evidence, Why: f.Why, Source: "gemini"}
		}
		if _, ok := Categories[mv.CategoryID]; ok {
			categoryID = mv.CategoryID
		} else if mv.CategoryID == "NEW" {
			categoryID = ""
		}
	}

	for _, fid := range flagOrder {
		if _, ok := flags[fid]; !ok {
			continue
		}
		has := false
		for _, s := range sigs {
			if s.FlagID == fid {
				has = true
				break
			}
		}
		if !has {
			src, w := "rules", 0.25
			if mv != nil {
				src = "gemini"
			}
			if CoreFlags[fid] {
				w = 0.5
			}
			sigs = append(sigs, Signal{Source: src, Name: "flag_" + fid, Weight: w, Detail: RedFlags[fid], FlagID: fid})
		}
	}

	anyOf := func(ids map[string]bool) bool {
		for id := range flags {
			if ids[id] {
				return true
			}
		}
		return false
	}
	_, hasF08 := flags["F08"]
	override := r.OverrideCritical || hasF08 || (anyOf(CriticalFlags) && anyOf(set("F02", "F11", "F20")))
	scoreVal := score(sigs, override)
	// A recording or photo the AI couldn't read must never come back as "no signs".
	cantCheck := mv == nil && hasMedia && len(flags) == 0
	if cantCheck && scoreVal < 30 {
		scoreVal = 30
	}
	lvl := level(scoreVal)

	verdict := map[string]string{"CRITICAL": "SCAM", "HIGH": "LIKELY_SCAM", "CAUTION": "UNSURE", "LOW": "NO_SIGNS_FOUND"}[lvl]
	// The model may raise the verdict only with surviving evidence or real confidence; otherwise label and level disagree.
	if mv != nil && (len(flags) > 0 || mv.PScam >= 0.5) {
		if rank, ok := verdictRank[mv.Verdict]; ok && rank > verdictRank[verdict] {
			verdict = mv.Verdict
		}
	}
	if anyOf(CoreFlags) && verdictRank[verdict] < verdictRank["LIKELY_SCAM"] {
		verdict = "LIKELY_SCAM"
	}

	var cat *CategoryOut
	if categoryID != "" && verdict != "NO_SIGNS_FOUND" {
		c := Categories[categoryID]
		facts := c.Facts
		if facts == nil {
			facts = []string{}
		}
		var pb *string
		if c.Playbook != "" {
			pb = &c.Playbook
		}
		cat = &CategoryOut{ID: categoryID, Name: c.Name, Lever: c.Lever, LeverName: Levers[c.Lever], Facts: facts, Playbook: pb}
	}

	factID := ""
	if mv != nil {
		if _, ok := OfficialFacts[mv.OfficialFactID]; ok {
			factID = mv.OfficialFactID
		}
	}
	if factID == "" && cat != nil && len(cat.Facts) > 0 {
		factID = cat.Facts[0]
	}
	if _, ok := flags["F05"]; factID == "" && ok {
		factID = "OF11"
	}
	moneySent := mv != nil && mv.MoneyAlreadySent
	playbookID := ""
	switch {
	case moneySent:
		playbookID = "P02"
	case cat != nil:
		if cat.Playbook != nil {
			playbookID = *cat.Playbook
		}
	case lvl == "HIGH" || lvl == "CRITICAL":
		playbookID = "P01"
	}

	allowed := map[string]bool{}
	for _, m := range phoneishRE.FindAllString(input, -1) {
		allowed[nonDigitRE.ReplaceAllString(m, "")] = true
	}
	var summary, doNow, sayThis, readAloud, outLang string
	nextSteps, clarify := []string{}, []string{}
	urgent := lvl == "HIGH" || lvl == "CRITICAL"
	if mv != nil {
		summary = stripNumbers(mv.Summary, allowed)
		doNow = stripNumbers(mv.DoNow, allowed)
		for i, s := range mv.NextSteps {
			if i == 3 {
				break
			}
			nextSteps = append(nextSteps, stripNumbers(s, allowed))
		}
		sayThis = stripNumbers(mv.SayThis, allowed)
		readAloud = stripNumbers(mv.ReadAloud, allowed)
		if verdict == "UNSURE" {
			for i, q := range mv.Clarify {
				if i == 2 {
					break
				}
				clarify = append(clarify, q)
			}
		}
		_, code := replyLanguage(lang, input)
		outLang = code
		if hasMedia || code == "" || (code == "hi-IN" && strings.HasPrefix(mv.Lang, "mr")) {
			outLang = mv.Lang
		}
	} else {
		switch {
		case cantCheck:
			summary = T.CantCheck
		case cat != nil:
			summary = fmt.Sprintf(T.Scam, cat.Name)
		case lvl != "LOW":
			summary = T.Signs
		default:
			summary = T.None
		}
		doNow = T.DoNow[lvl]
		if cantCheck {
			doNow = T.CantDoNow
		}
		if playbookID != "" {
			steps := Playbooks[playbookID]
			nextSteps = append(nextSteps, steps[:min(3, len(steps))]...)
		}
		if urgent {
			if l, ok := ExitLines[categoryID]; ok {
				sayThis = l
			} else {
				sayThis = ExitLines["default"]
			}
		}
		hang := ""
		if urgent {
			hang = T.Hangup
		}
		readAloud = strings.Join(nonEmpty(T.Open, summary, hang, doNow), " ")
		outLang = "en-IN"
		if lk == "hi" {
			outLang = "hi-IN"
		}
	}

	ordered := make([]FlagOut, 0, len(flags))
	for _, f := range flags {
		ordered = append(ordered, f)
	}
	sort.Slice(ordered, func(i, j int) bool {
		ci, cj := CoreFlags[ordered[i].FlagID], CoreFlags[ordered[j].FlagID]
		if ci != cj {
			return ci
		}
		return ordered[i].FlagID < ordered[j].FlagID
	})
	if len(ordered) > 5 {
		ordered = ordered[:5]
	}

	outSigs := []Signal{}
	for _, s := range sigs {
		if !(s.Source == "gemini" && s.Name == "p_scam") {
			outSigs = append(outSigs, s)
		}
	}
	extracted := map[string]any{"urls": r.URLs, "phones": r.Phones, "upi_ids": r.UPIIDs}
	if mv != nil {
		amounts := mv.Extracted.Amounts
		if amounts == nil {
			amounts = []string{}
		}
		extracted["amounts"], extracted["claimed_org"] = amounts, mv.Extracted.ClaimedOrg
	}
	resp := &CheckResponse{
		ID: newID(), Score: scoreVal, Level: lvl, Verdict: verdict, VerdictLabel: verdictLabels[verdict],
		Category: cat, Summary: summary, RedFlags: ordered, DoNow: doNow, NextSteps: nextSteps, SayThis: sayThis,
		ReadAloud: readAloud, Clarify: clarify, MoneyAlreadySent: moneySent, QR: r.QR, Signals: outSigs,
		Extracted: extracted, Helplines: Helplines, Lang: outLang, Degraded: degraded, LatencyMs: latency,
	}
	if factID != "" {
		resp.OfficialFact = &IDText{ID: factID, Text: OfficialFacts[factID]}
	}
	if playbookID != "" {
		resp.Playbook = &PlaybookOut{ID: playbookID, Steps: Playbooks[playbookID]}
	}
	if !degraded {
		resp.Model = &modelUsed
	}
	return resp
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func nonEmpty(vals ...string) []string {
	out := []string{}
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envSeconds(k string, def float64) time.Duration {
	var v float64
	if _, err := fmt.Sscanf(os.Getenv(k), "%g", &v); err != nil || v <= 0 {
		v = def
	}
	return time.Duration(v * float64(time.Second))
}
