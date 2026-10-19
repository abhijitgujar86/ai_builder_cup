package main

// "I already paid" golden-hour guide: fixed 1930-first steps + Gemini-drafted complaint.

import (
	"context"
	"fmt"
	"log"
	"strings"

	"google.golang.org/genai"
)

type PaidDetails struct {
	Amount, Method, Bank, Payee, TxnID, When, WhatHappened string
	MinutesAgo                                             *int
}

type paidDraft struct {
	Amount        string `json:"amount"`
	TxnID         string `json:"txn_id"`
	Payee         string `json:"payee"`
	TxnTime       string `json:"txn_time"`
	Bank          string `json:"bank"`
	ComplaintText string `json:"complaint_text"`
	ReadAloud     string `json:"read_aloud"`
	Lang          string `json:"lang"`
}

var paidSchema = jsObj(map[string]any{
	"amount": jsStr(), "txn_id": jsStr(), "payee": jsStr(), "txn_time": jsStr(), "bank": jsStr(),
	"complaint_text": jsStr(), "read_aloud": jsStr(), "lang": jsStr(),
})

const paidPrompt = `The user was scammed and already sent money (India). Using the details and any payment screenshot,
extract amount, transaction ID / UTR, payee (UPI ID or account), time and the user's bank ("" if unknown, never guess).
Write complaint_text in English for cybercrime.gov.in: first person, factual, under 150 words, include every
extracted detail, what the scammer claimed and asked, and that 1930 was called.
Write read_aloud (under 50 words) in the user's language: calm, no blame, telling them to call 1930 now and keep the details ready.
Do not write any phone number except 1930. lang = BCP-47 code of read_aloud.

DETAILS FROM USER:
%s
User language: %s`

var paidSteps = map[string][]string{
	"en": Playbooks["P02"],
	"hi": {"अभी 1930 पर कॉल करें। तैयार रखें: रकम, समय, ट्रांज़ैक्शन ID (UTR), पाने वाले का UPI ID या खाता, आपका बैंक।",
		"अपने बैंक की फ्रॉड हेल्पलाइन पर कॉल करें (कार्ड के पीछे या आधिकारिक ऐप वाला नंबर) और पैसे रोकने को कहें।",
		"सब कुछ का स्क्रीनशॉट लें। कोई चैट डिलीट न करें।",
		"24 घंटे के अंदर cybercrime.gov.in पर शिकायत दर्ज करें, 1930 का acknowledgement नंबर लिखें।",
		"पैसे वापस दिलाने के नाम पर फीस मांगने वाले को कभी पैसे न दें।",
		"किसी भरोसेमंद व्यक्ति को बताएं।"},
}

type PaidCard struct {
	Amount string `json:"amount"`
	TxnID  string `json:"txn_id"`
	Payee  string `json:"payee"`
	Time   string `json:"time"`
	Bank   string `json:"bank"`
}

type PaidResponse struct {
	Urgency       string   `json:"urgency"`
	CallNow       string   `json:"call_now"`
	Steps         []string `json:"steps"`
	Card          PaidCard `json:"card"`
	ComplaintText string   `json:"complaint_text"`
	FileAt        string   `json:"file_at"`
	ReadAloud     string   `json:"read_aloud"`
	Warning       string   `json:"warning"`
	Degraded      bool     `json:"degraded"`
}

func paidUrgency(minutesAgo *int, lk string) string {
	if minutesAgo != nil && *minutesAgo <= 60 {
		if lk == "en" {
			return "You are inside the first hour. Calling 1930 now gives the best chance to freeze the money."
		}
		return "अभी पहला घंटा चल रहा है। अभी 1930 पर कॉल करने से पैसे रुकने की सबसे अच्छी संभावना है।"
	}
	if lk == "en" {
		return "Call 1930 now anyway. Money can still be traced and frozen."
	}
	return "फिर भी अभी 1930 पर कॉल करें। पैसे अब भी ट्रेस और फ्रीज़ हो सकते हैं।"
}

func paidGuide(ctx context.Context, d PaidDetails, lang string, screenshot *Media) PaidResponse {
	lk := "en"
	if strings.HasPrefix(strings.ToLower(lang), "hi") {
		lk = "hi"
	}
	var lines []string
	add := func(k, v string) {
		if v != "" {
			lines = append(lines, k+": "+v)
		}
	}
	add("amount", d.Amount)
	if d.MinutesAgo != nil {
		add("minutes_ago", itoa(*d.MinutesAgo))
	}
	add("method", d.Method)
	add("bank", d.Bank)
	add("payee", d.Payee)
	add("txn_id", d.TxnID)
	add("when", d.When)
	add("what_happened", d.WhatHappened)
	detText := firstNonEmpty(strings.Join(lines, "\n"), "(none given)")

	var draft *paidDraft
	if geminiConfigured() {
		parts := []*genai.Part{genai.NewPartFromText(fmt.Sprintf(paidPrompt, detText, lang))}
		if screenshot != nil {
			parts = append(parts, genai.NewPartFromBytes(screenshot.Data, screenshot.MIME))
		}
		var v paidDraft
		if err := callGemini(ctx, modelDeep, parts, timeoutMedia, "", paidSchema, &v); err != nil {
			log.Printf("paid draft failed: %v", err)
		} else {
			draft = &v
		}
	}
	pick := func(fromModel, fromUser string) string {
		if draft != nil && fromModel != "" {
			return fromModel
		}
		return fromUser
	}
	var dm paidDraft
	if draft != nil {
		dm = *draft
	}
	card := PaidCard{Amount: pick(dm.Amount, d.Amount), TxnID: pick(dm.TxnID, d.TxnID), Payee: pick(dm.Payee, d.Payee),
		Time: pick(dm.TxnTime, d.When), Bank: pick(dm.Bank, d.Bank)}

	var complaint, readAloud string
	if draft != nil {
		complaint = stripNumbers(draft.ComplaintText, nil)
		readAloud = stripNumbers(draft.ReadAloud, nil)
	} else {
		complaint = fmt.Sprintf("I was cheated by a caller/message that %s. I sent %s to %s (transaction ID %s) at %s from my %s account. "+
			"I have called 1930. Please freeze the money and investigate.",
			firstNonEmpty(d.WhatHappened, "asked me to send money"), firstNonEmpty(card.Amount, "[amount]"),
			firstNonEmpty(card.Payee, "[payee UPI ID / account]"), firstNonEmpty(card.TxnID, "[UTR]"),
			firstNonEmpty(card.Time, "[date and time]"), firstNonEmpty(card.Bank, "[bank]"))
		if lk == "hi" {
			readAloud = paidSteps["hi"][0]
		} else {
			readAloud = "Please don't worry. Call 1930 now and keep the payment details ready."
		}
	}
	warning := "Anyone who promises to recover your money for a fee is also a scammer."
	if lk == "hi" {
		warning = "पैसे वापस दिलाने के नाम पर फीस मांगने वाला भी धोखेबाज़ है।"
	}
	return PaidResponse{Urgency: paidUrgency(d.MinutesAgo, lk), CallNow: "1930", Steps: paidSteps[lk], Card: card,
		ComplaintText: complaint, FileAt: "cybercrime.gov.in", ReadAloud: readAloud, Warning: warning, Degraded: draft == nil}
}
