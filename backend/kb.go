package main

// Scam knowledge base: grounding for Gemini and the rules layer.
// Source: reports/Consumer scams targeting vulnerable people.md. The model may only cite ids defined here.

import (
	"fmt"
	"strings"
)

type Category struct {
	Lever, Name string
	Triggers    []string
	Flags       []string
	Facts       []string
	Playbook    string
}

var Levers = map[string]string{
	"A": "Fear of authority",
	"B": "Fear for family",
	"C": "Fear of losing a service or benefit",
	"D": "Greed, hope or need",
	"E": "Love and loneliness",
	"F": "Everyday buying, selling and help-seeking",
	"G": "Device and account takeover",
}

var leverOrder = []string{"A", "B", "C", "D", "E", "F", "G"}

var categoryOrder = []string{"C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "C09", "C10", "C11", "C12", "C13",
	"C14", "C15", "C16", "C17", "C18", "C19", "C20", "C21", "C22", "C23", "C24", "C25", "C26", "C27", "C28", "C29", "C30", "C31"}

var Categories = map[string]Category{
	"C01": {"A", "Digital arrest (fake police / CBI / ED / judge)",
		[]string{"digital arrest", "cbi officer", "money laundering", "aadhaar misuse", "non-involvement", "noc certificate", "arrest warrant", "supreme court order", "ed officer", "ncb officer"},
		[]string{"F01", "F02", "F03", "F10", "F11", "F16", "F17", "F19", "F20"}, []string{"OF01", "OF02", "OF03"}, "P01"},
	"C02": {"A", "Courier parcel with 'drugs' (FedEx / customs)",
		[]string{"fedex", "dhl", "parcel", "customs", "drugs in", "mdma", "parcel mein"},
		[]string{"F10", "F11", "F02", "F20"}, []string{"OF01", "OF04"}, "P01"},
	"C03": {"A", "'Your number will be disconnected' (fake TRAI)",
		[]string{"trai", "press 9", "number will be blocked", "number band", "sim will be blocked"},
		[]string{"F11", "F20"}, []string{"OF05"}, "P01"},
	"C04": {"A", "Sextortion followed by fake police",
		[]string{"video viral", "obscene video", "crime branch", "nude video", "delete the video"},
		[]string{"F01", "F11"}, []string{"OF01"}, "P05"},
	"C05": {"B", "'Your son/daughter is arrested'",
		[]string{"son is arrested", "beta giraftaar", "daughter arrested", "dsp", "your son"},
		[]string{"F02", "F11", "F12"}, nil, "P06"},
	"C06": {"B", "'Hi Mum, new number' / 'Guess who' / hacked friend",
		[]string{"new number", "naya number", "hi mum", "hi mom", "guess who", "pehchana"},
		[]string{"F12"}, nil, "P06"},
	"C07": {"B", "AI voice clone of a relative",
		[]string{"voice note", "it's me", "main bol raha"},
		[]string{"F12", "F11"}, nil, "P06"},
	"C08": {"C", "Electricity / gas disconnection",
		[]string{"electricity", "bijli", "power will be cut", "lpg", "gas connection", "bill not updated"},
		[]string{"F11", "F06", "F18"}, []string{"OF06", "OF07"}, "P03"},
	"C09": {"C", "Bank KYC / account block / reward points",
		[]string{"kyc", "reward points", "account will be blocked", "yono", "pan update", "aadhaar update"},
		[]string{"F18", "F06", "F08"}, []string{"OF07"}, "P03"},
	"C10": {"C", "Pension / life certificate",
		[]string{"pension", "jeevan pramaan", "life certificate", "ppo"},
		[]string{"F08", "F17"}, []string{"OF07"}, "P03"},
	"C11": {"C", "Insurance bonus / lapsed policy refund",
		[]string{"policy bonus", "irdai", "lapsed policy", "insurance refund"},
		[]string{"F04"}, []string{"OF08"}, "P07"},
	"C12": {"C", "Government refund / rebate",
		[]string{"tax refund", "income tax refund", "refund approved"},
		[]string{"F04", "F08"}, []string{"OF08"}, "P03"},
	"C13": {"D", "Investment / trading group, fake app, deepfake ad",
		[]string{"stock tips", "trading app", "ipo allotment", "guaranteed return", "withdrawal tax", "crypto", "vip group"},
		[]string{"F13", "F04"}, []string{"OF09"}, "P07"},
	"C14": {"D", "Task / part-time job",
		[]string{"part time job", "like videos", "hotel rating", "prepaid task", "work from home", "daily income"},
		[]string{"F04", "F13"}, []string{"OF08"}, "P07"},
	"C15": {"D", "Fake overseas job (trafficking risk)",
		[]string{"thailand job", "job in cambodia", "job in myanmar", "data entry abroad"},
		[]string{"F04"}, []string{"OF10"}, ""},
	"C16": {"D", "Lottery / KBC prize",
		[]string{"kbc", "lottery", "lucky draw", "you have won", "prize money"},
		[]string{"F04"}, []string{"OF08"}, "P07"},
	"C17": {"D", "Fake government scheme / subsidy / scholarship",
		[]string{"pm kusum", "yojana", "scholarship", "subsidy", "registration fee"},
		[]string{"F04", "F05", "F15"}, []string{"OF08", "OF11"}, "P09"},
	"C18": {"D", "Illegal instant-loan app",
		[]string{"instant loan", "loan app", "loan approved"},
		[]string{"F06"}, nil, "P08"},
	"C19": {"E", "Romance / friendship / 'pig butchering'",
		[]string{"medical emergency", "joint investment", "my love", "dear friend"},
		[]string{"F04", "F13"}, []string{"OF09"}, "P07"},
	"C20": {"E", "Foreign gift parcel / customs fee",
		[]string{"gift parcel", "airport customs", "gift from uk", "foreign currency in parcel"},
		[]string{"F04", "F15"}, []string{"OF04"}, "P07"},
	"C21": {"E", "Matrimonial-site fraud",
		[]string{"matrimonial", "nri groom", "marriage proposal"},
		[]string{"F04"}, nil, "P07"},
	"C22": {"F", "'Army officer' buyer/seller and 'scan to receive' QR",
		[]string{"army officer", "posted out", "transfer posting", "scan to receive", "canteen"},
		[]string{"F05"}, []string{"OF11"}, "P09"},
	"C23": {"F", "Rental / property listing scam",
		[]string{"defence payment", "test transfer", "commando", "tenant"},
		[]string{"F05", "F14"}, []string{"OF11"}, "P09"},
	"C24": {"F", "Fake customer care / tech support",
		[]string{"customer care", "helpline", "refund process", "anydesk", "teamviewer", "quick support"},
		[]string{"F06", "F08"}, []string{"OF12"}, "P03"},
	"C25": {"F", "Fake shop / e-commerce / cash on delivery",
		[]string{"advance payment", "cash on delivery", "too cheap", "order confirm"},
		[]string{"F15"}, nil, "P02"},
	"C26": {"F", "'Sent by mistake, please refund'",
		[]string{"sent by mistake", "galti se", "wrong transfer", "please return the money"},
		[]string{"F14"}, []string{"OF13"}, "P09"},
	"C27": {"F", "Fake temple / darshan / donation",
		[]string{"darshan", "temple donation", "prasad", "vip pass"},
		[]string{"F15"}, []string{"OF12"}, "P02"},
	"C28": {"G", "Malicious app file on WhatsApp",
		[]string{".apk", "wedding invitation", "e-challan", "traffic challan", "rto challan"},
		[]string{"F06"}, []string{"OF07"}, "P03"},
	"C29": {"G", "SIM / eSIM swap",
		[]string{"5g upgrade", "esim", "sim upgrade"},
		[]string{"F08"}, []string{"OF07"}, "P04"},
	"C30": {"G", "Call merging to steal OTP",
		[]string{"merge the call", "merge call", "call merge"},
		[]string{"F07", "F08"}, []string{"OF14"}, "P03"},
	"C31": {"G", "Phishing link / OTP theft",
		[]string{"click the link", "verify your account", "otp"},
		[]string{"F18", "F08"}, []string{"OF07"}, "P03"},
}

var flagOrder = []string{"F01", "F02", "F03", "F04", "F05", "F06", "F07", "F08", "F09", "F10",
	"F11", "F12", "F13", "F14", "F15", "F16", "F17", "F18", "F19", "F20"}

var RedFlags = map[string]string{
	"F01": "Told to keep it secret from family, bank or staff",
	"F02": "Told to stay on the call or keep the camera on",
	"F03": "Asked to move money to a 'safe', 'verification' or 'RBI' account",
	"F04": "Asked to pay a fee to receive money, a prize, a job or a refund",
	"F05": "Asked to scan a QR code or enter a PIN to 'receive' money",
	"F06": "Asked to install an app, app file (.apk) or remote-control app",
	"F07": "Asked to merge calls",
	"F08": "Asked for an OTP, UPI PIN, CVV or password",
	"F09": "Asked to break a fixed deposit, take a loan or sell gold",
	"F10": "'Official' contacting you on WhatsApp or Skype video",
	"F11": "Urgent threat: arrest, disconnection or account block",
	"F12": "'Relative' on a new number asking for urgent money",
	"F13": "Guaranteed high returns or profit screenshots",
	"F14": "'Sent by mistake, please refund'",
	"F15": "Government or company fee to a personal UPI ID or account",
	"F16": "Told what to say to the bank (cover story)",
	"F17": "Uses your personal details (Aadhaar, pension no.) as 'proof'",
	"F18": "Link to update KYC, pay a bill or claim rewards",
	"F19": "'Official document' (warrant, court order, RBI letter) sent on chat",
	"F20": "Passed on to a 'higher officer'",
}

var CoreFlags = set("F01", "F02", "F03", "F04", "F05", "F06", "F07", "F08")

// Any of these with money or a live call means stop now.
var CriticalFlags = set("F03", "F05", "F06", "F08")

var factOrder = []string{"OF01", "OF02", "OF03", "OF04", "OF05", "OF06", "OF07", "OF08", "OF09", "OF10", "OF11", "OF12", "OF13", "OF14"}

var OfficialFacts = map[string]string{
	"OF01": "Police, CBI, ED and judges never arrest or question anyone on a video call. 'Digital arrest' does not exist.",
	"OF02": "No government agency asks you to move money to a 'safe' or 'verification' account.",
	"OF03": "Courts and police do not send warrants on WhatsApp or settle cases for money.",
	"OF04": "Courier companies do not transfer you to the police, and customs duty is never paid to a personal account.",
	"OF05": "TRAI does not disconnect phone numbers through calls.",
	"OF06": "Electricity and gas companies do not collect payments to personal numbers or ask you to install apps.",
	"OF07": "Banks, RBI and pension offices never ask for your OTP, PIN, CVV or an app install by call, SMS or WhatsApp.",
	"OF08": "Real prizes, refunds, schemes and bonuses never need a fee paid first.",
	"OF09": "Withdrawing your own investment never needs a 'tax' paid first. Check SEBI registration.",
	"OF10": "Overseas jobs should come only through government-registered recruiting agents.",
	"OF11": "You never scan a QR code or enter your UPI PIN to receive money. A PIN is only for paying.",
	"OF12": "Take helpline numbers only from the official app, website or the back of your card, not from search results.",
	"OF13": "Check your bank app balance. Return any money only through your bank, never by a payment request.",
	"OF14": "Never merge an unknown call with another call. Banks never need this.",
}

// The ONLY contact points the AI may show. Any other number in model output is stripped.
var Helplines = map[string]string{
	"1930":                 "National Cyber Fraud Helpline (call immediately if money is lost)",
	"112":                  "Emergency",
	"cybercrime.gov.in":    "File a cyber-crime complaint; 'Report & Check Suspect'",
	"sancharsaathi.gov.in": "Chakshu: report fraud calls, SMS and WhatsApp messages",
}
var helplineOrder = []string{"1930", "112", "cybercrime.gov.in", "sancharsaathi.gov.in"}
var AllowedNumbers = set("1930", "112")

var Playbooks = map[string][]string{
	"P01": {"Hang up now. Nothing bad will happen to you.", "Do not call them back.",
		"Call someone you trust and tell them.", "If you already paid, open 'I already paid'."},
	"P02": {"Call 1930 now. Keep ready: amount, time, transaction ID (UTR), payee UPI ID or account, your bank.",
		"Call your bank's fraud line (number on your card or official app) and ask them to block or hold the money.",
		"Screenshot everything and keep the chats. Do not delete anything.",
		"File the complaint on cybercrime.gov.in within 24 hours, quoting the 1930 acknowledgement number.",
		"Never pay anyone who promises to recover your money for a fee.",
		"Tell someone you trust."},
	"P03": {"Turn on airplane mode or switch off internet now.", "Uninstall any app they asked you to install.",
		"Call your bank from another phone and block cards and UPI.",
		"Change your UPI PIN and net-banking password.", "If money moved, open 'I already paid'."},
	"P04": {"Call your mobile operator from another phone.", "Call your bank and freeze your accounts.",
		"If there are transactions, open 'I already paid'."},
	"P05": {"Do not pay. Paying never stops the threats.", "Do not delete the chats. Block the account.",
		"Report on cybercrime.gov.in. This is not your shame.",
		"Any 'police' who calls about it later is part of the same scam."},
	"P06": {"Call your relative on their old saved number now.", "Ask a question only they would know.",
		"Call another family member.", "Never send money to a new number."},
	"P07": {"Stop paying. No fee will unlock your money.", "Save all chats and receipts.",
		"If you paid recently, open 'I already paid'."},
	"P08": {"Do not pay the extortion. Morphed photos are fake.", "Tell your family first.",
		"Report on cybercrime.gov.in."},
	"P09": {"Do not scan the QR code or enter your PIN.", "Give the buyer your UPI ID instead.",
		"Trust your bank app balance, not screenshots or SMS."},
}

var ExitLines = map[string]string{
	"C01":     "I will come to the police station myself.",
	"C02":     "I will contact the courier company myself.",
	"C05":     "I will call my son first.",
	"C06":     "I will call you on your old number.",
	"default": "I don't do this on the phone. Goodbye.",
}

var RemoteAccessApps = map[string]string{
	"com.anydesk.anydeskandroid":              "AnyDesk",
	"com.teamviewer.quicksupport.market":      "TeamViewer QuickSupport",
	"com.teamviewer.teamviewer.market.mobile": "TeamViewer",
	"com.rustdesk.rustdesk":                   "RustDesk",
	"com.sand.airdroid":                       "AirDroid",
	"com.sand.airdroidbiz":                    "AirDroid Business",
	"com.splashtop.remote.pad.v2":             "Splashtop",
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

// promptBlock is the compact KB text for the Gemini system instruction.
func promptBlock() string {
	var b strings.Builder
	b.WriteString("LEVERS:\n")
	for _, k := range leverOrder {
		fmt.Fprintf(&b, "  %s: %s\n", k, Levers[k])
	}
	b.WriteString("SCAM CATEGORIES (id lever name | trigger phrases):\n")
	for _, id := range categoryOrder {
		c := Categories[id]
		t := c.Triggers
		if len(t) > 6 {
			t = t[:6]
		}
		fmt.Fprintf(&b, "  %s %s %s | %s\n", id, c.Lever, c.Name, strings.Join(t, ", "))
	}
	b.WriteString("RED FLAGS (scammer instructions; F01-F08 are core):\n")
	for _, k := range flagOrder {
		fmt.Fprintf(&b, "  %s: %s\n", k, RedFlags[k])
	}
	b.WriteString("OFFICIAL FACTS (only these may be quoted as official):\n")
	for _, k := range factOrder {
		fmt.Fprintf(&b, "  %s: %s\n", k, OfficialFacts[k])
	}
	b.WriteString("HELPLINES (the only numbers/sites you may mention):\n")
	for _, k := range helplineOrder {
		fmt.Fprintf(&b, "  %s: %s\n", k, Helplines[k])
	}
	return strings.TrimRight(b.String(), "\n")
}
