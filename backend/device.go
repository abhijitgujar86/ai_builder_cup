package main

// Passive protection: score device/activity signals sent by the phone. Rules only, so it answers instantly.

import (
	"sort"
	"strings"
)

type DeviceEvent struct {
	OnCall                bool     `json:"on_call"`
	CallType              string   `json:"call_type"` // none | phone | whatsapp_voice | whatsapp_video | other_voip
	CallerKnown           bool     `json:"caller_known"`
	CallerNumber          string   `json:"caller_number"`
	CallSecs              int      `json:"call_secs"`
	PaymentAppForeground  bool     `json:"payment_app_foreground"`
	PaymentApp            string   `json:"payment_app"`
	RemoteAppsInstalled   []string `json:"remote_apps_installed"`
	RemoteAppRunning      bool     `json:"remote_app_running"`
	NewSideload           bool     `json:"new_sideload"`
	OTPReceivedDuringCall bool     `json:"otp_received_during_call"`
	SecondCallDuringCall  bool     `json:"second_call_during_call"`
	Lang                  string   `json:"lang"`
}

func defaultDeviceEvent() DeviceEvent {
	return DeviceEvent{CallType: "none", CallerKnown: true, Lang: "en"}
}

var deviceMessages = map[string]map[string][2]string{
	"call_plus_payment": {
		"en": {"Pause before you pay", "You are on a call with an unknown number and just opened {app}. Scammers make people pay while still on the call. Hang up first. Nothing bad will happen."},
		"hi": {"पैसे भेजने से पहले रुकिए", "आप एक अनजान नंबर से कॉल पर हैं और आपने {app} खोला है। धोखेबाज़ कॉल पर रहते हुए पैसे भिजवाते हैं। पहले फोन काटिए। कुछ बुरा नहीं होगा।"},
	},
	"long_unknown_video_call": {
		"en": {"Is this a 'digital arrest' call?", "This is a long video call from an unknown number. Real police, CBI or courts never question or arrest anyone on a video call. You can hang up now."},
		"hi": {"क्या यह 'डिजिटल अरेस्ट' कॉल है?", "यह अनजान नंबर से लंबी वीडियो कॉल है। असली पुलिस, CBI या कोर्ट कभी वीडियो कॉल पर पूछताछ या गिरफ्तारी नहीं करते। आप अभी फोन काट सकते हैं।"},
	},
	"remote_app": {
		"en": {"Someone can control your phone", "{app} lets another person control your phone. If a caller asked you to install it, uninstall it now and do not open your bank app."},
		"hi": {"कोई आपका फोन चला सकता है", "{app} से कोई और आपका फोन चला सकता है। अगर किसी कॉलर ने इसे इंस्टॉल करवाया है, तो इसे अभी हटाइए और बैंक ऐप न खोलें।"},
	},
	"otp_during_call": {
		"en": {"Never read an OTP to a caller", "An OTP arrived while you are on a call with an unknown number. Never tell anyone an OTP. Banks never ask for it."},
		"hi": {"कॉल पर OTP कभी न बताएं", "अनजान कॉल के दौरान OTP आया है। OTP किसी को न बताएं। बैंक कभी OTP नहीं मांगता।"},
	},
	"merge_risk": {
		"en": {"Don't merge calls", "A second call is coming in. Do not merge calls even if the caller asks. Banks never need this."},
		"hi": {"कॉल मर्ज न करें", "दूसरी कॉल आ रही है। कॉलर कहे तो भी कॉल मर्ज न करें। बैंक को इसकी कभी ज़रूरत नहीं होती।"},
	},
	"new_sideload": {
		"en": {"New app from outside Play Store", "An app was installed from outside the Play Store. If someone sent it on WhatsApp, uninstall it now."},
		"hi": {"Play Store के बाहर का नया ऐप", "Play Store के बाहर से एक ऐप इंस्टॉल हुआ है। अगर यह WhatsApp पर भेजा गया था, तो इसे अभी हटाइए।"},
	},
	"reported_number": {
		"en": {"Reported scam number", "Other users reported this number as a scam. Do not share codes or pay. You can hang up."},
		"hi": {"रिपोर्ट किया गया नंबर", "दूसरे लोगों ने इस नंबर को धोखे के रूप में रिपोर्ट किया है। कोड न बताएं, पैसे न भेजें। आप फोन काट सकते हैं।"},
	},
	"none": {
		"en": {"All quiet", "No risky pattern right now."},
		"hi": {"सब ठीक", "अभी कोई जोखिम वाला पैटर्न नहीं है।"},
	},
}

type Reason struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
}

type DeviceVerdict struct {
	Score          int      `json:"score"`
	Level          string   `json:"level"`
	Title          string   `json:"title"`
	Message        string   `json:"message"`
	Reasons        []Reason `json:"reasons"`
	Actions        []string `json:"actions"`
	ShowFullscreen bool     `json:"show_fullscreen"`
	Lang           string   `json:"lang"`
}

func evaluateDevice(e DeviceEvent) DeviceVerdict {
	var sigs []Signal
	unknownCall := e.OnCall && !e.CallerKnown
	app := firstNonEmpty(e.PaymentApp, "a payment app")
	names := []string{}
	for _, p := range e.RemoteAppsInstalled {
		names = append(names, firstNonEmpty(RemoteAccessApps[p], p))
	}
	remote := firstNonEmpty(strings.Join(names, ", "), "A remote-control app")

	if unknownCall && e.PaymentAppForeground {
		sigs = append(sigs, Signal{Source: "device", Name: "call_plus_payment", Weight: 0.6, Detail: "On a call with an unknown number while " + app + " is open"})
	}
	if unknownCall && e.CallType == "whatsapp_video" && e.CallSecs >= 300 {
		w := 0.5
		if e.CallSecs >= 900 {
			w = 0.7
		}
		sigs = append(sigs, Signal{Source: "device", Name: "long_unknown_video_call", Weight: w,
			Detail: "Video call from an unknown number for " + itoa(e.CallSecs/60) + " min"})
	}
	if e.RemoteAppRunning {
		sigs = append(sigs, Signal{Source: "device", Name: "remote_app", Weight: 0.6, Detail: remote + " is running"})
	} else if len(e.RemoteAppsInstalled) > 0 {
		sigs = append(sigs, Signal{Source: "device", Name: "remote_app", Weight: 0.4, Detail: remote + " is installed"})
	}
	if e.OTPReceivedDuringCall && unknownCall {
		sigs = append(sigs, Signal{Source: "device", Name: "otp_during_call", Weight: 0.7, Detail: "OTP arrived during a call with an unknown number"})
	}
	if e.SecondCallDuringCall && unknownCall {
		sigs = append(sigs, Signal{Source: "device", Name: "merge_risk", Weight: 0.4, Detail: "Second incoming call during an unknown call"})
	}
	if e.NewSideload {
		w := 0.4
		if e.OnCall {
			w = 0.6
		}
		sigs = append(sigs, Signal{Source: "device", Name: "new_sideload", Weight: w, Detail: "App installed from outside the Play Store"})
	}
	if e.CallerNumber != "" {
		for _, s := range repSignals("number", e.CallerNumber) {
			s.Name = "reported_number"
			sigs = append(sigs, s)
		}
		sigs = append(sigs, checkNumber(e.CallerNumber, "")...)
	}

	override := (e.RemoteAppRunning && e.OnCall && e.PaymentAppForeground) || (e.OTPReceivedDuringCall && unknownCall)
	scoreVal := score(sigs, override)
	lvl := level(scoreVal)
	lk := "en"
	if strings.HasPrefix(strings.ToLower(e.Lang), "hi") {
		lk = "hi"
	}
	key := "none"
	if len(sigs) > 0 && lvl != "LOW" {
		top := sigs[0]
		for _, s := range sigs[1:] {
			if s.Weight > top.Weight {
				top = s
			}
		}
		if _, ok := deviceMessages[top.Name]; ok {
			key = top.Name
		}
	}
	msg := deviceMessages[key][lk]
	fill := remote
	if key == "call_plus_payment" {
		fill = app
	}

	actions := []string{}
	if lvl == "HIGH" || lvl == "CRITICAL" {
		actions = append(actions, "HANG_UP", "DONT_PAY", "CALL_TRUSTED")
	}
	for _, s := range sigs {
		if s.Name == "remote_app" || s.Name == "new_sideload" {
			actions = append(actions, "UNINSTALL_APP")
			break
		}
	}
	if lvl != "LOW" {
		actions = append(actions, "OPEN_PAID_GUIDE")
	}
	sort.SliceStable(sigs, func(i, j int) bool { return sigs[i].Weight > sigs[j].Weight })
	reasons := []Reason{}
	for _, s := range sigs {
		reasons = append(reasons, Reason{s.Name, s.Detail})
	}
	lang := "en-IN"
	if lk == "hi" {
		lang = "hi-IN"
	}
	return DeviceVerdict{Score: scoreVal, Level: lvl, Title: msg[0], Message: strings.ReplaceAll(msg[1], "{app}", fill),
		Reasons: reasons, Actions: actions, ShowFullscreen: lvl == "HIGH" || lvl == "CRITICAL", Lang: lang}
}
