package main

// Google Web Risk Lookup API. Skipped (no signal) when WEBRISK_API_KEY is unset.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var webRiskThreats = []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "SOCIAL_ENGINEERING_EXTENDED_COVERAGE"}

func webRiskEnabled() bool { return os.Getenv("WEBRISK_API_KEY") != "" }

func webRiskCheck(ctx context.Context, raw string) []Signal {
	key := os.Getenv("WEBRISK_API_KEY")
	if key == "" {
		return nil
	}
	u := raw
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	q := url.Values{"uri": {u}, "key": {key}, "threatTypes": webRiskThreats}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://webrisk.googleapis.com/v1/uris:search?"+q.Encode(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var body struct {
		Threat *struct {
			ThreatTypes []string `json:"threatTypes"`
		} `json:"threat"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) != nil || body.Threat == nil {
		return nil
	}
	types := make([]string, len(body.Threat.ThreatTypes))
	for i, t := range body.Threat.ThreatTypes {
		types[i] = strings.ToLower(strings.ReplaceAll(t, "_", " "))
	}
	return []Signal{{Source: "webrisk", Name: "google_web_risk", Weight: 0.9,
		Detail: "Google Web Risk lists this link as " + strings.Join(types, ", ")}}
}
