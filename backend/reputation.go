package main

// Crowd reputation for phone numbers, UPI IDs and links.
// In-memory, seeded with clearly-labelled demo data (no Indian government feed is public).

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

//go:embed data/seed_reports.json
var seedJSON []byte

type RepRow struct {
	Count      int      `json:"count"`
	Categories []string `json:"categories"`
	LastSeen   string   `json:"last_seen"`
	Demo       bool     `json:"demo"`
}

var (
	repMu    sync.Mutex
	repStore = map[string]*RepRow{}
)

func repKey(kind, value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if kind == "number" {
		v = normalizePhone(v)
	}
	return kind + ":" + v
}

func init() {
	var rows []struct {
		Type, Value string
		Count       int
		Categories  []string
		LastSeen    string `json:"last_seen"`
	}
	if err := json.Unmarshal(seedJSON, &rows); err != nil {
		panic(err)
	}
	for _, r := range rows {
		cats := r.Categories
		if cats == nil {
			cats = []string{}
		}
		repStore[repKey(r.Type, r.Value)] = &RepRow{Count: r.Count, Categories: cats, LastSeen: r.LastSeen, Demo: true}
	}
}

func repLookup(kind, value string) *RepRow {
	repMu.Lock()
	defer repMu.Unlock()
	if r, ok := repStore[repKey(kind, value)]; ok {
		c := *r
		return &c
	}
	return nil
}

func repReport(kind, value, category string) RepRow {
	repMu.Lock()
	defer repMu.Unlock()
	k := repKey(kind, value)
	r, ok := repStore[k]
	if !ok {
		r = &RepRow{Categories: []string{}}
		repStore[k] = r
	}
	r.Count++
	if category != "" {
		r.Categories = appendUnique(r.Categories, category)
	}
	r.LastSeen = time.Now().Format("2006-01-02")
	return *r
}

func repSignals(kind, value string) []Signal {
	r := repLookup(kind, value)
	if r == nil || r.Count < 1 {
		return nil
	}
	w := 0.2
	if r.Count >= 10 {
		w = 0.8
	} else if r.Count >= 3 {
		w = 0.5
	}
	src := ""
	if r.Demo {
		src = " (demo data)"
	}
	label := map[string]string{"number": "number", "upi": "UPI ID", "url": "link"}[kind]
	return []Signal{{Source: "reputation", Name: "reported_" + kind, Weight: w,
		Detail: fmt.Sprintf("This %s was reported %d times as a scam%s", label, r.Count, src)}}
}
