package main

// Live Vertex AI checks for community learning. Skipped unless DHAAL_LIVE=1 (needs ADC and GOOGLE_CLOUD_PROJECT).

import (
	"context"
	"os"
	"strings"
	"testing"
)

func live(t *testing.T) {
	if os.Getenv("DHAAL_LIVE") != "1" {
		t.Skip("set DHAAL_LIVE=1 to run against Vertex AI")
	}
	t.Setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
	if os.Getenv("GOOGLE_CLOUD_LOCATION") == "" {
		t.Setenv("GOOGLE_CLOUD_LOCATION", "global")
	}
}

func TestLiveEmbeddingMatchesSeedSpace(t *testing.T) {
	live(t)
	ctx := context.Background()
	q, tag := embedText(ctx, "A man called saying he is from the census department. He said my family is not counted and I have to fill a form online and tell him the OTP or we lose our ration card.")
	if tag != vertexTag() || len(q) != embedDims {
		t.Fatalf("embedding fell back: tag=%s dims=%d", tag, len(q))
	}
	s := newCommunityStore(true)
	hits := s.match(q, tag, 3)
	if len(hits) == 0 || hits[0].id != "cp-census" {
		t.Fatalf("census report did not match the seed: %+v", hits)
	}
	far, _ := embedText(ctx, "Your OTP for login to SBI net banking is 482910. Do not share it with anyone.")
	if hs := s.match(far, tag, 3); len(hs) != 0 {
		t.Fatalf("genuine bank OTP SMS matched a pattern: %+v", hs)
	}
	t.Logf("census sim %.3f", hits[0].sim)
}

func TestLiveLearnsANewScamFromThreeReporters(t *testing.T) {
	live(t)
	old := community
	community = newCommunityStore(true)
	t.Cleanup(func() { community = old })
	ctx := context.Background()
	reports := []string{
		"Got a WhatsApp from 'Jio Rewards': my 4000 loyalty points expire tonight, open the link and enter the OTP to convert them into a 2000 rupee recharge.",
		"SMS says Airtel thanks points worth Rs 3500 will expire today, redeem by clicking the link and typing the code you receive.",
		"Someone messaged that my mobile operator reward points are expiring at midnight and I must redeem on their site with the OTP sent to me",
	}
	var last LearnResult
	for i, r := range reports {
		ip := "203.0." + string(rune('1'+i)) + ".9"
		last = community.learn(ctx, reportInput{Text: r, Lang: "en-IN"}, reporterKey("live-device-"+string(rune('a'+i)), ip), networkKey(ip))
		if !last.Accepted || last.Extraction != "gemini" {
			t.Fatalf("report %d not learned with Gemini: %+v", i, last)
		}
		t.Logf("report %d -> %s (%s) reporters=%d promoted=%v: %s", i, last.Pattern.ID, last.Pattern.Status, last.Pattern.Reporters, last.Promoted, last.Message)
	}
	if !last.Promoted || last.Pattern.Status != "active" || last.Pattern.HowItWorks == "" {
		t.Fatalf("not promoted: %+v", last.Pattern)
	}
	p := community.get(last.Pattern.ID)
	if p.HowHi == "" || strings.Contains(p.How, "http") {
		t.Fatalf("card: %+v", p)
	}
	t.Logf("card: %s | %s | %s | hi: %s", p.Title, p.How, p.Warning, p.TitleHi)
	j := startCommunityMatch(ctx, "Your Vi reward points worth 2500 expire today. Redeem now at the link and share the OTP to get free recharge.")
	if sigs := j.signals(ctx, nil); len(sigs) != 1 {
		t.Fatalf("next person not protected: %+v", j.hits)
	}
}

func TestLiveCheckUsesCommunity(t *testing.T) {
	live(t)
	old := community
	community = newCommunityStore(true)
	t.Cleanup(func() { community = old })
	t.Setenv("APP_USER", "")
	t.Setenv("APP_PASSWORD_HASH", "")
	resp := analyze(context.Background(), "SMS: Dear citizen, your household is not yet counted in Census 2027. Complete self enumeration today at the link or your family's ration benefits will be stopped.", nil, nil, "manual", "auto", "")
	if resp.Degraded || len(resp.Community) == 0 || resp.Community[0].ID != "cp-census" {
		t.Fatalf("degraded=%v community=%+v", resp.Degraded, resp.Community)
	}
	t.Logf("verdict=%s score=%d latency=%dms category=%v summary=%s", resp.Verdict, resp.Score, resp.LatencyMs, resp.Category, resp.Summary)
}

func TestLiveRejectsNonScamReport(t *testing.T) {
	live(t)
	old := community
	community = newCommunityStore(true)
	t.Cleanup(func() { community = old })
	res := community.learn(context.Background(), reportInput{Text: "Hi beta, dinner at 8 tonight, bring curd on the way home.", Lang: "en-IN"}, "live-x", "live-net")
	if res.Accepted {
		t.Fatalf("family message accepted as scam: %+v", res)
	}
}
