package provider

import (
	"net/http"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestPrepareSubscriptionContentMetadata(t *testing.T) {
	body := strings.Join([]string{
		"# profile-title: base64:Qm9keSB0aXRsZQ==",
		"// subscription-userinfo: upload=1; download=2; total=10; expire=20",
		"# support-url: javascript:alert(1)",
		"# announce: base64:TWFpbnRlbmFuY2UKc29vbg==",
		"# announce-url: https://example.com/news",
		"# subscription-refill-date: 30",
		`# content-disposition: attachment; filename="../nodes.txt"`,
		"vless://uuid@example.com:443#node",
	}, "\n")
	headers := http.Header{
		"Profile-Title":         []string{"Header title"},
		"Subscription-Userinfo": []string{"upload=7; total=100"},
		"Profile-Web-Page-Url":  []string{"https://example.com/account"},
	}

	content, info, metadata := prepareSubscriptionContent(body, metadataHeaderValues(headers))
	if content != "vless://uuid@example.com:443#node" {
		t.Fatalf("metadata preamble was not removed: %q", content)
	}
	if info.Upload != 7 || info.Download != 0 || info.Total != 100 || info.Expire != 0 {
		t.Fatalf("header did not override body userinfo: %+v", info)
	}
	if metadata.Title != "Header title" || metadata.WebPageURL != "https://example.com/account" {
		t.Fatalf("unexpected profile metadata: %+v", metadata)
	}
	if metadata.SupportURL != "" || metadata.Announce != "Maintenance soon" || metadata.AnnounceURL != "https://example.com/news" {
		t.Fatalf("metadata was not safely normalized: %+v", metadata)
	}
	if metadata.RefillDate != 30 || metadata.FileName != ".._nodes.txt" {
		t.Fatalf("unexpected refill or filename metadata: %+v", metadata)
	}
}

func TestProviderCacheMetadataRoundTripAndLegacy(t *testing.T) {
	source := "https://example.com/subscription?token=secret"
	info := adapter.SubscriptionInfo{Upload: 1, Download: 2, Total: 3, Expire: 4}
	metadata := adapter.SubscriptionMetadata{Title: "Example", SupportURL: "https://example.com/support"}
	content := encodeProviderCacheMetadata(source, info, metadata) + "\n" + `{"outbounds":[]}`
	decodedContent, sourceHash, decodedInfo, decodedMetadata := decodeProviderCacheContent(content)
	if decodedContent != `{"outbounds":[]}` || sourceHash != providerCacheSourceHash(source) || decodedInfo != info || decodedMetadata != metadata {
		t.Fatalf("cache metadata did not round-trip: content=%q source=%q info=%+v metadata=%+v", decodedContent, sourceHash, decodedInfo, decodedMetadata)
	}
	if sourceHash == providerCacheSourceHash("https://example.com/other") {
		t.Fatal("cache source hash matched a different provider URL")
	}
	for _, testCase := range []struct {
		name       string
		sourceHash string
		restore    bool
		current    bool
	}{
		{"legacy", "", true, false},
		{"current", sourceHash, true, true},
		{"replaced", providerCacheSourceHash("https://example.com/other"), false, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			restore, current := providerCacheSourceState(testCase.sourceHash, source)
			if restore != testCase.restore || current != testCase.current {
				t.Fatalf("unexpected cache source state: restore=%v current=%v", restore, current)
			}
		})
	}

	legacyContent, legacySourceHash, legacyInfo, legacyMetadata := decodeProviderCacheContent("upload=9; total=10\n" + `{"outbounds":[]}`)
	if legacyContent != `{"outbounds":[]}` || legacySourceHash != "" || legacyInfo.Upload != 9 || legacyInfo.Total != 10 || legacyMetadata != (adapter.SubscriptionMetadata{}) {
		t.Fatalf("legacy provider cache was not restored: content=%q source=%q info=%+v metadata=%+v", legacyContent, legacySourceHash, legacyInfo, legacyMetadata)
	}

	invalidContent, _, _, _ := decodeProviderCacheContent(providerCacheMetadataPrefix + "invalid\n" + `{"outbounds":[]}`)
	if invalidContent != `{"outbounds":[]}` {
		t.Fatalf("invalid cache metadata blocked outbound restore: %q", invalidContent)
	}
}

func TestMergeSubscriptionHeadersPreservesUnspecifiedCacheMetadata(t *testing.T) {
	info := adapter.SubscriptionInfo{Upload: 1, Total: 10}
	metadata := adapter.SubscriptionMetadata{Title: "Old", SupportURL: "https://example.com/support"}
	info, metadata = mergeSubscriptionData(info, metadata, map[string]string{"profile-title": "New"})
	if info.Upload != 1 || info.Total != 10 || metadata.Title != "New" || metadata.SupportURL != "https://example.com/support" {
		t.Fatalf("partial 304 metadata replaced cached values: info=%+v metadata=%+v", info, metadata)
	}
}
