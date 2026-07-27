package clashapi

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

type testSubscriptionProvider struct {
	adapter.Provider
}

func (p *testSubscriptionProvider) Type() string                  { return C.ProviderTypeRemote }
func (p *testSubscriptionProvider) Tag() string                   { return "subscription" }
func (p *testSubscriptionProvider) Outbounds() []adapter.Outbound { return nil }
func (p *testSubscriptionProvider) UpdatedAt() time.Time          { return time.Unix(1, 0) }
func (p *testSubscriptionProvider) SubscriptionInfo() adapter.SubscriptionInfo {
	return adapter.SubscriptionInfo{Upload: 1, Total: 10}
}
func (p *testSubscriptionProvider) SubscriptionMetadata() adapter.SubscriptionMetadata {
	return adapter.SubscriptionMetadata{Title: "Example", SupportURL: "https://example.com/support"}
}

func TestProviderInfoIncludesSubscriptionMetadata(t *testing.T) {
	content, err := json.Marshal(providerInfo(&Server{}, &testSubscriptionProvider{}))
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		SubscriptionMetadata adapter.SubscriptionMetadata `json:"subscriptionMetadata"`
	}
	if err = json.Unmarshal(content, &response); err != nil {
		t.Fatal(err)
	}
	if response.SubscriptionMetadata.Title != "Example" || response.SubscriptionMetadata.SupportURL != "https://example.com/support" {
		t.Fatalf("subscription metadata missing from provider API: %s", content)
	}
}
