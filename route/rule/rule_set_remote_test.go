package rule

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type missingDetourOutboundManager struct {
	adapter.OutboundManager
	defaultCalls int
}

func (m *missingDetourOutboundManager) Outbound(string) (adapter.Outbound, bool) { return nil, false }
func (m *missingDetourOutboundManager) Default() adapter.Outbound {
	m.defaultCalls++
	return nil
}

type recordingDetour struct {
	adapter.Outbound
	dialCalls int
}

func (d *recordingDetour) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dialCalls++
	return new(net.Dialer).DialContext(ctx, network, destination.String())
}

type recordingDetourOutboundManager struct {
	adapter.OutboundManager
	detour       adapter.Outbound
	defaultCalls int
}

func (m *recordingDetourOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.detour, tag == "proxy"
}

func (m *recordingDetourOutboundManager) Default() adapter.Outbound {
	m.defaultCalls++
	return nil
}

func TestRemoteRuleSetMissingDetourDoesNotFallbackOrFailStartup(t *testing.T) {
	manager := new(missingDetourOutboundManager)
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	ruleSet := NewRemoteRuleSet(ctx, logger.NOP(), option.RuleSet{
		Type:   C.RuleSetTypeRemote,
		Tag:    "missing-detour",
		Format: C.RuleSetFormatAuto,
		RemoteOptions: option.RemoteRuleSet{
			URL:            "https://example.com/rules",
			DownloadDetour: "proxy",
		},
	})
	if err := ruleSet.StartContext(ctx, nil); err != nil {
		t.Fatal(err)
	}
	defer ruleSet.Close()
	if manager.defaultCalls != 0 {
		t.Fatal("missing download detour fell back to the default outbound")
	}
	if ruleSet.updateTicker == nil {
		t.Fatal("remote rule-set did not schedule retries")
	}
}

func TestRemoteAutoRuleSetUsesConfiguredDetour(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "payload:\n  - example.com\n  - 192.0.2.0/24\n")
	}))
	defer server.Close()

	detour := new(recordingDetour)
	manager := &recordingDetourOutboundManager{detour: detour}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	startContext := adapter.NewHTTPStartContext(ctx)
	defer startContext.Close()
	ruleSet := NewRemoteRuleSet(ctx, logger.NOP(), option.RuleSet{
		Type:   C.RuleSetTypeRemote,
		Tag:    "detoured-auto",
		Format: C.RuleSetFormatAuto,
		RemoteOptions: option.RemoteRuleSet{
			URL:            server.URL,
			DownloadDetour: "proxy",
		},
	})
	if err := ruleSet.StartContext(ctx, startContext); err != nil {
		t.Fatal(err)
	}
	defer ruleSet.Close()
	if detour.dialCalls == 0 || manager.defaultCalls != 0 || ruleSet.revision != 1 {
		t.Fatalf("unexpected detour fetch: dial=%d default=%d revision=%d", detour.dialCalls, manager.defaultCalls, ruleSet.revision)
	}
	snapshot := ruleSet.ProviderSnapshot()
	if len(snapshot.IPCIDR.IPv4) != 1 || snapshot.IPCIDR.IPv4[0] != "192.0.2.0/24" {
		t.Fatalf("unexpected YAML CIDR export: %v", snapshot.IPCIDR.IPv4)
	}
}

func TestRemoteRuleSetHTTPFailureDoesNotFailStartup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	manager := &recordingDetourOutboundManager{detour: new(recordingDetour)}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	ruleSet := NewRemoteRuleSet(ctx, logger.NOP(), option.RuleSet{
		Type:   C.RuleSetTypeRemote,
		Tag:    "unavailable",
		Format: C.RuleSetFormatAuto,
		RemoteOptions: option.RemoteRuleSet{
			URL:            server.URL,
			DownloadDetour: "proxy",
		},
	})
	if err := ruleSet.StartContext(ctx, nil); err != nil {
		t.Fatal(err)
	}
	defer ruleSet.Close()
	if ruleSet.revision != 0 || ruleSet.updateTicker == nil {
		t.Fatal("unavailable remote rule-set became active or did not schedule retries")
	}
}

func TestRemoteRuleSetMalformedDownloadFailsStartup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "payload:\n  - 42\n")
	}))
	defer server.Close()
	manager := &recordingDetourOutboundManager{detour: new(recordingDetour)}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	ruleSet := NewRemoteRuleSet(ctx, logger.NOP(), option.RuleSet{
		Type:   C.RuleSetTypeRemote,
		Tag:    "malformed",
		Format: C.RuleSetFormatAuto,
		RemoteOptions: option.RemoteRuleSet{
			URL:            server.URL,
			DownloadDetour: "proxy",
		},
	})
	defer ruleSet.Close()
	if err := ruleSet.StartContext(ctx, nil); err == nil {
		t.Fatal("malformed downloaded rule-set did not fail startup")
	}
}

func TestRemoteRuleSetKeepsLastValidRulesOnParseFailure(t *testing.T) {
	ruleSet := &RemoteRuleSet{
		ctx: context.Background(),
		options: option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "preserve",
			Format: C.RuleSetFormatAuto,
		},
	}
	if err := ruleSet.loadBytes([]byte("payload:\n  - example.com\n"), time.Now(), "valid"); err != nil {
		t.Fatal(err)
	}
	if err := ruleSet.loadBytes([]byte("payload:\n  - 42\n"), time.Now(), "invalid"); err == nil {
		t.Fatal("expected invalid refresh to fail")
	}
	if ruleSet.revision != 1 || ruleSet.lastEtag != "valid" || len(ruleSet.rules) == 0 {
		t.Fatal("invalid refresh replaced the last valid rule-set")
	}
}
