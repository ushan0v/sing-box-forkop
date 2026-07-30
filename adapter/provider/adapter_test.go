package provider

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func TestNormalizeOutboundsForFilter(t *testing.T) {
	provider := &Adapter{removeEmojis: true, tagPrefix: "Prefix "}
	normalized := provider.NormalizeOutboundsForFilter([]option.Outbound{
		{Tag: "🇺🇸 Node"},
		{Tag: "🇺🇸 Node"},
	})
	var tags []string
	for _, outbound := range normalized {
		tags = append(tags, outbound.Tag)
	}
	if expected := []string{"US Node", "US Node #2"}; !reflect.DeepEqual(tags, expected) {
		t.Fatalf("unexpected filter tags: %v", tags)
	}
}

type linkTestOutbound struct {
	adapter.Outbound
	outboundAdapter.Adapter
}

func (o *linkTestOutbound) Type() string           { return o.Adapter.Type() }
func (o *linkTestOutbound) Tag() string            { return o.Adapter.Tag() }
func (o *linkTestOutbound) Network() []string      { return o.Adapter.Network() }
func (o *linkTestOutbound) Dependencies() []string { return o.Adapter.Dependencies() }

type linkTestOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *linkTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

type filteringTestOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *filteringTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

func (m *filteringTestOutboundManager) Started() bool {
	return true
}

func (m *filteringTestOutboundManager) SwapBatch(expectedOld map[string]adapter.Outbound, candidates []adapter.Outbound) (map[string]adapter.Outbound, error) {
	old := make(map[string]adapter.Outbound, len(expectedOld))
	for tag, expected := range expectedOld {
		if m.outbounds[tag] != expected {
			return nil, errors.New("unexpected old outbound")
		}
		old[tag] = expected
		delete(m.outbounds, tag)
	}
	for _, candidate := range candidates {
		m.outbounds[candidate.Tag()] = candidate
	}
	return old, nil
}

func TestProviderSkipsInvalidOutboundsAndKeepsAtomicFallback(t *testing.T) {
	registry := outboundAdapter.NewRegistry()
	outboundAdapter.Register[option.VLESSOutboundOptions](registry, "valid", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.VLESSOutboundOptions) (adapter.Outbound, error) {
		return &linkTestOutbound{Adapter: outboundAdapter.NewAdapter("valid", tag, nil, nil)}, nil
	})
	outboundAdapter.Register[option.VLESSOutboundOptions](registry, "invalid", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, _ string, _ option.VLESSOutboundOptions) (adapter.Outbound, error) {
		return nil, errors.New("invalid test outbound")
	})
	ctx := service.ContextWith[adapter.OutboundRegistry](context.Background(), registry)
	manager := &filteringTestOutboundManager{outbounds: make(map[string]adapter.Outbound)}
	logFactory := log.NewNOPFactory()
	provider := &Adapter{
		ctx:         ctx,
		outbound:    manager,
		logFactory:  logFactory,
		logger:      logFactory.NewLogger("test"),
		providerTag: "subscription",
	}
	applied, err := provider.UpdateOutbounds([]option.Outbound{
		{Type: "valid", Tag: "working", Options: &option.VLESSOutboundOptions{}},
		{Type: "invalid", Tag: "broken", Options: &option.VLESSOutboundOptions{}},
		{Type: "valid", Tag: "dependent", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "broken"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0].Tag != "working" || len(provider.Outbounds()) != 1 {
		t.Fatalf("invalid provider nodes were not isolated: applied=%v runtime=%v", applied, provider.Outbounds())
	}
	working := provider.Outbounds()[0]
	if _, err = provider.UpdateOutbounds([]option.Outbound{
		{Type: "invalid", Tag: "broken", Options: &option.VLESSOutboundOptions{}},
	}); err == nil {
		t.Fatal("provider with no usable outbounds must fail")
	}
	if current, loaded := manager.Outbound(working.Tag()); !loaded || current != working {
		t.Fatal("failed provider refresh replaced the last working state")
	}
}

func TestFlagToCountryCodeAllFlags(t *testing.T) {
	for first := 'A'; first <= 'Z'; first++ {
		for second := 'A'; second <= 'Z'; second++ {
			flag := string(rune(0x1F1E6+(first-'A'))) + string(rune(0x1F1E6+(second-'A')))
			expected := string(first) + string(second)
			result := flagToCountryCode(flag)
			// flagToCountryCode appends a space
			if result != expected+" " {
				t.Errorf("flagToCountryCode(%q) = %q, want %q", expected, result, expected+" ")
			}
		}
	}
}

func TestRemoveEmojisFromTags(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"🇺🇸 United States", "US United States"},
		{"🇷🇺 Россия", "RU Россия"},
		{"🇩🇪 Germany 🚀", "DE Germany"},
		{"🇫🇷🇬🇧 France-UK", "FR GB France-UK"},
		{"No emojis here", "No emojis here"},
		{"🌍 World", "World"},
		{"🇯🇵 Tokyo ⚡ Fast", "JP Tokyo Fast"},
		{"Germany 🇩🇪", "Germany DE"},
		{"Server 🇺🇸 Node", "Server US Node"},
	}
	for _, tt := range tests {
		actual := cleanOutboundTag(tt.input)
		if actual != tt.expected {
			t.Errorf("cleanOutboundTag(%q) = %q, want %q", tt.input, actual, tt.expected)
		}
	}
}

func TestProviderPublishesOnlyGeneratedOutboundLinks(t *testing.T) {
	runtimeOutbound := &linkTestOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, "subscription/node", nil, nil)}
	provider := &Adapter{outbound: &linkTestOutboundManager{outbounds: map[string]adapter.Outbound{
		runtimeOutbound.Tag(): runtimeOutbound,
	}}}
	prepared := []preparedOutbound{
		{
			tag: "subscription/node",
			source: option.Outbound{
				Type: C.TypeVLESS,
				Tag:  "node",
				Options: &option.VLESSOutboundOptions{
					ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
					UUID:          "00000000-0000-4000-8000-000000000001",
				},
			},
		},
	}
	if err := provider.publishOutbounds(prepared); err != nil {
		t.Fatal(err)
	}
	link, loaded := provider.OutboundLink(runtimeOutbound.Tag())
	if !loaded || link != "vless://00000000-0000-4000-8000-000000000001@example.com:443?security=none&type=tcp#node" {
		t.Fatalf("unexpected provider outbound link: loaded=%v link=%q", loaded, link)
	}
	if _, loaded = provider.OutboundLink("subscription/missing"); loaded {
		t.Fatal("unexpected link for missing provider outbound")
	}

	unsupported := &linkTestOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeSSH, "subscription/ssh", nil, nil)}
	provider.outbound.(*linkTestOutboundManager).outbounds[unsupported.Tag()] = unsupported
	if err := provider.publishOutbounds([]preparedOutbound{{
		tag: unsupported.Tag(), source: option.Outbound{Type: C.TypeSSH, Tag: "ssh", Options: &option.SSHOutboundOptions{}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, loaded = provider.OutboundLink(unsupported.Tag()); loaded {
		t.Fatal("unsupported outbound must not expose a lossy link")
	}
	if _, loaded = provider.OutboundLink(runtimeOutbound.Tag()); loaded {
		t.Fatal("removed outbound link survived provider refresh")
	}
}
