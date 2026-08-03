package group

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

type testSelectorOutbound struct {
	outboundAdapter.Adapter
	dialCount int
}

type blockingURLTestOutbound struct {
	outboundAdapter.Adapter
	started chan struct{}
	once    sync.Once
}

func (t *blockingURLTestOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	t.once.Do(func() { close(t.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (t *blockingURLTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

func (t *testSelectorOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	t.dialCount++
	return nil, errors.New("test outbound dialed")
}

func (t *testSelectorOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

type testOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *testOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

type testProvider struct {
	adapter.Provider
	tag       string
	outbounds []adapter.Outbound
}

func (p *testProvider) Tag() string { return p.tag }

func (p *testProvider) Outbounds() []adapter.Outbound {
	return append([]adapter.Outbound(nil), p.outbounds...)
}

func newTestOutbound(tag string) *testSelectorOutbound {
	return &testSelectorOutbound{Adapter: outboundAdapter.NewAdapter("test", tag, []string{"tcp", "udp"}, nil)}
}

func TestProviderOutboundFilterTag(t *testing.T) {
	if actual := providerOutboundFilterTag("subscription", "subscription/Node #2"); actual != "Node #2" {
		t.Fatalf("unexpected provider-local filter tag: %q", actual)
	}
}

func TestProviderGroupsFailClosedAndRecover(t *testing.T) {
	compatible := newTestOutbound("Compatible")
	node := newTestOutbound("provider/node")
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{
		compatible.Tag(): compatible,
		node.Tag():       node,
	}}
	provider := &testProvider{tag: "provider"}

	selector := &Selector{
		Adapter:        outboundAdapter.NewAdapter(C.TypeSelector, "selector", []string{"tcp", "udp"}, nil),
		ctx:            context.Background(),
		outbound:       manager,
		outbounds:      make(map[string]adapter.Outbound),
		interruptGroup: interrupt.NewGroup(),
		providers:      map[string]adapter.Provider{provider.Tag(): provider},
		providerTags:   []string{provider.Tag()},
	}
	if err := selector.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if len(selector.All()) != 0 || selector.Now() != "" {
		t.Fatalf("empty selector unexpectedly selected %q from %v", selector.Now(), selector.All())
	}
	if _, err := selector.DialContext(context.Background(), "tcp", M.Socksaddr{}); err == nil {
		t.Fatal("empty selector dial succeeded")
	}

	nopLogger := log.NewNOPFactory().NewLogger("test")
	urlTestGroup, err := NewURLTestGroup(context.Background(), manager, nopLogger, nil, "", 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	urlTest := &URLTest{
		Adapter:        outboundAdapter.NewAdapter(C.TypeURLTest, "urltest", []string{"tcp", "udp"}, nil),
		ctx:            context.Background(),
		outbound:       manager,
		logger:         nopLogger,
		group:          urlTestGroup,
		providers:      map[string]adapter.Provider{provider.Tag(): provider},
		outboundsCache: make(map[string][]adapter.Outbound),
		providerTags:   []string{provider.Tag()},
	}
	if err := urlTest.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if len(urlTest.All()) != 0 {
		t.Fatalf("empty urltest unexpectedly contains %v", urlTest.All())
	}
	if _, err := urlTest.DialContext(context.Background(), "tcp", M.Socksaddr{}); err == nil {
		t.Fatal("empty urltest dial succeeded")
	}
	if compatible.dialCount != 0 {
		t.Fatalf("empty provider groups dialed Compatible %d times", compatible.dialCount)
	}

	provider.outbounds = []adapter.Outbound{node}
	if err := selector.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if selector.Now() != node.Tag() || len(selector.All()) != 1 {
		t.Fatalf("selector did not recover after provider refresh: now=%q all=%v", selector.Now(), selector.All())
	}
	if err := urlTest.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if all := urlTest.All(); len(all) != 1 || all[0] != node.Tag() {
		t.Fatalf("urltest did not recover after provider refresh: %v", all)
	}
}

func TestURLTestProviderRefreshDoesNotWaitForHealthChecks(t *testing.T) {
	nodeA := &blockingURLTestOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "provider/node-a", []string{"tcp", "udp"}, nil),
		started: make(chan struct{}),
	}
	nodeB := &blockingURLTestOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "provider/node-b", []string{"tcp", "udp"}, nil),
		started: make(chan struct{}),
	}
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{
		nodeA.Tag(): nodeA,
		nodeB.Tag(): nodeB,
	}}
	provider := &testProvider{tag: "provider", outbounds: []adapter.Outbound{nodeA}}
	nopLogger := log.NewNOPFactory().NewLogger("test")
	urlTestGroup, err := NewURLTestGroup(context.Background(), manager, nopLogger, nil, "http://example.com", 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	urlTestGroup.history.StoreURLTestHistory(nodeA.Tag(), &adapter.URLTestHistory{
		Time:  time.Now(),
		Delay: 1,
	})
	urlTest := &URLTest{
		Adapter:        outboundAdapter.NewAdapter(C.TypeURLTest, "urltest", []string{"tcp", "udp"}, nil),
		ctx:            context.Background(),
		outbound:       manager,
		logger:         nopLogger,
		group:          urlTestGroup,
		providers:      map[string]adapter.Provider{provider.Tag(): provider},
		outboundsCache: make(map[string][]adapter.Outbound),
		providerTags:   []string{provider.Tag()},
	}

	done := make(chan error, 1)
	go func() { done <- urlTest.onProviderUpdated(provider.Tag()) }()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("provider refresh waited for URL tests")
	}
	select {
	case <-nodeA.started:
	case <-time.After(time.Second):
		t.Fatal("provider refresh did not start URL tests")
	}

	provider.outbounds = []adapter.Outbound{nodeB}
	if err = urlTest.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-nodeB.started:
	case <-time.After(time.Second):
		t.Fatal("new provider refresh was lost while a previous URL test was running")
	}
	urlTest.cancel()
}
