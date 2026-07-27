package outbound

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type testOutbound struct{ Adapter }

func (t *testOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, nil
}

func (t *testOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

func TestRemoveKeepsDependedOutbound(t *testing.T) {
	detour := &testOutbound{NewAdapter("test", "detour", nil, nil)}
	manager := &Manager{
		outbounds:     []adapter.Outbound{detour},
		outboundByTag: map[string]adapter.Outbound{"detour": detour},
		dependByTag:   map[string][]string{"detour": {"dependent"}},
	}

	if err := manager.Remove("detour"); err == nil {
		t.Fatal("expected removal to fail while an outbound depends on detour")
	}
	if current, loaded := manager.Outbound("detour"); !loaded || current != detour || len(manager.Outbounds()) != 1 {
		t.Fatal("failed removal must leave the outbound registered")
	}
}

func TestSwapBatchReplacesDependencyGraph(t *testing.T) {
	oldLeaf := &testOutbound{NewAdapter("test", "leaf", nil, nil)}
	oldGroup := &testOutbound{NewAdapter("test", "group", nil, []string{"leaf"})}
	newLeaf := &testOutbound{NewAdapter("test", "leaf", nil, nil)}
	newGroup := &testOutbound{NewAdapter("test", "group", nil, []string{"leaf"})}
	manager := &Manager{
		outbounds:       []adapter.Outbound{oldLeaf, oldGroup},
		outboundByTag:   map[string]adapter.Outbound{"leaf": oldLeaf, "group": oldGroup},
		dependByTag:     map[string][]string{"leaf": {"group"}},
		defaultOutbound: oldGroup,
	}

	old, err := manager.SwapBatch(map[string]adapter.Outbound{"group": oldGroup, "leaf": oldLeaf}, []adapter.Outbound{newLeaf, newGroup})
	if err != nil {
		t.Fatal(err)
	}
	if old["leaf"] != oldLeaf || old["group"] != oldGroup {
		t.Fatal("swap did not return replaced outbounds")
	}
	if current, _ := manager.Outbound("leaf"); current != newLeaf {
		t.Fatal("leaf was not swapped")
	}
	if current, _ := manager.Outbound("group"); current != newGroup || manager.Default() != newGroup {
		t.Fatal("dependent group was not swapped")
	}
	if len(manager.dependByTag["leaf"]) != 1 || manager.dependByTag["leaf"][0] != "group" {
		t.Fatalf("unexpected dependency index: %v", manager.dependByTag)
	}
}

func TestSwapBatchRejectsExternalDependent(t *testing.T) {
	oldLeaf := &testOutbound{NewAdapter("test", "leaf", nil, nil)}
	external := &testOutbound{NewAdapter("test", "external", nil, []string{"leaf"})}
	newLeaf := &testOutbound{NewAdapter("test", "leaf", nil, nil)}
	manager := &Manager{
		outbounds:     []adapter.Outbound{oldLeaf, external},
		outboundByTag: map[string]adapter.Outbound{"leaf": oldLeaf, "external": external},
		dependByTag:   map[string][]string{"leaf": {"external"}},
	}

	if _, err := manager.SwapBatch(map[string]adapter.Outbound{"leaf": oldLeaf}, []adapter.Outbound{newLeaf}); err == nil {
		t.Fatal("expected external dependency to reject batch swap")
	}
	if current, _ := manager.Outbound("leaf"); current != oldLeaf {
		t.Fatal("rejected batch swap changed live state")
	}
}
