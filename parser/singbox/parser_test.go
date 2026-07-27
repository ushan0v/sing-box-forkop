package singbox_test

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/singbox"
)

func TestParseBoxSubscriptionKeepsOnlyValidLeaves(t *testing.T) {
	ctx := include.Context(context.Background())
	outbounds, err := singbox.ParseBoxSubscription(ctx, `{
  "outbounds": [
    null,
    1,
    {},
    {"type": 1},
    {"type": "unknown", "tag": "unknown"},
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"},
    {"type": "dns", "tag": "dns"},
    {"type": "socks", "tag": "broken", "server": "127.0.0.1", "server_port": 65536},
    {"type": "socks", "tag": "leaf", "server": "127.0.0.1", "server_port": 1080},
    {"type": "socks", "tag": "hop", "server": "127.0.0.1", "server_port": 1081},
    {"type": "socks", "tag": "chained", "server": "127.0.0.1", "server_port": 1082, "detour": "hop"},
    {"type": "socks", "tag": "through-group", "server": "127.0.0.1", "server_port": 1083, "detour": "selector"},
    {"type": "socks", "tag": "through-invalid", "server": "127.0.0.1", "server_port": 1084, "detour": "broken"},
    {"type": "socks", "tag": "external", "server": "127.0.0.1", "server_port": 1085, "detour": "global-egress"},
    {"type": "selector", "tag": "selector", "outbounds": ["leaf"]},
    {"type": "urltest", "tag": "urltest", "outbounds": ["leaf"]},
    {"type": "fallback", "tag": "fallback", "outbounds": ["leaf"]}
  ]
}`)
	if err != nil {
		t.Fatal(err)
	}
	wantTags := []string{"leaf", "hop", "chained", "external"}
	if len(outbounds) != len(wantTags) {
		t.Fatalf("got %d outbounds, want %d: %#v", len(outbounds), len(wantTags), outbounds)
	}
	for index, wantTag := range wantTags {
		if outbounds[index].Type != C.TypeSOCKS || outbounds[index].Tag != wantTag {
			t.Errorf("outbound[%d] = %s/%s, want socks/%s", index, outbounds[index].Type, outbounds[index].Tag, wantTag)
		}
	}
	if detour := outbounds[2].Options.(*option.SOCKSOutboundOptions).Detour; detour != "hop" {
		t.Fatalf("leaf detour = %q, want hop", detour)
	}
	if detour := outbounds[3].Options.(*option.SOCKSOutboundOptions).Detour; detour != "global-egress" {
		t.Fatalf("external detour = %q, want global-egress", detour)
	}
}

func TestParseBoxSubscriptionRejectsDocumentsWithoutLeaves(t *testing.T) {
	ctx := include.Context(context.Background())
	for name, content := range map[string]string{
		"missing outbounds":    `{}`,
		"wrong outbounds type": `{"outbounds": {}}`,
		"only invalid entries": `{"outbounds": [null, {}, {"type": 1}, {"type": "unknown"}]}`,
		"only groups":          `{"outbounds": [{"type": "selector", "tag": "group", "outbounds": ["missing"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if outbounds, err := singbox.ParseBoxSubscription(ctx, content); err == nil || len(outbounds) != 0 {
				t.Fatalf("got (%v, %v), want no outbounds and an error", outbounds, err)
			}
		})
	}
}
