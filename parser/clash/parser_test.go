package clash

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseClashSubscriptionKeepsOnlyValidLeafChains(t *testing.T) {
	outbounds, err := ParseClashSubscription(context.Background(), `
proxies:
  - { name: hop, type: socks5, server: 127.0.0.1, port: 1080 }
  - { name: chained, type: socks5, server: 127.0.0.1, port: 1081, dialer-proxy: hop }
  - { name: through-group, type: socks5, server: 127.0.0.1, port: 1082, dialer-proxy: automatic }
  - { name: through-invalid, type: socks5, server: 127.0.0.1, port: 1083, dialer-proxy: through-group }
  - { name: external, type: socks5, server: 127.0.0.1, port: 1084, dialer-proxy: global-egress }
`)
	if err != nil {
		t.Fatal(err)
	}
	wantTags := []string{"hop", "chained"}
	if len(outbounds) != len(wantTags) {
		t.Fatalf("got %d outbounds, want %d: %#v", len(outbounds), len(wantTags), outbounds)
	}
	for index, wantTag := range wantTags {
		if outbounds[index].Tag != wantTag {
			t.Fatalf("outbound[%d] tag = %q, want %q", index, outbounds[index].Tag, wantTag)
		}
	}
	if detour := outbounds[1].Options.(*option.SOCKSOutboundOptions).Detour; detour != "hop" {
		t.Fatalf("leaf detour = %q, want hop", detour)
	}
}
