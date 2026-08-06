package clash

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
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

func TestParseClashXHTTPOptions(t *testing.T) {
	outbounds, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: xhttp
    type: vless
    server: xhttp.example
    port: 443
    uuid: uuid
    network: xhttp
    xhttp-opts:
      host: cdn.example
      path: /xhttp
      mode: stream-one
      no-grpc-header: true
      x-padding-bytes: 200-400
      x-padding-obfs-mode: true
      x-padding-key: pad
      x-padding-header: Referer
      x-padding-placement: header
      x-padding-method: tokenish
      uplink-http-method: PUT
      session-placement: cookie
      session-key: sid
      seq-placement: header
      seq-key: seq
      session-length: 8-16
      sc-max-each-post-bytes: 1000
      reuse-settings:
        max-concurrency: 2-4
        h-keep-alive-period: 12
`)
	if err != nil {
		t.Fatal(err)
	}
	transport := outbounds[0].Options.(*option.VLESSOutboundOptions).Transport
	if transport == nil || transport.Type != C.V2RayTransportTypeXHTTP {
		t.Fatalf("transport = %#v, want xhttp", transport)
	}
	xhttp := transport.XHTTPOptions
	if xhttp.Host != "cdn.example" || xhttp.Path != "/xhttp" || xhttp.Mode != "stream-one" ||
		!xhttp.NoGRPCHeader || xhttp.XPaddingBytes.From != 200 || !xhttp.XPaddingObfsMode ||
		xhttp.XPaddingKey != "pad" || xhttp.XPaddingHeader != "Referer" || xhttp.UplinkHTTPMethod != "PUT" ||
		xhttp.SessionPlacement != "cookie" || xhttp.SessionKey != "sid" || xhttp.SeqPlacement != "header" ||
		xhttp.SeqKey != "seq" || xhttp.SessionIDLength.From != 8 || xhttp.Xmux == nil ||
		xhttp.Xmux.MaxConcurrency.From != 2 || xhttp.Xmux.HKeepAlivePeriod != 12 {
		t.Fatalf("XHTTP options were lost: %#v", xhttp)
	}
}
