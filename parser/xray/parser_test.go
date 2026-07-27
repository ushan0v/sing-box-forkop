package xray

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestParseXraySubscriptionKeepsAllLeafDetoursAndMKCP(t *testing.T) {
	outbounds, err := ParseXraySubscription(context.Background(), `[
  {"outbounds":[{"protocol":7}]},
  {
    "outbounds":[
      null,
      {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"one.example","port":"443","users":[{"id":"uuid-a"}]}]}},
      {"protocol":"unsupported","tag":"ignored"}
    ]
  },
  {
    "outbounds":[
      {"protocol":"socks","tag":"hop","settings":{"servers":[{"address":"127.0.0.1","port":1080,"users":[{"user":"same","pass":"same"}]}]}},
      {
        "protocol":"vless",
        "tag":"edge-1",
        "settings":{"vnext":[{"address":"two.example","port":443,"users":[{"id":"uuid-b"}]}]},
        "proxySettings":{"tag":"hop","transportLayer":true},
        "streamSettings":{"network":"kcp","kcpSettings":{"header":{"type":"wechat-video"},"seed":"secret"}}
      },
      {"protocol":17}
    ]
  }
]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(outbounds) != 3 {
		t.Fatalf("got %d leaf outbounds, want 3: %#v", len(outbounds), outbounds)
	}
	byTag := make(map[string]option.Outbound, len(outbounds))
	for _, outbound := range outbounds {
		byTag[outbound.Tag] = outbound
		if outbound.Type == C.TypeSelector || outbound.Type == C.TypeURLTest || outbound.Type == C.TypeFallback {
			t.Fatalf("provider parser returned group %q", outbound.Tag)
		}
	}
	if byTag["proxy"].Type != C.TypeVLESS {
		t.Fatalf("proxy leaf missing: %#v", byTag)
	}
	hopOptions := byTag["hop"].Options.(*option.SOCKSOutboundOptions)
	if hopOptions.Username != "same" || hopOptions.Password != "same" {
		t.Fatalf("SOCKS credentials = %q:%q", hopOptions.Username, hopOptions.Password)
	}
	edgeOptions := byTag["edge-1"].Options.(*option.VLESSOutboundOptions)
	if edgeOptions.Detour != "hop" {
		t.Fatalf("edge detour = %q, want hop", edgeOptions.Detour)
	}
	if edgeOptions.Transport == nil || edgeOptions.Transport.Type != C.V2RayTransportTypeKCP {
		t.Fatalf("edge transport = %#v, want mkcp", edgeOptions.Transport)
	}
	if edgeOptions.Transport.KCPOptions.HeaderType != "wechat-video" || edgeOptions.Transport.KCPOptions.Seed != "secret" {
		t.Fatalf("edge KCP options = %#v", edgeOptions.Transport.KCPOptions)
	}
}

func TestProxySettingsWithoutTransportLayerIsNotDetour(t *testing.T) {
	source := sourceOutbound{ProxySettings: &proxySettings{Tag: "hop"}}
	if detour := sourceDetour(source); detour != "" {
		t.Fatalf("detour = %q, want empty", detour)
	}
	source.ProxySettings.TransportLayer = true
	if detour := sourceDetour(source); detour != "hop" {
		t.Fatalf("detour = %q, want hop", detour)
	}
}

func TestXrayInvalidDetourChainDoesNotDiscardUnrelatedLeaves(t *testing.T) {
	outbounds, err := ParseXraySubscription(context.Background(), `{
  "outbounds":[
    {
      "protocol":"vless",
      "tag":"depends-on-broken",
      "settings":{"vnext":[{"address":"one.example","port":443,"users":[{"id":"uuid-a"}]}]},
      "streamSettings":{"sockopt":{"dialerProxy":"broken"}}
    },
    {
      "protocol":"vless",
      "tag":"broken",
      "settings":{"vnext":[{"address":"two.example","port":443,"users":[{"id":"uuid-b"}]}]},
      "streamSettings":{"sockopt":{"dialerProxy":"unsupported-hop"}}
    },
    {"protocol":"freedom","tag":"unsupported-hop"},
    {"protocol":"vless","tag":"usable","settings":{"vnext":[{"address":"good.example","port":443,"users":[{"id":"uuid-c"}]}]}}
  ]
}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(outbounds) != 1 || outbounds[0].Tag != "usable" {
		t.Fatalf("invalid dependency chain leaked or unrelated leaf was lost: %#v", outbounds)
	}
}

func TestXrayExternalDetourIsPreserved(t *testing.T) {
	outbounds, err := ParseXraySubscription(context.Background(), `{
  "outbounds":[{
    "protocol":"vless",
    "tag":"proxy",
    "settings":{"vnext":[{"address":"one.example","port":443,"users":[{"id":"uuid-a"}]}]},
    "streamSettings":{"sockopt":{"dialerProxy":"global-egress"}}
  }]
}`)
	if err != nil {
		t.Fatal(err)
	}
	if detour := outbounds[0].Options.(*option.VLESSOutboundOptions).Detour; detour != "global-egress" {
		t.Fatalf("external detour = %q, want global-egress", detour)
	}
}

func TestXrayDiscardedSiblingDoesNotRenameValidLeaf(t *testing.T) {
	outbounds, err := ParseXraySubscription(context.Background(), `{
  "outbounds":[
    {"protocol":"freedom","tag":"duplicate"},
    {"protocol":"vless","tag":"duplicate","settings":{"vnext":[{"address":"good.example","port":443,"users":[{"id":"uuid-a"}]}]}},
    {
      "protocol":"vless",
      "tag":"ambiguous-dependent",
      "settings":{"vnext":[{"address":"other.example","port":443,"users":[{"id":"uuid-b"}]}]},
      "streamSettings":{"sockopt":{"dialerProxy":"duplicate"}}
    }
  ]
}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(outbounds) != 1 || outbounds[0].Tag != "duplicate" {
		t.Fatalf("discarded sibling renamed a leaf or ambiguous dependency survived: %#v", outbounds)
	}
}

func TestXrayHysteria2StreamSettings(t *testing.T) {
	outbounds, err := ParseXraySubscription(context.Background(), `{
  "outbounds":[{
    "protocol":"hysteria",
    "tag":"proxy",
    "settings":{"address":"hy.example","port":443},
    "streamSettings":{"hysteriaSettings":{"version":2,"auth":"secret"}}
  }]
}`)
	if err != nil {
		t.Fatal(err)
	}
	options := outbounds[0].Options.(*option.Hysteria2OutboundOptions)
	if options.Password != "secret" || options.Server != "hy.example" || options.ServerPort != 443 {
		t.Fatalf("unexpected Hysteria2 options: %#v", options)
	}
}

func TestXrayCommonProxyProtocols(t *testing.T) {
	outbounds, err := ParseXraySubscription(context.Background(), `{
  "outbounds": [
    {"protocol":"shadowsocks","tag":"ss","settings":{"servers":[{"address":"ss.example","port":8388,"method":"aes-256-gcm","password":"ss-secret"}]}},
    {"protocol":"trojan","tag":"trojan","settings":{"servers":[{"address":"trojan.example","port":443,"password":"trojan-secret"}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example"},"wsSettings":{"path":"/ws"}}},
    {"protocol":"http","tag":"http","settings":{"servers":[{"address":"http.example","port":8443,"users":[{"user":"alice","pass":"http-secret"}]}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"proxy.example"}}}
  ]
}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(outbounds) != 3 {
		t.Fatalf("got %d outbounds, want 3", len(outbounds))
	}
	ss := outbounds[0].Options.(*option.ShadowsocksOutboundOptions)
	if ss.Server != "ss.example" || ss.ServerPort != 8388 || ss.Method != "aes-256-gcm" || ss.Password != "ss-secret" {
		t.Fatalf("unexpected Shadowsocks options: %#v", ss)
	}
	trojan := outbounds[1].Options.(*option.TrojanOutboundOptions)
	if trojan.Password != "trojan-secret" || trojan.TLS == nil || trojan.TLS.ServerName != "sni.example" || trojan.Transport == nil || trojan.Transport.Type != C.V2RayTransportTypeWebsocket {
		t.Fatalf("unexpected Trojan options: %#v", trojan)
	}
	httpOptions := outbounds[2].Options.(*option.HTTPOutboundOptions)
	if httpOptions.Username != "alice" || httpOptions.Password != "http-secret" || httpOptions.TLS == nil || httpOptions.TLS.ServerName != "proxy.example" {
		t.Fatalf("unexpected HTTP options: %#v", httpOptions)
	}
}
