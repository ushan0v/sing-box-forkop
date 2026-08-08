package link

import (
	"encoding/base64"
	"testing"
	"time"

	mieruappctl "github.com/enfein/mieru/v3/pkg/appctl"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"google.golang.org/protobuf/proto"
)

func TestParseNaiveLinks(t *testing.T) {
	tests := []struct {
		name       string
		link       string
		server     string
		port       uint16
		password   string
		serverName string
		tag        string
		quic       bool
	}{
		{"HTTPS", "naive+https://user:p%40ss@example.com?extra-headers=X-Username%3Auser%0D%0AX-Role%3Aproxy&sni=front.example#Naive", "example.com", 443, "p@ss", "front.example", "Naive", false},
		{"QUIC", "naive+quic://user:password@quic.example:8443#Naive%20QUIC", "quic.example", 8443, "password", "quic.example", "Naive QUIC", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outbound, err := ParseSubscriptionLink(test.link)
			if err != nil {
				t.Fatal(err)
			}
			options := outbound.Options.(*option.NaiveOutboundOptions)
			if outbound.Type != C.TypeNaive || options.QUIC != test.quic {
				t.Fatalf("unexpected outbound: type=%q quic=%v", outbound.Type, options.QUIC)
			}
			if outbound.Tag != test.tag || options.Username != "user" || options.Password != test.password || options.Server != test.server || options.ServerPort != test.port {
				t.Fatalf("unexpected naive options: %#v", options)
			}
			if options.TLS == nil || !options.TLS.Enabled || options.TLS.ServerName != test.serverName {
				t.Fatalf("unexpected naive TLS options: %#v", options.TLS)
			}
			if test.name == "HTTPS" && (options.ExtraHeaders["X-Username"][0] != "user" || options.ExtraHeaders["X-Role"][0] != "proxy") {
				t.Fatalf("unexpected naive extra headers: %#v", options.ExtraHeaders)
			}
		})
	}
}

func TestParseMieruSimpleLink(t *testing.T) {
	outbound, err := ParseSubscriptionLink("mierus://alice:s3cret@203.0.113.7?profile=default&port=2012-2022&protocol=TCP&multiplexing=MULTIPLEXING_HIGH#Mieru")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(*option.MieruOutboundOptions)
	if outbound.Type != C.TypeMieru || outbound.Tag != "Mieru" {
		t.Fatalf("unexpected outbound: type=%q tag=%q", outbound.Type, outbound.Tag)
	}
	if options.Server != "203.0.113.7" || options.UserName != "alice" || options.Password != "s3cret" || options.Transport != "TCP" {
		t.Fatalf("unexpected mieru options: %#v", options)
	}
	if len(options.ServerPortRanges) != 1 || options.ServerPortRanges[0] != "2012-2022" || options.Multiplexing != "MULTIPLEXING_HIGH" {
		t.Fatalf("unexpected mieru port options: %#v", options)
	}
}

func TestParseMieruStandardLink(t *testing.T) {
	link, err := mieruappctl.ClientConfigToURL(&mierupb.ClientConfig{
		Profiles: []*mierupb.ClientProfile{{
			ProfileName: proto.String("default"),
			User:        &mierupb.User{Name: proto.String("alice"), Password: proto.String("s3cret")},
			Servers: []*mierupb.ServerEndpoint{{
				DomainName: proto.String("mieru.example"),
				PortBindings: []*mierupb.PortBinding{{
					Port: proto.Int32(443), Protocol: mierupb.TransportProtocol_TCP.Enum(),
				}},
			}},
		}},
		ActiveProfile: proto.String("default"),
	})
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := ParseSubscriptionLink(link)
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(*option.MieruOutboundOptions)
	if outbound.Type != C.TypeMieru || options.Server != "mieru.example" || options.ServerPort != 443 || options.Transport != "TCP" {
		t.Fatalf("unexpected mieru options: %#v", options)
	}
}

func TestParseSOCKSLinkPreservesEqualCredentials(t *testing.T) {
	outbound, err := ParseSubscriptionLink("socks5://same:same@127.0.0.1:1080#equal-creds")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(*option.SOCKSOutboundOptions)
	if outbound.Type != C.TypeSOCKS || outbound.Tag != "equal-creds" {
		t.Fatalf("unexpected outbound: type=%q tag=%q", outbound.Type, outbound.Tag)
	}
	if options.Username != "same" || options.Password != "same" {
		t.Fatalf("credentials = %q:%q, want same:same", options.Username, options.Password)
	}
}

func TestParseVLESSMKCPLink(t *testing.T) {
	outbound, err := ParseSubscriptionLink("vless://uuid@example.com:443?type=kcp&headerType=wechat-video&seed=secret#kcp")
	if err != nil {
		t.Fatal(err)
	}
	transport := outbound.Options.(*option.VLESSOutboundOptions).Transport
	if transport == nil || transport.Type != C.V2RayTransportTypeKCP {
		t.Fatalf("transport = %#v, want mkcp", transport)
	}
	if transport.KCPOptions.HeaderType != "wechat-video" || transport.KCPOptions.Seed != "secret" {
		t.Fatalf("KCP options = %#v", transport.KCPOptions)
	}
}

func TestParseVMessMKCPLink(t *testing.T) {
	payload := base64.RawStdEncoding.EncodeToString([]byte(`{"v":"2","ps":"kcp","add":"example.com","port":"443","id":"uuid","net":"kcp","type":"srtp","path":"seed"}`))
	outbound, err := ParseSubscriptionLink("vmess://" + payload)
	if err != nil {
		t.Fatal(err)
	}
	transport := outbound.Options.(*option.VMessOutboundOptions).Transport
	if transport == nil || transport.Type != C.V2RayTransportTypeKCP {
		t.Fatalf("transport = %#v, want mkcp", transport)
	}
	if transport.KCPOptions.HeaderType != "srtp" || transport.KCPOptions.Seed != "seed" {
		t.Fatalf("KCP options = %#v", transport.KCPOptions)
	}
}

func TestParseShadowsocks2022LinkWithEncodedUserInfo(t *testing.T) {
	link := "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206dGVzdC9rZXk6d2l0aC9zbGFzaGVz@example.com:443?type=tcp#encoded-userinfo"
	outbound, err := ParseSubscriptionLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Type != C.TypeShadowsocks || outbound.Tag != "encoded-userinfo" {
		t.Fatalf("unexpected outbound: type=%q tag=%q", outbound.Type, outbound.Tag)
	}
	options := outbound.Options.(*option.ShadowsocksOutboundOptions)
	if options.Method != "2022-blake3-aes-256-gcm" || options.Password != "test/key:with/slashes" || options.Server != "example.com" || options.ServerPort != 443 {
		t.Fatalf("unexpected Shadowsocks options: %#v", options)
	}
}

func TestGenerateSubscriptionLinkRoundTrip(t *testing.T) {
	packetEncoding := "xudp"
	tests := []option.Outbound{
		{
			Type: C.TypeVLESS,
			Tag:  "VLESS node",
			Options: &option.VLESSOutboundOptions{
				ServerOptions:  option.ServerOptions{Server: "vless.example", ServerPort: 443},
				UUID:           "00000000-0000-4000-8000-000000000001",
				Encryption:     "mlkem768x25519plus.native.0rtt.test",
				Flow:           "xtls-rprx-vision",
				PacketEncoding: &packetEncoding,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "sni.example", ALPN: []string{"h2", "http/1.1"},
					UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
					Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: "public-key", ShortID: "abcd"},
				}},
				Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP, XHTTPOptions: option.V2RayXHTTPOptions{
					Mode: "stream-one", V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
						Host: "cdn.example", Path: "/xhttp", XPaddingBytes: badoption.Range[int]{From: 100, To: 200},
					},
				}},
			},
		},
		{
			Type: C.TypeVLESS,
			Tag:  "VLESS gRPC",
			Options: &option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "vless-grpc.example", ServerPort: 443},
				UUID:          "00000000-0000-4000-8000-000000000004",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "distinct-sni.example",
				}},
				Transport: &option.V2RayTransportOptions{
					Type:        C.V2RayTransportTypeGRPC,
					GRPCOptions: option.V2RayGRPCOptions{ServiceName: "distinct-service"},
				},
			},
		},
		{
			Type: C.TypeVMess,
			Tag:  "VMess node",
			Options: &option.VMessOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "vmess.example", ServerPort: 443},
				UUID:          "00000000-0000-4000-8000-000000000002", Security: "auto", AlterId: 4,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "vmess-sni.example", ALPN: []string{"h2"}, Insecure: true,
					UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "firefox"},
				}},
				Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket, WebsocketOptions: option.V2RayWebsocketOptions{
					Path: "/ws", Headers: badoption.HTTPHeader{"Host": {"ws.example"}},
				}},
			},
		},
		{
			Type: C.TypeTrojan,
			Tag:  "Trojan node",
			Options: &option.TrojanOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "trojan.example", ServerPort: 443}, Password: "secret",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "trojan.example", ALPN: []string{"h2"},
				}},
				Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeGRPC, GRPCOptions: option.V2RayGRPCOptions{ServiceName: "service"}},
			},
		},
		{
			Type: C.TypeShadowsocks,
			Tag:  "SS node",
			Options: &option.ShadowsocksOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "2001:db8::1", ServerPort: 8388},
				Method:        "aes-256-gcm", Password: "p@ss:word", Plugin: "obfs-local", PluginOptions: "obfs=http",
			},
		},
		{
			Type: C.TypeSOCKS,
			Tag:  "SOCKS node",
			Options: &option.SOCKSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "socks.example", ServerPort: 1080}, Version: "5", Username: "user", Password: "p@ss",
			},
		},
		{
			Type: C.TypeHysteria2,
			Tag:  "Hysteria2 node",
			Options: &option.Hysteria2OutboundOptions{
				ServerOptions: option.ServerOptions{Server: "hy2.example", ServerPort: 443}, Password: "hy2-secret", UpMbps: 50, DownMbps: 100,
				Obfs: &option.Hysteria2Obfs{Type: "salamander", Password: "obfs-secret"},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "hy2-sni.example", ALPN: []string{"h3"}, Insecure: true,
				}},
			},
		},
		{
			Type: C.TypeTUIC,
			Tag:  "TUIC node",
			Options: &option.TUICOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "tuic.example", ServerPort: 443}, UUID: "00000000-0000-4000-8000-000000000003", Password: "tuic-secret",
				CongestionControl: "bbr", UDPRelayMode: "native", ZeroRTTHandshake: true, Heartbeat: badoption.Duration(10 * time.Second),
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "tuic-sni.example", ALPN: []string{"h3"},
				}},
			},
		},
		{
			Type: C.TypeHysteria,
			Tag:  "Hysteria node",
			Options: &option.HysteriaOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "hysteria.example", ServerPort: 443}, AuthString: "auth-secret", UpMbps: 25, DownMbps: 75, Obfs: "obfs-secret",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "hysteria-sni.example", ALPN: []string{"h3"},
				}},
			},
		},
	}

	for _, outbound := range tests {
		t.Run(outbound.Type, func(t *testing.T) {
			generated, err := GenerateSubscriptionLink(outbound)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseSubscriptionLink(generated)
			if err != nil {
				t.Fatalf("parse generated link %q: %v", generated, err)
			}
			if parsed.Type != outbound.Type || parsed.Tag != outbound.Tag {
				t.Fatalf("round-trip identity changed: type=%q tag=%q", parsed.Type, parsed.Tag)
			}
			regenerated, err := GenerateSubscriptionLink(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if regenerated != generated {
				t.Fatalf("share link is not stable\nfirst:  %s\nsecond: %s", generated, regenerated)
			}
		})
	}
}

func TestGenerateSubscriptionLinkRejectsUnsupportedValues(t *testing.T) {
	if _, err := GenerateSubscriptionLink(option.Outbound{Type: C.TypeDirect}); err == nil {
		t.Fatal("expected unsupported outbound type to fail")
	}
	_, err := GenerateSubscriptionLink(option.Outbound{
		Type: C.TypeHysteria2,
		Options: &option.Hysteria2OutboundOptions{
			ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
			ServerPorts:   []string{"443:8443"},
			Password:      "secret",
		},
	})
	if err == nil {
		t.Fatal("expected port hopping to fail instead of producing a lossy link")
	}
	_, err = GenerateSubscriptionLink(option.Outbound{
		Type: C.TypeTrojan,
		Options: &option.TrojanOutboundOptions{
			ServerOptions:               option.ServerOptions{Server: "example.com", ServerPort: 443},
			Password:                    "secret",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true}},
			Transport:                   &option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP},
		},
	})
	if err == nil {
		t.Fatal("expected an unsupported Trojan transport to fail instead of producing a lossy link")
	}
	for name, tls := range map[string]*option.OutboundTLSOptions{
		"plaintext":    nil,
		"disabled TLS": {Enabled: false},
		"Reality":      {Enabled: true, Reality: &option.OutboundRealityOptions{Enabled: true}},
		"ECH":          {Enabled: true, ECH: &option.OutboundECHOptions{Enabled: true}},
	} {
		t.Run("trojan "+name, func(t *testing.T) {
			_, err := GenerateSubscriptionLink(option.Outbound{
				Type: C.TypeTrojan,
				Options: &option.TrojanOutboundOptions{
					ServerOptions:               option.ServerOptions{Server: "example.com", ServerPort: 443},
					Password:                    "secret",
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
				},
			})
			if err == nil {
				t.Fatalf("expected %s Trojan to fail instead of producing a lossy link", name)
			}
		})
	}
}
