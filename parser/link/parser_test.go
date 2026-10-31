package link

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
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
		uotVersion uint8
	}{
		{"HTTPS", "naive+https://user:p%40ss@example.com?extra-headers=X-Username%3Auser%0D%0AX-Role%3Aproxy&sni=front.example#Naive", "example.com", 443, "p@ss", "front.example", "Naive", false, 0},
		{"QUIC", "naive+quic://user:password@quic.example:8443#Naive%20QUIC", "quic.example", 8443, "password", "quic.example", "Naive QUIC", true, 0},
		{"Shadowrocket HTTP2", "http2://" + base64.StdEncoding.EncodeToString([]byte("user:password@h2.example:443")) + "?peer=front.example&alpn=h2,http/1.1&padding=1&uot=2#Naive%20H2", "h2.example", 443, "password", "front.example", "Naive H2", false, 2},
		{"Shadowrocket HTTP3", "http3://" + base64.RawURLEncoding.EncodeToString([]byte("user:password@h3.example:8443")) + "?peer=front.example&alpn=h3&padding=1#Naive%20H3", "h3.example", 8443, "password", "front.example", "Naive H3", true, 0},
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
			if test.uotVersion == 0 && options.UDPOverTCP != nil || test.uotVersion != 0 && (options.UDPOverTCP == nil || !options.UDPOverTCP.Enabled || options.UDPOverTCP.Version != test.uotVersion) {
				t.Fatalf("unexpected naive UDP over TCP options: %#v", options.UDPOverTCP)
			}
		})
	}
}

func TestParseHTTPLinks(t *testing.T) {
	tests := []struct {
		link       string
		server     string
		port       uint16
		username   string
		password   string
		path       string
		tag        string
		tlsEnabled bool
	}{
		{"http://user:p%40ss@proxy.example:8080#Plain", "proxy.example", 8080, "user", "p@ss", "", "Plain", false},
		{"https://secure.example/connect#Secure", "secure.example", 443, "", "", "/connect", "Secure", true},
	}
	// A plain web link inside a subscription is not a proxy.
	if _, err := ParseSubscriptionLink("https://example.com/subscription"); err == nil {
		t.Fatal("a plain web link was imported as an HTTP proxy")
	}
	for _, test := range tests {
		outbound, err := ParseSubscriptionLink(test.link)
		if err != nil {
			t.Fatal(err)
		}
		options := outbound.Options.(*option.HTTPOutboundOptions)
		if outbound.Type != C.TypeHTTP || outbound.Tag != test.tag || options.Server != test.server || options.ServerPort != test.port || options.Username != test.username || options.Password != test.password || options.Path != test.path {
			t.Fatalf("unexpected HTTP outbound: %#v", outbound)
		}
		if (options.TLS != nil && options.TLS.Enabled) != test.tlsEnabled {
			t.Fatalf("unexpected HTTP TLS options: %#v", options.TLS)
		}
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

// The core has no mKCP transport, so a node using it is refused with a reason
// instead of being built as plain TCP.
func TestParseMKCPLinksAreRefused(t *testing.T) {
	vmessPayload := base64.RawStdEncoding.EncodeToString([]byte(`{"v":"2","ps":"kcp","add":"example.com","port":"443","id":"uuid","net":"kcp","type":"srtp","path":"seed"}`))
	for _, link := range []string{
		"vless://uuid@example.com:443?type=kcp&headerType=wechat-video&seed=secret#kcp",
		"vmess://" + vmessPayload,
	} {
		_, err := ParseSubscriptionLink(link)
		if err == nil || !strings.Contains(err.Error(), "unsupported transport") {
			t.Fatalf("%s: err = %v, want an unsupported transport", link, err)
		}
	}
}

// v2rayN writes every key, so a node without TLS extras carries empty strings: an empty ALPN entry
// is invalid, and an empty sni would drop the name taken from "add".
func TestParseVMessLinkWithEmptyTLSFields(t *testing.T) {
	payload := base64.RawStdEncoding.EncodeToString([]byte(
		`{"v":"2","ps":"empty","add":"example.com","port":"443","id":"uuid","net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":"","alpn":""}`,
	))
	outbound, err := ParseSubscriptionLink("vmess://" + payload)
	if err != nil {
		t.Fatal(err)
	}
	tlsOptions := outbound.Options.(*option.VMessOutboundOptions).TLS
	if tlsOptions == nil || !tlsOptions.Enabled {
		t.Fatalf("TLS = %#v, want enabled", tlsOptions)
	}
	if len(tlsOptions.ALPN) != 0 {
		t.Fatalf("ALPN = %#v, want none", tlsOptions.ALPN)
	}
	if tlsOptions.ServerName != "example.com" {
		t.Fatalf("server name = %q, want example.com", tlsOptions.ServerName)
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
			Type: C.TypeHTTP,
			Tag:  "HTTP node",
			Options: &option.HTTPOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "http.example", ServerPort: 443},
				Username:      "user", Password: "p@ss", Path: "/proxy%20path",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true}},
			},
		},
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
						Host: "cdn.example", Path: "/xhttp", XPaddingBytes: option.Range[int]{From: 100, To: 200},
					},
				}},
			},
		},
		{
			Type: C.TypeVLESS,
			Tag:  "VLESS XHTTP with a download leg",
			Options: &option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "up.example", ServerPort: 443},
				UUID:          "00000000-0000-4000-8000-000000000006",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "cdn.example",
					UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "firefox"},
				}},
				Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP, XHTTPOptions: option.V2RayXHTTPOptions{
					Mode:                  "stream-up",
					V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{Path: "/up"},
					Download: &option.V2RayXHTTPDownloadOptions{
						ServerOptions:         option.ServerOptions{Server: "down.example", ServerPort: 8443},
						V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{Host: "down.example", Path: "/down", XPaddingBytes: option.Range[int]{From: 50, To: 60}},
						OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
							Enabled: true, ServerName: "www.example.com",
							Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: "SSw7I859PPdN4DQ7fxV9fobXM61Ms3mqZRlIY1aJvHQ", ShortID: "5a"},
						}},
					},
				}},
			},
		},
		{
			Type: C.TypeVLESS,
			Tag:  "VLESS websocket",
			Options: &option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "ws.example", ServerPort: 443},
				UUID:          "00000000-0000-4000-8000-000000000005",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "ws.example",
				}},
				// The early data length rides in a share link's path.
				Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket, WebsocketOptions: option.V2RayWebsocketOptions{
					Path: "/ws", Headers: badoption.HTTPHeader{"Host": {"ws.example"}},
					MaxEarlyData: 2048, EarlyDataHeaderName: "Sec-WebSocket-Protocol",
				}},
			},
		},
		{
			Type: C.TypeVLESS,
			Tag:  "VLESS XHTTP reuse",
			Options: &option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "xhttp.example", ServerPort: 443},
				UUID:          "00000000-0000-4000-8000-000000000006",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "xhttp.example",
				}},
				// sing-box defaults the reuse block only when it is absent altogether.
				Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP, XHTTPOptions: option.V2RayXHTTPOptions{
					Mode: "packet-up", V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
						Path: "/x", XPaddingKey: "q", UplinkHTTPMethod: "DELETE",
						Xmux: &option.V2RayXHTTPXmuxOptions{
							MaxConnections:   option.Range[int]{From: 16, To: 32},
							HMaxRequestTimes: option.Range[int]{From: 600, To: 900},
							HKeepAlivePeriod: 20,
						},
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
			Type: C.TypeVMess,
			Tag:  "VMess XHTTP",
			Options: &option.VMessOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "vmess.example", ServerPort: 443},
				UUID:          "00000000-0000-4000-8000-000000000007", Security: "auto",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "vmess-sni.example", ALPN: []string{"h2"},
				}},
				Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP, XHTTPOptions: option.V2RayXHTTPOptions{
					Mode: "stream-up", V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
						Host: "cdn.example", Path: "/xhttp", XPaddingBytes: option.Range[int]{From: 100, To: 200},
					},
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
		{
			Type: C.TypeAnyTLS,
			Tag:  "AnyTLS node",
			Options: &option.AnyTLSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "anytls.example", ServerPort: 8443}, Password: "anytls-secret",
				DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true}},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "anytls-sni.example", ALPN: []string{"h2", "http/1.1"},
					UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
				}},
			},
		},
		{
			Type: C.TypeNaive,
			Tag:  "Naive node",
			Options: &option.NaiveOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "naive.example", ServerPort: 443},
				Username:      "naive-user", Password: "naive-secret",
				ExtraHeaders: badoption.HTTPHeader{"X-Extra": []string{"one", "two"}},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, ServerName: "naive-sni.example",
				}},
			},
		},
	}

	for _, outbound := range tests {
		t.Run(outbound.Type, func(t *testing.T) {
			testLinkRoundTrip(t, outbound)
		})
	}
}

func TestGenerateSubscriptionLinkWritesVerifyServerName(t *testing.T) {
	tls := func() *option.OutboundTLSOptions {
		return &option.OutboundTLSOptions{Enabled: true, ServerName: "front.example", VerifyServerName: []string{"real.example", "other.example"}}
	}
	for _, outbound := range []option.Outbound{
		{Type: C.TypeTrojan, Tag: "Trojan", Options: &option.TrojanOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "trojan.example", ServerPort: 443}, Password: "secret",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls()},
		}},
		{Type: C.TypeVMess, Tag: "VMess", Options: &option.VMessOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "vmess.example", ServerPort: 443}, UUID: "00000000-0000-4000-8000-000000000002", Security: "auto",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls()},
		}},
		{Type: C.TypeVLESS, Tag: "VLESS XHTTP", Options: &option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "up.example", ServerPort: 443}, UUID: "00000000-0000-4000-8000-000000000006",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "up.example"}},
			Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP, XHTTPOptions: option.V2RayXHTTPOptions{
				Mode:                  "stream-up",
				V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{Path: "/up"},
				Download: &option.V2RayXHTTPDownloadOptions{
					ServerOptions:               option.ServerOptions{Server: "down.example", ServerPort: 443},
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls()},
				},
			}},
		}},
	} {
		t.Run(outbound.Tag, func(t *testing.T) {
			testLinkRoundTrip(t, outbound)
		})
	}
}

func testLinkRoundTrip(t *testing.T, outbound option.Outbound) {
	t.Helper()
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
	// A share link has no way to say that a server is multiplexed, so rendering
	// one would hand out a link that connects differently from the server it
	// was made from.
	_, err = GenerateSubscriptionLink(option.Outbound{
		Type: C.TypeTrojan,
		Options: &option.TrojanOutboundOptions{
			ServerOptions:               option.ServerOptions{Server: "example.com", ServerPort: 443},
			Password:                    "secret",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true}},
			Multiplex:                   &option.OutboundMultiplexOptions{Enabled: true, Protocol: "smux"},
		},
	})
	if err == nil {
		t.Fatal("expected multiplex to fail instead of producing a lossy link")
	}
	for name, tls := range map[string]*option.OutboundTLSOptions{
		"plaintext":    nil,
		"disabled TLS": {Enabled: false},
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

	unsupported := map[string]option.Outbound{
		"VLESS network": {
			Type: C.TypeVLESS,
			Options: &option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
				UUID:          "uuid",
				Network:       option.NetworkList("tcp"),
			},
		},
		"VLESS certificate": {
			Type: C.TypeVLESS,
			Options: &option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
				UUID:          "uuid",
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
					Enabled: true, Certificate: []string{"certificate"},
				}},
			},
		},
		"VMess global padding": {
			Type: C.TypeVMess,
			Options: &option.VMessOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
				UUID:          "uuid",
				GlobalPadding: true,
			},
		},
		"Hysteria2 hop interval": {
			Type: C.TypeHysteria2,
			Options: &option.Hysteria2OutboundOptions{
				ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
				Password:      "secret",
				HopInterval:   badoption.Duration(time.Second),
			},
		},
	}
	for name, outbound := range unsupported {
		t.Run(name, func(t *testing.T) {
			if _, err := GenerateSubscriptionLink(outbound); err == nil {
				t.Fatal("unsupported options were silently omitted")
			}
		})
	}
}

func TestParseLinkRefusesWhatItCannotDial(t *testing.T) {
	for name, link := range map[string]string{
		"no port":                "vless://00000000-0000-4000-8000-000000000001@vless.example#node",
		"port zero":              "vless://00000000-0000-4000-8000-000000000001@vless.example:0#node",
		"unreadable port":        "trojan://secret@trojan.example:https#node",
		"an unsupported flow":    "vless://00000000-0000-4000-8000-000000000001@vless.example:443?flow=xtls-rprx-direct#node",
		"a masked stream in TLS": "vless://00000000-0000-4000-8000-000000000001@vless.example:443?type=tcp&headerType=http&security=tls#node",
		"an unsupported scheme":  "juicity://secret@juicity.example:443#node",
	} {
		t.Run(name, func(t *testing.T) {
			if outbound, err := ParseSubscriptionLink(link); err == nil {
				t.Fatalf("link was imported as %#v", outbound)
			}
		})
	}
}

func TestParseLinkReadsTheSameParametersWhateverTheirOrder(t *testing.T) {
	// Parameters are read by name, not in map order, so the ALPN list is the same on every run.
	const link = "vless://00000000-0000-4000-8000-000000000001@xhttp.example:443?type=xhttp&alpn=h3&security=tls&sni=xhttp.example&path=/x"
	for attempt := 0; attempt < 32; attempt++ {
		outbound, err := ParseSubscriptionLink(link)
		if err != nil {
			t.Fatal(err)
		}
		alpn := outbound.Options.(*option.VLESSOutboundOptions).TLS.ALPN
		if len(alpn) != 1 || alpn[0] != "h3" {
			t.Fatalf("ALPN = %q, want the one the link names", alpn)
		}
	}
}

func TestParseLinkWithoutSecurityHasNoTLS(t *testing.T) {
	outbound, err := ParseSubscriptionLink("vless://00000000-0000-4000-8000-000000000001@plain.example:80?security=none&sni=plain.example&fp=chrome#plaintext")
	if err != nil {
		t.Fatal(err)
	}
	if tls := outbound.Options.(*option.VLESSOutboundOptions).TLS; tls != nil {
		t.Fatalf("a link that asks for no security got TLS: %#v", tls)
	}
}

func TestParseShadowsocksLegacyLink(t *testing.T) {
	// The original form encodes the whole of method:password@host:port, and it
	// is still what most aggregator subscriptions export.
	outbound, err := ParseSubscriptionLink("ss://" +
		base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pass@word@ss.example:21123")) + "#legacy")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(*option.ShadowsocksOutboundOptions)
	if options.Server != "ss.example" || options.ServerPort != 21123 ||
		options.Method != "chacha20-ietf-poly1305" || options.Password != "pass@word" {
		t.Fatalf("legacy Shadowsocks link was read wrong: %#v", options)
	}
}

func TestParseShadowsocksRLinkIsRefused(t *testing.T) {
	// sing-box registers ShadowsocksR only as a stub that refuses to build, so
	// importing such a link would produce a server that can never be dialled.
	body := "ssr.example:8080:auth_aes128_md5:aes-128-cfb:tls1.2_ticket_auth:" +
		base64.RawURLEncoding.EncodeToString([]byte("ssr-password"))
	_, err := ParseSubscriptionLink("ssr://" + base64.RawURLEncoding.EncodeToString([]byte(body)))
	if err == nil {
		t.Fatal("a ShadowsocksR link was imported")
	}
	if !strings.Contains(err.Error(), "ShadowsocksR") {
		t.Fatalf("the reason does not name the protocol: %v", err)
	}
}

func TestParseVMessLinkWithNonStringFields(t *testing.T) {
	// Generators write the object weakly typed: the TLS flag as a boolean, port and alter id as numbers.
	payload := `{"v":2,"ps":"weak","add":"vm.example","port":443,"id":"00000000-0000-4000-8000-000000000001",` +
		`"aid":0,"scy":"auto","net":"ws","type":"none","host":"vm.example","path":"/ws","tls":true,"sni":"vm.example"}`
	outbound, err := ParseSubscriptionLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(payload)))
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(*option.VMessOutboundOptions)
	if outbound.Tag != "weak" || options.ServerPort != 443 || options.TLS == nil || !options.TLS.Enabled {
		t.Fatalf("the weakly typed object was read wrong: %#v", options)
	}
}

func TestParseVMessLinkReadsTheXHTTPModeWhereV2rayNWritesIt(t *testing.T) {
	for name, testCase := range map[string]struct {
		fields string
		mode   string
	}{
		"v2rayN, in type":     {`"type":"stream-one"`, "stream-one"},
		"mode wins":           {`"type":"stream-up","mode":"packet-up"`, "packet-up"},
		"the TCP header none": {`"type":"none"`, "auto"},
	} {
		t.Run(name, func(t *testing.T) {
			payload := `{"v":"2","ps":"x","add":"vm.example","port":"443","id":"00000000-0000-4000-8000-000000000001",` +
				`"aid":"0","scy":"auto","net":"xhttp","path":"/x","tls":"tls","sni":"vm.example",` + testCase.fields + `}`
			outbound, err := ParseSubscriptionLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(payload)))
			if err != nil {
				t.Fatal(err)
			}
			transport := outbound.Options.(*option.VMessOutboundOptions).Transport
			if transport == nil || transport.Type != C.V2RayTransportTypeXHTTP || transport.XHTTPOptions.Mode != testCase.mode {
				t.Fatalf("transport = %#v", transport)
			}
		})
	}
}

func TestParseShadowsocksLinkWithATrailingQuery(t *testing.T) {
	// The generator folds the empty query into the encoded payload, so what
	// follows the at sign is host:443? rather than a host and a port.
	outbound, err := ParseSubscriptionLink("ss://" +
		base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret@ss.example:30129?")) + "#trailing")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(*option.ShadowsocksOutboundOptions)
	if options.Server != "ss.example" || options.ServerPort != 30129 {
		t.Fatalf("endpoint = %s:%d", options.Server, options.ServerPort)
	}
}

func TestParseShadowsocksSIP002LinkWithAPathBeforeTheQuery(t *testing.T) {
	for name, testCase := range map[string]struct {
		link   string
		server string
		port   uint16
		plugin string
	}{
		"SIP002 example": {"ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example1", "192.168.100.1", 8888, "obfs-local"},
		"Outline key":    {"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@203.0.113.7:5678/?outline=1", "203.0.113.7", 5678, ""},
		"plain path":     {"ss://aes-256-gcm:secret@ss.example:443/#plain", "ss.example", 443, ""},
	} {
		t.Run(name, func(t *testing.T) {
			outbound, err := ParseSubscriptionLink(testCase.link)
			if err != nil {
				t.Fatal(err)
			}
			options := outbound.Options.(*option.ShadowsocksOutboundOptions)
			if options.Server != testCase.server || options.ServerPort != testCase.port || options.Plugin != testCase.plugin {
				t.Fatalf("read %s:%d plugin %q", options.Server, options.ServerPort, options.Plugin)
			}
		})
	}
}

func TestParseVMessURLLinkReadsTheQueryAsVLESSDoes(t *testing.T) {
	const uuid = "00000000-0000-4000-8000-000000000001"
	outbound, err := ParseSubscriptionLink("vmess://" + uuid + "@vm.example:443?type=grpc&serviceName=svc&security=reality&pbk=key&sid=01&sni=cdn.example#grpc")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(*option.VMessOutboundOptions)
	if options.Transport == nil || options.Transport.GRPCOptions.ServiceName != "svc" {
		t.Fatalf("gRPC service name was lost: %#v", options.Transport)
	}
	if options.TLS == nil || options.TLS.Reality == nil || options.TLS.Reality.PublicKey != "key" || options.TLS.ServerName != "cdn.example" {
		t.Fatalf("Reality was lost: %#v", options.TLS)
	}
	if options.Security != "auto" || outbound.Tag != "grpc" {
		t.Fatalf("unexpected VMess options: %#v", options)
	}

	outbound, err = ParseSubscriptionLink("vmess://" + uuid + "@vm.example:443?type=ws&path=/ws&ed=2048&security=tls&encryption=aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	options = outbound.Options.(*option.VMessOutboundOptions)
	if options.Transport == nil || options.Transport.WebsocketOptions.MaxEarlyData != 2048 || options.Security != "aes-128-gcm" || options.TLS == nil {
		t.Fatalf("WebSocket early data or security was lost: %#v", options)
	}
}

func TestParseVMessPayloadRefusesRealityItCannotDescribe(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(`{"add":"vm.example","port":443,"id":"00000000-0000-4000-8000-000000000001","net":"tcp","tls":"reality"}`))
	if _, err := ParseSubscriptionLink("vmess://" + payload); err == nil {
		t.Fatal("a VMess object with Reality and no Reality parameters was imported as TLS")
	}
}

func TestGenerateSubscriptionLinkUsesTheCommonSpellings(t *testing.T) {
	const uuid = "00000000-0000-4000-8000-000000000001"
	tls := &option.OutboundTLSOptions{Enabled: true, ServerName: "cdn.example"}
	grpc := &option.V2RayTransportOptions{Type: C.V2RayTransportTypeGRPC, GRPCOptions: option.V2RayGRPCOptions{ServiceName: "svc"}}
	generate := func(outbound option.Outbound) url.Values {
		t.Helper()
		link, err := GenerateSubscriptionLink(outbound)
		if err != nil {
			t.Fatalf("%s: %v", outbound.Type, err)
		}
		linkURL, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		return linkURL.Query()
	}

	query := generate(option.Outbound{Type: C.TypeTrojan, Tag: "trojan", Options: &option.TrojanOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "trojan.example", ServerPort: 443}, Password: "secret",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls}, Transport: grpc,
	}})
	if query.Get("serviceName") != "svc" || query.Has("grpc-service-name") {
		t.Fatalf("Trojan gRPC service name was not written as serviceName: %v", query)
	}

	query = generate(option.Outbound{Type: C.TypeVLESS, Tag: "upgrade", Options: &option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "vless.example", ServerPort: 443}, UUID: uuid,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
		Transport:                   &option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTPUpgrade, HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{Host: "cdn.example", Path: "/up"}},
		DialerOptions:               option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true}},
	}})
	if query.Get("type") != "httpupgrade" || query.Get("path") != "/up" || query.Get("host") != "cdn.example" || query.Get("tfo") != "1" {
		t.Fatalf("HTTPUpgrade or TCP Fast Open was not written: %v", query)
	}

	query = generate(option.Outbound{Type: C.TypeHysteria, Tag: "hysteria", Options: &option.HysteriaOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "hy.example", ServerPort: 443}, AuthString: "auth",
		UpMbps: 10, DownMbps: 50, Obfs: "secret",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
	}})
	if query.Get("upmbps") != "10" || query.Get("downmbps") != "50" || query.Get("obfs") != "xplus" || query.Get("obfsParam") != "secret" {
		t.Fatalf("Hysteria bandwidth or obfuscation was not written as the URI scheme spells it: %v", query)
	}

	link, err := GenerateSubscriptionLink(option.Outbound{Type: C.TypeVMess, Tag: "vmess", Options: &option.VMessOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "vm.example", ServerPort: 443}, UUID: uuid, Transport: grpc,
	}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]string
	if err = json.Unmarshal(decoded, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["path"] != "svc" || payload["host"] != "" {
		t.Fatalf("VMess gRPC service name was not written to path: %v", payload)
	}
}

func TestLinkXHTTPExtraFollowsXrayInBothLinkForms(t *testing.T) {
	const uuid = "00000000-0000-4000-8000-000000000001"
	extra := `{"mode":"stream-one","xPaddingBytes":"200-400"}`
	outbound, err := ParseSubscriptionLink("vless://" + uuid + "@x.example:443?type=xhttp&path=/x&mode=packet-up&security=tls&extra=" + url.QueryEscape(extra))
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(*option.VLESSOutboundOptions).Transport.XHTTPOptions
	if options.Mode != "packet-up" || options.XPaddingBytes.From != 200 {
		t.Fatalf("a VLESS link read extra against Xray: mode %q padding %v", options.Mode, options.XPaddingBytes)
	}

	payload, err := json.Marshal(map[string]any{"add": "x.example", "port": 443, "id": uuid, "net": "xhttp", "path": "/x", "tls": "tls", "extra": extra})
	if err != nil {
		t.Fatal(err)
	}
	outbound, err = ParseSubscriptionLink("vmess://" + base64.StdEncoding.EncodeToString(payload))
	if err != nil {
		t.Fatal(err)
	}
	options = outbound.Options.(*option.VMessOutboundOptions).Transport.XHTTPOptions
	if options.Mode != "" && options.Mode != "auto" || options.XPaddingBytes.From != 200 {
		t.Fatalf("a VMess object read extra against Xray: mode %q padding %v", options.Mode, options.XPaddingBytes)
	}
}

func TestParseHysteria2LinkHopIntervalAsClashReadsIt(t *testing.T) {
	for value, expected := range map[string][2]time.Duration{
		"30":    {30 * time.Second, 0},
		"10-30": {10 * time.Second, 30 * time.Second},
		"45s":   {45 * time.Second, 0},
	} {
		outbound, err := ParseSubscriptionLink("hysteria2://secret@hy.example:443?mport=20000-30000&hop-interval=" + value + "#hop")
		if err != nil {
			t.Fatal(err)
		}
		options := outbound.Options.(*option.Hysteria2OutboundOptions)
		if time.Duration(options.HopInterval) != expected[0] || time.Duration(options.HopIntervalMax) != expected[1] {
			t.Fatalf("hop-interval=%s read as %v-%v", value, options.HopInterval, options.HopIntervalMax)
		}
	}
	if _, err := ParseSubscriptionLink("hysteria2://secret@hy.example:443?hop-interval=30-10#hop"); err == nil {
		t.Fatal("a hop interval range running backwards was accepted")
	}
}
