package parser_test

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser"
	"github.com/sagernet/sing-box/parser/subscription"
)

// The fixtures under testdata are the shapes real providers hand out, with the
// addresses and credentials replaced: an array of complete Xray configurations
// (one document per server, each with its own freedom and blackhole outbound),
// a Clash configuration carrying the option spellings generators actually emit,
// and a list of share links in the forms they arrive in.

func readFixture(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func parseFixture(t *testing.T, name string) subscription.Result {
	t.Helper()
	result, err := parser.ParseSubscription(include.Context(context.Background()), readFixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func tags(result subscription.Result) []string {
	names := make([]string, 0, len(result.Outbounds))
	for _, outbound := range result.Outbounds {
		names = append(names, outbound.Tag)
	}
	return names
}

func find(t *testing.T, result subscription.Result, tag string) option.Outbound {
	t.Helper()
	for _, outbound := range result.Outbounds {
		if outbound.Tag == tag {
			return outbound
		}
	}
	t.Fatalf("server %q was not imported, got %q", tag, tags(result))
	return option.Outbound{}
}

func skippedReason(result subscription.Result, name string) string {
	for _, skipped := range result.Skipped {
		if strings.Contains(skipped.Label, name) {
			return skipped.Reason.Error()
		}
	}
	return ""
}

func TestParseXraySubscriptionFixture(t *testing.T) {
	result := parseFixture(t, "xray-documents.json")
	// Each document carries one server beside a freedom and a blackhole outbound, named by the
	// document remarks. The last document is the other panel shape: several servers with routing
	// rules, of which only the first is the one the document dials.
	wantServers := []string{"🇸🇪SWE-xhttp", "🇳🇱Neth-tcp", "🇫🇮 Finland"}
	got := tags(result)
	if len(got) != len(wantServers) {
		t.Fatalf("imported servers = %q, want %q", got, wantServers)
	}
	for index, tag := range wantServers {
		if got[index] != tag {
			t.Fatalf("server %d = %q, want %q", index, got[index], tag)
		}
	}
	routed := find(t, result, "🇫🇮 Finland").Options.(*option.VLESSOutboundOptions)
	if routed.Server != "fi.example.test" {
		t.Fatalf("the document was named after an alternate: %s", routed.Server)
	}
	if len(result.Skipped) != 0 {
		t.Fatalf("plumbing outbounds were reported as failures: %v", result.Skipped)
	}
	options := find(t, result, "🇸🇪SWE-xhttp").Options.(*option.VLESSOutboundOptions)
	if options.Server != "swe.example.test" || options.ServerPort != 443 {
		t.Fatalf("endpoint = %s:%d", options.Server, options.ServerPort)
	}
	if options.TLS == nil || !options.TLS.Enabled || options.TLS.UTLS.Fingerprint != "chrome" {
		t.Fatalf("TLS = %#v", options.TLS)
	}
	xhttp := options.Transport.XHTTPOptions
	if options.Transport.Type != C.V2RayTransportTypeXHTTP || xhttp.Mode != "packet-up" || xhttp.Path != "/update" {
		t.Fatalf("transport = %#v", options.Transport)
	}
	// The document writes these in the extra object; every one of them decides
	// what the server is asked for, so losing them means asking for the wrong
	// resource.
	if xhttp.XPaddingKey != "_dc" || xhttp.XPaddingHeader != "X-Cache" || xhttp.XPaddingPlacement != "queryInHeader" ||
		xhttp.XPaddingMethod != "tokenish" || !xhttp.XPaddingObfsMode || xhttp.UplinkHTTPMethod != "GET" {
		t.Fatalf("XHTTP padding settings were lost: %#v", xhttp)
	}
	if xhttp.Xmux == nil || xhttp.Xmux.MaxConnections.To != 2 || xhttp.Xmux.HMaxRequestTimes.From != 100 {
		t.Fatalf("XHTTP xmux settings were lost: %#v", xhttp.Xmux)
	}
	// The settings a server assumes when the document leaves them out have to be
	// filled in, because the parser builds the options rather than decoding them.
	if xhttp.SessionPlacement != "path" || xhttp.SeqPlacement != "path" || xhttp.UplinkDataKey != "X-Data" {
		t.Fatalf("XHTTP defaults were not applied: %#v", xhttp)
	}
	plain := find(t, result, "🇳🇱Neth-tcp").Options.(*option.VLESSOutboundOptions)
	if plain.Transport != nil {
		t.Fatalf("a raw connection got a transport: %#v", plain.Transport)
	}
	if plain.TLS == nil || len(plain.TLS.ALPN) != 1 || plain.TLS.ALPN[0] != "http/1.1" {
		t.Fatalf("TLS = %#v", plain.TLS)
	}
}

func TestParseClashSubscriptionFixture(t *testing.T) {
	result := parseFixture(t, "clash-proxies.yaml")
	want := []string{
		"🇪🇪 Estonia #1", "🇸🇬 Singapore", "🇺🇸 Los Angeles", "🇯🇵 Tokyo ws",
		"🇩🇪 Frankfurt hop", "🇳🇱 Amsterdam relay", "Direct chain",
	}
	got := tags(result)
	if len(got) != len(want) {
		t.Fatalf("imported servers = %q, want %q", got, want)
	}
	for index, tag := range want {
		if got[index] != tag {
			t.Fatalf("server %d = %q, want %q", index, got[index], tag)
		}
	}

	// A key the protocol does not define does not change how the connection is
	// made, and Clash ignores it as well.
	reality := find(t, result, "🇪🇪 Estonia #1").Options.(*option.VLESSOutboundOptions)
	if reality.TLS == nil || reality.TLS.Reality == nil || reality.TLS.Reality.ShortID != "3fca1964759edc55" {
		t.Fatalf("a post-quantum hint in reality-opts lost the server: %#v", reality.TLS)
	}
	shadowsocks := find(t, result, "🇸🇬 Singapore").Options.(*option.ShadowsocksOutboundOptions)
	if shadowsocks.ServerPort != 8388 || shadowsocks.Method != "chacha20-ietf-poly1305" {
		t.Fatalf("a quoted port or a stray TLS key lost the server: %#v", shadowsocks)
	}
	// raw is the current spelling of the plain TCP connection.
	if transport := find(t, result, "🇺🇸 Los Angeles").Options.(*option.VLESSOutboundOptions).Transport; transport != nil {
		t.Fatalf("raw got a transport: %#v", transport)
	}

	// The early data length lives in the path and has to come out of it: asking
	// for /tokyo?ed=2048 is asking for a resource the server does not serve.
	websocket := find(t, result, "🇯🇵 Tokyo ws").Options.(*option.VMessOutboundOptions).Transport
	if websocket.WebsocketOptions.Path != "/tokyo" || websocket.WebsocketOptions.MaxEarlyData != 2048 ||
		websocket.WebsocketOptions.EarlyDataHeaderName != "Sec-WebSocket-Protocol" {
		t.Fatalf("websocket early data was not taken out of the path: %#v", websocket.WebsocketOptions)
	}

	// Clash counts the hop interval in seconds and writes the speeds with a unit.
	hysteria := find(t, result, "🇩🇪 Frankfurt hop").Options.(*option.Hysteria2OutboundOptions)
	if time.Duration(hysteria.HopInterval) != 30*time.Second {
		t.Fatalf("hop interval = %s, want 30s", time.Duration(hysteria.HopInterval))
	}
	if hysteria.UpMbps != 50 || hysteria.DownMbps != 200 {
		t.Fatalf("speeds = %d/%d Mbps, want 50/200", hysteria.UpMbps, hysteria.DownMbps)
	}
	if len(hysteria.ServerPorts) != 1 || hysteria.ServerPorts[0] != "20000:30000" {
		t.Fatalf("port hopping range = %q", hysteria.ServerPorts)
	}

	// A chain keeps its base, and dialling through the entry that stands for a
	// plain connection means no detour at all.
	if detour := find(t, result, "🇳🇱 Amsterdam relay").Options.(*option.TrojanOutboundOptions).Detour; detour != "🇪🇪 Estonia #1" {
		t.Fatalf("chain detour = %q", detour)
	}
	if detour := find(t, result, "Direct chain").Options.(*option.SOCKSOutboundOptions).Detour; detour != "" {
		t.Fatalf("detour through the direct entry = %q, want none", detour)
	}

	// A server whose wire protocol sing-box cannot speak is left out with a
	// reason rather than imported as something else.
	for name, want := range map[string]string{
		"TUIC v4 node":    "TUIC v4",
		"SOCKS over TLS":  "SOCKS over TLS",
		"ShadowTLS node":  "shadow-tls-opts",
		"HTTP masquerade": "HTTP masquerading",
	} {
		if reason := skippedReason(result, name); !strings.Contains(reason, want) {
			t.Fatalf("%s was skipped with %q, want a reason naming %q", name, reason, want)
		}
	}
}

func TestParseLinkSubscriptionFixture(t *testing.T) {
	result := parseFixture(t, "links.txt")
	want := []string{
		"🇹🇭Thailand", "sip002", "🇪🇪 Estonia", "🇷🇺XHTTP", "grpc",
		"websocket", "🇪🇺 Europe", "VMess ws",
	}
	if got := tags(result); len(got) != len(want) {
		t.Fatalf("imported servers = %q, want %q", got, want)
	}

	// The original Shadowsocks link encodes the whole of method:password@host:port.
	legacy := find(t, result, "🇹🇭Thailand").Options.(*option.ShadowsocksOutboundOptions)
	if legacy.Server != "ss1.example.test" || legacy.ServerPort != 21123 ||
		legacy.Method != "chacha20-ietf-poly1305" || legacy.Password != "00000000-0000-4000-8000-000000000001" {
		t.Fatalf("the encoded Shadowsocks link was read wrong: %#v", legacy)
	}

	// The settings in a share link's extra object decide what the server is
	// asked for, and the object arrives verbatim rather than encoded.
	xhttp := find(t, result, "🇷🇺XHTTP").Options.(*option.VLESSOutboundOptions).Transport.XHTTPOptions
	if xhttp.XPaddingKey != "q" || xhttp.XPaddingPlacement != "query" || xhttp.UplinkHTTPMethod != "DELETE" ||
		xhttp.SessionPlacement != "query" || xhttp.SessionKey != "sid" || xhttp.SeqPlacement != "query" || xhttp.SeqKey != "offset" {
		t.Fatalf("XHTTP extra settings were lost: %#v", xhttp)
	}

	websocket := find(t, result, "websocket").Options.(*option.VLESSOutboundOptions).Transport
	if websocket.WebsocketOptions.Path != "/lovelive" || websocket.WebsocketOptions.MaxEarlyData != 2048 {
		t.Fatalf("websocket early data was not taken out of the path: %#v", websocket.WebsocketOptions)
	}

	// The VMess object names every key whether it is set or not.
	vmess := find(t, result, "VMess ws").Options.(*option.VMessOutboundOptions)
	if vmess.TLS == nil || vmess.TLS.ServerName != "vm.example.test" || len(vmess.TLS.ALPN) != 0 {
		t.Fatalf("empty fields of the VMess object were taken as values: %#v", vmess.TLS)
	}
	if vmess.Transport.WebsocketOptions.Path != "/vmess" || vmess.Transport.WebsocketOptions.MaxEarlyData != 2560 {
		t.Fatalf("websocket early data was not taken out of the path: %#v", vmess.Transport.WebsocketOptions)
	}

	if reason := skippedReason(result, "juicity"); !strings.Contains(reason, "unsupported scheme") {
		t.Fatalf("an unsupported scheme was skipped with %q", reason)
	}
	// sing-box cannot dial ShadowsocksR at all - its outbound is a stub that
	// refuses to build - so such a link is left out with the reason rather than
	// imported as a server that could never connect.
	if reason := skippedReason(result, "ssr"); !strings.Contains(reason, "ShadowsocksR") {
		t.Fatalf("a ShadowsocksR link was skipped with %q", reason)
	}
}

func TestParseSubscriptionRecognisesTheFormat(t *testing.T) {
	ctx := include.Context(context.Background())
	for name, content := range map[string]string{
		"sing-box": `{"outbounds": [{"type": "socks", "tag": "box", "server": "127.0.0.1", "server_port": 1080}]}`,
		"SIP008":   `{"version": 1, "servers": [{"remarks": "sip008", "server": "1.2.3.4", "server_port": 8388, "password": "p", "method": "aes-256-gcm"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := parser.ParseSubscription(ctx, content)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Outbounds) != 1 {
				t.Fatalf("imported servers = %q", tags(result))
			}
		})
	}
	// A document nobody recognises is reported as such, instead of as the
	// complaints of every parser in turn.
	_, err := parser.ParseSubscription(ctx, "just some text\n")
	if err == nil || !strings.Contains(err.Error(), "unrecognized") {
		t.Fatalf("unrecognised content reported as %v", err)
	}
	// A configuration whose every server is refused is answered by the parser that recognised it,
	// naming what was wrong.
	refused, err := parser.ParseSubscription(ctx,
		"proxies:\n  - {name: v4, type: tuic, server: a.example.test, port: 443, token: legacy}\n")
	if err == nil {
		t.Fatal("a configuration without a usable server was reported as a success")
	}
	if len(refused.Skipped) != 1 || !strings.Contains(refused.Skipped[0].Reason.Error(), "TUIC v4") {
		t.Fatalf("the reason the servers were refused was lost: %v", refused.Skipped)
	}
	// A provider is free to wrap any format in base64, not only a list of links.
	encoded := base64.StdEncoding.EncodeToString([]byte(readFixture(t, "clash-proxies.yaml")))
	result, err := parser.ParseSubscription(ctx, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outbounds) != 7 {
		t.Fatalf("imported servers from the encoded Clash configuration = %q", tags(result))
	}
}

func TestParseSubscriptionDropsChainsWithoutTheirBase(t *testing.T) {
	result, err := parser.ParseSubscription(include.Context(context.Background()), `
proxies:
  - { name: base, type: socks5, server: 127.0.0.1, port: 1080, tls: true }
  - { name: chained, type: socks5, server: 127.0.0.1, port: 1081, dialer-proxy: base }
  - { name: chained-twice, type: socks5, server: 127.0.0.1, port: 1082, dialer-proxy: chained }
  - { name: external, type: socks5, server: 127.0.0.1, port: 1083, dialer-proxy: user-configured }
  - { name: leaf, type: socks5, server: 127.0.0.1, port: 1084 }
`)
	if err != nil {
		t.Fatal(err)
	}
	// base cannot be imported, so nothing that dials through it is imported
	// either; a detour naming something outside the subscription is left alone,
	// because the user's own configuration may well provide it.
	if got := tags(result); len(got) != 2 || got[0] != "external" || got[1] != "leaf" {
		t.Fatalf("imported servers = %q, want external and leaf", got)
	}
	for _, name := range []string{"chained", "chained-twice"} {
		if reason := skippedReason(result, name); reason == "" {
			t.Fatalf("%s was dropped without a reason: %v", name, result.Skipped)
		}
	}
}

func TestParseBoxSubscriptionFixture(t *testing.T) {
	// A panel that serves sing-box writes a whole configuration: the servers
	// come with a selector naming them and a direct outbound beside them, and
	// neither of those is a server.
	result := parseFixture(t, "singbox-outbounds.json")
	want := []string{"🇪🇪 Estonia", "🇱🇻 Latvia", "🇩🇪 Germany"}
	got := tags(result)
	if len(got) != len(want) {
		t.Fatalf("imported servers = %q, want %q", got, want)
	}
	for index, tag := range want {
		if got[index] != tag {
			t.Fatalf("server %d = %q, want %q", index, got[index], tag)
		}
	}
	if len(result.Skipped) != 0 {
		t.Fatalf("the selector and the direct outbound were reported as failures: %v", result.Skipped)
	}
	options := find(t, result, "🇪🇪 Estonia").Options.(*option.VLESSOutboundOptions)
	if options.Flow != "xtls-rprx-vision" || options.TLS == nil || options.TLS.Reality == nil ||
		options.TLS.Reality.ShortID != "3fca1964759edc55" || options.TLS.UTLS.Fingerprint != "firefox" {
		t.Fatalf("the server was read wrong: %#v", options)
	}
}

func TestParseSIP008SubscriptionFixture(t *testing.T) {
	result := parseFixture(t, "sip008-servers.json")
	want := []string{"🇩🇪 Frankfurt", "🇸🇬 Singapore"}
	got := tags(result)
	if len(got) != len(want) {
		t.Fatalf("imported servers = %q, want %q", got, want)
	}
	// A quoted port and keys the format does not define are both written by
	// real generators, and neither changes how the server is dialled.
	singapore := find(t, result, "🇸🇬 Singapore").Options.(*option.ShadowsocksOutboundOptions)
	if singapore.ServerPort != 8389 || singapore.Plugin != "obfs-local" ||
		singapore.PluginOptions != "obfs=http;obfs-host=www.bing.com" {
		t.Fatalf("the server was read wrong: %#v", singapore)
	}
	if reason := skippedReason(result, "no method"); reason == "" {
		t.Fatalf("an incomplete server was dropped without a reason: %v", result.Skipped)
	}
}

func TestParseSubscriptionTellsAnEmptyOneFromABrokenOne(t *testing.T) {
	ctx := include.Context(context.Background())
	// An empty configuration, one whose servers could not be read, and content in no format are three
	// different answers.
	for name, content := range map[string]string{
		"an empty Clash configuration":     "proxies: []\nrules: []\n",
		"a sing-box skeleton":              `{"outbounds": [{"type": "direct", "tag": "direct"}]}`,
		"an Xray document without servers": `{"outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}]}`,
		// An empty document names no format, so no parser claims it.
		"an empty JSON array":  "[]",
		"an empty JSON object": "{}",
		"an empty body":        "  \n ",
	} {
		t.Run(name, func(t *testing.T) {
			result, err := parser.ParseSubscription(ctx, content)
			if err == nil {
				t.Fatal("an empty subscription was reported as a success")
			}
			if len(result.Skipped) != 0 {
				t.Fatalf("an empty subscription reported failures: %v", result.Skipped)
			}
			if !strings.Contains(err.Error(), "lists no server") {
				t.Fatalf("an empty subscription was reported as %v", err)
			}
		})
	}
}

// Remnawave answers an ended account, a device over its limit and an account without hosts with
// entries at 0.0.0.0:1 named after its notice, in the format the client asked for.
func TestParseSubscriptionTakesNoNotesForServers(t *testing.T) {
	ctx := include.Context(context.Background())
	const uuid = "00000000-0000-0000-0000-000000000000"
	for name, content := range map[string]string{
		"share links": "vless://" + uuid + "@0.0.0.0:1?encryption=none&security=none&type=tcp#%E2%8C%9B%20Subscription%20expired\n" +
			"vless://" + uuid + "@0.0.0.0:1?encryption=none&security=none&type=tcp#Contact%20support\n",
		"a sing-box configuration": `{"outbounds": [` +
			`{"type": "selector", "tag": "proxy", "outbounds": ["⌛ Subscription expired", "Contact support"]},` +
			`{"type": "vless", "tag": "⌛ Subscription expired", "server": "0.0.0.0", "server_port": 1, "uuid": "` + uuid + `"},` +
			`{"type": "vless", "tag": "Contact support", "server": "0.0.0.0", "server_port": 1, "uuid": "` + uuid + `"},` +
			`{"type": "direct", "tag": "direct"}]}`,
		"a Clash configuration": "proxies:\n" +
			"  - {name: \"⌛ Subscription expired\", type: vless, server: 0.0.0.0, port: 1, uuid: " + uuid + ", network: tcp}\n" +
			"  - {name: \"Contact support\", type: vless, server: 0.0.0.0, port: 1, uuid: " + uuid + ", network: tcp}\n",
	} {
		t.Run(name, func(t *testing.T) {
			result, err := parser.ParseSubscription(ctx, content)
			if err == nil {
				t.Fatalf("notes were imported as servers: %q", tags(result))
			}
			if !strings.Contains(err.Error(), "lists no server, only notes: ⌛ Subscription expired; Contact support") {
				t.Fatalf("the notes were reported as %v", err)
			}
			if len(result.Outbounds) != 0 {
				t.Fatalf("an error came with servers: %q", tags(result))
			}
		})
	}

	mixed := "vless://" + uuid + "@0.0.0.0:1?encryption=none&security=none&type=tcp#Expires%202026-12-01\n" +
		"vless://11111111-1111-1111-1111-111111111111@203.0.113.1:443?encryption=none&security=none&type=tcp#Server\n"
	result, err := parser.ParseSubscription(ctx, mixed)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outbounds) != 2 {
		t.Fatalf("a list with a note among its servers was read as %q", tags(result))
	}
}
