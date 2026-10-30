package link

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func parsedVLESS(t *testing.T, link string) *option.VLESSOutboundOptions {
	t.Helper()
	outbound, err := ParseSubscriptionLink(link)
	if err != nil {
		t.Fatalf("%s: %v", link, err)
	}
	return outbound.Options.(*option.VLESSOutboundOptions)
}

// Parameter names come in any case, and a link copied out of HTML has "&amp;" between them.
func TestLinkParameterNamesAsGeneratorsWriteThem(t *testing.T) {
	for _, link := range []string{
		"vless://" + xrayTestUUID + "@example.org:443?Security=tls&SNI=sni.example&Type=WS&Path=%2Fws#n",
		"vless://" + xrayTestUUID + "@example.org:443?security=tls&amp;sni=sni.example&amp;type=ws&amp;path=%2Fws#n",
		"vless://" + xrayTestUUID + "@example.org:443?security=TLS&serverName=sni.example&type=ws&path=%2Fws#n",
	} {
		options := parsedVLESS(t, link)
		if options.TLS == nil || options.TLS.ServerName != "sni.example" {
			t.Errorf("%s: TLS %+v", link, options.TLS)
		}
		if options.Transport == nil || options.Transport.Type != C.V2RayTransportTypeWebsocket || options.Transport.WebsocketOptions.Path != "/ws" {
			t.Errorf("%s: transport %+v", link, options.Transport)
		}
	}
}

// A Trojan password in base64 holds "/" and is not always escaped.
func TestLinkPasswordWithSlash(t *testing.T) {
	outbound, err := ParseSubscriptionLink("trojan://pa/ss+w=@example.org:443?sni=sni.example#n")
	if err != nil {
		t.Fatal(err)
	}
	options := outbound.Options.(*option.TrojanOutboundOptions)
	if options.Password != "pa/ss+w=" || options.Server != "example.org" || options.ServerPort != 443 {
		t.Fatalf("password %q, server %s:%d", options.Password, options.Server, options.ServerPort)
	}
}

func TestLinkVLESSValuesOfOtherClients(t *testing.T) {
	const reality = "&security=reality&sni=www.example.com&pbk=SSw7I859PPdN4DQ7fxV9fobXM61Ms3mqZRlIY1aJvHQ"
	if flow := parsedVLESS(t, "vless://"+xrayTestUUID+"@example.org:443?flow=xtls-rprx-vision-udp443"+reality+"#n").Flow; flow != "xtls-rprx-vision" {
		t.Errorf("flow %q, want plain Vision", flow)
	}
	for value, want := range map[string]string{"packet": "packetaddr", "xudp": "xudp", "none": ""} {
		encoding := parsedVLESS(t, "vless://"+xrayTestUUID+"@example.org:443?packetEncoding="+value+reality+"#n").PacketEncoding
		if got := ""; encoding != nil {
			got = *encoding
			if got != want {
				t.Errorf("packet encoding %s: %q, want %q", value, got, want)
			}
		} else if want != "" {
			t.Errorf("packet encoding %s: none, want %q", value, want)
		}
	}
	const setting = "mlkem768x25519plus.native.0rtt.SSw7I859PPdN4DQ7fxV9fobXM61Ms3mqZRlIY1aJvHQ"
	for value, want := range map[string]string{"aes-128-gcm": "", "auto": "", "none": "", setting: setting} {
		if encryption := parsedVLESS(t, "vless://"+xrayTestUUID+"@example.org:443?encryption="+value+reality+"#n").Encryption; encryption != want {
			t.Errorf("encryption %s: %q, want %q", value, encryption, want)
		}
	}
}

// XHTTP as v2rayA writes the mode, an extra escaped twice, and a range with fractions.
func TestLinkXHTTPForms(t *testing.T) {
	base := "vless://" + xrayTestUUID + "@example.org:443?security=tls&sni=sni.example&type=xhttp&path=%2Fx"
	if mode := parsedVLESS(t, base+"&mode=stream_one#n").Transport.XHTTPOptions.Mode; mode != "stream-one" {
		t.Errorf("mode %q", mode)
	}
	for _, extra := range []string{
		"%257B%2522xPaddingBytes%2522%253A%2522200-900%2522%257D",
		"%7B%22xPaddingBytes%22%3A%22200.0-900.0%22%7D",
		"%7B%22xPaddingBytes%22%3A%7B%22from%22%3A200%2C%22to%22%3A900%7D%7D",
	} {
		padding := parsedVLESS(t, base+"&extra="+extra+"#n").Transport.XHTTPOptions.XPaddingBytes
		if padding.From != 200 || padding.To != 900 {
			t.Errorf("extra %s: padding %v", extra, padding)
		}
	}
	if _, err := ParseSubscriptionLink(base + "&extra=%7B%22xPaddingBytes%22%3A%22200.5-900%22%7D#n"); err == nil {
		t.Error("a padding of 200.5 bytes was taken")
	}
}

// 3x-ui's subscription copies the panel's XMUX block into extra with an unset range as "",
// which Xray reads as 0.
func TestLinkXHTTPEmptyRangeIsZero(t *testing.T) {
	extra := `{"mode":"auto","xmux":{"maxConcurrency":"","maxConnections":3,"cMaxReuseTimes":0,` +
		`"hMaxRequestTimes":"600-900","hMaxReusableSecs":"1800-3000","hKeepAlivePeriod":0}}`
	link := "vless://" + xrayTestUUID + "@example.org:443?security=tls&sni=sni.example&type=xhttp&path=%2F&extra=" + url.QueryEscape(extra) + "#n"
	xmux := parsedVLESS(t, link).Transport.XHTTPOptions.Xmux
	if xmux == nil || xmux.MaxConcurrency != (option.Range[int]{}) || xmux.MaxConnections != (option.Range[int]{From: 3, To: 3}) {
		t.Errorf("xmux %+v", xmux)
	}
}

func TestLinkTLSOfOtherClients(t *testing.T) {
	const list = "AEX+DQBBtwAgACBnq8/sMmD3yl6v6TOKr4WgJz6Kj0nSUa8tR7+Tdbm5HwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="
	base := "vless://" + xrayTestUUID + "@example.org:443?security=tls&sni=sni.example"
	ech := parsedVLESS(t, base+"&ech="+list+"#n").TLS.ECH
	if ech == nil || !ech.Enabled || len(ech.Config) != 4 || ech.Config[0] != "-----BEGIN ECH CONFIGS-----" {
		t.Errorf("ECH from a list: %+v", ech)
	}
	ech = parsedVLESS(t, base+"&ech=cloudflare-ech.com%2Bhttps%3A%2F%2F1.1.1.1%2Fdns-query#n").TLS.ECH
	if ech == nil || !ech.Enabled || len(ech.Config) != 0 || ech.QueryServerName != "cloudflare-ech.com" {
		t.Errorf("ECH from DNS: %+v", ech)
	}
	const certificate = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	tls := parsedVLESS(t, base+"&nosni=1&cert="+url.QueryEscape(certificate)+"#n").TLS
	if !tls.DisableSNI || len(tls.Certificate) != 3 {
		t.Errorf("TLS %+v", tls)
	}
	if tls = parsedVLESS(t, base+"&cert=%2Fetc%2Fssl%2Fcert.pem#n").TLS; len(tls.Certificate) != 0 || tls.CertificatePath != "" {
		t.Errorf("a path in cert was taken: %+v", tls)
	}
}

func TestLinkHysteria2PortsParameter(t *testing.T) {
	outbound, err := ParseSubscriptionLink("hysteria2://secret@example.org:443?sni=sni.example&mport=1000-2000,3000#n")
	if err != nil {
		t.Fatal(err)
	}
	if ports := outbound.Options.(*option.Hysteria2OutboundOptions).ServerPorts; len(ports) != 2 || ports[0] != "1000:2000" || ports[1] != "3000:3000" {
		t.Fatalf("ports %v", ports)
	}
}

// v2rayN writes the user of a socks:// link as base64 of "user:password".
func TestLinkSOCKSUserInBase64(t *testing.T) {
	for link, want := range map[string][2]string{
		"socks://" + base64.StdEncoding.EncodeToString([]byte("user:pass")) + "@example.org:1080#n": {"user", "pass"},
		"socks5://user:pass@example.org:1080#n":                                                     {"user", "pass"},
		"socks://dXNlcg@example.org:1080#n":                                                         {"dXNlcg", ""},
	} {
		outbound, err := ParseSubscriptionLink(link)
		if err != nil {
			t.Fatal(err)
		}
		options := outbound.Options.(*option.SOCKSOutboundOptions)
		if options.Username != want[0] || options.Password != want[1] {
			t.Errorf("%s: %q %q", link, options.Username, options.Password)
		}
	}
}

// A node that could not connect is refused with the reason, not imported dead.
func TestLinkRefusesNodesThatCannotConnect(t *testing.T) {
	const shadowsocks = "ss://YWVzLTI1Ni1nY206cGFzcw@example.org:443"
	vless := "vless://" + xrayTestUUID + "@example.org:443?flow=xtls-rprx-vision"
	for _, link := range []string{
		"hysteria://example.org:443?protocol=faketcp&auth=secret#n",
		"hysteria://example.org:443?protocol=wechat-video&auth=secret#n",
		"hysteria://example.org:443?auth=secret&ca=%2Fetc%2Fssl%2Fca.pem#n",
		shadowsocks + "?type=ws&path=%2Fws#n",
		shadowsocks + "?security=tls&sni=sni.example#n",
		vless + "&security=tls&type=ws&path=%2Fws#n",
		vless + "&security=tls&type=grpc&serviceName=s#n",
		vless + "#n",
	} {
		if _, err := ParseSubscriptionLink(link); err == nil {
			t.Errorf("%s was taken", link)
		}
	}
	for _, link := range []string{
		"hysteria://example.org:443?protocol=udp&auth=secret#n",
		shadowsocks + "?plugin=obfs-local%3Bobfs%3Dhttp#n",
		vless + "&security=tls&sni=sni.example#n",
		vless + "&security=reality&sni=www.example.com&pbk=SSw7I859PPdN4DQ7fxV9fobXM61Ms3mqZRlIY1aJvHQ#n",
		vless + "&type=ws&path=%2Fws&encryption=mlkem768x25519plus.native.0rtt.SSw7I859PPdN4DQ7fxV9fobXM61Ms3mqZRlIY1aJvHQ#n",
	} {
		if _, err := ParseSubscriptionLink(link); err != nil {
			t.Errorf("%s: %v", link, err)
		}
	}
}

// downloadSettings in the extra of a link are the download leg as Xray-core reads it: stream
// settings of its own, with nothing taken from the upload.
func TestLinkXHTTPDownloadLeg(t *testing.T) {
	leg := func(fields string) string {
		return "vless://" + xrayTestUUID + "@up.example:443?security=tls&sni=cdn.example&type=xhttp&path=%2Fup&mode=packet-up&extra=" +
			url.QueryEscape(`{"downloadSettings":{`+fields+`}}`) + "#n"
	}
	download := parsedVLESS(t, leg(`"address":"down.example","port":8443,"network":"xhttp","security":"tls",
		"tlsSettings":{"serverName":"dl.example"},"xhttpSettings":{"path":"/down","host":"dl.example"}`)).Transport.XHTTPOptions.Download
	if download == nil || download.Server != "down.example" || download.ServerPort != 8443 || download.Path != "/down" || download.Host != "dl.example" {
		t.Fatalf("download %+v", download)
	}
	if download.TLS == nil || download.TLS.ServerName != "dl.example" || download.TLS.UTLS == nil || download.TLS.UTLS.Fingerprint != "chrome" {
		t.Fatalf("download TLS %+v", download.TLS)
	}
	if download.XPaddingBytes.From != 100 || download.XPaddingBytes.To != 1000 {
		t.Fatalf("download padding %v, want Xray's default", download.XPaddingBytes)
	}
	reality := parsedVLESS(t, leg(`"address":"down.example","port":443,"security":"reality",
		"realitySettings":{"serverName":"www.example.com","publicKey":"SSw7I859PPdN4DQ7fxV9fobXM61Ms3mqZRlIY1aJvHQ","shortId":"5a"}`)).Transport.XHTTPOptions.Download
	if reality == nil || reality.TLS == nil || reality.TLS.Reality == nil || reality.TLS.Reality.ShortID != "5a" {
		t.Fatalf("REALITY download %+v", reality)
	}
	for _, fields := range []string{
		`"address":"down.example","network":"xhttp"`,
		`"address":"down.example","port":443,"network":"ws"`,
		`"address":"down.example","port":443,"sockopt":{"dialerProxy":"other"}`,
	} {
		if _, err := ParseSubscriptionLink(leg(fields)); err == nil {
			t.Errorf("%s was taken", fields)
		}
	}
	if _, err := ParseSubscriptionLink(strings.Replace(leg(`"address":"down.example","port":443`), "packet-up", "stream-one", 1)); err == nil {
		t.Error("a download leg in stream-one was taken")
	}
}

// vcn, Xray-core's verifyPeerCertByName, names what the certificate is verified by instead of
// the SNI; REALITY verifies its own way.
func TestLinkVerifyServerName(t *testing.T) {
	base := "vless://" + xrayTestUUID + "@example.org:443?sni=front.example&vcn=real.example,%20other.example"
	if names := parsedVLESS(t, base+"&security=tls#n").TLS.VerifyServerName; strings.Join(names, " ") != "real.example other.example" {
		t.Errorf("VLESS: %q", names)
	}
	if names := parsedVLESS(t, base+"&security=reality&pbk=k#n").TLS.VerifyServerName; len(names) != 0 {
		t.Errorf("REALITY took %q", names)
	}
	outbound, err := ParseSubscriptionLink("hysteria2://secret@example.org:443?sni=front.example&vcn=real.example#n")
	if err != nil {
		t.Fatal(err)
	}
	if names := outbound.Options.(*option.Hysteria2OutboundOptions).TLS.VerifyServerName; strings.Join(names, " ") != "real.example" {
		t.Errorf("Hysteria2: %q", names)
	}
	payload := base64.RawStdEncoding.EncodeToString([]byte(`{"v":"2","ps":"n","add":"example.org","port":"443","id":"` + xrayTestUUID + `","net":"tcp","tls":"tls","sni":"front.example","vcn":"real.example"}`))
	outbound, err = ParseSubscriptionLink("vmess://" + payload)
	if err != nil {
		t.Fatal(err)
	}
	if names := outbound.Options.(*option.VMessOutboundOptions).TLS.VerifyServerName; strings.Join(names, " ") != "real.example" {
		t.Errorf("VMess: %q", names)
	}
	extra := url.QueryEscape(`{"downloadSettings":{"address":"down.example","port":443,"security":"tls","tlsSettings":{"serverName":"front.example","verifyPeerCertByName":"real.example"}}}`)
	download := parsedVLESS(t, "vless://"+xrayTestUUID+"@up.example:443?security=tls&type=xhttp&path=%2Fx&mode=packet-up&extra="+extra+"#n").Transport.XHTTPOptions.Download
	if names := download.TLS.VerifyServerName; strings.Join(names, " ") != "real.example" {
		t.Errorf("XHTTP download leg: %q", names)
	}
}

// A fingerprint is a Client Hello of TCP: an XHTTP leg over HTTP/3 has none, or every dial fails.
func TestLinkXHTTPOverHTTP3HasNoFingerprint(t *testing.T) {
	extra := url.QueryEscape(`{"downloadSettings":{"address":"down.example","port":443,"security":"tls","tlsSettings":{"alpn":["h3"],"fingerprint":"chrome"}}}`)
	options := parsedVLESS(t, "vless://"+xrayTestUUID+"@up.example:443?security=tls&sni=up.example&alpn=h3&fp=firefox&type=xhttp&path=%2Fx&mode=packet-up&extra="+extra+"#n")
	if options.TLS.UTLS != nil {
		t.Errorf("the HTTP/3 leg kept the fingerprint %+v", options.TLS.UTLS)
	}
	if download := options.Transport.XHTTPOptions.Download; download.TLS.UTLS != nil {
		t.Errorf("the HTTP/3 download leg kept the fingerprint %+v", download.TLS.UTLS)
	}
	for _, query := range []string{
		"security=tls&alpn=h2",
		"security=tls&alpn=h3%2Ch2",
		"security=reality&pbk=SSw7I859PPdN4DQ7fxV9fobXM61Ms3mqZRlIY1aJvHQ&sid=5a&alpn=h3",
	} {
		if tls := parsedVLESS(t, "vless://"+xrayTestUUID+"@up.example:443?"+query+"&type=xhttp&path=%2Fx#n").TLS; tls.UTLS == nil {
			t.Errorf("%s: an HTTP/2 leg lost its fingerprint", query)
		}
	}
}
