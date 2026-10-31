package link

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	"github.com/sagernet/sing-box/parser/xhttp"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
)

func GenerateSubscriptionLink(outbound option.Outbound) (string, error) {
	link, err := generateSubscriptionLink(outbound)
	if err != nil {
		return "", err
	}
	parsed, err := ParseSubscriptionLink(link)
	if err != nil {
		return "", E.Cause(err, "generated link cannot be parsed")
	}
	equal, err := shareLinkOutboundsEqual(outbound, parsed)
	if err != nil {
		return "", err
	}
	if !equal {
		return "", E.New(outbound.Type, " outbound contains options that cannot be represented safely as a share link")
	}
	return link, nil
}

func generateSubscriptionLink(outbound option.Outbound) (string, error) {
	switch outbound.Type {
	case C.TypeVLESS:
		return generateVLESSLink(outbound)
	case C.TypeVMess:
		return generateVMessLink(outbound)
	case C.TypeTrojan:
		return generateTrojanLink(outbound)
	case C.TypeShadowsocks:
		return generateShadowsocksLink(outbound)
	case C.TypeSOCKS:
		return generateSOCKSLink(outbound)
	case C.TypeHTTP:
		return generateHTTPLink(outbound)
	case C.TypeHysteria2:
		return generateHysteria2Link(outbound)
	case C.TypeTUIC:
		return generateTUICLink(outbound)
	case C.TypeHysteria:
		return generateHysteriaLink(outbound)
	case C.TypeAnyTLS:
		return generateAnyTLSLink(outbound)
	case C.TypeNaive:
		return generateNaiveLink(outbound)
	case C.TypeMieru:
		return generateMieruLink(outbound)
	case C.TypeTrustTunnel:
		return generateTrustTunnelLink(outbound)
	default:
		return "", E.New("unsupported outbound type: ", outbound.Type)
	}
}

func generateAnyTLSLink(outbound option.Outbound) (string, error) {
	options, loaded := outbound.Options.(*option.AnyTLSOutboundOptions)
	if !loaded || options.Password == "" {
		return "", E.New("invalid AnyTLS outbound")
	}
	u, err := shareURL("anytls", options.ServerOptions, url.User(options.Password), outbound.Tag)
	if err != nil {
		return "", err
	}
	query := u.Query()
	addTLSQuery(query, options.TLS, false)
	addXrayClientTLSQuery(query, options.TLS, nil)
	addTCPFastOpenQuery(query, options.DialerOptions)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func generateNaiveLink(outbound option.Outbound) (string, error) {
	options, loaded := outbound.Options.(*option.NaiveOutboundOptions)
	if !loaded || options.Username == "" {
		return "", E.New("invalid Naive outbound")
	}
	scheme := "naive+https"
	if options.QUIC {
		scheme = "naive+quic"
	}
	u, err := shareURL(scheme, options.ServerOptions, url.UserPassword(options.Username, options.Password), outbound.Tag)
	if err != nil {
		return "", err
	}
	query := u.Query()
	addTLSQuery(query, options.TLS, false)
	if len(options.ExtraHeaders) > 0 {
		names := make([]string, 0, len(options.ExtraHeaders))
		for name := range options.ExtraHeaders {
			names = append(names, name)
		}
		sort.Strings(names)
		var lines []string
		for _, name := range names {
			for _, value := range options.ExtraHeaders[name] {
				lines = append(lines, name+": "+value)
			}
		}
		query.Set("extra-headers", strings.Join(lines, "\n"))
	}
	if options.UDPOverTCP != nil && options.UDPOverTCP.Enabled && options.UDPOverTCP.Version != 0 {
		query.Set("uot", strconv.Itoa(int(options.UDPOverTCP.Version)))
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

// The mieru link is the format of the mieru project itself: the ports live in the
// query next to a transport each, and a profile name is required even though the
// outbound has none, so the tag stands in for it.
func generateMieruLink(outbound option.Outbound) (string, error) {
	options, loaded := outbound.Options.(*option.MieruOutboundOptions)
	if !loaded || options.UserName == "" || options.Password == "" {
		return "", E.New("invalid Mieru outbound")
	}
	if options.Server == "" {
		return "", E.New("missing server")
	}
	if options.Transport != "TCP" && options.Transport != "UDP" {
		return "", E.New("invalid mieru transport: ", options.Transport)
	}
	profile := outbound.Tag
	if profile == "" {
		profile = C.TypeMieru
	}
	query := url.Values{}
	query.Set("profile", profile)
	if options.ServerPort != 0 {
		query.Add("port", strconv.Itoa(int(options.ServerPort)))
		query.Add("protocol", options.Transport)
	}
	for _, portRange := range options.ServerPortRanges {
		query.Add("port", portRange)
		query.Add("protocol", options.Transport)
	}
	if len(query["port"]) == 0 {
		return "", E.New("missing server port")
	}
	if options.Multiplexing != "" {
		query.Set("multiplexing", options.Multiplexing)
	}
	if options.TrafficPattern != "" {
		query.Set("traffic-pattern", options.TrafficPattern)
	}
	u := &url.URL{
		Scheme:   "mierus",
		User:     url.UserPassword(options.UserName, options.Password),
		Host:     options.Server,
		RawQuery: query.Encode(),
		Fragment: outbound.Tag,
	}
	return u.String(), nil
}
func generateHTTPLink(outbound option.Outbound) (string, error) {
	options, loaded := outbound.Options.(*option.HTTPOutboundOptions)
	if !loaded {
		return "", E.New("invalid HTTP outbound")
	}
	var user *url.Userinfo
	if options.Password != "" {
		user = url.UserPassword(options.Username, options.Password)
	} else if options.Username != "" {
		user = url.User(options.Username)
	}
	scheme := "http"
	if options.TLS != nil && options.TLS.Enabled {
		scheme = "https"
	}
	u, err := shareURL(scheme, options.ServerOptions, user, outbound.Tag)
	if err != nil {
		return "", err
	}
	if options.Path != "" {
		u.Path, err = url.PathUnescape(options.Path)
		if err != nil {
			return "", E.Cause(err, "invalid HTTP path")
		}
		u.RawPath = options.Path
	}
	return u.String(), nil
}

func generateVLESSLink(outbound option.Outbound) (string, error) {
	options, loaded := outbound.Options.(*option.VLESSOutboundOptions)
	if !loaded || options.UUID == "" {
		return "", E.New("invalid VLESS outbound")
	}
	u, err := shareURL("vless", options.ServerOptions, url.User(options.UUID), outbound.Tag)
	if err != nil {
		return "", err
	}
	query := u.Query()
	addTLSQuery(query, options.TLS, true)
	if err = addV2RayTransportQuery(query, options.Transport); err != nil {
		return "", err
	}
	addXrayClientTLSQuery(query, options.TLS, options.Transport)
	addTCPFastOpenQuery(query, options.DialerOptions)
	if options.Encryption != "" && options.Encryption != "none" {
		query.Set("encryption", options.Encryption)
	}
	if options.Flow != "" {
		query.Set("flow", options.Flow)
	}
	if options.PacketEncoding != nil && *options.PacketEncoding != "" {
		query.Set("packetEncoding", *options.PacketEncoding)
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func generateTrojanLink(outbound option.Outbound) (string, error) {
	options, loaded := outbound.Options.(*option.TrojanOutboundOptions)
	if !loaded || options.Password == "" {
		return "", E.New("invalid Trojan outbound")
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return "", E.New("plaintext Trojan cannot be represented as a share link")
	}
	u, err := shareURL("trojan", options.ServerOptions, url.User(options.Password), outbound.Tag)
	if err != nil {
		return "", err
	}
	query := u.Query()
	addTLSQuery(query, options.TLS, true)
	if err = addV2RayTransportQuery(query, options.Transport); err != nil {
		return "", err
	}
	addXrayClientTLSQuery(query, options.TLS, options.Transport)
	addTCPFastOpenQuery(query, options.DialerOptions)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func generateShadowsocksLink(outbound option.Outbound) (string, error) {
	options, loaded := outbound.Options.(*option.ShadowsocksOutboundOptions)
	if !loaded || options.Method == "" || options.Password == "" {
		return "", E.New("invalid Shadowsocks outbound")
	}
	u, err := shareURL("ss", options.ServerOptions, nil, outbound.Tag)
	if err != nil {
		return "", err
	}
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(options.Method + ":" + options.Password))
	u.Opaque = "//" + userinfo + "@" + u.Host
	u.Host = ""
	if options.Plugin != "" {
		plugin := options.Plugin
		if options.PluginOptions != "" {
			plugin += ";" + options.PluginOptions
		}
		query := u.Query()
		query.Set("plugin", plugin)
		u.RawQuery = query.Encode()
	}
	return u.String(), nil
}

func generateSOCKSLink(outbound option.Outbound) (string, error) {
	options, loaded := outbound.Options.(*option.SOCKSOutboundOptions)
	if !loaded {
		return "", E.New("invalid SOCKS outbound")
	}
	switch options.Version {
	case "", "4", "4a", "5":
	default:
		return "", E.New("unsupported SOCKS version: ", options.Version)
	}
	scheme := "socks5"
	if options.Version == "4" {
		scheme = "socks4"
	} else if options.Version == "4a" {
		scheme = "socks4a"
	}
	var user *url.Userinfo
	if options.Username != "" {
		if options.Password == "" {
			user = url.User(options.Username)
		} else {
			user = url.UserPassword(options.Username, options.Password)
		}
	}
	u, err := shareURL(scheme, options.ServerOptions, user, outbound.Tag)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func generateHysteria2Link(outbound option.Outbound) (string, error) {
	options, loaded := outbound.Options.(*option.Hysteria2OutboundOptions)
	if !loaded || options.Password == "" {
		return "", E.New("invalid Hysteria2 outbound")
	}
	if len(options.ServerPorts) != 0 {
		return "", E.New("port hopping cannot be represented safely as a share link")
	}
	u, err := shareURL("hysteria2", options.ServerOptions, url.User(options.Password), outbound.Tag)
	if err != nil {
		return "", err
	}
	query := u.Query()
	addTLSQuery(query, options.TLS, false)
	addTCPFastOpenQuery(query, options.DialerOptions)
	if options.UpMbps != 0 {
		query.Set("up", strconv.Itoa(options.UpMbps))
	}
	if options.DownMbps != 0 {
		query.Set("down", strconv.Itoa(options.DownMbps))
	}
	if options.Obfs != nil {
		if options.Obfs.Type != "" {
			query.Set("obfs", options.Obfs.Type)
		}
		if options.Obfs.Password != "" {
			query.Set("obfs-password", options.Obfs.Password)
		}
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func generateTUICLink(outbound option.Outbound) (string, error) {
	options, loaded := outbound.Options.(*option.TUICOutboundOptions)
	if !loaded || options.UUID == "" {
		return "", E.New("invalid TUIC outbound")
	}
	u, err := shareURL("tuic", options.ServerOptions, url.UserPassword(options.UUID, options.Password), outbound.Tag)
	if err != nil {
		return "", err
	}
	query := u.Query()
	addTLSQuery(query, options.TLS, false)
	addTCPFastOpenQuery(query, options.DialerOptions)
	if options.CongestionControl != "" {
		query.Set("congestion_control", options.CongestionControl)
	}
	if options.UDPRelayMode != "" {
		query.Set("udp_relay_mode", options.UDPRelayMode)
	}
	if options.UDPOverStream {
		query.Set("udp_over_stream", "true")
	}
	if options.ZeroRTTHandshake {
		query.Set("zero_rtt_handshake", "true")
	}
	if options.Heartbeat != 0 {
		query.Set("heartbeat_interval", time.Duration(options.Heartbeat).String())
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func generateHysteriaLink(outbound option.Outbound) (string, error) {
	options, loaded := outbound.Options.(*option.HysteriaOutboundOptions)
	if !loaded {
		return "", E.New("invalid Hysteria outbound")
	}
	if len(options.ServerPorts) != 0 {
		return "", E.New("port hopping cannot be represented safely as a share link")
	}
	if len(options.Auth) != 0 && options.AuthString != "" {
		return "", E.New("both Hysteria auth and auth_str are set")
	}
	if options.Up != nil && options.UpMbps != 0 || options.Down != nil && options.DownMbps != 0 {
		return "", E.New("conflicting Hysteria bandwidth options")
	}
	u, err := shareURL("hysteria", options.ServerOptions, nil, outbound.Tag)
	if err != nil {
		return "", err
	}
	query := u.Query()
	addTLSQuery(query, options.TLS, false)
	addTCPFastOpenQuery(query, options.DialerOptions)
	if options.AuthString != "" {
		query.Set("auth", options.AuthString)
	} else if len(options.Auth) != 0 {
		query.Set("auth", string(options.Auth))
	}
	if options.UpMbps != 0 {
		query.Set("upmbps", strconv.Itoa(options.UpMbps))
	} else if options.Up != nil {
		up, err := bandwidthQueryValue(options.Up)
		if err != nil {
			return "", err
		}
		query.Set("up", up)
	}
	if options.DownMbps != 0 {
		query.Set("downmbps", strconv.Itoa(options.DownMbps))
	} else if options.Down != nil {
		down, err := bandwidthQueryValue(options.Down)
		if err != nil {
			return "", err
		}
		query.Set("down", down)
	}
	if options.Obfs != "" {
		query.Set("obfs", "xplus")
		query.Set("obfsParam", options.Obfs)
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func generateVMessLink(outbound option.Outbound) (string, error) {
	options, loaded := outbound.Options.(*option.VMessOutboundOptions)
	if !loaded || options.UUID == "" || options.Server == "" || options.ServerPort == 0 {
		return "", E.New("invalid VMess outbound")
	}
	payload := map[string]string{
		"v": "2", "ps": outbound.Tag, "add": options.Server, "port": strconv.Itoa(int(options.ServerPort)),
		"id": options.UUID, "aid": strconv.Itoa(options.AlterId), "scy": subscription.VMessSecurity(options.Security),
		"net": "tcp", "type": "none", "host": "", "path": "", "tls": "", "sni": "",
	}
	if options.PacketEncoding != "" {
		payload["packet_encoding"] = options.PacketEncoding
	}
	if options.TCPFastOpen {
		payload["tfo"] = "1"
	}
	if options.TLS != nil && options.TLS.Enabled {
		payload["tls"] = "tls"
		payload["sni"] = options.TLS.ServerName
		if !xrayTransportOwnsALPN(options.Transport) {
			payload["alpn"] = strings.Join(options.TLS.ALPN, ",")
		}
		payload["fp"] = "chrome"
		if options.TLS.UTLS != nil && options.TLS.UTLS.Enabled && options.TLS.UTLS.Fingerprint != "" {
			payload["fp"] = options.TLS.UTLS.Fingerprint
		}
		if options.TLS.Insecure {
			payload["insecure"] = "1"
		}
		if len(options.TLS.VerifyServerName) != 0 {
			payload["vcn"] = strings.Join(options.TLS.VerifyServerName, ",")
		}
	}
	if err := addVMessTransport(payload, options.Transport); err != nil {
		return "", err
	}
	content, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return "vmess://" + base64.RawStdEncoding.EncodeToString(content), nil
}

func shareLinkOutboundsEqual(left, right option.Outbound) (bool, error) {
	leftValue, err := shareLinkOutboundValue(left)
	if err != nil {
		return false, err
	}
	rightValue, err := shareLinkOutboundValue(right)
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(leftValue, rightValue), nil
}

func shareLinkOutboundValue(outbound option.Outbound) (map[string]any, error) {
	content, err := outbound.MarshalJSONContext(context.Background())
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err = json.Unmarshal(content, &value); err != nil {
		return nil, err
	}
	canonicalizeShareLinkValue(value)
	compactShareLinkValue(value)
	return value, nil
}

// canonicalizeShareLinkValue puts both sides of the comparison into one shape: sing-box's own
// decoder fills in the transport defaults, so an outbound without them matches its parsed link.
func canonicalizeShareLinkValue(value map[string]any) {
	canonicalizeShareLinkTransport(value)
	switch value["type"] {
	case C.TypeSOCKS:
		if value["version"] == nil || value["version"] == "" {
			value["version"] = "5"
		}
	case C.TypeVMess:
		security, _ := value["security"].(string)
		value["security"] = subscription.VMessSecurity(security)
	case C.TypeVLESS:
		if value["encryption"] == "none" {
			delete(value, "encryption")
		}
	case C.TypeTUIC:
		if value["congestion_control"] == "cubic" {
			delete(value, "congestion_control")
		}
	}
	tls, _ := value["tls"].(map[string]any)
	if tls == nil {
		return
	}
	switch value["type"] {
	case C.TypeVLESS, C.TypeVMess, C.TypeTrojan, C.TypeAnyTLS:
		if tls["utls"] == nil {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		}
	}
	serverName, _ := tls["server_name"].(string)
	if serverName == "" {
		serverName, _ = value["server"].(string)
	}
	transport, _ := value["transport"].(map[string]any)
	switch transportType, _ := transport["type"].(string); transportType {
	case C.V2RayTransportTypeWebsocket:
		headers, _ := transport["headers"].(map[string]any)
		if headers == nil {
			headers = make(map[string]any)
			transport["headers"] = headers
		}
		if headers["Host"] == nil {
			headers["Host"] = serverName
		}
		delete(tls, "alpn")
	case C.V2RayTransportTypeHTTPUpgrade, C.V2RayTransportTypeGRPC, C.V2RayTransportTypeHTTP:
		delete(tls, "alpn")
	case C.V2RayTransportTypeXHTTP:
		if reflect.DeepEqual(tls["alpn"], []any{"h2", "http/1.1"}) {
			delete(tls, "alpn")
		}
	}
	if tls["server_name"] == value["server"] {
		delete(tls, "server_name")
	}
}

func canonicalizeShareLinkTransport(value map[string]any) {
	source, _ := value["transport"].(map[string]any)
	if source == nil {
		return
	}
	encoded, err := json.Marshal(source)
	if err != nil {
		return
	}
	var options option.V2RayTransportOptions
	if json.Unmarshal(encoded, &options) != nil {
		return
	}
	normalized, err := json.Marshal(options)
	if err != nil {
		return
	}
	var result map[string]any
	if json.Unmarshal(normalized, &result) != nil {
		return
	}
	if download := mapValue(result["download"]); download != nil {
		if tls := mapValue(download["tls"]); tls != nil {
			if tls["utls"] == nil {
				tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
			}
			if tls["server_name"] == download["server"] {
				delete(tls, "server_name")
			}
		}
	}
	value["transport"] = result
}

func mapValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func compactShareLinkValue(value map[string]any) {
	for key, child := range value {
		switch typed := child.(type) {
		case map[string]any:
			compactShareLinkValue(typed)
			if len(typed) == 0 {
				delete(value, key)
			}
		case []any:
			if len(typed) == 0 {
				delete(value, key)
			}
		}
	}
}

func addV2RayTransportQuery(query url.Values, transport *option.V2RayTransportOptions) error {
	if transport == nil || transport.Type == "" {
		query.Set("type", "tcp")
		return nil
	}
	switch transport.Type {
	case C.V2RayTransportTypeWebsocket:
		query.Set("type", "ws")
		if path := websocketPath(transport.WebsocketOptions); path != "" {
			query.Set("path", path)
		}
		if host := transport.WebsocketOptions.Headers.Build().Get("Host"); host != "" {
			query.Set("host", host)
		}
		if name := transport.WebsocketOptions.EarlyDataHeaderName; name != "" && name != "Sec-WebSocket-Protocol" {
			query.Set("eh", name)
		}
	case C.V2RayTransportTypeGRPC:
		query.Set("type", "grpc")
		if transport.GRPCOptions.ServiceName != "" {
			query.Set("serviceName", transport.GRPCOptions.ServiceName)
		}
	case C.V2RayTransportTypeHTTPUpgrade:
		query.Set("type", "httpupgrade")
		if transport.HTTPUpgradeOptions.Host != "" {
			query.Set("host", transport.HTTPUpgradeOptions.Host)
		}
		if transport.HTTPUpgradeOptions.Path != "" {
			query.Set("path", transport.HTTPUpgradeOptions.Path)
		}
	case C.V2RayTransportTypeHTTP:
		query.Set("type", "http")
		if transport.HTTPOptions.Path != "" {
			query.Set("path", transport.HTTPOptions.Path)
		}
		if len(transport.HTTPOptions.Host) != 0 {
			query.Set("host", strings.Join(transport.HTTPOptions.Host, ","))
		}
	case C.V2RayTransportTypeXHTTP:
		query.Set("type", "xhttp")
		// The settings are normalised first, so an outbound written without the
		// defaults and one parsed back from a link produce the same link.
		options := normalizeXHTTPOptions(transport.XHTTPOptions)
		if options.Host != "" {
			query.Set("host", options.Host)
		}
		if options.Path != "" {
			query.Set("path", options.Path)
		}
		if options.Mode != "" {
			query.Set("mode", options.Mode)
		}
		// A link naming no protocol offers both, so writing them out only makes it differ from itself.
		if query.Get("alpn") == "h2,http/1.1" {
			query.Del("alpn")
		}
		extra := xhttpExtra(options)
		if options.Download != nil {
			download, err := xhttpDownloadExtra(options.Mode, options.Download)
			if err != nil {
				return err
			}
			extra["downloadSettings"] = download
		}
		if len(extra) != 0 {
			content, err := json.Marshal(extra)
			if err != nil {
				return err
			}
			query.Set("extra", base64.RawURLEncoding.EncodeToString(content))
		}
	default:
		return E.New("unsupported V2Ray transport: ", transport.Type)
	}
	return nil
}

func addVMessTransport(payload map[string]string, transport *option.V2RayTransportOptions) error {
	if transport == nil || transport.Type == "" {
		return nil
	}
	switch transport.Type {
	case C.V2RayTransportTypeWebsocket:
		payload["net"] = "ws"
		payload["path"] = websocketPath(transport.WebsocketOptions)
		payload["host"] = transport.WebsocketOptions.Headers.Build().Get("Host")
	case C.V2RayTransportTypeGRPC:
		payload["net"] = "grpc"
		payload["path"] = transport.GRPCOptions.ServiceName
	case C.V2RayTransportTypeHTTPUpgrade:
		payload["net"] = "httpupgrade"
		payload["path"] = transport.HTTPUpgradeOptions.Path
		payload["host"] = transport.HTTPUpgradeOptions.Host
	case C.V2RayTransportTypeHTTP:
		payload["net"] = "h2"
		payload["path"] = transport.HTTPOptions.Path
		payload["host"] = strings.Join(transport.HTTPOptions.Host, ",")
	case C.V2RayTransportTypeXHTTP:
		payload["net"] = "xhttp"
		options := normalizeXHTTPOptions(transport.XHTTPOptions)
		payload["host"] = options.Host
		payload["path"] = options.Path
		if options.Mode != "" {
			// v2rayN reads the mode from the field of the TCP header, the parser from "mode"
			payload["type"] = options.Mode
			payload["mode"] = options.Mode
		}
		extra := xhttpExtra(options)
		if options.Download != nil {
			download, err := xhttpDownloadExtra(options.Mode, options.Download)
			if err != nil {
				return err
			}
			extra["downloadSettings"] = download
		}
		if len(extra) != 0 {
			content, err := json.Marshal(extra)
			if err != nil {
				return err
			}
			payload["extra"] = base64.RawURLEncoding.EncodeToString(content)
		}
	default:
		return E.New("unsupported VMess transport: ", transport.Type)
	}
	return nil
}

// addXrayClientTLSQuery writes what the client of Xray-core takes anyway, so that the link reads
// back as the outbound it was made from.
func addXrayClientTLSQuery(query url.Values, tls *option.OutboundTLSOptions, transport *option.V2RayTransportOptions) {
	if tls == nil || !tls.Enabled {
		return
	}
	if query.Get("fp") == "" {
		query.Set("fp", "chrome")
	}
	if xrayTransportOwnsALPN(transport) {
		query.Del("alpn")
	}
}

func xrayTransportOwnsALPN(transport *option.V2RayTransportOptions) bool {
	if transport == nil {
		return false
	}
	switch transport.Type {
	case C.V2RayTransportTypeWebsocket, C.V2RayTransportTypeHTTPUpgrade, C.V2RayTransportTypeGRPC, C.V2RayTransportTypeHTTP:
		return true
	default:
		return false
	}
}

func addTLSQuery(query url.Values, tls *option.OutboundTLSOptions, includeSecurity bool) {
	if tls == nil || !tls.Enabled {
		if includeSecurity {
			query.Set("security", "none")
		}
		return
	}
	if includeSecurity {
		security := "tls"
		if tls.Reality != nil && tls.Reality.Enabled {
			security = "reality"
			query.Set("pbk", tls.Reality.PublicKey)
			query.Set("sid", tls.Reality.ShortID)
		}
		query.Set("security", security)
	}
	if tls.ServerName != "" {
		query.Set("sni", tls.ServerName)
	}
	if tls.Insecure {
		query.Set("insecure", "1")
	}
	if len(tls.VerifyServerName) != 0 {
		query.Set("vcn", strings.Join(tls.VerifyServerName, ","))
	}
	if len(tls.ALPN) != 0 {
		query.Set("alpn", strings.Join(tls.ALPN, ","))
	}
	if tls.UTLS != nil && tls.UTLS.Enabled && tls.UTLS.Fingerprint != "" {
		query.Set("fp", tls.UTLS.Fingerprint)
	}
}

func shareURL(scheme string, server option.ServerOptions, user *url.Userinfo, tag string) (*url.URL, error) {
	if server.Server == "" || server.ServerPort == 0 {
		return nil, E.New("missing server or port")
	}
	return &url.URL{Scheme: scheme, User: user, Host: net.JoinHostPort(server.Server, strconv.Itoa(int(server.ServerPort))), Fragment: tag}, nil
}

func addTCPFastOpenQuery(query url.Values, dialer option.DialerOptions) {
	if dialer.TCPFastOpen {
		query.Set("tfo", "1")
	}
}

// websocketPath puts the early data length into the path, which is where every
// client that reads a link looks for it.
func websocketPath(options option.V2RayWebsocketOptions) string {
	path := options.Path
	if options.MaxEarlyData > 0 {
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		path += separator + "ed=" + strconv.FormatUint(uint64(options.MaxEarlyData), 10)
	}
	return path
}

func bandwidthQueryValue(bandwidth *byteformats.NetworkBytesCompat) (string, error) {
	content, err := json.Marshal(bandwidth)
	if err != nil {
		return "", err
	}
	var value string
	if json.Unmarshal(content, &value) != nil {
		return "", E.New("a bandwidth without a unit cannot be represented as a share link")
	}
	return value, nil
}

// xhttpExtra writes only the XHTTP settings that differ from what the mode implies, so a link
// regenerated from a parsed one stays the same.
func xhttpExtra(options option.V2RayXHTTPOptions) map[string]any {
	defaults := defaultXHTTPOptions(options.Mode)
	extra := make(map[string]any)
	for _, field := range []struct {
		name     string
		value    option.Range[int]
		fallback option.Range[int]
	}{
		{"xPaddingBytes", options.XPaddingBytes, defaults.XPaddingBytes},
		{"sessionIDLength", options.SessionIDLength, defaults.SessionIDLength},
	} {
		if field.value != field.fallback {
			extra[field.name] = field.value.String()
		}
	}
	for _, field := range []struct {
		name     string
		value    *option.Range[int]
		fallback *option.Range[int]
	}{
		{"scMaxEachPostBytes", options.ScMaxEachPostBytes, defaults.ScMaxEachPostBytes},
		{"scMinPostsIntervalMs", options.ScMinPostsIntervalMs, defaults.ScMinPostsIntervalMs},
		{"scStreamUpServerSecs", options.ScStreamUpServerSecs, defaults.ScStreamUpServerSecs},
		{"uplinkChunkSize", options.UplinkChunkSize, defaults.UplinkChunkSize},
	} {
		if field.value != nil && (field.fallback == nil || *field.value != *field.fallback) {
			extra[field.name] = field.value.String()
		}
	}
	for _, field := range []struct {
		name     string
		value    string
		fallback string
	}{
		{"xPaddingKey", options.XPaddingKey, defaults.XPaddingKey},
		{"xPaddingHeader", options.XPaddingHeader, defaults.XPaddingHeader},
		{"xPaddingPlacement", options.XPaddingPlacement, defaults.XPaddingPlacement},
		{"xPaddingMethod", options.XPaddingMethod, defaults.XPaddingMethod},
		{"uplinkHTTPMethod", options.UplinkHTTPMethod, defaults.UplinkHTTPMethod},
		{"uplinkDataPlacement", options.UplinkDataPlacement, defaults.UplinkDataPlacement},
		{"uplinkDataKey", options.UplinkDataKey, defaults.UplinkDataKey},
		{"sessionIDPlacement", options.SessionPlacement, defaults.SessionPlacement},
		{"sessionIDKey", options.SessionKey, defaults.SessionKey},
		{"sessionIDTable", options.SessionIDTable, defaults.SessionIDTable},
		{"seqPlacement", options.SeqPlacement, defaults.SeqPlacement},
		{"seqKey", options.SeqKey, defaults.SeqKey},
		{"congestionController", options.CongestionController, defaults.CongestionController},
	} {
		if field.value != field.fallback {
			extra[field.name] = field.value
		}
	}
	if options.NoGRPCHeader != defaults.NoGRPCHeader {
		extra["noGRPCHeader"] = options.NoGRPCHeader
	}
	if options.NoSSEHeader != defaults.NoSSEHeader {
		extra["noSSEHeader"] = options.NoSSEHeader
	}
	if options.XPaddingObfsMode != defaults.XPaddingObfsMode {
		extra["xPaddingObfsMode"] = options.XPaddingObfsMode
	}
	if options.ScMaxBufferedPosts != defaults.ScMaxBufferedPosts {
		extra["scMaxBufferedPosts"] = options.ScMaxBufferedPosts
	}
	if options.ServerMaxHeaderBytes != defaults.ServerMaxHeaderBytes {
		extra["serverMaxHeaderBytes"] = options.ServerMaxHeaderBytes
	}
	if options.CWND != defaults.CWND {
		extra["cwnd"] = options.CWND
	}
	if xmux := xhttpXmuxExtra(options.Xmux); len(xmux) != 0 {
		extra["xmux"] = xmux
	}
	return extra
}

// xhttpDownloadExtra writes the download leg as Xray-core's downloadSettings, with the fingerprint
// a client of Xray takes anyway.
func xhttpDownloadExtra(mode string, download *option.V2RayXHTTPDownloadOptions) (map[string]any, error) {
	if download.Detour != "" {
		return nil, E.New("an XHTTP download through another outbound has no share link")
	}
	settings := xhttpExtra(option.V2RayXHTTPOptions{Mode: mode, V2RayXHTTPBaseOptions: download.V2RayXHTTPBaseOptions})
	if download.Host != "" {
		settings["host"] = download.Host
	}
	if download.Path != "" {
		settings["path"] = download.Path
	}
	leg := map[string]any{"address": download.Server, "port": download.ServerPort, "network": "xhttp", "security": "none", "xhttpSettings": settings}
	tls := download.TLS
	if tls == nil || !tls.Enabled {
		return leg, nil
	}
	security := map[string]any{"fingerprint": "chrome"}
	if tls.UTLS != nil && tls.UTLS.Enabled && tls.UTLS.Fingerprint != "" {
		security["fingerprint"] = tls.UTLS.Fingerprint
	}
	if tls.ServerName != "" {
		security["serverName"] = tls.ServerName
	}
	if tls.Reality != nil && tls.Reality.Enabled {
		security["publicKey"] = tls.Reality.PublicKey
		security["shortId"] = tls.Reality.ShortID
		leg["security"], leg["realitySettings"] = "reality", security
		return leg, nil
	}
	if len(tls.ALPN) != 0 {
		security["alpn"] = []string(tls.ALPN)
	}
	if tls.Insecure {
		security["allowInsecure"] = true
	}
	if len(tls.VerifyServerName) != 0 {
		security["verifyPeerCertByName"] = strings.Join(tls.VerifyServerName, ",")
	}
	leg["security"], leg["tlsSettings"] = "tls", security
	return leg, nil
}

// xhttpXmuxExtra writes every value of the reuse block: sing-box defaults it only when it is
// absent altogether.
func xhttpXmuxExtra(options *option.V2RayXHTTPXmuxOptions) map[string]any {
	if options == nil {
		return nil
	}
	defaults := &option.V2RayXHTTPXmuxOptions{}
	xmux := make(map[string]any)
	for _, field := range []struct {
		name     string
		value    option.Range[int]
		fallback option.Range[int]
	}{
		{"maxConcurrency", options.MaxConcurrency, defaults.MaxConcurrency},
		{"maxConnections", options.MaxConnections, defaults.MaxConnections},
		{"cMaxReuseTimes", options.CMaxReuseTimes, defaults.CMaxReuseTimes},
		{"hMaxRequestTimes", options.HMaxRequestTimes, defaults.HMaxRequestTimes},
		{"hMaxReusableSecs", options.HMaxReusableSecs, defaults.HMaxReusableSecs},
	} {
		if field.value != field.fallback {
			xmux[field.name] = field.value.String()
		}
	}
	if options.HKeepAlivePeriod != defaults.HKeepAlivePeriod {
		xmux["hKeepAlivePeriod"] = strconv.FormatInt(options.HKeepAlivePeriod, 10)
	}
	return xmux
}

// defaultXHTTPOptions is what sing-box makes of an XHTTP transport that names
// nothing but its mode.
func defaultXHTTPOptions(mode string) option.V2RayXHTTPOptions {
	return normalizeXHTTPOptions(option.V2RayXHTTPOptions{Mode: mode})
}

func normalizeXHTTPOptions(options option.V2RayXHTTPOptions) option.V2RayXHTTPOptions {
	normalized, _ := xhttp.Normalize(options)
	return normalized
}
