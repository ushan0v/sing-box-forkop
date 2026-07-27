package link

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func GenerateSubscriptionLink(outbound option.Outbound) (string, error) {
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
	case C.TypeHysteria2:
		return generateHysteria2Link(outbound)
	case C.TypeTUIC:
		return generateTUICLink(outbound)
	case C.TypeHysteria:
		return generateHysteriaLink(outbound)
	default:
		return "", E.New("unsupported outbound type: ", outbound.Type)
	}
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
	if err = addV2RayTransportQuery(query, options.Transport, "serviceName"); err != nil {
		return "", err
	}
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
	if options.TLS.Reality != nil && options.TLS.Reality.Enabled {
		return "", E.New("Trojan Reality cannot be represented as a share link")
	}
	if options.TLS.ECH != nil && options.TLS.ECH.Enabled {
		return "", E.New("Trojan ECH cannot be represented as a share link")
	}
	if options.Transport != nil && options.Transport.Type != "" &&
		options.Transport.Type != C.V2RayTransportTypeWebsocket && options.Transport.Type != C.V2RayTransportTypeGRPC {
		return "", E.New("unsupported Trojan transport: ", options.Transport.Type)
	}
	u, err := shareURL("trojan", options.ServerOptions, url.User(options.Password), outbound.Tag)
	if err != nil {
		return "", err
	}
	query := u.Query()
	addTLSQuery(query, options.TLS, true)
	if err = addV2RayTransportQuery(query, options.Transport, "grpc-service-name"); err != nil {
		return "", err
	}
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
	u, err := shareURLWithPorts("hysteria2", options.Server, options.ServerPort, options.ServerPorts, url.User(options.Password), outbound.Tag)
	if err != nil {
		return "", err
	}
	query := u.Query()
	addTLSQuery(query, options.TLS, false)
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
	u, err := shareURLWithPorts("hysteria", options.Server, options.ServerPort, options.ServerPorts, nil, outbound.Tag)
	if err != nil {
		return "", err
	}
	query := u.Query()
	addTLSQuery(query, options.TLS, false)
	if options.AuthString != "" {
		query.Set("auth", options.AuthString)
	} else if len(options.Auth) != 0 {
		query.Set("auth", string(options.Auth))
	}
	if options.UpMbps != 0 {
		query.Set("up_mbps", strconv.Itoa(options.UpMbps))
	} else if options.Up != nil {
		query.Set("up", strconv.FormatUint(options.Up.Value(), 10))
	}
	if options.DownMbps != 0 {
		query.Set("down_mbps", strconv.Itoa(options.DownMbps))
	} else if options.Down != nil {
		query.Set("down", strconv.FormatUint(options.Down.Value(), 10))
	}
	if options.Obfs != "" {
		query.Set("obfs", options.Obfs)
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
		"id": options.UUID, "aid": strconv.Itoa(options.AlterId), "scy": options.Security,
		"net": "tcp", "type": "none", "host": "", "path": "", "tls": "", "sni": "",
	}
	if payload["scy"] == "" {
		payload["scy"] = "auto"
	}
	if options.PacketEncoding != "" {
		payload["packet_encoding"] = options.PacketEncoding
	}
	if options.TLS != nil && options.TLS.Enabled {
		payload["tls"] = "tls"
		payload["sni"] = options.TLS.ServerName
		payload["alpn"] = strings.Join(options.TLS.ALPN, ",")
		if options.TLS.UTLS != nil && options.TLS.UTLS.Enabled {
			payload["fp"] = options.TLS.UTLS.Fingerprint
		}
		if options.TLS.Insecure {
			payload["insecure"] = "1"
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

func addV2RayTransportQuery(query url.Values, transport *option.V2RayTransportOptions, grpcKey string) error {
	if transport == nil || transport.Type == "" {
		query.Set("type", "tcp")
		return nil
	}
	switch transport.Type {
	case C.V2RayTransportTypeWebsocket:
		query.Set("type", "ws")
		if transport.WebsocketOptions.Path != "" {
			query.Set("path", transport.WebsocketOptions.Path)
		}
		if host := transport.WebsocketOptions.Headers.Build().Get("Host"); host != "" {
			query.Set("host", host)
		}
	case C.V2RayTransportTypeGRPC:
		query.Set("type", "grpc")
		if transport.GRPCOptions.ServiceName != "" {
			query.Set(grpcKey, transport.GRPCOptions.ServiceName)
		}
	case C.V2RayTransportTypeHTTP:
		query.Set("type", "http")
		if transport.HTTPOptions.Path != "" {
			query.Set("path", transport.HTTPOptions.Path)
		}
		if len(transport.HTTPOptions.Host) != 0 {
			query.Set("host", strings.Join(transport.HTTPOptions.Host, ","))
		}
	case C.V2RayTransportTypeKCP:
		query.Set("type", "kcp")
		if transport.KCPOptions.HeaderType != "" {
			query.Set("headerType", transport.KCPOptions.HeaderType)
		}
		if transport.KCPOptions.Seed != "" {
			query.Set("seed", transport.KCPOptions.Seed)
		}
	case C.V2RayTransportTypeXHTTP:
		query.Set("type", "xhttp")
		if transport.XHTTPOptions.Host != "" {
			query.Set("host", transport.XHTTPOptions.Host)
		}
		if transport.XHTTPOptions.Path != "" {
			query.Set("path", transport.XHTTPOptions.Path)
		}
		if transport.XHTTPOptions.Mode != "" {
			query.Set("mode", transport.XHTTPOptions.Mode)
		}
		extra := xhttpExtra(transport.XHTTPOptions)
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
		payload["path"] = transport.WebsocketOptions.Path
		payload["host"] = transport.WebsocketOptions.Headers.Build().Get("Host")
	case C.V2RayTransportTypeGRPC:
		payload["net"] = "grpc"
		payload["host"] = transport.GRPCOptions.ServiceName
	case C.V2RayTransportTypeHTTP:
		payload["net"] = "h2"
		payload["path"] = transport.HTTPOptions.Path
		payload["host"] = strings.Join(transport.HTTPOptions.Host, ",")
	case C.V2RayTransportTypeKCP:
		payload["net"] = "kcp"
		payload["type"] = transport.KCPOptions.HeaderType
		payload["seed"] = transport.KCPOptions.Seed
	default:
		return E.New("unsupported VMess transport: ", transport.Type)
	}
	return nil
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
	if len(tls.ALPN) != 0 {
		query.Set("alpn", strings.Join(tls.ALPN, ","))
	}
	if tls.UTLS != nil && tls.UTLS.Enabled && tls.UTLS.Fingerprint != "" {
		query.Set("fp", tls.UTLS.Fingerprint)
	}
}

func shareURL(scheme string, server option.ServerOptions, user *url.Userinfo, tag string) (*url.URL, error) {
	return shareURLWithPorts(scheme, server.Server, server.ServerPort, nil, user, tag)
}

func shareURLWithPorts(scheme, server string, port uint16, ports []string, user *url.Userinfo, tag string) (*url.URL, error) {
	if len(ports) != 0 {
		return nil, E.New("port hopping cannot be represented safely as a share link")
	}
	if server == "" || port == 0 {
		return nil, E.New("missing server or port")
	}
	portValue := strconv.Itoa(int(port))
	return &url.URL{Scheme: scheme, User: user, Host: net.JoinHostPort(server, portValue), Fragment: tag}, nil
}

func xhttpExtra(options option.V2RayXHTTPOptions) map[string]any {
	extra := make(map[string]any)
	if options.XPaddingBytes.To != 0 {
		extra["xPaddingBytes"] = options.XPaddingBytes.String()
	}
	if options.NoGRPCHeader {
		extra["noGRPCHeader"] = true
	}
	if options.ScMaxEachPostBytes != nil {
		extra["scMaxEachPostBytes"] = options.ScMaxEachPostBytes.String()
	}
	if options.ScMinPostsIntervalMs != nil {
		extra["scMinPostsIntervalMs"] = options.ScMinPostsIntervalMs.String()
	}
	if options.ScStreamUpServerSecs != nil {
		extra["scStreamUpServerSecs"] = options.ScStreamUpServerSecs.String()
	}
	if options.Xmux != nil {
		xmux := make(map[string]any)
		if options.Xmux.MaxConcurrency.To != 0 {
			xmux["maxConcurrency"] = options.Xmux.MaxConcurrency.String()
		}
		if options.Xmux.MaxConnections.To != 0 {
			xmux["maxConnections"] = options.Xmux.MaxConnections.String()
		}
		if options.Xmux.CMaxReuseTimes.To != 0 {
			xmux["cMaxReuseTimes"] = options.Xmux.CMaxReuseTimes.String()
		}
		if options.Xmux.HMaxRequestTimes.To != 0 {
			xmux["hMaxRequestTimes"] = options.Xmux.HMaxRequestTimes.String()
		}
		if options.Xmux.HMaxReusableSecs.To != 0 {
			xmux["hMaxReusableSecs"] = options.Xmux.HMaxReusableSecs.String()
		}
		if options.Xmux.HKeepAlivePeriod != 0 {
			xmux["hKeepAlivePeriod"] = strconv.FormatInt(options.Xmux.HKeepAlivePeriod, 10)
		}
		if len(xmux) != 0 {
			extra["xmux"] = xmux
		}
	}
	return extra
}
