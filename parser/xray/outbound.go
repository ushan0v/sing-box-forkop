package xray

import (
	"encoding/json"
	"strings"

	boxCommon "github.com/sagernet/sing-box/common"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

type parsedOutbound struct {
	sourceTag string
	detour    string
	outbound  option.Outbound
}

func parseSourceOutbound(content json.RawMessage, fallbackTag string) (parsedOutbound, bool) {
	var source sourceOutbound
	if json.Unmarshal(content, &source) != nil || source.Protocol == "" {
		return parsedOutbound{}, false
	}
	tag := source.Tag
	if tag == "" {
		tag = fallbackTag
	}
	var options any
	var outboundType string
	var err error
	switch strings.ToLower(source.Protocol) {
	case C.TypeVLESS:
		outboundType = C.TypeVLESS
		options, err = parseVLESS(source)
	case C.TypeVMess:
		outboundType = C.TypeVMess
		options, err = parseVMess(source)
	case C.TypeSOCKS:
		outboundType = C.TypeSOCKS
		options, err = parseSOCKS(source)
	case C.TypeShadowsocks, "ss":
		outboundType = C.TypeShadowsocks
		options, err = parseShadowsocks(source)
	case C.TypeTrojan:
		outboundType = C.TypeTrojan
		options, err = parseTrojan(source)
	case C.TypeHTTP:
		outboundType = C.TypeHTTP
		options, err = parseHTTP(source)
	case C.TypeHysteria:
		outboundType = C.TypeHysteria2
		options, err = parseHysteria2(source)
	default:
		return parsedOutbound{}, false
	}
	if err != nil {
		return parsedOutbound{}, false
	}
	return parsedOutbound{
		sourceTag: tag,
		detour:    sourceDetour(source),
		outbound: option.Outbound{
			Type:    outboundType,
			Tag:     tag,
			Options: options,
		},
	}, true
}

func parseVLESS(source sourceOutbound) (*option.VLESSOutboundOptions, error) {
	var settings struct {
		VNext []struct {
			Address string `json:"address"`
			Port    port   `json:"port"`
			Users   []struct {
				ID         string `json:"id"`
				Flow       string `json:"flow"`
				Encryption string `json:"encryption"`
			} `json:"users"`
		} `json:"vnext"`
	}
	if json.Unmarshal(source.Settings, &settings) != nil || len(settings.VNext) == 0 || len(settings.VNext[0].Users) == 0 {
		return nil, E.New("missing VLESS server or user")
	}
	server, user := settings.VNext[0], settings.VNext[0].Users[0]
	if server.Address == "" || server.Port == 0 || user.ID == "" {
		return nil, E.New("invalid VLESS server")
	}
	transport, err := parseTransport(source.StreamSettings)
	if err != nil {
		return nil, err
	}
	return &option.VLESSOutboundOptions{
		DialerOptions: option.DialerOptions{Detour: sourceDetour(source)},
		ServerOptions: option.ServerOptions{Server: server.Address, ServerPort: uint16(server.Port)},
		UUID:          user.ID,
		Flow:          user.Flow,
		Encryption:    user.Encryption,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: parseTLS(source.StreamSettings),
		},
		Transport: transport,
	}, nil
}

func parseVMess(source sourceOutbound) (*option.VMessOutboundOptions, error) {
	var settings struct {
		VNext []struct {
			Address string `json:"address"`
			Port    port   `json:"port"`
			Users   []struct {
				ID       string  `json:"id"`
				Security string  `json:"security"`
				AlterID  integer `json:"alterId"`
			} `json:"users"`
		} `json:"vnext"`
	}
	if json.Unmarshal(source.Settings, &settings) != nil || len(settings.VNext) == 0 || len(settings.VNext[0].Users) == 0 {
		return nil, E.New("missing VMess server or user")
	}
	server, user := settings.VNext[0], settings.VNext[0].Users[0]
	if server.Address == "" || server.Port == 0 || user.ID == "" {
		return nil, E.New("invalid VMess server")
	}
	transport, err := parseTransport(source.StreamSettings)
	if err != nil {
		return nil, err
	}
	security := user.Security
	if security == "" {
		security = "auto"
	}
	return &option.VMessOutboundOptions{
		DialerOptions: option.DialerOptions{Detour: sourceDetour(source)},
		ServerOptions: option.ServerOptions{Server: server.Address, ServerPort: uint16(server.Port)},
		UUID:          user.ID,
		Security:      security,
		AlterId:       int(user.AlterID),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: parseTLS(source.StreamSettings),
		},
		Transport: transport,
	}, nil
}

func parseSOCKS(source sourceOutbound) (*option.SOCKSOutboundOptions, error) {
	var settings struct {
		Servers []struct {
			Address string `json:"address"`
			Port    port   `json:"port"`
			Users   []struct {
				User     string `json:"user"`
				Pass     string `json:"pass"`
				Password string `json:"password"`
			} `json:"users"`
		} `json:"servers"`
	}
	if json.Unmarshal(source.Settings, &settings) != nil || len(settings.Servers) == 0 {
		return nil, E.New("missing SOCKS server")
	}
	server := settings.Servers[0]
	if server.Address == "" || server.Port == 0 {
		return nil, E.New("invalid SOCKS server")
	}
	options := &option.SOCKSOutboundOptions{
		DialerOptions: option.DialerOptions{Detour: sourceDetour(source)},
		ServerOptions: option.ServerOptions{Server: server.Address, ServerPort: uint16(server.Port)},
		Version:       "5",
	}
	if len(server.Users) > 0 {
		options.Username = server.Users[0].User
		options.Password = first(server.Users[0].Pass, server.Users[0].Password)
	}
	return options, nil
}

func parseShadowsocks(source sourceOutbound) (*option.ShadowsocksOutboundOptions, error) {
	var settings struct {
		Servers []struct {
			Address  string `json:"address"`
			Port     port   `json:"port"`
			Method   string `json:"method"`
			Password string `json:"password"`
		} `json:"servers"`
	}
	if json.Unmarshal(source.Settings, &settings) != nil || len(settings.Servers) == 0 {
		return nil, E.New("missing Shadowsocks server")
	}
	server := settings.Servers[0]
	if server.Address == "" || server.Port == 0 || server.Method == "" || server.Password == "" {
		return nil, E.New("invalid Shadowsocks server")
	}
	security := strings.ToLower(source.StreamSettings.Security)
	if !plainTransportSupported(source.StreamSettings) || (security != "" && security != "none") {
		return nil, E.New("unsupported Shadowsocks stream settings")
	}
	return &option.ShadowsocksOutboundOptions{
		DialerOptions: option.DialerOptions{Detour: sourceDetour(source)},
		ServerOptions: option.ServerOptions{Server: server.Address, ServerPort: uint16(server.Port)},
		Method:        server.Method,
		Password:      server.Password,
	}, nil
}

func parseTrojan(source sourceOutbound) (*option.TrojanOutboundOptions, error) {
	var settings struct {
		Servers []struct {
			Address  string `json:"address"`
			Port     port   `json:"port"`
			Password string `json:"password"`
		} `json:"servers"`
	}
	if json.Unmarshal(source.Settings, &settings) != nil || len(settings.Servers) == 0 {
		return nil, E.New("missing Trojan server")
	}
	server := settings.Servers[0]
	if server.Address == "" || server.Port == 0 || server.Password == "" {
		return nil, E.New("invalid Trojan server")
	}
	transport, err := parseTransport(source.StreamSettings)
	if err != nil {
		return nil, err
	}
	tls := parseTLS(source.StreamSettings)
	if tls == nil {
		tls = &option.OutboundTLSOptions{Enabled: true}
	}
	return &option.TrojanOutboundOptions{
		DialerOptions: option.DialerOptions{Detour: sourceDetour(source)},
		ServerOptions: option.ServerOptions{Server: server.Address, ServerPort: uint16(server.Port)},
		Password:      server.Password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: tls,
		},
		Transport: transport,
	}, nil
}

func parseHTTP(source sourceOutbound) (*option.HTTPOutboundOptions, error) {
	var settings struct {
		Servers []struct {
			Address string `json:"address"`
			Port    port   `json:"port"`
			Users   []struct {
				User     string `json:"user"`
				Pass     string `json:"pass"`
				Password string `json:"password"`
			} `json:"users"`
		} `json:"servers"`
	}
	if json.Unmarshal(source.Settings, &settings) != nil || len(settings.Servers) == 0 {
		return nil, E.New("missing HTTP server")
	}
	server := settings.Servers[0]
	if server.Address == "" || server.Port == 0 || !plainTransportSupported(source.StreamSettings) {
		return nil, E.New("invalid HTTP server")
	}
	options := &option.HTTPOutboundOptions{
		DialerOptions: option.DialerOptions{Detour: sourceDetour(source)},
		ServerOptions: option.ServerOptions{Server: server.Address, ServerPort: uint16(server.Port)},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: parseTLS(source.StreamSettings),
		},
	}
	if len(server.Users) > 0 {
		options.Username = server.Users[0].User
		options.Password = first(server.Users[0].Pass, server.Users[0].Password)
	}
	return options, nil
}

func plainTransportSupported(stream streamSettings) bool {
	network := strings.ToLower(stream.Network)
	return network == "" || network == "tcp"
}

func parseHysteria2(source sourceOutbound) (*option.Hysteria2OutboundOptions, error) {
	var settings struct {
		Version  integer `json:"version"`
		Address  string  `json:"address"`
		Server   string  `json:"server"`
		Port     port    `json:"port"`
		Auth     string  `json:"auth"`
		Password string  `json:"password"`
	}
	if json.Unmarshal(source.Settings, &settings) != nil {
		return nil, E.New("invalid Hysteria2 settings")
	}
	version := settings.Version
	if version == 0 {
		version = source.StreamSettings.HysteriaSettings.Version
	}
	if version != 2 {
		return nil, E.New("not a Hysteria2 outbound")
	}
	server := first(settings.Address, settings.Server)
	password := first(source.StreamSettings.HysteriaSettings.Auth, settings.Auth, settings.Password)
	if server == "" || settings.Port == 0 || password == "" {
		return nil, E.New("invalid Hysteria2 server")
	}
	tls := parseTLS(source.StreamSettings)
	if tls == nil {
		tls = &option.OutboundTLSOptions{Enabled: true}
	}
	return &option.Hysteria2OutboundOptions{
		DialerOptions: option.DialerOptions{Detour: sourceDetour(source)},
		ServerOptions: option.ServerOptions{Server: server, ServerPort: uint16(settings.Port)},
		Password:      password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: tls,
		},
	}, nil
}

func sourceDetour(source sourceOutbound) string {
	if source.StreamSettings.Sockopt.DialerProxy != "" {
		return source.StreamSettings.Sockopt.DialerProxy
	}
	if source.Sockopt.DialerProxy != "" {
		return source.Sockopt.DialerProxy
	}
	if source.ProxySettings != nil && source.ProxySettings.TransportLayer {
		return source.ProxySettings.Tag
	}
	return ""
}

func parseTLS(stream streamSettings) *option.OutboundTLSOptions {
	security := strings.ToLower(stream.Security)
	settings := stream.TLSSettings
	if security == "reality" {
		settings = stream.RealitySettings
	}
	if security != "tls" && security != "xtls" && security != "reality" && !tlsConfigured(settings) {
		return nil
	}
	tls := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: first(settings.ServerName, settings.ServerNameSnake, settings.SNI),
		Insecure:   truthy(settings.AllowInsecure) || truthy(settings.Insecure),
		ALPN:       badoption.Listable[string](settings.ALPN),
	}
	fingerprint := first(settings.Fingerprint, settings.FP)
	if fingerprint != "" {
		tls.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint}
	}
	if security == "reality" {
		tls.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: first(settings.PublicKey, settings.PublicKeySnake),
			ShortID:   first(settings.ShortID, settings.ShortIDSnake),
		}
		if tls.UTLS == nil {
			tls.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
		}
	}
	return tls
}

func tlsConfigured(settings tlsSettings) bool {
	return first(
		settings.ServerName,
		settings.ServerNameSnake,
		settings.SNI,
		settings.Fingerprint,
		settings.FP,
		settings.PublicKey,
		settings.PublicKeySnake,
		settings.ShortID,
		settings.ShortIDSnake,
	) != "" || len(settings.ALPN) > 0 || len(settings.AllowInsecure) > 0 || len(settings.Insecure) > 0
}

func parseTransport(stream streamSettings) (*option.V2RayTransportOptions, error) {
	switch strings.ToLower(stream.Network) {
	case "", "tcp":
		return nil, nil
	case "ws", "websocket":
		headers := badoption.HTTPHeader{}
		for key, value := range stream.WSSettings.Headers {
			headers[key] = []string{value}
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:    stream.WSSettings.Path,
				Headers: headers,
			},
		}, nil
	case "grpc":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: first(stream.GRPCSettings.ServiceName, stream.GRPCSettings.ServiceNameSnake),
			},
		}, nil
	case "http", "h2":
		path := ""
		if len(stream.HTTPSettings.Path) > 0 {
			path = stream.HTTPSettings.Path[0]
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Host: badoption.Listable[string](stream.HTTPSettings.Host),
				Path: path,
			},
		}, nil
	case "httpupgrade":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTPUpgrade,
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
				Host: stream.HTTPUpgradeSettings.Host,
				Path: stream.HTTPUpgradeSettings.Path,
			},
		}, nil
	case "xhttp", "splithttp":
		padding, _ := boxCommon.ParseXHTTPRange("100-1000")
		mode := stream.XHTTPSettings.Mode
		if mode == "" {
			mode = "auto"
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeXHTTP,
			XHTTPOptions: option.V2RayXHTTPOptions{
				Mode: mode,
				V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
					Host:          stream.XHTTPSettings.Host,
					Path:          stream.XHTTPSettings.Path,
					XPaddingBytes: padding,
				},
			},
		}, nil
	case "kcp", "mkcp":
		settings := stream.KCPSettings
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeKCP,
			KCPOptions: option.V2RayKCPOptions{
				MTU:              settings.MTU,
				TTI:              settings.TTI,
				UplinkCapacity:   settings.UplinkCapacity,
				DownlinkCapacity: settings.DownlinkCapacity,
				Congestion:       settings.Congestion,
				ReadBufferSize:   settings.ReadBufferSize,
				WriteBufferSize:  settings.WriteBufferSize,
				HeaderType:       settings.Header.Type,
				Seed:             settings.Seed,
			},
		}, nil
	case "quic":
		return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeQUIC}, nil
	default:
		return nil, E.New("unsupported Xray transport: ", stream.Network)
	}
}
