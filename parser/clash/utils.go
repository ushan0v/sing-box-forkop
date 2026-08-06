package clash

import (
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/byteformats"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

func clashClientFingerprint(clientFingerprint string) *option.OutboundUTLSOptions {
	if clientFingerprint == "" {
		return nil
	}
	return &option.OutboundUTLSOptions{
		Enabled:     true,
		Fingerprint: clientFingerprint,
	}
}

func clashHeaders(headers map[string]string) map[string]badoption.Listable[string] {
	if headers == nil {
		return nil
	}
	result := make(map[string]badoption.Listable[string])
	for key, value := range headers {
		result[key] = []string{value}
	}
	return result
}

func clashHysteria2Obfs(obfs string, password string) *option.Hysteria2Obfs {
	if obfs == "" {
		return nil
	}
	return &option.Hysteria2Obfs{
		Type:     obfs,
		Password: password,
	}
}

func clashNetworks(udpEnabled bool) option.NetworkList {
	if !udpEnabled {
		return N.NetworkTCP
	}
	return ""
}

func clashPluginName(plugin string) string {
	switch plugin {
	case "obfs":
		return "obfs-local"
	}
	return plugin
}

func clashPluginOptions(plugin string, opts map[string]any) string {
	options := make(shadowsocksPluginOptionsBuilder)
	switch plugin {
	case "obfs":
		options["obfs"] = opts["mode"]
		options["obfs-host"] = opts["host"]
	case "v2ray-plugin":
		options["mode"] = opts["mode"]
		options["tls"] = opts["tls"]
		options["host"] = opts["host"]
		options["path"] = opts["path"]
	}
	return options.Build()
}

func clashPorts(ports string) badoption.Listable[string] {
	if ports == "" {
		return nil
	}
	serverPorts := badoption.Listable[string]{}
	ports = strings.ReplaceAll(ports, "/", ",")
	for _, port := range strings.Split(ports, ",") {
		if port == "" {
			continue
		}
		port = strings.Replace(port, "-", ":", 1)
		serverPorts = append(serverPorts, port)
	}
	return serverPorts
}

func clashShadowsocksCipher(cipher string) string {
	switch cipher {
	case "dummy":
		return "none"
	}
	return cipher
}

func clashStringList(list []string) string {
	if len(list) > 0 {
		return list[0]
	}
	return ""
}

func clashSpeedToIntMbps(speed string) int {
	if speed == "" {
		return 0
	}
	if num, err := strconv.Atoi(speed); err == nil {
		return num
	}
	networkBytes := byteformats.NetworkBytesCompat{}
	if err := networkBytes.UnmarshalJSON([]byte(speed)); err != nil {
		return 0
	}
	return int(networkBytes.Value() / byteformats.MByte * 8)
}

func clashSpeedToNetworkBytes(speed string) *byteformats.NetworkBytesCompat {
	if speed == "" {
		return nil
	}
	networkBytes := &byteformats.NetworkBytesCompat{}
	if num, err := strconv.Atoi(speed); err == nil {
		speed = F.ToString(num, "Mbps")
	}
	if err := networkBytes.UnmarshalJSON([]byte(speed)); err != nil {
		return nil
	}
	return networkBytes
}

func clashTransport(network string, httpOpts HTTPOptions, h2Opts HTTP2Options, grpcOpts GrpcOptions, wsOpts WSOptions, xhttpOpts XHTTPOptions) *option.V2RayTransportOptions {
	switch network {
	case "http":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Method:  httpOpts.Method,
				Path:    clashStringList(httpOpts.Path),
				Headers: httpOpts.Headers,
			},
		}
	case "h2":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Path: h2Opts.Path,
				Host: h2Opts.Host,
			},
		}
	case "grpc":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: grpcOpts.GrpcServiceName,
			},
		}
	case "ws":
		headers := clashHeaders(wsOpts.Headers)
		if wsOpts.V2rayHttpUpgrade {
			var host string
			if headers != nil && headers["Host"] != nil {
				host = headers["Host"][0]
			}
			return &option.V2RayTransportOptions{
				Type: C.V2RayTransportTypeHTTPUpgrade,
				HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
					Host:    host,
					Path:    wsOpts.Path,
					Headers: headers,
				},
			}
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:                wsOpts.Path,
				Headers:             headers,
				MaxEarlyData:        uint32(wsOpts.MaxEarlyData),
				EarlyDataHeaderName: wsOpts.EarlyDataHeaderName,
			},
		}
	case "xhttp":
		return xhttpOpts.Build()
	default:
		return nil
	}
}

func clashTLSOptions(server string, tlsOptions *TLSOptions) option.OutboundTLSOptionsContainer {
	if tlsOptions != nil && tlsOptions.SNI == "" {
		tlsOptions.SNI = server
	}
	return option.OutboundTLSOptionsContainer{
		TLS: tlsOptions.Build(),
	}
}

func trimStringArray(array []string) []string {
	return common.Filter(array, func(it string) bool {
		return strings.TrimSpace(it) != ""
	})
}
