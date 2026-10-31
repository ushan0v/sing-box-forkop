package link

import (
	"encoding/json"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	"github.com/sagernet/sing-box/parser/xhttp"
	"github.com/sagernet/sing-box/parser/xray"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// vmessPayload is the object a VMess link carries, as v2rayN writes it. Every
// key is present in a generated link whether it is set or not, so an unset one
// arrives as an empty string and must not overwrite a value taken from
// elsewhere.
type vmessPayload struct {
	PS                 subscription.String     `json:"ps"`
	Add                subscription.String     `json:"add"`
	Port               subscription.Port       `json:"port"`
	ID                 subscription.String     `json:"id"`
	AlterID            subscription.Int        `json:"aid"`
	Security           subscription.String     `json:"scy"`
	Network            subscription.String     `json:"net"`
	HeaderType         subscription.String     `json:"type"`
	Host               subscription.String     `json:"host"`
	Path               subscription.String     `json:"path"`
	Seed               subscription.String     `json:"seed"`
	Mode               subscription.String     `json:"mode"`
	Extra              json.RawMessage         `json:"extra"`
	TLS                subscription.String     `json:"tls"`
	SNI                subscription.String     `json:"sni"`
	ALPN               subscription.StringList `json:"alpn"`
	Fingerprint        subscription.String     `json:"fp"`
	Insecure           subscription.Bool       `json:"insecure"`
	AllowInsecure      subscription.Bool       `json:"allowInsecure"`
	SkipCertVerify     subscription.Bool       `json:"skip-cert-verify"`
	VerifyServerName   subscription.StringList `json:"vcn"`
	PacketEncoding     subscription.String     `json:"packet_encoding"`
	PacketEncodingCaml subscription.String     `json:"packetEncoding"`
	XUDP               subscription.Bool       `json:"xudp"`
	TCPFastOpen        subscription.Bool       `json:"tfo"`
}

// parseVMessLink reads either shape of a VMess link: the base64 encoded object
// v2rayN exports, or the URL form of Xray, whose query is the one VLESS uses.
func parseVMessLink(link string) (option.Outbound, error) {
	decoded, isEncoded := subscription.DecodeBase64(strings.TrimPrefix(link, "vmess://"))
	if !isEncoded || !strings.HasPrefix(strings.TrimSpace(decoded), "{") {
		return parseVMessURL(link)
	}
	var payload vmessPayload
	if err := json.Unmarshal([]byte(decoded), &payload); err != nil {
		return option.Outbound{}, E.Cause(err, "invalid VMess link")
	}
	if payload.ID == "" {
		return option.Outbound{}, E.New("missing uuid")
	}
	if payload.Add == "" {
		return option.Outbound{}, E.New("missing server")
	}
	if payload.Port == 0 {
		return option.Outbound{}, E.New("missing server port")
	}
	if payload.TLS == "reality" {
		return option.Outbound{}, E.New("unsupported security: reality")
	}
	tls, err := vmessTLS(payload)
	if err != nil {
		return option.Outbound{}, err
	}
	transport, err := vmessTransport(payload, tls)
	if err != nil {
		return option.Outbound{}, err
	}
	alterID, err := payload.AlterID.Value("alterId")
	if err != nil {
		return option.Outbound{}, err
	}
	options := &option.VMessOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: string(payload.Add), ServerPort: uint16(payload.Port)},
		UUID:                        string(payload.ID),
		Security:                    subscription.VMessSecurity(string(payload.Security)),
		AlterId:                     alterID,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
		Transport:                   transport,
		DialerOptions:               option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: payload.TCPFastOpen.Value()}},
	}
	switch {
	case payload.PacketEncoding != "":
		options.PacketEncoding = string(payload.PacketEncoding)
	case payload.PacketEncodingCaml != "":
		options.PacketEncoding = string(payload.PacketEncodingCaml)
	case payload.XUDP.Value():
		options.PacketEncoding = "xudp"
	}
	return option.Outbound{
		Type:    C.TypeVMess,
		Tag:     string(payload.PS),
		Options: options,
	}, nil
}

func parseVMessURL(link string) (option.Outbound, error) {
	linkURL, err := parseLinkURL(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing uuid")
	}
	server, err := serverAddress(linkURL)
	if err != nil {
		return option.Outbound{}, err
	}
	port, err := serverPort(linkURL, 0)
	if err != nil {
		return option.Outbound{}, err
	}
	q := linkQuery(linkURL)
	tls, err := linkTLS(q, server, false)
	if err != nil {
		return option.Outbound{}, err
	}
	transport, err := linkTransport(q, tls)
	if err != nil {
		return option.Outbound{}, err
	}
	var alterID subscription.Int
	if value := q.get("alterId", "aid"); value != "" {
		if err = alterID.UnmarshalJSON([]byte(`"` + value + `"`)); err != nil {
			return option.Outbound{}, E.Cause(err, "invalid alterId")
		}
	}
	alterIDValue, err := alterID.Value("alterId")
	if err != nil {
		return option.Outbound{}, err
	}
	security := subscription.VMessSecurity(q.get("encryption", "scy"))
	return option.Outbound{
		Type: C.TypeVMess,
		Tag:  linkURL.Fragment,
		Options: &option.VMessOutboundOptions{
			ServerOptions:               option.ServerOptions{Server: server, ServerPort: port},
			UUID:                        linkURL.User.Username(),
			Security:                    security,
			AlterId:                     alterIDValue,
			PacketEncoding:              q.get("packetEncoding", "packet_encoding"),
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
			Transport:                   transport,
			DialerOptions:               option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: q.flag("tfo", "tcp-fast-open", "tcp_fast_open")}},
		},
	}, nil
}

func vmessTLS(payload vmessPayload) (*option.OutboundTLSOptions, error) {
	// h2 exists only over TLS, so a link that selects it means TLS whether it
	// says so or not.
	if !(payload.TLS == "tls" || payload.TLS == "1" || payload.TLS == "true" || payload.Network == "h2") {
		return nil, nil
	}
	tls := &option.OutboundTLSOptions{
		Enabled:          true,
		ServerName:       string(payload.Add),
		Insecure:         payload.Insecure.Value() || payload.AllowInsecure.Value() || payload.SkipCertVerify.Value(),
		ALPN:             badoption.Listable[string](payload.ALPN),
		VerifyServerName: badoption.Listable[string](payload.VerifyServerName),
	}
	if payload.SNI != "" {
		tls.ServerName = string(payload.SNI)
	} else if payload.Host != "" && payload.Network == "ws" {
		tls.ServerName = string(payload.Host)
	}
	// Xray-core imitates Chrome when a link names no fingerprint.
	utls, err := subscription.UTLSFingerprint(string(payload.Fingerprint), "chrome", false)
	if err != nil {
		return nil, err
	}
	tls.UTLS = utls
	return tls, nil
}

func vmessTransport(payload vmessPayload, tls *option.OutboundTLSOptions) (*option.V2RayTransportOptions, error) {
	switch strings.ToLower(string(payload.Network)) {
	case "", "tcp", "raw":
		var hosts []string
		if payload.Host != "" {
			hosts = strings.Split(string(payload.Host), ",")
		}
		return tcpHeaderTransport(string(payload.HeaderType), hosts, string(payload.Path), tls)
	case "ws", "websocket":
		path, earlyData := subscription.SplitWebsocketEarlyData(string(payload.Path))
		options := option.V2RayWebsocketOptions{Path: path}
		if host := websocketHost(string(payload.Host), tls); host != "" {
			options.Headers = badoption.HTTPHeader{"Host": []string{host}}
		}
		if earlyData > 0 {
			options.MaxEarlyData = earlyData
			options.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
		}
		ownALPN(tls)
		return &option.V2RayTransportOptions{
			Type:             C.V2RayTransportTypeWebsocket,
			WebsocketOptions: options,
		}, nil
	case "httpupgrade":
		path, _ := subscription.SplitWebsocketEarlyData(string(payload.Path))
		ownALPN(tls)
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTPUpgrade,
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
				Host: string(payload.Host),
				Path: path,
			},
		}, nil
	case "h2", "http", "h3":
		var host badoption.Listable[string]
		if payload.Host != "" {
			host = strings.Split(string(payload.Host), ",")
		}
		ownALPN(tls)
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Host: host,
				Path: string(payload.Path),
			},
		}, nil
	case "grpc", "gun":
		// The service name lives in the path in current exports and in the host
		// in older ones.
		serviceName := string(payload.Path)
		if serviceName == "" {
			serviceName = string(payload.Host)
		}
		ownALPN(tls)
		return &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{ServiceName: serviceName},
		}, nil
	case "xhttp", "splithttp":
		settings, err := xhttp.LinkSettings(string(payload.Host), string(payload.Path), vmessXHTTPMode(payload), string(payload.Extra))
		if err != nil {
			return nil, err
		}
		return settings.Build(xray.XHTTPDownload)
	case "quic":
		return nil, E.New("unsupported QUIC transport")
	}
	return nil, E.New("unsupported transport: ", string(payload.Network))
}

// v2rayN keeps the XHTTP mode in "type", the field of the TCP header, and reads it back from
// there; "none" or anything else in it leaves the mode to the client, as v2rayN does.
func vmessXHTTPMode(payload vmessPayload) string {
	if payload.Mode != "" {
		return string(payload.Mode)
	}
	switch mode := strings.ToLower(string(payload.HeaderType)); mode {
	case "auto", "packet-up", "stream-up", "stream-one":
		return mode
	}
	return ""
}
