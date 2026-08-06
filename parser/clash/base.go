package clash

import (
	"encoding/base64"
	"fmt"
	"strings"

	boxCommon "github.com/sagernet/sing-box/common"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type HTTPOptions struct {
	Method  string               `yaml:"method,omitempty"`
	Path    []string             `yaml:"path,omitempty"`
	Headers badoption.HTTPHeader `yaml:"headers,omitempty"`
}

type HTTP2Options struct {
	Host []string `yaml:"host,omitempty"`
	Path string   `yaml:"path,omitempty"`
}

type GrpcOptions struct {
	GrpcServiceName string `yaml:"grpc-service-name,omitempty"`
}

type WSOptions struct {
	Path                string            `yaml:"path,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty"`
	MaxEarlyData        int               `yaml:"max-early-data,omitempty"`
	EarlyDataHeaderName string            `yaml:"early-data-header-name,omitempty"`
	V2rayHttpUpgrade    bool              `yaml:"v2ray-http-upgrade,omitempty"`
}

type XHTTPOptions struct {
	Path                 string            `yaml:"path,omitempty"`
	Host                 string            `yaml:"host,omitempty"`
	Mode                 string            `yaml:"mode,omitempty"`
	Headers              map[string]string `yaml:"headers,omitempty"`
	NoGRPCHeader         bool              `yaml:"no-grpc-header,omitempty"`
	XPaddingBytes        any               `yaml:"x-padding-bytes,omitempty"`
	XPaddingObfsMode     bool              `yaml:"x-padding-obfs-mode,omitempty"`
	XPaddingKey          string            `yaml:"x-padding-key,omitempty"`
	XPaddingHeader       string            `yaml:"x-padding-header,omitempty"`
	XPaddingPlacement    string            `yaml:"x-padding-placement,omitempty"`
	XPaddingMethod       string            `yaml:"x-padding-method,omitempty"`
	UplinkHTTPMethod     string            `yaml:"uplink-http-method,omitempty"`
	SessionPlacement     string            `yaml:"session-placement,omitempty"`
	SessionKey           string            `yaml:"session-key,omitempty"`
	SessionTable         string            `yaml:"session-table,omitempty"`
	SessionLength        any               `yaml:"session-length,omitempty"`
	SeqPlacement         string            `yaml:"seq-placement,omitempty"`
	SeqKey               string            `yaml:"seq-key,omitempty"`
	UplinkDataPlacement  string            `yaml:"uplink-data-placement,omitempty"`
	UplinkDataKey        string            `yaml:"uplink-data-key,omitempty"`
	UplinkChunkSize      any               `yaml:"uplink-chunk-size,omitempty"`
	ScMaxEachPostBytes   any               `yaml:"sc-max-each-post-bytes,omitempty"`
	ScMinPostsIntervalMs any               `yaml:"sc-min-posts-interval-ms,omitempty"`
	ScStreamUpServerSecs any               `yaml:"sc-stream-up-server-secs,omitempty"`
	Xmux                 *XHTTPXmuxOptions `yaml:"reuse-settings,omitempty"`
}

type XHTTPXmuxOptions struct {
	MaxConcurrency   any `yaml:"max-concurrency,omitempty"`
	MaxConnections   any `yaml:"max-connections,omitempty"`
	CMaxReuseTimes   any `yaml:"c-max-reuse-times,omitempty"`
	HMaxRequestTimes any `yaml:"h-max-request-times,omitempty"`
	HMaxReusableSecs any `yaml:"h-max-reusable-secs,omitempty"`
	HKeepAlivePeriod any `yaml:"h-keep-alive-period,omitempty"`
}

func (x XHTTPOptions) Build() *option.V2RayTransportOptions {
	padding, _ := boxCommon.ParseXHTTPRange("100-1000")
	if value, ok := clashXHTTPRange(x.XPaddingBytes); ok {
		padding = value
	}
	base := option.V2RayXHTTPBaseOptions{
		Host:                x.Host,
		Path:                x.Path,
		Headers:             x.Headers,
		XPaddingBytes:       padding,
		NoGRPCHeader:        x.NoGRPCHeader,
		XPaddingObfsMode:    x.XPaddingObfsMode,
		XPaddingKey:         x.XPaddingKey,
		XPaddingHeader:      x.XPaddingHeader,
		XPaddingPlacement:   x.XPaddingPlacement,
		XPaddingMethod:      x.XPaddingMethod,
		UplinkHTTPMethod:    x.UplinkHTTPMethod,
		SessionPlacement:    x.SessionPlacement,
		SessionKey:          x.SessionKey,
		SessionIDTable:      x.SessionTable,
		SeqPlacement:        x.SeqPlacement,
		SeqKey:              x.SeqKey,
		UplinkDataPlacement: x.UplinkDataPlacement,
		UplinkDataKey:       x.UplinkDataKey,
	}
	setClashXHTTPRangeValue(x.SessionLength, &base.SessionIDLength)
	setClashXHTTPRange(x.UplinkChunkSize, &base.UplinkChunkSize)
	setClashXHTTPRange(x.ScMaxEachPostBytes, &base.ScMaxEachPostBytes)
	setClashXHTTPRange(x.ScMinPostsIntervalMs, &base.ScMinPostsIntervalMs)
	setClashXHTTPRange(x.ScStreamUpServerSecs, &base.ScStreamUpServerSecs)
	if x.Xmux != nil {
		base.Xmux = &option.V2RayXHTTPXmuxOptions{}
		setClashXHTTPRangeValue(x.Xmux.MaxConcurrency, &base.Xmux.MaxConcurrency)
		setClashXHTTPRangeValue(x.Xmux.MaxConnections, &base.Xmux.MaxConnections)
		setClashXHTTPRangeValue(x.Xmux.CMaxReuseTimes, &base.Xmux.CMaxReuseTimes)
		setClashXHTTPRangeValue(x.Xmux.HMaxRequestTimes, &base.Xmux.HMaxRequestTimes)
		setClashXHTTPRangeValue(x.Xmux.HMaxReusableSecs, &base.Xmux.HMaxReusableSecs)
		if value, ok := clashXHTTPInt64(x.Xmux.HKeepAlivePeriod); ok {
			base.Xmux.HKeepAlivePeriod = value
		}
	}
	mode := x.Mode
	if mode == "" {
		mode = "auto"
	}
	return &option.V2RayTransportOptions{
		Type: C.V2RayTransportTypeXHTTP,
		XHTTPOptions: option.V2RayXHTTPOptions{
			Mode:                  mode,
			V2RayXHTTPBaseOptions: base,
		},
	}
}

func setClashXHTTPRange(value any, target **badoption.Range[int]) {
	if parsed, ok := clashXHTTPRange(value); ok {
		*target = &parsed
	}
}

func setClashXHTTPRangeValue(value any, target *badoption.Range[int]) {
	if parsed, ok := clashXHTTPRange(value); ok {
		*target = parsed
	}
}

func clashXHTTPRange(value any) (badoption.Range[int], bool) {
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" || text == "<nil>" {
		return badoption.Range[int]{}, false
	}
	result, err := boxCommon.ParseXHTTPRange(text)
	return result, err == nil
}

func clashXHTTPInt64(value any) (int64, bool) {
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" || text == "<nil>" {
		return 0, false
	}
	var result int64
	if _, err := fmt.Sscan(text, &result); err != nil {
		return 0, false
	}
	return result, true
}

type MuxOptions struct {
	Enabled        bool           `yaml:"enabled,omitempty"`
	Protocol       string         `yaml:"protocol,omitempty"`
	MaxConnections int            `yaml:"max-connections,omitempty"`
	MinStreams     int            `yaml:"min-streams,omitempty"`
	MaxStreams     int            `yaml:"max-streams,omitempty"`
	Padding        bool           `yaml:"padding,omitempty"`
	BrutalOpts     *BrutalOptions `yaml:"brutal-opts,omitempty"`
}

func (s *MuxOptions) Build() *option.OutboundMultiplexOptions {
	if s == nil {
		return nil
	}
	return &option.OutboundMultiplexOptions{
		Enabled:        s.Enabled,
		Protocol:       s.Protocol,
		MaxConnections: s.MaxConnections,
		MinStreams:     s.MinStreams,
		MaxStreams:     s.MaxStreams,
		Padding:        s.Padding,
		Brutal:         s.BrutalOpts.Build(),
	}
}

type BrutalOptions struct {
	Enabled bool   `yaml:"enabled,omitempty"`
	Up      string `yaml:"up,omitempty"`
	Down    string `yaml:"down,omitempty"`
}

func (b *BrutalOptions) Build() *option.BrutalOptions {
	if b == nil {
		return nil
	}
	return &option.BrutalOptions{
		Enabled:  b.Enabled,
		UpMbps:   clashSpeedToIntMbps(b.Up),
		DownMbps: clashSpeedToIntMbps(b.Down),
	}
}

type RealityOptions struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

func (r *RealityOptions) Build() *option.OutboundRealityOptions {
	if r == nil {
		return nil
	}
	return &option.OutboundRealityOptions{
		Enabled:   true,
		PublicKey: r.PublicKey,
		ShortID:   r.ShortID,
	}
}

type ECHOptions struct {
	Enable bool   `yaml:"enable,omitempty"`
	Config string `yaml:"config,omitempty"`
}

func (e *ECHOptions) Build() *option.OutboundECHOptions {
	if e == nil {
		return nil
	}
	list, err := base64.StdEncoding.DecodeString(e.Config)
	if err != nil {
		return nil
	}
	return &option.OutboundECHOptions{
		Enabled: e.Enable,
		Config:  trimStringArray(strings.Split(string(list), "\n")),
	}
}

type TLSOptions struct {
	TLS               bool            `yaml:"tls,omitempty"`
	SNI               string          `yaml:"sni,omitempty"`
	SkipCertVerify    bool            `yaml:"skip-cert-verify,omitempty"`
	ALPN              []string        `yaml:"alpn,omitempty"`
	ClientFingerprint string          `yaml:"client-fingerprint,omitempty"`
	CustomCA          string          `yaml:"ca,omitempty"`
	CustomCAString    string          `yaml:"ca-str,omitempty"`
	Certificate       string          `yaml:"certificate,omitempty"`
	PrivateKey        string          `yaml:"private-key,omitempty"`
	ECHOpts           *ECHOptions     `yaml:"ech-opts,omitempty"`
	RealityOpts       *RealityOptions `yaml:"reality-opts,omitempty"`
}

func (t *TLSOptions) Build() *option.OutboundTLSOptions {
	if t == nil {
		return nil
	}
	options := &option.OutboundTLSOptions{
		Enabled:         t.TLS,
		ServerName:      t.SNI,
		Insecure:        t.SkipCertVerify,
		ALPN:            t.ALPN,
		UTLS:            clashClientFingerprint(t.ClientFingerprint),
		Certificate:     trimStringArray(strings.Split(t.CustomCAString, "\n")),
		CertificatePath: t.CustomCA,
		ECH:             t.ECHOpts.Build(),
		Reality:         t.RealityOpts.Build(),
	}
	if strings.HasPrefix(t.Certificate, "-----BEGIN ") {
		options.ClientCertificate = trimStringArray(strings.Split(t.Certificate, "\n"))
	} else {
		options.ClientCertificatePath = t.Certificate
	}
	if strings.HasPrefix(t.PrivateKey, "-----BEGIN ") {
		options.ClientKey = trimStringArray(strings.Split(t.PrivateKey, "\n"))
	} else {
		options.ClientKeyPath = t.PrivateKey
	}
	return options
}

type DialerOptions struct {
	TFO         bool   `yaml:"tfo,omitempty"`
	MPTCP       bool   `yaml:"mptcp,omitempty"`
	Interface   string `yaml:"interface-name,omitempty"`
	RoutingMark int    `yaml:"routing-mark,omitempty"`
	DialerProxy string `yaml:"dialer-proxy,omitempty"`
}

func (b *DialerOptions) Build() option.DialerOptions {
	return option.DialerOptions{
		Detour:        b.DialerProxy,
		BindInterface: b.Interface,
		TCPFastOpen:   b.TFO,
		TCPMultiPath:  b.MPTCP,
		RoutingMark:   option.FwMark(b.RoutingMark),
	}
}

type ServerOptions struct {
	Server string `yaml:"server"`
	Port   int    `yaml:"port"`
}

func (s *ServerOptions) Build() option.ServerOptions {
	return option.ServerOptions{
		Server:     s.Server,
		ServerPort: uint16(s.Port),
	}
}
