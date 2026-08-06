package xray

import (
	"encoding/json"
	"strconv"
	"strings"
)

type document struct {
	Outbounds []json.RawMessage `json:"outbounds"`
}

type sourceOutbound struct {
	Protocol       string          `json:"protocol"`
	Tag            string          `json:"tag"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings streamSettings  `json:"streamSettings"`
	Sockopt        sockopt         `json:"sockopt"`
	ProxySettings  *proxySettings  `json:"proxySettings"`
}

type proxySettings struct {
	Tag            string `json:"tag"`
	TransportLayer bool   `json:"transportLayer"`
}

type sockopt struct {
	DialerProxy string `json:"dialerProxy"`
}

type streamSettings struct {
	Network             string              `json:"network"`
	Security            string              `json:"security"`
	Sockopt             sockopt             `json:"sockopt"`
	HysteriaSettings    hysteriaSettings    `json:"hysteriaSettings"`
	TLSSettings         tlsSettings         `json:"tlsSettings"`
	RealitySettings     tlsSettings         `json:"realitySettings"`
	WSSettings          websocketSettings   `json:"wsSettings"`
	GRPCSettings        grpcSettings        `json:"grpcSettings"`
	HTTPSettings        httpSettings        `json:"httpSettings"`
	HTTPUpgradeSettings httpUpgradeSettings `json:"httpupgradeSettings"`
	XHTTPSettings       xhttpSettings       `json:"xhttpSettings"`
	KCPSettings         kcpSettings         `json:"kcpSettings"`
}

type hysteriaSettings struct {
	Version integer `json:"version"`
	Auth    string  `json:"auth"`
}

type tlsSettings struct {
	ServerName      string          `json:"serverName"`
	ServerNameSnake string          `json:"server_name"`
	SNI             string          `json:"sni"`
	ALPN            stringList      `json:"alpn"`
	AllowInsecure   json.RawMessage `json:"allowInsecure"`
	Insecure        json.RawMessage `json:"insecure"`
	Fingerprint     string          `json:"fingerprint"`
	FP              string          `json:"fp"`
	PublicKey       string          `json:"publicKey"`
	PublicKeySnake  string          `json:"public_key"`
	ShortID         string          `json:"shortId"`
	ShortIDSnake    string          `json:"short_id"`
}

type websocketSettings struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

type grpcSettings struct {
	ServiceName      string `json:"serviceName"`
	ServiceNameSnake string `json:"service_name"`
}

type httpSettings struct {
	Host stringList `json:"host"`
	Path stringList `json:"path"`
}

type httpUpgradeSettings struct {
	Host string `json:"host"`
	Path string `json:"path"`
}

type xhttpSettings struct {
	Host  string          `json:"host"`
	Path  string          `json:"path"`
	Mode  string          `json:"mode"`
	Extra json.RawMessage `json:"extra"`
}

type kcpSettings struct {
	MTU              uint32 `json:"mtu"`
	TTI              uint32 `json:"tti"`
	UplinkCapacity   uint32 `json:"uplinkCapacity"`
	DownlinkCapacity uint32 `json:"downlinkCapacity"`
	Congestion       bool   `json:"congestion"`
	ReadBufferSize   uint32 `json:"readBufferSize"`
	WriteBufferSize  uint32 `json:"writeBufferSize"`
	Seed             string `json:"seed"`
	Header           struct {
		Type string `json:"type"`
	} `json:"header"`
}

type port uint16

func (p *port) UnmarshalJSON(content []byte) error {
	var number uint64
	if err := json.Unmarshal(content, &number); err != nil {
		var text string
		if json.Unmarshal(content, &text) != nil {
			return nil
		}
		number, _ = strconv.ParseUint(text, 10, 16)
	}
	if number > 0 && number <= 65535 {
		*p = port(number)
	}
	return nil
}

type integer int

func (i *integer) UnmarshalJSON(content []byte) error {
	var number int
	if err := json.Unmarshal(content, &number); err != nil {
		var text string
		if json.Unmarshal(content, &text) != nil {
			return nil
		}
		number, _ = strconv.Atoi(text)
	}
	*i = integer(number)
	return nil
}

type stringList []string

func (l *stringList) UnmarshalJSON(content []byte) error {
	var values []string
	if err := json.Unmarshal(content, &values); err == nil {
		*l = values
		return nil
	}
	var value string
	if err := json.Unmarshal(content, &value); err != nil {
		return err
	}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			*l = append(*l, item)
		}
	}
	return nil
}

func first(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func truthy(value json.RawMessage) bool {
	var boolean bool
	if json.Unmarshal(value, &boolean) == nil {
		return boolean
	}
	var text string
	return json.Unmarshal(value, &text) == nil && (text == "1" || strings.EqualFold(text, "true"))
}
