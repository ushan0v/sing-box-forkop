package clash

import (
	"context"

	providerAdapter "github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"gopkg.in/yaml.v3"
)

type ClashConfig struct {
	Proxies []ClashProxy `yaml:"proxies"`
}

type _ClashProxy struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Options Proxy  `yaml:"-"`

	SingType string `yaml:"-"`
}
type ClashProxy _ClashProxy

type Proxy interface {
	Build() any
}

func (c *ClashProxy) UnmarshalYAML(value *yaml.Node) error {
	err := value.Decode((*_ClashProxy)(c))
	if err != nil {
		return err
	}
	var options Proxy
	switch c.Type {
	case "ss":
		c.SingType = C.TypeShadowsocks
		options = &ShadowSocksOption{}
	case "tuic":
		c.SingType = C.TypeTUIC
		options = &TuicOption{}
	case "vmess":
		c.SingType = C.TypeVMess
		options = &VmessOption{}
	case "vless":
		c.SingType = C.TypeVLESS
		options = &VlessOption{}
	case "socks5":
		c.SingType = C.TypeSOCKS
		options = &Socks5Option{}
	case "http":
		c.SingType = C.TypeHTTP
		options = &HttpOption{}
	case "trojan":
		c.SingType = C.TypeTrojan
		options = &TrojanOption{}
	case "hysteria":
		c.SingType = C.TypeHysteria
		options = &HysteriaOption{}
	case "hysteria2":
		c.SingType = C.TypeHysteria2
		options = &Hysteria2Option{}
	case "ssh":
		c.SingType = C.TypeSSH
		options = &SSHOption{}
	case "anytls":
		c.SingType = C.TypeAnyTLS
		options = &AnyTLSOption{}
	default:
		return nil
	}
	err = value.Decode(options)
	if err != nil {
		return err
	}
	c.Options = options
	return nil
}

func (c *ClashProxy) Build() option.Outbound {
	outbound := option.Outbound{
		Tag:  c.Name,
		Type: c.SingType,
	}
	if c.Options != nil {
		outbound.Options = c.Options.Build()
	}
	return outbound
}

func ParseClashSubscription(_ context.Context, content string) ([]option.Outbound, error) {
	config := &ClashConfig{}
	err := yaml.Unmarshal([]byte(content), &config)
	if err != nil {
		return nil, E.Cause(err, "parse clash config")
	}
	invalidTags := make(map[string]bool)
	outbounds := make([]option.Outbound, 0, len(config.Proxies))
	knownTags := make(map[string]bool, len(config.Proxies))
	for _, proxy := range config.Proxies {
		if proxy.SingType == "" {
			if proxy.Name != "" {
				invalidTags[proxy.Name] = true
			}
			continue
		}
		outbound := proxy.Build()
		outbounds = append(outbounds, outbound)
		if outbound.Tag != "" {
			knownTags[outbound.Tag] = true
		}
	}
	for _, outbound := range outbounds {
		dialer, loaded := outbound.Options.(option.DialerOptionsWrapper)
		if !loaded {
			continue
		}
		detour := dialer.TakeDialerOptions().Detour
		if detour != "" && !knownTags[detour] {
			invalidTags[detour] = true
		}
	}
	return providerAdapter.FilterInvalidOutbounds(outbounds, invalidTags), nil
}
