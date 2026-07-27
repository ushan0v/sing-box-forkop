package link

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func parseHysteria2Link(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	var options option.Hysteria2OutboundOptions
	TLSOptions := option.OutboundTLSOptions{
		Enabled: true,
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	Obfs := &option.Hysteria2Obfs{}
	options.ServerPort = uint16(443)
	options.Server = linkURL.Hostname()
	TLSOptions.ServerName = linkURL.Hostname()
	if linkURL.User != nil {
		options.Password = linkURL.User.Username()
	}
	if linkURL.Port() != "" {
		options.ServerPort = common.StringToType[uint16](linkURL.Port())
	}
	for key, values := range linkURL.Query() {
		value := values[0]
		switch key {
		case "up":
			options.UpMbps, _ = strconv.Atoi(value)
		case "down":
			options.DownMbps, _ = strconv.Atoi(value)
		case "obfs":
			if value == "salamander" {
				Obfs.Type = "salamander"
				options.Obfs = Obfs
			}
		case "obfs-password":
			Obfs.Password = value
		case "insecure", "skip-cert-verify":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		case "sni", "peer":
			TLSOptions.ServerName = value
		case "alpn":
			TLSOptions.ALPN = strings.Split(value, ",")
		}
	}
	outbound := option.Outbound{
		Type: C.TypeHysteria2,
		Tag:  linkURL.Fragment,
	}
	options.TLS = &TLSOptions
	outbound.Options = &options
	return outbound, nil
}
