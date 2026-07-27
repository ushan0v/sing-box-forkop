package link

import (
	"net/url"

	"github.com/sagernet/sing-box/common"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func parseSOCKSLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.Hostname() == "" || linkURL.Port() == "" {
		return option.Outbound{}, E.New("missing server or port")
	}
	version := "5"
	switch linkURL.Scheme {
	case "socks4":
		version = "4"
	case "socks4a":
		version = "4a"
	}
	options := &option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     linkURL.Hostname(),
			ServerPort: common.StringToType[uint16](linkURL.Port()),
		},
		Version: version,
	}
	if options.ServerPort == 0 {
		return option.Outbound{}, E.New("invalid server port")
	}
	if linkURL.User != nil {
		options.Username = linkURL.User.Username()
		options.Password, _ = linkURL.User.Password()
	}
	return option.Outbound{
		Type:    C.TypeSOCKS,
		Tag:     linkURL.Fragment,
		Options: options,
	}, nil
}
