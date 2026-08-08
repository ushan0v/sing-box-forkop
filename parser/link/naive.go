package link

import (
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	"golang.org/x/net/http/httpguts"
)

func parseNaiveLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.Hostname() == "" {
		return option.Outbound{}, E.New("missing server")
	}
	serverPort := uint64(443)
	if linkURL.Port() != "" {
		serverPort, err = strconv.ParseUint(linkURL.Port(), 10, 16)
		if err != nil || serverPort == 0 {
			return option.Outbound{}, E.New("invalid server port")
		}
	}
	query := linkURL.Query()
	tlsServerName := query.Get("sni")
	if tlsServerName == "" {
		tlsServerName = linkURL.Hostname()
	}
	options := option.NaiveOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     linkURL.Hostname(),
			ServerPort: uint16(serverPort),
		},
		QUIC: linkURL.Scheme == "naive+quic",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: tlsServerName,
			},
		},
	}
	if linkURL.User != nil {
		options.Username = linkURL.User.Username()
		options.Password, _ = linkURL.User.Password()
	}
	if extraHeaders := query.Get("extra-headers"); extraHeaders != "" {
		options.ExtraHeaders, err = parseNaiveExtraHeaders(extraHeaders)
		if err != nil {
			return option.Outbound{}, err
		}
	}
	return option.Outbound{
		Type:    C.TypeNaive,
		Tag:     linkURL.Fragment,
		Options: &options,
	}, nil
}

func parseNaiveExtraHeaders(value string) (badoption.HTTPHeader, error) {
	headers := badoption.HTTPHeader{}
	for _, line := range strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n") {
		if line == "" {
			continue
		}
		name, headerValue, found := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		headerValue = strings.TrimSpace(headerValue)
		if !found || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(headerValue) {
			return nil, E.New("invalid extra-headers entry: ", line)
		}
		headers[name] = append(headers[name], headerValue)
	}
	return headers, nil
}
