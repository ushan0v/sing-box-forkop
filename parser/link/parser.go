package link

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/common"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func ParseSubscriptionLink(link string) (option.Outbound, error) {
	reg := regexp.MustCompile(`^(.*?)(://)(.*?)([@?#].*)?$`)
	result := reg.FindStringSubmatch(link)
	if result == nil {
		return option.Outbound{}, E.New("invalid link")
	}

	scheme := result[1]
	switch scheme {
	case "socks", "socks4", "socks4a", "socks5":
		return parseSOCKSLink(link)
	case "tuic":
		return parseTuicLink(link)
	case "trojan":
		return parseTrojanLink(link)
	case "vless":
		return parseVLESSLink(link)
	case "hysteria":
		return parseHysteriaLink(link)
	case "hy2", "hysteria2":
		return parseHysteria2Link(link)
	case "anytls":
		return parseAnyTLSLink(link)
	}
	result[3], _ = common.DecodeBase64URLSafe(result[3])
	if scheme == "ss" {
		credentials := strings.SplitN(result[3], ":", 2)
		if len(credentials) == 2 {
			result[3] = url.UserPassword(credentials[0], credentials[1]).String()
		}
	}
	link = strings.Join(result[1:], "")
	switch scheme {
	case "ss":
		return parseShadowsocksLink(link)
	case "vmess":
		return parseVMessLink(link)
	default:
		return option.Outbound{}, E.New("unsupported scheme: ", scheme)
	}
}
