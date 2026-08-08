package link

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"

	mieruappctl "github.com/enfein/mieru/v3/pkg/appctl"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"google.golang.org/protobuf/proto"
)

func parseMieruLink(link string) (option.Outbound, error) {
	link, tag, err := splitMieruLinkFragment(link)
	if err != nil {
		return option.Outbound{}, err
	}
	config, err := mieruappctl.ParseURLClientConfig(link)
	if err != nil {
		return option.Outbound{}, err
	}
	profile, err := selectMieruProfile(config)
	if err != nil {
		return option.Outbound{}, err
	}
	options, err := mieruProfileToOutboundOptions(profile)
	if err != nil {
		return option.Outbound{}, err
	}
	return option.Outbound{
		Type:    C.TypeMieru,
		Tag:     tag,
		Options: options,
	}, nil
}

func splitMieruLinkFragment(link string) (string, string, error) {
	link, fragment, found := strings.Cut(link, "#")
	if !found {
		return link, "", nil
	}
	tag, err := url.PathUnescape(fragment)
	if err != nil {
		return "", "", E.Cause(err, "decode fragment")
	}
	return link, tag, nil
}

func selectMieruProfile(config *mierupb.ClientConfig) (*mierupb.ClientProfile, error) {
	profiles := config.GetProfiles()
	if activeProfile := config.GetActiveProfile(); activeProfile != "" {
		for _, profile := range profiles {
			if profile.GetProfileName() == activeProfile {
				return profile, nil
			}
		}
		return nil, E.New("active mieru profile not found: ", activeProfile)
	}
	if len(profiles) != 1 {
		return nil, E.New("mieru link must contain exactly one profile without active_profile")
	}
	return profiles[0], nil
}

func mieruProfileToOutboundOptions(profile *mierupb.ClientProfile) (*option.MieruOutboundOptions, error) {
	if len(profile.GetServers()) != 1 {
		return nil, E.New("mieru profile must contain exactly one server")
	}
	if profile.GetMtu() != 0 && profile.GetMtu() != 1400 {
		return nil, E.New("unsupported mieru MTU: ", profile.GetMtu())
	}
	if mode := profile.GetHandshakeMode(); mode != mierupb.HandshakeMode_HANDSHAKE_DEFAULT && mode != mierupb.HandshakeMode_HANDSHAKE_STANDARD {
		return nil, E.New("unsupported mieru handshake mode: ", mode.String())
	}
	server := profile.GetServers()[0]
	serverAddress := server.GetDomainName()
	if serverAddress == "" {
		serverAddress = server.GetIpAddress()
	}
	if serverAddress == "" {
		return nil, E.New("mieru server address is empty")
	}
	user := profile.GetUser()
	if user.GetName() == "" || user.GetPassword() == "" {
		return nil, E.New("mieru username and password are required")
	}
	bindings := server.GetPortBindings()
	if len(bindings) == 0 {
		return nil, E.New("mieru server has no port bindings")
	}
	transport := bindings[0].GetProtocol().String()
	if transport != "TCP" && transport != "UDP" {
		return nil, E.New("invalid mieru transport: ", transport)
	}
	options := &option.MieruOutboundOptions{
		ServerOptions: option.ServerOptions{Server: serverAddress},
		Transport:     transport,
		UserName:      user.GetName(),
		Password:      user.GetPassword(),
	}
	if profile.Multiplexing != nil && profile.GetMultiplexing().GetLevel() != mierupb.MultiplexingLevel_MULTIPLEXING_DEFAULT {
		options.Multiplexing = profile.GetMultiplexing().GetLevel().String()
	}
	if trafficPattern := profile.GetTrafficPattern(); trafficPattern != nil {
		content, err := proto.Marshal(trafficPattern)
		if err != nil {
			return nil, E.Cause(err, "marshal mieru traffic pattern")
		}
		options.TrafficPattern = base64.StdEncoding.EncodeToString(content)
	}
	for _, binding := range bindings {
		if binding.GetProtocol().String() != transport {
			return nil, E.New("mixed mieru transports cannot be represented by one outbound")
		}
		if portRange := binding.GetPortRange(); portRange != "" {
			options.ServerPortRanges = append(options.ServerPortRanges, portRange)
			continue
		}
		port := binding.GetPort()
		if port < 1 || port > 65535 {
			return nil, E.New("invalid mieru server port: ", port)
		}
		if options.ServerPort == 0 {
			options.ServerPort = uint16(port)
		} else {
			options.ServerPortRanges = append(options.ServerPortRanges, strconv.Itoa(int(port))+"-"+strconv.Itoa(int(port)))
		}
	}
	return options, nil
}
