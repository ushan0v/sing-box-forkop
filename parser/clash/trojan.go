package clash

import "github.com/sagernet/sing-box/option"

type TrojanOption struct {
	DialerOptions `yaml:",inline"`
	ServerOptions `yaml:",inline"`
	TLSOptions    `yaml:",inline"`
	Password      string       `yaml:"password"`
	UDP           bool         `yaml:"udp,omitempty"`
	Network       string       `yaml:"network,omitempty"`
	GrpcOpts      GrpcOptions  `yaml:"grpc-opts,omitempty"`
	WSOpts        WSOptions    `yaml:"ws-opts,omitempty"`
	XHTTPOpts     XHTTPOptions `yaml:"xhttp-opts,omitempty"`
	MuxOpts       *MuxOptions  `yaml:"smux,omitempty"`
}

func (t *TrojanOption) Build() any {
	t.TLS = true
	return &option.TrojanOutboundOptions{
		DialerOptions:               t.DialerOptions.Build(),
		ServerOptions:               t.ServerOptions.Build(),
		Password:                    t.Password,
		Network:                     clashNetworks(t.UDP),
		OutboundTLSOptionsContainer: clashTLSOptions(t.Server, &t.TLSOptions),
		Multiplex:                   t.MuxOpts.Build(),
		Transport:                   clashTransport(t.Network, HTTPOptions{}, HTTP2Options{}, t.GrpcOpts, t.WSOpts, t.XHTTPOpts),
	}
}
