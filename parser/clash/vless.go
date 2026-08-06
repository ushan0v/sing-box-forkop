package clash

import "github.com/sagernet/sing-box/option"

type VlessOption struct {
	DialerOptions  `yaml:",inline"`
	ServerOptions  `yaml:",inline"`
	*TLSOptions    `yaml:",inline"`
	UUID           string       `yaml:"uuid"`
	Flow           string       `yaml:"flow,omitempty"`
	UDP            bool         `yaml:"udp,omitempty"`
	PacketAddr     bool         `yaml:"packet-addr,omitempty"`
	XUDP           bool         `yaml:"xudp,omitempty"`
	PacketEncoding string       `yaml:"packet-encoding,omitempty"`
	Network        string       `yaml:"network,omitempty"`
	ServerName     string       `yaml:"servername,omitempty"`
	HTTPOpts       HTTPOptions  `yaml:"http-opts,omitempty"`
	HTTP2Opts      HTTP2Options `yaml:"h2-opts,omitempty"`
	GrpcOpts       GrpcOptions  `yaml:"grpc-opts,omitempty"`
	WSOpts         WSOptions    `yaml:"ws-opts,omitempty"`
	XHTTPOpts      XHTTPOptions `yaml:"xhttp-opts,omitempty"`
	MuxOpts        *MuxOptions  `yaml:"smux,omitempty"`
}

func (v *VlessOption) Build() any {
	if v.TLSOptions != nil {
		v.SNI = v.ServerName
	}
	switch v.PacketEncoding {
	case "":
		if v.PacketAddr {
			v.PacketEncoding = "packetaddr"
		} else {
			v.PacketEncoding = "xudp"
		}
	case "packet":
		v.PacketEncoding = "packetaddr"
	}
	return &option.VLESSOutboundOptions{
		DialerOptions:               v.DialerOptions.Build(),
		ServerOptions:               v.ServerOptions.Build(),
		UUID:                        v.UUID,
		Flow:                        v.Flow,
		Network:                     clashNetworks(v.UDP),
		OutboundTLSOptionsContainer: clashTLSOptions(v.Server, v.TLSOptions),
		Multiplex:                   v.MuxOpts.Build(),
		Transport:                   clashTransport(v.Network, v.HTTPOpts, v.HTTP2Opts, v.GrpcOpts, v.WSOpts, v.XHTTPOpts),
		PacketEncoding:              &v.PacketEncoding,
	}
}
