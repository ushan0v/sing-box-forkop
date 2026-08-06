package clash

import "github.com/sagernet/sing-box/option"

type VmessOption struct {
	DialerOptions       `yaml:",inline"`
	ServerOptions       `yaml:",inline"`
	*TLSOptions         `yaml:",inline"`
	UUID                string       `yaml:"uuid"`
	AlterID             int          `yaml:"alterId"`
	Cipher              string       `yaml:"cipher"`
	UDP                 bool         `yaml:"udp,omitempty"`
	Network             string       `yaml:"network,omitempty"`
	ServerName          string       `yaml:"servername,omitempty"`
	HTTPOpts            HTTPOptions  `yaml:"http-opts,omitempty"`
	HTTP2Opts           HTTP2Options `yaml:"h2-opts,omitempty"`
	GrpcOpts            GrpcOptions  `yaml:"grpc-opts,omitempty"`
	WSOpts              WSOptions    `yaml:"ws-opts,omitempty"`
	XHTTPOpts           XHTTPOptions `yaml:"xhttp-opts,omitempty"`
	PacketAddr          bool         `yaml:"packet-addr,omitempty"`
	XUDP                bool         `yaml:"xudp,omitempty"`
	PacketEncoding      string       `yaml:"packet-encoding,omitempty"`
	GlobalPadding       bool         `yaml:"global-padding,omitempty"`
	AuthenticatedLength bool         `yaml:"authenticated-length,omitempty"`
	MuxOpts             *MuxOptions  `yaml:"smux,omitempty"`
}

func (v *VmessOption) Build() any {
	if v.TLSOptions != nil {
		v.SNI = v.ServerName
	}
	switch v.PacketEncoding {
	case "":
		if v.XUDP {
			v.PacketEncoding = "xudp"
		} else if v.PacketAddr {
			v.PacketEncoding = "packetaddr"
		}
	case "packet":
		v.PacketEncoding = "packetaddr"
	}
	return &option.VMessOutboundOptions{
		DialerOptions:               v.DialerOptions.Build(),
		ServerOptions:               v.ServerOptions.Build(),
		UUID:                        v.UUID,
		Security:                    v.Cipher,
		AlterId:                     v.AlterID,
		GlobalPadding:               v.GlobalPadding,
		AuthenticatedLength:         v.AuthenticatedLength,
		Network:                     clashNetworks(v.UDP),
		OutboundTLSOptionsContainer: clashTLSOptions(v.Server, v.TLSOptions),
		PacketEncoding:              v.PacketEncoding,
		Multiplex:                   v.MuxOpts.Build(),
		Transport:                   clashTransport(v.Network, v.HTTPOpts, v.HTTP2Opts, v.GrpcOpts, v.WSOpts, v.XHTTPOpts),
	}
}
