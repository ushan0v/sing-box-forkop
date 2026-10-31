package option

type VLESSInboundOptions struct {
	ListenOptions
	Users []VLESSUser `json:"users,omitempty"`
	// Decryption is the server's setting of VLESS Encryption as Xray writes it,
	// "mlkem768x25519plus.<mode>.<seconds>s[.<padding>].<private key>": the server then
	// takes only clients whose "encryption" names its public key. Empty or "none" is VLESS
	// as it was.
	Decryption string `json:"decryption,omitempty"`
	InboundTLSOptionsContainer
	Multiplex *InboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport *V2RayTransportOptions   `json:"transport,omitempty"`
}

type VLESSUser struct {
	Name string `json:"name,omitempty"`
	UUID string `json:"uuid"`
	Flow string `json:"flow,omitempty"`
}

type VLESSOutboundOptions struct {
	DialerOptions
	ServerOptions
	UUID string `json:"uuid"`
	Flow string `json:"flow,omitempty"`
	// Encryption is the client's setting of VLESS Encryption as Xray writes it,
	// "mlkem768x25519plus.<mode>.<1rtt|0rtt>[.<padding>].<key>": a layer between the
	// transport and VLESS that a server with "decryption" set requires. Empty or
	// "none" is VLESS as it was (podkop-engine).
	Encryption string      `json:"encryption,omitempty"`
	Network    NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	Multiplex      *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport      *V2RayTransportOptions    `json:"transport,omitempty"`
	PacketEncoding *string                   `json:"packet_encoding,omitempty"`
}
