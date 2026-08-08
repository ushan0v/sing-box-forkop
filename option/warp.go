package option

import "github.com/sagernet/sing/common/json/badoption"

type WARPEndpointOptions struct {
	System                      bool                     `json:"system,omitempty"`
	Name                        string                   `json:"name,omitempty"`
	ListenPort                  uint16                   `json:"listen_port,omitempty"`
	UDPTimeout                  badoption.Duration       `json:"udp_timeout,omitempty"`
	PersistentKeepaliveInterval *badoption.Range[uint32] `json:"persistent_keepalive_interval,omitempty"`
	Workers                     int                      `json:"workers,omitempty"`
	PreallocatedBuffersPerPool  uint32                   `json:"preallocated_buffers_per_pool,omitempty"`
	DisablePauses               bool                     `json:"disable_pauses,omitempty"`
	Amnezia                     *WARPAmnezia             `json:"amnezia,omitempty"`
	Profile                     CloudflareProfile        `json:"profile,omitempty"`
	DialerOptions
}

type WARPAmnezia struct {
	JC                     int                      `json:"jc,omitempty"`
	JMin                   int                      `json:"jmin,omitempty"`
	JMax                   int                      `json:"jmax,omitempty"`
	I1                     string                   `json:"i1,omitempty"`
	I2                     string                   `json:"i2,omitempty"`
	I3                     string                   `json:"i3,omitempty"`
	I4                     string                   `json:"i4,omitempty"`
	I5                     string                   `json:"i5,omitempty"`
	ContentPaddingAddition *badoption.Range[uint32] `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         *badoption.Range[uint32] `json:"rekey_after_time,omitempty"`
	RekeyTimeout           *badoption.Range[uint32] `json:"rekey_timeout,omitempty"`
	RejectAfterTime        *badoption.Range[uint32] `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       *badoption.Range[uint32] `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   *badoption.Range[uint32] `json:"max_handshake_attempts,omitempty"`
}
