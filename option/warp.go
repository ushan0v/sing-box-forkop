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
	Amnezia                     *WireGuardAmnezia        `json:"amnezia,omitempty"`
	Profile                     CloudflareProfile        `json:"profile,omitempty"`
	DialerOptions
}
