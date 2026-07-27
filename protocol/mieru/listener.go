package mieru

import (
	"context"
	"net"
	"net/netip"
)

type mieruListenerFactory struct {
	listenAddress netip.Addr
	listenConfig  net.ListenConfig
}

func (f *mieruListenerFactory) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	network, address, err := f.endpoint(network, address)
	if err != nil {
		return nil, err
	}
	return f.listenConfig.Listen(ctx, network, address)
}

func (f *mieruListenerFactory) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	network, address, err := f.endpoint(network, address)
	if err != nil {
		return nil, err
	}
	return f.listenConfig.ListenPacket(ctx, network, address)
}

func (f *mieruListenerFactory) endpoint(network, address string) (string, string, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", err
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		if f.listenAddress.Is4() {
			network = "tcp4"
		} else {
			network = "tcp6"
		}
	case "udp", "udp4", "udp6":
		if f.listenAddress.Is4() {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	return network, net.JoinHostPort(f.listenAddress.String(), port), nil
}
