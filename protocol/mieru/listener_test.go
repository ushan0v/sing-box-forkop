package mieru

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestMieruListenerFactoryKeepsDefaultWildcard(t *testing.T) {
	config, _, err := buildMieruServerConfig(context.Background(), option.MieruInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: 443},
		Transport:     "TCP",
		Users:         []option.MieruUser{{Name: "user", Password: "password"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	factory := config.StreamListenerFactory.(*mieruListenerFactory)
	if !factory.listenAddress.IsUnspecified() || !factory.listenAddress.Is4() {
		t.Fatalf("default listen address = %s, want IPv4 wildcard", factory.listenAddress)
	}
}

func TestMieruListenerFactoryEndpoint(t *testing.T) {
	testCases := []struct {
		name            string
		listenAddress   string
		inputNetwork    string
		inputAddress    string
		expectedNetwork string
		expectedAddress string
	}{
		{
			name:            "IPv4",
			listenAddress:   "192.0.2.1",
			inputNetwork:    "tcp6",
			inputAddress:    "[::]:443",
			expectedNetwork: "tcp4",
			expectedAddress: "192.0.2.1:443",
		},
		{
			name:            "IPv6",
			listenAddress:   "2001:db8::1",
			inputNetwork:    "udp4",
			inputAddress:    "0.0.0.0:8443",
			expectedNetwork: "udp6",
			expectedAddress: "[2001:db8::1]:8443",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			factory := &mieruListenerFactory{
				listenAddress: netip.MustParseAddr(testCase.listenAddress),
			}
			network, address, err := factory.endpoint(testCase.inputNetwork, testCase.inputAddress)
			if err != nil {
				t.Fatal(err)
			}
			if network != testCase.expectedNetwork {
				t.Fatalf("unexpected network: got %q, want %q", network, testCase.expectedNetwork)
			}
			if address != testCase.expectedAddress {
				t.Fatalf("unexpected address: got %q, want %q", address, testCase.expectedAddress)
			}
		})
	}
}
