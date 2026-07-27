package warp

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/cloudflare"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func validWARPTestConfig(t *testing.T) *Config {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	config := &Config{PrivateKey: key.String()}
	config.Interface.Addresses.V4 = "172.16.0.2"
	config.Interface.Addresses.V6 = "2606:4700:110:8765::2"
	config.Peers = make([]cloudflare.Peer, 1)
	config.Peers[0].PublicKey = key.PublicKey().String()
	config.Peers[0].Endpoint.Host = "engage.cloudflareclient.com"
	config.Peers[0].Endpoint.Ports = []int{2408}
	return config
}

func TestWARPConfigValidation(t *testing.T) {
	if err := validateConfig(validWARPTestConfig(t)); err != nil {
		t.Fatalf("valid WARP config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "empty private key", mutate: func(config *Config) { config.PrivateKey = "" }},
		{name: "empty peers", mutate: func(config *Config) { config.Peers = nil }},
		{name: "empty ports", mutate: func(config *Config) { config.Peers[0].Endpoint.Ports = nil }},
		{name: "invalid IPv4 address", mutate: func(config *Config) { config.Interface.Addresses.V4 = "not-an-ip" }},
		{name: "invalid IPv6 address", mutate: func(config *Config) { config.Interface.Addresses.V6 = "not-an-ip" }},
		{name: "empty peer key", mutate: func(config *Config) { config.Peers[0].PublicKey = "" }},
		{name: "empty peer host", mutate: func(config *Config) { config.Peers[0].Endpoint.Host = "" }},
		{name: "invalid port", mutate: func(config *Config) { config.Peers[0].Endpoint.Ports = []int{0} }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := validWARPTestConfig(t)
			testCase.mutate(config)
			if err := validateConfig(config); err == nil {
				t.Fatal("invalid WARP config was accepted")
			}
		})
	}
}

func TestWARPProfileCacheMatch(t *testing.T) {
	config := validWARPTestConfig(t)
	if !cachedConfigMatchesProfile(config, "") || !cachedConfigMatchesProfile(config, config.PrivateKey) {
		t.Fatal("matching cached WARP profile was rejected")
	}
	if cachedConfigMatchesProfile(config, "different-key") || cachedConfigMatchesProfile(nil, "") {
		t.Fatal("stale cached WARP profile was accepted")
	}
}

func TestWARPEndpointStartsAtPostStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	endpoint := &Endpoint{
		ctx:    ctx,
		cancel: cancel,
		await:  make(chan struct{}),
	}
	endpoint.startHandler = func() {
		close(started)
		close(endpoint.await)
	}

	if err := endpoint.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
		t.Fatal("WARP initialization started before StartStatePostStart")
	case <-time.After(50 * time.Millisecond):
	}
	if err := endpoint.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("WARP initialization did not start during StartStatePostStart")
	}
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWARPEndpointCloseBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	endpoint := &Endpoint{
		ctx:    ctx,
		cancel: cancel,
		await:  make(chan struct{}),
	}

	done := make(chan error, 1)
	go func() { done <- endpoint.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("WARP close blocked before initialization started")
	}
}

func TestWARPEndpointCloseCancelsInitialization(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	endpoint := &Endpoint{
		ctx:    ctx,
		cancel: cancel,
		await:  make(chan struct{}),
	}
	endpoint.startHandler = func() {
		defer close(endpoint.await)
		<-ctx.Done()
	}

	if err := endpoint.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- endpoint.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("WARP close did not cancel initialization")
	}
}
