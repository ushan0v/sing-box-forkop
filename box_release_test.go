package box_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func startBox(t *testing.T, content string) (*box.Box, context.Context) {
	t.Helper()
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(content))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close() })
	return instance, ctx
}

func fakeIPStore(t *testing.T, ctx context.Context) adapter.FakeIPStore {
	t.Helper()
	transport, loaded := service.FromContext[adapter.DNSTransportManager](ctx).Transport("fakeip")
	require.True(t, loaded)
	return transport.(adapter.FakeIPTransport).Store()
}

// The instance taking over opens the cache file at once, where bbolt would wait a second for
// every try at its lock, and keeps the fakeip addresses the released one gave out.
func TestReleaseHandsOverCacheFileAndFakeIP(t *testing.T) {
	config := fmt.Sprintf(`{
		"log": {"disabled": true},
		"dns": {"servers": [{"type": "local", "tag": "local"}, {"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/16"}]},
		"experimental": {"cache_file": {"enabled": true, "path": %q, "store_fakeip": true}}
	}`, filepath.Join(t.TempDir(), "cache.db"))
	released, releasedCtx := startBox(t, config)
	address, err := fakeIPStore(t, releasedCtx).Create("example.com", false)
	require.NoError(t, err)

	require.NoError(t, released.Release())
	startedAt := time.Now()
	_, ctx := startBox(t, config)
	require.Less(t, time.Since(startedAt), time.Second)
	domain, loaded := fakeIPStore(t, ctx).Lookup(address)
	require.True(t, loaded)
	require.Equal(t, "example.com", domain)
	require.NoError(t, released.Close())
}

// The instance taking over gets the sockets of the released one's listeners, where binding
// the address again would fail; a socket nobody took closes once it has started.
func TestReleaseHandsOverListeners(t *testing.T) {
	freePort := func() int {
		probe, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		defer probe.Close()
		return probe.Addr().(*net.TCPAddr).Port
	}
	inbound := func(tag string, port int) string {
		return fmt.Sprintf(`{"type": "mixed", "tag": %q, "listen": "127.0.0.1", "listen_port": %d}`, tag, port)
	}
	config := func(inbounds string) string {
		return fmt.Sprintf(`{"log": {"disabled": true}, "inbounds": [%s]}`, inbounds)
	}
	kept, dropped := freePort(), freePort()
	released, _ := startBox(t, config(inbound("kept", kept)+", "+inbound("dropped", dropped)))
	require.NoError(t, released.Release())

	startBox(t, config(inbound("kept", kept)))
	require.NoError(t, released.CloseReleasedListeners())
	conn, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", kept))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	probe, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", dropped))
	require.NoError(t, err)
	require.NoError(t, probe.Close())
	require.NoError(t, released.Close())
}
