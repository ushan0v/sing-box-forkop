package listener

import (
	"context"
	"net/netip"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func pathMTUDiscovery(t *testing.T, listener *Listener) int {
	t.Helper()
	rawConn, err := listener.UDPConn().SyscallConn()
	require.NoError(t, err)
	var value int
	var sockoptErr error
	require.NoError(t, rawConn.Control(func(fd uintptr) {
		value, sockoptErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER)
	}))
	require.NoError(t, sockoptErr)
	return value
}

// The socket the new listener gets has the options it asked for, not those of the released
// one.
func TestTakeOverKeepsNoChangedOption(t *testing.T) {
	port := freePort(t)
	listenAddr := badoption.Addr(netip.AddrFrom4([4]byte{127, 0, 0, 1}))
	listen := func(ctx context.Context, fragment bool) *Listener {
		listener := New(Options{
			Context: ctx,
			Logger:  log.NewNOPFactory().NewLogger("test"),
			Network: []string{N.NetworkUDP},
			Listen:  option.ListenOptions{Listen: &listenAddr, ListenPort: port, UDPFragment: &fragment},
			PacketHandler: &packetGreeter{writer: func() N.PacketWriter {
				return nil
			}},
		})
		require.NoError(t, listener.Start())
		t.Cleanup(func() { listener.Close() })
		return listener
	}
	oldCtx, oldOwner := ContextWithOwner(context.Background())
	released := listen(oldCtx, false)
	require.Equal(t, syscall.IP_PMTUDISC_DO, pathMTUDiscovery(t, released))

	oldOwner.Release()
	newCtx, _ := ContextWithOwner(context.Background())
	require.Equal(t, syscall.IP_PMTUDISC_DONT, pathMTUDiscovery(t, listen(newCtx, true)))
}
