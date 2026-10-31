package listener

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// greeter writes its name to each connection it is handed, then echoes it.
type greeter string

func (g greeter) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	_, _ = conn.Write([]byte(g))
	_, _ = io.Copy(conn, conn)
}

// packetGreeter answers each packet with its name.
type packetGreeter struct {
	name   string
	writer func() N.PacketWriter
}

func (g *packetGreeter) NewPacket(buffer *buf.Buffer, source M.Socksaddr) {
	buffer.Release()
	answer := buf.NewSize(16)
	answer.WriteString(g.name)
	_ = g.writer().WritePacket(answer, source)
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer probe.Close()
	return uint16(probe.Addr().(*net.TCPAddr).Port)
}

func startListener(t *testing.T, ctx context.Context, network string, port uint16, reuseAddr bool, name string) (*Listener, error) {
	t.Helper()
	listenAddr := badoption.Addr(netip.AddrFrom4([4]byte{127, 0, 0, 1}))
	handler := &packetGreeter{name: name}
	listener := New(Options{
		Context:           ctx,
		Logger:            log.NewNOPFactory().NewLogger("test"),
		Network:           []string{network},
		Listen:            option.ListenOptions{Listen: &listenAddr, ListenPort: port, ReuseAddr: reuseAddr},
		ConnectionHandler: greeter(name),
		PacketHandler:     handler,
	})
	handler.writer = listener.PacketWriter
	err := listener.Start()
	if err == nil {
		t.Cleanup(func() { listener.Close() })
	}
	return listener, err
}

func address(port uint16) string {
	return "127.0.0.1:" + strconv.Itoa(int(port))
}

func greeting(t *testing.T, conn net.Conn) string {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(testWait)))
	answer := make([]byte, 16)
	n, err := conn.Read(answer)
	require.NoError(t, err)
	return string(answer[:n])
}

func dialGreeting(t *testing.T, network string, port uint16) (net.Conn, string) {
	t.Helper()
	conn, err := net.Dial(network, address(port))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	if network == N.NetworkUDP {
		_, err = conn.Write([]byte("hello"))
		require.NoError(t, err)
	}
	return conn, greeting(t, conn)
}

func requireEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	_, err := conn.Write([]byte("ping"))
	require.NoError(t, err)
	require.Equal(t, "ping", greeting(t, conn))
}

// The address never stops accepting across a reload: the instance taking over gets the
// socket itself, while the connections the released one accepted stay with it.
func TestTakeOverTCP(t *testing.T) {
	port := freePort(t)
	oldCtx, oldOwner := ContextWithOwner(context.Background())
	_, err := startListener(t, oldCtx, N.NetworkTCP, port, false, "old")
	require.NoError(t, err)
	kept, name := dialGreeting(t, N.NetworkTCP, port)
	require.Equal(t, "old", name)

	oldOwner.Release()
	newCtx, _ := ContextWithOwner(context.Background())
	_, err = startListener(t, newCtx, N.NetworkTCP, port, false, "new")
	require.NoError(t, err)
	for range 5 {
		_, name = dialGreeting(t, N.NetworkTCP, port)
		require.Equal(t, "new", name)
	}
	requireEcho(t, kept)
}

func TestTakeOverUDP(t *testing.T) {
	port := freePort(t)
	oldCtx, oldOwner := ContextWithOwner(context.Background())
	_, err := startListener(t, oldCtx, N.NetworkUDP, port, false, "old")
	require.NoError(t, err)
	_, name := dialGreeting(t, N.NetworkUDP, port)
	require.Equal(t, "old", name)

	oldOwner.Release()
	newCtx, _ := ContextWithOwner(context.Background())
	_, err = startListener(t, newCtx, N.NetworkUDP, port, false, "new")
	require.NoError(t, err)
	for range 5 {
		_, name = dialGreeting(t, N.NetworkUDP, port)
		require.Equal(t, "new", name)
	}
}

// A socket made with other options cannot be taken as it is: the released one is closed and
// the address bound again.
func TestTakeOverChangedOptions(t *testing.T) {
	port := freePort(t)
	oldCtx, oldOwner := ContextWithOwner(context.Background())
	_, err := startListener(t, oldCtx, N.NetworkTCP, port, false, "old")
	require.NoError(t, err)
	kept, _ := dialGreeting(t, N.NetworkTCP, port)

	oldOwner.Release()
	newCtx, _ := ContextWithOwner(context.Background())
	_, err = startListener(t, newCtx, N.NetworkTCP, port, true, "new")
	require.NoError(t, err)
	_, name := dialGreeting(t, N.NetworkTCP, port)
	require.Equal(t, "new", name)
	requireEcho(t, kept)
}

// An address the new configuration no longer has stops accepting once the instance taking
// over has started.
func TestCloseReleased(t *testing.T) {
	port := freePort(t)
	oldCtx, oldOwner := ContextWithOwner(context.Background())
	_, err := startListener(t, oldCtx, N.NetworkTCP, port, false, "old")
	require.NoError(t, err)

	oldOwner.Release()
	require.NoError(t, oldOwner.CloseReleased())
	probe, err := net.Listen("tcp4", address(port))
	require.NoError(t, err)
	require.NoError(t, probe.Close())
}

// Only a socket given up is taken: two listeners on one address are still refused.
func TestNoTakeOverWithoutRelease(t *testing.T) {
	port := freePort(t)
	oldCtx, _ := ContextWithOwner(context.Background())
	_, err := startListener(t, oldCtx, N.NetworkTCP, port, false, "old")
	require.NoError(t, err)

	newCtx, _ := ContextWithOwner(context.Background())
	_, err = startListener(t, newCtx, N.NetworkTCP, port, false, "new")
	require.Error(t, err)
	_, name := dialGreeting(t, N.NetworkTCP, port)
	require.Equal(t, "old", name)
}
