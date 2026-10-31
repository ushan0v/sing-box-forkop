//go:build with_wireguard && with_gvisor

package box_test

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func wireGuardKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key)
}

// A WireGuard endpoint binds its listen port outside the listeners an instance hands over,
// and one that finds the port taken only logs it: the released one has to close it.
func TestReleaseFreesTheWireGuardPort(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	port := probe.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, probe.Close())
	config := fmt.Sprintf(`{
		"log": {"disabled": true},
		"endpoints": [{"type": "wireguard", "tag": "wg", "address": ["10.77.0.1/32"], "private_key": %q,
			"listen_port": %d, "peers": [{"public_key": %q, "allowed_ips": ["10.77.0.2/32"]}]}]
	}`, wireGuardKey(t), port, wireGuardKey(t))
	released, _ := startBox(t, config)

	require.NoError(t, released.Release())
	listener, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", port))
	require.NoError(t, err)
	require.NoError(t, listener.Close())
	require.NoError(t, released.Close())
}
