package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A pair of keys: what the server holds and what the client's setting names.
func testKeys(t *testing.T, kind string) (serverKey []byte, clientKey string) {
	switch kind {
	case "x25519":
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		return private.Bytes(), base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	case "mlkem768":
		private, err := mlkem.GenerateKey768()
		require.NoError(t, err)
		return private.Bytes(), base64.RawURLEncoding.EncodeToString(private.EncapsulationKey().Bytes())
	}
	t.Fatal("unknown key kind ", kind)
	return nil, ""
}

type testServer struct {
	listener  net.Listener
	instance  *ServerInstance
	handshook atomic.Int32 // connections whose handshake the server accepted
	failed    atomic.Int32
}

// newTestServer is the server of Xray (server.go) behind a TCP listener: every connection is
// echoed back.
func newTestServer(t *testing.T, keys [][]byte, xorMode uint32, seconds int64, padding string) *testServer {
	instance := new(ServerInstance)
	require.NoError(t, instance.Init(keys, xorMode, seconds, 0, padding))
	return serveInstance(t, instance)
}

func serveInstance(t *testing.T, instance *ServerInstance) *testServer {
	server := &testServer{instance: instance}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server.listener = listener
	t.Cleanup(func() {
		listener.Close()
		server.instance.Close()
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				encrypted, err := server.instance.Handshake(conn, nil)
				if err != nil {
					server.failed.Add(1)
					return
				}
				server.handshook.Add(1)
				buffer := make([]byte, 32*1024)
				for {
					n, err := encrypted.Read(buffer)
					if err != nil {
						return
					}
					_, err = encrypted.Write(buffer[:n])
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return server
}

func (s *testServer) dial(t *testing.T, client *ClientInstance) *CommonConn {
	conn, err := net.Dial("tcp", s.listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	encrypted, err := client.Handshake(conn)
	require.NoError(t, err)
	return encrypted
}

// echo sends size random bytes and expects them back.
func echo(t *testing.T, conn net.Conn, size int) {
	sent := make([]byte, size)
	rand.Read(sent)
	go conn.Write(sent)
	received := make([]byte, size)
	_, err := io.ReadFull(conn, received)
	require.NoError(t, err, "size %d", size)
	require.True(t, bytes.Equal(sent, received), "size %d", size)
}

var testSizes = []int{1, 100, 8192, 8193, 16384, 20000, 70000}

func TestHandshakeAndData(t *testing.T) {
	t.Parallel()
	for mode, xorMode := range map[string]uint32{"native": 0, "xorpub": 1, "random": 2} {
		for _, kind := range []string{"x25519", "mlkem768"} {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				t.Parallel()
				serverKey, clientKey := testKeys(t, kind)
				server := newTestServer(t, [][]byte{serverKey}, xorMode, 0, "")
				client, err := NewClient(Prefix + "." + mode + ".1rtt." + clientKey)
				require.NoError(t, err)
				for i := 0; i < 2; i++ {
					conn := server.dial(t, client)
					for _, size := range testSizes {
						echo(t, conn, size)
					}
				}
				require.EqualValues(t, 2, server.handshook.Load())
			})
		}
	}
}

// Two keys: a server behind a relay, each takes its own layer off.
func TestTwoKeys(t *testing.T) {
	t.Parallel()
	firstServer, firstClient := testKeys(t, "x25519")
	secondServer, secondClient := testKeys(t, "mlkem768")
	server := newTestServer(t, [][]byte{firstServer, secondServer}, 1, 0, "")
	client, err := NewClient(Prefix + ".xorpub.1rtt." + firstClient + "." + secondClient)
	require.NoError(t, err)
	echo(t, server.dial(t, client), 5000)
}

// 0-RTT: the second connection reuses what the first agreed on and sends its data at once.
func TestZeroRTT(t *testing.T) {
	t.Parallel()
	for mode, xorMode := range map[string]uint32{"native": 0, "xorpub": 1, "random": 2} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			serverKey, clientKey := testKeys(t, "x25519")
			server := newTestServer(t, [][]byte{serverKey}, xorMode, 600, "")
			client, err := NewClient(Prefix + "." + mode + ".0rtt." + clientKey)
			require.NoError(t, err)
			first := server.dial(t, client)
			require.NotNil(t, first.PeerAEAD, "the first connection is a full handshake")
			echo(t, first, 3000)
			for i := 0; i < 3; i++ {
				next := server.dial(t, client)
				require.Nil(t, next.PeerAEAD, "a later connection waits for nothing before its data")
				for _, size := range testSizes {
					echo(t, next, size)
				}
			}
			require.EqualValues(t, 4, server.handshook.Load())
		})
	}
}

// A server that no longer knows the ticket (restarted): that connection fails, the client
// forgets the ticket, the next one is a full handshake.
func TestZeroRTTUnknownTicket(t *testing.T) {
	t.Parallel()
	serverKey, clientKey := testKeys(t, "x25519")
	client, err := NewClient(Prefix + ".native.0rtt." + clientKey)
	require.NoError(t, err)
	echo(t, newTestServer(t, [][]byte{serverKey}, 0, 600, "").dial(t, client), 100)

	restarted := newTestServer(t, [][]byte{serverKey}, 0, 600, "")
	stale := restarted.dial(t, client)
	require.Nil(t, stale.PeerAEAD)
	_, err = stale.Write([]byte("request"))
	require.NoError(t, err)
	_, err = stale.Read(make([]byte, 100))
	require.ErrorContains(t, err, "new handshake needed")

	fresh := restarted.dial(t, client)
	require.NotNil(t, fresh.PeerAEAD)
	echo(t, fresh, 100)
}

// A server that allows no 0-RTT hands out no ticket: every connection is a full handshake.
func TestZeroRTTNotAllowedByServer(t *testing.T) {
	t.Parallel()
	serverKey, clientKey := testKeys(t, "x25519")
	server := newTestServer(t, [][]byte{serverKey}, 0, 0, "")
	client, err := NewClient(Prefix + ".native.0rtt." + clientKey)
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		conn := server.dial(t, client)
		require.NotNil(t, conn.PeerAEAD)
		echo(t, conn, 100)
	}
}

func TestPaddingSetting(t *testing.T) {
	t.Parallel()
	serverKey, clientKey := testKeys(t, "x25519")
	server := newTestServer(t, [][]byte{serverKey}, 0, 0, "100-200-300.100-1-5.100-50-60")
	client, err := NewClient(Prefix + ".native.1rtt.100-111-1111.75-0-11.50-0-3333." + clientKey)
	require.NoError(t, err)
	require.Len(t, client.PaddingLens, 2)
	require.Len(t, client.PaddingGaps, 1)
	echo(t, server.dial(t, client), 1000)
}

// The wrong key: the server cannot read the hello and the handshake fails.
func TestWrongKey(t *testing.T) {
	t.Parallel()
	serverKey, _ := testKeys(t, "x25519")
	_, otherKey := testKeys(t, "x25519")
	server := newTestServer(t, [][]byte{serverKey}, 0, 0, "")
	client, err := NewClient(Prefix + ".native.1rtt." + otherKey)
	require.NoError(t, err)
	conn, err := net.Dial("tcp", server.listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = client.Handshake(conn)
	require.Error(t, err)
	require.EqualValues(t, 0, server.handshook.Load())
}

func TestNewClientSetting(t *testing.T) {
	t.Parallel()
	_, x25519Key := testKeys(t, "x25519")
	_, mlkemKey := testKeys(t, "mlkem768")
	for _, setting := range []string{
		Prefix + ".native.1rtt." + x25519Key,
		Prefix + ".native.0rtt." + x25519Key,
		Prefix + ".xorpub.0rtt." + mlkemKey,
		Prefix + ".random.1rtt." + x25519Key + "." + mlkemKey,
		Prefix + ".native.0rtt.100-111-1111.75-0-111.50-0-3333." + x25519Key,
	} {
		client, err := NewClient(setting)
		require.NoError(t, err, setting[:40])
		require.NotNil(t, client)
	}
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 31))
	for name, setting := range map[string]string{
		"empty":             "",
		"none":              "none",
		"another prefix":    "mlkem1024.native.1rtt." + x25519Key,
		"no key":            Prefix + ".native.1rtt",
		"only padding":      Prefix + ".native.1rtt.100-111-1111",
		"unknown mode":      Prefix + ".plain.1rtt." + x25519Key,
		"unknown handshake": Prefix + ".native.2rtt." + x25519Key,
		"key of 31 bytes":   Prefix + ".native.1rtt." + short,
		"not base64":        Prefix + ".native.1rtt." + strings.Repeat("!", 43),
		"padding after key": Prefix + ".native.1rtt." + x25519Key + ".100-111-1111",
		"bad padding":       Prefix + ".native.1rtt.100-111." + x25519Key,
		"small padding":     Prefix + ".native.1rtt.100-1-2." + x25519Key,
		"a pause of 10 min": Prefix + ".native.1rtt.100-111-1111.100-600000-600000." + x25519Key,
		"pauses of 12 s":    Prefix + ".native.1rtt.100-111-1111.100-0-6000.50-0-3333.100-6000-0." + x25519Key,
	} {
		_, err := NewClient(setting)
		require.Error(t, err, name)
	}
	// pauses of 10 s in all are still a setting
	_, err := NewClient(Prefix + ".native.1rtt.100-111-1111.100-0-5000.50-0-3333.100-5000-0." + x25519Key)
	require.NoError(t, err)
}

// A setting comes out of a share link too, and what is said about a wrong one ends up in
// logs: no piece of the setting is repeated, wherever in it the piece stands.
func TestNewClientErrorsDoNotRepeatTheSetting(t *testing.T) {
	t.Parallel()
	_, x25519Key := testKeys(t, "x25519")
	const mark = "s3cretMark"
	for name, setting := range map[string]string{
		"as the mode":            Prefix + "." + mark + ".1rtt." + x25519Key,
		"the key as the mode":    Prefix + "." + x25519Key + ".native.0rtt",
		"as the handshake":       Prefix + ".native." + mark + "." + x25519Key,
		"glued to the handshake": Prefix + ".native.0rtt" + mark + "://user@host:443?x=1." + x25519Key,
		"as a padding segment":   Prefix + ".native.1rtt." + mark + "." + x25519Key,
		"in a padding segment":   Prefix + ".native.1rtt.100-" + mark + "-5." + x25519Key,
		"a segment after a key":  Prefix + ".native.1rtt." + x25519Key + "." + mark,
		"as a key":               Prefix + ".native.1rtt." + mark + mark + mark,
		"as the prefix":          mark + ".native.1rtt." + x25519Key,
	} {
		_, err := NewClient(setting)
		require.Error(t, err, name)
		require.NotContains(t, err.Error(), mark, name)
		require.NotContains(t, err.Error(), x25519Key, name)
		require.NotContains(t, err.Error(), "user@host", name)
	}
}

// The server's setting as Xray's vlessenc writes it, with each kind of key, and the pairs a
// client of it connects with, 0-RTT included.
func TestNewServerSetting(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"x25519", "mlkem768"} {
		for _, setting := range []struct{ server, client string }{
			{".native.600s.", ".native.0rtt."},
			{".xorpub.300-600s.", ".xorpub.0rtt."},
			{".random.0s.", ".random.1rtt."},
			{".native.600s.100-111-1111.75-0-111.50-0-3333.", ".native.0rtt.100-111-1111.75-0-111.50-0-3333."},
		} {
			t.Run(kind+setting.server, func(t *testing.T) {
				t.Parallel()
				serverKey, clientKey := testKeys(t, kind)
				instance, err := NewServer(Prefix + setting.server + base64.RawURLEncoding.EncodeToString(serverKey))
				require.NoError(t, err)
				server := serveInstance(t, instance)
				client, err := NewClient(Prefix + setting.client + clientKey)
				require.NoError(t, err)
				for i := 0; i < 2; i++ {
					echo(t, server.dial(t, client), 5000)
				}
				require.EqualValues(t, 2, server.handshook.Load())
			})
		}
	}
}

func TestNewServerRefusesASetting(t *testing.T) {
	t.Parallel()
	serverKey, clientKey := testKeys(t, "x25519")
	key := base64.RawURLEncoding.EncodeToString(serverKey)
	_, mlkemPublic := testKeys(t, "mlkem768")
	const mark = "s3cretMark"
	for name, setting := range map[string]string{
		"empty":                "",
		"none":                 "none",
		"the client's setting": Prefix + ".native.0rtt." + clientKey,
		"no key":               Prefix + ".native.600s",
		"unknown mode":         Prefix + ".plain.600s." + key,
		"negative seconds":     Prefix + ".native.-5s." + key,
		"a public ML-KEM key":  Prefix + ".native.600s." + mlkemPublic,
		"padding after key":    Prefix + ".native.600s." + key + ".100-111-1111",
		"a pause of 10 min":    Prefix + ".native.600s.100-111-1111.100-600000-600000." + key,
		"as the mode":          Prefix + "." + mark + ".600s." + key,
		"as the seconds":       Prefix + ".native." + mark + "." + key,
		"as a key":             Prefix + ".native.600s." + mark + mark + mark,
	} {
		_, err := NewServer(setting)
		require.Error(t, err, name)
		require.NotContains(t, err.Error(), mark, name)
		require.NotContains(t, err.Error(), key, name)
	}
}

// The entry of Vision's list for this layer: the layer is found, and what Vision writes
// past it to is the connection right under it.
func TestVisionEntry(t *testing.T) {
	t.Parallel()
	serverKey, clientKey := testKeys(t, "x25519")
	server := newTestServer(t, [][]byte{serverKey}, 2, 0, "")
	client, err := NewClient(Prefix + ".random.1rtt." + clientKey)
	require.NoError(t, err)
	encrypted := server.dial(t, client)
	entry := visionRegistry[len(visionRegistry)-1]
	loaded, under, _, _ := entry(encrypted)
	require.True(t, loaded)
	require.Equal(t, encrypted.Conn, under)
	_, isXor := under.(*XorConn)
	require.True(t, isXor, "in the random mode the layer under is the XOR one, not the transport")

	plain, err := net.Dial("tcp", server.listener.Addr().String())
	require.NoError(t, err)
	defer plain.Close()
	loaded, _, _, _ = entry(plain)
	require.False(t, loaded)
}
