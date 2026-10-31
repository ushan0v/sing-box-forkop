package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

const reloadTestWait = 5 * time.Second

func echoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func freeReloadPort(t *testing.T) int {
	t.Helper()
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer probe.Close()
	return probe.Addr().(*net.TCPAddr).Port
}

func reloadOptions(t *testing.T, port int) option.Options {
	t.Helper()
	options, err := json.UnmarshalExtendedContext[option.Options](globalCtx, []byte(fmt.Sprintf(`{
		"log": {"disabled": true},
		"inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": %d}],
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`, port)))
	require.NoError(t, err)
	return options
}

// proxiedConn opens a tunnel to target through the HTTP proxy at port.
func proxiedConn(t *testing.T, port int, target string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(reloadTestWait)))
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, status, " 200 ")
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	require.Zero(t, reader.Buffered())
	return conn
}

func echoes(conn net.Conn) bool {
	if conn.SetReadDeadline(time.Now().Add(reloadTestWait)) != nil {
		return false
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		return false
	}
	answer := make([]byte, 4)
	_, err := io.ReadFull(conn, answer)
	return err == nil && string(answer) == "ping"
}

// A reload keeps the connections the replaced instance serves, which it closes once they end.
func TestReloadKeepsConnections(t *testing.T) {
	preRun(mainCommand, nil)
	target := echoServer(t)
	port := freeReloadPort(t)
	running, err := startService(reloadOptions(t, port))
	require.NoError(t, err)
	defer running.close()
	kept := proxiedConn(t, port, target)
	require.True(t, echoes(kept))

	require.NoError(t, running.reload(reloadOptions(t, port)))
	require.True(t, echoes(kept))
	require.True(t, echoes(proxiedConn(t, port, target)))
	select {
	case <-running.retiring.closed:
		t.Fatal("the replaced instance closed while it served a connection")
	default:
	}
	require.NoError(t, kept.Close())
	select {
	case <-running.retiring.closed:
	case <-time.After(reloadTestWait):
		t.Fatal("the replaced instance outlived its connections")
	}
}

// Without the memory for both instances a reload restarts, as before.
func TestReloadWithoutRoomRestarts(t *testing.T) {
	saved := roomForReload
	roomForReload = func() bool { return false }
	t.Cleanup(func() { roomForReload = saved })
	preRun(mainCommand, nil)
	target := echoServer(t)
	port := freeReloadPort(t)
	running, err := startService(reloadOptions(t, port))
	require.NoError(t, err)
	defer running.close()
	kept := proxiedConn(t, port, target)

	require.NoError(t, running.reload(reloadOptions(t, port)))
	require.Nil(t, running.retiring)
	require.False(t, echoes(kept))
	require.True(t, echoes(proxiedConn(t, port, target)))
}
