package clashapi

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

func newListenTestServer(t *testing.T, address string) *Server {
	return newStatusTestServer(t, context.Background(), address, http.StatusNoContent)
}

func newStatusTestServer(t *testing.T, ctx context.Context, address string, status int) *Server {
	saved := listenRetryDelay
	listenRetryDelay = 20 * time.Millisecond
	t.Cleanup(func() { listenRetryDelay = saved })
	return &Server{
		ctx:    ctx,
		logger: log.NewNOPFactory().NewLogger("clash-api"),
		httpServer: &http.Server{Addr: address, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		})},
		closed:             make(chan struct{}),
		externalController: true,
	}
}

func answers(address string) bool {
	return answersWith(address, http.StatusNoContent)
}

func answersWith(address string, status int) bool {
	client := &http.Client{Timeout: 200 * time.Millisecond, Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Get("http://" + address + "/")
	if err != nil {
		return false
	}
	response.Body.Close()
	return response.StatusCode == status
}

// An address taken by another program does not fail the start: the API comes up once the
// address is free.
func TestExternalControllerListenRetried(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := blocker.Addr().String()
	server := newListenTestServer(t, address)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().NewLogger("scope"))
	require.NoError(t, server.Start(adapter.StartStateStarted, scope))
	defer scope.Close()

	blocker.Close()
	require.Eventually(t, func() bool { return answers(address) }, 5*time.Second, 20*time.Millisecond)
}

// A server whose scope is closed while it waits to retry does not listen afterwards.
func TestExternalControllerRetryEndsOnClose(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := blocker.Addr().String()
	server := newListenTestServer(t, address)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().NewLogger("scope"))
	require.NoError(t, server.Start(adapter.StartStateStarted, scope))
	require.NoError(t, scope.Close())

	blocker.Close()
	time.Sleep(200 * time.Millisecond)
	_, err = net.DialTimeout("tcp", address, 200*time.Millisecond)
	require.Error(t, err)
}

// Across a reload the API of the new instance answers at once, on the socket the old one gave
// up, where binding the address again would wait for a retry.
func TestExternalControllerTakenOverOnReload(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := blocker.Addr().String()
	require.NoError(t, blocker.Close())
	start := func(ctx context.Context, status int) {
		scope := adapter.NewScope(context.Background(), log.NewNOPFactory().NewLogger("scope"))
		require.NoError(t, newStatusTestServer(t, ctx, address, status).Start(adapter.StartStateStarted, scope))
		t.Cleanup(func() { scope.Close() })
	}
	oldCtx, oldOwner := listener.ContextWithOwner(context.Background())
	start(oldCtx, http.StatusNoContent)
	require.True(t, answers(address))

	oldOwner.Release()
	newCtx, _ := listener.ContextWithOwner(context.Background())
	start(newCtx, http.StatusAccepted)
	require.True(t, answersWith(address, http.StatusAccepted))
}
