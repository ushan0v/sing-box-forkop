package urltest

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type testDialer struct {
	address string
}

func (d *testDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

func (d *testDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func TestUnifiedDelayRespectsContextDeadline(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 2 {
			time.Sleep(200 * time.Millisecond)
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(ContextWithIsUnifiedDelay(context.Background()), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := URLTest(ctx, server.URL, &testDialer{address: server.Listener.Addr().String()})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline, got %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 150*time.Millisecond {
		t.Fatalf("URL test exceeded context deadline: %v", elapsed)
	}
}

func TestExpectedStatus(t *testing.T) {
	expectedStatus, err := ParseExpectedStatus("200-299/304")
	if err != nil {
		t.Fatal(err)
	}
	if !expectedStatus.Contains(http.StatusNoContent) || !expectedStatus.Contains(http.StatusNotModified) || expectedStatus.Contains(http.StatusBadGateway) {
		t.Fatal("expected status ranges were parsed incorrectly")
	}

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	dialer := &testDialer{address: server.Listener.Addr().String()}
	if _, err = URLTestWithExpectedStatus(context.Background(), server.URL, dialer, expectedStatus); err != nil {
		t.Fatal(err)
	}
	rejectedStatus, err := ParseExpectedStatus("200")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = URLTestWithExpectedStatus(context.Background(), server.URL, dialer, rejectedStatus); err == nil {
		t.Fatal("unexpected HTTP status was accepted")
	}
}
