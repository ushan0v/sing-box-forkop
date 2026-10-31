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
	delay   time.Duration
}

func (d *testDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	time.Sleep(d.delay)
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

// A server, or a proxy on the way, may close the connection after the first
// response; the second request then needs a connection of its own, and its
// dial is no part of the measured round trip.
func TestUnifiedDelaySurvivesConnectionClose(t *testing.T) {
	for _, closeConnection := range []bool{false, true} {
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			if closeConnection {
				response.Header().Set("Connection", "close")
			}
			response.WriteHeader(http.StatusNoContent)
		}))
		dialer := &testDialer{address: server.Listener.Addr().String(), delay: 150 * time.Millisecond}
		delay, err := URLTest(ContextWithIsUnifiedDelay(context.Background()), server.URL, dialer)
		server.Close()
		if err != nil {
			t.Fatalf("close=%v: %v", closeConnection, err)
		}
		if requests.Load() != 2 {
			t.Fatalf("close=%v: expected two requests, got %d", closeConnection, requests.Load())
		}
		if delay >= 100 {
			t.Fatalf("close=%v: the delay includes the 150 ms dial: %d ms", closeConnection, delay)
		}
	}
}

// A delay of zero means a failed test to the Clash API and to URLTest
// selection, so a server on the same host is never measured as 0 ms.
func TestURLTestReportsAtLeastOneMillisecond(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	dialer := &testDialer{address: server.Listener.Addr().String()}
	ctx := ContextWithIsUnifiedDelay(context.Background())
	for attempt := 0; attempt < 20; attempt++ {
		delay, err := URLTest(ctx, server.URL, dialer)
		if err != nil {
			t.Fatal(err)
		}
		if delay == 0 {
			t.Fatal("a test that succeeded reported a delay of zero")
		}
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

	for _, invalid := range []string{"99", "600", "299-200", ",", "/", "///"} {
		if _, err = ParseExpectedStatus(invalid); err == nil {
			t.Fatalf("invalid expected status %q was accepted", invalid)
		}
	}
}
