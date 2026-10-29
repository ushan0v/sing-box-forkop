package group

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func bandwidthOptions() *option.URLTestBandwidthOptions {
	return &option.URLTestBandwidthOptions{Enabled: true, URL: "https://download.example/file"}
}

func TestBandwidthOptionsAreOptInAndBounded(t *testing.T) {
	for _, options := range []*option.URLTestBandwidthOptions{nil, {URL: "broken"}} {
		if b, err := newURLTestBandwidth(options); b != nil || err != nil {
			t.Fatal(b, err)
		}
	}
	for _, change := range []func(*option.URLTestBandwidthOptions){
		func(o *option.URLTestBandwidthOptions) { o.URL = "ftp://example.com/file" },
		func(o *option.URLTestBandwidthOptions) { o.URL = "https://user:secret@example.com/file" },
		func(o *option.URLTestBandwidthOptions) { o.Interval = badoption.Duration(time.Second) },
		func(o *option.URLTestBandwidthOptions) { o.Timeout = badoption.Duration(61 * time.Second) },
		func(o *option.URLTestBandwidthOptions) { o.MaxBytes = 1 },
		func(o *option.URLTestBandwidthOptions) { o.MinimumMbps = -1 },
		func(o *option.URLTestBandwidthOptions) { o.Confirmations = 11 },
	} {
		o := bandwidthOptions()
		change(o)
		if _, err := newURLTestBandwidth(o); err == nil {
			t.Fatalf("accepted invalid options: %+v", o)
		}
	}
}

func TestBandwidthAdmissionAndLatencyReserve(t *testing.T) {
	fastPing := newTypedTestOutbound(C.TypeVLESS, "fast-ping")
	fastDownload := newTypedTestOutbound(C.TypeVLESS, "fast-download")
	g, err := NewURLTestGroup(context.Background(), nil, nil, []adapter.Outbound{fastPing, fastDownload}, "", nil, 0, 50, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.bandwidth, _ = newURLTestBandwidth(bandwidthOptions())
	g.history.StoreURLTestHistory(fastPing.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	g.history.StoreURLTestHistory(fastDownload.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 80})
	g.selectedOutboundTCP = fastPing
	check := func(want adapter.Outbound) {
		t.Helper()
		if got, _ := g.Select(N.NetworkTCP); got != want {
			t.Fatalf("got %v, want %v", got.Tag(), want.Tag())
		}
	}
	good := BandwidthResult{Time: time.Now(), Mbps: 100}
	bad := BandwidthResult{Time: time.Now(), Mbps: 5}
	g.bandwidth.record(fastDownload.Tag(), good)
	check(fastPing) // One good sample cannot qualify a node.
	g.bandwidth.record(fastDownload.Tag(), good)
	check(fastDownload) // Qualification also displaces an incumbent with lower latency.
	g.bandwidth.record(fastDownload.Tag(), bad)
	check(fastDownload)
	g.bandwidth.record(fastDownload.Tag(), bad)
	check(fastPing) // No admitted nodes: retain the normal latency reserve.
	g.bandwidth.record(fastDownload.Tag(), good)
	g.bandwidth.record(fastDownload.Tag(), good)
	g.history.DeleteURLTestHistory(fastDownload.Tag())
	check(fastPing) // A dead admitted member cannot exclude the working reserve.
	g.history.StoreURLTestHistory(fastDownload.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 80})
	r := g.bandwidth.results[fastDownload.Tag()]
	r.Time = time.Now().Add(-13 * time.Hour)
	g.bandwidth.results[fastDownload.Tag()] = r
	check(fastPing) // Expired qualifications are not authoritative.
}

type bandwidthDialer struct {
	N.Dialer
	address string
	calls   int
}

func (d *bandwidthDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.calls++
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

func TestBandwidthTransferBoundsAndHTTPFailures(t *testing.T) {
	for _, status := range []int{200, 206, 302, 403, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Range") != "bytes=0-1048575" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("missing download bounds")
				}
				w.Header().Set("Location", "/redirect")
				w.WriteHeader(status)
				if status == 200 || status == 206 {
					_, _ = w.Write([]byte(strings.Repeat("x", 2*1024*1024)))
				}
			}))
			defer server.Close()
			dialer := &bandwidthDialer{address: server.Listener.Addr().String()}
			result := measureBandwidth(context.Background(), dialer, option.URLTestBandwidthOptions{URL: server.URL, MaxBytes: 1024 * 1024, Timeout: badoption.Duration(time.Second)})
			if status == 200 || status == 206 {
				if result.Error != "" || result.Bytes != 1024*1024 || result.Mbps <= 0 {
					t.Fatalf("bad bounded result: %+v", result)
				}
			} else if result.Error == "" {
				t.Fatal("HTTP error qualified a node")
			}
			if dialer.calls != 1 {
				t.Fatal("request redirected outside the bounded test")
			}
		})
	}
}

func TestBandwidthCancellationDoesNotProduceAnObservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := measureBandwidth(ctx, &bandwidthDialer{address: "127.0.0.1:1"}, option.URLTestBandwidthOptions{URL: "http://test.invalid/file", MaxBytes: 1024 * 1024, Timeout: badoption.Duration(time.Second)})
	if result.Error == "" || result.Mbps != 0 {
		t.Fatal("canceled test succeeded")
	}
}

func TestBandwidthEmptyStartupAndClose(t *testing.T) {
	g, err := NewURLTestGroup(context.Background(), nil, nil, nil, "", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	g.bandwidth, _ = newURLTestBandwidth(bandwidthOptions())
	if g.startBandwidthTest(false) || !g.bandwidth.lastRun.IsZero() {
		t.Fatal("an empty provider used the scheduled sweep")
	}
	node := &blockingURLTestOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, "blocked", []string{"tcp"}, nil), started: make(chan struct{})}
	g.outbounds = []adapter.Outbound{node}
	if !g.startBandwidthTest(false) {
		t.Fatal("the first provider members were not tested")
	}
	select {
	case <-node.started:
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not start")
	}
	if g.startBandwidthTest(true) {
		t.Fatal("duplicate sweep started")
	}
	_ = g.Close()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		g.bandwidth.access.Lock()
		running := g.bandwidth.running
		g.bandwidth.access.Unlock()
		if !running {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("closing a group left a bandwidth probe running")
}

func TestBandwidthRateLimitDoesNotDisqualifyOrRenew(t *testing.T) {
	b, _ := newURLTestBandwidth(bandwidthOptions())
	at := time.Now().Add(-time.Hour)
	for range 2 {
		b.record("node", BandwidthResult{Time: at, Mbps: 100})
	}
	for range 3 {
		b.record("node", BandwidthResult{Time: time.Now(), Error: "HTTP status 429"})
	}
	r := b.results["node"]
	if !r.Admitted || !r.Time.Equal(at) || r.Mbps != 100 || r.bad != 0 {
		t.Fatalf("rate limiting changed the member rating: %+v", r)
	}
}
