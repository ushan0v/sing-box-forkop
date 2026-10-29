package group

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

func TestBandwidthThroughputRanksBeforeLatency(t *testing.T) {
	estonia := newTypedTestOutbound(C.TypeVLESS, "estonia")
	norway := newTypedTestOutbound(C.TypeVLESS, "norway")
	g, _ := NewURLTestGroup(context.Background(), nil, nil, []adapter.Outbound{norway, estonia}, "", nil, 0, 10, 0, false)
	defer g.Close()
	o := bandwidthOptions()
	o.Strategy = "throughput"
	g.bandwidth, _ = newURLTestBandwidth(o)
	g.selectedOutboundTCP = norway
	for tag, speed := range map[string]float64{"estonia": 229, "norway": 167} {
		for range 2 {
			g.bandwidth.record(tag, BandwidthResult{Time: time.Now(), Mbps: speed})
		}
	}
	g.history.StoreURLTestHistory("estonia", &adapter.URLTestHistory{Time: time.Now(), Delay: 80})
	g.history.StoreURLTestHistory("norway", &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	if got, _ := g.Select(N.NetworkTCP); got != estonia {
		t.Fatal("latency beat significantly higher throughput")
	}
	// Within the configured 20% band latency is the secondary criterion.
	g.bandwidth.record("norway", BandwidthResult{Time: time.Now(), Mbps: 210})
	if got, _ := g.Select(N.NetworkTCP); got != norway {
		t.Fatal("similar-speed candidates ignored latency")
	}
	g.history.DeleteURLTestHistory("estonia")
	if got, _ := g.Select(N.NetworkTCP); got != norway {
		t.Fatal("dead fast node excluded reachable reserve")
	}
}

func TestAdaptiveBandwidthSchedule(t *testing.T) {
	o := bandwidthOptions()
	o.Adaptive = true
	b, err := newURLTestBandwidth(o)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	b.lastRun = now
	b.lastSelected = now
	if full, selected := b.plan(now.Add(9*time.Minute), false, true); full || selected {
		t.Fatal("selected check ran early")
	}
	if full, selected := b.plan(now.Add(10*time.Minute), false, true); full || !selected {
		t.Fatal("selected check did not become due")
	}
	b.lastSelected = now.Add(5 * time.Hour)
	if full, _ := b.plan(now.Add(6*time.Hour), false, true); !full {
		t.Fatal("selected probes postponed full sweep")
	}
	if full, _ := b.plan(now, true, true); !full {
		t.Fatal("manual request did not force full sweep")
	}
	if _, selected := b.plan(now.Add(time.Hour), false, false); selected {
		t.Fatal("scheduled check without selected node")
	}
	o.SelectedInterval = badoption.Duration(7 * time.Hour)
	if _, err := newURLTestBandwidth(o); err == nil {
		t.Fatal("accepted selected interval beyond full interval")
	}
}

type adaptiveTestOutbound struct {
	outboundAdapter.Adapter
	address string
	dials   atomic.Int32
}

func (o *adaptiveTestOutbound) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	o.dials.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, o.address)
}
func (o *adaptiveTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("unused")
}

func TestAdaptiveBandwidthConfirmsDegradationAndTestsReserve(t *testing.T) {
	var selectedRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if selectedRequests.Add(1) <= 2 {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", 1024*1024)))
	}))
	defer server.Close()
	slow := &adaptiveTestOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, "slow", []string{N.NetworkTCP}, nil), address: server.Listener.Addr().String()}
	fast := &adaptiveTestOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, "fast", []string{N.NetworkTCP}, nil), address: server.Listener.Addr().String()}
	g, _ := NewURLTestGroup(context.Background(), nil, nil, []adapter.Outbound{slow, fast}, "", nil, 0, 10, 0, false)
	defer g.Close()
	o := bandwidthOptions()
	o.Adaptive = true
	o.Strategy = "throughput"
	o.URL = server.URL
	o.MaxBytes = 1024 * 1024
	g.bandwidth, _ = newURLTestBandwidth(o)
	g.bandwidth.lastRun = time.Now()
	g.selectedOutboundTCP = slow
	for _, member := range []adapter.Outbound{slow, fast} {
		g.history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
		for range 2 {
			g.bandwidth.record(member.Tag(), BandwidthResult{Time: time.Now(), Mbps: 100})
		}
	}
	if !g.startBandwidthTest(false) {
		t.Fatal("adaptive probe did not start")
	}
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
		g.bandwidth.access.Lock()
		running := g.bandwidth.running
		g.bandwidth.access.Unlock()
		if !running {
			if slow.dials.Load() != 2 || fast.dials.Load() != 1 {
				t.Fatalf("unexpected selected/reserve probes: %d/%d", slow.dials.Load(), fast.dials.Load())
			}
			if got, _ := g.Select(N.NetworkTCP); got != fast {
				t.Fatal("degraded selected server retained")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("adaptive recovery did not finish")
}
