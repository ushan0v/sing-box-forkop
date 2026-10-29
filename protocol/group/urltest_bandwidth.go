package group

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// These observations belong to a group, not to the shared latency history: a
// different download URL or threshold need not qualify the same member.
type BandwidthResult struct {
	Time     time.Time `json:"time"`
	Mbps     float64   `json:"mbps"`
	Bytes    int64     `json:"bytes"`
	Admitted bool      `json:"admitted"`
	Error    string    `json:"error,omitempty"`
	good     int
	bad      int
}

type BandwidthStatus struct {
	Running     bool                       `json:"running"`
	MinimumMbps float64                    `json:"minimum_mbps"`
	Results     map[string]BandwidthResult `json:"results"`
}

type urlTestBandwidth struct {
	options    option.URLTestBandwidthOptions
	access     sync.Mutex
	running    bool
	lastRun    time.Time
	results    map[string]BandwidthResult
	generation uint64
}

// Router throughput is a shared resource: groups must not benchmark each other.
var bandwidthProbeSlot = make(chan struct{}, 1)

func newURLTestBandwidth(options *option.URLTestBandwidthOptions) (*urlTestBandwidth, error) {
	if options == nil || !options.Enabled {
		return nil, nil
	}
	o := *options
	u, err := url.Parse(o.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("bandwidth_test.url must be an HTTP(S) URL without credentials or fragment")
	}
	if o.Interval == 0 {
		o.Interval = badoption.Duration(6 * time.Hour)
	}
	if o.Timeout == 0 {
		o.Timeout = badoption.Duration(10 * time.Second)
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = 32 * 1024 * 1024
	}
	if o.MinimumMbps == 0 {
		o.MinimumMbps = 50
	}
	if o.Confirmations == 0 {
		o.Confirmations = 2
	}
	if time.Duration(o.Interval) < time.Minute || time.Duration(o.Interval) > 7*24*time.Hour {
		return nil, errors.New("bandwidth_test.interval must be between 1m and 168h")
	}
	if time.Duration(o.Timeout) < time.Second || time.Duration(o.Timeout) > time.Minute {
		return nil, errors.New("bandwidth_test.timeout must be between 1s and 1m")
	}
	if o.MaxBytes < 1024*1024 || o.MaxBytes > 512*1024*1024 {
		return nil, errors.New("bandwidth_test.max_bytes must be between 1 MiB and 512 MiB")
	}
	if o.MinimumMbps < 1 || o.MinimumMbps > 100000 || o.Confirmations < 1 || o.Confirmations > 10 {
		return nil, errors.New("invalid bandwidth_test.minimum_mbps (1..100000) or confirmations (1..10)")
	}
	return &urlTestBandwidth{options: o, results: make(map[string]BandwidthResult)}, nil
}

// BandwidthStatus is nil for an ordinary, latency-only URLTest.
func (s *URLTest) BandwidthStatus() *BandwidthStatus {
	if s.group == nil || s.group.bandwidth == nil {
		return nil
	}
	g := s.group
	g.access.RLock()
	members := append([]adapter.Outbound(nil), g.outbounds...)
	g.access.RUnlock()
	b := g.bandwidth
	b.access.Lock()
	defer b.access.Unlock()
	status := &BandwidthStatus{Running: b.running, MinimumMbps: b.options.MinimumMbps, Results: make(map[string]BandwidthResult)}
	for _, member := range members {
		if result, ok := b.results[member.Tag()]; ok {
			result.Admitted = result.Admitted && time.Since(result.Time) <= 2*time.Duration(b.options.Interval)
			status.Results[member.Tag()] = result
		}
	}
	return status
}

// StartBandwidthTest starts an asynchronous sweep. Calls while one is running
// join that sweep, so repeated button presses cannot multiply the traffic.
func (s *URLTest) StartBandwidthTest() bool {
	return s.group != nil && s.group.startBandwidthTest(true)
}

func (g *URLTestGroup) startBandwidthTest(force bool) bool {
	b := g.bandwidth
	if b == nil || g.ctx.Err() != nil {
		return false
	}
	g.access.RLock()
	members := append([]adapter.Outbound(nil), g.outbounds...)
	g.access.RUnlock()
	if len(members) == 0 {
		return false
	}
	b.access.Lock()
	if b.running || (!force && time.Since(b.lastRun) < time.Duration(b.options.Interval)) {
		b.access.Unlock()
		return false
	}
	b.running, b.lastRun = true, time.Now()
	generation := b.generation
	b.access.Unlock()
	go func() {
		defer func() {
			b.access.Lock()
			b.running = false
			retry := b.generation != generation
			b.access.Unlock()
			if retry {
				g.startBandwidthTest(false)
			}
		}()
		select {
		case bandwidthProbeSlot <- struct{}{}:
			defer func() { <-bandwidthProbeSlot }()
		case <-g.ctx.Done():
			return
		}
		// Retire removed subscription nodes, including their admission counters.
		b.access.Lock()
		for tag := range b.results {
			if !common.Any(members, func(o adapter.Outbound) bool { return o.Tag() == tag }) {
				delete(b.results, tag)
			}
		}
		b.access.Unlock()
		for _, member := range members {
			if g.ctx.Err() != nil {
				return
			}
			if !common.Contains(member.Network(), N.NetworkTCP) {
				continue
			}
			// A group can change its egress mid-transfer; qualify leaves only.
			if _, isGroup := member.(adapter.OutboundGroup); isGroup {
				continue
			}
			b.access.Lock()
			attempts := 1
			if b.results[member.Tag()].Time.IsZero() {
				attempts = b.options.Confirmations
			}
			b.access.Unlock()
			// Seed a new member without waiting hours for its second observation.
			for attempt := 0; attempt < attempts; attempt++ {
				select {
				case <-time.After(time.Second):
				case <-g.ctx.Done():
					return
				}
				result := measureBandwidth(g.ctx, member, b.options)
				if g.ctx.Err() != nil {
					return
				}
				b.access.Lock()
				if b.generation != generation {
					b.access.Unlock()
					return
				}
				b.record(member.Tag(), result)
				b.access.Unlock()
			}
		}
		if g.ctx.Err() == nil {
			g.performUpdateCheck()
		}
	}()
	return true
}

// access must be held by the caller.
func (b *urlTestBandwidth) record(tag string, result BandwidthResult) {
	previous := b.results[tag]
	// A download origin's rate limit is inconclusive about this member. Keep
	// the last measurement and its original age; repeated 429s cannot renew it.
	if result.Error == "HTTP status 429" && !previous.Time.IsZero() {
		previous.Error = result.Error
		b.results[tag] = previous
		return
	}
	if result.Error == "HTTP status 429" {
		b.results[tag] = result
		return
	}
	result.Admitted = previous.Admitted
	if result.Error == "" && result.Mbps >= b.options.MinimumMbps {
		result.good = previous.good + 1
		if result.good >= b.options.Confirmations {
			result.Admitted = true
		}
	} else {
		result.bad = previous.bad + 1
		if result.bad >= b.options.Confirmations {
			result.Admitted = false
		}
	}
	b.results[tag] = result
}

// Called with g.access held. No qualifying reachable members means ordinary
// latency selection remains the reserve, including during initial warm-up.
func (g *URLTestGroup) bandwidthCandidates(network string) map[string]bool {
	b := g.bandwidth
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	var admitted map[string]bool
	for _, member := range g.outbounds {
		r := b.results[member.Tag()]
		if !r.Admitted || time.Since(r.Time) > 2*time.Duration(b.options.Interval) ||
			!common.Contains(member.Network(), network) || g.history.LoadURLTestHistory(RealTag(member, network)) == nil {
			continue
		}
		if admitted == nil {
			admitted = make(map[string]bool)
		}
		admitted[member.Tag()] = true
	}
	return admitted
}

func measureBandwidth(ctx context.Context, detour N.Dialer, options option.URLTestBandwidthOptions) BandwidthResult {
	result := BandwidthResult{Time: time.Now()}
	testCtx, cancel := context.WithTimeout(ctx, time.Duration(options.Timeout))
	defer cancel()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return detour.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
		TLSClientConfig:    &tls.Config{Time: ntp.TimeFuncFromContext(ctx), RootCAs: adapter.RootPoolFromContext(ctx)},
		DisableCompression: true,
		DisableKeepAlives:  true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(testCtx, http.MethodGet, options.URL, nil)
	if err != nil {
		result.Error = "invalid download URL"
		return result
	}
	req.Header.Set("Range", "bytes=0-"+strconv.FormatInt(options.MaxBytes-1, 10))
	req.Header.Set("Accept-Encoding", "identity")
	start := time.Now()
	response, err := client.Do(req)
	if err != nil {
		result.Error = "download request failed"
		// url.Error includes the configured URL, which may carry query secrets.
		// Its inner error explains DNS/TLS failures without echoing that URL.
		var requestError *url.Error
		if errors.As(err, &requestError) {
			result.Error += ": " + requestError.Err.Error()
		}
		return result
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
		result.Error = fmt.Sprintf("HTTP status %d", response.StatusCode)
		return result
	}
	result.Bytes, err = io.CopyN(io.Discard, response.Body, options.MaxBytes)
	elapsed := time.Since(start).Seconds()
	// A bounded transfer may end on our timeout, but caller cancellation or a
	// broken stream must not masquerade as a successful speed observation.
	if ctx.Err() != nil || (err != nil && !errors.Is(err, io.EOF) && !errors.Is(testCtx.Err(), context.DeadlineExceeded)) || result.Bytes < 1024*1024 {
		result.Error = "incomplete download"
		return result
	}
	result.Mbps = float64(result.Bytes) * 8 / elapsed / 1000000
	return result
}
