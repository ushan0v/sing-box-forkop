package group

import (
	"context"
	"errors"
	"net"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type fallbackHealthTestOutbound struct {
	outboundAdapter.Adapter
	access    sync.Mutex
	available bool
	dialCount int
}

func (o *fallbackHealthTestOutbound) setAvailable(available bool) {
	o.access.Lock()
	o.available = available
	o.access.Unlock()
}

func (o *fallbackHealthTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	o.access.Lock()
	o.dialCount++
	available := o.available
	o.access.Unlock()
	if !available {
		return nil, errors.New("unavailable")
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buffer := make([]byte, 4096)
		_, _ = server.Read(buffer)
		_, _ = server.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	}()
	return client, nil
}

func (o *fallbackHealthTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

type fallbackBlockingOutbound struct {
	outboundAdapter.Adapter
	started chan struct{}
	once    sync.Once
}

func (o *fallbackBlockingOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	o.once.Do(func() { close(o.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (o *fallbackBlockingOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

type fallbackEarlyOutbound struct {
	outboundAdapter.Adapter
	started chan struct{}
}

func (o *fallbackEarlyOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	client, server := net.Pipe()
	return &fallbackTestEarlyConn{Conn: client, ctx: ctx, peer: server, started: o.started}, nil
}

func (o *fallbackEarlyOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

type fallbackTestEarlyConn struct {
	net.Conn
	ctx     context.Context
	peer    net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *fallbackTestEarlyConn) Write([]byte) (int, error) {
	if c.started != nil {
		c.once.Do(func() { close(c.started) })
	}
	<-c.ctx.Done()
	return 0, c.ctx.Err()
}

func (c *fallbackTestEarlyConn) Close() error {
	_ = c.peer.Close()
	return c.Conn.Close()
}

func (c *fallbackTestEarlyConn) NeedHandshake() bool { return true }

func newFallbackHealthTestOutbound(tag string, available bool) *fallbackHealthTestOutbound {
	return &fallbackHealthTestOutbound{
		Adapter:   outboundAdapter.NewAdapter("test", tag, []string{"tcp", "udp"}, nil),
		available: available,
	}
}

func newTestFallback(candidates ...fallbackCandidate) *Fallback {
	health := make(map[string]fallbackHealth, len(candidates))
	for _, candidate := range candidates {
		health[candidate.tag] = fallbackHealth{outbound: candidate.outbound}
	}
	selected := ""
	if len(candidates) > 0 {
		selected = candidates[0].tag
	}
	return &Fallback{
		logger:         log.NewNOPFactory().NewLogger("test"),
		history:        urltest.NewHistoryStorage(),
		candidates:     candidates,
		health:         health,
		selected:       selected,
		link:           "http://health.test/generate_204",
		timeout:        50 * time.Millisecond,
		maxFailedTimes: defaultFallbackMaxFailedAttempts,
		attemptTimeout: 20 * time.Millisecond,
		idleTimeout:    time.Minute,
		interruptGroup: interrupt.NewGroup(),
		lastActive:     time.Now(),
		wake:           make(chan struct{}, 1),
	}
}

func TestFallbackDefaultHealthTiming(t *testing.T) {
	outbound, err := NewFallback(
		context.Background(),
		nil,
		log.NewNOPFactory().NewLogger("test"),
		"fallback",
		option.FallbackOutboundOptions{
			GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"primary"}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	fallback := outbound.(*Fallback)
	if fallback.interval != 5*time.Minute || fallback.timeout != 5*time.Second || fallback.idleTimeout != fallback.interval || fallback.maxFailedTimes != 5 || !fallback.expectedStatus.Contains(500) {
		t.Fatalf("unexpected Fallback health defaults: interval=%v timeout=%v idle=%v max-failed=%d", fallback.interval, fallback.timeout, fallback.idleTimeout, fallback.maxFailedTimes)
	}
}

func TestFallbackFlattensLevelsAndDeduplicatesProviderMembers(t *testing.T) {
	nodeA := newTestOutbound("provider/a")
	nodeB := newTestOutbound("provider/b")
	nodeC := newTestOutbound("provider/c")
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{
		nodeA.Tag(): nodeA,
		nodeB.Tag(): nodeB,
		nodeC.Tag(): nodeC,
	}}
	provider := &testProvider{tag: "provider", outbounds: []adapter.Outbound{nodeA, nodeB, nodeC}}
	fallback := &Fallback{
		outbound: manager,
		levels: []fallbackLevel{
			{outboundTags: []string{nodeA.Tag()}},
			{providerTags: []string{provider.Tag()}, include: regexp.MustCompile(`a|b`)},
			{providerTags: []string{provider.Tag()}},
		},
		providers:      map[string]adapter.Provider{provider.Tag(): provider},
		health:         make(map[string]fallbackHealth),
		interruptGroup: interrupt.NewGroup(),
	}
	if err := fallback.rebuildCandidates(); err != nil {
		t.Fatal(err)
	}
	all := fallback.All()
	if len(all) != 3 || all[0] != nodeA.Tag() || all[1] != nodeB.Tag() || all[2] != nodeC.Tag() {
		t.Fatalf("unexpected flattened Fallback order: %v", all)
	}
	if fallback.candidates[0].level != 0 || fallback.candidates[1].level != 1 || fallback.candidates[2].level != 2 {
		t.Fatalf("Fallback levels were not preserved: %+v", fallback.candidates)
	}
	levels := fallback.Levels()
	if len(levels) != 3 || len(levels[0].Outbounds) != 1 || len(levels[1].Outbounds) != 1 || len(levels[2].Outbounds) != 1 {
		t.Fatalf("Fallback runtime levels are incomplete: %+v", levels)
	}
}

func TestFallbackHealthCheckFailsOverAndRecoversPriority(t *testing.T) {
	primary := newFallbackHealthTestOutbound("primary", false)
	secondary := newFallbackHealthTestOutbound("secondary", true)
	fallback := newTestFallback(
		fallbackCandidate{tag: primary.Tag(), outbound: primary},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	fallback.checkOutbounds(context.Background())
	if fallback.Now() != secondary.Tag() {
		t.Fatalf("Fallback did not select healthy lower priority: %q", fallback.Now())
	}

	primary.setAvailable(true)
	fallback.checkOutbounds(context.Background())
	if fallback.Now() != primary.Tag() {
		t.Fatalf("Fallback did not recover higher priority: %q", fallback.Now())
	}
}

func TestFallbackStartupRetryChecksOnlyFirstCandidate(t *testing.T) {
	primary := newFallbackHealthTestOutbound("primary", false)
	secondary := newFallbackHealthTestOutbound("secondary", true)
	fallback := newTestFallback(
		fallbackCandidate{tag: primary.Tag(), outbound: primary},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	fallback.checkOutbounds(context.Background())
	primary.setAvailable(true)
	fallback.checkFirstOutbound(context.Background())
	if primary.dialCount != 2 || secondary.dialCount != 1 {
		t.Fatalf("startup retry checked unrelated candidates: primary=%d secondary=%d", primary.dialCount, secondary.dialCount)
	}
	if fallback.Now() != primary.Tag() {
		t.Fatalf("Fallback did not recover the first candidate: %q", fallback.Now())
	}
}

func TestFallbackSkipsKnownUnhealthyOutbound(t *testing.T) {
	primary := newFallbackHealthTestOutbound("primary", false)
	secondary := newFallbackHealthTestOutbound("secondary", true)
	fallback := newTestFallback(
		fallbackCandidate{tag: primary.Tag(), outbound: primary},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	fallback.health[primary.Tag()] = fallbackHealth{outbound: primary, checked: true, alive: false}
	fallback.selected = secondary.Tag()
	conn, err := fallback.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if primary.dialCount != 0 || secondary.dialCount != 1 {
		t.Fatalf("unhealthy primary was used as a probe: primary=%d secondary=%d", primary.dialCount, secondary.dialCount)
	}
}

func TestFallbackDialFailuresUseMihomoThreshold(t *testing.T) {
	primary := newFallbackHealthTestOutbound("primary", false)
	secondary := newFallbackHealthTestOutbound("secondary", true)
	fallback := newTestFallback(
		fallbackCandidate{tag: primary.Tag(), outbound: primary},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	fallback.maxFailedTimes = 2
	for attempt := 0; attempt < fallback.maxFailedTimes-1; attempt++ {
		conn, err := fallback.DialContext(context.Background(), "tcp", M.Socksaddr{})
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	state := fallback.health[primary.Tag()]
	if state.checked || state.failureCount != fallback.maxFailedTimes-1 || fallback.Now() != primary.Tag() {
		t.Fatalf("ordinary failures changed global state too early: checked=%v failures=%d now=%q", state.checked, state.failureCount, fallback.Now())
	}
	select {
	case <-fallback.wake:
		t.Fatal("Fallback started health check before Mihomo failure threshold")
	default:
	}

	conn, err := fallback.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	select {
	case <-fallback.wake:
	default:
		t.Fatal("Fallback did not request health check after repeated failures")
	}
	if fallback.Now() != primary.Tag() {
		t.Fatalf("failure threshold changed global selection before health check: %q", fallback.Now())
	}
	fallback.checkOutbounds(context.Background())
	if fallback.Now() != secondary.Tag() {
		t.Fatalf("health check did not fail over after repeated failures: %q", fallback.Now())
	}
}

func TestFallbackAttemptTimeoutLeavesContextForNextOutbound(t *testing.T) {
	blocked := &fallbackBlockingOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "blocked", []string{"tcp", "udp"}, nil),
		started: make(chan struct{}),
	}
	secondary := newFallbackHealthTestOutbound("secondary", true)
	fallback := newTestFallback(
		fallbackCandidate{tag: blocked.Tag(), outbound: blocked},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	conn, err := fallback.DialContext(ctx, "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("blackholed outbound consumed the caller context: %s", elapsed)
	}
	if fallback.Now() != blocked.Tag() {
		t.Fatalf("user connection failure changed global selection: %q", fallback.Now())
	}
	fallback.checkOutbounds(context.Background())
	if fallback.Now() != secondary.Tag() {
		t.Fatalf("health check did not move past the black hole: %q", fallback.Now())
	}
}

func TestFallbackAttemptTimeoutReservesCallerDeadline(t *testing.T) {
	fallback := &Fallback{attemptTimeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	attemptContext, attemptCancel := fallback.newAttemptContext(ctx, 2)
	defer attemptCancel()
	deadline, loaded := attemptContext.Deadline()
	if !loaded {
		t.Fatal("Fallback attempt has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining < 400*time.Millisecond || remaining > 600*time.Millisecond {
		t.Fatalf("Fallback did not reserve caller time for the next candidate: %s", remaining)
	}
}

func TestFallbackRetriesFailedEarlyHandshakeWrite(t *testing.T) {
	early := &fallbackEarlyOutbound{Adapter: outboundAdapter.NewAdapter("test", "early", []string{"tcp", "udp"}, nil)}
	secondary := newFallbackHealthTestOutbound("secondary", true)
	fallback := newTestFallback(
		fallbackCandidate{tag: early.Tag(), outbound: early},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := fallback.DialContext(ctx, "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if fallback.Now() != early.Tag() {
		t.Fatalf("early handshake failure changed global selection: %q", fallback.Now())
	}
	fallback.checkOutbounds(context.Background())
	if fallback.Now() != secondary.Tag() {
		t.Fatalf("health check did not move past the failed early handshake: %q", fallback.Now())
	}
}

func TestFallbackEarlyCloseCancelsBlockedWrite(t *testing.T) {
	started := make(chan struct{})
	early := &fallbackEarlyOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "early", []string{"tcp", "udp"}, nil),
		started: started,
	}
	fallback := newTestFallback(fallbackCandidate{tag: early.Tag(), outbound: early})
	conn, err := fallback.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan struct{})
	go func() {
		_, _ = conn.Write([]byte("request"))
		close(writeDone)
	}()
	<-started
	closeDone := make(chan struct{})
	go func() {
		_ = conn.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("closing an early Fallback connection did not cancel its blocked write")
	}
	<-writeDone
}
