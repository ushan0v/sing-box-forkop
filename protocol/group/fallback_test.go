package group

import (
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type fallbackHealthTestOutbound struct {
	outboundAdapter.Adapter
	access    sync.Mutex
	available bool
	dialCount int
}

type fallbackHistoryGroupOutbound struct {
	*fallbackHealthTestOutbound
	selected adapter.Outbound
}

func (o *fallbackHistoryGroupOutbound) All() []string {
	if o.selected == nil {
		return nil
	}
	return []string{o.selected.Tag()}
}

func (o *fallbackHistoryGroupOutbound) Selected(string) adapter.Outbound { return o.selected }

func (o *fallbackHistoryGroupOutbound) AttachConnection(io.Closer) func() { return func() {} }

// selectedTag is the member a group reports for TCP, or "" without one.
func selectedTag(group adapter.OutboundGroup) string {
	if selected := group.Selected(N.NetworkTCP); selected != nil {
		return selected.Tag()
	}
	return ""
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

// fallbackContextBoundOutbound closes its connections when the context they
// were dialed with ends, as the gRPC and HTTP/2 transports of sing-box 1.14.1 do.
type fallbackContextBoundOutbound struct {
	outboundAdapter.Adapter
	early bool
}

func (o *fallbackContextBoundOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	client, server := net.Pipe()
	context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = server.Close()
	})
	go func() {
		defer server.Close()
		buffer := make([]byte, 64)
		for {
			n, err := server.Read(buffer)
			if err != nil {
				return
			}
			if _, err = server.Write(buffer[:n]); err != nil {
				return
			}
		}
	}()
	if o.early {
		return &fallbackTestHandshakeConn{Conn: client}, nil
	}
	return client, nil
}

func (o *fallbackContextBoundOutbound) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() { _ = conn.Close() })
	return conn, nil
}

type fallbackTestHandshakeConn struct {
	net.Conn
	access    sync.Mutex
	handshake bool
}

func (c *fallbackTestHandshakeConn) Write(buffer []byte) (int, error) {
	c.access.Lock()
	c.handshake = true
	c.access.Unlock()
	return c.Conn.Write(buffer)
}

func (c *fallbackTestHandshakeConn) NeedHandshake() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return !c.handshake
}

func echoesThrough(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "ping" {
		t.Fatalf("read: %q, %v", reply, err)
	}
}

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
		ctx:            context.Background(),
		outbound:       &testOutboundManager{outbounds: map[string]adapter.Outbound{}},
		logger:         log.NewNOPFactory().NewLogger("test"),
		history:        urltest.NewHistoryStorage(),
		coordinator:    urltest.NewCoordinator(),
		candidates:     candidates,
		health:         health,
		selected:       selected,
		link:           "http://health.test/generate_204",
		interval:       time.Minute,
		timeout:        50 * time.Millisecond,
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
	if fallback.interval != 5*time.Minute || fallback.timeout != 5*time.Second || fallback.idleTimeout != fallback.interval || !fallback.expectedStatus.Contains(500) {
		t.Fatalf("unexpected Fallback health defaults: interval=%v timeout=%v idle=%v", fallback.interval, fallback.timeout, fallback.idleTimeout)
	}
}

func TestFallbackFlattensGroupsAndDeduplicatesProviderMembers(t *testing.T) {
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
		groups: []fallbackGroup{
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
	if fallback.candidates[0].group != 0 || fallback.candidates[1].group != 1 || fallback.candidates[2].group != 2 {
		t.Fatalf("Fallback groups were not preserved: %+v", fallback.candidates)
	}
	groups := fallback.Groups()
	if len(groups) != 3 || len(groups[0].Outbounds) != 1 || len(groups[1].Outbounds) != 1 || len(groups[2].Outbounds) != 1 {
		t.Fatalf("Fallback runtime groups are incomplete: %+v", groups)
	}
}

// Providers start after the outbounds and hand their members over later, so a
// group of provider members is empty when it starts; only an update that leaves
// it empty is worth a warning.
func TestFallbackWarnsOnlyWhenAnUpdateLeavesNoMembers(t *testing.T) {
	node := newTypedTestOutbound(C.TypeVLESS, "provider/node")
	provider := &testProvider{tag: "provider"}
	logger := &urlTestWarningLogger{ContextLogger: log.NewNOPFactory().NewLogger("test")}
	fallback := &Fallback{
		ctx:            context.Background(),
		outbound:       &testOutboundManager{outbounds: map[string]adapter.Outbound{node.Tag(): node}},
		logger:         logger,
		groups:         []fallbackGroup{{providerTags: []string{provider.Tag()}, include: regexp.MustCompile("^node$")}},
		providers:      map[string]adapter.Provider{provider.Tag(): provider},
		health:         make(map[string]fallbackHealth),
		interruptGroup: interrupt.NewGroup(),
		wake:           make(chan struct{}, 1),
	}
	if err := fallback.rebuildCandidates(); err != nil {
		t.Fatal(err)
	}
	if logger.warnings != 0 {
		t.Fatalf("a group waiting for its provider warned: %d", logger.warnings)
	}
	provider.outbounds = []adapter.Outbound{node}
	if err := fallback.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if len(fallback.All()) != 1 || logger.warnings != 0 {
		t.Fatalf("unexpected members %v or warnings %d", fallback.All(), logger.warnings)
	}
	fallback.groups[0].include = regexp.MustCompile("^nothing$")
	if err := fallback.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if len(fallback.All()) != 0 || logger.warnings != 1 {
		t.Fatalf("an update that left no members was not reported: members %v, warnings %d", fallback.All(), logger.warnings)
	}
}

func TestFallbackHealthCheckFailsOverAndRecoversPriority(t *testing.T) {
	primary := newFallbackHealthTestOutbound("primary", false)
	secondary := newFallbackHealthTestOutbound("secondary", true)
	fallback := newTestFallback(
		fallbackCandidate{tag: primary.Tag(), outbound: primary},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	fallback.checkOutbounds(context.Background(), 0)
	if selectedTag(fallback) != secondary.Tag() {
		t.Fatalf("Fallback did not select healthy lower priority: %q", selectedTag(fallback))
	}

	primary.setAvailable(true)
	fallback.checkOutbounds(context.Background(), 0)
	if selectedTag(fallback) != primary.Tag() {
		t.Fatalf("Fallback did not recover higher priority: %q", selectedTag(fallback))
	}
}

func TestFallbackManualURLTestUsesConfiguredStatus(t *testing.T) {
	node := newFallbackHealthTestOutbound("node", true)
	fallback := newTestFallback(fallbackCandidate{tag: node.Tag(), outbound: node})
	fallback.expectedStatus, _ = urltest.ParseExpectedStatus("200")
	if result, err := fallback.URLTest(context.Background()); err != nil || len(result) != 0 {
		t.Fatalf("unexpected rejected result: %v, %v", result, err)
	}

	fallback.expectedStatus, _ = urltest.ParseExpectedStatus("204")
	if result, err := fallback.URLTest(context.Background()); err != nil || len(result) != 1 {
		t.Fatalf("unexpected accepted result: %v, %v", result, err)
	}
}

func TestFallbackStoresHistoryUnderRealOutboundTag(t *testing.T) {
	group := &fallbackHistoryGroupOutbound{
		fallbackHealthTestOutbound: newFallbackHealthTestOutbound("group", true),
		selected:                   newFallbackHealthTestOutbound("node", true),
	}
	fallback := newTestFallback(fallbackCandidate{tag: group.Tag(), outbound: group})

	if _, err := fallback.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fallback.history.LoadURLTestHistory("node") == nil {
		t.Fatal("history was not stored under the selected outbound tag")
	}
	if fallback.history.LoadURLTestHistory(group.Tag()) != nil {
		t.Fatal("history was stored under the group tag")
	}
}

func TestFallbackStartupRetryScope(t *testing.T) {
	primary := newFallbackHealthTestOutbound("primary", false)
	secondary := newFallbackHealthTestOutbound("secondary", false)
	fallback := newTestFallback(
		fallbackCandidate{tag: primary.Tag(), outbound: primary},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	fallback.checkOutbounds(context.Background(), 0)
	if len(fallback.startupRetryCandidates()) != 2 {
		t.Fatal("a fully unreachable group must retry every member")
	}

	secondary.setAvailable(true)
	fallback.checkOutbounds(context.Background(), 0)
	retry := fallback.startupRetryCandidates()
	if len(retry) != 1 || retry[0].tag != primary.Tag() {
		t.Fatalf("a working group must retry only the first member: %+v", retry)
	}

	primary.setAvailable(true)
	fallback.checkOutbounds(context.Background(), 0)
	if len(fallback.startupRetryCandidates()) != 0 {
		t.Fatal("startup retry did not stop after the first member recovered")
	}
}

func TestFallbackDialsUnhealthyMembersAsLastResort(t *testing.T) {
	primary := newFallbackHealthTestOutbound("primary", false)
	secondary := newFallbackHealthTestOutbound("secondary", false)
	fallback := newTestFallback(
		fallbackCandidate{tag: primary.Tag(), outbound: primary},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	fallback.checkOutbounds(context.Background(), 0)
	if selectedTag(fallback) != primary.Tag() {
		t.Fatalf("a fully unhealthy group must still report its first member: %q", selectedTag(fallback))
	}

	primary.setAvailable(true)
	primary.dialCount = 0
	secondary.dialCount = 0
	conn, err := fallback.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatalf("a fully unhealthy group refused to dial: %v", err)
	}
	_ = conn.Close()
	if primary.dialCount != 1 || secondary.dialCount != 0 {
		t.Fatalf("last resort is not limited to the first member: primary=%d secondary=%d", primary.dialCount, secondary.dialCount)
	}
}

func TestFallbackPinsAndReleasesSelectedOutbound(t *testing.T) {
	primary := newFallbackHealthTestOutbound("primary", true)
	secondary := newFallbackHealthTestOutbound("secondary", true)
	fallback := newTestFallback(
		fallbackCandidate{tag: primary.Tag(), outbound: primary},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	fallback.checkOutbounds(context.Background(), 0)
	if selectedTag(fallback) != primary.Tag() {
		t.Fatalf("unexpected automatic selection: %q", selectedTag(fallback))
	}
	if fallback.SelectOutbound("missing") {
		t.Fatal("Fallback pinned an outbound that is not a member")
	}
	if !fallback.SelectOutbound(secondary.Tag()) || selectedTag(fallback) != secondary.Tag() || fallback.Fixed() != secondary.Tag() {
		t.Fatalf("Fallback did not honour the manual pin: now=%q fixed=%q", selectedTag(fallback), fallback.Fixed())
	}

	primary.dialCount = 0
	secondary.dialCount = 0
	conn, err := fallback.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if primary.dialCount != 0 || secondary.dialCount != 1 {
		t.Fatalf("pinned member was not dialed first: primary=%d secondary=%d", primary.dialCount, secondary.dialCount)
	}

	if !fallback.SelectOutbound("") || fallback.Fixed() != "" || selectedTag(fallback) != primary.Tag() {
		t.Fatalf("Fallback did not release the pin on request: now=%q fixed=%q", selectedTag(fallback), fallback.Fixed())
	}

	if !fallback.SelectOutbound(secondary.Tag()) {
		t.Fatal("Fallback refused to pin an existing member")
	}
	secondary.setAvailable(false)
	fallback.checkOutbounds(context.Background(), 0)
	if fallback.Fixed() != "" || selectedTag(fallback) != primary.Tag() {
		t.Fatalf("Fallback did not release a dead pin: now=%q fixed=%q", selectedTag(fallback), fallback.Fixed())
	}
}

// A member is pinned from the dashboard because it works now, whatever the last
// health check said about it.
func TestFallbackRetestsADownMemberBeforePinningIt(t *testing.T) {
	primary := newFallbackHealthTestOutbound("primary", true)
	secondary := newFallbackHealthTestOutbound("secondary", false)
	fallback := newTestFallback(
		fallbackCandidate{tag: primary.Tag(), outbound: primary},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	fallback.checkOutbounds(context.Background(), 0)
	secondary.setAvailable(true)
	if !fallback.SelectOutbound(secondary.Tag()) || fallback.Fixed() != secondary.Tag() || selectedTag(fallback) != secondary.Tag() {
		t.Fatalf("a member that came back was not pinned: now=%q fixed=%q", selectedTag(fallback), fallback.Fixed())
	}

	primary.setAvailable(false)
	fallback.checkOutbounds(context.Background(), 0)
	dials := primary.dialCount
	if !fallback.SelectOutbound(primary.Tag()) || fallback.Fixed() != "" || selectedTag(fallback) != secondary.Tag() {
		t.Fatalf("a member still down was pinned: now=%q fixed=%q", selectedTag(fallback), fallback.Fixed())
	}
	if primary.dialCount != dials+1 {
		t.Fatalf("pinning a down member did not test it once: %d dials", primary.dialCount-dials)
	}
	select {
	case <-fallback.wake:
		t.Fatal("pinning a member asked for a check of the whole group")
	default:
	}
}

func TestFallbackKeepsAPinWhileNoMemberAnswers(t *testing.T) {
	primary := newFallbackHealthTestOutbound("primary", true)
	secondary := newFallbackHealthTestOutbound("secondary", true)
	fallback := newTestFallback(
		fallbackCandidate{tag: primary.Tag(), outbound: primary},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	fallback.checkOutbounds(context.Background(), 0)
	if !fallback.SelectOutbound(secondary.Tag()) {
		t.Fatal("Fallback refused to pin an existing member")
	}

	primary.setAvailable(false)
	secondary.setAvailable(false)
	fallback.checkOutbounds(context.Background(), 0)
	if fallback.Fixed() != secondary.Tag() {
		t.Fatalf("an outage of every member released the pin: fixed=%q", fallback.Fixed())
	}

	primary.setAvailable(true)
	secondary.setAvailable(true)
	fallback.checkOutbounds(context.Background(), 0)
	if fallback.Fixed() != secondary.Tag() || selectedTag(fallback) != secondary.Tag() {
		t.Fatalf("the pin did not hold after the outage: now=%q fixed=%q", selectedTag(fallback), fallback.Fixed())
	}
}

func TestFallbackJudgesAURLTestMemberAfterItsOwnTest(t *testing.T) {
	dead := newFallbackHealthTestOutbound("dead", false)
	alive := newFallbackHealthTestOutbound("alive", true)
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{dead.Tag(): dead, alive.Tag(): alive}}
	group, err := NewURLTestGroup(context.Background(), manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{dead, alive}, "http://health.test/generate_204", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	urlTest := &URLTest{
		Adapter:  outboundAdapter.NewAdapter(C.TypeURLTest, "urltest", []string{"tcp", "udp"}, nil),
		ctx:      context.Background(),
		outbound: manager,
		logger:   log.NewNOPFactory().NewLogger("test"),
		group:    group,
	}
	backup := newFallbackHealthTestOutbound("backup", true)
	fallback := newTestFallback(
		fallbackCandidate{tag: backup.Tag(), outbound: backup},
		fallbackCandidate{tag: urlTest.Tag(), outbound: urlTest},
	)
	if !fallback.SelectOutbound(urlTest.Tag()) {
		t.Fatal("Fallback refused to pin its URLTest member")
	}

	fallback.checkOutbounds(context.Background(), 0)
	if fallback.Fixed() != urlTest.Tag() || selectedTag(fallback) != urlTest.Tag() {
		t.Fatalf("a check before the URLTest chose a member released the pin: now=%q fixed=%q", selectedTag(fallback), fallback.Fixed())
	}
	retry := fallback.startupRetryCandidates()
	if len(retry) != 1 || retry[0].tag != urlTest.Tag() {
		t.Fatalf("the unjudged URLTest member is not retried: %+v", retry)
	}

	group.CheckOutbounds(context.Background(), true)
	_, _ = fallback.checkCandidates(context.Background(), retry, 0)
	if state := fallback.health[urlTest.Tag()]; !state.checked || !state.alive || fallback.Fixed() != urlTest.Tag() {
		t.Fatalf("the URLTest member was not judged by the member it chose: checked=%v alive=%v fixed=%q", state.checked, state.alive, fallback.Fixed())
	}
	if retry = fallback.startupRetryCandidates(); len(retry) != 0 {
		t.Fatalf("startup retry did not stop once every member was judged: %+v", retry)
	}
}

func TestFallbackChecksAgainWhenTheNetworkChanges(t *testing.T) {
	node := newFallbackHealthTestOutbound("node", true)
	fallback := newTestFallback(fallbackCandidate{tag: node.Tag(), outbound: node})
	var routed adapter.Outbound = fallback
	listener, isListener := routed.(adapter.InterfaceUpdateListener)
	if !isListener {
		t.Fatal("a network change does not reach the group")
	}
	ctx, cancel := context.WithCancel(context.Background())
	listener.InterfaceUpdated(ctx)
	cancel()
	select {
	case <-fallback.wake:
	default:
		t.Fatal("a network change did not ask for a health check")
	}
}

func TestFallbackIgnoresFailuresThatDoNotProveAMemberIsDown(t *testing.T) {
	direct := &fallbackHealthTestOutbound{
		Adapter: outboundAdapter.NewAdapter(C.TypeDirect, "direct", []string{"tcp", "udp"}, nil),
	}
	fallback := newTestFallback(fallbackCandidate{tag: direct.Tag(), outbound: direct})
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := fallback.DialContext(context.Background(), "tcp", M.Socksaddr{}); err == nil {
			t.Fatal("expected the failing member to report an error")
		}
	}
	if state := fallback.health[direct.Tag()]; state.failures.count != 0 {
		t.Fatalf("direct failures were counted: %d", state.failures.count)
	}
	select {
	case <-fallback.wake:
		t.Fatal("direct failures requested a health check")
	default:
	}
}

func TestFallbackAttemptTimeoutIsConfigurable(t *testing.T) {
	outbound, err := NewFallback(
		context.Background(),
		nil,
		log.NewNOPFactory().NewLogger("test"),
		"fallback",
		option.FallbackOutboundOptions{
			GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"primary"}},
			AttemptTimeout:    badoption.Duration(2 * time.Second),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if outbound.(*Fallback).attemptTimeout != 2*time.Second {
		t.Fatalf("unexpected attempt timeout: %v", outbound.(*Fallback).attemptTimeout)
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
	for attempt := 0; attempt < maxDialFailures-1; attempt++ {
		conn, err := fallback.DialContext(context.Background(), "tcp", M.Socksaddr{})
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	state := fallback.health[primary.Tag()]
	if state.checked || state.failures.count != maxDialFailures-1 || selectedTag(fallback) != primary.Tag() {
		t.Fatalf("ordinary failures changed global state too early: checked=%v failures=%d now=%q", state.checked, state.failures.count, selectedTag(fallback))
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
	if selectedTag(fallback) != primary.Tag() {
		t.Fatalf("failure threshold changed global selection before health check: %q", selectedTag(fallback))
	}
	fallback.checkOutbounds(context.Background(), 0)
	if selectedTag(fallback) != secondary.Tag() {
		t.Fatalf("health check did not fail over after repeated failures: %q", selectedTag(fallback))
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
	if selectedTag(fallback) != blocked.Tag() {
		t.Fatalf("user connection failure changed global selection: %q", selectedTag(fallback))
	}
	fallback.checkOutbounds(context.Background(), 0)
	if selectedTag(fallback) != secondary.Tag() {
		t.Fatalf("health check did not move past the black hole: %q", selectedTag(fallback))
	}
}

func TestFallbackAttemptTimeoutReservesCallerDeadline(t *testing.T) {
	fallback := &Fallback{attemptTimeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	attempt := fallback.newAttempt(ctx, 2)
	defer attempt.fail(nil)
	if attempt.timeout < 400*time.Millisecond || attempt.timeout > 600*time.Millisecond {
		t.Fatalf("Fallback did not reserve caller time for the next candidate: %s", attempt.timeout)
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
	if selectedTag(fallback) != early.Tag() {
		t.Fatalf("early handshake failure changed global selection: %q", selectedTag(fallback))
	}
	fallback.checkOutbounds(context.Background(), 0)
	if selectedTag(fallback) != secondary.Tag() {
		t.Fatalf("health check did not move past the failed early handshake: %q", selectedTag(fallback))
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

func TestFallbackAcceptsGroupMembersAndSharesTheirChecks(t *testing.T) {
	node := newFallbackHealthTestOutbound("node", true)
	inner := &fallbackHistoryGroupOutbound{
		fallbackHealthTestOutbound: newFallbackHealthTestOutbound("inner", true),
		selected:                   node,
	}
	outbound, err := NewFallback(
		context.Background(),
		nil,
		log.NewNOPFactory().NewLogger("test"),
		"fallback",
		option.FallbackOutboundOptions{
			Groups: []option.FallbackGroupOptions{
				{GroupCommonOption: option.GroupCommonOption{Outbounds: []string{inner.Tag()}}},
				{GroupCommonOption: option.GroupCommonOption{Outbounds: []string{node.Tag()}}},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := outbound.Dependencies()
	if len(dependencies) != 2 || dependencies[0] != inner.Tag() || dependencies[1] != node.Tag() {
		t.Fatalf("group members are not declared as dependencies: %v", dependencies)
	}

	fallback := outbound.(*Fallback)
	fallback.outbound = &testOutboundManager{outbounds: map[string]adapter.Outbound{
		inner.Tag(): inner,
		node.Tag():  node,
	}}
	fallback.timeout = 50 * time.Millisecond
	fallback.link = "http://health.test/generate_204"
	if err = fallback.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().NewLogger("test"))); err != nil {
		t.Fatalf("a group member was rejected: %v", err)
	}
	all := fallback.All()
	if len(all) != 2 || all[0] != inner.Tag() || all[1] != node.Tag() {
		t.Fatalf("unexpected members: %v", all)
	}

	fallback.checkOutbounds(context.Background(), 0)
	if selectedTag(fallback) != inner.Tag() {
		t.Fatalf("the group member was not selected: %q", selectedTag(fallback))
	}
	if dials := inner.dialCount + node.dialCount; dials != 1 {
		t.Fatalf("the same node was probed once per referencing member: %d", dials)
	}
}

// The attempt timeout of the test fallback is 20 ms, so each connection is used
// well after it would have run out.
func TestFallbackKeepsTheDialContextOfAnOpenConnection(t *testing.T) {
	for _, early := range []bool{false, true} {
		node := &fallbackContextBoundOutbound{
			Adapter: outboundAdapter.NewAdapter("test", "node", []string{"tcp", "udp"}, nil),
			early:   early,
		}
		fallback := newTestFallback(fallbackCandidate{tag: node.Tag(), outbound: node})
		conn, err := fallback.DialContext(context.Background(), "tcp", M.Socksaddr{})
		if err != nil {
			t.Fatal(err)
		}
		echoesThrough(t, conn)
		time.Sleep(100 * time.Millisecond)
		echoesThrough(t, conn)
		_ = conn.Close()

		packetConn, err := fallback.ListenPacket(context.Background(), M.Socksaddr{})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		if _, err = packetConn.WriteTo([]byte("ping"), packetConn.LocalAddr()); err != nil {
			t.Fatalf("the packet connection did not outlive its dial: %v", err)
		}
		_ = packetConn.Close()
	}
}

// A connection the router hands to the group is a user connection, which a
// switch closes only with interrupt_exist_connections.
func TestFallbackKeepsRoutedConnectionsAcrossASwitch(t *testing.T) {
	node := &fallbackContextBoundOutbound{Adapter: outboundAdapter.NewAdapter("test", "node", []string{"tcp", "udp"}, nil)}
	fallback := newTestFallback(fallbackCandidate{tag: node.Tag(), outbound: node})
	inbound, peer := net.Pipe()
	defer peer.Close()
	// what the router does with a connection it routes to the group
	ctx := interrupt.ContextWithIsExternalConnection(context.Background(), true)
	detach := fallback.AttachConnection(inbound)
	defer detach()
	remote, err := fallback.DialContext(ctx, N.NetworkTCP, M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	fallback.interruptGroup.Interrupt(false)
	echoesThrough(t, remote)
	_ = remote.Close()
	if err = inbound.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("the switch closed the routed connection: %v", err)
	}
}

// The coordinator keeps the result of the previous tick, a little younger than
// one interval when the next tick comes; reusing it would test each member only
// every other interval.
func TestFallbackTickRetestsTheResultOfThePreviousTick(t *testing.T) {
	node := newFallbackHealthTestOutbound("node", true)
	fallback := newTestFallback(fallbackCandidate{tag: node.Tag(), outbound: node})
	fallback.interval = 200 * time.Millisecond
	fallback.periodicCheck(context.Background())
	time.Sleep(140 * time.Millisecond)
	fallback.periodicCheck(context.Background())
	if node.dialCount != 2 {
		t.Fatalf("a tick reused the result of the previous tick: %d dials", node.dialCount)
	}
	fallback.periodicCheck(context.Background())
	if node.dialCount != 2 {
		t.Fatalf("a tick retested a member another check had just tested: %d dials", node.dialCount)
	}
}

func TestFallbackDialEndsWithItsCaller(t *testing.T) {
	blocked := &fallbackBlockingOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "blocked", []string{"tcp", "udp"}, nil),
		started: make(chan struct{}),
	}
	fallback := newTestFallback(fallbackCandidate{tag: blocked.Tag(), outbound: blocked})
	fallback.attemptTimeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-blocked.started
		cancel()
	}()
	returnsWithin(t, time.Second, "a dial whose caller gave up", func() {
		if _, err := fallback.DialContext(ctx, "tcp", M.Socksaddr{}); !errors.Is(err, context.Canceled) {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestFallbackNamesTheAttemptTimeout(t *testing.T) {
	blocked := &fallbackBlockingOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "blocked", []string{"tcp", "udp"}, nil),
		started: make(chan struct{}),
	}
	fallback := newTestFallback(fallbackCandidate{tag: blocked.Tag(), outbound: blocked})
	_, err := fallback.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err == nil || !strings.Contains(err.Error(), "attempt timed out after 20ms") {
		t.Fatalf("unexpected error: %v", err)
	}

	attempt := fallback.newAttempt(context.Background(), 1)
	attempt.keep()
	if err = attempt.fail(errors.New("broken")); err.Error() != "broken" {
		t.Fatalf("an attempt that never timed out reported: %v", err)
	}
}

type fallbackBrokenWriteOutbound struct {
	outboundAdapter.Adapter
	early bool
}

func (o *fallbackBrokenWriteOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	conn := &fallbackBrokenWriteConn{Conn: client, err: errors.New(o.Tag() + " broken")}
	if o.early {
		return &fallbackTestHandshakeConn{Conn: conn}, nil
	}
	return conn, nil
}

func (o *fallbackBrokenWriteOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

type fallbackBrokenWriteConn struct {
	net.Conn
	err error
}

func (c *fallbackBrokenWriteConn) Write([]byte) (int, error) { return 0, c.err }

func TestFallbackReportsWhyTheLastHandshakeFailed(t *testing.T) {
	early := &fallbackBrokenWriteOutbound{Adapter: outboundAdapter.NewAdapter("test", "early", []string{"tcp"}, nil), early: true}
	plain := &fallbackBrokenWriteOutbound{Adapter: outboundAdapter.NewAdapter("test", "plain", []string{"tcp"}, nil)}
	fallback := newTestFallback(
		fallbackCandidate{tag: early.Tag(), outbound: early},
		fallbackCandidate{tag: plain.Tag(), outbound: plain},
	)
	conn, err := fallback.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("request")); err == nil || err.Error() != "plain broken" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFallbackFailureWindowIgnoresHealthCheckTimeout(t *testing.T) {
	primary := newFallbackHealthTestOutbound("primary", false)
	secondary := newFallbackHealthTestOutbound("secondary", true)
	fallback := newTestFallback(
		fallbackCandidate{tag: primary.Tag(), outbound: primary},
		fallbackCandidate{tag: secondary.Tag(), outbound: secondary},
	)
	fallback.timeout = time.Nanosecond
	for attempt := 0; attempt < maxDialFailures; attempt++ {
		conn, err := fallback.DialContext(context.Background(), "tcp", M.Socksaddr{})
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	select {
	case <-fallback.wake:
	default:
		t.Fatal("a tiny health check timeout must not shrink the failure window")
	}
}

// A manual test carries the request's deadline, and a group larger than that budget leaves members
// unchecked: what was measured is reported, and an undialed member keeps its health.
func TestFallbackURLTestReportsWhatItMeasuredWhenTimeRunsOut(t *testing.T) {
	answering := newFallbackHealthTestOutbound("answering", true)
	blocking := &fallbackBlockingOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "blocking", []string{"tcp"}, nil),
		started: make(chan struct{}),
	}
	fallback := newTestFallback(
		fallbackCandidate{tag: answering.Tag(), outbound: answering},
		fallbackCandidate{tag: blocking.Tag(), outbound: blocking},
	)
	fallback.health[blocking.Tag()] = fallbackHealth{
		outbound: blocking,
		checked:  true,
		alive:    true,
	}
	// Longer than the deadline below, so the blocking member is cut short by the
	// caller's budget rather than failing a test of its own.
	fallback.timeout = time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	result, err := fallback.URLTest(ctx)
	if err != nil {
		t.Fatalf("a check that ran out of time reported an error: %v", err)
	}
	if _, measured := result[answering.Tag()]; !measured {
		t.Fatalf("a member that answered was left out of the result: %v", result)
	}
	if state := fallback.health[blocking.Tag()]; !state.alive {
		t.Fatal("a member the check never finished was marked unavailable")
	}
}
