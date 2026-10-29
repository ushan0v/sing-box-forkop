package group

import (
	"context"
	"io"
	"maps"
	"net"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func RegisterURLTest(registry *outbound.Registry) {
	outbound.Register[option.URLTestOutboundOptions](registry, C.TypeURLTest, NewURLTest)
}

var (
	_ adapter.DialingOutboundGroup    = (*URLTest)(nil)
	_ adapter.InterfaceUpdateListener = (*URLTest)(nil)
)

type URLTest struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	logger                       log.ContextLogger
	tags                         []string
	link                         string
	expectedStatus               urltest.ExpectedStatus
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	group                        *URLTestGroup
	bandwidth                    *urlTestBandwidth
	checkAccess                  sync.Mutex
	interruptExternalConnections bool
	access                       sync.RWMutex

	provider          adapter.ProviderManager
	providers         map[string]adapter.Provider
	providerCallbacks []providerCallbackRegistration
	outboundsCache    map[string][]adapter.Outbound
	cancel            context.CancelFunc

	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	excludeTypes    map[string]bool
	useAllProviders bool
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (adapter.Outbound, error) {
	expectedStatus, err := urltest.ParseExpectedStatus(options.ExpectedStatus)
	if err != nil {
		return nil, E.Cause(err, "invalid URLTest expected_status")
	}
	bandwidth, err := newURLTestBandwidth(options.BandwidthTest)
	if err != nil {
		return nil, err
	}
	outbound := &URLTest{
		Adapter:                      outbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		link:                         options.URL,
		expectedStatus:               expectedStatus,
		bandwidth:                    bandwidth,
		interval:                     time.Duration(options.Interval),
		tolerance:                    options.Tolerance,
		idleTimeout:                  time.Duration(options.IdleTimeout),
		interruptExternalConnections: options.InterruptExistConnections,

		provider:       service.FromContext[adapter.ProviderManager](ctx),
		providers:      make(map[string]adapter.Provider),
		outboundsCache: make(map[string][]adapter.Outbound),

		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		excludeTypes:    excludedOutboundTypes(options.ExcludeTypes),
		useAllProviders: options.UseAllProviders,
	}
	for i, tag := range outbound.tags {
		if slices.Contains(outbound.tags[:i], tag) {
			return nil, E.New("duplicate tag: ", tag)
		}
	}
	return outbound, nil
}

func (s *URLTest) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		scope.Add(s.Close)
		return s.start()
	case adapter.StartStateStarted:
		s.group.PostStart()
	}
	return nil
}

func (s *URLTest) start() (err error) {
	defer func() {
		if err != nil {
			unregisterProviderCallbacks(s.providerCallbacks)
			s.providerCallbacks = nil
		}
	}()
	if (s.useAllProviders || len(s.providerTags) > 0) && s.provider == nil {
		return E.New("outbound provider manager unavailable")
	}
	if s.useAllProviders {
		var providerTags []string
		for _, provider := range s.provider.Providers() {
			providerTags = append(providerTags, provider.Tag())
			s.providers[provider.Tag()] = provider
			s.providerCallbacks = append(s.providerCallbacks, registerProviderCallback(provider, s.onProviderUpdated))
		}
		s.providerTags = providerTags
	} else {
		for i, tag := range s.providerTags {
			provider, loaded := s.provider.Get(tag)
			if !loaded {
				return E.New("outbound provider ", i, " not found: ", tag)
			}
			s.providers[tag] = provider
			s.providerCallbacks = append(s.providerCallbacks, registerProviderCallback(provider, s.onProviderUpdated))
		}
	}
	if len(s.tags)+len(s.providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}

	outbounds := make([]adapter.Outbound, 0, len(s.tags))
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	group, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.expectedStatus, s.interval, s.tolerance, s.idleTimeout, s.interruptExternalConnections)
	if err != nil {
		return err
	}
	s.group = group
	s.group.bandwidth = s.bandwidth
	return nil
}

func (s *URLTest) Close() error {
	s.access.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.access.Unlock()
	unregisterProviderCallbacks(s.providerCallbacks)
	s.providerCallbacks = nil
	return common.Close(
		common.PtrOrNil(s.group),
	)
}

func (s *URLTest) All() []string {
	s.access.RLock()
	defer s.access.RUnlock()
	return append([]string(nil), s.tags...)
}

func (s *URLTest) Selected(network string) adapter.Outbound {
	group := s.group
	if group == nil {
		return nil
	}
	var outbound adapter.Outbound
	group.access.RLock()
	if network == N.NetworkUDP {
		outbound = group.selectedOutboundUDP
	} else {
		outbound = group.selectedOutboundTCP
	}
	group.access.RUnlock()
	if outbound == nil {
		outbound, _ = group.Select(network)
	}
	return outbound
}

func (s *URLTest) AttachConnection(closer io.Closer) func() {
	s.group.Touch()
	return s.group.interruptGroup.Add(closer, true)
}

// DialsMembers keeps the router dialing through the group, which counts the failed dials of its
// member and checks the group again at once when enough of them failed.
func (s *URLTest) DialsMembers() {}

func (s *URLTest) References() []string {
	group := s.group
	if group == nil {
		return nil
	}
	group.access.RLock()
	defer group.access.RUnlock()
	var references []string
	if group.selectedOutboundTCP != nil {
		references = append(references, group.selectedOutboundTCP.Tag())
	}
	if group.selectedOutboundUDP != nil && group.selectedOutboundUDP != group.selectedOutboundTCP {
		references = append(references, group.selectedOutboundUDP.Tag())
	}
	return references
}

func (s *URLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.group.URLTest(ctx)
}

func (s *URLTest) CheckOutbounds() {
	s.group.CheckOutbounds(s.ctx, true)
}

func (s *URLTest) PerformUpdateCheck() {
	s.group.performUpdateCheck()
}

func (s *URLTest) InterfaceUpdated(ctx context.Context) {
	group := s.group
	if group == nil {
		return
	}
	if group.pause.IsDevicePaused() || group.pause.IsNetworkPaused() {
		return
	}
	go func() {
		s.checkAccess.Lock()
		defer s.checkAccess.Unlock()
		if ctx.Err() != nil {
			return
		}
		group.CheckOutbounds(ctx, true)
	}()
}

func (s *URLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	var outbound adapter.Outbound
	s.group.access.RLock()
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		outbound = s.group.selectedOutboundTCP
	case N.NetworkUDP:
		outbound = s.group.selectedOutboundUDP
	default:
		s.group.access.RUnlock()
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	s.group.access.RUnlock()
	if outbound == nil {
		outbound, _ = s.group.Select(network)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		s.group.dialSucceeded()
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.group.deleteHistory(outbound.Tag())
	s.group.dialFailed(ctx, outbound, err)
	return nil, memberError(outbound, err)
}

// memberError names the member that failed: the caller logs the error with the outbound it
// dialed, which is the group or a selector above it.
func memberError(member adapter.Outbound, err error) error {
	return E.Cause(err, "outbound/", member.Type(), "[", member.Tag(), "]")
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	s.group.access.RLock()
	outbound := s.group.selectedOutboundUDP
	s.group.access.RUnlock()
	if outbound == nil {
		outbound, _ = s.group.Select(N.NetworkUDP)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		s.group.dialSucceeded()
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.group.deleteHistory(outbound.Tag())
	s.group.dialFailed(ctx, outbound, err)
	return nil, memberError(outbound, err)
}

func (s *URLTest) onProviderUpdated(tag string) error {
	s.access.Lock()
	_, loaded := s.providers[tag]
	if !loaded {
		s.access.Unlock()
		return E.New("outbound provider not found: ", tag)
	}
	var (
		tags      = s.Dependencies()
		outbounds []adapter.Outbound
	)
	for _, tag := range tags {
		detour, _ := s.outbound.Outbound(tag)
		outbounds = append(outbounds, detour)
	}
	for _, providerTag := range s.providerTags {
		if providerTag != tag && s.outboundsCache[providerTag] != nil {
			for _, detour := range s.outboundsCache[providerTag] {
				tags = append(tags, detour.Tag())
				outbounds = append(outbounds, detour)
			}
			continue
		}
		provider := s.providers[providerTag]
		var cache []adapter.Outbound
		for _, detour := range provider.Outbounds() {
			tag := detour.Tag()
			filterTag := providerOutboundFilterTag(providerTag, tag)
			if s.excludeTypes[detour.Type()] {
				continue
			}
			if s.exclude != nil && s.exclude.MatchString(filterTag) {
				continue
			}
			if s.include != nil && !s.include.MatchString(filterTag) {
				continue
			}
			tags = append(tags, tag)
			cache = append(cache, detour)
		}
		outbounds = append(outbounds, cache...)
		s.outboundsCache[providerTag] = cache
	}
	if len(outbounds) == 0 {
		s.logger.Warn("urltest has no members, connections will fail until a member appears")
	}
	s.tags = tags
	s.group.access.Lock()
	previousMembers := s.group.outbounds
	s.group.outbounds = outbounds
	if s.group.selectedOutboundTCP != nil {
		s.group.selectedOutboundTCP = outboundByTag(outbounds, s.group.selectedOutboundTCP.Tag(), N.NetworkTCP)
	}
	if s.group.selectedOutboundUDP != nil {
		s.group.selectedOutboundUDP = outboundByTag(outbounds, s.group.selectedOutboundUDP.Tag(), N.NetworkUDP)
	}
	if s.group.ticker != nil {
		s.group.ticker.Reset(s.group.interval)
	}
	if b := s.group.bandwidth; b != nil && !slices.Equal(previousMembers, outbounds) {
		b.access.Lock()
		b.generation++
		b.lastRun = time.Time{}
		for member := range b.results {
			if outboundByTag(previousMembers, member, N.NetworkTCP) != outboundByTag(outbounds, member, N.NetworkTCP) {
				delete(b.results, member)
			}
		}
		b.access.Unlock()
	}
	s.group.access.Unlock()
	ctx, cancel := context.WithCancel(s.ctx)
	if s.cancel != nil {
		s.cancel()
	}
	s.cancel = cancel
	s.access.Unlock()
	go func() { _, _ = s.group.urlTest(ctx, true) }()
	return nil
}

type URLTestGroup struct {
	ctx                          context.Context
	cancel                       context.CancelFunc
	bandwidth                    *urlTestBandwidth
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	link                         string
	expectedStatus               urltest.ExpectedStatus
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	history                      *urltest.HistoryStorage
	sharedHistory                *urltest.HistoryStorage
	coordinator                  *urltest.Coordinator
	checking                     chan struct{}
	selectedOutboundTCP          adapter.Outbound
	selectedOutboundUDP          adapter.Outbound
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.RWMutex
	ticker                       *time.Ticker
	close                        chan struct{}
	started                      bool
	lastActive                   common.TypedValue[time.Time]
	failureAccess                sync.Mutex
	failures                     dialFailures
	failureCheck                 atomic.Bool
}

func NewURLTestGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, expectedStatus urltest.ExpectedStatus, interval time.Duration, tolerance uint16, idleTimeout time.Duration, interruptExternalConnections bool) (*URLTestGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	coordinator := service.PtrFromContext[urltest.Coordinator](ctx)
	if coordinator == nil {
		coordinator = urltest.NewCoordinator()
	}
	ctx, cancel := context.WithCancel(ctx)
	return &URLTestGroup{
		ctx:                          ctx,
		cancel:                       cancel,
		outbound:                     outboundManager,
		logger:                       logger,
		outbounds:                    outbounds,
		link:                         link,
		expectedStatus:               expectedStatus,
		interval:                     interval,
		tolerance:                    tolerance,
		idleTimeout:                  idleTimeout,
		history:                      urltest.NewHistoryStorage(),
		sharedHistory:                historyStorage(ctx),
		coordinator:                  coordinator,
		checking:                     make(chan struct{}, 1),
		close:                        make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
	}, nil
}

// freshFor is how long a scheduled check takes a result as current: half an interval keeps a tick
// from reusing the previous tick's results, while groups probing one member within it still share
// a probe.
func freshFor(interval time.Duration) time.Duration {
	return interval / 2
}

func (g *URLTestGroup) deleteHistory(tag string) {
	g.history.DeleteURLTestHistory(tag)
	g.sharedHistory.DeleteURLTestHistory(tag)
}

func (g *URLTestGroup) storeHistory(tag string, history *adapter.URLTestHistory) {
	g.history.StoreURLTestHistory(tag, history)
	g.sharedHistory.StoreURLTestHistory(tag, history)
}

func (g *URLTestGroup) dialSucceeded() {
	g.failureAccess.Lock()
	g.failures = dialFailures{}
	g.failureAccess.Unlock()
}

// dialFailed checks the members at once when failed dials call for it, instead of leaving the
// group on a dead member until the next periodic check; one such check runs at a time.
func (g *URLTestGroup) dialFailed(ctx context.Context, detour adapter.Outbound, err error) {
	if ctx.Err() != nil || !countableDialFailure(detour, err) {
		return
	}
	g.failureAccess.Lock()
	check := g.failures.add(time.Now(), err)
	g.failureAccess.Unlock()
	if !check || !g.failureCheck.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer g.failureCheck.Store(false)
		g.CheckOutbounds(g.ctx, true)
	}()
}

func (g *URLTestGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	g.started = true
	g.lastActive.Store(time.Now())
	go g.CheckOutbounds(g.ctx, false)
}

func (g *URLTestGroup) Touch() {
	g.access.Lock()
	defer g.access.Unlock()
	if !g.started {
		return
	}
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		return
	}
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	go g.loopCheck(ticker, g.close)
}

func (g *URLTestGroup) Close() error {
	if g.cancel != nil {
		g.cancel()
	}
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	g.ticker = nil
	g.pause.UnregisterCallback(g.pauseCallback)
	g.pauseCallback = nil
	close(g.close)
	return nil
}

func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	g.access.RLock()
	defer g.access.RUnlock()
	return g.selectOutbound(network)
}

func (g *URLTestGroup) selectOutbound(network string) (adapter.Outbound, bool) {
	qualified := g.bandwidthCandidates(network)
	var minDelay uint16
	var minOutbound adapter.Outbound
	switch network {
	case N.NetworkTCP:
		if g.selectedOutboundTCP != nil && (qualified == nil || qualified[g.selectedOutboundTCP.Tag()]) {
			if history := g.history.LoadURLTestHistory(RealTag(g.selectedOutboundTCP, N.NetworkTCP)); history != nil {
				minOutbound = g.selectedOutboundTCP
				minDelay = history.Delay
			}
		}
	case N.NetworkUDP:
		if g.selectedOutboundUDP != nil && (qualified == nil || qualified[g.selectedOutboundUDP.Tag()]) {
			if history := g.history.LoadURLTestHistory(RealTag(g.selectedOutboundUDP, N.NetworkUDP)); history != nil {
				minOutbound = g.selectedOutboundUDP
				minDelay = history.Delay
			}
		}
	}
	for _, detour := range g.outbounds {
		if qualified != nil && !qualified[detour.Tag()] {
			continue
		}
		if !common.Contains(detour.Network(), network) {
			continue
		}
		history := g.history.LoadURLTestHistory(RealTag(detour, network))
		if history == nil {
			continue
		}
		if minDelay == 0 || minDelay > history.Delay+g.tolerance {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	if minOutbound == nil {
		for _, detour := range g.outbounds {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			return detour, false
		}
		return nil, false
	}
	return minOutbound, true
}

func (g *URLTestGroup) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}) {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(g.ctx, false)
	}
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			if g.ticker == ticker {
				g.ticker.Stop()
				g.ticker = nil
				g.pause.UnregisterCallback(g.pauseCallback)
				g.pauseCallback = nil
			}
			g.access.Unlock()
			return
		}
		g.CheckOutbounds(g.ctx, false)
	}
}

func (g *URLTestGroup) CheckOutbounds(ctx context.Context, force bool) {
	_, _ = g.urlTest(ctx, force)
}

func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, true)
}

// urlTest checks every outbound of the group. An unforced check is skipped
// while another one is running; a forced check runs at once, and the
// coordinator joins it to the tests already in flight.
func (g *URLTestGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	result := make(map[string]uint16)
	if !force {
		select {
		case g.checking <- struct{}{}:
			defer func() { <-g.checking }()
		default:
			return result, nil
		}
	}
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	var resultAccess sync.Mutex
	g.access.RLock()
	outbounds := append([]adapter.Outbound(nil), g.outbounds...)
	g.access.RUnlock()
	for _, detour := range outbounds {
		tag := detour.Tag()
		realTag := MemberTag(detour)
		if checked[realTag] {
			continue
		}
		history := g.history.LoadURLTestHistory(realTag)
		if !force && history != nil && time.Since(history.Time) < freshFor(g.interval) {
			continue
		}
		checked[realTag] = true
		p, loaded := g.outbound.Outbound(realTag)
		if !loaded {
			continue
		}
		b.Go(realTag, func() (any, error) {
			maxAge := freshFor(g.interval)
			if force {
				maxAge = 0
			}
			t, at, err := g.coordinator.Check(ctx, g.link, g.expectedStatus, realTag, p, C.TCPTimeout, maxAge)
			if err != nil && ctx.Err() != nil {
				// Running out of the caller's time says nothing about the member,
				// so its history stays.
				return nil, nil
			}
			if err != nil {
				g.logger.Debug("outbound ", tag, " unavailable: ", err)
				g.deleteHistory(realTag)
			} else {
				g.logger.Debug("outbound ", tag, " available: ", t, "ms")
				g.storeHistory(realTag, &adapter.URLTestHistory{
					Time:  at,
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	if g.ctx.Err() == nil {
		g.performUpdateCheck()
		g.startBandwidthTest(false)
	}
	return result, nil
}

type urlTestResult struct {
	delay uint16
	err   error
}

type urlTestBatch struct {
	ctx      context.Context
	outbound adapter.OutboundManager
	history  *urltest.HistoryStorage
	logger   log.Logger
	batch    *batch.Batch[any]
	checked  map[string]bool
	groups   []adapter.OutboundGroup
	access   sync.Mutex
	result   map[string]uint16
}

func URLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool) map[string]uint16 {
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	testBatch := &urlTestBatch{
		ctx:      ctx,
		outbound: outboundManager,
		history:  history,
		logger:   logger,
		batch:    b,
		checked:  make(map[string]bool),
		result:   make(map[string]uint16),
	}
	testBatch.test(outbounds, link, interval, force)
	b.Wait()
	for _, outboundGroup := range testBatch.groups {
		groupHistory := history.LoadURLTestHistory(RealTag(outboundGroup, N.NetworkTCP))
		if groupHistory != nil {
			testBatch.result[outboundGroup.Tag()] = groupHistory.Delay
		}
	}
	return testBatch.result
}

func (b *urlTestBatch) test(outbounds []adapter.Outbound, link string, interval time.Duration, force bool) {
	for _, detour := range outbounds {
		tag := detour.Tag()
		if b.checked[tag] {
			continue
		}
		switch nested := detour.(type) {
		case *URLTest:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.batch.Go(tag, func() (any, error) {
				nestedResult, _ := nested.group.urlTest(b.ctx, force)
				b.access.Lock()
				maps.Copy(b.result, nestedResult)
				b.access.Unlock()
				return nil, nil
			})
		case adapter.OutboundGroup:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.test(common.FilterNotNil(common.Map(nested.All(), func(it string) adapter.Outbound {
				member, _ := b.outbound.Outbound(it)
				return member
			})), link, interval, force)
		default:
			history := b.history.LoadURLTestHistory(tag)
			if !force && history != nil && time.Since(history.Time) < interval {
				continue
			}
			b.checked[tag] = true
			b.batch.Go(tag, func() (any, error) {
				testCtx, cancel := context.WithTimeout(b.ctx, C.TCPTimeout)
				defer cancel()
				testChan := make(chan urlTestResult, 1)
				go func() {
					delay, testErr := urltest.URLTest(testCtx, link, detour)
					testChan <- urlTestResult{delay, testErr}
				}()
				var testResult urlTestResult
				select {
				case testResult = <-testChan:
				case <-testCtx.Done():
					testResult.err = testCtx.Err()
				}
				if testResult.err != nil {
					b.logger.Debug("outbound ", tag, " unavailable: ", testResult.err)
					b.history.DeleteURLTestHistory(tag)
				} else {
					b.logger.Debug("outbound ", tag, " available: ", testResult.delay, "ms")
					b.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
						Time:  time.Now(),
						Delay: testResult.delay,
					})
					b.access.Lock()
					b.result[tag] = testResult.delay
					b.access.Unlock()
				}
				return nil, nil
			})
		}
	}
}

func (g *URLTestGroup) performUpdateCheck() {
	g.access.Lock()
	var (
		updated  bool
		selected bool
	)
	if outbound, exists := g.selectOutbound(N.NetworkTCP); outbound != nil && (g.selectedOutboundTCP == nil || (exists && outbound != g.selectedOutboundTCP)) {
		if g.selectedOutboundTCP != nil && g.selectedOutboundTCP.Tag() != outbound.Tag() {
			updated = true
		}
		g.selectedOutboundTCP = outbound
		selected = true
	}
	if outbound, exists := g.selectOutbound(N.NetworkUDP); outbound != nil && (g.selectedOutboundUDP == nil || (exists && outbound != g.selectedOutboundUDP)) {
		if g.selectedOutboundUDP != nil && g.selectedOutboundUDP.Tag() != outbound.Tag() {
			updated = true
		}
		g.selectedOutboundUDP = outbound
		selected = true
	}
	g.access.Unlock()
	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
	if selected {
		g.history.NotifyUpdated()
	}
}

func outboundByTag(outbounds []adapter.Outbound, tag string, network string) adapter.Outbound {
	if tag == "" {
		return nil
	}
	for _, outbound := range outbounds {
		if outbound.Tag() == tag && common.Contains(outbound.Network(), network) {
			return outbound
		}
	}
	return nil
}
