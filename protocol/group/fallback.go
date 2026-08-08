package group

import (
	"context"
	"errors"
	"net"
	"regexp"
	"sync"
	"syscall"
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
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const (
	defaultFallbackURL                  = "https://www.gstatic.com/generate_204"
	defaultFallbackAttemptTimeout       = 5 * time.Second
	defaultFallbackMaxFailedAttempts    = 5
	defaultFallbackStartupRetryInterval = 5 * time.Second
	defaultFallbackStartupRetryCount    = 12
)

func RegisterFallback(registry *outbound.Registry) {
	outbound.Register[option.FallbackOutboundOptions](registry, C.TypeFallback, NewFallback)
}

var _ adapter.OutboundGroup = (*Fallback)(nil)

type fallbackLevel struct {
	tag             string
	outboundTags    []string
	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	useAllProviders bool
}

type fallbackCandidate struct {
	tag      string
	outbound adapter.Outbound
	level    int
}

type fallbackHealth struct {
	outbound       adapter.Outbound
	checked        bool
	alive          bool
	failureCount   int
	failureStarted time.Time
}

type fallbackCheckResult struct {
	candidate fallbackCandidate
	delay     uint16
	err       error
}

type FallbackLevel struct {
	Tag       string   `json:"tag,omitempty"`
	Outbounds []string `json:"outbounds"`
}

type Fallback struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	provider                     adapter.ProviderManager
	logger                       logger.ContextLogger
	history                      adapter.URLTestHistoryStorage
	levels                       []fallbackLevel
	providers                    map[string]adapter.Provider
	candidates                   []fallbackCandidate
	health                       map[string]fallbackHealth
	selected                     string
	link                         string
	interval                     time.Duration
	timeout                      time.Duration
	maxFailedTimes               int
	expectedStatus               urltest.ExpectedStatus
	attemptTimeout               time.Duration
	idleTimeout                  time.Duration
	interruptExternalConnections bool
	interruptGroup               *interrupt.Group
	lastActive                   time.Time
	access                       sync.RWMutex
	checkAccess                  sync.Mutex
	wake                         chan struct{}
	cancel                       context.CancelFunc
}

func NewFallback(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FallbackOutboundOptions) (adapter.Outbound, error) {
	if len(options.Levels) > 0 && (len(options.Outbounds) > 0 || len(options.Providers) > 0 || options.UseAllProviders || options.Include != nil || options.Exclude != nil) {
		return nil, E.New("fallback levels cannot be combined with top-level members")
	}
	levelOptions := options.Levels
	if len(levelOptions) == 0 {
		levelOptions = []option.FallbackLevelOptions{{GroupCommonOption: options.GroupCommonOption}}
	}
	var (
		levels       []fallbackLevel
		dependencies []string
		hasMembers   bool
	)
	for _, levelOptions := range levelOptions {
		level := fallbackLevel{
			tag:             levelOptions.Tag,
			outboundTags:    append([]string(nil), levelOptions.Outbounds...),
			providerTags:    append([]string(nil), levelOptions.Providers...),
			exclude:         (*regexp.Regexp)(levelOptions.Exclude),
			include:         (*regexp.Regexp)(levelOptions.Include),
			useAllProviders: levelOptions.UseAllProviders,
		}
		if len(level.outboundTags) > 0 || len(level.providerTags) > 0 || level.useAllProviders {
			hasMembers = true
		}
		dependencies = append(dependencies, level.outboundTags...)
		levels = append(levels, level)
	}
	if !hasMembers {
		return nil, E.New("missing fallback members")
	}

	interval := time.Duration(options.Interval)
	if interval == 0 {
		interval = 5 * time.Minute
	}
	timeout := time.Duration(options.Timeout)
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	idleTimeout := time.Duration(options.IdleTimeout)
	if idleTimeout == 0 {
		idleTimeout = interval
	}
	if interval <= 0 || timeout <= 0 || idleTimeout <= 0 {
		return nil, E.New("fallback durations must be positive")
	}
	if interval > idleTimeout {
		return nil, E.New("fallback interval must be less or equal than idle_timeout")
	}
	maxFailedTimes := options.MaxFailedTimes
	if maxFailedTimes == 0 {
		maxFailedTimes = defaultFallbackMaxFailedAttempts
	}
	if maxFailedTimes < 1 {
		return nil, E.New("fallback max_failed_times must be positive")
	}
	expectedStatus, err := urltest.ParseExpectedStatus(options.ExpectedStatus)
	if err != nil {
		return nil, E.Cause(err, "invalid fallback expected_status")
	}
	link := options.URL
	if link == "" {
		link = defaultFallbackURL
	}
	history := service.FromContext[adapter.URLTestHistoryStorage](ctx)
	if history == nil {
		if clashServer := service.FromContext[adapter.ClashServer](ctx); clashServer != nil {
			history = clashServer.HistoryStorage()
		} else {
			history = urltest.NewHistoryStorage()
		}
	}
	return &Fallback{
		Adapter:                      outbound.NewAdapter(C.TypeFallback, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		provider:                     service.FromContext[adapter.ProviderManager](ctx),
		logger:                       logger,
		history:                      history,
		levels:                       levels,
		providers:                    make(map[string]adapter.Provider),
		health:                       make(map[string]fallbackHealth),
		link:                         link,
		interval:                     interval,
		timeout:                      timeout,
		maxFailedTimes:               maxFailedTimes,
		expectedStatus:               expectedStatus,
		attemptTimeout:               defaultFallbackAttemptTimeout,
		idleTimeout:                  idleTimeout,
		interruptExternalConnections: options.InterruptExistConnections,
		interruptGroup:               interrupt.NewGroup(),
		lastActive:                   time.Now(),
		wake:                         make(chan struct{}, 1),
	}, nil
}

func (s *Fallback) Start() error {
	providerTags := make(map[string]bool)
	var allProviders []adapter.Provider
	for _, level := range s.levels {
		if level.useAllProviders {
			if s.provider == nil {
				return E.New("outbound provider manager unavailable")
			}
			allProviders = s.provider.Providers()
			break
		}
	}
	for levelIndex := range s.levels {
		level := &s.levels[levelIndex]
		if level.useAllProviders {
			level.providerTags = level.providerTags[:0]
			for _, provider := range allProviders {
				level.providerTags = append(level.providerTags, provider.Tag())
			}
		}
		for _, providerTag := range level.providerTags {
			providerTags[providerTag] = true
		}
	}
	if len(providerTags) > 0 && s.provider == nil {
		return E.New("outbound provider manager unavailable")
	}
	for providerTag := range providerTags {
		provider, loaded := s.provider.Get(providerTag)
		if !loaded {
			return E.New("outbound provider not found: ", providerTag)
		}
		s.providers[providerTag] = provider
		provider.RegisterCallback(s.onProviderUpdated)
	}
	return s.rebuildCandidates()
}

func (s *Fallback) PostStart() error {
	healthContext, cancel := context.WithCancel(s.ctx)
	s.cancel = cancel
	go s.loopCheck(healthContext)
	return nil
}

func (s *Fallback) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *Fallback) Now() string {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.selected
}

func (s *Fallback) All() []string {
	s.access.RLock()
	defer s.access.RUnlock()
	tags := make([]string, 0, len(s.candidates))
	for _, candidate := range s.candidates {
		tags = append(tags, candidate.tag)
	}
	return tags
}

func (s *Fallback) Levels() []FallbackLevel {
	s.access.RLock()
	defer s.access.RUnlock()
	levels := make([]FallbackLevel, len(s.levels))
	for index, level := range s.levels {
		levels[index].Tag = level.tag
	}
	for _, candidate := range s.candidates {
		levels[candidate.level].Outbounds = append(levels[candidate.level].Outbounds, candidate.tag)
	}
	return levels
}

func (s *Fallback) onProviderUpdated(string) error {
	if err := s.rebuildCandidates(); err != nil {
		return err
	}
	s.requestCheck()
	return nil
}

func (s *Fallback) rebuildCandidates() error {
	assigned := make(map[string]bool)
	var candidates []fallbackCandidate
	for levelIndex, level := range s.levels {
		for _, tag := range level.outboundTags {
			if assigned[tag] {
				continue
			}
			detour, loaded := s.outbound.Outbound(tag)
			if !loaded {
				return E.New("fallback outbound not found: ", tag)
			}
			assigned[tag] = true
			candidates = append(candidates, fallbackCandidate{tag: tag, outbound: detour, level: levelIndex})
		}
		for _, providerTag := range level.providerTags {
			provider := s.providers[providerTag]
			for _, detour := range provider.Outbounds() {
				tag := detour.Tag()
				filterTag := providerOutboundFilterTag(providerTag, tag)
				if assigned[tag] || level.exclude != nil && level.exclude.MatchString(filterTag) || level.include != nil && !level.include.MatchString(filterTag) {
					continue
				}
				assigned[tag] = true
				candidates = append(candidates, fallbackCandidate{tag: tag, outbound: detour, level: levelIndex})
			}
		}
	}

	s.access.Lock()
	oldSelected := s.selected
	oldHealth := s.health
	health := make(map[string]fallbackHealth, len(candidates))
	for _, candidate := range candidates {
		state, loaded := oldHealth[candidate.tag]
		if !loaded || state.outbound != candidate.outbound {
			state = fallbackHealth{outbound: candidate.outbound}
		}
		health[candidate.tag] = state
	}
	s.candidates = candidates
	s.health = health
	s.selected = s.selectAvailableLocked()
	newSelected := s.selected
	s.access.Unlock()
	s.interruptSelection(oldSelected, newSelected)
	return nil
}

func (s *Fallback) selectAvailableLocked() string {
	for _, candidate := range s.candidates {
		state := s.health[candidate.tag]
		if !state.checked || state.alive {
			return candidate.tag
		}
	}
	return ""
}

func (s *Fallback) candidatesForNetwork(network string) []fallbackCandidate {
	s.access.RLock()
	defer s.access.RUnlock()
	var candidates []fallbackCandidate
	for _, candidate := range s.candidates {
		state := s.health[candidate.tag]
		if state.checked && !state.alive || !common.Contains(candidate.outbound.Network(), N.NetworkName(network)) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func (s *Fallback) candidateAvailable(candidate fallbackCandidate) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	state, loaded := s.health[candidate.tag]
	return loaded && state.outbound == candidate.outbound && (!state.checked || state.alive)
}

func (s *Fallback) touch() {
	s.access.Lock()
	wasIdle := time.Since(s.lastActive) > s.idleTimeout
	s.lastActive = time.Now()
	s.access.Unlock()
	if wasIdle {
		s.requestCheck()
	}
}

func (s *Fallback) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.touch()
	candidates := s.candidatesForNetwork(network)
	connectionContext, closeCancel := context.WithCancel(ctx)
	conn, candidate, remaining, cancel, err := s.dialCandidates(connectionContext, network, destination, candidates)
	if err != nil {
		closeCancel()
		return nil, err
	}
	if N.NeedHandshakeForWrite(conn) {
		conn = &fallbackEarlyConn{
			Conn:        conn,
			fallback:    s,
			ctx:         connectionContext,
			network:     network,
			destination: destination,
			candidate:   candidate,
			remaining:   remaining,
			cancel:      cancel,
			closeCancel: closeCancel,
			pending:     true,
		}
	} else {
		cancel()
		closeCancel()
	}
	return s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
}

func (s *Fallback) dialCandidates(ctx context.Context, network string, destination M.Socksaddr, candidates []fallbackCandidate) (net.Conn, fallbackCandidate, []fallbackCandidate, context.CancelFunc, error) {
	var lastError error
	for index, candidate := range candidates {
		if !s.candidateAvailable(candidate) {
			continue
		}
		attemptContext, cancel := s.newAttemptContext(ctx, len(candidates)-index)
		conn, err := candidate.outbound.DialContext(attemptContext, network, destination)
		if err == nil {
			if !N.NeedHandshakeForWrite(conn) {
				s.recordDialSuccess(candidate)
			}
			return conn, candidate, candidates[index+1:], cancel, nil
		}
		cancel()
		lastError = err
		if ctx.Err() != nil {
			return nil, fallbackCandidate{}, nil, func() {}, ctx.Err()
		}
		s.logger.InfoContext(ctx, "fallback outbound ", candidate.tag, " failed: ", err)
		s.recordDialFailure(candidate, err)
	}
	if lastError == nil {
		lastError = E.New("no available fallback outbounds")
	}
	return nil, fallbackCandidate{}, nil, func() {}, lastError
}

func (s *Fallback) newAttemptContext(ctx context.Context, candidateCount int) (context.Context, context.CancelFunc) {
	timeout := s.attemptTimeout
	if timeout <= 0 {
		timeout = defaultFallbackAttemptTimeout
	}
	if deadline, loaded := ctx.Deadline(); loaded && candidateCount > 0 {
		remaining := time.Until(deadline)
		if shared := remaining / time.Duration(candidateCount); shared < timeout {
			timeout = shared
		}
	}
	return context.WithTimeout(ctx, timeout)
}

func (s *Fallback) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.touch()
	var lastError error
	candidates := s.candidatesForNetwork(N.NetworkUDP)
	for index, candidate := range candidates {
		attemptContext, cancel := s.newAttemptContext(ctx, len(candidates)-index)
		conn, err := candidate.outbound.ListenPacket(attemptContext, destination)
		cancel()
		if err == nil {
			s.recordDialSuccess(candidate)
			return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
		}
		lastError = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s.logger.InfoContext(ctx, "fallback outbound ", candidate.tag, " failed: ", err)
		s.recordDialFailure(candidate, err)
	}
	if lastError == nil {
		lastError = E.New("no available fallback outbounds")
	}
	return nil, lastError
}

func (s *Fallback) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	conn = s.interruptGroup.NewConn(conn, true, interrupt.IsProviderConnectionFromContext(ctx))
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *Fallback) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	conn = s.interruptGroup.NewSingPacketConn(conn, true, interrupt.IsProviderConnectionFromContext(ctx))
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func (s *Fallback) interruptSelection(oldSelected string, newSelected string) {
	if oldSelected == "" || oldSelected == newSelected {
		return
	}
	s.logger.Info("fallback switched from ", oldSelected, " to ", newSelected)
	s.interruptGroup.Interrupt(s.interruptExternalConnections)
}

func (s *Fallback) recordDialSuccess(candidate fallbackCandidate) {
	s.access.Lock()
	defer s.access.Unlock()
	state, loaded := s.health[candidate.tag]
	if !loaded || state.outbound != candidate.outbound {
		return
	}
	state.failureCount = 0
	state.failureStarted = time.Time{}
	s.health[candidate.tag] = state
}

func (s *Fallback) recordDialFailure(candidate fallbackCandidate, err error) {
	s.access.Lock()
	state, loaded := s.health[candidate.tag]
	if !loaded || state.outbound != candidate.outbound {
		s.access.Unlock()
		return
	}
	now := time.Now()
	failureWindow := s.timeout
	if failureWindow <= 0 {
		failureWindow = defaultFallbackAttemptTimeout
	}
	if state.failureCount == 0 || now.Sub(state.failureStarted) > failureWindow {
		state.failureCount = 1
		state.failureStarted = now
	} else {
		state.failureCount++
	}
	maxFailedTimes := s.maxFailedTimes
	if maxFailedTimes <= 0 {
		maxFailedTimes = defaultFallbackMaxFailedAttempts
	}
	check := errors.Is(err, syscall.ECONNREFUSED) || state.failureCount >= maxFailedTimes
	if check {
		state.failureCount = 0
		state.failureStarted = time.Time{}
	}
	s.health[candidate.tag] = state
	s.access.Unlock()
	if check {
		s.requestCheck()
	}
}

func (s *Fallback) requestCheck() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Fallback) loopCheck(ctx context.Context) {
	s.checkOutbounds(ctx)
	for retry := 0; retry < defaultFallbackStartupRetryCount && ctx.Err() == nil && s.needsInitialHealthRetry(); retry++ {
		timer := time.NewTimer(defaultFallbackStartupRetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			s.checkFirstOutbound(ctx)
		}
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			s.checkOutbounds(ctx)
		case <-ticker.C:
			s.access.RLock()
			active := time.Since(s.lastActive) <= s.idleTimeout
			s.access.RUnlock()
			if active {
				s.checkOutbounds(ctx)
			}
		}
	}
}

func (s *Fallback) needsInitialHealthRetry() bool {
	s.access.RLock()
	defer s.access.RUnlock()
	if len(s.candidates) == 0 {
		return false
	}
	state, loaded := s.health[s.candidates[0].tag]
	return loaded && state.checked && !state.alive
}

func (s *Fallback) checkOutbounds(ctx context.Context) {
	s.access.RLock()
	candidates := append([]fallbackCandidate(nil), s.candidates...)
	s.access.RUnlock()
	s.checkCandidates(ctx, candidates)
}

func (s *Fallback) checkFirstOutbound(ctx context.Context) {
	s.access.RLock()
	if len(s.candidates) == 0 {
		s.access.RUnlock()
		return
	}
	candidate := s.candidates[0]
	s.access.RUnlock()
	s.checkCandidates(ctx, []fallbackCandidate{candidate})
}

func (s *Fallback) checkCandidates(ctx context.Context, candidates []fallbackCandidate) {
	s.checkAccess.Lock()
	defer s.checkAccess.Unlock()
	results := make([]fallbackCheckResult, len(candidates))
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	for index, candidate := range candidates {
		results[index].candidate = candidate
		b.Go(candidate.tag, func() (any, error) {
			testContext, cancel := context.WithTimeout(ctx, s.timeout)
			defer cancel()
			results[index].delay, results[index].err = urltest.URLTestWithExpectedStatus(testContext, s.link, candidate.outbound, s.expectedStatus)
			return nil, nil
		})
	}
	b.Wait()
	if ctx.Err() != nil {
		return
	}

	s.access.Lock()
	oldSelected := s.selected
	for _, result := range results {
		state, loaded := s.health[result.candidate.tag]
		if !loaded || state.outbound != result.candidate.outbound {
			continue
		}
		state.checked = true
		state.alive = result.err == nil
		state.failureCount = 0
		state.failureStarted = time.Time{}
		s.health[result.candidate.tag] = state
		if result.err == nil {
			s.history.StoreURLTestHistory(result.candidate.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: result.delay})
			s.logger.Debug("fallback outbound ", result.candidate.tag, " available: ", result.delay, "ms")
		} else {
			s.history.DeleteURLTestHistory(result.candidate.tag)
			s.logger.Debug("fallback outbound ", result.candidate.tag, " unavailable: ", result.err)
		}
	}
	s.selected = s.selectAvailableLocked()
	newSelected := s.selected
	s.access.Unlock()
	s.interruptSelection(oldSelected, newSelected)
}

type fallbackEarlyConn struct {
	net.Conn
	fallback    *Fallback
	ctx         context.Context
	network     string
	destination M.Socksaddr
	candidate   fallbackCandidate
	remaining   []fallbackCandidate
	cancel      context.CancelFunc
	closeCancel context.CancelFunc
	pending     bool
	closed      bool
	access      sync.Mutex
}

func (c *fallbackEarlyConn) Write(buffer []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.pending {
		return c.Conn.Write(buffer)
	}
	for {
		n, err := c.Conn.Write(buffer)
		c.cancel()
		c.cancel = func() {}
		if err == nil {
			c.fallback.recordDialSuccess(c.candidate)
			c.pending = false
			return n, nil
		}
		_ = c.Conn.Close()
		c.fallback.recordDialFailure(c.candidate, err)
		if n > 0 || c.ctx.Err() != nil {
			c.pending = false
			return n, err
		}
		conn, candidate, remaining, cancel, dialErr := c.fallback.dialCandidates(c.ctx, c.network, c.destination, c.remaining)
		if dialErr != nil {
			c.pending = false
			return 0, dialErr
		}
		c.Conn = conn
		c.candidate = candidate
		c.remaining = remaining
		c.cancel = cancel
		if !N.NeedHandshakeForWrite(conn) {
			cancel()
			c.cancel = func() {}
		}
	}
}

func (c *fallbackEarlyConn) Close() error {
	c.closeCancel()
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.cancel()
	return c.Conn.Close()
}

func (c *fallbackEarlyConn) NeedHandshake() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.pending && N.NeedHandshakeForWrite(c.Conn)
}

func (c *fallbackEarlyConn) ReaderReplaceable() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return !c.pending
}

func (c *fallbackEarlyConn) WriterReplaceable() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return !c.pending
}

func (c *fallbackEarlyConn) Upstream() any {
	c.access.Lock()
	defer c.access.Unlock()
	return c.Conn
}
