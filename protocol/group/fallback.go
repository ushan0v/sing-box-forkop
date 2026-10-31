package group

import (
	"context"
	"io"
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
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const (
	defaultFallbackAttemptTimeout       = 5 * time.Second
	defaultFallbackStartupRetryInterval = 5 * time.Second
	defaultFallbackStartupRetryCount    = 12
)

func RegisterFallback(registry *outbound.Registry) {
	outbound.Register[option.FallbackOutboundOptions](registry, C.TypeFallback, NewFallback)
}

var (
	_ adapter.DialingOutboundGroup    = (*Fallback)(nil)
	_ adapter.URLTestGroup            = (*Fallback)(nil)
	_ adapter.SelectableOutboundGroup = (*Fallback)(nil)
	_ adapter.InterfaceUpdateListener = (*Fallback)(nil)
)

type fallbackGroup struct {
	outboundTags    []string
	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	excludeTypes    map[string]bool
	useAllProviders bool
}

type fallbackCandidate struct {
	tag      string
	outbound adapter.Outbound
	group    int
}

type fallbackHealth struct {
	outbound adapter.Outbound
	checked  bool
	alive    bool
	failures dialFailures
}

type fallbackCheckResult struct {
	candidate fallbackCandidate
	delay     uint16
	at        time.Time
	err       error
}

type FallbackGroup struct {
	Outbounds []string `json:"outbounds"`
}

type Fallback struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	provider                     adapter.ProviderManager
	logger                       logger.ContextLogger
	history                      *urltest.HistoryStorage
	groups                       []fallbackGroup
	providers                    map[string]adapter.Provider
	providerCallbacks            []providerCallbackRegistration
	candidates                   []fallbackCandidate
	health                       map[string]fallbackHealth
	selected                     string
	fixed                        string
	coordinator                  *urltest.Coordinator
	link                         string
	interval                     time.Duration
	timeout                      time.Duration
	expectedStatus               urltest.ExpectedStatus
	attemptTimeout               time.Duration
	idleTimeout                  time.Duration
	interruptExternalConnections bool
	interruptGroup               *interrupt.Group
	lastActive                   time.Time
	access                       sync.RWMutex
	rebuildAccess                sync.Mutex
	wake                         chan struct{}
	cancel                       context.CancelFunc
}

func NewFallback(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FallbackOutboundOptions) (adapter.Outbound, error) {
	if len(options.Groups) > 0 && (len(options.Outbounds) > 0 || len(options.Providers) > 0 || options.UseAllProviders || options.Include != nil || options.Exclude != nil) {
		return nil, E.New("fallback groups cannot be combined with top-level members")
	}
	groupOptions := options.Groups
	if len(groupOptions) == 0 {
		groupOptions = []option.FallbackGroupOptions{{GroupCommonOption: options.GroupCommonOption}}
	}
	var (
		groups       []fallbackGroup
		dependencies []string
		hasMembers   bool
	)
	for _, currentOptions := range groupOptions {
		group := fallbackGroup{
			outboundTags:    append([]string(nil), currentOptions.Outbounds...),
			providerTags:    append([]string(nil), currentOptions.Providers...),
			exclude:         (*regexp.Regexp)(currentOptions.Exclude),
			include:         (*regexp.Regexp)(currentOptions.Include),
			excludeTypes:    excludedOutboundTypes(currentOptions.ExcludeTypes),
			useAllProviders: currentOptions.UseAllProviders,
		}
		if len(group.outboundTags) > 0 || len(group.providerTags) > 0 || group.useAllProviders {
			hasMembers = true
		}
		dependencies = append(dependencies, group.outboundTags...)
		groups = append(groups, group)
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
	attemptTimeout := time.Duration(options.AttemptTimeout)
	if attemptTimeout == 0 {
		attemptTimeout = defaultFallbackAttemptTimeout
	}
	if attemptTimeout < 0 {
		return nil, E.New("fallback attempt_timeout must be positive")
	}
	expectedStatus, err := urltest.ParseExpectedStatus(options.ExpectedStatus)
	if err != nil {
		return nil, E.Cause(err, "invalid fallback expected_status")
	}
	coordinator := service.PtrFromContext[urltest.Coordinator](ctx)
	if coordinator == nil {
		coordinator = urltest.NewCoordinator()
	}
	return &Fallback{
		Adapter:                      outbound.NewAdapter(C.TypeFallback, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		provider:                     service.FromContext[adapter.ProviderManager](ctx),
		logger:                       logger,
		coordinator:                  coordinator,
		groups:                       groups,
		providers:                    make(map[string]adapter.Provider),
		health:                       make(map[string]fallbackHealth),
		link:                         options.URL,
		interval:                     interval,
		timeout:                      timeout,
		expectedStatus:               expectedStatus,
		attemptTimeout:               attemptTimeout,
		idleTimeout:                  idleTimeout,
		interruptExternalConnections: options.InterruptExistConnections,
		interruptGroup:               interrupt.NewGroup(),
		lastActive:                   time.Now(),
		wake:                         make(chan struct{}, 1),
	}, nil
}

func (s *Fallback) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		scope.Add(s.Close)
		return s.start()
	case adapter.StartStatePostStart:
		s.postStart()
	}
	return nil
}

func (s *Fallback) start() (err error) {
	defer func() {
		if err != nil {
			unregisterProviderCallbacks(s.providerCallbacks)
			s.providerCallbacks = nil
		}
	}()
	s.history = historyStorage(s.ctx)
	providerTags := make(map[string]bool)
	var allProviders []adapter.Provider
	for _, group := range s.groups {
		if group.useAllProviders {
			if s.provider == nil {
				return E.New("outbound provider manager unavailable")
			}
			allProviders = s.provider.Providers()
			break
		}
	}
	for groupIndex := range s.groups {
		group := &s.groups[groupIndex]
		if group.useAllProviders {
			group.providerTags = group.providerTags[:0]
			for _, provider := range allProviders {
				group.providerTags = append(group.providerTags, provider.Tag())
			}
		}
		for _, providerTag := range group.providerTags {
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
		s.providerCallbacks = append(s.providerCallbacks, registerProviderCallback(provider, s.onProviderUpdated))
	}
	if s.Tag() != "" {
		if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil {
			s.fixed = cacheFile.LoadSelected(s.Tag())
		}
	}
	return s.rebuildCandidates()
}

func (s *Fallback) postStart() {
	healthContext, cancel := context.WithCancel(s.ctx)
	s.cancel = cancel
	go s.loopCheck(healthContext)
}

func (s *Fallback) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	unregisterProviderCallbacks(s.providerCallbacks)
	s.providerCallbacks = nil
	return nil
}

// Selected is the member a dial of network tries first; the dial goes through the group, which
// moves on to the next member when that one fails.
func (s *Fallback) Selected(network string) adapter.Outbound {
	candidates := s.candidatesForNetwork(network)
	if len(candidates) == 0 {
		return nil
	}
	return candidates[0].outbound
}

func (s *Fallback) AttachConnection(closer io.Closer) func() {
	return s.interruptGroup.Add(closer, true)
}

func (s *Fallback) DialsMembers() {}

func (s *Fallback) All() []string {
	s.access.RLock()
	defer s.access.RUnlock()
	tags := make([]string, 0, len(s.candidates))
	for _, candidate := range s.candidates {
		tags = append(tags, candidate.tag)
	}
	return tags
}

// References keeps every candidate referenced, not only the selected one: a failed dial moves on
// to the next candidate at once, and a backup without its idle connections would make that slower.
func (s *Fallback) References() []string {
	return s.All()
}

func (s *Fallback) Groups() []FallbackGroup {
	s.access.RLock()
	defer s.access.RUnlock()
	groups := make([]FallbackGroup, len(s.groups))
	for _, candidate := range s.candidates {
		groups[candidate.group].Outbounds = append(groups[candidate.group].Outbounds, candidate.tag)
	}
	return groups
}

func (s *Fallback) onProviderUpdated(string) error {
	if err := s.rebuildCandidates(); err != nil {
		return err
	}
	if len(s.All()) == 0 {
		s.logger.Warn("fallback has no members, connections will fail until a member appears")
	}
	s.requestCheck()
	return nil
}

func (s *Fallback) rebuildCandidates() error {
	s.rebuildAccess.Lock()
	defer s.rebuildAccess.Unlock()
	assigned := make(map[string]bool)
	var candidates []fallbackCandidate
	for groupIndex, group := range s.groups {
		for _, tag := range group.outboundTags {
			if assigned[tag] {
				continue
			}
			detour, loaded := s.outbound.Outbound(tag)
			if !loaded {
				return E.New("fallback outbound not found: ", tag)
			}
			assigned[tag] = true
			candidates = append(candidates, fallbackCandidate{tag: tag, outbound: detour, group: groupIndex})
		}
		for _, providerTag := range group.providerTags {
			provider := s.providers[providerTag]
			for _, detour := range provider.Outbounds() {
				tag := detour.Tag()
				filterTag := providerOutboundFilterTag(providerTag, tag)
				if assigned[tag] || group.excludeTypes[detour.Type()] ||
					group.exclude != nil && group.exclude.MatchString(filterTag) ||
					group.include != nil && !group.include.MatchString(filterTag) {
					continue
				}
				assigned[tag] = true
				candidates = append(candidates, fallbackCandidate{tag: tag, outbound: detour, group: groupIndex})
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

func (s *Fallback) usableLocked(candidate fallbackCandidate) bool {
	state := s.health[candidate.tag]
	return !state.checked || state.alive
}

// selectAvailableLocked mirrors Mihomo findAliveProxy: a manually pinned member
// wins while it stays usable, otherwise the first usable member by priority
// wins, and when nothing passed the health check the group still reports its
// highest priority member instead of reporting no selection at all. A pin is
// released only for another member that works, so it outlives a network outage.
func (s *Fallback) selectAvailableLocked() string {
	if s.fixed != "" {
		for _, candidate := range s.candidates {
			if candidate.tag != s.fixed {
				continue
			}
			if s.usableLocked(candidate) {
				return candidate.tag
			}
			if common.Any(s.candidates, s.usableLocked) {
				s.clearFixedLocked()
			}
			break
		}
	}
	for _, candidate := range s.candidates {
		if s.usableLocked(candidate) {
			return candidate.tag
		}
	}
	if len(s.candidates) > 0 {
		return s.candidates[0].tag
	}
	return ""
}

func (s *Fallback) clearFixedLocked() {
	if s.fixed == "" {
		return
	}
	s.logger.Info("fallback released pinned outbound ", s.fixed)
	s.fixed = ""
	s.storeFixed("")
}

func (s *Fallback) storeFixed(tag string) {
	if s.Tag() == "" {
		return
	}
	cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
	if cacheFile == nil {
		return
	}
	if err := cacheFile.StoreSelected(s.Tag(), tag); err != nil {
		s.logger.Error("store selected: ", err)
	}
}

// SelectOutbound pins the group to one member, or releases the pin when tag is
// empty. A member the last health check found down is tested again first, as
// Mihomo does, and stays unpinned if it is still down. The pin is released as
// soon as the pinned member fails a health check another member passes.
func (s *Fallback) SelectOutbound(tag string) bool {
	if tag != "" {
		s.access.RLock()
		index := slices.IndexFunc(s.candidates, func(it fallbackCandidate) bool { return it.tag == tag })
		var down []fallbackCandidate
		if index >= 0 && !s.usableLocked(s.candidates[index]) {
			down = append(down, s.candidates[index])
		}
		s.access.RUnlock()
		if index < 0 {
			return false
		}
		if len(down) > 0 {
			_, _ = s.checkCandidates(s.ctx, down, 0)
		}
	}
	s.access.Lock()
	if tag != "" && !common.Any(s.candidates, func(it fallbackCandidate) bool { return it.tag == tag }) {
		s.access.Unlock()
		return false
	}
	if s.fixed == tag {
		s.access.Unlock()
		return true
	}
	oldSelected := s.selected
	s.fixed = tag
	s.storeFixed(tag)
	s.selected = s.selectAvailableLocked()
	newSelected := s.selected
	s.access.Unlock()
	s.interruptSelection(oldSelected, newSelected)
	return true
}

func (s *Fallback) Fixed() string {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.fixed
}

// candidatesForNetwork returns the members able to serve network. Healthy
// members come first, followed by the highest priority unhealthy one, so a
// group whose health checks all failed still dials its first member the way
// Mihomo does instead of refusing the connection. Only one unhealthy member is
// kept, otherwise a real outage would make every connection walk the whole
// subscription before failing.
func (s *Fallback) candidatesForNetwork(network string) []fallbackCandidate {
	s.access.RLock()
	defer s.access.RUnlock()
	var (
		pinned     []fallbackCandidate
		usable     []fallbackCandidate
		lastResort []fallbackCandidate
	)
	for _, candidate := range s.candidates {
		if !common.Contains(candidate.outbound.Network(), N.NetworkName(network)) {
			continue
		}
		switch {
		case !s.usableLocked(candidate):
			if len(lastResort) == 0 {
				lastResort = append(lastResort, candidate)
			}
		case s.fixed != "" && candidate.tag == s.fixed:
			pinned = append(pinned, candidate)
		default:
			usable = append(usable, candidate)
		}
	}
	candidates := make([]fallbackCandidate, 0, len(pinned)+len(usable)+len(lastResort))
	candidates = append(candidates, pinned...)
	candidates = append(candidates, usable...)
	return append(candidates, lastResort...)
}

func (s *Fallback) candidateActive(candidate fallbackCandidate) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	state, loaded := s.health[candidate.tag]
	return loaded && state.outbound == candidate.outbound
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
	conn, candidate, remaining, attempt, err := s.dialCandidates(connectionContext, network, destination, candidates)
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
			attempt:     attempt,
			closeCancel: closeCancel,
			pending:     true,
		}
	} else {
		closeCancel()
	}
	return s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

// dialCandidates dials candidates in order and returns the first connection. A
// connection that still has to complete its handshake comes with its attempt
// running, any other with its attempt kept.
func (s *Fallback) dialCandidates(ctx context.Context, network string, destination M.Socksaddr, candidates []fallbackCandidate) (net.Conn, fallbackCandidate, []fallbackCandidate, *fallbackAttempt, error) {
	var lastError error
	for index, candidate := range candidates {
		if !s.candidateActive(candidate) {
			continue
		}
		attempt := s.newAttempt(ctx, len(candidates)-index)
		conn, err := candidate.outbound.DialContext(attempt.ctx, network, destination)
		if err == nil {
			if !N.NeedHandshakeForWrite(conn) {
				attempt.keep()
				s.recordDialSuccess(candidate)
			}
			return conn, candidate, candidates[index+1:], attempt, nil
		}
		err = attempt.fail(err)
		lastError = err
		if ctx.Err() != nil {
			return nil, fallbackCandidate{}, nil, nil, ctx.Err()
		}
		s.logger.InfoContext(ctx, "fallback outbound ", candidate.tag, " failed: ", err)
		s.recordDialFailure(candidate, err)
	}
	if lastError == nil {
		lastError = E.New("no available fallback outbounds")
	}
	return nil, fallbackCandidate{}, nil, nil, lastError
}

// fallbackAttempt is the context one member is dialed with. It ends when the
// attempt times out or the caller gives up, until keep releases it from both:
// transports such as gRPC and HTTP/2 hold their stream on the context they were
// dialed with for as long as the connection is open.
type fallbackAttempt struct {
	ctx      context.Context
	cancel   context.CancelFunc
	timer    *time.Timer
	unlink   func() bool
	timeout  time.Duration
	timedOut atomic.Bool
}

func (s *Fallback) newAttempt(ctx context.Context, candidateCount int) *fallbackAttempt {
	timeout := s.attemptTimeout
	if deadline, loaded := ctx.Deadline(); loaded && candidateCount > 0 {
		remaining := time.Until(deadline)
		if shared := remaining / time.Duration(candidateCount); shared < timeout {
			timeout = shared
		}
	}
	attemptContext, cancel := context.WithCancel(context.WithoutCancel(ctx))
	attempt := &fallbackAttempt{
		ctx:     attemptContext,
		cancel:  cancel,
		unlink:  context.AfterFunc(ctx, cancel),
		timeout: timeout,
	}
	attempt.timer = time.AfterFunc(timeout, func() {
		attempt.timedOut.Store(true)
		cancel()
	})
	return attempt
}

func (a *fallbackAttempt) keep() {
	a.timer.Stop()
	a.unlink()
}

// fail ends an attempt whose dial or handshake failed. A dial cut short by the
// attempt timeout only reports a cancelled context, so the timeout is named
// instead.
func (a *fallbackAttempt) fail(err error) error {
	a.keep()
	a.cancel()
	if a.timedOut.Load() {
		return E.New("attempt timed out after ", a.timeout)
	}
	return err
}

func (s *Fallback) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.touch()
	var lastError error
	candidates := s.candidatesForNetwork(N.NetworkUDP)
	for index, candidate := range candidates {
		if !s.candidateActive(candidate) {
			continue
		}
		attempt := s.newAttempt(ctx, len(candidates)-index)
		conn, err := candidate.outbound.ListenPacket(attempt.ctx, destination)
		if err == nil {
			attempt.keep()
			s.recordDialSuccess(candidate)
			return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
		}
		err = attempt.fail(err)
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
	state.failures = dialFailures{}
	s.health[candidate.tag] = state
}

func (s *Fallback) recordDialFailure(candidate fallbackCandidate, err error) {
	if !countableDialFailure(candidate.outbound, err) {
		return
	}
	s.access.Lock()
	state, loaded := s.health[candidate.tag]
	if !loaded || state.outbound != candidate.outbound {
		s.access.Unlock()
		return
	}
	check := state.failures.add(time.Now(), err)
	s.health[candidate.tag] = state
	s.access.Unlock()
	if check {
		s.requestCheck()
	}
}

// InterfaceUpdated checks the members again after a change of the default
// interface, which may have taken any of them down or brought them back.
func (s *Fallback) InterfaceUpdated(context.Context) {
	s.requestCheck()
}

func (s *Fallback) requestCheck() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Fallback) loopCheck(ctx context.Context) {
	s.checkOutbounds(ctx, 0)
	go s.startupRetry(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			s.checkOutbounds(ctx, 0)
		case <-ticker.C:
			s.access.RLock()
			active := time.Since(s.lastActive) <= s.idleTimeout
			s.access.RUnlock()
			if active {
				s.periodicCheck(ctx)
			}
		}
	}
}

// startupRetry repeats the health check shortly after start, because the router
// network is often not usable yet when sing-box starts. It runs beside the
// periodic ticker instead of delaying it.
func (s *Fallback) startupRetry(ctx context.Context) {
	for retry := 0; retry < defaultFallbackStartupRetryCount; retry++ {
		if len(s.startupRetryCandidates()) == 0 {
			return
		}
		timer := time.NewTimer(defaultFallbackStartupRetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		candidates := s.startupRetryCandidates()
		if len(candidates) == 0 {
			return
		}
		_, _ = s.checkCandidates(ctx, candidates, 0)
	}
}

// startupRetryCandidates retries the whole group while nothing is alive, which
// is what a not yet usable network looks like, and once something works only the
// highest priority member and the members no check has judged yet, so a
// permanently dead first member cannot cause repeated full sweeps on every start.
func (s *Fallback) startupRetryCandidates() []fallbackCandidate {
	s.access.RLock()
	defer s.access.RUnlock()
	if len(s.candidates) == 0 {
		return nil
	}
	for _, candidate := range s.candidates {
		if state := s.health[candidate.tag]; state.checked && state.alive {
			var retry []fallbackCandidate
			if first := s.candidates[0]; !s.usableLocked(first) {
				retry = append(retry, first)
			}
			for _, unjudged := range s.candidates {
				if !s.health[unjudged.tag].checked {
					retry = append(retry, unjudged)
				}
			}
			return retry
		}
	}
	return append([]fallbackCandidate(nil), s.candidates...)
}

func (s *Fallback) periodicCheck(ctx context.Context) {
	s.checkOutbounds(ctx, freshFor(s.interval))
}

func (s *Fallback) checkOutbounds(ctx context.Context, maxAge time.Duration) {
	s.access.RLock()
	candidates := append([]fallbackCandidate(nil), s.candidates...)
	s.access.RUnlock()
	_, _ = s.checkCandidates(ctx, candidates, maxAge)
}

func (s *Fallback) URLTest(ctx context.Context) (map[string]uint16, error) {
	s.access.RLock()
	candidates := append([]fallbackCandidate(nil), s.candidates...)
	s.access.RUnlock()
	return s.checkCandidates(ctx, candidates, 0)
}

// PerformUpdateCheck follows a delay test of a single node. The group selects
// from its own health checks, which that test does not change.
func (s *Fallback) PerformUpdateCheck() {
}

// checkCandidates health checks candidates. Results produced less than maxAge
// ago by another group testing the same member with the same URL are reused;
// pass maxAge 0 to force a fresh test.
func (s *Fallback) checkCandidates(ctx context.Context, candidates []fallbackCandidate, maxAge time.Duration) (map[string]uint16, error) {
	candidates = common.Filter(candidates, func(it fallbackCandidate) bool { return selectedByTest(it.outbound) })
	resultMap := make(map[string]uint16)
	results := make([]fallbackCheckResult, len(candidates))
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	for index, candidate := range candidates {
		results[index].candidate = candidate
		b.Go(candidate.tag, func() (any, error) {
			results[index].delay, results[index].at, results[index].err = s.coordinator.Check(ctx, s.link, s.expectedStatus, MemberTag(candidate.outbound), candidate.outbound, s.timeout, maxAge)
			return nil, nil
		})
	}
	b.Wait()

	s.access.Lock()
	oldSelected := s.selected
	for _, result := range results {
		// A failure after the caller's deadline says nothing about the member,
		// so its health and delay stay as they were.
		if result.err != nil && ctx.Err() != nil {
			continue
		}
		state, loaded := s.health[result.candidate.tag]
		if !loaded || state.outbound != result.candidate.outbound {
			continue
		}
		state.checked = true
		state.alive = result.err == nil
		state.failures = dialFailures{}
		s.health[result.candidate.tag] = state
		if result.err == nil {
			resultMap[result.candidate.tag] = result.delay
			s.history.StoreURLTestHistory(MemberTag(result.candidate.outbound), &adapter.URLTestHistory{Time: result.at, Delay: result.delay})
			s.logger.Debug("fallback outbound ", result.candidate.tag, " available: ", result.delay, "ms")
		} else {
			s.history.DeleteURLTestHistory(MemberTag(result.candidate.outbound))
			s.logger.Debug("fallback outbound ", result.candidate.tag, " unavailable: ", result.err)
		}
	}
	s.selected = s.selectAvailableLocked()
	newSelected := s.selected
	s.access.Unlock()
	s.interruptSelection(oldSelected, newSelected)
	return resultMap, nil
}

// selectedByTest reports whether member dials what a test chose: a URLTest that has not tested
// its members yet dials the first of them, so a check through it says nothing about the group.
func selectedByTest(member adapter.Outbound) bool {
	urlTest, isURLTest := member.(*URLTest)
	if !isURLTest {
		return true
	}
	group := urlTest.group
	if group == nil {
		return false
	}
	group.access.RLock()
	defer group.access.RUnlock()
	return group.selectedOutboundTCP != nil
}

type fallbackEarlyConn struct {
	net.Conn
	fallback    *Fallback
	ctx         context.Context
	network     string
	destination M.Socksaddr
	candidate   fallbackCandidate
	remaining   []fallbackCandidate
	attempt     *fallbackAttempt
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
		if err == nil {
			c.attempt.keep()
			c.closeCancel()
			c.fallback.recordDialSuccess(c.candidate)
			c.pending = false
			return n, nil
		}
		err = c.attempt.fail(err)
		_ = c.Conn.Close()
		c.fallback.recordDialFailure(c.candidate, err)
		if n > 0 || c.ctx.Err() != nil || len(c.remaining) == 0 {
			c.pending = false
			return n, err
		}
		conn, candidate, remaining, attempt, dialErr := c.fallback.dialCandidates(c.ctx, c.network, c.destination, c.remaining)
		if dialErr != nil {
			c.pending = false
			return 0, dialErr
		}
		c.Conn = conn
		c.candidate = candidate
		c.remaining = remaining
		c.attempt = attempt
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
