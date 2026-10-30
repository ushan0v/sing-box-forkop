package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser"
	"github.com/sagernet/sing-box/parser/subscription"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
)

func RegisterProvider(registry *provider.Registry) {
	provider.Register[option.ProviderRemoteOptions](registry, C.ProviderTypeRemote, NewProviderRemote)
}

var _ adapter.Provider = (*ProviderRemote)(nil)

const providerFetchTimeout = 4 * C.TCPTimeout

type ProviderRemote struct {
	provider.Adapter
	ctx              context.Context
	cancel           context.CancelFunc
	logger           log.ContextLogger
	outbound         adapter.OutboundManager
	provider         adapter.ProviderManager
	cacheFile        adapter.CacheFile
	dialer           N.Dialer
	access           sync.RWMutex
	lastEtag         string
	retryInterval    time.Duration
	rawContent       string
	lastUpdated      time.Time
	subscriptionInfo adapter.SubscriptionInfo
	subscriptionMeta adapter.SubscriptionMetadata
	ticker           *time.Ticker
	updateAccess     sync.Mutex

	url            string
	userAgent      string
	downloadDetour string
	updateInterval time.Duration
	exclude        *regexp.Regexp
	include        *regexp.Regexp
	headers        http.Header
}

func NewProviderRemote(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderRemoteOptions) (adapter.Provider, error) {
	if options.URL == "" {
		return nil, E.New("provider URL is required")
	}
	// A missing update_interval disables scheduled updates: the provider is fetched until it first has
	// content, and when updated through the Clash API.
	updateInterval := time.Duration(options.UpdateInterval)
	if updateInterval < 0 {
		updateInterval = 0
	}
	if updateInterval > 0 && updateInterval < time.Minute {
		updateInterval = time.Minute
	}
	var userAgent string
	if options.UserAgent == "" {
		userAgent = "sing-box " + C.Version
	} else {
		userAgent = options.UserAgent
	}
	ctx, cancel := context.WithCancel(ctx)
	outbound := service.FromContext[adapter.OutboundManager](ctx)
	logger := logFactory.NewLogger(F.ToString("provider/remote", "[", tag, "]"))
	updateChan := make(chan struct{})
	close(updateChan)
	p := &ProviderRemote{
		Adapter:  provider.NewAdapter(ctx, router, outbound, logFactory, logger, tag, C.ProviderTypeRemote, options.HealthCheck),
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		outbound: outbound,
		provider: service.FromContext[adapter.ProviderManager](ctx),

		url:            options.URL,
		userAgent:      userAgent,
		downloadDetour: options.DownloadDetour,
		headers:        options.Headers.Build(),
		updateInterval: updateInterval,
		exclude:        (*regexp.Regexp)(options.Exclude),
		include:        (*regexp.Regexp)(options.Include),
	}
	p.SetRemoveEmojis(options.RemoveEmojis)
	p.SetOverrideDialerOptions(options.OverrideDialerOptions)
	p.SetExcludeTypes(options.ExcludeTypes)
	if err := p.SetOverride(options.Override); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *ProviderRemote) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(s.Close)
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	if s.cacheFile != nil && s.cacheFile.StoreSubscriptions() {
		if saveSub := s.cacheFile.LoadSubscription(s.Tag()); saveSub != nil {
			s.restoreProviderCache(saveSub)
		}
	}
	if s.downloadDetour != "" {
		outbound, loaded := s.outbound.Outbound(s.downloadDetour)
		if !loaded {
			return E.New("detour outbound not found: ", s.downloadDetour)
		}
		s.dialer = outbound
	} else {
		s.dialer = s.outbound.Default()
	}

	lastUpdated := s.UpdatedAt()
	if s.updateInterval <= 0 && !lastUpdated.IsZero() {
		return s.Adapter.Start()
	}
	firstUpdate := time.Until(lastUpdated.Add(s.updateInterval))
	if lastUpdated.IsZero() || firstUpdate <= 0 {
		firstUpdate = time.Nanosecond
	}
	s.ticker = time.NewTicker(firstUpdate)
	go s.loopUpdate()
	return s.Adapter.Start()
}

func (s *ProviderRemote) References() []string {
	if s.downloadDetour != "" {
		return []string{s.downloadDetour}
	}
	defaultOutbound := s.outbound.Default()
	if defaultOutbound == nil {
		return nil
	}
	return []string{defaultOutbound.Tag()}
}

// Update logs a failure for the schedule and the Clash API alike, since only the log names the
// provider.
func (s *ProviderRemote) Update() error {
	// a group that switches members closes the connections it did not route; this one stays
	err := s.fetch(interrupt.ContextWithIsExternalConnection(s.ctx, true))
	if err != nil {
		s.logger.Error("update outbound provider: ", err)
	}
	s.resetUpdateTicker(s.nextUpdateInterval(err))
	return err
}

func (s *ProviderRemote) etag() string {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.lastEtag
}

func (s *ProviderRemote) UpdatedAt() time.Time {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.lastUpdated
}

func (s *ProviderRemote) SubscriptionInfo() adapter.SubscriptionInfo {
	info, _ := s.subscriptionData()
	return info
}

func (s *ProviderRemote) SubscriptionMetadata() adapter.SubscriptionMetadata {
	_, metadata := s.subscriptionData()
	return metadata
}

func (s *ProviderRemote) Close() error {
	s.cancel()
	s.access.Lock()
	if s.ticker != nil {
		s.ticker.Stop()
	}
	s.access.Unlock()
	s.updateAccess.Lock()
	err := common.Close(&s.Adapter)
	s.updateAccess.Unlock()
	return err
}

const (
	providerRetryFloor = time.Minute
	// The backoff limit of a provider without update_interval, which still
	// retries until it has content.
	providerRetryCeiling = time.Hour
)

// nextUpdateInterval reports when to fetch the provider again and remembers the
// retry it settled on, so consecutive failures back off.
func (s *ProviderRemote) nextUpdateInterval(updateErr error) time.Duration {
	s.access.Lock()
	defer s.access.Unlock()
	if updateErr == nil {
		s.retryInterval = 0
		return s.updateInterval
	}
	s.retryInterval = nextProviderRetryInterval(s.retryInterval, s.updateInterval)
	return s.retryInterval
}

// nextProviderRetryInterval doubles the wait after each consecutive failure
// until it reaches the interval the provider was configured with.
func nextProviderRetryInterval(previous, updateInterval time.Duration) time.Duration {
	ceiling := updateInterval
	if ceiling <= 0 {
		ceiling = providerRetryCeiling
	}
	next := 2 * previous
	if next < providerRetryFloor {
		next = providerRetryFloor
	}
	if next > ceiling {
		next = ceiling
	}
	return next
}

func (s *ProviderRemote) resetUpdateTicker(updateInterval time.Duration) {
	s.access.Lock()
	defer s.access.Unlock()
	select {
	case <-s.ctx.Done():
		return
	default:
	}
	if s.ticker == nil {
		return
	}
	if updateInterval <= 0 {
		s.ticker.Stop()
		return
	}
	s.ticker.Reset(updateInterval)
}

func (s *ProviderRemote) fetch(ctx context.Context) error {
	s.updateAccess.Lock()
	defer s.updateAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, providerFetchTimeout)
	defer cancel()
	s.logger.Debug("updating outbound provider ", s.Tag(), " from URL: ", s.url)
	transport := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: C.TCPTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
		},
		TLSClientConfig: &tls.Config{
			Time:    ntp.TimeFuncFromContext(ctx),
			RootCAs: adapter.RootPoolFromContext(ctx),
		},
	}
	client := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()
	result, err := s.fetchProvider(ctx, client)
	if err != nil {
		s.applyFailedFetch(result)
		return err
	}
	if result.notModified {
		s.applyNotModified(result)
		return nil
	}
	s.applyFetchedProvider(result)
	return nil
}

type providerFetchResult struct {
	info           adapter.SubscriptionInfo
	metadata       adapter.SubscriptionMetadata
	metadataValues map[string]string
	etag           string
	notModified    bool
}

func (s *ProviderRemote) fetchProvider(ctx context.Context, client *http.Client) (providerFetchResult, error) {
	var result providerFetchResult
	req, err := http.NewRequest(http.MethodGet, s.url, nil)
	if err != nil {
		return result, err
	}
	lastEtag := s.etag()
	if lastEtag != "" {
		req.Header.Set("If-None-Match", lastEtag)
	}
	req.Header.Set("User-Agent", s.userAgent)
	for name, values := range s.headers {
		req.Header[name] = values
	}
	response, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	result.metadataValues = metadataHeaderValues(response.Header)
	result.etag = response.Header.Get("Etag")
	if response.StatusCode == http.StatusNotModified {
		result.notModified = true
		return result, nil
	}
	if response.StatusCode != http.StatusOK {
		return result, E.New("unexpected status: ", response.Status)
	}
	if reason := deviceRefusal(response.Header); reason != "" {
		return result, E.New("the provider refused this device: ", reason)
	}
	contentRaw, err := io.ReadAll(response.Body)
	if err != nil {
		return result, err
	}
	content, info, metadata := prepareSubscriptionContent(string(contentRaw), result.metadataValues)
	result.info, result.metadata = info, metadata
	if err := s.updateProviderFromContent(content); err != nil {
		return result, err
	}
	return result, nil
}

// applyFailedFetch keeps the metadata headers of a response whose body could not be used, such as
// an expired subscription; the servers stay, and the etag is dropped so a 304 cannot hide the
// failure.
func (s *ProviderRemote) applyFailedFetch(result providerFetchResult) {
	if len(result.metadataValues) == 0 {
		return
	}
	info, metadata := s.subscriptionData()
	info, metadata = mergeSubscriptionData(info, metadata, result.metadataValues)
	s.setSubscriptionData(info, metadata)
	s.saveProviderCache()
}

func (s *ProviderRemote) applyNotModified(result providerFetchResult) {
	info, metadata := s.subscriptionData()
	info, metadata = mergeSubscriptionData(info, metadata, result.metadataValues)
	s.setSubscriptionData(info, metadata)
	s.access.Lock()
	if result.etag != "" {
		s.lastEtag = result.etag
	}
	s.lastUpdated = time.Now()
	s.access.Unlock()
	s.saveProviderCache()
	s.logger.Info("update outbound provider ", s.Tag(), ": not modified")
}

func (s *ProviderRemote) applyFetchedProvider(result providerFetchResult) {
	s.access.Lock()
	s.lastEtag = result.etag
	s.lastUpdated = time.Now()
	s.access.Unlock()
	s.setSubscriptionData(result.info, result.metadata)
	s.saveProviderCache()
	s.logger.Info("updated outbound provider ", s.Tag())
}

func (s *ProviderRemote) saveProviderCache() {
	if s.cacheFile == nil || !s.cacheFile.StoreSubscriptions() {
		return
	}
	s.access.RLock()
	saved := adapter.SavedBinary{
		LastUpdated: s.lastUpdated,
		Content:     append([]byte(encodeProviderCacheMetadata(s.subscriptionInfo, s.subscriptionMeta)+"\n"), s.rawContent...),
		LastEtag:    s.lastEtag,
		URLHash:     providerCacheIdentity(s.url, s.userAgent, s.headers),
	}
	s.access.RUnlock()
	if err := s.cacheFile.SaveSubscription(s.Tag(), &saved); err != nil {
		s.logger.Error("save outbound provider cache file: ", err)
	}
}

func (s *ProviderRemote) restoreProviderCache(saved *adapter.SavedBinary) {
	if !bytes.Equal(saved.URLHash, providerCacheIdentity(s.url, s.userAgent, s.headers)) {
		s.logger.Info("cached outbound provider was fetched from another source, will refetch")
		return
	}
	content, info, metadata, loaded := decodeProviderCacheContent(string(saved.Content))
	if !loaded {
		return
	}
	s.setSubscriptionData(info, metadata)
	if err := s.updateProviderFromContent(content); err != nil {
		s.logger.Warn(E.Cause(err, "restore cached outbound provider"))
		return
	}
	s.access.Lock()
	s.lastUpdated, s.lastEtag = saved.LastUpdated, saved.LastEtag
	s.access.Unlock()
}

func (s *ProviderRemote) subscriptionData() (adapter.SubscriptionInfo, adapter.SubscriptionMetadata) {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.subscriptionInfo, s.subscriptionMeta
}

func (s *ProviderRemote) setSubscriptionData(info adapter.SubscriptionInfo, metadata adapter.SubscriptionMetadata) {
	s.access.Lock()
	s.subscriptionInfo = info
	s.subscriptionMeta = metadata
	s.access.Unlock()
}

func (s *ProviderRemote) loopUpdate() {
	for {
		runtime.GC()
		select {
		case <-s.ctx.Done():
			return
		case <-s.ticker.C:
			_ = s.Update()
		}
	}
}

func (s *ProviderRemote) updateProviderFromContent(content string) error {
	parsed, err := parser.ParseSubscription(s.ctx, content)
	subscription.ReportSkipped(s.logger, s.Tag(), parsed)
	if err != nil {
		return err
	}
	outboundOpts, err := s.FilterOutbounds(parsed.Outbounds, s.exclude, s.include)
	if err != nil {
		return err
	}
	err = s.UpdateOutbounds(outboundOpts)
	if err != nil {
		return err
	}
	s.access.Lock()
	s.rawContent = content
	s.access.Unlock()
	return nil
}

func getFirstLine(content string) (string, string) {
	lines := strings.Split(content, "\n")
	if len(lines) == 1 {
		return lines[0], ""
	}
	others := strings.Join(lines[1:], "\n")
	return lines[0], others
}
