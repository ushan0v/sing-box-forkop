package provider

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
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
	lastEtag         string
	lastOutOpts      []option.Outbound
	lastUpdated      time.Time
	subscriptionInfo adapter.SubscriptionInfo
	subscriptionMeta adapter.SubscriptionMetadata
	subscriptionLock sync.RWMutex
	ticker           *time.Ticker
	tickerAccess     sync.Mutex
	updating         atomic.Bool

	url            string
	userAgents     []string
	lastUserAgent  string
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
	updateInterval := time.Duration(options.UpdateInterval)
	if updateInterval <= 0 {
		updateInterval = 24 * time.Hour
	}
	if updateInterval < time.Minute {
		updateInterval = time.Minute
	}
	userAgents := normalizeUserAgents(options.UserAgent)
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
		userAgents:     userAgents,
		downloadDetour: options.DownloadDetour,
		headers:        options.Headers.Build(),
		updateInterval: updateInterval,
		exclude:        (*regexp.Regexp)(options.Exclude),
		include:        (*regexp.Regexp)(options.Include),
	}
	p.SetRemoveEmojis(options.RemoveEmojis)
	p.SetTagPrefix(options.TagPrefix)
	p.SetOutboundDetour(options.OutboundDetour)
	return p, nil
}

func normalizeUserAgents(configured []string) []string {
	var result []string
	seen := make(map[string]bool)
	for _, userAgent := range configured {
		userAgent = strings.TrimSpace(userAgent)
		if userAgent == "" || seen[userAgent] {
			continue
		}
		seen[userAgent] = true
		result = append(result, userAgent)
	}
	if len(result) == 0 {
		result = append(result, "sing-box "+C.Version)
	}
	return result
}

func preferredUserAgents(userAgents []string, preferred string) []string {
	if preferred == "" || len(userAgents) < 2 || userAgents[0] == preferred {
		return userAgents
	}
	result := make([]string, 0, len(userAgents))
	for _, userAgent := range userAgents {
		if userAgent == preferred {
			result = append(result, userAgent)
			break
		}
	}
	for _, userAgent := range userAgents {
		if userAgent != preferred {
			result = append(result, userAgent)
		}
	}
	return result
}

func (s *ProviderRemote) Start() error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	if s.cacheFile != nil {
		if saveSub := s.cacheFile.LoadSubscription(s.Tag()); saveSub != nil {
			content, info, metadata := decodeProviderCacheContent(string(saveSub.Content))
			s.setSubscriptionData(info, metadata)
			if err := s.updateProviderFromContent(content); err != nil {
				return E.Cause(err, "restore cached outbound provider")
			}
			s.lastUpdated, s.lastEtag = saveSub.LastUpdated, saveSub.LastEtag
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

	firstUpdate := time.Until(s.lastUpdated.Add(s.updateInterval))
	if s.lastUpdated.IsZero() || firstUpdate <= 0 {
		firstUpdate = time.Nanosecond
	}
	s.ticker = time.NewTicker(firstUpdate)
	go s.loopUpdate()
	return s.Adapter.Start()
}

func (s *ProviderRemote) Update() error {
	ctx := interrupt.ContextWithIsProviderConnection(s.ctx)
	err := s.fetch(ctx)
	s.resetUpdateTicker(nextProviderUpdateInterval(s.updateInterval, err))
	return err
}

func (s *ProviderRemote) UpdatedAt() time.Time {
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
	s.tickerAccess.Lock()
	if s.ticker != nil {
		s.ticker.Stop()
	}
	s.tickerAccess.Unlock()
	return common.Close(&s.Adapter)
}

func (s *ProviderRemote) updateOnce() {
	ctx := interrupt.ContextWithIsProviderConnection(s.ctx)
	err := s.fetch(ctx)
	if err != nil {
		s.logger.Error("update outbound provider: ", err)
	}
	s.resetUpdateTicker(nextProviderUpdateInterval(s.updateInterval, err))
}

func nextProviderUpdateInterval(updateInterval time.Duration, updateErr error) time.Duration {
	if updateErr == nil || updateInterval <= time.Minute {
		return updateInterval
	}
	return time.Minute
}

func (s *ProviderRemote) resetUpdateTicker(updateInterval time.Duration) {
	s.tickerAccess.Lock()
	defer s.tickerAccess.Unlock()
	select {
	case <-s.ctx.Done():
		return
	default:
	}
	if s.ticker != nil {
		s.ticker.Reset(updateInterval)
	}
}

func (s *ProviderRemote) fetch(ctx context.Context) error {
	if s.updating.Swap(true) {
		return E.New("provider is updating")
	}
	defer s.updating.Store(false)
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
	var fetchErr error
	for index, userAgent := range preferredUserAgents(s.userAgents, s.lastUserAgent) {
		result, err := s.fetchWithUserAgent(ctx, client, userAgent, index == 0)
		if err != nil {
			fetchErr = E.Errors(fetchErr, E.Cause(err, "user-agent ", userAgent))
			continue
		}
		s.lastUserAgent = userAgent
		if result.notModified {
			s.applyNotModified(result)
			return nil
		}
		s.applyFetchedProvider(result)
		return nil
	}
	return E.Cause(fetchErr, "all user-agent candidates failed")
}

type providerFetchResult struct {
	info           adapter.SubscriptionInfo
	metadata       adapter.SubscriptionMetadata
	metadataValues map[string]string
	etag           string
	notModified    bool
}

func (s *ProviderRemote) fetchWithUserAgent(ctx context.Context, client *http.Client, userAgent string, useETag bool) (providerFetchResult, error) {
	var result providerFetchResult
	req, err := http.NewRequest(http.MethodGet, s.url, nil)
	if err != nil {
		return result, err
	}
	if useETag && s.lastEtag != "" {
		req.Header.Set("If-None-Match", s.lastEtag)
	}
	req.Header.Set("User-Agent", userAgent)
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
	contentRaw, err := io.ReadAll(response.Body)
	if err != nil {
		return result, err
	}
	content, info, metadata := prepareSubscriptionContent(string(contentRaw), result.metadataValues)
	contentRaw = nil
	result.info, result.metadata = info, metadata
	if err := s.updateProviderFromContent(content); err != nil {
		return result, err
	}
	return result, nil
}

func (s *ProviderRemote) applyNotModified(result providerFetchResult) {
	info, metadata := s.subscriptionData()
	info, metadata = mergeSubscriptionData(info, metadata, result.metadataValues)
	s.setSubscriptionData(info, metadata)
	if result.etag != "" {
		s.lastEtag = result.etag
	}
	s.lastUpdated = time.Now()
	s.saveProviderCache()
	s.logger.Notice("update outbound provider ", s.Tag(), ": not modified")
}

func (s *ProviderRemote) applyFetchedProvider(result providerFetchResult) {
	if result.etag != "" {
		s.lastEtag = result.etag
	}
	s.setSubscriptionData(result.info, result.metadata)
	s.lastUpdated = time.Now()
	s.saveProviderCache()
	s.logger.Notice("updated outbound provider ", s.Tag())
}

func (s *ProviderRemote) saveProviderCache() {
	if s.cacheFile == nil {
		return
	}
	content, err := json.Marshal(option.Options{Outbounds: s.lastOutOpts})
	if err != nil {
		s.logger.Error("encode outbound provider cache: ", err)
		return
	}
	info, metadata := s.subscriptionData()
	content = append([]byte(encodeProviderCacheMetadata(info, metadata)+"\n"), content...)
	if err = s.cacheFile.SaveSubscription(s.Tag(), &adapter.SavedBinary{
		LastUpdated: s.lastUpdated,
		Content:     content,
		LastEtag:    s.lastEtag,
	}); err != nil {
		s.logger.Error("save outbound provider cache file: ", err)
	}
}

func (s *ProviderRemote) subscriptionData() (adapter.SubscriptionInfo, adapter.SubscriptionMetadata) {
	s.subscriptionLock.RLock()
	defer s.subscriptionLock.RUnlock()
	return s.subscriptionInfo, s.subscriptionMeta
}

func (s *ProviderRemote) setSubscriptionData(info adapter.SubscriptionInfo, metadata adapter.SubscriptionMetadata) {
	s.subscriptionLock.Lock()
	s.subscriptionInfo = info
	s.subscriptionMeta = metadata
	s.subscriptionLock.Unlock()
}

func (s *ProviderRemote) loopUpdate() {
	for {
		runtime.GC()
		select {
		case <-s.ctx.Done():
			return
		case <-s.ticker.C:
			s.updateOnce()
		}
	}
}

func (s *ProviderRemote) updateProviderFromContent(content string) error {
	outboundOpts, err := parser.ParseSubscription(s.ctx, content)
	if err != nil {
		return err
	}
	outboundOpts = common.Filter(outboundOpts, func(outbound option.Outbound) bool {
		return (s.exclude == nil || !s.exclude.MatchString(outbound.Tag)) &&
			(s.include == nil || s.include.MatchString(outbound.Tag))
	})
	if err := s.UpdateOutbounds(s.lastOutOpts, outboundOpts); err != nil {
		return err
	}
	s.lastOutOpts = outboundOpts
	return nil
}

func getFirstLine(content string) (string, string) {
	firstLine, others, _ := strings.Cut(content, "\n")
	return firstLine, others
}
