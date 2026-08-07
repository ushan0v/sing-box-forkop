package rule

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	convertor "github.com/sagernet/sing-box/common/convertor/ruleset"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"go4.org/netipx"
)

var _ adapter.RuleSet = (*RemoteRuleSet)(nil)

const ruleSetFetchTimeout = 4 * C.TCPTimeout

type remoteRuleSetUnavailableError struct {
	err error
}

func (e *remoteRuleSetUnavailableError) Error() string { return e.err.Error() }
func (e *remoteRuleSetUnavailableError) Unwrap() error { return e.err }

func remoteRuleSetUnavailable(err error) error {
	return &remoteRuleSetUnavailableError{err: err}
}

func isRemoteRuleSetUnavailable(err error) bool {
	var unavailable *remoteRuleSetUnavailableError
	return errors.As(err, &unavailable)
}

type RemoteRuleSet struct {
	ctx            context.Context
	cancel         context.CancelFunc
	logger         logger.ContextLogger
	outbound       adapter.OutboundManager
	options        option.RuleSet
	updateInterval time.Duration
	dialer         N.Dialer
	updateAccess   sync.Mutex
	access         sync.RWMutex
	rules          []adapter.HeadlessRule
	metadata       adapter.RuleSetMetadata
	ipCIDRExport   adapter.RuleSetIPCIDRExport
	revision       uint64
	lastUpdated    time.Time
	lastEtag       string
	updateTicker   *time.Ticker
	cacheFile      adapter.CacheFile
	pauseManager   pause.Manager
	callbacks      list.List[adapter.RuleSetUpdateCallback]
	refs           atomic.Int32
}

func NewRemoteRuleSet(ctx context.Context, logger logger.ContextLogger, options option.RuleSet) *RemoteRuleSet {
	ctx, cancel := context.WithCancel(ctx)
	var updateInterval time.Duration
	if options.RemoteOptions.UpdateInterval > 0 {
		updateInterval = time.Duration(options.RemoteOptions.UpdateInterval)
	} else {
		updateInterval = 24 * time.Hour
	}
	return &RemoteRuleSet{
		ctx:            ctx,
		cancel:         cancel,
		outbound:       service.FromContext[adapter.OutboundManager](ctx),
		logger:         logger,
		options:        options,
		updateInterval: updateInterval,
		pauseManager:   service.FromContext[pause.Manager](ctx),
	}
}

func (s *RemoteRuleSet) Name() string {
	return s.options.Tag
}

func (s *RemoteRuleSet) String() string {
	return strings.Join(F.MapToString(s.rules), " ")
}

func (s *RemoteRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	s.dialer = s.resolveDialer()
	if s.dialer == nil && s.options.RemoteOptions.DownloadDetour != "" {
		s.logger.Error("download detour not found for rule-set ", s.options.Tag, ": ", s.options.RemoteOptions.DownloadDetour)
	}
	if s.cacheFile != nil {
		if savedSet := s.cacheFile.LoadRuleSet(s.options.Tag); savedSet != nil {
			err := s.loadBytes(savedSet.Content, savedSet.LastUpdated, savedSet.LastEtag)
			if err != nil {
				s.logger.Warn(E.Cause(err, "restore cached rule-set, will refetch"))
			}
		}
	}
	if s.ProviderSnapshot().UpdatedAt.IsZero() {
		err := s.fetch(ctx, startContext)
		if err != nil {
			if !isRemoteRuleSetUnavailable(err) {
				return E.Cause(err, "initial rule-set: ", s.options.Tag)
			}
			s.logger.Error(E.Cause(err, "initial rule-set ", s.options.Tag))
		}
	}
	s.updateTicker = time.NewTicker(s.updateInterval)
	return nil
}

func (s *RemoteRuleSet) resolveDialer() N.Dialer {
	if s.outbound == nil {
		return nil
	}
	if detour := s.options.RemoteOptions.DownloadDetour; detour != "" {
		outbound, loaded := s.outbound.Outbound(detour)
		if !loaded {
			return nil
		}
		return outbound
	}
	return s.outbound.Default()
}

func (s *RemoteRuleSet) PostStart() error {
	go s.loopUpdate()
	return nil
}

func (s *RemoteRuleSet) Metadata() adapter.RuleSetMetadata {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.metadata
}

func (s *RemoteRuleSet) ProviderSnapshot() adapter.RuleSetProviderSnapshot {
	s.access.RLock()
	defer s.access.RUnlock()
	return adapter.RuleSetProviderSnapshot{
		Type:      s.options.Type,
		Format:    s.options.Format,
		UpdatedAt: s.lastUpdated,
		Revision:  s.revision,
		IPCIDR:    s.ipCIDRExport,
	}
}

func (s *RemoteRuleSet) Update() error {
	return s.fetch(s.ctx, nil)
}

func (s *RemoteRuleSet) ExtractIPSet() []*netipx.IPSet {
	s.access.RLock()
	defer s.access.RUnlock()
	return common.FlatMap(s.rules, extractIPSetFromRule)
}

func (s *RemoteRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *RemoteRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *RemoteRuleSet) Cleanup() {
	if s.refs.Load() == 0 {
		s.rules = nil
	}
}

func (s *RemoteRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *RemoteRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *RemoteRuleSet) loadBytes(content []byte, updatedAt time.Time, lastEtag string) error {
	plainRuleSet, _, err := convertor.Read(bytes.NewReader(content), s.options.Format)
	if err != nil {
		return err
	}
	rules := make([]adapter.HeadlessRule, len(plainRuleSet.Rules))
	for i, ruleOptions := range plainRuleSet.Rules {
		rules[i], err = NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
	}
	metadata := adapter.RuleSetMetadata{
		ContainsProcessRule: HasHeadlessRule(plainRuleSet.Rules, isProcessHeadlessRule),
		ContainsWIFIRule:    HasHeadlessRule(plainRuleSet.Rules, isWIFIHeadlessRule),
		ContainsIPCIDRRule:  HasHeadlessRule(plainRuleSet.Rules, isIPCIDRHeadlessRule),
	}
	ipCIDRExport := buildRuleSetIPCIDRExportIfPresent(plainRuleSet.Rules, metadata.ContainsIPCIDRRule)
	s.access.Lock()
	s.metadata = metadata
	s.ipCIDRExport = ipCIDRExport
	s.rules = rules
	s.lastUpdated = updatedAt
	s.lastEtag = lastEtag
	s.revision++
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(s)
	}
	return nil
}

func (s *RemoteRuleSet) loopUpdate() {
	if time.Since(s.ProviderSnapshot().UpdatedAt) > s.updateInterval {
		err := s.fetch(s.ctx, nil)
		if err != nil {
			s.logger.Error("fetch rule-set ", s.options.Tag, ": ", err)
		} else if s.refs.Load() == 0 {
			s.rules = nil
		}
	}
	for {
		runtime.GC()
		select {
		case <-s.ctx.Done():
			return
		case <-s.updateTicker.C:
			s.updateOnce()
		}
	}
}

func (s *RemoteRuleSet) updateOnce() {
	err := s.fetch(s.ctx, nil)
	if err != nil {
		s.logger.Error("fetch rule-set ", s.options.Tag, ": ", err)
	} else if s.refs.Load() == 0 {
		s.rules = nil
	}
}

func (s *RemoteRuleSet) fetch(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.updateAccess.Lock()
	defer s.updateAccess.Unlock()
	if s.dialer == nil {
		s.dialer = s.resolveDialer()
	}
	if s.dialer == nil {
		if detour := s.options.RemoteOptions.DownloadDetour; detour != "" {
			return remoteRuleSetUnavailable(E.New("download detour unavailable: ", detour))
		}
		return remoteRuleSetUnavailable(E.New("default outbound unavailable"))
	}
	ctx, cancel := context.WithTimeout(ctx, ruleSetFetchTimeout)
	defer cancel()
	s.logger.Debug("updating rule-set ", s.options.Tag, " from URL: ", s.options.RemoteOptions.URL)
	var httpClient *http.Client
	if startContext != nil {
		httpClient = startContext.HTTPClient(s.options.RemoteOptions.DownloadDetour, s.dialer)
	} else {
		httpClient = &http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				TLSHandshakeTimeout: C.TCPTimeout,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return s.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
				},
				TLSClientConfig: &tls.Config{
					Time:    ntp.TimeFuncFromContext(s.ctx),
					RootCAs: adapter.RootPoolFromContext(s.ctx),
				},
			},
		}
	}
	request, err := http.NewRequest("GET", s.options.RemoteOptions.URL, nil)
	if err != nil {
		return err
	}
	s.access.RLock()
	lastEtag := s.lastEtag
	s.access.RUnlock()
	if lastEtag != "" {
		request.Header.Set("If-None-Match", lastEtag)
	}
	response, err := httpClient.Do(request.WithContext(ctx))
	if err != nil {
		return remoteRuleSetUnavailable(err)
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.access.Lock()
		s.lastUpdated = time.Now()
		lastUpdated := s.lastUpdated
		s.access.Unlock()
		if s.cacheFile != nil {
			savedRuleSet := s.cacheFile.LoadRuleSet(s.options.Tag)
			if savedRuleSet != nil {
				savedRuleSet.LastUpdated = lastUpdated
				err = s.cacheFile.SaveRuleSet(s.options.Tag, savedRuleSet)
				if err != nil {
					s.logger.Error("save rule-set updated time: ", err)
					return nil
				}
			}
		}
		s.logger.Notice("update rule-set ", s.options.Tag, ": not modified")
		return nil
	default:
		return remoteRuleSetUnavailable(E.New("unexpected status: ", response.Status))
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return remoteRuleSetUnavailable(err)
	}
	eTagHeader := response.Header.Get("Etag")
	if eTagHeader == "" {
		eTagHeader = lastEtag
	}
	lastUpdated := time.Now()
	err = s.loadBytes(content, lastUpdated, eTagHeader)
	if err != nil {
		return err
	}
	if s.cacheFile != nil {
		err = s.cacheFile.SaveRuleSet(s.options.Tag, &adapter.SavedBinary{
			LastUpdated: lastUpdated,
			Content:     content,
			LastEtag:    eTagHeader,
		})
		if err != nil {
			s.logger.Error("save rule-set cache: ", err)
		}
	}
	s.logger.Notice("updated rule-set ", s.options.Tag)
	return nil
}

func (s *RemoteRuleSet) Close() error {
	s.rules = nil
	s.cancel()
	if s.updateTicker != nil {
		s.updateTicker.Stop()
	}
	return nil
}

func (s *RemoteRuleSet) Match(metadata *adapter.InboundContext) bool {
	return !s.matchStates(metadata).isEmpty()
}

func (s *RemoteRuleSet) matchStates(metadata *adapter.InboundContext) ruleMatchStateSet {
	return s.matchStatesWithBase(metadata, 0)
}

func (s *RemoteRuleSet) matchStatesWithBase(metadata *adapter.InboundContext, base ruleMatchState) ruleMatchStateSet {
	var stateSet ruleMatchStateSet
	for _, rule := range s.rules {
		nestedMetadata := *metadata
		nestedMetadata.ResetRuleMatchCache()
		stateSet = stateSet.merge(matchHeadlessRuleStatesWithBase(rule, &nestedMetadata, base))
	}
	return stateSet
}
