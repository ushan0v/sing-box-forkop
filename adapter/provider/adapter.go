package provider

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	linkParser "github.com/sagernet/sing-box/parser/link"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

type Adapter struct {
	ctx            context.Context
	outbound       adapter.OutboundManager
	router         adapter.Router
	logFactory     log.Factory
	logger         log.ContextLogger
	providerType   string
	providerTag    string
	outbounds      []adapter.Outbound
	outboundsByTag map[string]adapter.Outbound
	outboundLinks  []string
	outboundOpts   []option.Outbound
	access         sync.RWMutex
	ticker         *time.Ticker
	checking       atomic.Bool
	history        adapter.URLTestHistoryStorage
	callbackAccess sync.Mutex
	callbacks      list.List[adapter.ProviderUpdateCallback]

	link           string
	enabled        bool
	removeEmojis   bool
	tagPrefix      string
	outboundDetour string
	timeout        time.Duration
	interval       time.Duration
}

func NewAdapter(ctx context.Context, router adapter.Router, outbound adapter.OutboundManager, logFactory log.Factory, logger log.ContextLogger, providerTag string, providerType string, options option.ProviderHealthCheckOptions) Adapter {
	timeout := time.Duration(options.Timeout)
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	interval := time.Duration(options.Interval)
	if interval == 0 {
		interval = 10 * time.Minute
	}
	if interval < time.Minute {
		interval = time.Minute
	}
	return Adapter{
		ctx:          ctx,
		outbound:     outbound,
		router:       router,
		logFactory:   logFactory,
		logger:       logger,
		providerType: providerType,
		providerTag:  providerTag,

		enabled:  options.Enabled,
		link:     options.URL,
		timeout:  timeout,
		interval: interval,
	}
}

func (a *Adapter) SetRemoveEmojis(remove bool) {
	a.removeEmojis = remove
}

func (a *Adapter) SetTagPrefix(prefix string) {
	a.tagPrefix = prefix
}

func (a *Adapter) SetOutboundDetour(detour string) {
	a.outboundDetour = detour
}

func (a *Adapter) Start() error {
	a.history = service.FromContext[adapter.URLTestHistoryStorage](a.ctx)
	if a.history == nil {
		if clashServer := service.FromContext[adapter.ClashServer](a.ctx); clashServer != nil {
			a.history = clashServer.HistoryStorage()
		} else {
			a.history = urltest.NewHistoryStorage()
		}
	}
	go a.loopCheck()
	return nil
}

func (a *Adapter) Type() string {
	return a.providerType
}

func (a *Adapter) Tag() string {
	return a.providerTag
}

func (a *Adapter) Outbounds() []adapter.Outbound {
	a.access.RLock()
	defer a.access.RUnlock()
	return append([]adapter.Outbound(nil), a.outbounds...)
}

func (a *Adapter) Outbound(tag string) (adapter.Outbound, bool) {
	a.access.RLock()
	defer a.access.RUnlock()
	if a.outboundsByTag == nil {
		return nil, false
	}
	detour, ok := a.outboundsByTag[tag]
	return detour, ok
}

func (a *Adapter) OutboundLink(tag string) (string, bool) {
	a.access.RLock()
	defer a.access.RUnlock()
	for index, outbound := range a.outbounds {
		if outbound.Tag() == tag && index < len(a.outboundLinks) && a.outboundLinks[index] != "" {
			return a.outboundLinks[index], true
		}
	}
	return "", false
}

func (a *Adapter) UpdateOutbounds(newOpts []option.Outbound) ([]option.Outbound, error) {
	sourceOpts := FilterInvalidOutbounds(newOpts, nil)
	if len(newOpts) > 0 && len(sourceOpts) == 0 {
		return nil, E.New("no usable provider outbounds")
	}
	a.access.RLock()
	oldOpts := cloneOutbounds(a.outboundOpts)
	a.access.RUnlock()
	newOpts = cloneOutbounds(sourceOpts)
	normalizeOutboundTags(newOpts, a.removeEmojis, a.tagPrefix)
	oldOutbounds, err := prepareOutbounds(a.providerTag, oldOpts, a.outboundDetour)
	if err != nil {
		return nil, err
	}
	newOutbounds, err := prepareOutbounds(a.providerTag, newOpts, a.outboundDetour)
	if err != nil {
		return nil, err
	}
	oldRuntimeOutbounds, appliedOutbounds, err := a.replaceOutbounds(oldOutbounds, newOutbounds)
	if err != nil {
		restoreErr := a.publishOutbounds(oldOutbounds)
		a.UpdateGroups()
		return nil, E.Errors(err, restoreErr)
	}
	if err = a.publishOutbounds(appliedOutbounds); err != nil {
		return nil, err
	}
	a.UpdateGroups()
	for _, oldOutbound := range oldRuntimeOutbounds {
		if err := common.Close(oldOutbound); err != nil {
			a.logger.Error("close replaced provider outbound [", oldOutbound.Tag(), "]: ", err)
		}
	}
	if a.enabled && a.history != nil {
		go a.HealthCheck(a.ctx)
	}
	appliedOpts := make([]option.Outbound, 0, len(appliedOutbounds))
	for _, outbound := range sourceOrder(appliedOutbounds) {
		appliedOpts = append(appliedOpts, sourceOpts[outbound.position])
	}
	return appliedOpts, nil
}

func (a *Adapter) NormalizeOutboundsForFilter(opts []option.Outbound) []option.Outbound {
	opts = cloneOutbounds(FilterInvalidOutbounds(opts, nil))
	normalizeOutboundTags(opts, a.removeEmojis, "")
	return opts
}

func (a *Adapter) publishOutbounds(preparedOutbounds []preparedOutbound) error {
	var (
		outbounds      = make([]adapter.Outbound, 0, len(preparedOutbounds))
		outboundsByTag = make(map[string]adapter.Outbound)
		outboundLinks  = make([]string, 0, len(preparedOutbounds))
	)
	for _, prepared := range sourceOrder(preparedOutbounds) {
		outbound, loaded := a.outbound.Outbound(prepared.tag)
		if !loaded {
			return E.New("provider outbound not found after update: ", prepared.tag)
		}
		outbounds = append(outbounds, outbound)
		outboundsByTag[prepared.tag] = outbound
		link, _ := linkParser.GenerateSubscriptionLink(prepared.source)
		outboundLinks = append(outboundLinks, link)
	}
	a.access.Lock()
	a.outbounds = outbounds
	a.outboundsByTag = outboundsByTag
	a.outboundLinks = outboundLinks
	a.outboundOpts = make([]option.Outbound, 0, len(preparedOutbounds))
	for _, prepared := range sourceOrder(preparedOutbounds) {
		a.outboundOpts = append(a.outboundOpts, prepared.source)
	}
	a.access.Unlock()
	return nil
}

func (a *Adapter) HealthCheck(ctx context.Context) (map[string]uint16, error) {
	if a.ticker != nil {
		a.ticker.Reset(a.interval)
	}
	return a.healthcheck(ctx)
}

func (a *Adapter) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	return a.callbacks.PushBack(callback)
}

func (a *Adapter) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	a.callbacks.Remove(element)
}

func (a *Adapter) UpdateGroups() {
	a.callbackAccess.Lock()
	var callbacks []adapter.ProviderUpdateCallback
	for element := a.callbacks.Front(); element != nil; element = element.Next() {
		callbacks = append(callbacks, element.Value)
	}
	a.callbackAccess.Unlock()
	for _, callback := range callbacks {
		if err := callback(a.providerTag); err != nil {
			a.logger.Error("update provider group: ", err)
		}
	}
}

func (a *Adapter) Close() error {
	if a.ticker != nil {
		a.ticker.Stop()
	}
	a.access.Lock()
	outbounds := a.outbounds
	a.outbounds = nil
	a.outboundsByTag = nil
	a.outboundLinks = nil
	a.outboundOpts = nil
	a.access.Unlock()
	var err error
	for _, ob := range outbounds {
		if err2 := a.outbound.Remove(ob.Tag()); err2 != nil {
			err = E.Append(err, err2, func(err error) error {
				return E.Cause(err, "close outbound [", ob.Tag(), "]")
			})
		}
	}
	return err
}

func (a *Adapter) loopCheck() {
	if !a.enabled {
		return
	}
	a.ticker = time.NewTicker(a.interval)
	a.healthcheck(a.ctx)
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.ticker.C:
			a.healthcheck(a.ctx)
		}
	}
}

func (a *Adapter) healthcheck(ctx context.Context) (map[string]uint16, error) {
	result := make(map[string]uint16)
	if a.checking.Swap(true) {
		return result, nil
	}
	defer a.checking.Store(false)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	var resultAccess sync.Mutex
	checked := make(map[string]bool)
	for _, detour := range a.Outbounds() {
		tag := detour.Tag()
		if checked[tag] {
			continue
		}
		checked[tag] = true
		b.Go(tag, func() (any, error) {
			ctx, cancel := context.WithTimeout(a.ctx, a.timeout)
			defer cancel()
			t, err := urltest.URLTest(ctx, a.link, detour)
			if err != nil {
				a.logger.Debug("outbound ", tag, " unavailable: ", err)
				a.history.DeleteURLTestHistory(tag)
			} else {
				a.logger.Debug("outbound ", tag, " available: ", t, "ms")
				a.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
					Time:  time.Now(),
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
	return result, nil
}

func normalizeOutboundTags(opts []option.Outbound, removeEmojis bool, tagPrefix string) {
	count := make(map[string]int)
	tags := make(map[string]string)
	for i, opt := range opts {
		originalTag := opt.Tag
		tag := originalTag
		if removeEmojis {
			tag = cleanOutboundTag(tag)
		}
		if tag != "" {
			tag = tagPrefix + tag
		}
		count[tag]++
		if count[tag] > 1 {
			tag = F.ToString(tag, " #", count[tag])
		}
		opts[i].Tag = tag
		if originalTag != "" {
			if _, exists := tags[originalTag]; !exists {
				tags[originalTag] = tag
			}
		}
	}
	for _, outbound := range opts {
		rewriteOutboundReferences(outbound.Options, tags)
	}
}

func cloneOutbounds(outbounds []option.Outbound) []option.Outbound {
	cloned := make([]option.Outbound, len(outbounds))
	for index, outbound := range outbounds {
		cloned[index] = outbound
		cloned[index].Options = cloneOptions(outbound.Options)
	}
	return cloned
}

func cleanOutboundTag(tag string) string {
	cleaned := flagRegex.ReplaceAllStringFunc(tag, flagToCountryCode)
	cleaned = emojiRegex.ReplaceAllString(cleaned, "")
	cleaned = multiSpaceRegex.ReplaceAllString(cleaned, " ")
	return strings.TrimSpace(cleaned)
}

func flagToCountryCode(flag string) string {
	runes := []rune(flag)
	if len(runes) == 2 {
		return string(rune(runes[0]-0x1F1E6+'A')) + string(rune(runes[1]-0x1F1E6+'A')) + " "
	}
	return ""
}

var flagRegex = regexp.MustCompile(`[\x{1F1E6}-\x{1F1FF}]{2}`)
var emojiRegex = regexp.MustCompile(`[\x{1F1E0}-\x{1F1FF}\x{1F300}-\x{1F9FF}\x{2600}-\x{27BF}\x{FE00}-\x{FE0F}\x{200D}]+`)
var multiSpaceRegex = regexp.MustCompile(`\s{2,}`)
