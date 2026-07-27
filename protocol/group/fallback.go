package group

import (
	"context"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterFallback(registry *outbound.Registry) {
	outbound.Register[option.FallbackOutboundOptions](registry, C.TypeFallback, NewFallback)
}

var _ adapter.OutboundGroup = (*Fallback)(nil)

type Fallback struct {
	outbound.Adapter
	ctx                 context.Context
	outbound            adapter.OutboundManager
	logger              logger.ContextLogger
	tags                []string
	configuredTags      []string
	excludeGroupMembers []string
	outbounds           map[string]adapter.Outbound
	lastUsedOutbound    string
	blacklistTimeout    time.Duration
	blacklist           map[string]time.Time
	mtx                 sync.Mutex

	provider       adapter.ProviderManager
	providers      map[string]adapter.Provider
	outboundsCache map[string][]adapter.Outbound

	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	useAllProviders bool
}

func NewFallback(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FallbackOutboundOptions) (adapter.Outbound, error) {
	if len(options.Outbounds)+len(options.Providers) == 0 && !options.UseAllProviders {
		return nil, E.New("missing tags")
	}
	blacklistTimeout := time.Duration(options.BlacklistTimeout)
	if blacklistTimeout == 0 {
		blacklistTimeout = time.Minute
	}
	dependencies := append([]string(nil), options.Outbounds...)
	dependencies = append(dependencies, options.ExcludeGroupMembers...)
	outbound := &Fallback{
		Adapter:             outbound.NewAdapter(C.TypeFallback, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		ctx:                 ctx,
		outbound:            service.FromContext[adapter.OutboundManager](ctx),
		logger:              logger,
		tags:                append([]string(nil), options.Outbounds...),
		configuredTags:      append([]string(nil), options.Outbounds...),
		excludeGroupMembers: append([]string(nil), options.ExcludeGroupMembers...),
		outbounds:           make(map[string]adapter.Outbound, len(options.Outbounds)),
		blacklistTimeout:    blacklistTimeout,
		blacklist:           make(map[string]time.Time),

		provider:       service.FromContext[adapter.ProviderManager](ctx),
		providers:      make(map[string]adapter.Provider),
		outboundsCache: make(map[string][]adapter.Outbound),

		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		useAllProviders: options.UseAllProviders,
	}
	return outbound, nil
}

func (s *Fallback) Start() error {
	if s.useAllProviders {
		var providerTags []string
		for _, provider := range s.provider.Providers() {
			providerTags = append(providerTags, provider.Tag())
			s.providers[provider.Tag()] = provider
			provider.RegisterCallback(s.onProviderUpdated)
		}
		s.providerTags = providerTags
	} else {
		for i, tag := range s.providerTags {
			provider, loaded := s.provider.Get(tag)
			if !loaded {
				return E.New("outbound provider ", i, " not found: ", tag)
			}
			s.providers[tag] = provider
			provider.RegisterCallback(s.onProviderUpdated)
		}
	}
	for i, tag := range s.tags {
		outbound, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		s.outbounds[tag] = outbound
	}
	for i, tag := range s.excludeGroupMembers {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("excluded outbound group ", i, " not found: ", tag)
		}
		if _, isGroup := detour.(adapter.OutboundGroup); !isGroup {
			return E.New("excluded outbound is not a group: ", tag)
		}
	}
	if len(s.tags) > 0 {
		s.lastUsedOutbound = s.tags[0]
	}
	return nil
}

func (s *Fallback) Now() string {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.lastUsedOutbound
}

func (s *Fallback) All() []string {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return append([]string(nil), s.tags...)
}

func (s *Fallback) onProviderUpdated(tag string) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if _, loaded := s.providers[tag]; !loaded {
		return E.New(s.Tag(), ": outbound provider not found: ", tag)
	}
	tags := append([]string(nil), s.configuredTags...)
	outbounds := make(map[string]adapter.Outbound)
	for _, outboundTag := range tags {
		detour, loaded := s.outbound.Outbound(outboundTag)
		if loaded {
			outbounds[outboundTag] = detour
		}
	}
	excluded := excludedGroupMembers(s.outbound, s.excludeGroupMembers)
	for _, providerTag := range s.providerTags {
		cache := s.outboundsCache[providerTag]
		if providerTag == tag || cache == nil {
			cache = nil
			provider := s.providers[providerTag]
			for _, detour := range provider.Outbounds() {
				tag := detour.Tag()
				if s.exclude != nil && s.exclude.MatchString(tag) {
					continue
				}
				if s.include != nil && !s.include.MatchString(tag) {
					continue
				}
				cache = append(cache, detour)
			}
			s.outboundsCache[providerTag] = cache
		}
		for _, detour := range cache {
			if excluded[detour.Tag()] {
				continue
			}
			tags = append(tags, detour.Tag())
			outbounds[detour.Tag()] = detour
		}
	}
	for blacklistedTag := range s.blacklist {
		if _, loaded := outbounds[blacklistedTag]; !loaded {
			delete(s.blacklist, blacklistedTag)
		}
	}
	if _, loaded := outbounds[s.lastUsedOutbound]; !loaded {
		if len(tags) > 0 {
			s.lastUsedOutbound = tags[0]
		} else {
			s.lastUsedOutbound = ""
		}
	}
	s.tags = tags
	s.outbounds = outbounds
	return nil
}

func (s *Fallback) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.mtx.Lock()
	var active, blacklisted []fallbackCandidate
	for _, tag := range s.tags {
		candidate := fallbackCandidate{tag: tag, outbound: s.outbounds[tag]}
		if s.isBlacklisted(tag) {
			blacklisted = append(blacklisted, candidate)
		} else {
			active = append(active, candidate)
		}
	}
	s.mtx.Unlock()

	var err error
	for _, candidate := range active {
		var conn net.Conn
		conn, err = candidate.outbound.DialContext(ctx, network, destination)
		if err != nil {
			s.logger.InfoContext(ctx, err)
			s.mtx.Lock()
			s.addToBlacklist(candidate)
			s.mtx.Unlock()
			continue
		}
		s.mtx.Lock()
		s.lastUsedOutbound = candidate.tag
		s.mtx.Unlock()
		return conn, nil
	}
	for _, candidate := range blacklisted {
		var conn net.Conn
		conn, err = candidate.outbound.DialContext(ctx, network, destination)
		if err != nil {
			s.logger.InfoContext(ctx, err)
			continue
		}
		s.mtx.Lock()
		delete(s.blacklist, candidate.tag)
		s.lastUsedOutbound = candidate.tag
		s.mtx.Unlock()
		return conn, nil
	}
	if err == nil {
		err = E.New("no available outbounds")
	}
	return nil, err
}

func (s *Fallback) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.mtx.Lock()
	var active, blacklisted []fallbackCandidate
	for _, tag := range s.tags {
		candidate := fallbackCandidate{tag: tag, outbound: s.outbounds[tag]}
		if s.isBlacklisted(tag) {
			blacklisted = append(blacklisted, candidate)
		} else {
			active = append(active, candidate)
		}
	}
	s.mtx.Unlock()

	var err error
	for _, candidate := range active {
		var conn net.PacketConn
		conn, err = candidate.outbound.ListenPacket(ctx, destination)
		if err != nil {
			s.logger.InfoContext(ctx, err)
			s.mtx.Lock()
			s.addToBlacklist(candidate)
			s.mtx.Unlock()
			continue
		}
		s.mtx.Lock()
		s.lastUsedOutbound = candidate.tag
		s.mtx.Unlock()
		return conn, nil
	}
	for _, candidate := range blacklisted {
		var conn net.PacketConn
		conn, err = candidate.outbound.ListenPacket(ctx, destination)
		if err != nil {
			s.logger.InfoContext(ctx, err)
			continue
		}
		s.mtx.Lock()
		delete(s.blacklist, candidate.tag)
		s.lastUsedOutbound = candidate.tag
		s.mtx.Unlock()
		return conn, nil
	}
	if err == nil {
		err = E.New("no available outbounds")
	}
	return nil, err
}

type fallbackCandidate struct {
	tag      string
	outbound adapter.Outbound
}

func (s *Fallback) isBlacklisted(tag string) bool {
	if s.blacklistTimeout == 0 {
		return false
	}
	expiry, ok := s.blacklist[tag]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(s.blacklist, tag)
		return false
	}
	return true
}

func (s *Fallback) addToBlacklist(candidate fallbackCandidate) {
	if s.blacklistTimeout > 0 && s.outbounds[candidate.tag] == candidate.outbound {
		s.blacklist[candidate.tag] = time.Now().Add(s.blacklistTimeout)
	}
}
