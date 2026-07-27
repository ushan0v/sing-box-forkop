package adapter

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/x/list"
)

type Provider interface {
	Type() string
	Tag() string
	Outbounds() []Outbound
	Outbound(tag string) (Outbound, bool)
	UpdatedAt() time.Time
	HealthCheck(ctx context.Context) (map[string]uint16, error)
	RegisterCallback(callback ProviderUpdateCallback) *list.Element[ProviderUpdateCallback]
	UnregisterCallback(element *list.Element[ProviderUpdateCallback])
}

type ProviderUpdater interface {
	Update() error
}

type ProviderSubscriptionInfo interface {
	SubscriptionInfo() SubscriptionInfo
}

type ProviderSubscriptionMetadata interface {
	SubscriptionMetadata() SubscriptionMetadata
}

type ProviderOutboundLink interface {
	OutboundLink(tag string) (string, bool)
}

type ProviderRegistry interface {
	option.ProviderOptionsRegistry
	CreateProvider(ctx context.Context, router Router, logFactory log.Factory, tag string, providerType string, options any) (Provider, error)
}

type ProviderManager interface {
	Lifecycle
	Providers() []Provider
	Get(tag string) (Provider, bool)
	Remove(tag string) error
	Create(ctx context.Context, router Router, logFactory log.Factory, tag string, providerType string, options any) error
}

type SubscriptionInfo struct {
	Upload   int64
	Download int64
	Total    int64
	Expire   int64
}

type SubscriptionMetadata struct {
	Title       string `json:"title,omitempty"`
	WebPageURL  string `json:"webPageUrl,omitempty"`
	SupportURL  string `json:"supportUrl,omitempty"`
	Announce    string `json:"announce,omitempty"`
	AnnounceURL string `json:"announceUrl,omitempty"`
	RefillDate  int64  `json:"refillDate,omitempty"`
	FileName    string `json:"fileName,omitempty"`
}

type ProviderUpdateCallback = func(tag string) error
