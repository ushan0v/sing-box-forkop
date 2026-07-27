package clashapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type linkAPIOutbound struct {
	adapter.Outbound
	outboundAdapter.Adapter
}

func (o *linkAPIOutbound) Type() string           { return o.Adapter.Type() }
func (o *linkAPIOutbound) Tag() string            { return o.Adapter.Tag() }
func (o *linkAPIOutbound) Network() []string      { return o.Adapter.Network() }
func (o *linkAPIOutbound) Dependencies() []string { return o.Adapter.Dependencies() }

type linkAPIOutboundManager struct {
	adapter.OutboundManager
	outbounds []adapter.Outbound
}

func (m *linkAPIOutboundManager) Outbounds() []adapter.Outbound { return m.outbounds }
func (m *linkAPIOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	for _, outbound := range m.outbounds {
		if outbound.Tag() == tag {
			return outbound, true
		}
	}
	return nil, false
}
func (m *linkAPIOutboundManager) Default() adapter.Outbound { return m.outbounds[0] }

type linkAPIProvider struct {
	adapter.Provider
	links map[string]string
}

func (p *linkAPIProvider) OutboundLink(tag string) (string, bool) {
	link, loaded := p.links[tag]
	return link, loaded
}

type linkAPIProviderManager struct {
	adapter.ProviderManager
	providers []adapter.Provider
}

func (m *linkAPIProviderManager) Providers() []adapter.Provider { return m.providers }

type linkAPIEndpointManager struct{ adapter.EndpointManager }

func (m *linkAPIEndpointManager) Endpoints() []adapter.Endpoint { return nil }

type unifiedDelayProbeOutbound struct {
	*linkAPIOutbound
	unifiedDelay bool
}

func (o *unifiedDelayProbeOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	o.unifiedDelay = urltest.IsUnifiedDelayFromContext(ctx)
	return nil, errors.New("probe")
}

func (o *unifiedDelayProbeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("probe")
}

func TestProxyLinkAPIIsExplicitAuthenticatedAndUncached(t *testing.T) {
	const (
		tag       = "subscription/node"
		secretURI = "vless://00000000-0000-4000-8000-000000000001@example.com:443#node"
	)
	outbound := &linkAPIOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, tag, []string{"tcp"}, nil)}
	server := &Server{
		outbound:       &linkAPIOutboundManager{outbounds: []adapter.Outbound{outbound}},
		endpoint:       &linkAPIEndpointManager{},
		provider:       &linkAPIProviderManager{providers: []adapter.Provider{&linkAPIProvider{links: map[string]string{tag: secretURI}}}},
		urlTestHistory: urltest.NewHistoryStorage(),
	}
	handler := authentication("api-secret")(proxyRouter(server, nil))

	request := httptest.NewRequest(http.MethodGet, "/subscription%2Fnode/link", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated link request returned %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/subscription%2Fnode/link", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Authorization", "Bearer api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated link request returned %d: %s", response.Code, response.Body)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected Cache-Control: %q", response.Header().Get("Cache-Control"))
	}
	var result struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.URL != secretURI {
		t.Fatalf("unexpected link response: %q", result.URL)
	}
	openHandler := authentication("")(proxyRouter(server, nil))
	request = httptest.NewRequest(http.MethodGet, "/subscription%2Fnode/link", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	response = httptest.NewRecorder()
	openHandler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("remote link request without an API secret returned %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/subscription%2Fnode/link", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	response = httptest.NewRecorder()
	openHandler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("local link request without an API secret returned %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("bulk proxy request returned %d: %s", response.Code, response.Body)
	}
	if strings.Contains(response.Body.String(), secretURI) || strings.Contains(response.Body.String(), `"url"`) {
		t.Fatalf("bulk proxy response leaked a share link: %s", response.Body)
	}

	request = httptest.NewRequest(http.MethodGet, "/subscription%2Fmissing/link", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Authorization", "Bearer api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing proxy returned %d", response.Code)
	}

	server.provider = &linkAPIProviderManager{providers: []adapter.Provider{&linkAPIProvider{links: map[string]string{}}}}
	request = httptest.NewRequest(http.MethodGet, "/subscription%2Fnode/link", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Authorization", "Bearer api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unsupported proxy returned %d with Cache-Control %q", response.Code, response.Header().Get("Cache-Control"))
	}

	request = httptest.NewRequest(http.MethodGet, "/subscription%2Fnode/link", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set("Authorization", "Bearer api-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("remote link request returned %d with Cache-Control %q", response.Code, response.Header().Get("Cache-Control"))
	}
}

func TestProxyDelayPreservesUnifiedDelayContext(t *testing.T) {
	const tag = "subscription/node"
	outbound := &unifiedDelayProbeOutbound{
		linkAPIOutbound: &linkAPIOutbound{
			Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, tag, []string{"tcp"}, nil),
		},
	}
	ctx := urltest.ContextWithIsUnifiedDelay(context.Background())
	clashServer, err := NewServer(ctx, log.NewNOPFactory(), option.ClashAPIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server := clashServer.(*Server)
	server.outbound = &linkAPIOutboundManager{outbounds: []adapter.Outbound{outbound}}

	request := httptest.NewRequest(http.MethodGet, "/proxies/subscription%2Fnode/delay?url=https%3A%2F%2Fexample.com&timeout=100", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	if server.httpServer.BaseContext == nil {
		t.Fatal("Clash API server has no base context")
	}
	request = request.WithContext(server.httpServer.BaseContext(nil))
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)

	if !outbound.unifiedDelay {
		t.Fatal("proxy delay request lost Unified Delay context")
	}
}
