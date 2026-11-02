//go:build go1.24

package tls

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type echTestNetworkManager struct {
	adapter.NetworkManager
	options adapter.NetworkOptions
}

func (m *echTestNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return m.options
}

type echTestTransportManager struct {
	adapter.DNSTransportManager
	transports map[string]adapter.DNSTransport
}

func (m *echTestTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, loaded := m.transports[tag]
	return transport, loaded
}

type echTestTransport struct {
	adapter.DNSTransport
}

type echTestRouter struct {
	adapter.DNSRouter
	options  adapter.DNSQueryOptions
	question mDNS.Question
}

func (r *echTestRouter) Exchange(_ context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	r.options = options
	r.question = message.Question[0]
	response := new(mDNS.Msg)
	response.SetReply(message)
	response.Answer = []mDNS.RR{&mDNS.HTTPS{SVCB: mDNS.SVCB{
		Hdr:    mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeHTTPS, Class: mDNS.ClassINET, Ttl: 300},
		Target: ".",
		Value:  []mDNS.SVCBKeyValue{&mDNS.SVCBECHConfig{ECH: []byte{1, 2, 3}}},
	}}}
	return response, nil
}

type echTestConfig struct {
	ECHCapableConfig
	list []byte
}

func (c *echTestConfig) ECHConfigList() []byte              { return c.list }
func (c *echTestConfig) SetECHConfigList(l []byte)          { c.list = l }
func (c *echTestConfig) ServerName() string                 { return "node.example" }
func (c *echTestConfig) Client(net.Conn) (aTLS.Conn, error) { return nil, nil }

func echTestContext(defaultResolver string, transports map[string]adapter.DNSTransport) (context.Context, *echTestRouter) {
	router := new(echTestRouter)
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), router)
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, &echTestTransportManager{transports: transports})
	ctx = service.ContextWith[adapter.NetworkManager](ctx, &echTestNetworkManager{options: adapter.NetworkOptions{DomainResolver: defaultResolver}})
	return ctx, router
}

func echTestOptions(queryServerName string) option.OutboundTLSOptions {
	return option.OutboundTLSOptions{ECH: &option.OutboundECHOptions{Enabled: true, QueryServerName: queryServerName}}
}

func TestECHQueryUsesDefaultDomainResolver(t *testing.T) {
	t.Parallel()
	resolver := new(echTestTransport)
	ctx, router := echTestContext("resolver", map[string]adapter.DNSTransport{"resolver": resolver})

	config, err := parseECHClientConfig(ctx, &echTestConfig{}, echTestOptions("cloudflare-ech.com"))
	require.NoError(t, err)
	_, err = config.(*ECHClientConfig).fetchAndHandshake(ctx, nil)
	require.NoError(t, err)

	require.Same(t, resolver, router.options.Transport, "a set transport takes the query past the DNS rules")
	require.Equal(t, "cloudflare-ech.com.", router.question.Name)
	require.Equal(t, mDNS.TypeHTTPS, router.question.Qtype)
}

func TestECHQueryKeepsDomainResolverAcrossClone(t *testing.T) {
	t.Parallel()
	resolver := new(echTestTransport)
	ctx, _ := echTestContext("resolver", map[string]adapter.DNSTransport{"resolver": resolver})

	queryOptions, err := echQueryOptions(ctx)
	require.NoError(t, err)
	inner := &echTestConfig{}
	cloned := (&ECHClientConfig{ECHCapableConfig: &echTestCloneConfig{inner}, queryOptions: queryOptions}).Clone()
	require.Same(t, resolver, cloned.(*ECHClientConfig).queryOptions.Transport)
}

type echTestCloneConfig struct {
	*echTestConfig
}

func (c *echTestCloneConfig) Clone() Config { return c }

func TestECHQueryGoesThroughRulesWithoutDomainResolver(t *testing.T) {
	t.Parallel()
	ctx, router := echTestContext("", nil)

	config, err := parseECHClientConfig(ctx, &echTestConfig{}, echTestOptions(""))
	require.NoError(t, err)
	_, err = config.(*ECHClientConfig).fetchAndHandshake(ctx, nil)
	require.NoError(t, err)

	require.Nil(t, router.options.Transport)
	require.Equal(t, "node.example.", router.question.Name)
}

func TestECHQueryRefusesUnknownDomainResolver(t *testing.T) {
	t.Parallel()
	ctx, _ := echTestContext("missing", map[string]adapter.DNSTransport{})

	_, err := parseECHClientConfig(ctx, &echTestConfig{}, echTestOptions(""))
	require.ErrorContains(t, err, "default domain resolver not found: missing")
}
