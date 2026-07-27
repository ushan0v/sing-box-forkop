package clashapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/x/list"

	"github.com/stretchr/testify/require"
)

type testRuleProvider struct {
	adapter.RuleSet
	name       string
	snapshot   adapter.RuleSetProviderSnapshot
	callbacks  list.List[adapter.RuleSetUpdateCallback]
	registered chan struct{}
}

func (p *testRuleProvider) Name() string {
	return p.name
}

func (p *testRuleProvider) ProviderSnapshot() adapter.RuleSetProviderSnapshot {
	return p.snapshot
}

func (p *testRuleProvider) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	element := p.callbacks.PushBack(callback)
	select {
	case p.registered <- struct{}{}:
	default:
	}
	return element
}

func (p *testRuleProvider) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	p.callbacks.Remove(element)
}

func (p *testRuleProvider) Update() error {
	p.snapshot.Revision++
	p.snapshot.UpdatedAt = time.Now()
	for _, callback := range p.callbacks.Array() {
		callback(p)
	}
	return nil
}

type testRuleProviderRouter struct {
	adapter.Router
	ruleSets []adapter.RuleSet
}

func (r *testRuleProviderRouter) RuleSet(tag string) (adapter.RuleSet, bool) {
	for _, ruleSet := range r.ruleSets {
		if ruleSet.Name() == tag {
			return ruleSet, true
		}
	}
	return nil, false
}

func (r *testRuleProviderRouter) RuleSets() []adapter.RuleSet {
	return r.ruleSets
}

func TestRuleProviderAPI(t *testing.T) {
	provider := &testRuleProvider{
		name: "private",
		snapshot: adapter.RuleSetProviderSnapshot{
			Type:     C.RuleSetTypeRemote,
			Format:   C.RuleSetFormatText,
			Revision: 1,
			IPCIDR:   adapter.RuleSetIPCIDRExport{IPv4: []string{"192.0.2.0/24"}},
		},
		registered: make(chan struct{}, 1),
	}
	secondProvider := &testRuleProvider{
		name:     "second",
		snapshot: adapter.RuleSetProviderSnapshot{Revision: 4},
	}
	handler := ruleProviderRouter(&Server{router: &testRuleProviderRouter{ruleSets: []adapter.RuleSet{provider, secondProvider}}})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, response.Code)
	var providers struct {
		Revision  uint64                          `json:"revision"`
		Providers map[string]ruleProviderResponse `json:"providers"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &providers))
	require.Equal(t, providers.Providers[provider.name].Revision+providers.Providers[secondProvider.name].Revision, providers.Revision)
	require.Equal(t, uint64(5), providers.Revision)
	require.Equal(t, "HTTP", providers.Providers[provider.name].VehicleType)
	require.Equal(t, C.RuleSetFormatText, providers.Providers[provider.name].Format)
	require.Equal(t, []string{"192.0.2.0/24"}, providers.Providers[provider.name].IPCIDR.IPv4)

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/private", nil))
	require.Equal(t, http.StatusOK, response.Code)

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/private", nil))
	require.Equal(t, http.StatusNoContent, response.Code)
	require.Equal(t, uint64(2), provider.snapshot.Revision)

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/events?once=1&since=5", nil))
	var event ruleProviderEvent
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &event))
	require.Equal(t, uint64(6), event.Revision)
	<-provider.registered

	response = httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/events?once=1&since=6", nil))
		close(done)
	}()
	<-provider.registered
	require.NoError(t, provider.Update())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("long poll did not receive rule-set update")
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &event))
	require.Equal(t, provider.name, event.Name)
	require.Equal(t, uint64(7), event.Revision)
}
