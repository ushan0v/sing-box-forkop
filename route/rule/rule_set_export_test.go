package rule

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/convertor/plain"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestRuleSetIPCIDRExport(t *testing.T) {
	rules := []option.HeadlessRule{
		defaultExportRule(option.DefaultHeadlessRule{IPCIDR: []string{"10.0.0.0/8", "2001:db8::/32"}}),
		defaultExportRule(option.DefaultHeadlessRule{
			IPCIDR:    []string{"192.0.2.0/24", "2001:db9::/32"},
			Port:      []uint16{443},
			PortRange: []string{"80:81"},
		}),
		// Destination matchers in one default rule are alternatives, so the IP branch is safe to export.
		defaultExportRule(option.DefaultHeadlessRule{
			DomainSuffix: []string{"example.com"},
			IPCIDR:       []string{"198.51.100.0/24"},
		}),
		{
			Type: C.RuleTypeLogical,
			LogicalOptions: option.LogicalHeadlessRule{
				Mode: C.LogicalTypeAnd,
				Rules: []option.HeadlessRule{
					defaultExportRule(option.DefaultHeadlessRule{DomainSuffix: []string{"required.example"}}),
					defaultExportRule(option.DefaultHeadlessRule{IPCIDR: []string{"203.0.113.0/24"}}),
				},
			},
		},
		defaultExportRule(option.DefaultHeadlessRule{
			Network: []string{"tcp"},
			IPCIDR:  []string{"172.16.0.0/12"},
		}),
		defaultExportRule(option.DefaultHeadlessRule{
			IPCIDR: []string{"172.31.0.0/16"},
			Invert: true,
		}),
		defaultExportRule(option.DefaultHeadlessRule{
			IPCIDR:    []string{"192.0.3.0/24"},
			PortRange: []string{"100:50"},
		}),
		{
			Type: C.RuleTypeLogical,
			LogicalOptions: option.LogicalHeadlessRule{
				Mode: C.LogicalTypeAnd,
				Rules: []option.HeadlessRule{
					defaultExportRule(option.DefaultHeadlessRule{
						IPCIDR:    []string{"192.0.4.0/24"},
						PortRange: []string{"80:100"},
					}),
					defaultExportRule(option.DefaultHeadlessRule{PortRange: []string{"90:110"}}),
				},
			},
		},
	}

	exported := buildRuleSetIPCIDRExport(rules)
	require.Equal(t, []string{"10.0.0.0/8", "198.51.100.0/24"}, exported.IPv4)
	require.Equal(t, []string{"2001:db8::/32"}, exported.IPv6)
	require.Equal(t, []adapter.RuleSetIPCIDRScoped{
		{
			Prefixes: []string{"192.0.2.0/24"},
			PortRanges: []adapter.RuleSetPortRange{
				{Start: 80, End: 81},
				{Start: 443, End: 443},
			},
		},
		{
			Prefixes:   []string{"192.0.4.0/24"},
			PortRanges: []adapter.RuleSetPortRange{{Start: 90, End: 100}},
		},
	}, exported.ScopedIPv4)
	require.Equal(t, []adapter.RuleSetIPCIDRScoped{{
		Prefixes: []string{"2001:db9::/32"},
		PortRanges: []adapter.RuleSetPortRange{
			{Start: 80, End: 81},
			{Start: 443, End: 443},
		},
	}}, exported.ScopedIPv6)
	require.Equal(t, []adapter.RuleSetIPCIDRSkipped{
		{Path: "rules[3].rules[0]", Reason: "non_ip_destination_constraint"},
		{Path: "rules[4]", Reason: "unsupported_constraints"},
		{Path: "rules[5]", Reason: "inverted_rule"},
		{Path: "rules[6]", Reason: "invalid_port_range"},
	}, exported.Skipped)

	textRules, err := plain.ToOptions(strings.NewReader("text.example\n100.64.0.0/10\n2001:db8:1::1\n"))
	require.NoError(t, err)
	textExport := buildRuleSetIPCIDRExport(textRules)
	require.Equal(t, []string{"100.64.0.0/10"}, textExport.IPv4)
	require.Equal(t, []string{"2001:db8:1::1/128"}, textExport.IPv6)
}

func TestRuleSetIPCIDRExportSkipsDomainOnlyRulesWithoutPerRuleAllocations(t *testing.T) {
	const ruleCount = 10_000
	rules := make([]option.HeadlessRule, ruleCount)
	for index := range rules {
		rules[index] = defaultExportRule(option.DefaultHeadlessRule{
			DomainSuffix: []string{"example.com"},
			Network:      []string{"tcp"},
		})
	}

	assertEmpty := func(exported adapter.RuleSetIPCIDRExport) {
		if len(exported.IPv4) != 0 || len(exported.IPv6) != 0 || len(exported.ScopedIPv4) != 0 || len(exported.ScopedIPv6) != 0 || len(exported.Skipped) != 0 {
			panic("domain-only rule-set produced an nft export")
		}
	}
	assertEmpty(buildRuleSetIPCIDRExport(rules))
	allocations := testing.AllocsPerRun(5, func() {
		assertEmpty(buildRuleSetIPCIDRExport(rules))
	})
	require.Less(t, allocations, float64(100), "domain-only rule count must not drive exporter allocations")
}

func TestRuleSetIPCIDRExportHonorsMetadataGate(t *testing.T) {
	rules := []option.HeadlessRule{
		defaultExportRule(option.DefaultHeadlessRule{IPCIDR: []string{"192.0.2.0/24"}}),
	}
	exported := buildRuleSetIPCIDRExportIfPresent(rules, false)
	require.NotNil(t, exported.IPv4)
	require.NotNil(t, exported.IPv6)
	require.NotNil(t, exported.ScopedIPv4)
	require.NotNil(t, exported.ScopedIPv6)
	require.Empty(t, exported.IPv4)
	require.Empty(t, exported.IPv6)
	require.Empty(t, exported.ScopedIPv4)
	require.Empty(t, exported.ScopedIPv6)
	require.Empty(t, exported.Skipped)
}

func defaultExportRule(options option.DefaultHeadlessRule) option.HeadlessRule {
	return option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: options}
}
