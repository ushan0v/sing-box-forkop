package rule

import (
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"go4.org/netipx"
)

const maxRuleSetExportClauses = 4096 // ponytail: bounds logical AND expansion; raise if real rule-sets exceed it.

type ruleSetExportClause struct {
	ipSet     *netipx.IPSet
	ports     []adapter.RuleSetPortRange
	nonIPPath string
}

type ruleSetScopedAccumulator struct {
	ports   []adapter.RuleSetPortRange
	builder netipx.IPSetBuilder
}

func buildRuleSetIPCIDRExport(rules []option.HeadlessRule) adapter.RuleSetIPCIDRExport {
	var (
		unscopedBuilder netipx.IPSetBuilder
		scopedBuilders  map[string]*ruleSetScopedAccumulator
		skipped         []adapter.RuleSetIPCIDRSkipped
	)
	for index, headlessRule := range rules {
		if !HasHeadlessRule(rules[index:index+1], isIPCIDRHeadlessRule) {
			continue
		}
		path := "rules[" + strconv.Itoa(index) + "]"
		clauses, ruleSkipped := exportRuleSetClauses(headlessRule, path)
		skipped = append(skipped, ruleSkipped...)
		for _, clause := range clauses {
			if clause.ipSet == nil {
				continue
			}
			if clause.nonIPPath != "" {
				skipped = append(skipped, adapter.RuleSetIPCIDRSkipped{
					Path:   clause.nonIPPath,
					Reason: "non_ip_destination_constraint",
				})
				continue
			}
			if clause.ports == nil {
				unscopedBuilder.AddSet(clause.ipSet)
				continue
			}
			key := ruleSetPortRangeKey(clause.ports)
			accumulator := scopedBuilders[key]
			if accumulator == nil {
				if scopedBuilders == nil {
					scopedBuilders = make(map[string]*ruleSetScopedAccumulator)
				}
				accumulator = &ruleSetScopedAccumulator{ports: clause.ports}
				scopedBuilders[key] = accumulator
			}
			accumulator.builder.AddSet(clause.ipSet)
		}
	}

	unscoped, _ := unscopedBuilder.IPSet()
	result := emptyRuleSetIPCIDRExport()
	result.Skipped = normalizeRuleSetSkipped(skipped)
	for _, prefix := range unscoped.Prefixes() {
		if prefix.Addr().Is4() {
			result.IPv4 = append(result.IPv4, prefix.String())
		} else {
			result.IPv6 = append(result.IPv6, prefix.String())
		}
	}

	keys := make([]string, 0, len(scopedBuilders))
	for key := range scopedBuilders {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		accumulator := scopedBuilders[key]
		accumulator.builder.RemoveSet(unscoped)
		ipSet, _ := accumulator.builder.IPSet()
		var ipv4Prefixes, ipv6Prefixes []string
		for _, prefix := range ipSet.Prefixes() {
			if prefix.Addr().Is4() {
				ipv4Prefixes = append(ipv4Prefixes, prefix.String())
			} else {
				ipv6Prefixes = append(ipv6Prefixes, prefix.String())
			}
		}
		if len(ipv4Prefixes) > 0 {
			result.ScopedIPv4 = append(result.ScopedIPv4, adapter.RuleSetIPCIDRScoped{
				Prefixes:   ipv4Prefixes,
				PortRanges: accumulator.ports,
			})
		}
		if len(ipv6Prefixes) > 0 {
			result.ScopedIPv6 = append(result.ScopedIPv6, adapter.RuleSetIPCIDRScoped{
				Prefixes:   ipv6Prefixes,
				PortRanges: accumulator.ports,
			})
		}
	}
	return result
}

func buildRuleSetIPCIDRExportIfPresent(rules []option.HeadlessRule, containsIPCIDR bool) adapter.RuleSetIPCIDRExport {
	if !containsIPCIDR {
		return emptyRuleSetIPCIDRExport()
	}
	return buildRuleSetIPCIDRExport(rules)
}

func emptyRuleSetIPCIDRExport() adapter.RuleSetIPCIDRExport {
	return adapter.RuleSetIPCIDRExport{
		IPv4:       make([]string, 0),
		IPv6:       make([]string, 0),
		ScopedIPv4: make([]adapter.RuleSetIPCIDRScoped, 0),
		ScopedIPv6: make([]adapter.RuleSetIPCIDRScoped, 0),
	}
}

func exportRuleSetClauses(rule option.HeadlessRule, path string) ([]ruleSetExportClause, []adapter.RuleSetIPCIDRSkipped) {
	switch rule.Type {
	case "", C.RuleTypeDefault:
		return exportDefaultRuleSetClause(rule.DefaultOptions, path)
	case C.RuleTypeLogical:
		logicalRule := rule.LogicalOptions
		if logicalRule.Invert {
			return nil, []adapter.RuleSetIPCIDRSkipped{{Path: path, Reason: "inverted_rule"}}
		}
		switch logicalRule.Mode {
		case C.LogicalTypeOr:
			var clauses []ruleSetExportClause
			var skipped []adapter.RuleSetIPCIDRSkipped
			for index, child := range logicalRule.Rules {
				childClauses, childSkipped := exportRuleSetClauses(child, childRuleSetPath(path, index))
				clauses = append(clauses, childClauses...)
				skipped = append(skipped, childSkipped...)
			}
			return clauses, skipped
		case C.LogicalTypeAnd:
			clauses := []ruleSetExportClause{{}}
			var skipped []adapter.RuleSetIPCIDRSkipped
			for index, child := range logicalRule.Rules {
				childClauses, childSkipped := exportRuleSetClauses(child, childRuleSetPath(path, index))
				skipped = append(skipped, childSkipped...)
				if len(childClauses) == 0 {
					return nil, skipped
				}
				if len(clauses) > maxRuleSetExportClauses/len(childClauses) {
					return nil, append(skipped, adapter.RuleSetIPCIDRSkipped{Path: path, Reason: "too_many_logical_combinations"})
				}
				combined := make([]ruleSetExportClause, 0, len(clauses)*len(childClauses))
				for _, left := range clauses {
					for _, right := range childClauses {
						if clause, loaded := combineRuleSetExportClauses(left, right); loaded {
							combined = append(combined, clause)
						}
					}
				}
				clauses = combined
				if len(clauses) == 0 {
					return nil, skipped
				}
			}
			return clauses, skipped
		default:
			return nil, []adapter.RuleSetIPCIDRSkipped{{Path: path, Reason: "unsupported_logical_mode"}}
		}
	default:
		return nil, []adapter.RuleSetIPCIDRSkipped{{Path: path, Reason: "unsupported_rule_type"}}
	}
}

func exportDefaultRuleSetClause(rule option.DefaultHeadlessRule, path string) ([]ruleSetExportClause, []adapter.RuleSetIPCIDRSkipped) {
	if rule.Invert {
		return nil, []adapter.RuleSetIPCIDRSkipped{{Path: path, Reason: "inverted_rule"}}
	}
	remaining := rule
	remaining.Domain = nil
	remaining.DomainSuffix = nil
	remaining.DomainKeyword = nil
	remaining.DomainRegex = nil
	remaining.IPCIDR = nil
	remaining.Port = nil
	remaining.PortRange = nil
	remaining.Invert = false
	remaining.DomainMatcher = nil
	remaining.IPSet = nil
	remaining.AdGuardDomain = nil
	remaining.AdGuardDomainMatcher = nil
	if !reflect.DeepEqual(remaining, option.DefaultHeadlessRule{}) {
		return nil, []adapter.RuleSetIPCIDRSkipped{{Path: path, Reason: "unsupported_constraints"}}
	}

	ipSet, valid := ruleSetIPSet(rule)
	if !valid {
		return nil, []adapter.RuleSetIPCIDRSkipped{{Path: path, Reason: "invalid_ip_cidr"}}
	}
	ports, valid := ruleSetPortRanges(rule.Port, rule.PortRange)
	if !valid {
		return nil, []adapter.RuleSetIPCIDRSkipped{{Path: path, Reason: "invalid_port_range"}}
	}
	clause := ruleSetExportClause{ipSet: ipSet, ports: ports}
	if ipSet == nil && hasRuleSetDomainConstraint(rule) {
		clause.nonIPPath = path
	}
	return []ruleSetExportClause{clause}, nil
}

func ruleSetIPSet(rule option.DefaultHeadlessRule) (*netipx.IPSet, bool) {
	var builder netipx.IPSetBuilder
	if rule.IPSet != nil {
		builder.AddSet(rule.IPSet)
	}
	for _, value := range rule.IPCIDR {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			builder.AddPrefix(prefix.Masked())
			continue
		}
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" {
			return nil, false
		}
		builder.Add(address)
	}
	ipSet, err := builder.IPSet()
	if err != nil {
		return nil, false
	}
	if len(ipSet.Prefixes()) == 0 {
		return nil, true
	}
	return ipSet, true
}

func hasRuleSetDomainConstraint(rule option.DefaultHeadlessRule) bool {
	return len(rule.Domain) > 0 || len(rule.DomainSuffix) > 0 || len(rule.DomainKeyword) > 0 || len(rule.DomainRegex) > 0 ||
		rule.DomainMatcher != nil || len(rule.AdGuardDomain) > 0 || rule.AdGuardDomainMatcher != nil
}

func ruleSetPortRanges(ports []uint16, rawRanges []string) ([]adapter.RuleSetPortRange, bool) {
	if len(ports) == 0 && len(rawRanges) == 0 {
		return nil, true
	}
	ranges := make([]adapter.RuleSetPortRange, 0, len(ports)+len(rawRanges))
	for _, port := range ports {
		ranges = append(ranges, adapter.RuleSetPortRange{Start: port, End: port})
	}
	for _, rawRange := range rawRanges {
		left, right, loaded := strings.Cut(rawRange, ":")
		if !loaded {
			return nil, false
		}
		start, end := uint64(0), uint64(0xffff)
		var err error
		if left != "" {
			start, err = strconv.ParseUint(left, 10, 16)
			if err != nil {
				return nil, false
			}
		}
		if right != "" {
			end, err = strconv.ParseUint(right, 10, 16)
			if err != nil {
				return nil, false
			}
		}
		if start > end {
			continue
		}
		ranges = append(ranges, adapter.RuleSetPortRange{Start: uint16(start), End: uint16(end)})
	}
	ranges = normalizeRuleSetPortRanges(ranges)
	if len(ranges) == 0 {
		return nil, false
	}
	return ranges, true
}

func normalizeRuleSetPortRanges(ranges []adapter.RuleSetPortRange) []adapter.RuleSetPortRange {
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].Start == ranges[j].Start {
			return ranges[i].End < ranges[j].End
		}
		return ranges[i].Start < ranges[j].Start
	})
	result := make([]adapter.RuleSetPortRange, 0, len(ranges))
	for _, item := range ranges {
		if len(result) == 0 || uint32(item.Start) > uint32(result[len(result)-1].End)+1 {
			result = append(result, item)
			continue
		}
		if item.End > result[len(result)-1].End {
			result[len(result)-1].End = item.End
		}
	}
	return result
}

func combineRuleSetExportClauses(left, right ruleSetExportClause) (ruleSetExportClause, bool) {
	result := ruleSetExportClause{
		ipSet:     left.ipSet,
		ports:     intersectRuleSetPortRanges(left.ports, right.ports),
		nonIPPath: left.nonIPPath,
	}
	if result.nonIPPath == "" {
		result.nonIPPath = right.nonIPPath
	}
	if left.ports != nil && right.ports != nil && len(result.ports) == 0 {
		return ruleSetExportClause{}, false
	}
	if result.ipSet == nil {
		result.ipSet = right.ipSet
	} else if right.ipSet != nil {
		var builder netipx.IPSetBuilder
		builder.AddSet(result.ipSet)
		builder.Intersect(right.ipSet)
		result.ipSet, _ = builder.IPSet()
		if len(result.ipSet.Prefixes()) == 0 {
			return ruleSetExportClause{}, false
		}
	}
	return result, true
}

func intersectRuleSetPortRanges(left, right []adapter.RuleSetPortRange) []adapter.RuleSetPortRange {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	var result []adapter.RuleSetPortRange
	for _, first := range left {
		for _, second := range right {
			start := max(first.Start, second.Start)
			end := min(first.End, second.End)
			if start <= end {
				result = append(result, adapter.RuleSetPortRange{Start: start, End: end})
			}
		}
	}
	return normalizeRuleSetPortRanges(result)
}

func ruleSetPortRangeKey(ranges []adapter.RuleSetPortRange) string {
	var builder strings.Builder
	for _, item := range ranges {
		builder.WriteString(strconv.FormatUint(uint64(item.Start), 10))
		builder.WriteByte(':')
		builder.WriteString(strconv.FormatUint(uint64(item.End), 10))
		builder.WriteByte(',')
	}
	return builder.String()
}

func childRuleSetPath(parent string, index int) string {
	return parent + ".rules[" + strconv.Itoa(index) + "]"
}

func normalizeRuleSetSkipped(skipped []adapter.RuleSetIPCIDRSkipped) []adapter.RuleSetIPCIDRSkipped {
	if len(skipped) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	result := make([]adapter.RuleSetIPCIDRSkipped, 0, len(skipped))
	for _, item := range skipped {
		key := item.Path + "\x00" + item.Reason
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Path == result[j].Path {
			return result[i].Reason < result[j].Reason
		}
		return result[i].Path < result[j].Path
	})
	return result
}
