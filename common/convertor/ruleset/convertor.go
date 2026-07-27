package ruleset

import (
	"bytes"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/convertor/plain"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"

	"gopkg.in/yaml.v3"
)

const autoDetectPrefixBytes = 64 << 10

func Read(reader io.Reader, format string) (option.PlainRuleSet, string, error) {
	if format == C.RuleSetFormatAuto {
		prefix, err := io.ReadAll(io.LimitReader(reader, autoDetectPrefixBytes))
		if err != nil {
			return option.PlainRuleSet{}, "", err
		}
		format = detectFormat(prefix)
		reader = io.MultiReader(bytes.NewReader(prefix), reader)
		if format == C.RuleSetFormatText {
			rules, err := plain.ToOptionsStrict(reader)
			return option.PlainRuleSet{Rules: rules}, format, err
		}
	}
	return read(reader, format)
}

func read(reader io.Reader, format string) (option.PlainRuleSet, string, error) {
	var ruleSet option.PlainRuleSet
	switch format {
	case C.RuleSetFormatSource:
		content, err := io.ReadAll(reader)
		if err != nil {
			return ruleSet, format, err
		}
		compat, err := json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return ruleSet, format, err
		}
		ruleSet, err = compat.Upgrade()
		return ruleSet, format, err
	case C.RuleSetFormatBinary:
		compat, err := srs.Read(reader, false)
		if err != nil {
			return ruleSet, format, err
		}
		ruleSet, err = compat.Upgrade()
		return ruleSet, format, err
	case C.RuleSetFormatText:
		rules, err := plain.ToOptions(reader)
		ruleSet.Rules = rules
		return ruleSet, format, err
	case C.RuleSetFormatYAML:
		content, err := io.ReadAll(reader)
		if err != nil {
			return ruleSet, format, err
		}
		rules, err := clashRules(content)
		ruleSet.Rules = rules
		return ruleSet, format, err
	default:
		return ruleSet, format, E.New("unknown rule-set format: ", format)
	}
}

func detectFormat(content []byte) string {
	trimmed := bytes.TrimSpace(content)
	trimmed = bytes.TrimSpace(bytes.TrimPrefix(trimmed, []byte{0xEF, 0xBB, 0xBF}))
	if len(trimmed) >= len(srs.MagicBytes) && bytes.Equal(trimmed[:len(srs.MagicBytes)], srs.MagicBytes[:]) {
		return C.RuleSetFormatBinary
	}
	trimmed = meaningfulPrefix(trimmed)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return C.RuleSetFormatSource
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return C.RuleSetFormatYAML
	}
	line := bytes.TrimSpace(bytes.SplitN(trimmed, []byte{'\n'}, 2)[0])
	if bytes.HasPrefix(line, []byte("- ")) || hasYAMLPayload(trimmed) {
		return C.RuleSetFormatYAML
	}
	return C.RuleSetFormatText
}

func hasYAMLPayload(content []byte) bool {
	for _, line := range bytes.Split(content, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if bytes.Equal(line, []byte("payload:")) ||
			(bytes.HasPrefix(line, []byte("payload:")) && len(line) > len("payload:") && (line[len("payload:")] == ' ' || line[len("payload:")] == '\t')) {
			return true
		}
	}
	return false
}

func meaningfulPrefix(content []byte) []byte {
	for {
		content = bytes.TrimSpace(content)
		switch {
		case bytes.HasPrefix(content, []byte("#")), bytes.HasPrefix(content, []byte("//")), bytes.HasPrefix(content, []byte("---")):
			if end := bytes.IndexByte(content, '\n'); end >= 0 {
				content = content[end+1:]
				continue
			}
			return nil
		case bytes.HasPrefix(content, []byte("/*")):
			if end := bytes.Index(content[2:], []byte("*/")); end >= 0 {
				content = content[end+4:]
				continue
			}
			return content
		default:
			return content
		}
	}
}

type valueSet[T comparable] struct {
	values []T
	seen   map[T]struct{}
}

func (s *valueSet[T]) add(value T) {
	if s.seen == nil {
		s.seen = make(map[T]struct{})
	}
	if _, loaded := s.seen[value]; loaded {
		return
	}
	s.seen[value] = struct{}{}
	s.values = append(s.values, value)
}

type clashRuleValues struct {
	domain           valueSet[string]
	domainSuffix     valueSet[string]
	domainKeyword    valueSet[string]
	domainRegex      valueSet[string]
	ipCIDR           valueSet[string]
	sourceIPCIDR     valueSet[string]
	port             valueSet[uint16]
	portRange        valueSet[string]
	sourcePort       valueSet[uint16]
	sourcePortRange  valueSet[string]
	processName      valueSet[string]
	processPath      valueSet[string]
	processPathRegex valueSet[string]
	network          valueSet[string]
}

func clashRules(content []byte) ([]option.HeadlessRule, error) {
	items, err := yamlRuleItems(content)
	if err != nil {
		return nil, err
	}
	var values clashRuleValues
	for index, item := range items {
		if err = values.addRule(strings.TrimSpace(item)); err != nil {
			return nil, E.Cause(err, "parse clash rule-set item[", index, "]")
		}
	}
	rules := values.rules()
	if len(rules) == 0 {
		return nil, E.New("empty clash rule-set")
	}
	return rules, nil
}

func yamlRuleItems(content []byte) ([]string, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, E.Cause(err, "decode clash rule-set")
	}
	if len(document.Content) != 1 {
		return nil, E.New("empty clash rule-set document")
	}
	root := document.Content[0]
	var payload *yaml.Node
	switch root.Kind {
	case yaml.SequenceNode:
		payload = root
	case yaml.MappingNode:
		for i := 0; i < len(root.Content); i += 2 {
			key, value := root.Content[i], root.Content[i+1]
			if key.Value != "payload" {
				continue
			}
			if payload != nil {
				return nil, E.New("clash rule-set must contain only one payload")
			}
			payload = value
		}
	default:
		return nil, E.New("clash rule-set root must be a mapping or sequence")
	}
	if payload == nil {
		return nil, E.New("missing clash rule-set payload")
	}
	if payload.Kind != yaml.SequenceNode {
		return nil, E.New("clash rule-set payload must be a sequence")
	}
	items := make([]string, 0, len(payload.Content))
	for _, item := range payload.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" || strings.TrimSpace(item.Value) == "" {
			return nil, E.New("clash rule-set payload items must be non-empty strings")
		}
		items = append(items, item.Value)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, E.New("multiple clash rule-set documents are not supported")
		}
		return nil, E.Cause(err, "decode clash rule-set")
	}
	return items, nil
}

func (v *clashRuleValues) addRule(line string) error {
	if line == "" {
		return E.New("empty rule")
	}
	parts := strings.Split(line, ",")
	if len(parts) == 1 {
		return v.addDomainOrIP(line)
	}
	ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(parts[1])
	modifiers := parts[2:]
	if value == "" {
		return E.New("missing ", ruleType, " value")
	}
	switch ruleType {
	case "DOMAIN":
		if err := rejectExtraFields(ruleType, modifiers); err != nil {
			return err
		}
		return addDomain(&v.domain, value)
	case "DOMAIN-SUFFIX":
		if err := rejectExtraFields(ruleType, modifiers); err != nil {
			return err
		}
		return addDomainSuffix(&v.domainSuffix, value)
	case "DOMAIN-KEYWORD":
		if err := rejectExtraFields(ruleType, modifiers); err != nil {
			return err
		}
		v.domainKeyword.add(value)
	case "DOMAIN-REGEX":
		if err := rejectExtraFields(ruleType, modifiers); err != nil {
			return err
		}
		return addRegex(&v.domainRegex, value)
	case "DOMAIN-WILDCARD":
		if err := rejectExtraFields(ruleType, modifiers); err != nil {
			return err
		}
		return addRegex(&v.domainRegex, globRegex(value, false))
	case "IP-CIDR", "IP-CIDR6":
		return addIPRule(&v.ipCIDR, value, modifiers)
	case "SRC-IP-CIDR", "SRC-IP-CIDR6":
		return addIPRule(&v.sourceIPCIDR, value, modifiers)
	case "DST-PORT":
		if err := rejectExtraFields(ruleType, modifiers); err != nil {
			return err
		}
		return addPorts(value, &v.port, &v.portRange)
	case "SRC-PORT":
		if err := rejectExtraFields(ruleType, modifiers); err != nil {
			return err
		}
		return addPorts(value, &v.sourcePort, &v.sourcePortRange)
	case "PROCESS-NAME":
		if err := rejectExtraFields(ruleType, modifiers); err != nil {
			return err
		}
		v.processName.add(value)
	case "PROCESS-PATH":
		if err := rejectExtraFields(ruleType, modifiers); err != nil {
			return err
		}
		v.processPath.add(value)
	case "PROCESS-PATH-REGEX":
		if err := rejectExtraFields(ruleType, modifiers); err != nil {
			return err
		}
		return addRegex(&v.processPathRegex, value)
	case "PROCESS-PATH-WILDCARD":
		if err := rejectExtraFields(ruleType, modifiers); err != nil {
			return err
		}
		return addRegex(&v.processPathRegex, globRegex(value, false))
	case "NETWORK":
		if err := rejectExtraFields(ruleType, modifiers); err != nil {
			return err
		}
		for _, network := range strings.Split(strings.ToLower(value), "/") {
			network = strings.TrimSpace(network)
			if network != "tcp" && network != "udp" {
				return E.New("unsupported network: ", value)
			}
			v.network.add(network)
		}
	default:
		return E.New("unsupported clash rule type: ", ruleType)
	}
	return nil
}

func rejectExtraFields(ruleType string, fields []string) error {
	if len(fields) > 0 {
		return E.New("unexpected fields in ", ruleType, " rule")
	}
	return nil
}

func (v *clashRuleValues) addDomainOrIP(value string) error {
	if prefix, loaded := parsePrefix(value); loaded {
		v.ipCIDR.add(prefix)
		return nil
	}
	switch {
	case strings.HasPrefix(value, "+."):
		return addDomainSuffix(&v.domainSuffix, value[2:])
	case strings.HasPrefix(value, "."):
		return addDomainSuffix(&v.domainSuffix, value)
	case strings.ContainsAny(value, "*?"):
		return addRegex(&v.domainRegex, globRegex(value, true))
	default:
		return addDomain(&v.domain, value)
	}
}

func addDomain(values *valueSet[string], value string) error {
	domain, loaded := plain.NormalizeDomain(value)
	if !loaded || strings.HasPrefix(domain, ".") {
		return E.New("invalid domain: ", value)
	}
	values.add(domain)
	return nil
}

func addDomainSuffix(values *valueSet[string], value string) error {
	domain, loaded := plain.NormalizeDomain(value)
	if !loaded {
		return E.New("invalid domain suffix: ", value)
	}
	values.add(domain)
	return nil
}

func addRegex(values *valueSet[string], value string) error {
	if _, err := regexp.Compile(value); err != nil {
		return E.Cause(err, "invalid regular expression")
	}
	values.add(value)
	return nil
}

func addIPRule(values *valueSet[string], value string, modifiers []string) error {
	prefix, loaded := parsePrefix(value)
	if !loaded {
		return E.New("invalid IP address or prefix: ", value)
	}
	for _, modifier := range modifiers {
		modifier = strings.ToLower(strings.TrimSpace(modifier))
		if modifier != "no-resolve" {
			return E.New("unsupported IP rule modifier: ", modifier)
		}
	}
	values.add(prefix)
	return nil
}

func parsePrefix(value string) (string, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Zone() == "" {
		return prefix.Masked().String(), true
	}
	if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
		return address.String(), true
	}
	return "", false
}

func addPorts(value string, ports *valueSet[uint16], ranges *valueSet[string]) error {
	for _, item := range strings.FieldsFunc(value, func(character rune) bool { return character == '/' || character == ',' }) {
		item = strings.TrimSpace(item)
		if item == "" {
			return E.New("empty port")
		}
		if start, end, ranged := strings.Cut(item, "-"); ranged {
			startPort, err := parsePort(start)
			if err != nil {
				return err
			}
			endPort, err := parsePort(end)
			if err != nil {
				return err
			}
			if startPort > endPort {
				return E.New("invalid port range: ", item)
			}
			ranges.add(strconv.Itoa(int(startPort)) + ":" + strconv.Itoa(int(endPort)))
			continue
		}
		port, err := parsePort(item)
		if err != nil {
			return err
		}
		ports.add(port)
	}
	return nil
}

func parsePort(value string) (uint16, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil || parsed == 0 {
		return 0, E.New("invalid port: ", value)
	}
	return uint16(parsed), nil
}

func globRegex(value string, domain bool) string {
	var builder strings.Builder
	builder.WriteByte('^')
	for _, character := range value {
		switch character {
		case '*':
			if domain {
				builder.WriteString("[^.]+")
			} else {
				builder.WriteString(".*")
			}
		case '?':
			if domain {
				builder.WriteString("[^.]")
			} else {
				builder.WriteByte('.')
			}
		default:
			builder.WriteString(regexp.QuoteMeta(string(character)))
		}
	}
	builder.WriteByte('$')
	return builder.String()
}

func (v *clashRuleValues) rules() []option.HeadlessRule {
	var rules []option.HeadlessRule
	appendRule := func(options option.DefaultHeadlessRule) {
		rules = append(rules, option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: options})
	}
	if len(v.domain.values) > 0 {
		appendRule(option.DefaultHeadlessRule{Domain: v.domain.values})
	}
	if len(v.domainSuffix.values) > 0 {
		appendRule(option.DefaultHeadlessRule{DomainSuffix: v.domainSuffix.values})
	}
	if len(v.domainKeyword.values) > 0 {
		appendRule(option.DefaultHeadlessRule{DomainKeyword: v.domainKeyword.values})
	}
	if len(v.domainRegex.values) > 0 {
		appendRule(option.DefaultHeadlessRule{DomainRegex: v.domainRegex.values})
	}
	if len(v.ipCIDR.values) > 0 {
		appendRule(option.DefaultHeadlessRule{IPCIDR: v.ipCIDR.values})
	}
	if len(v.sourceIPCIDR.values) > 0 {
		appendRule(option.DefaultHeadlessRule{SourceIPCIDR: v.sourceIPCIDR.values})
	}
	if len(v.port.values) > 0 || len(v.portRange.values) > 0 {
		appendRule(option.DefaultHeadlessRule{Port: v.port.values, PortRange: v.portRange.values})
	}
	if len(v.sourcePort.values) > 0 || len(v.sourcePortRange.values) > 0 {
		appendRule(option.DefaultHeadlessRule{SourcePort: v.sourcePort.values, SourcePortRange: v.sourcePortRange.values})
	}
	if len(v.processName.values) > 0 {
		appendRule(option.DefaultHeadlessRule{ProcessName: v.processName.values})
	}
	if len(v.processPath.values) > 0 {
		appendRule(option.DefaultHeadlessRule{ProcessPath: v.processPath.values})
	}
	if len(v.processPathRegex.values) > 0 {
		appendRule(option.DefaultHeadlessRule{ProcessPathRegex: v.processPathRegex.values})
	}
	if len(v.network.values) > 0 {
		appendRule(option.DefaultHeadlessRule{Network: v.network.values})
	}
	return rules
}
