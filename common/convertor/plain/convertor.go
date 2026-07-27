package plain

import (
	"bufio"
	"io"
	"net/netip"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/idna"
)

// ToOptions converts a plain list containing domain suffixes, IP addresses and
// CIDR prefixes into independent headless rules. Invalid lines are ignored.
func ToOptions(reader io.Reader) ([]option.HeadlessRule, error) {
	return toOptions(reader, false)
}

// ToOptionsStrict rejects invalid non-comment lines instead of ignoring them.
func ToOptionsStrict(reader io.Reader) ([]option.HeadlessRule, error) {
	return toOptions(reader, true)
}

func toOptions(reader io.Reader, strict bool) ([]option.HeadlessRule, error) {
	var domains, prefixes []string
	domainSet := make(map[string]struct{})
	prefixSet := make(map[string]struct{})
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := trimLine(scanner.Text())
		if line == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(line); err == nil && prefix.Addr().Zone() == "" {
			addUnique(&prefixes, prefixSet, prefix.Masked().String())
			continue
		}
		if address, err := netip.ParseAddr(line); err == nil && address.Zone() == "" {
			addUnique(&prefixes, prefixSet, address.String())
			continue
		}
		if domain, loaded := NormalizeDomain(line); loaded {
			addUnique(&domains, domainSet, domain)
			continue
		}
		if strict {
			return nil, E.New("invalid text rule-set item: ", line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, E.Cause(err, "read text rule-set")
	}
	var rules []option.HeadlessRule
	if len(domains) > 0 {
		rules = append(rules, option.HeadlessRule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultHeadlessRule{
				DomainSuffix: domains,
			},
		})
	}
	if len(prefixes) > 0 {
		rules = append(rules, option.HeadlessRule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultHeadlessRule{
				IPCIDR: prefixes,
			},
		})
	}
	if len(rules) == 0 {
		return nil, E.New("empty text rule-set")
	}
	return rules, nil
}

func trimLine(line string) string {
	line = strings.TrimPrefix(line, "\ufeff")
	end := len(line)
	for _, marker := range []string{"#", "//"} {
		if index := strings.Index(line[:end], marker); index >= 0 {
			end = index
		}
	}
	return strings.TrimSpace(line[:end])
}

func NormalizeDomain(value string) (string, bool) {
	hasLeadingDot := strings.HasPrefix(value, ".")
	if hasLeadingDot {
		value = value[1:]
	}
	if value == "" || strings.HasSuffix(value, ".") {
		return "", false
	}
	value, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", false
	}
	value = strings.ToLower(value)
	if !validDomain(value) {
		return "", false
	}
	if hasLeadingDot {
		value = "." + value
	}
	return value, true
}

func validDomain(value string) bool {
	if len(value) > 253 {
		return false
	}
	hasLetter := false
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range []byte(label) {
			isLetter := character >= 'a' && character <= 'z'
			if isLetter {
				hasLetter = true
			}
			if !isLetter && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return hasLetter
}

func addUnique(values *[]string, seen map[string]struct{}, value string) {
	if _, loaded := seen[value]; loaded {
		return
	}
	seen[value] = struct{}{}
	*values = append(*values, value)
}
