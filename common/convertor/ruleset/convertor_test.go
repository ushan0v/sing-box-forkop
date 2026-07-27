package ruleset

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestReadClashYAML(t *testing.T) {
	content := `payload:
  - example.com
  - +.suffix.example
  - .subdomains.example
  - '*.one-level.example'
  - 192.0.2.7
  - 2001:db8::/32
  - DOMAIN-KEYWORD,tracker
  - DOMAIN-REGEX,^api[0-9]+\.example$
  - IP-CIDR,198.51.100.7/24,no-resolve
  - SRC-IP-CIDR,10.0.0.0/8
  - DST-PORT,80/443/1000-1002
  - PROCESS-NAME,curl
  - NETWORK,TCP/UDP
`
	ruleSet, format, err := Read(strings.NewReader(content), C.RuleSetFormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if format != C.RuleSetFormatYAML {
		t.Fatalf("expected yaml detection, got %q", format)
	}
	if len(ruleSet.Rules) != 9 {
		t.Fatalf("expected 9 grouped rules, got %d", len(ruleSet.Rules))
	}
	if !slices.Equal(ruleSet.Rules[0].DefaultOptions.Domain, []string{"example.com"}) {
		t.Fatalf("unexpected exact domains: %v", ruleSet.Rules[0].DefaultOptions.Domain)
	}
	if !slices.Equal(ruleSet.Rules[1].DefaultOptions.DomainSuffix, []string{"suffix.example", ".subdomains.example"}) {
		t.Fatalf("unexpected suffixes: %v", ruleSet.Rules[1].DefaultOptions.DomainSuffix)
	}
	if !slices.Equal(ruleSet.Rules[4].DefaultOptions.IPCIDR, []string{"192.0.2.7", "2001:db8::/32", "198.51.100.0/24"}) {
		t.Fatalf("unexpected destination prefixes: %v", ruleSet.Rules[4].DefaultOptions.IPCIDR)
	}
	if !slices.Equal(ruleSet.Rules[6].DefaultOptions.Port, []uint16{80, 443}) ||
		!slices.Equal(ruleSet.Rules[6].DefaultOptions.PortRange, []string{"1000:1002"}) {
		t.Fatalf("unexpected destination ports: %+v", ruleSet.Rules[6].DefaultOptions)
	}
}

func TestAutoDetectionRejectsDamagedInput(t *testing.T) {
	for name, content := range map[string]string{
		"json": `{not-json`,
		"yaml": "payload:\n  - DOMAIN-SUFFIX\n  - 42\n",
		"text": "example.com\n<html>denied</html>\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Read(strings.NewReader(content), C.RuleSetFormatAuto); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestAutoDetectionIgnoresExtensionAssumptions(t *testing.T) {
	if format := detectFormat([]byte("\xef\xbb\xbf  # list\nbehavior: domain\npayload:\n  - example.com\n")); format != C.RuleSetFormatYAML {
		t.Fatalf("expected yaml, got %q", format)
	}
	if format := detectFormat([]byte{'S', 'R', 'S', 1}); format != C.RuleSetFormatBinary {
		t.Fatalf("expected binary, got %q", format)
	}
	if format := detectFormat([]byte("// source comment\n{\"version\": 4, \"rules\": []}")); format != C.RuleSetFormatSource {
		t.Fatalf("expected commented source, got %q", format)
	}
	for _, content := range []string{"payload: [example.com]\n", "[example.com]\n"} {
		ruleSet, format, err := Read(strings.NewReader(content), C.RuleSetFormatAuto)
		if err != nil {
			t.Fatal(err)
		}
		if format != C.RuleSetFormatYAML || len(ruleSet.Rules) != 1 {
			t.Fatalf("unexpected flow-style result: format=%q rules=%d", format, len(ruleSet.Rules))
		}
	}
}

func TestClashWildcardAndCommaSeparatedPorts(t *testing.T) {
	ruleSet, _, err := Read(strings.NewReader("payload:\n  - DOMAIN-WILDCARD,foo*.example\n  - DST-PORT,80/443\n"), C.RuleSetFormatYAML)
	if err != nil {
		t.Fatal(err)
	}
	if ruleSet.Rules[0].DefaultOptions.DomainRegex[0] != `^foo.*\.example$` {
		t.Fatalf("unexpected classical wildcard: %v", ruleSet.Rules[0].DefaultOptions.DomainRegex)
	}
	if !slices.Equal(ruleSet.Rules[1].DefaultOptions.Port, []uint16{80, 443}) {
		t.Fatalf("unexpected comma-separated ports: %v", ruleSet.Rules[1].DefaultOptions.Port)
	}
}

func TestClashYAMLRejectsUnsupportedRule(t *testing.T) {
	for name, content := range map[string]string{
		"unsupported":  "payload:\n  - GEOIP,CN\n",
		"full config":  "rules:\n  - DOMAIN,example.com,PROXY\n",
		"policy field": "payload:\n  - DOMAIN,example.com,PROXY\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Read(strings.NewReader(content), C.RuleSetFormatYAML); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestAutoReadsEverySupportedFormat(t *testing.T) {
	plainRuleSet := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{
			DomainSuffix: []string{"example.com"},
		},
	}}}
	var binary bytes.Buffer
	if err := srs.Write(&binary, plainRuleSet, C.RuleSetVersionCurrent); err != nil {
		t.Fatal(err)
	}
	for name, testCase := range map[string]struct {
		content []byte
		format  string
	}{
		"binary": {binary.Bytes(), C.RuleSetFormatBinary},
		"source": {[]byte(`{"version":4,"rules":[{"domain_suffix":["example.com"]}]}`), C.RuleSetFormatSource},
		"text":   {[]byte("example.com\n"), C.RuleSetFormatText},
		"yaml":   {[]byte("payload:\n  - example.com\n"), C.RuleSetFormatYAML},
	} {
		t.Run(name, func(t *testing.T) {
			ruleSet, format, err := Read(bytes.NewReader(testCase.content), C.RuleSetFormatAuto)
			if err != nil {
				t.Fatal(err)
			}
			if format != testCase.format || len(ruleSet.Rules) == 0 {
				t.Fatalf("unexpected result: format=%q rules=%d", format, len(ruleSet.Rules))
			}
		})
	}
}
