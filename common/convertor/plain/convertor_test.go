package plain

import (
	"slices"
	"strings"
	"testing"
)

func TestToOptionsMixedList(t *testing.T) {
	rules, err := ToOptions(strings.NewReader("\ufeff# comment\r\n" +
		"Example.COM\r\n" +
		".Sub.Example.COM // suffix comment\r\n" +
		"пример.рф\r\n" +
		"192.0.2.1\r\n" +
		"198.51.100.23/24 # prefix comment\r\n" +
		"2001:db8::1\r\n" +
		"Example.COM\r\n" +
		"https://invalid.example/path\r\n" +
		"999.999.999.999\r\n" +
		"*.invalid.example\r\n" +
		"invalid_domain\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected domain and IP rules, got %d", len(rules))
	}
	wantDomains := []string{"example.com", ".sub.example.com", "xn--e1afmkfd.xn--p1ai"}
	if !slices.Equal(rules[0].DefaultOptions.DomainSuffix, wantDomains) {
		t.Fatalf("unexpected domains: %v", rules[0].DefaultOptions.DomainSuffix)
	}
	wantPrefixes := []string{"192.0.2.1", "198.51.100.0/24", "2001:db8::1"}
	if !slices.Equal(rules[1].DefaultOptions.IPCIDR, wantPrefixes) {
		t.Fatalf("unexpected prefixes: %v", rules[1].DefaultOptions.IPCIDR)
	}
}

func TestToOptionsRejectsEmptyList(t *testing.T) {
	_, err := ToOptions(strings.NewReader("# comment\nhttps://invalid.example/path\n999.999.999.999\n"))
	if err == nil {
		t.Fatal("expected an empty text rule-set error")
	}
}
