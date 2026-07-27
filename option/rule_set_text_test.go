package option

import (
	"encoding/json"
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestTextRuleSetOptions(t *testing.T) {
	var local RuleSet
	if err := json.Unmarshal([]byte(`{"type":"local","tag":"local-list","path":"/etc/forkop/list.txt"}`), &local); err != nil {
		t.Fatal(err)
	}
	if local.Format != C.RuleSetFormatText {
		t.Fatalf("expected inferred text format, got %q", local.Format)
	}

	var remote RuleSet
	if err := json.Unmarshal([]byte(`{"type":"remote","tag":"remote-list","format":"text","url":"https://example.com/list","download_detour":"proxy","update_interval":"1h"}`), &remote); err != nil {
		t.Fatal(err)
	}
	if remote.Format != C.RuleSetFormatText || remote.RemoteOptions.DownloadDetour != "proxy" {
		t.Fatalf("unexpected remote text rule-set: %+v", remote)
	}
}

func TestYAMLAndAutoRuleSetOptions(t *testing.T) {
	for path, format := range map[string]string{
		"/etc/forkop/list.yaml": C.RuleSetFormatYAML,
		"/etc/forkop/list.yml":  C.RuleSetFormatYAML,
	} {
		var ruleSet RuleSet
		if err := json.Unmarshal([]byte(`{"type":"local","tag":"list","path":"`+path+`"}`), &ruleSet); err != nil {
			t.Fatal(err)
		}
		if ruleSet.Format != format {
			t.Fatalf("expected %q for %q, got %q", format, path, ruleSet.Format)
		}
	}
	var ruleSet RuleSet
	if err := json.Unmarshal([]byte(`{"type":"remote","tag":"list","format":"auto","url":"https://example.com/list"}`), &ruleSet); err != nil {
		t.Fatal(err)
	}
	if ruleSet.Format != C.RuleSetFormatAuto {
		t.Fatalf("expected auto format, got %q", ruleSet.Format)
	}
}
