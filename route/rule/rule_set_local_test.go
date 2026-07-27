package rule

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func TestDamagedLocalRuleSetFailsStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "damaged.list")
	if err := os.WriteFile(path, []byte("<html>denied</html>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewLocalRuleSet(context.Background(), logger.NOP(), option.RuleSet{
		Type:   C.RuleSetTypeLocal,
		Tag:    "damaged",
		Format: C.RuleSetFormatAuto,
		LocalOptions: option.LocalRuleSet{
			Path: path,
		},
	})
	if err == nil {
		t.Fatal("damaged local rule-set was accepted")
	}
}
