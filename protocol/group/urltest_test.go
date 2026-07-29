package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/service"
)

func TestURLTestGroupHistoryIsIsolated(t *testing.T) {
	sharedHistory := urltest.NewHistoryStorage()
	ctx := service.ContextWithPtr(context.Background(), sharedHistory)
	first, err := NewURLTestGroup(ctx, nil, nil, nil, "", 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewURLTestGroup(ctx, nil, nil, nil, "", 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	first.storeHistory("node", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	second.storeHistory("node", &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	second.deleteHistory("node")

	if history := first.history.LoadURLTestHistory("node"); history == nil || history.Delay != 10 {
		t.Fatal("one URLTest group deleted another group's history")
	}
	if second.history.LoadURLTestHistory("node") != nil {
		t.Fatal("failed URLTest group kept its local history")
	}
	if history := sharedHistory.LoadURLTestHistory("node"); history == nil || history.Delay != 20 {
		t.Fatal("failed URLTest group deleted the last shared dashboard result")
	}
}
