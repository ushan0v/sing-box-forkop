package fallback

import (
	"context"
	"sync"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

type testTransport struct {
	delay    time.Duration
	rcode    int
	id       uint16
	started  chan<- struct{}
	ready    <-chan struct{}
	waitCtx  bool
	startMu  sync.Mutex
	startOne bool
}

func (t *testTransport) Type() string                   { return C.DNSTypeUDP }
func (t *testTransport) Tag() string                    { return "test" }
func (t *testTransport) Dependencies() []string         { return nil }
func (t *testTransport) Start(adapter.StartStage) error { return nil }
func (t *testTransport) Close() error                   { return nil }
func (t *testTransport) Reset()                         {}

func (t *testTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.startMu.Lock()
	if !t.startOne {
		t.startOne = true
		if t.started != nil {
			t.started <- struct{}{}
		}
	}
	t.startMu.Unlock()
	if t.ready != nil {
		select {
		case <-t.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if t.waitCtx {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	timer := time.NewTimer(t.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return &mDNS.Msg{MsgHdr: mDNS.MsgHdr{Id: t.id, Rcode: t.rcode}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestParallelUsesFirstResponseAndStartsAllServers(t *testing.T) {
	started := make(chan struct{}, 2)
	ready := make(chan struct{})
	servers := []adapter.DNSTransport{
		&testTransport{delay: 40 * time.Millisecond, id: 1, started: started, ready: ready},
		&testTransport{delay: 5 * time.Millisecond, id: 2, started: started, ready: ready},
	}
	strategy, err := CreateStrategy("parallel", servers, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan *mDNS.Msg, 1)
	go func() {
		response, _ := strategy(context.Background(), &mDNS.Msg{})
		result <- response
	}()
	for range servers {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("parallel strategy did not start every server")
		}
	}
	close(ready)
	select {
	case response := <-result:
		if response == nil || response.Id != 2 {
			t.Fatalf("parallel strategy did not return the fastest response: %#v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("parallel strategy did not return")
	}
}

func TestFallbackSkipsUnusableResponses(t *testing.T) {
	for _, strategyName := range []string{"parallel", "sequential"} {
		for _, rcode := range []int{mDNS.RcodeServerFailure, mDNS.RcodeRefused} {
			t.Run(strategyName+"/"+mDNS.RcodeToString[rcode], func(t *testing.T) {
				servers := []adapter.DNSTransport{
					&testTransport{delay: time.Millisecond, rcode: rcode},
					&testTransport{delay: 5 * time.Millisecond, rcode: mDNS.RcodeSuccess},
				}
				strategy, err := CreateStrategy(strategyName, servers, nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := strategy(context.Background(), &mDNS.Msg{})
				if err != nil || response == nil || response.Rcode != mDNS.RcodeSuccess {
					t.Fatalf("%s strategy accepted or returned unusable response: response=%v err=%v", strategyName, response, err)
				}
			})
		}
	}
}

func TestSequentialSharesDeadlineAcrossServers(t *testing.T) {
	servers := []adapter.DNSTransport{
		&testTransport{waitCtx: true},
		&testTransport{rcode: mDNS.RcodeSuccess},
	}
	strategy, err := CreateStrategy("sequential", servers, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	response, err := strategy(ctx, &mDNS.Msg{})
	if err != nil || response == nil || response.Rcode != mDNS.RcodeSuccess {
		t.Fatalf("sequential strategy did not reach the next server: response=%v err=%v", response, err)
	}
}
