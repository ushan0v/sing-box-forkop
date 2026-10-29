package clashapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestURLTestBandwidthAPIIsOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			node := &testBandwidthAPIOutbound{linkAPIOutbound: &linkAPIOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, "main/node", []string{"tcp"}, nil)}}
			manager := &linkAPIOutboundManager{outbounds: []adapter.Outbound{node}}
			ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
			outbound, err := group.NewURLTest(ctx, nil, log.NewNOPFactory().NewLogger("test"), "main/Auto #1", option.URLTestOutboundOptions{
				GroupCommonOption: option.GroupCommonOption{Outbounds: []string{node.Tag()}},
				BandwidthTest:     &option.URLTestBandwidthOptions{Enabled: enabled, URL: "http://download.example/file"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = outbound.(adapter.Lifecycle).Start(adapter.StartStateStart, adapter.NewScope(ctx, log.NewNOPFactory().NewLogger("test"))); err != nil {
				t.Fatal(err)
			}
			defer outbound.(interface{ Close() error }).Close()
			manager.outbounds = append(manager.outbounds, outbound)
			clashServer, err := NewServer(clashTestContext(ctx), log.NewNOPFactory(), option.ClashAPIOptions{})
			if err != nil {
				t.Fatal(err)
			}
			server := clashServer.(*Server)
			server.outbound = manager
			server.endpoint = &linkAPIEndpointManager{}
			request := httptest.NewRequest(http.MethodPost, "/proxies/main%2FAuto%20%231/bandwidth", nil)
			request.RemoteAddr = "127.0.0.1:1234"
			response := httptest.NewRecorder()
			server.httpServer.Handler.ServeHTTP(response, request)
			want := http.StatusBadRequest
			if enabled {
				want = http.StatusAccepted
			}
			if response.Code != want {
				t.Fatalf("got %d: %s", response.Code, response.Body)
			}
			if (outbound.(*group.URLTest).BandwidthStatus() != nil) != enabled {
				t.Fatal("disabled group exposes bandwidth status")
			}
		})
	}
}

// The worker can be canceled while a request is in progress, without touching
// production selectors or leaving its global probe slot occupied.
type testBandwidthAPIOutbound struct{ *linkAPIOutbound }

func (o *testBandwidthAPIOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
