package parser

import (
	"context"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/clash"
	"github.com/sagernet/sing-box/parser/raw"
	"github.com/sagernet/sing-box/parser/singbox"
	"github.com/sagernet/sing-box/parser/sip008"
	"github.com/sagernet/sing-box/parser/xray"
	E "github.com/sagernet/sing/common/exceptions"
)

var subscriptionParsers = []func(ctx context.Context, content string) ([]option.Outbound, error){
	xray.ParseXraySubscription,
	singbox.ParseBoxSubscription,
	clash.ParseClashSubscription,
	sip008.ParseSIP008Subscription,
	raw.ParseRawSubscription,
}

func ParseSubscription(ctx context.Context, content string) ([]option.Outbound, error) {
	var pErr error
	for _, parser := range subscriptionParsers {
		servers, err := parser(ctx, content)
		if len(servers) > 0 {
			return servers, nil
		}
		pErr = E.Errors(pErr, err)
	}
	return nil, E.Cause(pErr, "no servers found")
}
