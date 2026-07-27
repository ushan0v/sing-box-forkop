package singbox

import (
	"context"

	providerAdapter "github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

type _SingBoxDocument struct {
	Outbounds   []option.Outbound `json:"outbounds"`
	InvalidTags map[string]bool   `json:"-"`
}
type SingBoxDocument _SingBoxDocument

func (o *SingBoxDocument) UnmarshalJSONContext(ctx context.Context, inputContent []byte) error {
	var content badjson.JSONObject
	err := content.UnmarshalJSONContext(ctx, inputContent)
	if err != nil {
		return err
	}
	outbounds, ok := content.Get("outbounds")
	if !ok {
		return E.New("missing outbounds in sing-box configuration")
	}
	rawOutbounds, ok := outbounds.(badjson.JSONArray)
	if !ok {
		return E.New("outbounds in sing-box configuration is not an array")
	}
	o.InvalidTags = make(map[string]bool)
	for _, rawOutbound := range rawOutbounds {
		outboundObject, ok := rawOutbound.(*badjson.JSONObject)
		if !ok {
			continue
		}
		discard := func() {
			tagValue, loaded := outboundObject.Get("tag")
			tag, valid := tagValue.(string)
			if loaded && valid && tag != "" {
				o.InvalidTags[tag] = true
			}
		}
		typeValue, loaded := outboundObject.Get("type")
		if !loaded {
			continue
		}
		outboundType, ok := typeValue.(string)
		if !ok {
			continue
		}
		switch outboundType {
		case C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeSelector, C.TypeURLTest, C.TypeFallback:
			discard()
			continue
		}
		outboundContent, err := outboundObject.MarshalJSONContext(ctx)
		if err != nil {
			discard()
			continue
		}
		var outbound option.Outbound
		err = json.UnmarshalContext(ctx, outboundContent, &outbound)
		if err != nil {
			discard()
			continue
		}
		o.Outbounds = append(o.Outbounds, outbound)
	}
	o.Outbounds = providerAdapter.FilterInvalidOutbounds(o.Outbounds, o.InvalidTags)
	return nil
}

func ParseBoxSubscription(ctx context.Context, content string) ([]option.Outbound, error) {
	options, err := json.UnmarshalExtendedContext[SingBoxDocument](ctx, []byte(content))
	if err != nil {
		return nil, err
	}
	if len(options.Outbounds) == 0 {
		return nil, E.New("no servers found")
	}
	return options.Outbounds, nil
}
