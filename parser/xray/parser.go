package xray

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	providerAdapter "github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func ParseXraySubscription(_ context.Context, content string) ([]option.Outbound, error) {
	var documents []json.RawMessage
	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &documents); err != nil {
			return nil, err
		}
	} else {
		documents = []json.RawMessage{json.RawMessage(trimmed)}
	}
	taken := make(map[string]bool)
	invalidTags := make(map[string]bool)
	var outbounds []option.Outbound
	for index, rawDocument := range documents {
		var config document
		if json.Unmarshal(rawDocument, &config) != nil {
			continue
		}
		outbounds = append(outbounds, parseDocument(config, index, taken, invalidTags)...)
	}
	outbounds = providerAdapter.FilterInvalidOutbounds(outbounds, invalidTags)
	if len(outbounds) == 0 {
		return nil, E.New("no Xray servers found")
	}
	return outbounds, nil
}

func parseDocument(config document, documentIndex int, taken, invalidTags map[string]bool) []option.Outbound {
	nodes := make([]parsedOutbound, 0, len(config.Outbounds))
	for index, rawOutbound := range config.Outbounds {
		node, loaded := parseSourceOutbound(rawOutbound, "server-"+strconv.Itoa(documentIndex+1)+"-"+strconv.Itoa(index+1))
		if !loaded {
			var source struct {
				Tag string `json:"tag"`
			}
			if json.Unmarshal(rawOutbound, &source) == nil && source.Tag != "" {
				invalidTags[source.Tag] = true
			}
			continue
		}
		node.outbound.Tag = uniqueTag(node.outbound.Tag, taken)
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return nil
	}
	tagMap := make(map[string]string, len(nodes))
	for _, node := range nodes {
		if _, exists := tagMap[node.sourceTag]; !exists {
			tagMap[node.sourceTag] = node.outbound.Tag
		}
	}
	for index := range nodes {
		if nodes[index].detour == "" {
			continue
		}
		detour, loaded := tagMap[nodes[index].detour]
		if !loaded {
			continue
		}
		dialer := nodes[index].outbound.Options.(option.DialerOptionsWrapper)
		dialerOptions := dialer.TakeDialerOptions()
		dialerOptions.Detour = detour
		dialer.ReplaceDialerOptions(dialerOptions)
	}
	result := make([]option.Outbound, len(nodes))
	for index, node := range nodes {
		result[index] = node.outbound
	}
	return result
}

func uniqueTag(base string, taken map[string]bool) string {
	if base == "" {
		base = "server"
	}
	if !taken[base] {
		taken[base] = true
		return base
	}
	for suffix := 1; ; suffix++ {
		candidate := base + "-" + strconv.Itoa(suffix)
		if !taken[candidate] {
			taken[candidate] = true
			return candidate
		}
	}
}
