package parser

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/clash"
	"github.com/sagernet/sing-box/parser/raw"
	"github.com/sagernet/sing-box/parser/singbox"
	"github.com/sagernet/sing-box/parser/sip008"
	"github.com/sagernet/sing-box/parser/subscription"
	"github.com/sagernet/sing-box/parser/xray"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

var subscriptionParsers = []func(ctx context.Context, content string) (subscription.Result, error){
	xray.ParseXraySubscription,
	singbox.ParseBoxSubscription,
	sip008.ParseSIP008Subscription,
	clash.ParseClashSubscription,
	raw.ParseRawSubscription,
}

// ParseSubscription reads a subscription in whichever format it turns out to be
// written in. Each parser first answers whether the content is its own format,
// and only the one that recognises it reports on the servers inside.
func ParseSubscription(ctx context.Context, content string) (subscription.Result, error) {
	// A provider is free to wrap any format in base64, not only a list of links.
	if decoded, isEncoded := subscription.DecodeBase64(content); isEncoded {
		content = decoded
	}
	if isEmptySubscription(content) {
		return subscription.Result{}, E.New("the subscription lists no server")
	}
	for _, parse := range subscriptionParsers {
		result, err := parse(ctx, content)
		if errors.Is(err, subscription.ErrUnrecognized) {
			continue
		}
		if err != nil {
			return result, err
		}
		result = resolveChains(result)
		if len(result.Outbounds) == 0 {
			// A subscription that lists no server at all and one whose every
			// server had to be left out are different answers to give: the first
			// is what a provider hands out when the account has nothing on it,
			// the second means the servers are there and could not be read.
			if len(result.Skipped) == 0 {
				return result, E.New("the ", result.Format, " subscription lists no server")
			}
			return result, E.New("no server of the ", result.Format, " subscription could be imported")
		}
		if notes := placeholderNotes(result.Outbounds); notes != nil {
			result.Outbounds = nil
			return result, E.New("the ", result.Format, " subscription lists no server, only notes: ", strings.Join(notes, "; "))
		}
		return result, nil
	}
	return subscription.Result{}, E.New("unrecognized subscription format")
}

// placeholderNotes returns the names of the servers when every one is at the unspecified address:
// Remnawave sends such entries in place of the servers, each name a line of its notice.
func placeholderNotes(outbounds []option.Outbound) []string {
	notes := make([]string, 0, len(outbounds))
	for _, outbound := range outbounds {
		server, hasServer := outbound.Options.(option.ServerOptionsWrapper)
		if !hasServer || !server.TakeServerOptions().Build().Addr.IsUnspecified() {
			return nil
		}
		notes = append(notes, outbound.Tag)
	}
	return notes
}

// isEmptySubscription reports whether the content carries no server at all, as a
// panel answers for an account that has run out, rather than a format nobody
// recognises: an empty document names no format for a parser to recognise.
func isEmptySubscription(content string) bool {
	trimmed := strings.TrimSpace(content)
	switch {
	case trimmed == "":
		return true
	case strings.HasPrefix(trimmed, "["):
		var documents []json.RawMessage
		return json.Unmarshal([]byte(trimmed), &documents) == nil && len(documents) == 0
	case strings.HasPrefix(trimmed, "{"):
		var document map[string]json.RawMessage
		return json.Unmarshal([]byte(trimmed), &document) == nil && len(document) == 0
	}
	return false
}

// resolveChains drops the servers that dial through an entry the parser had to
// refuse. Importing such a server would connect somewhere other than where the
// subscription said, so it is left out with the entry it depended on.
func resolveChains(result subscription.Result) subscription.Result {
	if len(result.Refused) == 0 {
		return result
	}
	outbounds, broken := provider.FilterInvalidOutboundsWithSkipped(result.Outbounds, result.Refused)
	result.Outbounds = outbounds
	for _, outbound := range broken {
		result.Skipped = append(result.Skipped, subscription.Skipped{
			Label:  F.ToString("server ", outbound.Tag),
			Reason: E.New("dials through a server that could not be imported"),
		})
	}
	return result
}
