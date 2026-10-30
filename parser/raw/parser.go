package raw

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/parser/link"
	"github.com/sagernet/sing-box/parser/subscription"
	F "github.com/sagernet/sing/common/format"
)

// ParseRawSubscription reads the plain list of share links most providers hand
// out, one link per line.
func ParseRawSubscription(_ context.Context, content string) (subscription.Result, error) {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	recognized := false
	for _, line := range lines {
		if strings.Contains(line, "://") {
			recognized = true
			break
		}
	}
	if !recognized {
		return subscription.Result{}, subscription.ErrUnrecognized
	}
	collector := subscription.NewCollector("share link")
	for index, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		outbound, err := link.ParseSubscriptionLink(line)
		if err != nil {
			collector.Skip("", linkLabel(index, line), safeLinkParseError(err))
			continue
		}
		collector.Add(outbound)
	}
	return collector.Result(), nil
}

// linkLabel names a link for a report without repeating the link itself, which
// carries the server address and its credentials.
func linkLabel(index int, link string) string {
	parsed, err := url.Parse(link)
	if err != nil {
		return F.ToString("subscription link ", index+1)
	}
	if parsed.Fragment != "" {
		return F.ToString("subscription link ", index+1, " (", parsed.Scheme, ", ", parsed.Fragment, ")")
	}
	return F.ToString("subscription link ", index+1, " (", parsed.Scheme, ")")
}

// safeLinkParseError strips the link out of a url.Error, so a report of a link
// that could not be read never repeats the credentials it carries.
func safeLinkParseError(err error) error {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return errors.New(urlError.Op + ": " + urlError.Err.Error())
	}
	return err
}
