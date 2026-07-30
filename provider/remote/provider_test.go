package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestNextProviderUpdateInterval(t *testing.T) {
	updateErr := errors.New("fetch failed")
	for _, testCase := range []struct {
		name     string
		interval time.Duration
		err      error
		expected time.Duration
	}{
		{"success", 6 * time.Hour, nil, 6 * time.Hour},
		{"failed", 6 * time.Hour, updateErr, time.Minute},
		{"failed short interval", 30 * time.Second, updateErr, 30 * time.Second},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if actual := nextProviderUpdateInterval(testCase.interval, testCase.err); actual != testCase.expected {
				t.Fatalf("unexpected interval: %s", actual)
			}
		})
	}
}

func TestProviderTagPrefixOptions(t *testing.T) {
	var remote option.ProviderRemoteOptions
	if err := json.Unmarshal([]byte(`{"tag_prefix":"remote: ","user_agent":"sing-box"}`), &remote); err != nil {
		t.Fatal(err)
	}
	var local option.ProviderLocalOptions
	if err := json.Unmarshal([]byte(`{"path":"subscription.txt","tag_prefix":"local: "}`), &local); err != nil {
		t.Fatal(err)
	}
	var inline option.ProviderInlineOptions
	if err := json.Unmarshal([]byte(`{"tag_prefix":"inline: "}`), &inline); err != nil {
		t.Fatal(err)
	}
	if remote.TagPrefix != "remote: " || remote.UserAgent != "sing-box" || local.TagPrefix != "local: " || inline.TagPrefix != "inline: " {
		t.Fatalf("unexpected provider options: %#v %q %q", remote, local.TagPrefix, inline.TagPrefix)
	}
}

func TestFetchProviderHonorsDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-request.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	remote := &ProviderRemote{url: server.URL, userAgent: "sing-box"}
	if _, err := remote.fetchProvider(ctx, server.Client()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled provider response was not canceled: %v", err)
	}
}
