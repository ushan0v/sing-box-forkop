package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestNormalizeUserAgents(t *testing.T) {
	configured := []string{" happ ", "", "happ", "sing-box"}
	expected := []string{"happ", "sing-box"}
	if actual := normalizeUserAgents(configured); !reflect.DeepEqual(actual, expected) {
		t.Fatalf("unexpected user agents: %v", actual)
	}
	if actual := preferredUserAgents(expected, "sing-box"); !reflect.DeepEqual(actual, []string{"sing-box", "happ"}) {
		t.Fatalf("unexpected preferred order: %v", actual)
	}
}

func TestProviderUserAgentAcceptsStringOrArray(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		content  string
		expected []string
	}{
		{"string", `{"user_agent":"happ"}`, []string{"happ"}},
		{"array", `{"user_agent":["happ","sing-box"]}`, []string{"happ", "sing-box"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var options option.ProviderRemoteOptions
			if err := json.Unmarshal([]byte(testCase.content), &options); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual([]string(options.UserAgent), testCase.expected) {
				t.Fatalf("unexpected user agents: %v", options.UserAgent)
			}
		})
	}
}

func TestProviderTagPrefixOptions(t *testing.T) {
	var remote option.ProviderRemoteOptions
	if err := json.Unmarshal([]byte(`{"tag_prefix":"remote: "}`), &remote); err != nil {
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
	if remote.TagPrefix != "remote: " || local.TagPrefix != "local: " || inline.TagPrefix != "inline: " {
		t.Fatalf("unexpected provider tag prefixes: %q %q %q", remote.TagPrefix, local.TagPrefix, inline.TagPrefix)
	}
}

func TestFetchWithUserAgentHonorsDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-request.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	remote := &ProviderRemote{url: server.URL}
	if _, err := remote.fetchWithUserAgent(ctx, server.Client(), "sing-box", false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled provider response was not canceled: %v", err)
	}
}
