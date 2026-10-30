package provider

import (
	"crypto/sha256"
	"encoding/base64"
	stdjson "encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/sagernet/sing-box/adapter"
	boxCommon "github.com/sagernet/sing-box/common"
	"github.com/sagernet/sing-box/parser/subscription"
)

const providerCacheMetadataPrefix = "# sing-box-provider-metadata:"

var subscriptionMetadataKeys = []string{
	"profile-title",
	"subscription-userinfo",
	"profile-web-page-url",
	"support-url",
	"announce",
	"announce-url",
	"subscription-refill-date",
	"content-disposition",
}

type providerCacheMetadata struct {
	Version  uint8                        `json:"version"`
	Info     adapter.SubscriptionInfo     `json:"subscription_info"`
	Metadata adapter.SubscriptionMetadata `json:"subscription_metadata"`
}

const providerCacheVersion = 1

func prepareSubscriptionContent(rawContent string, headerValues map[string]string) (string, adapter.SubscriptionInfo, adapter.SubscriptionMetadata) {
	content, _ := boxCommon.DecodeBase64URLSafe(rawContent)
	values := make(map[string]string)
	firstLine, remaining := getFirstLine(content)
	if _, loaded := parseInfo(strings.TrimSpace(firstLine)); loaded {
		values["subscription-userinfo"] = strings.TrimSpace(firstLine)
		content, _ = boxCommon.DecodeBase64URLSafe(remaining)
	}
	for key, value := range headerValues {
		values[key] = value
	}
	info, metadata := mergeSubscriptionData(adapter.SubscriptionInfo{}, adapter.SubscriptionMetadata{}, values)
	return content, info, metadata
}

func metadataHeaderValues(header http.Header) map[string]string {
	values := make(map[string]string)
	for _, key := range subscriptionMetadataKeys {
		if value := strings.TrimSpace(header.Get(key)); value != "" {
			values[key] = value
		}
	}
	return values
}

func mergeSubscriptionData(info adapter.SubscriptionInfo, metadata adapter.SubscriptionMetadata, values map[string]string) (adapter.SubscriptionInfo, adapter.SubscriptionMetadata) {
	if value, loaded := values["subscription-userinfo"]; loaded {
		info, _ = parseInfo(value)
	}
	if value, loaded := values["profile-title"]; loaded {
		metadata.Title = cleanMetadataText(value, 120, true)
	}
	if value, loaded := values["profile-web-page-url"]; loaded {
		metadata.WebPageURL = cleanMetadataURL(value)
	}
	if value, loaded := values["support-url"]; loaded {
		metadata.SupportURL = cleanMetadataURL(value)
	}
	if value, loaded := values["announce"]; loaded {
		metadata.Announce = cleanMetadataText(value, 500, true)
	}
	if value, loaded := values["announce-url"]; loaded {
		metadata.AnnounceURL = cleanMetadataURL(value)
	}
	if value, loaded := values["subscription-refill-date"]; loaded {
		metadata.RefillDate, _ = parseMetadataNumber(value)
	}
	if value, loaded := values["content-disposition"]; loaded {
		metadata.FileName = contentDispositionFileName(value)
	}
	return info, metadata
}

// deviceRefusal tells why Remnawave did not take this device: it answers such a request with
// status 200, these headers, and nothing or a list of notes in place of the servers.
func deviceRefusal(header http.Header) string {
	refused := func(name string) bool { return strings.EqualFold(header.Get(name), "true") }
	switch {
	case refused("x-hwid-max-devices-reached"):
		return "the subscription's limit of devices is reached"
	case refused("x-hwid-not-supported"):
		return "it requires the X-HWID header"
	case refused("x-hwid-limit"):
		return "it did not take the X-HWID of this device"
	}
	return ""
}

func parseInfo(value string) (adapter.SubscriptionInfo, bool) {
	var info adapter.SubscriptionInfo
	loaded := false
	for _, field := range strings.Split(value, ";") {
		key, rawNumber, found := strings.Cut(field, "=")
		if !found {
			continue
		}
		number, valid := parseMetadataNumber(rawNumber)
		if !valid {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "upload":
			info.Upload = number
		case "download":
			info.Download = number
		case "total":
			info.Total = number
		case "expire":
			info.Expire = number
		default:
			continue
		}
		loaded = true
	}
	return info, loaded
}

func parseMetadataNumber(value string) (int64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	number, err := strconv.ParseInt(value, 10, 64)
	return number, err == nil
}

func cleanMetadataText(value string, maximum int, decodeBase64 bool) string {
	value = strings.TrimSpace(value)
	if decodeBase64 && len(value) >= 7 && strings.EqualFold(value[:7], "base64:") {
		decoded, loaded := subscription.DecodeBase64(value[7:])
		if !loaded {
			return ""
		}
		value = decoded
	}
	var builder strings.Builder
	lastSpace := true
	length := 0
	for _, character := range strings.ToValidUTF8(value, "") {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			if !lastSpace && length < maximum {
				builder.WriteByte(' ')
				lastSpace = true
				length++
			}
			continue
		}
		if length >= maximum {
			break
		}
		builder.WriteRune(character)
		lastSpace = false
		length++
	}
	return strings.TrimSpace(builder.String())
}

func cleanMetadataURL(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 2048 || strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsControl(character) || unicode.IsSpace(character)
	}) >= 0 {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	return value
}

func contentDispositionFileName(value string) string {
	_, parameters, err := mime.ParseMediaType(value)
	fileName := parameters["filename"]
	if err != nil || fileName == "" {
		for _, parameter := range strings.Split(value, ";") {
			key, candidate, loaded := strings.Cut(parameter, "=")
			if loaded && strings.EqualFold(strings.TrimSpace(key), "filename") {
				fileName = strings.Trim(strings.TrimSpace(candidate), `"`)
				break
			}
		}
	}
	fileName = cleanMetadataText(fileName, 120, false)
	return strings.NewReplacer("/", "_", "\\", "_").Replace(fileName)
}

// providerCacheIdentity identifies the request a cached subscription came
// from, so a provider whose URL or headers changed refetches instead of
// restoring content from the old source.
func providerCacheIdentity(source string, userAgent string, headers http.Header) []byte {
	identity, _ := stdjson.Marshal(struct {
		Source    string      `json:"source"`
		UserAgent string      `json:"user_agent"`
		Headers   http.Header `json:"headers"`
	}{source, userAgent, headers})
	hash := sha256.Sum256(identity)
	return hash[:]
}

func encodeProviderCacheMetadata(info adapter.SubscriptionInfo, metadata adapter.SubscriptionMetadata) string {
	content, _ := stdjson.Marshal(providerCacheMetadata{Version: providerCacheVersion, Info: info, Metadata: metadata})
	return providerCacheMetadataPrefix + base64.RawURLEncoding.EncodeToString(content)
}

func decodeProviderCacheContent(content string) (string, adapter.SubscriptionInfo, adapter.SubscriptionMetadata, bool) {
	firstLine, remaining := getFirstLine(content)
	if !strings.HasPrefix(firstLine, providerCacheMetadataPrefix) {
		return "", adapter.SubscriptionInfo{}, adapter.SubscriptionMetadata{}, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(firstLine, providerCacheMetadataPrefix)))
	if err != nil {
		return "", adapter.SubscriptionInfo{}, adapter.SubscriptionMetadata{}, false
	}
	var cached providerCacheMetadata
	if stdjson.Unmarshal(decoded, &cached) != nil || cached.Version != providerCacheVersion {
		return "", adapter.SubscriptionInfo{}, adapter.SubscriptionMetadata{}, false
	}
	return remaining, cached.Info, cached.Metadata, true
}
