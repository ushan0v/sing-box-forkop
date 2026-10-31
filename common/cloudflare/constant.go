package cloudflare

const (
	// The same API as api.cloudflareclient.com, which ISPs in Russia block.
	ApiUrl     = "https://api.devices.cloudflare.com"
	ApiVersion = "v0a4471"
	KeyTypeWg  = "curve25519"
	TunTypeWg  = "wireguard"
)

var Headers = map[string]string{
	"User-Agent":        "WARP for Android",
	"CF-Client-Version": "a-6.35-4471",
	"Content-Type":      "application/json; charset=UTF-8",
	"Connection":        "Keep-Alive",
}
