package cloudflare

import (
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestGeneratedWARPProfile(t *testing.T) {
	privateKey := wgtypes.Key{1}
	generated, err := generatedWARPProfile(&CloudflareProfile{ID: "profile-id", Token: "auth-token"}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if generated.ID != "profile-id" || generated.AuthToken != "auth-token" || generated.PrivateKey != privateKey.String() {
		t.Fatalf("unexpected generated profile: %+v", generated)
	}
	if _, err = generatedWARPProfile(&CloudflareProfile{}, privateKey); err == nil {
		t.Fatal("incomplete profile accepted")
	}
}
