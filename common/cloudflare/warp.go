package cloudflare

import (
	"context"
	"errors"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type GeneratedWARPProfile struct {
	ID         string `json:"id"`
	AuthToken  string `json:"auth_token"`
	PrivateKey string `json:"private_key"`
}

func GenerateWARPProfile(ctx context.Context) (GeneratedWARPProfile, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return GeneratedWARPProfile{}, err
	}
	profile, err := NewCloudflareApi().CreateProfile(ctx, privateKey.PublicKey().String())
	if err != nil {
		return GeneratedWARPProfile{}, err
	}
	return generatedWARPProfile(profile, privateKey)
}

func generatedWARPProfile(profile *CloudflareProfile, privateKey wgtypes.Key) (GeneratedWARPProfile, error) {
	if profile == nil || profile.ID == "" || profile.Token == "" {
		return GeneratedWARPProfile{}, errors.New("Cloudflare returned an incomplete WARP profile")
	}
	return GeneratedWARPProfile{
		ID:         profile.ID,
		AuthToken:  profile.Token,
		PrivateKey: privateKey.String(),
	}, nil
}
