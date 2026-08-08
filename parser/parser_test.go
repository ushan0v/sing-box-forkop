package parser

import (
	"context"
	"encoding/base64"
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestParseNaiveAndMieruSubscription(t *testing.T) {
	content := "naive+https://user:password@naive.example:443#Naive\n" +
		"mierus://user:password@mieru.example?profile=default&port=2012-2022&protocol=TCP#Mieru\n"
	outbounds, err := ParseSubscription(context.Background(), base64.StdEncoding.EncodeToString([]byte(content)))
	if err != nil {
		t.Fatal(err)
	}
	if len(outbounds) != 2 || outbounds[0].Type != C.TypeNaive || outbounds[1].Type != C.TypeMieru {
		t.Fatalf("unexpected subscription outbounds: %#v", outbounds)
	}
}
