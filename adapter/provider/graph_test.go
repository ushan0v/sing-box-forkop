package provider

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestPrepareProviderGraph(t *testing.T) {
	source := []option.Outbound{
		{
			Type: C.TypeVLESS,
			Tag:  "primary",
			Options: &option.VLESSOutboundOptions{
				DialerOptions: option.DialerOptions{Detour: "hop"},
			},
		},
		{Type: C.TypeVLESS, Tag: "hop", Options: &option.VLESSOutboundOptions{}},
	}

	prepared, err := prepareOutbounds("subscription", source, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared) != 2 || prepared[0].tag != "subscription/hop" || prepared[1].tag != "subscription/primary" {
		t.Fatalf("unexpected dependency order: %v", preparedTags(prepared))
	}
	primary := prepared[1].runtime.Options.(*option.VLESSOutboundOptions)
	if primary.Detour != "subscription/hop" {
		t.Fatalf("internal detour was not namespaced: %q", primary.Detour)
	}
	if source[0].Options.(*option.VLESSOutboundOptions).Detour != "hop" {
		t.Fatal("preparing a provider graph must not mutate source options")
	}

	updated := append([]option.Outbound(nil), source...)
	updatedHop := *source[1].Options.(*option.VLESSOutboundOptions)
	updatedHop.UUID = "changed"
	updated[1].Options = &updatedHop
	newPrepared, err := prepareOutbounds("subscription", updated, "")
	if err != nil {
		t.Fatal(err)
	}
	affected := affectedOutbounds(prepared, newPrepared)
	for _, tag := range []string{"subscription/hop", "subscription/primary"} {
		if !affected[tag] {
			t.Fatalf("dependent outbound %q was not marked for recreation", tag)
		}
	}
}

func TestPrepareProviderGraphAppliesDefaultDetourOnlyWhenEmpty(t *testing.T) {
	source := []option.Outbound{
		{Type: C.TypeVLESS, Tag: "plain", Options: &option.VLESSOutboundOptions{}},
		{
			Type: C.TypeVLESS,
			Tag:  "chained",
			Options: &option.VLESSOutboundOptions{
				DialerOptions: option.DialerOptions{Detour: "hop"},
			},
		},
		{Type: C.TypeSOCKS, Tag: "hop", Options: &option.SOCKSOutboundOptions{}},
		{Type: C.TypeVLESS, Tag: "external", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "global-egress"}}},
	}
	prepared, err := prepareOutbounds("subscription", source, "cascade")
	if err != nil {
		t.Fatal(err)
	}
	byTag := make(map[string]preparedOutbound, len(prepared))
	for _, outbound := range prepared {
		byTag[outbound.tag] = outbound
	}
	if detour := byTag["subscription/plain"].runtime.Options.(*option.VLESSOutboundOptions).Detour; detour != "cascade" {
		t.Fatalf("plain detour = %q, want cascade", detour)
	}
	if detour := byTag["subscription/chained"].runtime.Options.(*option.VLESSOutboundOptions).Detour; detour != "subscription/hop" {
		t.Fatalf("chained detour = %q, want internal hop", detour)
	}
	if detour := byTag["subscription/external"].runtime.Options.(*option.VLESSOutboundOptions).Detour; detour != "global-egress" {
		t.Fatalf("external detour = %q, want global-egress", detour)
	}
	if source[0].Options.(*option.VLESSOutboundOptions).Detour != "" {
		t.Fatal("default detour mutated source options")
	}
}

func TestFilterInvalidOutboundsDropsOnlyBrokenChains(t *testing.T) {
	outbounds := []option.Outbound{
		{Type: C.TypeSOCKS, Tag: "hop", Options: &option.SOCKSOutboundOptions{}},
		{Type: C.TypeVLESS, Tag: "valid", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "hop"}}},
		{Type: C.TypeVLESS, Tag: "through-group", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "group"}}},
		{Type: C.TypeVLESS, Tag: "through-invalid", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "broken"}}},
		{Type: C.TypeVLESS, Tag: "external", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "global-egress"}}},
	}
	filtered := FilterInvalidOutbounds(outbounds, map[string]bool{"group": true, "broken": true})
	if len(filtered) != 3 || filtered[0].Tag != "hop" || filtered[1].Tag != "valid" || filtered[2].Tag != "external" {
		t.Fatalf("unexpected filtered outbounds: %#v", filtered)
	}
}

func TestNormalizeProviderTagsRewritesLeafDetours(t *testing.T) {
	outbounds := []option.Outbound{
		{Type: C.TypeVLESS, Tag: "🇩🇪 hop", Options: &option.VLESSOutboundOptions{}},
		{
			Type: C.TypeVLESS,
			Tag:  "node",
			Options: &option.VLESSOutboundOptions{
				DialerOptions: option.DialerOptions{Detour: "🇩🇪 hop"},
			},
		},
	}
	normalizeOutboundTags(outbounds, true, "")
	if outbounds[0].Tag != "DE hop" || outbounds[1].Options.(*option.VLESSOutboundOptions).Detour != "DE hop" {
		t.Fatalf("tag normalization broke detour: tag=%q detour=%q", outbounds[0].Tag, outbounds[1].Options.(*option.VLESSOutboundOptions).Detour)
	}
}

func TestNormalizeProviderTagsAppliesPrefixWithoutMutatingSource(t *testing.T) {
	outbounds := []option.Outbound{
		{Type: C.TypeVLESS, Tag: "hop", Options: &option.VLESSOutboundOptions{}},
		{Type: C.TypeVLESS, Tag: "node", Options: &option.VLESSOutboundOptions{DialerOptions: option.DialerOptions{Detour: "hop"}}},
	}
	cloned := cloneOutbounds(outbounds)
	normalizeOutboundTags(cloned, false, "site: ")
	if cloned[0].Tag != "site: hop" || cloned[1].Options.(*option.VLESSOutboundOptions).Detour != "site: hop" {
		t.Fatalf("tag prefix broke detour: tags=%q,%q detour=%q", cloned[0].Tag, cloned[1].Tag, cloned[1].Options.(*option.VLESSOutboundOptions).Detour)
	}
	if outbounds[0].Tag != "hop" || outbounds[1].Options.(*option.VLESSOutboundOptions).Detour != "hop" {
		t.Fatal("provider tag normalization mutated source options")
	}
}

func preparedTags(outbounds []preparedOutbound) []string {
	result := make([]string, 0, len(outbounds))
	for _, outbound := range outbounds {
		result = append(result, outbound.tag)
	}
	return result
}
