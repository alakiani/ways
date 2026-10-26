package store_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

func TestDevicesGetUnusedAddressesThatAreNeverReused(t *testing.T) {
	s := open(t, newClock())
	u, err := s.CreateUser(ctx, "maryam")
	if err != nil {
		t.Fatal(err)
	}
	d1, err := s.CreateDevice(ctx, u.ID, "phone", "key1")
	if err != nil {
		t.Fatal(err)
	}
	if d1.Address != netip.MustParseAddr("10.77.0.2") {
		t.Errorf("first device address = %s, want 10.77.0.2 (10.77.0.1 is the resolver)", d1.Address)
	}
	if err := s.RevokeDevice(ctx, d1.ID); err != nil {
		t.Fatal(err)
	}
	d2, _ := s.CreateDevice(ctx, u.ID, "laptop", "key2")
	if d2.Address == d1.Address {
		t.Error("a revoked device's address was reused")
	}
	devs, _ := s.Devices(ctx)
	if len(devs) != 2 || !devs[0].Revoked || devs[0].PublicKey != "" || devs[1].Revoked {
		t.Errorf("devices = %+v, want the revoked one without its key", devs)
	}

	s.SetUserSuspended(ctx, u.ID, true)
	if devs, _ := s.Devices(ctx); !devs[1].UserSuspended {
		t.Error("suspension not visible on the device")
	}
	probe, err := s.CreateDevice(ctx, "", "probe", "key3")
	if err != nil || probe.UserID != "" {
		t.Errorf("probe device = %+v, %v", probe, err)
	}
}

func TestBuiltinRulesAndSets(t *testing.T) {
	s := open(t, newClock())
	rules, err := s.Rules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || rules[1].Name != "IR" || rules[2].Name != "Default" {
		t.Fatalf("rules = %+v", rules)
	}
	ir, def := rules[1], rules[2]
	if ir.Fallback != protocol.FallbackNext || def.Fallback != protocol.FallbackDrop || !def.Builtin {
		t.Errorf("IR = %+v, default = %+v", ir, def)
	}
	if def.RequiredTags[0] != "!IR" || ir.RequiredTags[0] != "IR" {
		t.Errorf("tags: IR %v, default %v", ir.RequiredTags, def.RequiredTags)
	}
}

func TestSetContentIsFeedPlusAdditionsMinusRemovals(t *testing.T) {
	s := open(t, newClock())
	p := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, x := range ss {
			out = append(out, netip.MustParsePrefix(x))
		}
		return out
	}
	if err := s.SetFeedContent(ctx, 1, p("2.144.0.0/14", "5.160.0.0/16")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOverrides(ctx, 1, p("185.0.0.0/24"), p("5.160.0.0/17")); err != nil {
		t.Fatal(err)
	}
	sets, _ := s.DestinationSets(ctx)
	ir := sets[0]
	body, err := s.SetBlob(ctx, ir.ContentHash)
	if err != nil {
		t.Fatal(err)
	}
	if want := "2.144.0.0/14\n5.160.128.0/17\n185.0.0.0/24\n"; body != want {
		t.Errorf("content = %q, want %q", body, want)
	}

	if err := s.RefreshSetContent(ctx, 2); err != nil {
		t.Fatal(err)
	}
	sets, _ = s.DestinationSets(ctx)
	if body, _ := s.SetBlob(ctx, sets[1].ContentHash); strings.TrimSpace(body) != "0.0.0.0/0" {
		t.Errorf("Everything = %q", body)
	}
}

func TestSettingIfUnsetKeepsTheFirstValue(t *testing.T) {
	s := open(t, newClock())
	if v, _ := s.SetSettingIfUnset(ctx, "k", "a"); v != "a" {
		t.Errorf("first = %q", v)
	}
	if v, _ := s.SetSettingIfUnset(ctx, "k", "b"); v != "a" {
		t.Errorf("second = %q, want the first value kept", v)
	}
}

// Abroad Devices take their addresses from the upper half of the pool, so a
// Bridge matches them all with one prefix (ADR 0014).
func TestAbroadDevicesGetTheUpperHalfOfThePool(t *testing.T) {
	s := open(t, newClock())
	u, _ := s.CreateUser(ctx, "maryam")
	if err := s.SetUserAbroad(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	ord, err := s.AddDevice(ctx, u.ID, "phone", "k1", "", false)
	if err != nil {
		t.Fatal(err)
	}
	ab, err := s.AddDevice(ctx, u.ID, "phone abroad", "k2", "", true)
	if err != nil {
		t.Fatal(err)
	}
	ab2, _ := s.AddDevice(ctx, u.ID, "laptop abroad", "k3", "", true)
	if ord.Address != netip.MustParseAddr("10.77.0.2") || ord.Abroad {
		t.Errorf("ordinary Device = %+v", ord)
	}
	if ab.Address != netip.MustParseAddr("10.77.128.1") || !ab.Abroad || ab2.Address != netip.MustParseAddr("10.77.128.2") {
		t.Errorf("Abroad Devices = %+v, %+v", ab, ab2)
	}
	if !store.AbroadPool.Contains(ab.Address) || store.AbroadPool.Contains(ord.Address) || !store.DevicePool.Contains(ab.Address) {
		t.Errorf("pools: abroad %s, devices %s", store.AbroadPool, store.DevicePool)
	}
	devs, _ := s.Devices(ctx)
	if len(devs) != 3 || devs[0].Abroad || !devs[1].Abroad || !devs[1].UserAbroad {
		t.Errorf("devices = %+v", devs)
	}
	s.SetUserAbroad(ctx, u.ID, false)
	if devs, _ := s.Devices(ctx); devs[1].UserAbroad {
		t.Error("the permission's removal is not visible on the Device")
	}
	if a, _ := s.Account(ctx, u.ID); a.Abroad {
		t.Error("the Account still has the permission")
	}
}

func TestAbroadRuleIsBuiltInFirstAndMatchesBySource(t *testing.T) {
	s := open(t, newClock())
	rules, _ := s.Rules(ctx)
	if len(rules) != 3 || rules[0].Name != "Abroad" {
		t.Fatalf("rules = %+v", rules)
	}
	ab := rules[0]
	if ab.Source != store.AbroadPool.String() || !ab.Builtin || ab.Fallback != protocol.FallbackDrop ||
		len(ab.RequiredTags) != 1 || ab.RequiredTags[0] != "IR" {
		t.Errorf("Abroad Rule = %+v", ab)
	}
	if rules[1].Source != "" || rules[2].Source != "" {
		t.Error("a destination Rule has a source")
	}
	if err := s.UpdateRule(ctx, ab.ID, []string{"!IR"}, "next"); err == nil {
		t.Error("the Abroad Rule could be changed")
	}
}
