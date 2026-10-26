package coordinator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/alakiani/ways/internal/arvan"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

func TestPlanMembers(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	three := []string{"ir1", "ir2", "ir3"}
	for _, tc := range []struct {
		name      string
		members   []string
		bridges   []string
		elSince   map[string]time.Time
		inelSince map[string]time.Time
		want      []string
	}{
		{name: "an empty record takes every eligible Bridge at once",
			bridges: three, elSince: map[string]time.Time{"ir1": now, "ir3": now},
			want: []string{"ir1", "ir3"}},
		{name: "nothing eligible and no members: still empty",
			bridges: three, inelSince: map[string]time.Time{"ir1": ago(time.Hour)}},
		{name: "a member stays while ineligible under 60 s",
			members: []string{"ir1", "ir2"}, bridges: three,
			elSince: map[string]time.Time{"ir2": ago(time.Hour)}, inelSince: map[string]time.Time{"ir1": ago(59 * time.Second)},
			want: []string{"ir1", "ir2"}},
		{name: "after 60 s ineligible it leaves",
			members: []string{"ir1", "ir2"}, bridges: three,
			elSince: map[string]time.Time{"ir2": ago(time.Hour)}, inelSince: map[string]time.Time{"ir1": ago(60 * time.Second)},
			want: []string{"ir2"}},
		{name: "a Bridge outside rejoins only after 5 min eligible",
			members: []string{"ir2"}, bridges: three,
			elSince: map[string]time.Time{"ir1": ago(4 * time.Minute), "ir2": ago(time.Hour), "ir3": ago(5 * time.Minute)},
			want:    []string{"ir2", "ir3"}},
		{name: "the last member never leaves",
			members: []string{"ir1"}, bridges: three,
			inelSince: map[string]time.Time{"ir1": ago(time.Hour), "ir2": ago(time.Hour)},
			want:      []string{"ir1"}},
		{name: "every member failing at once: the record stays as it was",
			members: []string{"ir1", "ir2"}, bridges: three,
			inelSince: map[string]time.Time{"ir1": ago(time.Hour), "ir2": ago(time.Hour)},
			want:      []string{"ir1", "ir2"}},
		{name: "when the last member leaves, an eligible Bridge takes over at once",
			members: []string{"ir1"}, bridges: three,
			inelSince: map[string]time.Time{"ir1": ago(time.Hour)}, elSince: map[string]time.Time{"ir2": ago(10 * time.Second)},
			want: []string{"ir2"}},
		{name: "a Node no longer a domestic Bridge leaves at once",
			members: []string{"gone", "ir1"}, bridges: three,
			elSince: map[string]time.Time{"ir1": ago(time.Hour)},
			want:    []string{"ir1"}},
		{name: "a member not probed yet stays",
			members: []string{"ir1", "ir2"}, bridges: three,
			want: []string{"ir1", "ir2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			members := slices.Clone(tc.members)
			got := planMembers(members, tc.bridges, tc.elSince, tc.inelSince, now, time.Minute, 5*time.Minute)
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
			if !slices.Equal(members, tc.members) {
				t.Errorf("planMembers changed its input: %v", members)
			}
		})
	}
}

func TestIneligibility(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	fresh := func(mode string) *protocol.HealthStatus {
		return &protocol.HealthStatus{ReceivedAt: now.Add(-10 * time.Second),
			Health: protocol.Health{Paths: []protocol.RuleHealth{{RuleID: 1, Mode: "direct"}, {RuleID: 2, Mode: mode}}}}
	}
	ok := protocol.ProbeResult{OK: true}
	for _, tc := range []struct {
		name  string
		probe protocol.ProbeResult
		h     *protocol.HealthStatus
		want  []string
	}{
		{"direct", ok, fresh("direct"), nil},
		{"transit counts", ok, fresh("transit"), nil},
		{"probe failing", protocol.ProbeResult{}, fresh("direct"), []string{"probe failing"}},
		{"never reported", ok, nil, []string{"Agent not reporting"}},
		{"stale report", ok, &protocol.HealthStatus{ReceivedAt: now.Add(-91 * time.Second)}, []string{"Agent not reporting"}},
		{"default Rule in fallback", ok, fresh("fallback"), []string{"no default-Rule Path"}},
		{"default Rule not reported yet", protocol.ProbeResult{}, &protocol.HealthStatus{ReceivedAt: now},
			[]string{"probe failing", "no default-Rule Path"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ineligibility(tc.probe, tc.h, 2, now, 90*time.Second)
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSyncAddressRecord sets the record once per change, never empties it,
// and retries after ArvanCloud fails.
func TestSyncAddressRecord(t *testing.T) {
	a := newAPI(t)
	ctx := context.Background()
	dns := arvan.NewFake("key", "wayfinder.ir")
	srv := httptest.NewServer(dns)
	t.Cleanup(srv.Close)
	a.c.DNS = &arvan.Client{BaseURL: srv.URL, APIKey: "key", Zone: "wayfinder.ir", TTL: 120}
	ips := func(ss ...string) []netip.Addr {
		var out []netip.Addr
		for _, s := range ss {
			out = append(out, netip.MustParseAddr(s))
		}
		return out
	}

	if err := a.c.syncAddressRecord(ctx, a.c.bridgeBook(), ips("192.0.2.2", "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if got := dns.A("bridge"); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) || !dns.OneInTurn("bridge") {
		t.Fatalf("record = %v, one in turn %v", got, dns.OneInTurn("bridge"))
	}

	// Unchanged: no call. An operator's hand edit shows it was not rewritten.
	dns.Put("bridge", "198.51.100.1")
	a.c.syncAddressRecord(ctx, a.c.bridgeBook(), ips("192.0.2.1", "192.0.2.2"))
	if got := dns.A("bridge"); !slices.Equal(got, []string{"198.51.100.1"}) {
		t.Errorf("an unchanged set was published again: %v", got)
	}

	// Nothing to publish leaves the record alone (ADR 0011).
	a.c.syncAddressRecord(ctx, a.c.bridgeBook(), nil)
	if got := dns.A("bridge"); len(got) != 1 {
		t.Errorf("an empty set changed the record: %v", got)
	}

	// A failed update is counted and retried by the next round.
	dns.FailWith = http.StatusServiceUnavailable
	if err := a.c.syncAddressRecord(ctx, a.c.bridgeBook(), ips("192.0.2.1")); err == nil {
		t.Fatal("want ArvanCloud's error")
	}
	if a.c.address.dnsFailures != 1 {
		t.Errorf("dnsFailures = %d, want 1", a.c.address.dnsFailures)
	}
	dns.FailWith = 0
	if err := a.c.syncAddressRecord(ctx, a.c.bridgeBook(), ips("192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if got := dns.A("bridge"); !slices.Equal(got, []string{"192.0.2.1"}) || a.c.address.dnsFailures != 0 {
		t.Errorf("after the retry: record %v, dnsFailures %d", got, a.c.address.dnsFailures)
	}
}

// TestBridgeAddressStatus shows the members and the probe's view on the
// Admin's status board.
func TestBridgeAddressStatus(t *testing.T) {
	a := newAPI(t)
	ctx := context.Background()
	ids := map[string]string{}
	for _, name := range []string{"ir1", "ir2"} {
		n, err := a.s.CreateNode(ctx, name, []protocol.Role{protocol.RoleBridge}, []string{"IR"})
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = n.ID
		a.s.PutHealth(ctx, n.ID, protocol.Health{AppliedVersion: 1}, "192.0.2."+name[2:])
	}
	a.c.address.probes[ids["ir1"]] = protocol.ProbeResult{OK: true, At: *a.clock}
	a.c.address.probes[ids["ir2"]] = protocol.ProbeResult{At: *a.clock, Error: "timeout"}
	a.c.address.reasons[ids["ir2"]] = []string{"probe failing"}
	a.s.JoinAddress(ctx, store.BridgeRecord, ids["ir1"])

	var o protocol.Overview
	a.admin().must(200, "GET", "/v1/admin/overview", nil, &o)
	st := o.BridgeAddress
	if st.Host != "bridge.wayfinder.ir" || len(st.Bridges) != 2 {
		t.Fatalf("status = %+v", st)
	}
	if b := st.Bridges[0]; b.Name != "ir1" || !b.InRecord || b.Joined == nil || !b.Eligible || b.Addr != "192.0.2.1" {
		t.Errorf("ir1 = %+v", b)
	}
	if b := st.Bridges[1]; b.Name != "ir2" || b.InRecord || b.Eligible || !slices.Equal(b.Reasons, []string{"probe failing"}) {
		t.Errorf("ir2 = %+v", b)
	}
}

func TestAbroadIneligibility(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	fresh := func(mode string) *protocol.HealthStatus {
		return &protocol.HealthStatus{ReceivedAt: now.Add(-10 * time.Second),
			Health: protocol.Health{Paths: []protocol.RuleHealth{{RuleID: 3, Mode: mode}, {RuleID: 2, Mode: "local"}}}}
	}
	for _, tc := range []struct {
		name string
		h    *protocol.HealthStatus
		want []string
	}{
		{"direct", fresh("direct"), nil},
		{"transit counts", fresh("transit"), nil},
		{"never reported", nil, []string{"Agent not reporting"}},
		{"stale report", &protocol.HealthStatus{ReceivedAt: now.Add(-91 * time.Second)}, []string{"Agent not reporting"}},
		{"no IR Exit", fresh("fallback"), []string{"no Abroad-Rule Path"}},
		{"an Agent from before the Abroad Rule", &protocol.HealthStatus{ReceivedAt: now,
			Health: protocol.Health{Paths: []protocol.RuleHealth{{RuleID: 2, Mode: "local"}}}}, []string{"no Abroad-Rule Path"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := abroadIneligibility(tc.h, 3, now, 90*time.Second); !slices.Equal(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// The Abroad Bridge Address publishes the Abroad Bridges with a working
// Abroad-Rule Path, judged by their reports, and leaves the Bridge
// Address alone (ADR 0014).
func TestAbroadRoundPublishesAbroadBridges(t *testing.T) {
	a := newAPI(t)
	ctx := context.Background()
	dns := arvan.NewFake("key", "wayfinder.ir")
	srv := httptest.NewServer(dns)
	t.Cleanup(srv.Close)
	a.c.DNS = &arvan.Client{BaseURL: srv.URL, APIKey: "key", Zone: "wayfinder.ir", TTL: 120}
	abroadRule, err := a.c.abroadRuleID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	report := func(name string, roles []protocol.Role, tags []string, addr, mode string) {
		n, err := a.s.CreateNode(ctx, name, roles, tags)
		if err != nil {
			t.Fatal(err)
		}
		a.s.PutHealth(ctx, n.ID, protocol.Health{Paths: []protocol.RuleHealth{{RuleID: abroadRule, Mode: mode}}}, addr)
	}
	both := []protocol.Role{protocol.RoleBridge, protocol.RoleExit}
	report("aws", both, nil, "192.0.2.1", "direct")
	report("lightnode", both, nil, "192.0.2.2", "fallback")
	report("ir1", both, []string{"IR"}, "198.51.100.1", "local")
	report("exit-only", []protocol.Role{protocol.RoleExit}, nil, "192.0.2.3", "direct")

	if err := a.c.abroadRound(ctx); err != nil {
		t.Fatal(err)
	}
	if got := dns.A("abroad"); !slices.Equal(got, []string{"192.0.2.1"}) || !dns.OneInTurn("abroad") {
		t.Errorf("abroad record = %v", got)
	}
	if got := dns.A("bridge"); len(got) != 0 {
		t.Errorf("the Bridge Address changed: %v", got)
	}
	st, err := a.c.AbroadAddressStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Host != "abroad.wayfinder.ir" || len(st.Bridges) != 2 || !st.Bridges[0].InRecord || !st.Bridges[0].Eligible ||
		st.Bridges[1].Eligible || !slices.Equal(st.Bridges[1].Reasons, []string{"no Abroad-Rule Path"}) {
		t.Errorf("status = %+v", st)
	}
	if m, _ := a.s.AddressMembers(ctx, store.BridgeRecord); len(m) != 0 {
		t.Errorf("Bridge Address members = %+v", m)
	}
}
