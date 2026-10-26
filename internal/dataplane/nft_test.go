package dataplane

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/alakiani/ways/internal/protocol"
)

func allOn(key string) (a [buckets]string) {
	for i := range a {
		a[i] = key
	}
	return a
}

func bridgeRuleset() ruleset {
	ir := nftRule{ID: 1, Elements: []string{"2.144.0.0/14", "5.160.0.0/16"}, Device: allOn("link:3"), Transit: allOn("link:3")}
	def := nftRule{ID: 2, Elements: []string{"0.0.0.0/0"}, Device: allOn("link:4"), Transit: allOn(keyDrop)}
	return ruleset{
		Bridge: true, ResolverAddr: "10.77.0.1", Rules: []nftRule{ir, def}, DefaultRule: 2,
		TransitIfaces: []string{"ways9i"}, LinkIfaces: map[string]uint64{"ways9i": 9, "ways3i": 3, "ways4i": 4}, Uplink: "eth0",
	}
}

func TestBridgeRuleset(t *testing.T) {
	got := render(bridgeRuleset())
	for _, want := range []string{
		"table inet ways\ndelete table inet ways\n", // replaced atomically
		"set rule_1 { type ipv4_addr; flags interval; elements = { 2.144.0.0/14, 5.160.0.0/16 } }",
		"map dev_1 { type ipv4_addr : mark; elements = { 0.0.0.0 : 0x20003, 0.0.0.1 : 0x20003,",
		"0.0.0.63 : 0x20003 } }",
		"map tr_2 { type ipv4_addr : mark; elements = { 0.0.0.0 : 0x40001,",
		`set transit_ifaces { type ifname; elements = { "ways9i" } }`,
		`iifname "ways0" meta nfproto ipv6 drop`,
		`iifname "ways0" tcp dport 853 counter meta mark set ip saddr & 0.0.0.63 map @dev_2 accept`,
		`iifname "ways0" ip daddr @rule_1 counter meta mark set ip saddr & 0.0.0.63 map @dev_1 accept`,
		`iifname "ways0" ip daddr @rule_2 counter meta mark set ip saddr & 0.0.0.63 map @dev_2 accept`,
		`iifname "ways0" counter drop`,
		`iifname @transit_ifaces ct direction original ip daddr @rule_1 counter meta mark set ip saddr & 0.0.0.63 map @tr_1 accept`,
		`iifname "ways0" meta l4proto { tcp, udp } th dport 53 counter dnat ip to 10.77.0.1:53`,
		`ct state new counter ct mark set iifname map { "ways3i" : 0x20003, "ways4i" : 0x20004, "ways9i" : 0x20009 }`,
		`ct direction reply ct mark & 0xffff0000 == 0x20000 counter meta mark set ct mark`,
		"tcp option maxseg size set rt mtu",
		"set usage_up { type ipv4_addr . mark; flags dynamic; size 65536; }",
		`iifname "ways0" ct state new ct mark set meta mark or 0x10000`,
		`iifname "ways0" update @usage_up { ip saddr . meta mark counter }`,
		`oifname "ways0" update @usage_down { ip daddr . ct mark counter }`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, got)
		}
	}
	pos := func(s string) int { return strings.Index(got, s) }
	if pos("tcp dport 853") > pos("@rule_1") {
		t.Error("DoT is marked after the Rules, so an IR-set resolver would leave domestically")
	}
	if pos(`iifname "ways0" counter drop`) < pos("map @dev_2 accept\n") {
		t.Error("the fail-closed drop comes before the Rules")
	}
	if strings.Contains(got, "masquerade") {
		t.Error("a Bridge that is no Exit masquerades")
	}
}

func TestExitRuleset(t *testing.T) {
	got := render(ruleset{Exit: true, LinkIfaces: map[string]uint64{"ways3l": 7, "ways4l": 7, "ways9l": 2}, Uplink: "eth0"})
	for _, want := range []string{
		`ct state new counter ct mark set iifname map { "ways3l" : 0x20007, "ways4l" : 0x20007, "ways9l" : 0x20002 }`,
		`oifname "eth0" ct mark & 0xffff0000 == 0x20000 counter masquerade`,
		// Replies to masqueraded connections are only translated back while
		// a nat chain hooks prerouting.
		"type nat hook prerouting",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ways0") || strings.Contains(got, "ip saddr 10.77.0.0/16") {
		t.Errorf("an Exit ruleset mentions Devices:\n%s", got)
	}
}

func TestDualRoleMasqueradesItsDevices(t *testing.T) {
	r := bridgeRuleset()
	r.Exit = true
	if got := render(r); !strings.Contains(got, `oifname "eth0" ip saddr 10.77.0.0/16 counter masquerade`) {
		t.Errorf("a dual-role Node does not masquerade its Devices:\n%s", got)
	}
}

// The monitoring port answers the Coordinator VM only; everyone else,
// over IPv4 or IPv6, is dropped without a reply (ADR 0006).
func TestMonitoringPortIsAllowlisted(t *testing.T) {
	r := bridgeRuleset()
	if strings.Contains(render(r), "tcp dport 9443") {
		t.Error("monitoring rules with no monitoring port")
	}
	r.MonitorPort, r.MonitorAllow = 9443, []string{"192.0.2.100", "2001:db8::1"}
	got := render(r)
	for _, want := range []string{
		"\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n",
		"\t\ttcp dport 9443 ip saddr { 192.0.2.100 } accept\n",
		"\t\ttcp dport 9443 ip6 saddr { 2001:db8::1 } accept\n",
		"\t\ttcp dport 9443 drop\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "tcp dport 9443 drop") < strings.Index(got, "accept\n\t\ttcp dport 9443 ip6") {
		t.Error("the drop comes before the allowlist")
	}
}

// GRE has no authentication, so an Exit takes it only from current peers,
// and on a GRE interface forwards only new traffic from Devices or the mesh
// (ADR 0009). Replies to this Node's own connections still come back.
func TestGREIsLimitedToPeersAndOurRanges(t *testing.T) {
	r := ruleset{Exit: true, LinkIfaces: map[string]uint64{"ways3l": 7, "ways4l": 7}, Uplink: "eth0",
		GREIfaces: []string{"ways3l"}, GREPeers: []string{"203.0.113.9", "198.51.100.4"}}
	got := render(r)
	for _, want := range []string{
		"\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n",
		"\t\tmeta l4proto gre ip saddr { 198.51.100.4, 203.0.113.9 } accept\n",
		"\t\tmeta l4proto gre drop\n",
		`iifname { "ways3l" } ct direction original ip saddr != { 10.77.0.0/16, 10.78.0.0/16 } counter drop`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "meta l4proto gre drop") < strings.Index(got, "meta l4proto gre ip saddr") {
		t.Error("GRE is dropped before the peers are accepted")
	}
	forward := got[strings.Index(got, "chain forward"):]
	if !strings.Contains(forward[:strings.Index(forward, "\n\t}")], "ct direction original ip saddr !=") {
		t.Error("the source check is not in the forward chain")
	}

	// No GRE peer: no GRE at all.
	got = render(ruleset{Exit: true, Uplink: "eth0"})
	if !strings.Contains(got, "\t\tmeta l4proto gre drop\n") || strings.Contains(got, "gre ip saddr") || strings.Contains(got, "10.78.0.0/16") {
		t.Errorf("ruleset without GRE peers:\n%s", got)
	}
}

func TestBucketUpdatesTouchOnlyMovedBuckets(t *testing.T) {
	old := allOn("link:3")
	moved := old
	moved[5], moved[60] = "link:4", keyDrop
	got := bucketUpdates("dev_2", old, moved)
	want := "delete element inet ways dev_2 { 0.0.0.5 }\nadd element inet ways dev_2 { 0.0.0.5 : 0x20004 }\n" +
		"delete element inet ways dev_2 { 0.0.0.60 }\nadd element inet ways dev_2 { 0.0.0.60 : 0x40001 }\n"
	if got != want {
		t.Errorf("updates =\n%s\nwant\n%s", got, want)
	}
	if bucketUpdates("dev_2", old, old) != "" {
		t.Error("no change produced updates")
	}
}

// A GRE instance whose peer address is missing, such as one from a snapshot
// an older Agent saved, must not break the whole ruleset (nft rejects an
// empty set).
func TestGREPeerWithoutAddressIsLeftOut(t *testing.T) {
	for _, peers := range [][]string{{""}, {"", "203.0.113.9"}, {"not-an-ip"}} {
		r := ruleset{Exit: true, LinkIfaces: map[string]uint64{"ways3l": 7}, Uplink: "eth0",
			GREIfaces: []string{"ways3l"}, GREPeers: peers}
		got := render(r)
		if strings.Contains(got, "{  }") || strings.Contains(got, "{ ,") || strings.Contains(got, "not-an-ip") {
			t.Errorf("peers %q render an invalid set:\n%s", peers, got)
		}
		if !strings.Contains(got, "\t\tmeta l4proto gre drop\n") {
			t.Errorf("peers %q: GRE is no longer dropped by default", peers)
		}
	}
	got := render(ruleset{Exit: true, LinkIfaces: map[string]uint64{"ways3l": 7}, Uplink: "eth0",
		GREIfaces: []string{"ways3l"}, GREPeers: []string{"", "203.0.113.9"}})
	if !strings.Contains(got, "meta l4proto gre ip saddr { 203.0.113.9 } accept") {
		t.Errorf("the valid peer was lost:\n%s", got)
	}
}

func TestThrottledDevicesArePolicedAheadOfMetering(t *testing.T) {
	rs := bridgeRuleset()
	rs.Throttles = throttles([]protocol.Device{
		{PublicKey: "a", Address: "10.77.0.9/32", Rate: 500_000},
		{PublicKey: "b", Address: "10.77.0.5/32", Rate: 250_000},
		{PublicKey: "c", Address: "10.77.0.6/32"}, // active
		{PublicKey: "d", Address: "bogus", Rate: 1},
		{PublicKey: "e", Address: "fd00::1/128", Rate: 1},
	})
	got := render(rs)
	for _, want := range []string{
		"limit up_10_77_0_5 { rate over 250000 bytes/second }",
		"limit down_10_77_0_5 { rate over 250000 bytes/second }",
		"limit up_10_77_0_9 { rate over 500000 bytes/second }",
		"limit down_10_77_0_9 { rate over 500000 bytes/second }",
		`map throttle_up { type ipv4_addr : limit; elements = { 10.77.0.5 : "up_10_77_0_5", 10.77.0.9 : "up_10_77_0_9" } }`,
		`map throttle_down { type ipv4_addr : limit; elements = { 10.77.0.5 : "down_10_77_0_5", 10.77.0.9 : "down_10_77_0_9" } }`,
		"\t\ttype filter hook forward priority mangle; policy accept;\n" +
			"\t\tiifname \"ways0\" limit name ip saddr map @throttle_up drop\n" +
			"\t\toifname \"ways0\" limit name ip daddr map @throttle_down drop\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "10_77_0_6") || strings.Contains(got, "bogus") || strings.Contains(got, "fd00") {
		t.Errorf("an active Device or a bad address is throttled:\n%s", got)
	}
	// Throttled traffic is still metered: the policer drops only what is
	// over the rate, and accepts nothing past metering.
	if strings.Index(got, "@throttle_down drop") > strings.Index(got, "update @usage_up") {
		t.Error("throttling comes after metering")
	}
	if strings.Contains(got, "@throttle_up accept") || strings.Contains(got, "@throttle_down accept") {
		t.Error("a throttle rule accepts, which would skip metering")
	}
}

func TestNoThrottlesRenderNoPolicers(t *testing.T) {
	got := render(bridgeRuleset())
	if strings.Contains(got, "limit") || strings.Contains(got, "throttle") {
		t.Errorf("a Bridge with no throttled Device renders policers:\n%s", got)
	}
	got = render(ruleset{Exit: true, Throttles: []throttle{{Addr: netip.MustParseAddr("10.77.0.5"), Rate: 1}}, Uplink: "eth0"})
	if strings.Contains(got, "throttle") {
		t.Errorf("a Node that is no Bridge renders policers:\n%s", got)
	}
}

func TestAbroadRuleMatchesBySourceAheadOfEverything(t *testing.T) {
	rs := bridgeRuleset()
	abroad := nftRule{ID: 3, Source: "10.77.128.0/17", Device: allOn("link:3"), Transit: allOn(keyLocal)}
	rs.Rules = append([]nftRule{abroad}, rs.Rules...)
	got := render(rs)
	for _, want := range []string{
		"map dev_3 { type ipv4_addr : mark; elements = { 0.0.0.0 : 0x20003,",
		`iifname "ways0" ip saddr 10.77.128.0/17 counter meta mark set ip saddr & 0.0.0.63 map @dev_3 accept`,
		`iifname @transit_ifaces ct direction original ip saddr 10.77.128.0/17 counter meta mark set ip saddr & 0.0.0.63 map @tr_3 accept`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "set rule_3") || strings.Contains(got, "@rule_3") {
		t.Error("the Abroad Rule has a Destination Set")
	}
	pos := func(s string) int { return strings.Index(got, s) }
	// DoT and every destination Rule come after it, so an Abroad Device's
	// traffic, DoT included, never leaves abroad (ADR 0014).
	if dev := pos(`iifname "ways0" ip saddr 10.77.128.0/17`); dev < 0 || dev > pos(`iifname "ways0" tcp dport 853`) || dev > pos("@rule_1") {
		t.Error("the Abroad Rule is not first for Devices")
	}
	if tr := pos(`iifname @transit_ifaces ct direction original ip saddr 10.77.128.0/17`); tr < 0 ||
		tr > pos("iifname @transit_ifaces ct direction original tcp dport 853") || tr > pos("@tr_1 accept") {
		t.Error("the Abroad Rule is not first for transit")
	}
}
