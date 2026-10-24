//go:build linux

package e2e

import (
	"context"
	"net"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alakiani/ways/internal/arvan"
	"github.com/alakiani/ways/internal/coordinator"
	"github.com/alakiani/ways/internal/lab"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/testutil"
)

// TestBridgeAddress is ADR 0011's "proves in the lab" test: the
// Coordinator keeps the Bridge Address's record to the domestic Bridges
// its probe Device finds healthy, one answer per lookup in turn. Killing a
// Bridge removes it after 60 s, a Device that toggles its tunnel reaches
// the Bridge left, and the killed Bridge rejoins once it has been healthy
// for the rejoin delay.
func TestBridgeAddress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	al := startAddressLab(t, ctx, "ir1", "ir3")
	l, co, dns, members := al.l, al.co, al.dns, al.members
	co.c.Address.RejoinAfter = 10 * time.Second // ADR 0011's 5 min, shortened; the 60 s stays
	go co.c.RunBridgeAddress(ctx)

	// An empty record takes both Bridges as soon as the probe passes.
	testutil.Eventually(t, 120*time.Second, "the record holds ir1 and ir3", func() bool {
		return slices.Equal(members(), []string{"ir1", "ir3"})
	})
	if !dns.OneInTurn("bridge") || dns.TTL("bridge") != 120 {
		t.Errorf("record answers one in turn %v, TTL %d", dns.OneInTurn("bridge"), dns.TTL("bridge"))
	}

	// A User's Device; its lookup answered with ir1.
	user, _ := co.store.CreateUser(ctx, "maryam")
	key, _ := wgtypes.GeneratePrivateKey()
	dev, err := co.store.CreateDevice(ctx, user.ID, "phone", key.PublicKey().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := co.c.Reconcile(ctx); err != nil { // the Bridges are already up: tell them
		t.Fatal(err)
	}
	bridgePub, _ := co.c.BridgePublicKey(ctx)
	bridgeKey, _ := wgtypes.ParseKey(bridgePub)
	p := newPhone(t, l.Node("phone1"), key, dev.Address, l.Node("ir1"), bridgeKey, coordinator.DefaultDevicePort)
	abroad := func() (string, error) { return p.ask("93.184.215.14:7") }
	ab1 := l.Node("ab1").Addr().String()
	p.leavesFrom("abroad through ir1", abroad, ab1, 60*time.Second)

	// Kill ir1. It stays in the record for 60 s, then leaves.
	kill := l.Filter(lab.DropAll(l.Node("ir1")))
	killed := time.Now()
	testutil.Eventually(t, 120*time.Second, "ir1 leaves the record", func() bool {
		return slices.Equal(members(), []string{"ir3"})
	})
	took := time.Since(killed)
	t.Logf("ir1 left the record %v after it died", took.Round(100*time.Millisecond))
	if took < 60*time.Second {
		t.Errorf("ir1 left after %v, before the 60 s", took)
	}
	if took > 60*time.Second+3*co.c.Address.ProbeEvery+5*time.Second {
		t.Errorf("ir1 took %v to leave, want about 60 s", took)
	}

	// Toggling the tunnel looks the Bridge Address up again: only ir3 is
	// left to answer with.
	p.toggle(l.Node("ir3"), coordinator.DefaultDevicePort)
	p.leavesFrom("abroad through ir3 after the toggle", abroad, ab1, 30*time.Second)

	// ir3 dies too: the record is never emptied, so it keeps ir3.
	kill3 := l.Filter(lab.DropAll(l.Node("ir3")))
	time.Sleep(60*time.Second + 3*co.c.Address.ProbeEvery)
	if got := members(); !slices.Equal(got, []string{"ir3"}) {
		t.Errorf("with every Bridge dead the record holds %v, want ir3 kept", got)
	}
	kill3.Remove()

	// ir1 recovers. It rejoins only after the rejoin delay.
	kill.Remove()
	recovered := time.Now()
	testutil.Eventually(t, 90*time.Second, "ir1 rejoins the record", func() bool {
		return slices.Equal(members(), []string{"ir1", "ir3"})
	})
	if took := time.Since(recovered); took < co.c.Address.RejoinAfter {
		t.Errorf("ir1 rejoined after %v, before the %v", took, co.c.Address.RejoinAfter)
	}

	// The status board agrees with ArvanCloud.
	st, err := co.c.BridgeAddressStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Published || st.Removals != 1 || st.Joins != 3 {
		t.Errorf("status = %+v, want published, 1 removal and 3 joins", st)
	}
	for _, b := range st.Bridges {
		if !b.InRecord || !b.Eligible || b.Addr != l.Node(b.Name).Addr().String() {
			t.Errorf("status shows %+v", b)
		}
	}
}

// addressLab is a lab mesh for the Bridge Address test: domestic Bridges,
// an Exit, a phone, a faked ArvanCloud, and the Coordinator's probe Device.
type addressLab struct {
	l      *lab.Lab
	co     *coord
	m      *mesh
	dns    *arvan.Fake
	addrOf map[string]string // a Bridge's address -> its name
}

// startAddressLab starts the Agents and returns once every Bridge can
// carry Devices, so the caller's first round finds them all eligible.
func startAddressLab(t *testing.T, ctx context.Context, bridges ...string) *addressLab {
	binDir(t)
	if out, err := execCommand("modprobe", "wireguard"); err != nil {
		t.Fatalf("modprobe wireguard: %v: %s", err, out)
	}
	specs := []lab.Spec{{Name: "coord"}}
	for _, b := range bridges {
		specs = append(specs, lab.Spec{Name: b})
	}
	specs = append(specs,
		lab.Spec{Name: "ab1"},
		lab.Spec{Name: "phone1"},
		lab.At("web-ab", "93.184.215.14"),
		lab.At("dns-ab", "9.9.9.9"),
		lab.At("egress-ab", "1.0.0.10"),
		lab.At("egress-ir", "2.188.0.10"),
	)
	l := lab.StartSpecs(t, specs...)
	co := startCoordinator(t, l.Node("coord"))
	co.c.Upstreams = []string{"9.9.9.9"}
	egressTargets(t, co, l.Node("egress-ab"), l.Node("egress-ir"))
	upstreamCA := serveEgress(t, l.Node("dns-ab")) // a resolver abroad that answers the probe's query
	whoami(t, l.Node("web-ab"), 7)
	dumpNetOnFailure(t, l, bridges...)

	// ArvanCloud, faked, with the record still on a placeholder.
	dns := arvan.NewFake("lab-key", "wayfinder.ir")
	dns.Put("bridge", "192.0.2.1")
	api := httptest.NewServer(dns)
	t.Cleanup(api.Close)
	co.c.DNS = &arvan.Client{BaseURL: api.URL, APIKey: "lab-key", Zone: "wayfinder.ir", TTL: 120}
	co.c.Address.ProbeEvery = 2 * time.Second // ADR 0011's 15 s, shortened
	co.c.Address.ProbeHostname = "check.abroad"
	co.c.Address.Enter = l.Node("coord").Do // the probe dials from the Coordinator host

	if err := co.c.InitProbe(ctx); err != nil {
		t.Fatal(err)
	}
	m := &mesh{t: t, l: l, co: co, ids: map[string]string{}, agents: map[string]*agentProc{},
		agentArgs: []string{"-upstream-ca", upstreamCA}}
	addrOf := map[string]string{}
	for _, b := range bridges {
		m.startAgent(b, []protocol.Role{protocol.RoleBridge}, []string{"IR"})
		addrOf[l.Node(b).Addr().String()] = b
	}
	m.startAgent("ab1", []protocol.Role{protocol.RoleExit}, nil)

	const defaultRule = 2
	for _, b := range bridges {
		testutil.Eventually(t, 120*time.Second, b+" has a direct default-Rule Path", func() bool {
			return m.ruleHealth(b, defaultRule).Mode == "direct"
		})
	}
	return &addressLab{l: l, co: co, m: m, dns: dns, addrOf: addrOf}
}

// members are the Bridges the record at ArvanCloud holds, by name, sorted.
func (al *addressLab) members() []string {
	var out []string
	for _, a := range al.dns.A("bridge") {
		if n, ok := al.addrOf[a]; ok {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// toggle turns the phone's tunnel off and on, its lookup of the Bridge
// Address answered with bridge: the old session goes, and the next packet
// starts a handshake.
func (p *phone) toggle(bridge *lab.Node, port int) {
	p.t.Helper()
	gw := netip.PrefixFrom(p.node.Addr(), 24).Masked().Addr().Next()
	if out, err := p.node.Command("ip", "route", "replace", bridge.Addr().String()+"/32", "via", gw.String(), "dev", "wan0").CombinedOutput(); err != nil {
		p.t.Fatalf("route to %s: %v: %s", bridge.Name(), err, out)
	}
	err := p.node.Do(func() error {
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer c.Close()
		keepalive := 5 * time.Second
		return c.ConfigureDevice("wg0", wgtypes.Config{ReplacePeers: true, Peers: []wgtypes.PeerConfig{{
			PublicKey:                   p.bridgeKey,
			Endpoint:                    &net.UDPAddr{IP: bridge.Addr().AsSlice(), Port: port},
			AllowedIPs:                  []net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}},
			PersistentKeepaliveInterval: &keepalive,
		}}})
	})
	if err != nil {
		p.t.Fatal(err)
	}
}
