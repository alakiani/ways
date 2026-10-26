//go:build linux

package e2e

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alakiani/ways/internal/coordinator"
	"github.com/alakiani/ways/internal/lab"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/testutil"
)

// TestAbroadDevices is ADR 0014 in the lab: an Abroad Device on an Abroad
// Bridge leaves from a domestic Exit for every destination, its DNS
// included, and is dropped rather than sent out abroad when no domestic
// Exit is left. An ordinary Device on the same Abroad Bridge still splits
// by destination, and an Abroad Device on a domestic Bridge leaves from it.
func TestAbroadDevices(t *testing.T) {
	binDir(t)
	if out, err := execCommand("modprobe", "wireguard"); err != nil {
		t.Fatalf("modprobe wireguard: %v: %s", err, out)
	}
	l := lab.StartSpecs(t,
		lab.Spec{Name: "coord"},
		lab.Spec{Name: "ir1"}, // domestic Bridge and Exit
		lab.Spec{Name: "ab1"}, // Abroad Bridge and Exit
		lab.Spec{Name: "phone1"},
		lab.Spec{Name: "phone2"},
		lab.Spec{Name: "phone3"},
		lab.At("web-ir", "2.144.0.10"),
		lab.At("web-ab", "93.184.215.14"),
		lab.At("dns-ab", "9.9.9.9"),
		// A domestic resolver; like the real ones, it is in the IR set.
		lab.At("dns-ir", "2.189.0.53"),
		lab.At("egress-ab", "1.0.0.10"),
		lab.At("egress-ir", "2.188.0.10"),
	)
	ctx := context.Background()
	co := startCoordinator(t, l.Node("coord"))
	co.c.Upstreams = []string{"9.9.9.9"}
	co.c.AbroadUpstreams = []string{"2.189.0.53"}
	egressTargets(t, co, l.Node("egress-ab"), l.Node("egress-ir"))
	co.c.FeedURL, co.c.RIPEstatURL = serveFeed(t, irFeed("2.144.0.0/14", "2.176.0.0/12")), ""
	if err := co.c.RefreshIRFeed(ctx); err != nil {
		t.Fatal(err)
	}
	dumpNetOnFailure(t, l, "ir1", "ab1", "phone1", "phone2", "phone3")
	whoami(t, l.Node("web-ir"), 7)
	whoami(t, l.Node("web-ab"), 7)
	whoami(t, l.Node("web-ab"), 853)
	upstreamCA := dnsServer(t, l.Node("dns-ab"))
	dnsServer(t, l.Node("dns-ir"))

	// One User with the abroad permission: two Abroad Devices and one
	// ordinary Device.
	user, err := co.store.CreateUser(ctx, "maryam")
	if err != nil {
		t.Fatal(err)
	}
	if err := co.store.SetUserAbroad(ctx, user.ID, true); err != nil {
		t.Fatal(err)
	}
	device := func(name string, abroad bool) (wgtypes.Key, netip.Addr) {
		key, _ := wgtypes.GeneratePrivateKey()
		d, err := co.store.AddDevice(ctx, user.ID, name, key.PublicKey().String(), "", abroad)
		if err != nil {
			t.Fatal(err)
		}
		return key, d.Address
	}
	k1, a1 := device("phone abroad", true)
	k2, a2 := device("phone", false)
	k3, a3 := device("laptop abroad", true)

	m := &mesh{t: t, l: l, co: co, ids: map[string]string{}, agents: map[string]*agentProc{},
		agentArgs: []string{"-upstream-ca", upstreamCA}}
	both := []protocol.Role{protocol.RoleBridge, protocol.RoleExit}
	m.startAgent("ir1", both, []string{"IR"})
	m.startAgent("ab1", both, nil)

	pub, err := co.c.BridgePublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bridgeKey, _ := wgtypes.ParseKey(pub)
	port := coordinator.DefaultDevicePort
	p1 := newPhone(t, l.Node("phone1"), k1, a1, l.Node("ab1"), bridgeKey, port) // Abroad Device, Abroad Bridge
	p2 := newPhone(t, l.Node("phone2"), k2, a2, l.Node("ab1"), bridgeKey, port) // ordinary Device, Abroad Bridge
	p3 := newPhone(t, l.Node("phone3"), k3, a3, l.Node("ir1"), bridgeKey, port) // Abroad Device, domestic Bridge

	ir1, ab1 := l.Node("ir1").Addr().String(), l.Node("ab1").Addr().String()
	webAb, webIR := "93.184.215.14:7", "2.144.0.10:7"
	udp := func(p *phone, target string) func() (string, error) {
		return func() (string, error) { return p.ask(target) }
	}
	tcp := func(p *phone, target string, dns bool) func() (string, error) {
		return func() (string, error) { return p.askTCP(target, dns) }
	}

	// Everything from the Abroad Device leaves from Iran. ir1 receives it
	// from ab1, a Bridge, and classifies it as transit: the Abroad Rule
	// holds there too.
	p1.leavesFrom("an Abroad Device to a site abroad", udp(p1, webAb), ir1, 120*time.Second)
	p1.leavesFrom("an Abroad Device to a site in Iran", udp(p1, webIR), ir1, 30*time.Second)
	p1.leavesFrom("an Abroad Device's DoT", tcp(p1, "93.184.215.14:853", false), ir1, 30*time.Second)
	// Its lookups go to the domestic resolver, from Iran, over UDP and TCP.
	p1.leavesFrom("an Abroad Device's DNS over UDP", udp(p1, "8.8.8.8:53"), "dns:"+ir1, 30*time.Second)
	p1.leavesFrom("an Abroad Device's DNS over TCP", tcp(p1, "8.8.8.8:53", true), "dns:"+ir1, 30*time.Second)

	// An ordinary Device on the Abroad Bridge splits by destination, and
	// its DNS still goes abroad over TLS.
	p2.leavesFrom("an ordinary Device to a site abroad", udp(p2, webAb), ab1, 30*time.Second)
	p2.leavesFrom("an ordinary Device to a site in Iran", udp(p2, webIR), ir1, 30*time.Second)
	p2.leavesFrom("an ordinary Device's DNS", udp(p2, "8.8.8.8:53"), "dns:"+ab1, 30*time.Second)

	// An Abroad Device on a domestic Bridge leaves from that Bridge.
	p3.leavesFrom("an Abroad Device on a domestic Bridge, abroad", udp(p3, webAb), ir1, 60*time.Second)
	p3.leavesFrom("its DNS", udp(p3, "8.8.8.8:53"), "dns:"+ir1, 30*time.Second)

	// With no domestic Exit left, the Abroad Device's traffic is dropped,
	// never sent out of the Abroad Bridge (ADR 0014). ir1 loses its own
	// egress check, so it is no longer an eligible Exit.
	if out, err := l.Node("ir1").Command("nft", "add table ip cut; add chain ip cut out { type filter hook output priority 0; }; "+
		"add rule ip cut out ip daddr 2.188.0.10 drop").CombinedOutput(); err != nil {
		t.Fatalf("cutting ir1's egress check: %v: %s", err, out)
	}
	testutil.Eventually(t, 30*time.Second, "the Abroad Device is cut off", func() bool {
		_, err := p1.ask(webAb)
		return err != nil
	})
	for range 5 {
		if got, err := p1.ask(webAb); err == nil {
			t.Fatalf("with no domestic Exit, the Abroad Device left from %s", got)
		}
	}
	p2.leavesFrom("the ordinary Device still browses abroad", udp(p2, webAb), ab1, 5*time.Second)

	// It comes back when ir1 does.
	if out, err := l.Node("ir1").Command("nft", "delete table ip cut").CombinedOutput(); err != nil {
		t.Fatalf("restoring ir1's egress check: %v: %s", err, out)
	}
	p1.leavesFrom("the Abroad Device after ir1 recovered", udp(p1, webAb), ir1, 60*time.Second)

	// Without the permission, its Abroad Devices leave the Bridges.
	if err := co.store.SetUserAbroad(ctx, user.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := co.c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, 20*time.Second, "the Abroad Device without the permission is cut off", func() bool {
		_, err := p1.ask(webAb)
		return err != nil
	})
	p2.leavesFrom("the ordinary Device is unaffected", udp(p2, webAb), ab1, 5*time.Second)
}
