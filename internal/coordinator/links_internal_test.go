package coordinator

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/alakiani/ways/internal/awg"
	"github.com/alakiani/ways/internal/ca"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

type mesh struct {
	t     *testing.T
	c     *Coordinator
	s     *store.Store
	nodes map[string]store.Node
	addrs map[string]string // each Node's public address
}

var bg = context.Background()

// newMesh creates Nodes by name; those named ir* are tagged IR.
func newMesh(t *testing.T, names ...string) *mesh {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "ways.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := &mesh{t: t, c: New(s, authority, slog.New(slog.DiscardHandler)), s: s, nodes: map[string]store.Node{}, addrs: map[string]string{}}
	for i, name := range names {
		var tags []string
		if name[:2] == "ir" {
			tags = []string{"IR"}
		}
		n, err := s.CreateNode(bg, name, []protocol.Role{protocol.RoleBridge, protocol.RoleExit}, tags)
		if err != nil {
			t.Fatal(err)
		}
		m.nodes[name] = n
		m.addrs[name] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}).String()
		// Every Node has reported once, with its Link key.
		m.health(name, protocol.Health{LinkPublicKey: name + "-key"})
	}
	return m
}

// health delivers a health report from name, as the health handler would.
func (m *mesh) health(name string, h protocol.Health) {
	m.t.Helper()
	n := m.nodes[name]
	if err := m.s.PutHealth(bg, n.ID, h, m.addrs[name]); err != nil {
		m.t.Fatal(err)
	}
	n, _ = m.s.Node(bg, n.ID)
	if _, err := m.c.takeLinkHealth(bg, n, h); err != nil {
		m.t.Fatal(err)
	}
	if err := m.c.Reconcile(bg); err != nil {
		m.t.Fatal(err)
	}
	m.nodes[name] = n
}

func (m *mesh) state(name string) protocol.State {
	m.t.Helper()
	snap, err := m.s.LatestSnapshot(bg, m.nodes[name].ID)
	if err != nil {
		m.t.Fatal(err)
	}
	var st protocol.State
	if err := json.Unmarshal(snap.Body, &st); err != nil {
		m.t.Fatal(err)
	}
	return st
}

func (m *mesh) link(from, to string) protocol.Link {
	m.t.Helper()
	for _, l := range m.state(from).Links {
		if l.Peer.Name == to {
			return l
		}
	}
	m.t.Fatalf("%s has no link to %s", from, to)
	return protocol.Link{}
}

func transports(l protocol.Link) []protocol.Transport {
	var ts []protocol.Transport
	for _, in := range l.Instances {
		ts = append(ts, in.Transport)
	}
	return ts
}

// choose has the listening end of every link of name pick ports and
// parameters, as its Agent would.
func (m *mesh) choose(name string) {
	m.t.Helper()
	var h protocol.Health
	for _, l := range m.state(name).Links {
		for _, in := range l.Instances {
			if l.Initiator || in.ListenPort != 0 || in.Transport == protocol.TransportGRE {
				continue
			}
			ch := protocol.ListenChoice{InstanceID: in.ID, Port: awg.ChoosePort()}
			if in.Transport == protocol.TransportAmneziaWG {
				p := awg.Generate()
				ch.AWG = &p
			}
			h.Listening = append(h.Listening, ch)
		}
	}
	m.health(name, h)
}

func TestLinksAreAFullMeshWithTransportsByFilterSide(t *testing.T) {
	m := newMesh(t, "ir1", "ir2", "ab1")
	for _, name := range []string{"ir1", "ir2", "ab1"} {
		m.choose(name)
	}

	// Across the filter: IR end initiates; GRE, two AmneziaWG, then plain
	// WireGuard (ADR 0009).
	cross := m.link("ir1", "ab1")
	if !cross.Initiator || m.link("ab1", "ir1").Initiator {
		t.Error("across the filter, the IR end must initiate")
	}
	wantCross := []protocol.Transport{protocol.TransportGRE, protocol.TransportAmneziaWG, protocol.TransportAmneziaWG, protocol.TransportWireGuard}
	for _, l := range []protocol.Link{cross, m.link("ab1", "ir1")} {
		if ts := transports(l); !slices.Equal(ts, wantCross) {
			t.Errorf("crossing link transports = %v, want %v", ts, wantCross)
		}
	}

	// Same side: lower id initiates; GRE, then plain WireGuard (ADR 0013).
	same := m.link("ir1", "ir2")
	lowerIsIR1 := m.nodes["ir1"].ID < m.nodes["ir2"].ID
	if same.Initiator != lowerIsIR1 {
		t.Errorf("same-side initiator: ir1 initiates = %v, want %v", same.Initiator, lowerIsIR1)
	}
	wantSame := []protocol.Transport{protocol.TransportGRE, protocol.TransportWireGuard}
	for _, l := range []protocol.Link{same, m.link("ir2", "ir1")} {
		if ts := transports(l); !slices.Equal(ts, wantSame) {
			t.Errorf("same-side link transports = %v, want %v", ts, wantSame)
		}
	}
	if n := len(m.state("ir1").Links); n != 2 {
		t.Errorf("ir1 has %d links, want 2", n)
	}
}

// udpInstances are a Link's instances without GRE, which needs no choice.
func udpInstances(l protocol.Link) []protocol.Instance {
	return slices.DeleteFunc(slices.Clone(l.Instances), func(in protocol.Instance) bool { return in.Transport == protocol.TransportGRE })
}

func TestInitiatorGetsTheListenersChoice(t *testing.T) {
	m := newMesh(t, "ir1", "ab1")
	if l := udpInstances(m.link("ab1", "ir1")); len(l) != 3 || l[0].ListenPort != 0 || l[0].AWG != nil {
		t.Fatalf("listener before choosing = %+v, want instances asking it to choose", l)
	}
	if l := udpInstances(m.link("ir1", "ab1")); len(l) != 0 {
		t.Fatalf("initiator has %d UDP instances before the listener chose", len(l))
	}

	m.choose("ab1")
	listen, init := udpInstances(m.link("ab1", "ir1")), udpInstances(m.link("ir1", "ab1"))
	if len(init) != 3 {
		t.Fatalf("initiator has %d UDP instances, want 3", len(init))
	}
	for i := range init {
		li, ii := listen[i], init[i]
		isAWG := li.Transport == protocol.TransportAmneziaWG
		if li.ID != ii.ID || li.ListenPort == 0 || isAWG && (li.AWG == nil || *li.AWG != *ii.AWG) || !isAWG && ii.AWG != nil {
			t.Errorf("instance %d: listener %+v, initiator %+v", i, li, ii)
		}
		if want := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.2"), li.ListenPort).String(); ii.Endpoint != want {
			t.Errorf("endpoint = %q, want %q", ii.Endpoint, want)
		}
		lp, ip := netip.MustParsePrefix(li.Addr), netip.MustParsePrefix(ii.Addr)
		if lp.Bits() != 31 || lp.Masked() != ip.Masked() || li.PeerAddr != ip.Addr().String() || ii.PeerAddr != lp.Addr().String() {
			t.Errorf("addresses: listener %s→%s, initiator %s→%s", li.Addr, li.PeerAddr, ii.Addr, ii.PeerAddr)
		}
		if !MeshRange.Contains(lp.Addr()) || li.Iface == ii.Iface {
			t.Errorf("listener %+v, initiator %+v", li, ii)
		}
	}
	if listen[0].ListenPort == listen[1].ListenPort && *listen[0].AWG == *listen[1].AWG {
		t.Error("two instances share a fingerprint")
	}
}

// A GRE instance needs no choice from the listener: both ends get it at
// once, each with the other's seen address as the remote end (ADR 0009).
func TestGREInstanceHasThePeersSeenAddress(t *testing.T) {
	m := newMesh(t, "ir1", "ab1")
	init, listen := m.link("ir1", "ab1").Instances, m.link("ab1", "ir1").Instances
	if len(init) == 0 || len(listen) == 0 || init[0].Transport != protocol.TransportGRE || listen[0].Transport != protocol.TransportGRE {
		t.Fatalf("before any choice: initiator %+v, listener %+v, want GRE first on both", init, listen)
	}
	gi, gl := init[0], listen[0]
	if gi.ID != gl.ID || gi.Remote != m.addrs["ab1"] || gl.Remote != m.addrs["ir1"] {
		t.Errorf("GRE remotes: initiator %+v, listener %+v", gi, gl)
	}
	if gi.Endpoint != "" || gi.ListenPort != 0 || gl.ListenPort != 0 || gi.AWG != nil || gl.AWG != nil {
		t.Errorf("GRE instance carries UDP settings: initiator %+v, listener %+v", gi, gl)
	}
	lp, ip := netip.MustParsePrefix(gl.Addr), netip.MustParsePrefix(gi.Addr)
	if lp.Bits() != 31 || lp.Masked() != ip.Masked() || !MeshRange.Contains(lp.Addr()) || gl.PeerAddr != ip.Addr().String() {
		t.Errorf("GRE addresses: listener %s→%s, initiator %s→%s", gl.Addr, gl.PeerAddr, gi.Addr, gi.PeerAddr)
	}
	// A listen choice for a GRE instance is refused.
	m.health("ab1", protocol.Health{Listening: []protocol.ListenChoice{{InstanceID: gl.ID, Port: 20000}}})
	if got := m.link("ab1", "ir1").Instances[0]; got.ListenPort != 0 {
		t.Errorf("a listen port was stored for GRE: %+v", got)
	}

	// The remote follows a new seen address.
	m.addrs["ab1"] = "198.51.100.7"
	m.health("ab1", protocol.Health{})
	if got := m.link("ir1", "ab1").Instances[0]; got.ID != gi.ID || got.Remote != "198.51.100.7" {
		t.Errorf("after ab1 moved: %+v", got)
	}

	// Without an IPv4 seen address there is nothing to point GRE at.
	m.addrs["ab1"] = "2001:db8::7"
	m.health("ab1", protocol.Health{})
	for _, in := range m.link("ir1", "ab1").Instances {
		if in.Transport == protocol.TransportGRE {
			t.Errorf("GRE instance towards an IPv6 address: %+v", in)
		}
	}
}

// Links made before GRE gain the new instances and keep the old ones, so
// the instance carrying a Link stays a candidate. A crossing Link had only
// its two AmneziaWG instances before ADR 0009.
func TestExistingLinksGainGRE(t *testing.T) {
	m := newMesh(t, "ir1", "ab1")
	if err := m.s.SetTransports(bg, []protocol.Transport{protocol.TransportAmneziaWG}); err != nil {
		t.Fatal(err)
	}
	if err := m.c.Reconcile(bg); err != nil {
		t.Fatal(err)
	}
	m.choose("ab1")
	before := m.link("ir1", "ab1").Instances
	if ts := transports(m.link("ir1", "ab1")); !slices.Equal(ts, []protocol.Transport{protocol.TransportAmneziaWG, protocol.TransportAmneziaWG}) {
		t.Fatalf("before GRE: %v", ts)
	}

	// The candidate list as it is now.
	if err := m.s.SetTransports(bg, []protocol.Transport{protocol.TransportWireGuard, protocol.TransportAmneziaWG, protocol.TransportGRE}); err != nil {
		t.Fatal(err)
	}
	if err := m.c.Reconcile(bg); err != nil {
		t.Fatal(err)
	}
	m.choose("ab1")
	after := m.link("ir1", "ab1").Instances
	if len(after) != 4 || after[0].Transport != protocol.TransportGRE || after[3].Transport != protocol.TransportWireGuard {
		t.Fatalf("after GRE: %+v", after)
	}
	for i, old := range before {
		if got := after[i+1]; got.ID != old.ID || got.ListenPort != old.ListenPort || *got.AWG != *old.AWG {
			t.Errorf("AmneziaWG instance %d changed: %+v, was %+v", i, got, old)
		}
	}
}

func TestInvalidChoiceIsIgnored(t *testing.T) {
	m := newMesh(t, "ir1", "ab1")
	in := m.link("ab1", "ir1").Instances[0]
	bad := awg.Generate()
	bad.H2 = bad.H1
	m.health("ab1", protocol.Health{Listening: []protocol.ListenChoice{
		{InstanceID: in.ID, Port: 20000, AWG: &bad},
	}})
	if l := m.link("ab1", "ir1"); l.Instances[0].ListenPort != 0 {
		t.Error("an invalid choice was stored")
	}
}

func TestInstanceDownTooLongIsReplaced(t *testing.T) {
	m := newMesh(t, "ir1", "ab1")
	m.c.LinkTiming.ReplaceAfterSeconds = 3600
	m.choose("ab1")
	l := m.link("ir1", "ab1")
	// GRE, AmneziaWG, AmneziaWG, WireGuard: GRE and the first AmneziaWG
	// instance go down.
	gre, old := l.Instances[0], l.Instances[1]

	report := func(down time.Duration) {
		since := time.Now().Add(-down)
		m.health("ir1", protocol.Health{Links: []protocol.LinkHealth{{LinkID: l.ID, Instances: []protocol.InstanceHealth{
			{ID: gre.ID, DownSince: &since}, {ID: old.ID, DownSince: &since}, {ID: l.Instances[2].ID, Up: true},
		}}}})
	}
	report(59 * time.Minute)
	if got := m.link("ir1", "ab1").Instances[1].ID; got != old.ID {
		t.Fatalf("replaced after 59 minutes")
	}

	// The listener's view of how long it has been down does not count.
	since := time.Now().Add(-2 * time.Hour)
	m.health("ab1", protocol.Health{Links: []protocol.LinkHealth{{LinkID: l.ID, Instances: []protocol.InstanceHealth{{ID: old.ID, DownSince: &since}}}}})
	if got := m.link("ir1", "ab1").Instances[1].ID; got != old.ID {
		t.Fatalf("replaced on the listener's report")
	}

	report(61 * time.Minute)
	listen := m.link("ab1", "ir1")
	if len(listen.Instances) != 4 {
		t.Fatalf("%d instances after replacement, want 4", len(listen.Instances))
	}
	// GRE has no port or fingerprint to change, so it is never replaced
	// (ADR 0009).
	if listen.Instances[0].ID != gre.ID {
		t.Errorf("the GRE instance was replaced: %+v", listen.Instances[0])
	}
	fresh := listen.Instances[2]
	if listen.Instances[1].ID == old.ID || fresh.ID == old.ID || fresh.ID < old.ID || fresh.Transport != protocol.TransportAmneziaWG {
		t.Fatalf("instances after replacement = %+v", listen.Instances)
	}
	if fresh.ListenPort != 0 || fresh.AWG != nil {
		t.Errorf("replacement carries old choices: %+v", fresh)
	}
	m.choose("ab1")
	if got := m.link("ab1", "ir1").Instances[2]; got.ListenPort == old.ListenPort && *got.AWG == *old.AWG {
		t.Error("replacement kept the old port and parameters")
	}
}

func TestTagChangeRederivesTransports(t *testing.T) {
	m := newMesh(t, "ir1", "ab1")
	m.choose("ab1")
	// ab1 moves inside the filter: the Link no longer crosses it.
	if err := m.c.UpdateNode(bg, m.nodes["ab1"].ID, []protocol.Role{protocol.RoleBridge}, []string{"IR"}); err != nil {
		t.Fatal(err)
	}
	m.nodes["ab1"], _ = m.s.Node(bg, m.nodes["ab1"].ID)
	var l protocol.Link
	for _, name := range []string{"ir1", "ab1"} {
		if lk := m.link(name, map[string]string{"ir1": "ab1", "ab1": "ir1"}[name]); !lk.Initiator {
			l = lk
		}
	}
	if ts := transports(l); !slices.Equal(ts, []protocol.Transport{protocol.TransportGRE, protocol.TransportWireGuard}) {
		t.Errorf("after the tag change, listener sees %v, want [gre wireguard]", ts)
	}
}

func TestDisabledTransportIsLeftOut(t *testing.T) {
	m := newMesh(t, "ab1", "ab2")
	m.choose("ab1")
	m.choose("ab2")
	if err := m.s.SetTransports(bg, []protocol.Transport{protocol.TransportWireGuard, protocol.TransportAmneziaWG}); err != nil {
		t.Fatal(err)
	}
	if err := m.c.Reconcile(bg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ab1", "ab2"} {
		for _, l := range m.state(name).Links {
			if ts := transports(l); !slices.Equal(ts, []protocol.Transport{protocol.TransportWireGuard}) {
				t.Errorf("%s: transports %v with gre disabled, want [wireguard]", name, ts)
			}
		}
	}
}

func TestEgressTargetsDependOnTags(t *testing.T) {
	m := newMesh(t, "ir1", "ab1")
	if c := m.state("ir1").EgressCheck; c == nil || c.Hostname != DefaultEgressTargets.IR.Hostname {
		t.Errorf("IR Exit egress check = %+v, want the domestic targets", c)
	}
	if c := m.state("ab1").EgressCheck; c == nil || c.Hostname != DefaultEgressTargets.Abroad.Hostname {
		t.Errorf("abroad Exit egress check = %+v, want the abroad targets", c)
	}
}
