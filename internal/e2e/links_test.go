//go:build linux

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/alakiani/ways/internal/lab"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
	"github.com/alakiani/ways/internal/testutil"
)

// binDir holds the agent and amneziawg-go binaries the lab runs. CI builds
// them before the tests; see .github/workflows/ci.yml.
func binDir(t *testing.T) string {
	dir := os.Getenv("WAYS_BIN")
	if dir == "" {
		t.Skip("WAYS_BIN is not set: build ./cmd/agent and amneziawg-go into a directory and point WAYS_BIN at it")
	}
	return dir
}

// mesh is the lab mesh of this test: Nodes running the real Agent binary.
type mesh struct {
	t      *testing.T
	l      *lab.Lab
	co     *coord
	ids    map[string]string // Node name -> id
	agents map[string]*agentProc
	// agentArgs are extra flags for every Agent.
	agentArgs []string
}

func (m *mesh) startAgent(name string, roles []protocol.Role, tags []string) {
	t := m.t
	bin := binDir(t)
	created := m.co.admin.CreateNode(t, protocol.CreateNodeRequest{Name: name, Roles: roles, Tags: tags})
	m.ids[name] = created.Node.ID

	dir := t.TempDir()
	caFile, tokenFile, logFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "token"), filepath.Join(dir, "agent.log")
	os.WriteFile(caFile, m.co.caPEM, 0o644)
	os.WriteFile(tokenFile, []byte(created.EnrollmentToken), 0o600)
	log, err := os.Create(logFile)
	if err != nil {
		t.Fatal(err)
	}
	ap := &agentProc{t: t, node: m.l.Node(name), log: log, args: []string{filepath.Join(bin, "agent"),
		"-coordinators", m.co.agentURL, "-ca", caFile, "-state-dir", filepath.Join(dir, "state"),
		"-enroll-token-file", tokenFile, "-awg-runner", "exec", "-awg-binary", filepath.Join(bin, "amneziawg-go"),
		"-health-interval", "1s"}}
	ap.args = append(ap.args, m.agentArgs...)
	ap.start()
	dumpOnFailure(t, "agent "+name, logFile)
	t.Cleanup(ap.stop)
	m.agents[name] = ap
}

// agentProc is a running Agent binary in a lab Node.
type agentProc struct {
	t    *testing.T
	node *lab.Node
	args []string
	log  *os.File
	cmd  *exec.Cmd
}

func (a *agentProc) start() {
	a.t.Helper()
	a.cmd = a.node.Command(a.args[0], a.args[1:]...)
	a.cmd.Stdout, a.cmd.Stderr = a.log, a.log
	if err := a.cmd.Start(); err != nil {
		a.t.Fatal(err)
	}
}

func (a *agentProc) stop() {
	if a.cmd != nil && a.cmd.Process != nil {
		a.cmd.Process.Kill()
		a.cmd.Wait()
	}
}

// restart kills the Agent and starts it again on the same state; tunnels
// and nftables state live on, as on a real Node.
func (a *agentProc) restart() {
	a.stop()
	a.start()
}

// linkID is the id of the Link between two Nodes.
func (m *mesh) linkID(a, b string) uint64 {
	m.t.Helper()
	links, err := m.co.store.Links(context.Background())
	if err != nil {
		m.t.Fatal(err)
	}
	for _, l := range links {
		if (l.NodeA == m.ids[a] && l.NodeB == m.ids[b]) || (l.NodeA == m.ids[b] && l.NodeB == m.ids[a]) {
			return l.ID
		}
	}
	m.t.Fatalf("no link between %s and %s", a, b)
	return 0
}

// link is what Node from reports about a Link.
func (m *mesh) link(from string, linkID uint64) protocol.LinkHealth {
	m.t.Helper()
	if h := m.co.health(m.t, m.ids[from]); h != nil {
		for _, lh := range h.Links {
			if lh.LinkID == linkID {
				return lh
			}
		}
	}
	return protocol.LinkHealth{}
}

// instances are a Link's live instances, as the Coordinator stores them.
func (m *mesh) instances(linkID uint64) []store.Instance {
	m.t.Helper()
	all, err := m.co.store.Instances(context.Background())
	if err != nil {
		m.t.Fatal(err)
	}
	var out []store.Instance
	for _, in := range all {
		if in.LinkID == linkID {
			out = append(out, in)
		}
	}
	return out
}

func (m *mesh) instance(id uint64) store.Instance {
	m.t.Helper()
	all, _ := m.co.store.Instances(context.Background())
	for _, in := range all {
		if in.ID == id {
			return in
		}
	}
	m.t.Fatalf("no live instance %d", id)
	return store.Instance{}
}

func (m *mesh) name(nodeID string) string {
	for name, id := range m.ids {
		if id == nodeID {
			return name
		}
	}
	return ""
}

// TestLinks is session 3's "proves in the lab" test: blocking one
// instance's UDP port moves the Link to its other instance within seconds;
// a dead instance is replaced with new parameters. Since ADR 0009 a Link
// that crosses the filter has GRE, two AmneziaWG instances and plain
// WireGuard, in that order; since ADR 0013 a same-side Link has GRE, then
// plain WireGuard.
func TestLinks(t *testing.T) {
	binDir(t)
	for _, mod := range []string{"wireguard", "ip_gre"} {
		if out, err := exec.Command("modprobe", mod).CombinedOutput(); err != nil {
			t.Fatalf("modprobe %s: %v: %s", mod, err, out)
		}
	}
	l := lab.Start(t, "coord", "ir1", "ir2", "ab1", "ab2")
	co := startCoordinator(t, l.Node("coord"))
	co.c.LinkTiming = protocol.LinkTiming{SwitchBackSeconds: 15, RetryMinSeconds: 2, RetryMaxSeconds: 4, ReplaceAfterSeconds: 25}
	m := &mesh{t: t, l: l, co: co, ids: map[string]string{}, agents: map[string]*agentProc{}}

	m.startAgent("ir1", []protocol.Role{protocol.RoleBridge}, []string{"IR"})
	m.startAgent("ir2", []protocol.Role{protocol.RoleBridge, protocol.RoleExit}, []string{"IR"})
	m.startAgent("ab1", []protocol.Role{protocol.RoleExit}, nil)
	m.startAgent("ab2", []protocol.Role{protocol.RoleExit}, nil)

	// Every Link of every Node comes up.
	names := []string{"ir1", "ir2", "ab1", "ab2"}
	testutil.Eventually(t, 90*time.Second, "every link up at both ends", func() bool {
		for i, a := range names {
			for _, b := range names[i+1:] {
				id := m.linkID(a, b)
				if !m.link(a, id).Up || !m.link(b, id).Up {
					return false
				}
			}
		}
		return true
	})

	// Across the filter: GRE, two AmneziaWG, one plain WireGuard.
	cross := m.linkID("ir1", "ab1")
	byTransport := map[protocol.Transport]int{}
	for _, in := range m.instances(cross) {
		byTransport[in.Transport]++
	}
	if byTransport[protocol.TransportGRE] != 1 || byTransport[protocol.TransportAmneziaWG] != 2 || byTransport[protocol.TransportWireGuard] != 1 {
		t.Errorf("crossing link instances by transport = %v, want 1 gre, 2 amneziawg, 1 wireguard", byTransport)
	}
	// Same side: GRE, then plain WireGuard, no AmneziaWG (ADR 0013).
	same := m.linkID("ir1", "ir2")
	byTransport = map[protocol.Transport]int{}
	for _, in := range m.instances(same) {
		byTransport[in.Transport]++
	}
	if byTransport[protocol.TransportGRE] != 1 || byTransport[protocol.TransportWireGuard] != 1 || len(byTransport) != 2 {
		t.Errorf("same-side link instances by transport = %v, want 1 gre, 1 wireguard", byTransport)
	}
	// GRE is preferred. If WireGuard came up a moment sooner, the Link
	// moves to GRE after the switch-back time.
	testutil.Eventually(t, 45*time.Second, "same-side link carried by gre", func() bool {
		return m.link("ir1", same).Transport == protocol.TransportGRE
	})

	// With GRE blocked, the crossing Link runs on AmneziaWG. Blocking the
	// active instance's port moves it within seconds to the other
	// AmneziaWG instance, once that one is Up as a warm standby.
	greBlock := l.Filter(lab.DropGREBetween(l.Node("ir1"), l.Node("ab1")))
	testutil.Eventually(t, 60*time.Second, "both amneziawg instances up and carrying at ir1", func() bool {
		ups := 0
		lh := m.link("ir1", cross)
		for _, ih := range lh.Instances {
			if ih.Up && m.instance(ih.ID).Transport == protocol.TransportAmneziaWG {
				ups++
			}
		}
		return ups == 2 && lh.Transport == protocol.TransportAmneziaWG
	})
	active := m.link("ir1", cross).ActiveInstance
	blocked := m.instance(active)
	block := l.Filter(lab.DropUDP(l.Node(m.name(blocked.Listener)), blocked.ListenPort))
	start := time.Now()
	testutil.Eventually(t, 15*time.Second, "crossing link moves off the blocked instance", func() bool {
		lh := m.link("ir1", cross)
		return lh.Up && lh.ActiveInstance != active && lh.ActiveInstance != 0 && lh.Transport == protocol.TransportAmneziaWG
	})
	moved := time.Since(start)
	t.Logf("crossing link moved from instance %d to %d in %v; instances %+v", active, m.link("ir1", cross).ActiveInstance,
		moved.Round(100*time.Millisecond), m.link("ir1", cross).Instances)
	if moved > 8*time.Second {
		t.Errorf("moving off a blocked instance took %v, want a few seconds", moved)
	}

	// Same side: off GRE while it is blocked, onto plain WireGuard, and
	// back to GRE only after it has been Up for the switch-back time.
	sameGRE := l.Filter(lab.DropGREBetween(l.Node("ir1"), l.Node("ir2")))
	testutil.Eventually(t, 15*time.Second, "same-side link moves to wireguard", func() bool {
		lh := m.link("ir1", same)
		return lh.Up && lh.Transport == protocol.TransportWireGuard
	})
	sameGRE.Remove()
	unblocked := time.Now()
	// GRE counts as Up again once the losses from the block leave its
	// 30 s window, and the Link returns 15 s after that.
	testutil.Eventually(t, 75*time.Second, "same-side link switches back to gre", func() bool {
		return m.link("ir1", same).Transport == protocol.TransportGRE
	})
	if back := time.Since(unblocked); back < 15*time.Second {
		t.Errorf("switched back to gre after %v, before the 15 s switch-back", back)
	}

	// The blocked crossing instance stays dead, so it is replaced: a new
	// instance with a new port and new parameters, which comes up.
	testutil.Eventually(t, 90*time.Second, "the dead instance is replaced and its successor is up", func() bool {
		var fresh *store.Instance
		for _, in := range m.instances(cross) {
			if in.ID == blocked.ID {
				return false
			}
			if in.ID > blocked.ID && in.ListenPort != 0 {
				fresh = &in
			}
		}
		if fresh == nil {
			return false
		}
		for _, ih := range m.link("ir1", cross).Instances {
			if ih.ID == fresh.ID && ih.Up {
				return true
			}
		}
		return false
	})
	for _, in := range m.instances(cross) {
		if in.ID > blocked.ID && in.ListenPort == blocked.ListenPort && *in.AWG == *blocked.AWG {
			t.Errorf("replacement %d kept the dead instance's port and parameters", in.ID)
		}
	}
	block.Remove()
	greBlock.Remove()
}
