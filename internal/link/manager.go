// Package link is the Agent's half of the Link layer (ADR 0007): it brings
// up every candidate instance of every Link the snapshot lists, probes each
// one in-tunnel every second, carries each Link on its best Up instance, and
// reports what it measures.
package link

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alakiani/ways/internal/awg"
	"github.com/alakiani/ways/internal/protocol"
)

// Config configures a Manager.
type Config struct {
	// StateDir holds the Link key and the listener's choices.
	StateDir   string
	Transports map[protocol.Transport]Transport
	Log        *slog.Logger
	// CheckEgress runs an Exit's egress check; nil means the real one.
	CheckEgress func(ctx context.Context, c protocol.EgressCheck) bool
	// ProbeInterval is 1 s (ADR 0007); tests may shorten it.
	ProbeInterval time.Duration
}

const (
	keyFile     = "link.key"
	choicesFile = "listen.json"

	egressInterval = 5 * time.Second
	egressMisses   = 3 // in a row before the egress check fails (ADR 0008)
	selectInterval = 200 * time.Millisecond
)

// Manager runs this Node's Links. It is the Agent's Applier for Links.
type Manager struct {
	cfg  Config
	log  *slog.Logger
	key  wgtypes.Key
	ctx  context.Context // lives as long as the Manager runs
	stop context.CancelFunc

	egressOK atomic.Bool
	transit  atomic.Pointer[[]uint32] // Rules this Node carries transit for

	mu      sync.Mutex
	self    string // this Node's name, for metric labels
	timing  protocol.LinkTiming
	egress  *protocol.EgressCheck
	links   map[uint64]*linkState
	insts   map[uint64]*instance
	choices map[uint64]protocol.ListenChoice // this Node's choices as a listener

	// A Bridge measures what each Link's far end can still send it.
	bridge  bool
	scoring protocol.Scoring
	tputs   map[uint64]*throughput
}

type linkState struct {
	id     uint64
	peer   protocol.Peer
	order  []uint64 // instance ids, most preferred first
	active uint64
	routed bool // the Link's table has been set for active
}

// New loads or creates the Node's Link key and its listener's choices.
func New(cfg Config) (*Manager, error) {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.ProbeInterval == 0 {
		cfg.ProbeInterval = time.Second
	}
	if cfg.CheckEgress == nil {
		cfg.CheckEgress = checkEgress
	}
	m := &Manager{cfg: cfg, log: cfg.Log, timing: protocol.DefaultLinkTiming,
		links: map[uint64]*linkState{}, insts: map[uint64]*instance{}, choices: map[uint64]protocol.ListenChoice{},
		scoring: protocol.DefaultScoring, tputs: map[uint64]*throughput{}}
	m.ctx, m.stop = context.WithCancel(context.Background())

	keyPath := filepath.Join(cfg.StateDir, keyFile)
	b, err := os.ReadFile(keyPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if m.key, err = wgtypes.GeneratePrivateKey(); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, []byte(m.key.String()), 0o600); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if m.key, err = wgtypes.ParseKey(strings.TrimSpace(string(b))); err != nil {
			return nil, fmt.Errorf("%s: %w", keyPath, err)
		}
	}

	if b, err := os.ReadFile(filepath.Join(cfg.StateDir, choicesFile)); err == nil {
		var list []protocol.ListenChoice
		if err := json.Unmarshal(b, &list); err != nil {
			return nil, err
		}
		for _, c := range list {
			m.choices[c.InstanceID] = c
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return m, nil
}

// PublicKey is the Node's Link public key.
func (m *Manager) PublicKey() string { return m.key.PublicKey().String() }

// Run answers probes and throughput tests, chooses each Link's active
// instance, runs the egress check and, on a Bridge, the throughput tests,
// until ctx ends. Instances stay up after it returns.
func (m *Manager) Run(ctx context.Context) error {
	defer m.stop()
	conn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", ProbePort))
	if err != nil {
		return fmt.Errorf("probe port: %w", err)
	}
	tln, err := net.Listen("tcp4", fmt.Sprintf(":%d", ThroughputPort))
	if err != nil {
		conn.Close()
		return fmt.Errorf("throughput port: %w", err)
	}
	go serveThroughput(ctx, tln, m.isLinkAddr)
	go m.throughputLoop(ctx)
	go serveProbes(ctx, &wakingConn{conn, m}, func() Flags {
		f := Flags{EgressOK: m.egressOK.Load()}
		if t := m.transit.Load(); t != nil {
			f.TransitRules = *t
		}
		return f
	})
	go m.egressLoop(ctx)

	t := time.NewTicker(selectInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			for _, in := range m.insts {
				in.halt()
			}
			m.mu.Unlock()
			return nil
		case <-t.C:
			m.selectActive(ctx)
		}
	}
}

// wakingConn wakes an instance's prober whenever its peer probes it, so a
// listening end in backoff notices at once that the initiator got through.
type wakingConn struct {
	net.PacketConn
	m *Manager
}

func (c *wakingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, from, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		if ua, ok := from.(*net.UDPAddr); ok {
			if a, ok := netip.AddrFromSlice(ua.IP.To4()); ok {
				c.m.wake(a)
			}
		}
	}
	return n, from, err
}

func (m *Manager) wake(peer netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, in := range m.insts {
		if in.peerAddr == peer {
			in.wake()
		}
	}
}

// Apply brings the Node's instances in line with the snapshot. Instances
// already up with the same configuration are left alone, so an apply never
// resets a live tunnel.
func (m *Manager) Apply(ctx context.Context, st protocol.State) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.self, m.timing = st.Node.Name, st.LinkTiming
	if m.timing.RetryMinSeconds == 0 {
		m.timing = protocol.DefaultLinkTiming
	}
	m.egress = nil
	if slices.Contains(st.Node.Roles, protocol.RoleExit) {
		m.egress = st.EgressCheck
	}
	m.bridge, m.scoring = slices.Contains(st.Node.Roles, protocol.RoleBridge), protocol.DefaultScoring
	if st.Bridge != nil {
		m.scoring = st.Bridge.Scoring
	}

	want := map[uint64]bool{}
	wantIface := map[string]bool{}
	links := map[uint64]*linkState{}
	for _, l := range st.Links {
		ls := m.links[l.ID]
		if ls == nil {
			ls = &linkState{id: l.ID}
		}
		ls.peer, ls.order = l.Peer, nil
		links[l.ID] = ls
		if len(l.Instances) == 0 {
			continue
		}
		peerKey, err := wgtypes.ParseKey(l.Peer.PublicKey)
		if err != nil {
			m.log.Error("bad peer key", "link", l.ID, "peer", l.Peer.Name, "err", err)
			continue
		}
		for _, spec := range l.Instances {
			cfg, err := m.configFor(l, spec, peerKey)
			if err != nil {
				m.log.Error("instance config", "link", l.ID, "instance", spec.ID, "err", err)
				continue
			}
			tr := m.cfg.Transports[spec.Transport]
			if tr == nil {
				m.log.Error("no such transport on this Agent", "instance", spec.ID, "transport", spec.Transport)
				continue
			}
			want[spec.ID], wantIface[spec.Iface] = true, true
			ls.order = append(ls.order, spec.ID)
			if in := m.insts[spec.ID]; in != nil {
				in.reconfigure(cfg)
				continue
			}
			in := newInstance(m.ctx, m, l.ID, spec, cfg, tr, !l.Initiator)
			m.insts[spec.ID] = in
			go in.run()
		}
	}

	for id, in := range m.insts {
		if !want[id] {
			in.halt()
			if err := in.transport.Down(ctx, in.iface()); err != nil {
				m.log.Error("take instance down", "instance", id, "err", err)
			}
			delete(m.insts, id)
			delete(m.choices, id)
			m.log.Info("instance removed", "instance", id)
		}
	}
	for id := range m.links {
		if links[id] == nil {
			flushTable(ctx, id)
		}
	}
	for id := range m.tputs {
		if links[id] == nil {
			delete(m.tputs, id)
		}
	}
	m.links = links

	// Interfaces left from instances this Agent no longer knows, such as
	// ones retired while it was stopped.
	if ifaces, err := instanceIfaces(ctx); err == nil {
		for _, name := range ifaces {
			if !wantIface[name] {
				m.log.Info("removing stray instance interface", "iface", name)
				for _, tr := range m.cfg.Transports {
					tr.Down(ctx, name)
				}
			}
		}
	}
	for id := range m.choices {
		if !want[id] {
			delete(m.choices, id)
		}
	}
	return m.saveChoices()
}

// configFor works out this end's configuration of an instance. On the
// listening end it fills in the port and parameters the Coordinator does
// not have yet from this Agent's earlier choice, or makes one.
func (m *Manager) configFor(l protocol.Link, spec protocol.Instance, peerKey wgtypes.Key) (InstanceConfig, error) {
	addr, err := netip.ParsePrefix(spec.Addr)
	if err != nil {
		return InstanceConfig{}, err
	}
	c := InstanceConfig{Iface: spec.Iface, PrivateKey: m.key, PeerKey: peerKey, Addr: addr, AWG: spec.AWG}
	if spec.Transport == protocol.TransportGRE {
		// Both ends have the other's address; nothing is chosen.
		if c.Remote, err = netip.ParseAddr(spec.Remote); err != nil || !c.Remote.Is4() {
			return InstanceConfig{}, fmt.Errorf("gre remote %q: not an IPv4 address", spec.Remote)
		}
		c.AWG = nil
		return c, nil
	}
	isAWG := spec.Transport == protocol.TransportAmneziaWG
	if l.Initiator {
		if c.Endpoint, err = net.ResolveUDPAddr("udp4", spec.Endpoint); err != nil {
			return InstanceConfig{}, fmt.Errorf("endpoint: %w", err)
		}
		if isAWG && c.AWG == nil {
			return InstanceConfig{}, errors.New("no AmneziaWG parameters from the listener")
		}
		return c, nil
	}
	c.ListenPort = spec.ListenPort
	if c.ListenPort == 0 || isAWG && c.AWG == nil {
		ch, ok := m.choices[spec.ID]
		if !ok {
			ch = protocol.ListenChoice{InstanceID: spec.ID, Port: awg.ChoosePort()}
			if isAWG {
				p := awg.Generate()
				ch.AWG = &p
			}
			m.choices[spec.ID] = ch
			m.log.Info("chose listen port and parameters", "instance", spec.ID, "port", ch.Port)
		}
		if c.ListenPort == 0 {
			c.ListenPort = ch.Port
		}
		if isAWG && c.AWG == nil {
			c.AWG = ch.AWG
		}
	}
	return c, nil
}

func (m *Manager) saveChoices() error {
	list := make([]protocol.ListenChoice, 0, len(m.choices))
	for _, c := range m.choices {
		list = append(list, c)
	}
	slices.SortFunc(list, func(a, b protocol.ListenChoice) int { return int(int64(a.InstanceID) - int64(b.InstanceID)) })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(m.cfg.StateDir, choicesFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(m.cfg.StateDir, choicesFile))
}

// selectActive carries each Link on its best Up instance (ADR 0007).
func (m *Manager) selectActive(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	switchBack := time.Duration(m.timing.SwitchBackSeconds) * time.Second
	for _, ls := range m.links {
		var cands []candidate
		for _, id := range ls.order {
			if in := m.insts[id]; in != nil {
				cands = append(cands, in.candidate())
			}
		}
		next := choose(now, ls.active, cands, switchBack)
		if next == ls.active && ls.routed {
			continue
		}
		iface := ""
		if next != 0 {
			iface = m.insts[next].iface()
		}
		if err := routeVia(ctx, ls.id, iface); err != nil {
			m.log.Error("route link", "link", ls.id, "err", err)
			continue
		}
		if next != ls.active {
			m.log.Info("link switched", "link", ls.id, "peer", ls.peer.Name, "from", ls.active, "to", next)
		}
		ls.active, ls.routed = next, true
	}
}

// SetTransitRules sets the Rules this Node tells its neighbours it can
// carry transit for, in every probe reply (ADR 0008).
func (m *Manager) SetTransitRules(rules []uint32) { m.transit.Store(&rules) }

// EgressOK reports this Node's own latest egress check.
func (m *Manager) EgressOK() bool { return m.egressOK.Load() }

// Status is a Link as the data plane needs it.
type Status struct {
	ID   uint64
	Peer protocol.Peer
	// Up is set while an instance carries the Link; Iface is that
	// instance's interface.
	Up    bool
	Iface string
	// Table is the routing table that carries the Link.
	Table string
	// RTT, and the flags in the peer's latest probe reply, on the active
	// instance.
	RTT              time.Duration
	PeerEgressOK     bool
	PeerTransitRules []uint32
	// ThroughputMbps is the Link's throughput figure, 0 until measured.
	ThroughputMbps float64
}

// LinkStatus returns every Link of this Node, by id.
func (m *Manager) LinkStatus() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Status
	for _, id := range slices.Sorted(maps.Keys(m.links)) {
		ls := m.links[id]
		st := Status{ID: id, Peer: ls.peer, Up: ls.active != 0 && ls.routed, Table: linkTable(id)}
		if tp := m.tputs[id]; tp != nil {
			st.ThroughputMbps = tp.mbps
		}
		if in := m.insts[ls.active]; st.Up && in != nil {
			st.Iface = in.iface()
			in.mu.Lock()
			st.RTT = in.meter.rtt(time.Now())
			st.PeerEgressOK, st.PeerTransitRules = in.flags.EgressOK, slices.Clone(in.flags.TransitRules)
			in.mu.Unlock()
		}
		out = append(out, st)
	}
	return out
}

// LinkTable is the routing table that carries a Link.
func LinkTable(linkID uint64) string { return linkTable(linkID) }

// Report adds the Link key, the listener's choices and Link health to a
// health report.
func (m *Manager) Report(_ context.Context, h *protocol.Health) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	h.LinkPublicKey = m.PublicKey()
	for _, id := range slices.Sorted(maps.Keys(m.insts)) {
		in := m.insts[id]
		if in.listener && in.spec.Transport != protocol.TransportGRE {
			cfg := in.config()
			h.Listening = append(h.Listening, protocol.ListenChoice{InstanceID: id, Port: cfg.ListenPort, AWG: cfg.AWG})
		}
	}
	for _, id := range slices.Sorted(maps.Keys(m.links)) {
		ls := m.links[id]
		lh := protocol.LinkHealth{LinkID: id, Up: ls.active != 0, ActiveInstance: ls.active, LastSuccessSeconds: -1, Instances: []protocol.InstanceHealth{}}
		if tp := m.tputs[id]; tp != nil {
			lh.ThroughputMbps = tp.mbps
		}
		for _, iid := range ls.order {
			in := m.insts[iid]
			if in == nil {
				continue
			}
			ih, lastSuccess, flags := in.health(now)
			lh.Instances = append(lh.Instances, ih)
			if iid == ls.active {
				lh.Transport = in.spec.Transport
				lh.RTTMillis, lh.Loss = ih.RTTMillis, ih.Loss
				if !lastSuccess.IsZero() {
					lh.LastSuccessSeconds = now.Sub(lastSuccess).Seconds()
				}
				lh.PeerEgressOK, lh.PeerTransitRules = flags.EgressOK, flags.TransitRules
			}
		}
		h.Links = append(h.Links, lh)
	}
}

// egressVerdict is the egress check as the Node reports it: it passes at
// the first pass, and fails only after egressMisses misses in a row. A lone
// miss is a slow resolver or object rather than a lost uplink, and failing
// on it moves every bucket off the Exit and back, resetting the
// connections through it twice.
type egressVerdict struct {
	ok     bool
	misses int // in a row
}

func (v *egressVerdict) observe(passed bool) {
	if passed {
		v.ok, v.misses = true, 0
		return
	}
	v.misses++
	if v.misses >= egressMisses {
		v.ok = false
	}
}

func (m *Manager) egressLoop(ctx context.Context) {
	t := time.NewTicker(egressInterval)
	defer t.Stop()
	var v egressVerdict
	for {
		m.mu.Lock()
		check := m.egress
		m.mu.Unlock()
		if check == nil {
			v = egressVerdict{} // not an Exit: nothing to pass
		} else {
			v.observe(m.cfg.CheckEgress(ctx, *check))
		}
		if m.egressOK.Swap(v.ok) != v.ok {
			m.log.Info("egress check changed", "ok", v.ok)
		} else if v.ok && v.misses > 0 {
			m.log.Info("egress check missed", "in_a_row", v.misses, "fails_at", egressMisses)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// checkEgress resolves the hostname through any of the resolvers and
// fetches the URL (ADR 0008).
func checkEgress(ctx context.Context, c protocol.EgressCheck) bool {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	resolved := false
	for _, server := range c.Resolvers {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		}}
		if addrs, err := r.LookupHost(ctx, c.Hostname); err == nil && len(addrs) > 0 {
			resolved = true
			break
		}
	}
	if !resolved {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 400
}
