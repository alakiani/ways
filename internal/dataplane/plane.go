// Package dataplane is the Agent's Bridge and Exit data plane (ADR 0004,
// ADR 0005, ADR 0008): the Device-facing WireGuard interface with the shared
// Bridge identity, Rules over Destination Sets in nftables, Path selection
// with 64 buckets per Rule spread over candidates, transit hand-off, the
// DNS relay and its redirects, the IPv6 drop, and NAT on Exits with replies
// sent back over the Link they came in on.
package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alakiani/ways/internal/agent"
	"github.com/alakiani/ways/internal/link"
	"github.com/alakiani/ways/internal/protocol"
)

// LinkSource is the Link layer as the data plane uses it.
type LinkSource interface {
	LinkStatus() []link.Status
	// EgressOK is this Node's own egress check.
	EgressOK() bool
	// SetTransitRules sets the Rules this Node offers transit for.
	SetTransitRules([]uint32)
}

// Config configures a Plane.
type Config struct {
	// StateDir caches Destination Sets by hash.
	StateDir string
	Links    LinkSource
	Log      *slog.Logger
	// UpstreamRoots verify the resolver's upstreams' DNS-over-TLS
	// certificates; nil means the system's roots.
	UpstreamRoots *x509.CertPool
}

const (
	syncInterval = 500 * time.Millisecond
	// rulesInterval is how often the ip rules are checked between States:
	// systemd-networkd deletes rules it did not make when it restarts.
	rulesInterval = 5 * time.Second
	usageInterval = 10 * time.Second
	// maxUsagePerReport keeps a health report small after a long outage;
	// the rest goes in the reports after it.
	maxUsagePerReport = 500
)

// Plane is the Agent's Applier for the data plane.
type Plane struct {
	cfg Config
	log *slog.Logger
	wg  *wgctrl.Client

	mu       sync.Mutex
	fetch    agent.Fetch
	st       *protocol.State
	uplink   uplink
	resolver *resolver
	resKey   string // what the running resolver was started with

	// Path selection state, per Rule: buckets for this Bridge's own
	// Devices and for transit traffic, and each candidate's availability.
	dev, tr map[uint64]*bucketState
	avail   map[string]*availability
	applied map[string][buckets]string // nft map name -> buckets in force
	paths   []protocol.RuleHealth
	// views are each Rule's candidates for this Bridge's own Devices, as
	// the last step weighed them, for /metrics.
	views   map[uint64][]candidateView
	transit []uint32
	// moves counts bucket moves of Device traffic by Rule name and kind:
	// steps that moved any bucket, and buckets moved (ADR 0006).
	moves, movedBuckets map[[2]string]uint64

	meter *meter
}

type uplink struct{ dev, gateway string }

// New returns a Plane.
func New(cfg Config) (*Plane, error) {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(cfg.StateDir, "sets"), 0o700); err != nil {
		return nil, err
	}
	m, err := openMeter(filepath.Join(cfg.StateDir, "usage.json"), time.Now)
	if err != nil {
		return nil, err
	}
	return &Plane{cfg: cfg, log: cfg.Log, wg: c, dev: map[uint64]*bucketState{}, tr: map[uint64]*bucketState{},
		avail: map[string]*availability{}, applied: map[string][buckets]string{}, meter: m,
		moves: map[[2]string]uint64{}, movedBuckets: map[[2]string]uint64{}}, nil
}

// UseFetch implements agent.FetchUser.
func (p *Plane) UseFetch(f agent.Fetch) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fetch = f
}

// Apply puts the snapshot's data plane into effect. Run it after the Link
// layer's Apply, so Link instances exist.
func (p *Plane) Apply(ctx context.Context, st protocol.State) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := setSysctls(); err != nil {
		return err
	}
	up, err := findUplink(ctx)
	if err != nil {
		return err
	}
	p.uplink = up

	rs := ruleset{Uplink: up.dev, LinkIfaces: map[string]uint64{}, Exit: slices.Contains(st.Node.Roles, protocol.RoleExit)}
	if m := st.Monitor; m != nil && m.Port != 0 {
		rs.MonitorPort = m.Port
		for _, a := range m.AllowFrom {
			if addr, err := netip.ParseAddr(a); err == nil {
				rs.MonitorAllow = append(rs.MonitorAllow, addr.String())
			}
		}
	}
	for _, l := range st.Links {
		for _, in := range l.Instances {
			rs.LinkIfaces[in.Iface] = l.ID
			if in.Transport == protocol.TransportGRE {
				rs.GREIfaces, rs.GREPeers = append(rs.GREIfaces, in.Iface), append(rs.GREPeers, in.Remote)
			}
			if slices.Contains(l.Peer.Roles, protocol.RoleBridge) {
				rs.TransitIfaces = append(rs.TransitIfaces, in.Iface)
			}
		}
	}

	p.st = &st
	b := st.Bridge
	if b != nil && len(b.Rules) > 0 {
		if err := p.applyDeviceIface(ctx, b); err != nil {
			return fmt.Errorf("device interface: %w", err)
		}
		rs.Bridge = true
		rs.DefaultRule = b.Rules[len(b.Rules)-1].ID
		addr, err := netip.ParsePrefix(b.Address)
		if err != nil {
			return err
		}
		rs.ResolverAddr = addr.Addr().String()
		rs.Throttles = throttles(b.Devices)
		dev, tr := p.computePaths()
		for _, r := range b.AllRules() {
			if r.Source != "" {
				src, err := netip.ParsePrefix(r.Source)
				if err != nil || !src.Addr().Is4() {
					return fmt.Errorf("rule %s: bad source %q", r.Name, r.Source)
				}
				rs.Rules = append(rs.Rules, nftRule{ID: r.ID, Source: src.Masked().String(), Device: dev[r.ID], Transit: tr[r.ID]})
				continue
			}
			prefixes, err := p.set(ctx, r.SetHash)
			if err != nil {
				return fmt.Errorf("rule %s: %w", r.Name, err)
			}
			rs.Rules = append(rs.Rules, nftRule{ID: r.ID, Elements: prefixes, Device: dev[r.ID], Transit: tr[r.ID]})
		}
	} else {
		rs.TransitIfaces = nil
		deleteLink(ctx, DeviceIface)
	}

	// Count what moved under the old ruleset before its counters go, also
	// right after an Agent restart, when the old ruleset is still loaded.
	if st.Bridge != nil {
		p.collectUsage(ctx, &st)
	}
	if err := nft(ctx, render(rs)); err != nil {
		return err
	}
	p.meter.reset()
	clear(p.applied)
	for _, r := range rs.Rules {
		p.applied[fmt.Sprintf("dev_%d", r.ID)] = r.Device
		p.applied[fmt.Sprintf("tr_%d", r.ID)] = r.Transit
	}
	if _, err := p.syncRules(ctx); err != nil {
		return err
	}
	return p.syncResolver()
}

// Run keeps each Rule's buckets in step with the Links until ctx ends.
func (p *Plane) Run(ctx context.Context) {
	t := time.NewTicker(syncInterval)
	defer t.Stop()
	usage := time.NewTicker(usageInterval)
	defer usage.Stop()
	rules := time.NewTicker(rulesInterval)
	defer rules.Stop()
	for {
		select {
		case <-rules.C:
			p.mu.Lock()
			if p.st != nil {
				if n, err := p.syncRules(ctx); err != nil {
					p.log.Warn("ip rules", "err", err)
				} else if n > 0 {
					p.log.Warn("ip rules restored; something else deleted them", "count", n)
				}
			}
			p.mu.Unlock()
		case <-usage.C:
			p.mu.Lock()
			if p.st != nil && p.st.Bridge != nil {
				p.collectUsage(ctx, p.st)
			}
			p.mu.Unlock()
		case <-ctx.Done():
			p.mu.Lock()
			if p.resolver != nil {
				p.resolver.stop()
			}
			p.mu.Unlock()
			return
		case <-t.C:
			p.mu.Lock()
			p.syncPaths(ctx)
			p.mu.Unlock()
		}
	}
}

// applyDeviceIface brings up the Device-facing interface with the shared
// Bridge identity and exactly the snapshot's Devices as peers.
func (p *Plane) applyDeviceIface(ctx context.Context, b *protocol.BridgeState) error {
	key, err := wgtypes.ParseKey(b.PrivateKey)
	if err != nil {
		return err
	}
	if !linkExists(ctx, DeviceIface) {
		if err := ip(ctx, "link", "add", "dev", DeviceIface, "type", "wireguard"); err != nil {
			return err
		}
	}
	dev, err := p.wg.Device(DeviceIface)
	if err != nil {
		return err
	}
	port := int(b.ListenPort)
	cfg := wgtypes.Config{PrivateKey: &key, ListenPort: &port}
	want := map[wgtypes.Key]bool{}
	for _, d := range b.Devices {
		pk, err := wgtypes.ParseKey(d.PublicKey)
		if err != nil {
			p.log.Warn("skipping device with a bad key", "address", d.Address)
			continue
		}
		_, ipnet, err := net.ParseCIDR(d.Address)
		if err != nil {
			continue
		}
		want[pk] = true
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: pk, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*ipnet}})
	}
	for _, peer := range dev.Peers {
		if !want[peer.PublicKey] {
			cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: peer.PublicKey, Remove: true})
		}
	}
	if err := p.wg.ConfigureDevice(DeviceIface, cfg); err != nil {
		return err
	}
	if err := ip(ctx, "addr", "replace", b.Address, "dev", DeviceIface); err != nil {
		return err
	}
	return ip(ctx, "link", "set", "dev", DeviceIface, "mtu", "1420", "up")
}

// throttles returns the snapshot's throttled Devices in address order. A
// Device without a valid IPv4 address is left out: nft would reject the
// whole ruleset over it.
func throttles(devices []protocol.Device) []throttle {
	var out []throttle
	for _, d := range devices {
		prefix, err := netip.ParsePrefix(d.Address)
		if d.Rate == 0 || err != nil || !prefix.Addr().Is4() {
			continue
		}
		out = append(out, throttle{Addr: prefix.Addr(), Rate: d.Rate})
	}
	slices.SortFunc(out, func(a, b throttle) int { return a.Addr.Compare(b.Addr) })
	return slices.CompactFunc(out, func(a, b throttle) bool { return a.Addr == b.Addr })
}

// set returns a Destination Set's prefixes, from the cache or the
// Coordinator. Content is checked against its hash before it is used.
func (p *Plane) set(ctx context.Context, hash string) ([]string, error) {
	path := filepath.Join(p.cfg.StateDir, "sets", hash)
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if p.fetch == nil {
			return nil, errors.New("set not cached and the Coordinator is not reachable yet")
		}
		if body, err = p.fetch(ctx, "/v1/sets/"+hash); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != hash {
		os.Remove(path)
		return nil, fmt.Errorf("set %s: content does not match its hash", hash)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			if _, err := netip.ParsePrefix(line); err != nil {
				return nil, fmt.Errorf("set %s: %w", hash, err)
			}
			out = append(out, line)
		}
	}
	return out, nil
}

// syncRules keeps exactly this plane's ip rules: each Link's mark leads
// to the Link's table, the local mark to the main table, and the drop mark
// to a blackhole. Device traffic that matches no Rule is dropped by
// nftables, not by an ip rule: an "iif ways0" rule would also catch the
// kernel's reverse-path lookups for replies to Devices and drop them all.
// It returns how many rules it added.
func (p *Plane) syncRules(ctx context.Context) (int, error) {
	want := map[string]bool{}
	for _, l := range p.st.Links {
		want[fmt.Sprintf("%d fwmark %#x lookup %s", prioLinks, linkMark(l.ID), link.LinkTable(l.ID))] = true
	}
	if p.st.Bridge != nil {
		if err := ip(ctx, "route", "replace", "blackhole", "default", "table", fmt.Sprint(dropTable)); err != nil {
			return 0, err
		}
		want[fmt.Sprintf("%d fwmark %#x lookup main", prioRules, localMark)] = true
		want[fmt.Sprintf("%d fwmark %#x lookup %d", prioRules, dropMark, dropTable)] = true
	}
	have, err := ourRules(ctx)
	if err != nil {
		return 0, err
	}
	added := 0
	for spec := range want {
		if !have[spec] {
			f := strings.Fields(spec)
			if err := ip(ctx, append([]string{"rule", "add", "priority"}, f...)...); err != nil {
				return added, err
			}
			added++
		}
	}
	for spec := range have {
		if !want[spec] {
			f := strings.Fields(spec)
			ip(ctx, append([]string{"rule", "del", "priority"}, f...)...)
		}
	}
	return added, nil
}

// computePaths steps every Rule's buckets and returns them resolved, for
// Devices and for transit. Call with mu held.
func (p *Plane) computePaths() (dev, tr map[uint64][buckets]string) {
	b := p.st.Bridge
	if b == nil {
		return nil, nil
	}
	now := time.Now()
	links := p.cfg.Links.LinkStatus()
	selfEgress := p.cfg.Links.EgressOK()
	var transit []uint32
	var health []protocol.RuleHealth
	views := map[uint64][]candidateView{}
	for _, r := range b.AllRules() {
		for _, view := range []struct {
			name    string
			states  map[uint64]*bucketState
			transit bool
		}{{"dev", p.dev, false}, {"tr", p.tr, true}} {
			cands := deriveCandidates(r, p.st.Node, selfEgress, links, view.transit)
			eligible, ownEligible := 0, false
			fillThroughput(cands)
			for i := range cands {
				c := &cands[i]
				key := fmt.Sprintf("%d|%s|%s", r.ID, view.name, c.key)
				a := p.avail[key]
				if a == nil {
					a = &availability{}
					p.avail[key] = a
				}
				a.observe(now, c.eligible)
				c.avail = a.value(now, b.Scoring)
				c.weight = weight(c.mbps, c.avail, c.rtt, b.Scoring)
				if c.eligible {
					eligible++
					ownEligible = ownEligible || c.kind != candTransit
				}
			}
			st := view.states[r.ID]
			if st == nil {
				st = &bucketState{}
				view.states[r.ID] = st
			}
			moves := st.step(now, cands, b.Scoring)
			logMoves(p.log, r.Name, view.name, moves)
			if !view.transit {
				p.countMoves(r.Name, moves)
				views[r.ID] = targetShares(cands, b.Scoring.Cutoff)
			}
			if !view.transit {
				if ownEligible {
					transit = append(transit, uint32(r.ID))
				}
				health = append(health, protocol.RuleHealth{RuleID: r.ID, Mode: orNone(st.mode), Eligible: eligible})
			}
		}
	}
	dev, tr = resolve(b.AllRules(), p.dev), resolve(b.AllRules(), p.tr)
	for i := range health {
		shares := map[string]int{}
		for _, k := range dev[health[i].RuleID] {
			shares[k]++
		}
		health[i].Shares = shares
	}
	p.paths, p.views = health, views
	if !slices.Equal(transit, p.transit) {
		p.log.Info("transit offered", "rules", transit)
		p.transit = transit
	}
	p.cfg.Links.SetTransitRules(transit)
	return dev, tr
}

// logMoves logs one line per kind of move, with how many buckets went.
func logMoves(log *slog.Logger, rule, view string, moves []move) {
	type group struct{ from, to, kind, reason string }
	counts := map[group]int{}
	var order []group
	for _, m := range moves {
		g := group{orNone(m.from), orNone(m.to), m.kind, m.reason}
		if counts[g] == 0 {
			order = append(order, g)
		}
		counts[g]++
	}
	for _, g := range order {
		log.Info("buckets moved", "rule", rule, "view", view, "count", counts[g], "from", g.from, "to", g.to,
			"kind", g.kind, "reason", g.reason)
	}
}

// syncPaths moves whatever buckets changed, one atomic nft transaction for
// all of them. Call with mu held.
func (p *Plane) syncPaths(ctx context.Context) {
	if p.st == nil || p.st.Bridge == nil {
		if p.st != nil {
			p.cfg.Links.SetTransitRules(nil)
		}
		return
	}
	dev, tr := p.computePaths()
	var b strings.Builder
	next := map[string][buckets]string{}
	for _, r := range p.st.Bridge.AllRules() {
		for name, assign := range map[string][buckets]string{fmt.Sprintf("dev_%d", r.ID): dev[r.ID], fmt.Sprintf("tr_%d", r.ID): tr[r.ID]} {
			b.WriteString(bucketUpdates(name, p.applied[name], assign))
			next[name] = assign
		}
	}
	if b.Len() == 0 {
		return
	}
	if err := nft(ctx, b.String()); err != nil {
		p.log.Error("move buckets", "err", err)
		return
	}
	p.applied = next
}

// Report adds bucket shares per candidate per Rule, and usage, to a
// health report. A Bridge reads its counters first, so the report carries
// every byte moved until now, not as of the last 10 s reading (ADR 0010).
func (p *Plane) Report(ctx context.Context, h *protocol.Health) {
	p.mu.Lock()
	h.Paths = slices.Clone(p.paths)
	if p.st != nil && p.st.Bridge != nil {
		p.collectUsage(ctx, p.st)
	}
	p.mu.Unlock()
	h.Usage = p.meter.report(maxUsagePerReport)
}

// Acked drops the usage the Coordinator now has.
func (p *Plane) Acked(h *protocol.Health) { p.meter.acked(h.Usage) }

// collectUsage reads the counting sets into the meter, naming Exits by st.
// Call with mu held.
func (p *Plane) collectUsage(ctx context.Context, st *protocol.State) {
	peers := map[uint32]string{}
	for _, l := range st.Links {
		peers[linkMark(l.ID)] = l.Peer.ID
	}
	self := st.Node.ID
	exitOf := func(mark uint32) string {
		if mark == localMark {
			return self
		}
		return peers[mark] // a transit Bridge's id while in transit
	}
	if err := p.meter.collect(func(set string) ([]counterElem, error) { return readCounters(ctx, set) }, exitOf); err != nil {
		p.log.Warn("read usage counters", "err", err)
	}
}

// readCounters lists a counting set's elements and their byte counters.
func readCounters(ctx context.Context, set string) ([]counterElem, error) {
	out, err := exec.CommandContext(ctx, "nft", "-j", "list", "set", "inet", "ways", set).Output()
	if err != nil {
		return nil, err
	}
	return parseCounters(out)
}

// parseCounters reads `nft -j list set` output for sets of
// ipv4_addr . mark with per-element counters.
func parseCounters(b []byte) ([]counterElem, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []counterElem
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		for _, raw := range item.Set.Elem {
			var e struct {
				Elem struct {
					Val struct {
						Concat []json.RawMessage `json:"concat"`
					} `json:"val"`
					Counter struct {
						Bytes uint64 `json:"bytes"`
					} `json:"counter"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &e); err != nil || len(e.Elem.Val.Concat) != 2 {
				continue
			}
			var addr string
			var mark uint32
			if json.Unmarshal(e.Elem.Val.Concat[0], &addr) != nil || json.Unmarshal(e.Elem.Val.Concat[1], &mark) != nil {
				continue
			}
			out = append(out, counterElem{addr: addr, mark: mark, bytes: e.Elem.Counter.Bytes})
		}
	}
	return out, nil
}

// resolverMark is the mark of the resolver's own queries: those of a
// Device at the resolver's address, in the default Rule, or in the Abroad
// Rule for an Abroad Device's lookups (ADR 0014). Call with mu held.
func (p *Plane) resolverMark(abroad bool) uint32 {
	b := p.st.Bridge
	if b == nil || len(b.Rules) == 0 || abroad && b.AbroadRule == nil {
		return dropMark
	}
	rule := b.Rules[len(b.Rules)-1].ID
	if abroad {
		rule = b.AbroadRule.ID
	}
	addr, _ := netip.ParsePrefix(b.Address)
	bucket := int(addr.Addr().As4()[3]) % buckets
	return markFor(p.applied[fmt.Sprintf("dev_%d", rule)][bucket])
}

// syncResolver runs the DNS relay on a Bridge, restarting it when what it
// relays changes. Call with mu held.
func (p *Plane) syncResolver() error {
	b := p.st.Bridge
	key := ""
	var abroad netip.Prefix
	if b != nil {
		addr, _ := netip.ParsePrefix(b.Address)
		if b.AbroadRule != nil {
			abroad, _ = netip.ParsePrefix(b.AbroadRule.Source)
		}
		key = fmt.Sprintf("%s|%s|%s|%s", addr.Addr(), strings.Join(b.Upstreams, ","), abroad, strings.Join(b.AbroadUpstreams, ","))
	}
	if key == p.resKey {
		return nil
	}
	if p.resolver != nil {
		p.resolver.stop()
		p.resolver = nil
	}
	p.resKey = ""
	if b == nil {
		return nil
	}
	addr, _ := netip.ParsePrefix(b.Address)
	markOf := func(abroad bool) func() uint32 {
		return func() uint32 {
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.resolverMark(abroad)
		}
	}
	r := newResolver(net.JoinHostPort(addr.Addr().String(), "53"), b.Upstreams, markOf(false))
	r.roots = p.cfg.UpstreamRoots
	r.abroad, r.abroadUpstreams, r.abroadMark = abroad, b.AbroadUpstreams, markOf(true)
	if err := r.start(); err != nil {
		return fmt.Errorf("resolver: %w", err)
	}
	p.resolver, p.resKey = r, key
	p.log.Info("resolver up", "listen", r.addrUDP(), "upstreams", b.Upstreams, "abroad_upstreams", b.AbroadUpstreams)
	return nil
}

// ourRules lists the ip rules in this plane's priority band.
func ourRules(ctx context.Context) (map[string]bool, error) {
	out, err := exec.CommandContext(ctx, "ip", "-j", "rule", "show").Output()
	if err != nil {
		return nil, err
	}
	var rules []struct {
		Priority int    `json:"priority"`
		Fwmark   string `json:"fwmark"`
		Table    string `json:"table"`
	}
	if err := json.Unmarshal(out, &rules); err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, r := range rules {
		switch {
		case r.Priority < prioRules || r.Priority > prioMax:
		case r.Fwmark != "":
			have[fmt.Sprintf("%d fwmark %s lookup %s", r.Priority, r.Fwmark, r.Table)] = true
		}
	}
	return have, nil
}

// setSysctls turns on forwarding and loose reverse-path filtering: replies
// and transit traffic arrive over Links, not the interface the main table
// would use to reach their sources.
func setSysctls() error {
	for k, v := range map[string]string{
		"ip_forward":             "1",
		"conf/all/rp_filter":     "2",
		"conf/default/rp_filter": "2",
	} {
		if err := os.WriteFile("/proc/sys/net/ipv4/"+k, []byte(v), 0o644); err != nil {
			return fmt.Errorf("sysctl %s: %w", k, err)
		}
	}
	return nil
}

// findUplink is the interface and gateway of the main table's default
// route: the Node's public NIC.
func findUplink(ctx context.Context) (uplink, error) {
	out, err := exec.CommandContext(ctx, "ip", "-j", "route", "show", "default", "table", "main").Output()
	if err != nil {
		return uplink{}, err
	}
	var routes []struct {
		Dev     string `json:"dev"`
		Gateway string `json:"gateway"`
	}
	if err := json.Unmarshal(out, &routes); err != nil {
		return uplink{}, err
	}
	if len(routes) == 0 {
		return uplink{}, errors.New("no default route: cannot tell the uplink")
	}
	return uplink{dev: routes[0].Dev, gateway: routes[0].Gateway}, nil
}

func nft(ctx context.Context, ruleset string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func ip(ctx context.Context, args ...string) error {
	if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

func linkExists(ctx context.Context, dev string) bool {
	return exec.CommandContext(ctx, "ip", "link", "show", "dev", dev).Run() == nil
}

func deleteLink(ctx context.Context, dev string) {
	if linkExists(ctx, dev) {
		ip(ctx, "link", "del", "dev", dev)
	}
}
