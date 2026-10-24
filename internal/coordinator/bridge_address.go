package coordinator

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alakiani/ways/internal/probe"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// AddressDNS sets the Bridge Address's A record; the ArvanCloud client is
// one (ADR 0011).
type AddressDNS interface {
	SetA(ctx context.Context, host string, addrs []netip.Addr) error
}

// DefaultBridgeAddress is the hostname in every Device's config.
const DefaultBridgeAddress = "bridge.wayfinder.ir"

// AddressSettings are ADR 0011's timings for the Bridge Address.
type AddressSettings struct {
	ProbeEvery  time.Duration // how often the probe Device checks each Bridge
	RemoveAfter time.Duration // how long a Bridge stays ineligible before it leaves the record
	RejoinAfter time.Duration // how long a Bridge outside the record stays eligible before it joins
	// ReportingWithin is how recent a Bridge's last health report must be
	// for its Agent to count as reporting.
	ReportingWithin time.Duration
	ProbeTimeout    time.Duration
	ProbeHostname   string // what the probe resolves through each Bridge
	// Enter runs fn in the network the probe dials from; nil runs it
	// directly. The lab dials from the Coordinator's namespace.
	Enter func(fn func() error) error
}

// DefaultAddressSettings are ADR 0011's: a probe every 15 s, a Bridge
// leaves after 60 s ineligible and rejoins after 5 min eligible. An Agent
// reports every 30 s, so three missed reports mean it is not reporting.
var DefaultAddressSettings = AddressSettings{
	ProbeEvery:      15 * time.Second,
	RemoveAfter:     60 * time.Second,
	RejoinAfter:     5 * time.Minute,
	ReportingWithin: 90 * time.Second,
	ProbeTimeout:    5 * time.Second,
	ProbeHostname:   "www.gstatic.com",
}

// addressState is what the Bridge Address loop remembers between rounds.
// It is not stored: after a restart every Bridge starts its timers afresh.
type addressState struct {
	mu        sync.Mutex
	probes    map[string]protocol.ProbeResult // by Node id
	inelSince map[string]time.Time            // by Node id, while ineligible
	elSince   map[string]time.Time            // by Node id, while eligible
	reasons   map[string][]string             // by Node id, while ineligible
	prober    *probe.Prober
	// published is the record's addresses as ArvanCloud last accepted
	// them, joined; "" until the first update, so a restart sets it once.
	published string
	// dnsFailures counts ArvanCloud API calls failed in a row.
	dnsFailures int
	// joins and removals count changes to the record since start.
	joins, removals int
}

// RunBridgeAddress probes every domestic Bridge, judges eligibility, and
// keeps the Bridge Address's record to the eligible Bridges, every
// ProbeEvery until ctx ends.
func (c *Coordinator) RunBridgeAddress(ctx context.Context) {
	if c.DNS == nil {
		c.log.Warn("no DNS client: the Bridge Address's members are tracked but its record is not updated")
	}
	t := time.NewTicker(c.Address.ProbeEvery)
	defer t.Stop()
	for {
		if err := c.addressRound(ctx); err != nil && ctx.Err() == nil {
			c.log.Error("bridge address", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// addressRound is one round: probe, judge, plan the members, update DNS.
func (c *Coordinator) addressRound(ctx context.Context) error {
	p, err := c.prober(ctx)
	if err != nil {
		return fmt.Errorf("probe Device: %w", err)
	}
	bridges, health, err := c.domesticBridges(ctx)
	if err != nil {
		return err
	}
	defaultRule, err := c.defaultRuleID(ctx)
	if err != nil {
		return err
	}
	bridgePub, err := c.BridgePublicKey(ctx)
	if err != nil {
		return err
	}
	bridgeKey, err := wgtypes.ParseKey(bridgePub)
	if err != nil {
		return err
	}
	port, err := c.devicePort(ctx)
	if err != nil {
		return err
	}
	resolver := store.DevicePool.Addr().Next()

	// Probe every Bridge at once; one dead Bridge must not hold up the rest.
	results := make([]protocol.ProbeResult, len(bridges))
	var wg sync.WaitGroup
	for i, b := range bridges {
		addr, err := netip.ParseAddr(seenAddr(health[b.ID]))
		if err != nil {
			results[i] = protocol.ProbeResult{At: c.store.Now(), Error: "no public address known yet"}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := p.Check(ctx, netip.AddrPortFrom(addr, port), bridgeKey, resolver)
			results[i] = protocol.ProbeResult{OK: err == nil, At: c.store.Now()}
			if err != nil {
				results[i].Error = err.Error()
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}

	now := c.store.Now()
	ids := make([]string, len(bridges))
	names := map[string]string{}
	s := &c.address
	s.mu.Lock()
	for i, b := range bridges {
		ids[i], names[b.ID] = b.ID, b.Name
		s.probes[b.ID] = results[i]
		reasons := ineligibility(results[i], health[b.ID], defaultRule, now, c.Address.ReportingWithin)
		if !results[i].OK {
			c.log.Debug("probe failed", "node", b.Name, "err", results[i].Error)
		}
		_, was := s.inelSince[b.ID]
		switch {
		case len(reasons) == 0:
			delete(s.inelSince, b.ID)
			delete(s.reasons, b.ID)
			if _, ok := s.elSince[b.ID]; !ok {
				s.elSince[b.ID] = now
			}
			if was {
				c.log.Info("Bridge became eligible", "node", b.Name)
			}
		default:
			s.reasons[b.ID] = reasons
			delete(s.elSince, b.ID)
			if !was {
				s.inelSince[b.ID] = now
				c.log.Warn("Bridge became ineligible", "node", b.Name, "reasons", reasons, "probe", results[i].Error)
			}
		}
	}
	for id := range s.probes {
		if !slices.Contains(ids, id) {
			delete(s.probes, id)
			delete(s.inelSince, id)
			delete(s.elSince, id)
			delete(s.reasons, id)
		}
	}
	inelSince, elSince := maps.Clone(s.inelSince), maps.Clone(s.elSince)
	s.mu.Unlock()

	stored, err := c.store.BridgeAddress(ctx)
	if err != nil {
		return err
	}
	var members []string
	for _, m := range stored {
		members = append(members, m.NodeID)
	}
	next := planMembers(members, ids, elSince, inelSince, now, c.Address.RemoveAfter, c.Address.RejoinAfter)
	for _, id := range members {
		if slices.Contains(next, id) {
			continue
		}
		c.log.Warn("Bridge removed from the Bridge Address", "node", cmp.Or(names[id], id))
		if err := c.store.LeaveBridgeAddress(ctx, id); err != nil {
			return err
		}
		s.mu.Lock()
		s.removals++
		s.mu.Unlock()
	}
	for _, id := range next {
		if slices.Contains(members, id) {
			continue
		}
		c.log.Info("Bridge joined the Bridge Address", "node", names[id])
		if err := c.store.JoinBridgeAddress(ctx, id); err != nil {
			return err
		}
		s.mu.Lock()
		s.joins++
		s.mu.Unlock()
	}

	// The record holds every member's public address, never none.
	var addrs []netip.Addr
	for _, id := range next {
		if a, err := netip.ParseAddr(seenAddr(health[id])); err == nil && a.Is4() {
			addrs = append(addrs, a)
		}
	}
	return c.syncAddressRecord(ctx, addrs)
}

// syncAddressRecord makes the Bridge Address's record hold addrs, unless
// it already does or addrs is empty.
func (c *Coordinator) syncAddressRecord(ctx context.Context, addrs []netip.Addr) error {
	if c.DNS == nil || len(addrs) == 0 {
		return nil
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	want := fmt.Sprint(addrs)
	s := &c.address
	s.mu.Lock()
	published := s.published
	s.mu.Unlock()
	if want == published {
		return nil
	}
	err := c.DNS.SetA(ctx, c.BridgeAddress, addrs)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.dnsFailures++
		return fmt.Errorf("%s: %w", c.BridgeAddress, err)
	}
	s.dnsFailures = 0
	s.published = want
	c.log.Info("Bridge Address record updated", "host", c.BridgeAddress, "addrs", addrs)
	return nil
}

// ineligibility lists why a Bridge may not be in the Bridge Address; none
// means it may (ADR 0005, ADR 0011).
func ineligibility(p protocol.ProbeResult, h *protocol.HealthStatus, defaultRule uint64, now time.Time, reportingWithin time.Duration) []string {
	var out []string
	if !p.OK {
		out = append(out, "probe failing")
	}
	if h == nil || now.Sub(h.ReceivedAt) > reportingWithin {
		out = append(out, "Agent not reporting")
		return out
	}
	i := slices.IndexFunc(h.Paths, func(r protocol.RuleHealth) bool { return r.RuleID == defaultRule })
	if i < 0 || h.Paths[i].Mode == "" || h.Paths[i].Mode == "fallback" {
		out = append(out, "no default-Rule Path")
	}
	return out
}

// planMembers works out which Bridges the Bridge Address holds next (ADR
// 0011). A member stays until it has been ineligible for removeAfter. A
// Bridge outside joins once it has been eligible for rejoinAfter, or at
// once while no member is left, so a new fleet is not without one for
// minutes. The record is never emptied: if every member would leave, they
// all stay. A Node no longer a domestic Bridge leaves at once. bridges are
// the domestic Bridges in order, and so is the result.
func planMembers(members, bridges []string, elSince, inelSince map[string]time.Time,
	now time.Time, removeAfter, rejoinAfter time.Duration) []string {
	var kept, out []string
	for _, b := range bridges {
		if slices.Contains(members, b) {
			kept = append(kept, b)
		}
	}
	for _, b := range kept {
		if since, inel := inelSince[b]; !inel || now.Sub(since) < removeAfter {
			out = append(out, b)
		}
	}
	empty := len(out) == 0
	for _, b := range bridges {
		since, el := elSince[b]
		if el && !slices.Contains(kept, b) && (empty || now.Sub(since) >= rejoinAfter) {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return kept
	}
	slices.SortStableFunc(out, func(x, y string) int { return slices.Index(bridges, x) - slices.Index(bridges, y) })
	return out
}

// BridgeAddressStatus reports the Bridges the Bridge Address holds and the
// probe's view of every domestic Bridge, for the status board.
func (c *Coordinator) BridgeAddressStatus(ctx context.Context) (protocol.AddressStatus, error) {
	st := protocol.AddressStatus{Host: c.BridgeAddress, Bridges: []protocol.AddressBridge{}}
	bridges, health, err := c.domesticBridges(ctx)
	if err != nil {
		return st, err
	}
	stored, err := c.store.BridgeAddress(ctx)
	if err != nil {
		return st, err
	}
	s := &c.address
	s.mu.Lock()
	defer s.mu.Unlock()
	st.Joins, st.Removals, st.Published = s.joins, s.removals, s.published != ""
	for _, b := range bridges {
		ab := protocol.AddressBridge{Name: b.Name, Addr: seenAddr(health[b.ID]), Reasons: s.reasons[b.ID]}
		if i := slices.IndexFunc(stored, func(m store.AddressMember) bool { return m.NodeID == b.ID }); i >= 0 {
			joined := time.Unix(stored[i].Joined, 0).UTC()
			ab.InRecord, ab.Joined = true, &joined
		}
		if p, ok := s.probes[b.ID]; ok {
			ab.Probe = &p
			ab.Eligible = len(ab.Reasons) == 0
		}
		if t, ok := s.inelSince[b.ID]; ok {
			ab.IneligibleSince = &t
		}
		st.Bridges = append(st.Bridges, ab)
	}
	return st, nil
}

// domesticBridges are the Bridges tagged IR, by name, with every Node's
// latest health report. Only they face Devices (ADR 0011).
func (c *Coordinator) domesticBridges(ctx context.Context) ([]store.Node, map[string]*protocol.HealthStatus, error) {
	nodes, err := c.store.Nodes(ctx)
	if err != nil {
		return nil, nil, err
	}
	var out []store.Node
	health := map[string]*protocol.HealthStatus{}
	for _, n := range nodes {
		if !isBridge(n) || !isIR(n) {
			continue
		}
		out = append(out, n)
		if health[n.ID], err = c.store.Health(ctx, n.ID); err != nil {
			return nil, nil, err
		}
	}
	return out, health, nil
}

func (c *Coordinator) defaultRuleID(ctx context.Context) (uint64, error) {
	rules, err := c.store.Rules(ctx)
	if err != nil || len(rules) == 0 {
		return 0, err
	}
	return rules[len(rules)-1].ID, nil // in priority order, the default Rule last
}

func (c *Coordinator) devicePort(ctx context.Context) (uint16, error) {
	s, err := c.store.SetSettingIfUnset(ctx, "device_port", strconv.Itoa(DefaultDevicePort))
	if err != nil {
		return 0, err
	}
	port, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("settings.device_port: %w", err)
	}
	return uint16(port), nil
}

// InitProbe creates the probe Device if it does not exist yet, so the
// first snapshots already admit it.
func (c *Coordinator) InitProbe(ctx context.Context) error {
	_, err := c.prober(ctx)
	return err
}

// prober returns the probe Device, creating it once: a Device belonging
// to no User and counted toward no cap, whose key the Coordinator holds.
// Creating it reconciles, so every Bridge admits it.
func (c *Coordinator) prober(ctx context.Context) (*probe.Prober, error) {
	s := &c.address
	s.mu.Lock()
	p := s.prober
	s.mu.Unlock()
	if p == nil {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		k, err := c.store.SetSettingIfUnset(ctx, "probe_private_key", key.String())
		if err != nil {
			return nil, err
		}
		if key, err = wgtypes.ParseKey(k); err != nil {
			return nil, fmt.Errorf("settings.probe_private_key: %w", err)
		}
		addr, err := c.probeDevice(ctx, key.PublicKey().String())
		if err != nil {
			return nil, err
		}
		p = &probe.Prober{PrivateKey: key, Address: addr}
		s.mu.Lock()
		s.prober = p
		s.mu.Unlock()
	}
	p.Hostname, p.Timeout, p.Enter = c.Address.ProbeHostname, c.Address.ProbeTimeout, c.Address.Enter
	return p, nil
}

// probeDevice returns the probe Device's address, adding its row first if
// it has none.
func (c *Coordinator) probeDevice(ctx context.Context, pub string) (netip.Addr, error) {
	devices, err := c.store.Devices(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	if i := slices.IndexFunc(devices, func(d store.Device) bool { return d.PublicKey == pub }); i >= 0 {
		return devices[i].Address, nil
	}
	d, err := c.store.CreateDevice(ctx, "", "probe", pub)
	if err != nil {
		return netip.Addr{}, err
	}
	c.log.Info("probe Device created", "address", d.Address)
	return d.Address, c.Reconcile(ctx)
}

func seenAddr(h *protocol.HealthStatus) string {
	if h == nil {
		return ""
	}
	return h.SeenAddr
}
