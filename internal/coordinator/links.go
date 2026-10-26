package coordinator

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/alakiani/ways/internal/awg"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// MeshRange holds every instance's /31 (ADR 0007).
var MeshRange = netip.MustParsePrefix("10.78.0.0/16")

// EgressTargets are what Exits check to set egress OK (ADR 0008): an Exit
// tagged IR checks domestic targets, so an international shutdown does not
// pull domestic Exits out of IR traffic; every other Exit checks abroad.
type EgressTargets struct {
	IR, Abroad protocol.EgressCheck
}

// DefaultEgressTargets are starting values; change them without a release
// by setting Coordinator.Egress.
var DefaultEgressTargets = EgressTargets{
	IR: protocol.EgressCheck{
		Resolvers: []string{"178.22.122.100", "78.157.42.100"},
		Hostname:  "www.aparat.com",
		URL:       "https://www.aparat.com/robots.txt",
	},
	Abroad: protocol.EgressCheck{
		Resolvers: []string{"1.1.1.1", "9.9.9.9"},
		Hostname:  "www.gstatic.com",
		URL:       "http://www.gstatic.com/generate_204",
	},
}

func isIR(n store.Node) bool { return slices.Contains(n.Tags, "IR") }

// crosses reports whether a Link between a and b crosses the filter.
func crosses(a, b store.Node) bool { return isIR(a) != isIR(b) }

// ends returns the initiating and listening Node of a Link: the IR end
// initiates across the filter, otherwise the Node with the lower id.
func ends(a, b store.Node) (initiator, listener store.Node) {
	if crosses(a, b) {
		if isIR(a) {
			return a, b
		}
		return b, a
	}
	if a.ID < b.ID {
		return a, b
	}
	return b, a
}

// wantedTransports is a Link's candidate instances by Transport, in
// preference order: across the filter one GRE instance, two AmneziaWG
// instances and one plain WireGuard instance (ADR 0009); on the same side
// one GRE and one plain WireGuard instance, since nothing filters it
// (ADR 0013). Transports off the global list are left out.
func wantedTransports(a, b store.Node, enabled []protocol.Transport) []protocol.Transport {
	want := []protocol.Transport{protocol.TransportGRE, protocol.TransportWireGuard}
	if crosses(a, b) {
		want = []protocol.Transport{protocol.TransportGRE, protocol.TransportAmneziaWG, protocol.TransportAmneziaWG, protocol.TransportWireGuard}
	}
	return slices.DeleteFunc(want, func(t protocol.Transport) bool { return !slices.Contains(enabled, t) })
}

// deriveLinks makes a Link for every Node pair and brings each Link's live
// instances in line with what it should have.
func (c *Coordinator) deriveLinks(ctx context.Context, nodes []store.Node) error {
	enabled, err := c.store.Transports(ctx)
	if err != nil {
		return err
	}
	insts, err := c.store.Instances(ctx)
	if err != nil {
		return err
	}
	byLink := map[uint64][]store.Instance{}
	for _, in := range insts {
		byLink[in.LinkID] = append(byLink[in.LinkID], in)
	}
	for i, a := range nodes {
		for _, b := range nodes[i+1:] {
			l, err := c.store.EnsureLink(ctx, a.ID, b.ID)
			if err != nil {
				return err
			}
			var want []protocol.Transport
			_, listener := ends(a, b)
			if !l.Disabled {
				want = wantedTransports(a, b, enabled)
			}
			for _, in := range byLink[l.ID] {
				// Keep an instance only if its Transport is still wanted and
				// the same end still listens.
				if k := slices.Index(want, in.Transport); k >= 0 && in.Listener == listener.ID {
					want = slices.Delete(want, k, k+1)
					continue
				}
				c.log.Info("retiring instance", "link", l.ID, "instance", in.ID, "transport", in.Transport)
				if err := c.store.RetireInstance(ctx, in.ID); err != nil {
					return err
				}
			}
			for _, t := range want {
				in, err := c.store.CreateInstance(ctx, l.ID, t, listener.ID)
				if err != nil {
					return err
				}
				c.log.Info("new instance", "link", l.ID, "instance", in.ID, "transport", t)
			}
		}
	}
	return nil
}

// meshView is everything desiredState needs about the mesh.
type meshView struct {
	nodes     map[string]store.Node
	links     []store.Link
	instances map[uint64][]store.Instance // by Link id, oldest first
	seenAddr  map[string]string           // a Node's public address, as the Coordinator sees it
	bridge    *protocol.BridgeState       // shared by every Bridge
}

func (c *Coordinator) loadMesh(ctx context.Context, nodes []store.Node) (meshView, error) {
	v := meshView{nodes: map[string]store.Node{}, instances: map[uint64][]store.Instance{}, seenAddr: map[string]string{}}
	for _, n := range nodes {
		v.nodes[n.ID] = n
		h, err := c.store.Health(ctx, n.ID)
		if err != nil {
			return v, err
		}
		if h != nil {
			v.seenAddr[n.ID] = h.SeenAddr
		}
	}
	var err error
	if v.links, err = c.store.Links(ctx); err != nil {
		return v, err
	}
	insts, err := c.store.Instances(ctx)
	if err != nil {
		return v, err
	}
	for _, in := range insts {
		v.instances[in.LinkID] = append(v.instances[in.LinkID], in)
	}
	return v, nil
}

// linksFor is n's view of its Links.
func linksFor(n store.Node, v meshView) []protocol.Link {
	out := []protocol.Link{}
	for _, l := range v.links {
		if l.NodeA != n.ID && l.NodeB != n.ID {
			continue
		}
		peerID := l.NodeA
		if peerID == n.ID {
			peerID = l.NodeB
		}
		peer, ok := v.nodes[peerID]
		if !ok || l.Disabled {
			continue
		}
		initiator, _ := ends(n, peer)
		link := protocol.Link{
			ID:        l.ID,
			Peer:      protocol.Peer{ID: peer.ID, Name: peer.Name, Roles: peer.Roles, Tags: peer.Tags, PublicKey: peer.LinkPublicKey},
			Initiator: initiator.ID == n.ID,
			Instances: []protocol.Instance{},
		}
		if n.LinkPublicKey == "" || peer.LinkPublicKey == "" {
			out = append(out, link) // no instance can come up without both keys
			continue
		}
		for _, in := range preferenceOrder(v.instances[l.ID]) {
			listenAddr, initAddr := slotAddrs(in.Slot)
			pi := protocol.Instance{ID: in.ID, Transport: in.Transport}
			if in.Transport == protocol.TransportGRE {
				// Both ends point their tunnel at the other's seen address,
				// and nobody chooses anything (ADR 0009).
				remote, err := netip.ParseAddr(v.seenAddr[peer.ID])
				if err != nil || !remote.Is4() {
					continue
				}
				pi.Remote = remote.String()
				if link.Initiator {
					pi.Iface = fmt.Sprintf("ways%di", in.ID)
					pi.Addr, pi.PeerAddr = netip.PrefixFrom(initAddr, 31).String(), listenAddr.String()
				} else {
					pi.Iface = fmt.Sprintf("ways%dl", in.ID)
					pi.Addr, pi.PeerAddr = netip.PrefixFrom(listenAddr, 31).String(), initAddr.String()
				}
				link.Instances = append(link.Instances, pi)
				continue
			}
			if link.Initiator {
				addr := v.seenAddr[peer.ID]
				if in.ListenPort == 0 || addr == "" || in.Transport == protocol.TransportAmneziaWG && in.AWG == nil {
					continue // the listener has not chosen yet
				}
				pi.Iface = fmt.Sprintf("ways%di", in.ID)
				pi.Addr, pi.PeerAddr = netip.PrefixFrom(initAddr, 31).String(), listenAddr.String()
				pi.Endpoint = net.JoinHostPort(addr, fmt.Sprint(in.ListenPort))
			} else {
				pi.Iface = fmt.Sprintf("ways%dl", in.ID)
				pi.Addr, pi.PeerAddr = netip.PrefixFrom(listenAddr, 31).String(), initAddr.String()
			}
			pi.ListenPort, pi.AWG = in.ListenPort, in.AWG
			link.Instances = append(link.Instances, pi)
		}
		out = append(out, link)
	}
	return out
}

// preferenceOrder sorts a Link's instances by Transport, then in the order
// they were created: GRE, AmneziaWG, then plain WireGuard (ADR 0009). A
// same-side Link has no AmneziaWG (ADR 0013), so the one order serves both.
func preferenceOrder(insts []store.Instance) []store.Instance {
	order := []protocol.Transport{protocol.TransportGRE, protocol.TransportAmneziaWG, protocol.TransportWireGuard}
	out := slices.Clone(insts)
	slices.SortStableFunc(out, func(a, b store.Instance) int {
		if ra, rb := slices.Index(order, a.Transport), slices.Index(order, b.Transport); ra != rb {
			return ra - rb
		}
		return int(int64(a.ID) - int64(b.ID))
	})
	return out
}

// slotAddrs returns the listener's and the initiator's inner address of a
// mesh slot: the even and the odd address of its /31.
func slotAddrs(slot int) (listener, initiator netip.Addr) {
	base := MeshRange.Addr().As4()
	v := binary.BigEndian.Uint32(base[:]) + uint32(2*slot)
	var a, b [4]byte
	binary.BigEndian.PutUint32(a[:], v)
	binary.BigEndian.PutUint32(b[:], v+1)
	return netip.AddrFrom4(a), netip.AddrFrom4(b)
}

// takeLinkHealth records what a health report says about Links: the
// Node's Link key, the ports and parameters it chose as a listener, and
// how long instances it initiates have been down. An instance down for
// ReplaceAfter is retired, and reconciling gives the Link a fresh one. It
// reports whether anything changed.
func (c *Coordinator) takeLinkHealth(ctx context.Context, n store.Node, h protocol.Health) (bool, error) {
	changed := false
	if h.LinkPublicKey != "" {
		ch, err := c.store.SetLinkPublicKey(ctx, n.ID, h.LinkPublicKey)
		if err != nil {
			return false, err
		}
		changed = changed || ch
	}
	if len(h.Listening) == 0 && len(h.Links) == 0 {
		return changed, nil
	}
	insts, err := c.store.Instances(ctx)
	if err != nil {
		return false, err
	}
	byID := map[uint64]store.Instance{}
	for _, in := range insts {
		byID[in.ID] = in
	}

	for _, ch := range h.Listening {
		in, ok := byID[ch.InstanceID]
		if !ok || in.Listener != n.ID || in.ListenPort != 0 {
			continue
		}
		if err := validChoice(in, ch); err != nil {
			c.log.Warn("rejected listen choice", "node", n.Name, "instance", in.ID, "err", err)
			continue
		}
		stored, err := c.store.SetListenChoice(ctx, in.ID, n.ID, ch.Port, ch.AWG)
		if err != nil {
			return false, err
		}
		changed = changed || stored
	}

	replaceAfter := time.Duration(c.LinkTiming.ReplaceAfterSeconds) * time.Second
	for _, lh := range h.Links {
		for _, ih := range lh.Instances {
			in, ok := byID[ih.ID]
			if !ok || in.Listener == n.ID {
				continue // only the initiating end's view counts
			}
			if err := c.store.SetInstanceDownSince(ctx, in.ID, ih.DownSince); err != nil {
				return false, err
			}
			// Replacing changes an instance's port and fingerprint. A GRE
			// instance has neither, so it just keeps retrying (ADR 0009).
			if in.Transport == protocol.TransportGRE {
				continue
			}
			if ih.DownSince != nil && c.store.Now().Sub(*ih.DownSince) >= replaceAfter {
				c.log.Warn("replacing instance down too long", "link", in.LinkID, "instance", in.ID, "down_since", ih.DownSince)
				if err := c.store.RetireInstance(ctx, in.ID); err != nil {
					return false, err
				}
				changed = true
			}
		}
	}
	return changed, nil
}

func validChoice(in store.Instance, ch protocol.ListenChoice) error {
	if ch.Port < 10000 || ch.Port > 60000 {
		return fmt.Errorf("port %d outside 10000-60000", ch.Port)
	}
	switch in.Transport {
	case protocol.TransportGRE:
		return fmt.Errorf("a GRE instance has no port")
	case protocol.TransportAmneziaWG:
		if ch.AWG == nil {
			return fmt.Errorf("no AmneziaWG parameters")
		}
		return awg.Validate(*ch.AWG)
	default:
		if ch.AWG != nil {
			return fmt.Errorf("AmneziaWG parameters on a %s instance", in.Transport)
		}
	}
	return nil
}
