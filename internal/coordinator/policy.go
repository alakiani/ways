package coordinator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alakiani/ways/internal/irfeed"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// DefaultDevicePort is the UDP port Bridges listen on for Devices
// (ADR 0005, amended in MVP 04).
const DefaultDevicePort = 61873

// DefaultUpstreams are the public resolvers abroad that Bridge resolvers
// forward to (ADR 0004).
var DefaultUpstreams = []string{"1.1.1.1", "9.9.9.9"}

// EffectiveState is what a Bridge does with a Device (ADR 0003).
type EffectiveState string

const (
	StateActive    EffectiveState = "active"
	StateBlocked   EffectiveState = "blocked"
	StateThrottled EffectiveState = "throttled" // slowed to a rate (ADR 0010)
)

// quotaState is what a User's Quota does to their Devices: nothing until
// they run out, then block them, or slow them if an Admin chose that.
type quotaState struct {
	ranOut bool
	rate   uint64 // bytes per second when slowed; 0 blocks
}

func quotaStateOf(q store.QuotaStanding) quotaState {
	if !q.RanOut() {
		return quotaState{}
	}
	return quotaState{ranOut: true, rate: q.SlowRate}
}

// effectiveState is the pure policy function of ADR 0003. Its reasons rank
// device revoked, then user suspended, then an Abroad Device whose User
// lacks the abroad permission (ADR 0014), then quota used up (ADR 0010), so
// a resumed User still out of Quota stays blocked.
func effectiveState(revoked, userSuspended, abroadDenied bool, quota quotaState) (EffectiveState, string) {
	switch {
	case revoked:
		return StateBlocked, "device revoked"
	case userSuspended:
		return StateBlocked, "user suspended"
	case abroadDenied:
		return StateBlocked, "abroad not allowed"
	case quota.ranOut && quota.rate > 0:
		return StateThrottled, "quota used up"
	case quota.ranOut:
		return StateBlocked, "quota used up"
	}
	return StateActive, ""
}

// quotaStates returns the quota state of every User who has run out.
func (c *Coordinator) quotaStates(ctx context.Context) (map[string]quotaState, error) {
	standings, err := c.store.QuotaStandings(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]quotaState{}
	for _, q := range standings {
		if st := quotaStateOf(q); st.ranOut {
			out[q.UserID] = st
		}
	}
	return out, nil
}

// quotaChanged re-evaluates every User with a Quota and reports whether
// anyone's state differs from what the latest snapshots enforce.
func (c *Coordinator) quotaChanged(ctx context.Context) (bool, error) {
	now, err := c.quotaStates(ctx)
	if err != nil {
		return false, err
	}
	c.quotaMu.Lock()
	defer c.quotaMu.Unlock()
	return c.quotaSeen == nil || !maps.Equal(now, c.quotaSeen), nil
}

// CheckQuotas re-evaluates every User's Quota and reconciles if anyone's
// state changed (ADR 0010).
func (c *Coordinator) CheckQuotas(ctx context.Context) error {
	changed, err := c.quotaChanged(ctx)
	if err != nil || !changed {
		return err
	}
	return c.Reconcile(ctx)
}

// RunQuotaPeriods re-evaluates every User's Quota every interval until ctx
// ends, so a new Quota Period brings a User back within interval of its
// start: their blocked Devices move no bytes that would trigger it.
func (c *Coordinator) RunQuotaPeriods(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := c.CheckQuotas(ctx); err != nil && ctx.Err() == nil {
			c.log.Error("check quotas", "err", err)
		}
	}
}

// bridgeState is the part of the snapshot every Bridge shares: the Bridge
// identity, the Devices allowed in, and the Rules. quota holds the Users
// who have run out of Quota.
func (c *Coordinator) bridgeState(ctx context.Context, quota map[string]quotaState) (*protocol.BridgeState, error) {
	key, err := c.bridgeKey(ctx)
	if err != nil {
		return nil, err
	}
	portS, err := c.store.SetSettingIfUnset(ctx, "device_port", strconv.Itoa(DefaultDevicePort))
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portS, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("settings.device_port: %w", err)
	}
	b := &protocol.BridgeState{
		PrivateKey: key,
		ListenPort: uint16(port),
		Address:    netip.PrefixFrom(store.DevicePool.Addr().Next(), store.DevicePool.Bits()).String(),
		Upstreams:  c.Upstreams,
		Devices:    []protocol.Device{},
		Scoring:    c.Scoring,
	}

	devices, err := c.store.Devices(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range devices {
		// A throttled Device stays in and carries its rate (ADR 0010).
		st, _ := effectiveState(d.Revoked || d.PublicKey == "", d.UserSuspended, d.Abroad && !d.UserAbroad, quota[d.UserID])
		if st == StateBlocked {
			continue
		}
		dev := protocol.Device{PublicKey: d.PublicKey, Address: netip.PrefixFrom(d.Address, 32).String()}
		if st == StateThrottled {
			dev.Rate = quota[d.UserID].rate
		}
		b.Devices = append(b.Devices, dev)
	}

	sets, err := c.store.DestinationSets(ctx)
	if err != nil {
		return nil, err
	}
	hashes := map[uint64]string{}
	for _, s := range sets {
		if s.ContentHash == "" {
			if err := c.store.RefreshSetContent(ctx, s.ID); err != nil {
				return nil, err
			}
			return c.bridgeState(ctx, quota)
		}
		hashes[s.ID] = s.ContentHash
	}
	rules, err := c.store.Rules(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		if r.Source != "" {
			// The Abroad Rule goes apart, where older Agents never see it
			// (ADR 0014). Its lookups go to the domestic resolvers.
			b.AbroadRule = &protocol.Rule{ID: r.ID, Name: r.Name, Priority: r.Priority, Source: r.Source,
				RequiredTags: r.RequiredTags, Fallback: r.Fallback}
			b.AbroadUpstreams = c.Egress.IR.Resolvers
			continue
		}
		b.Rules = append(b.Rules, protocol.Rule{ID: r.ID, Name: r.Name, Priority: r.Priority, SetHash: hashes[r.SetID],
			RequiredTags: r.RequiredTags, Fallback: r.Fallback})
	}
	return b, nil
}

// bridgeKey returns the shared Bridge private key, creating it once. It
// lives in the database, so the nightly backup carries it (ADR 0005).
func (c *Coordinator) bridgeKey(ctx context.Context) (string, error) {
	if k, err := c.store.Setting(ctx, "bridge_private_key"); err != nil || k != "" {
		return k, err
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	return c.store.SetSettingIfUnset(ctx, "bridge_private_key", k.String())
}

// BridgePublicKey is what Device configs name as their peer.
func (c *Coordinator) BridgePublicKey(ctx context.Context) (string, error) {
	k, err := c.bridgeKey(ctx)
	if err != nil {
		return "", err
	}
	key, err := wgtypes.ParseKey(k)
	if err != nil {
		return "", err
	}
	return key.PublicKey().String(), nil
}

// isBridge reports whether n holds the Bridge Role.
func isBridge(n store.Node) bool { return slices.Contains(n.Roles, protocol.RoleBridge) }

// setBlob serves a Destination Set's content by hash to Agents.
func (c *Coordinator) setBlob(w http.ResponseWriter, r *http.Request) {
	body, err := c.store.SetBlob(r.Context(), r.PathValue("hash"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such set")
		return
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, body)
}

// ErrFeedRejected means an IR feed update failed its gates; the last good
// set stays in force.
var ErrFeedRejected = errors.New("IR feed update rejected")

// RefreshIRFeed fetches the IR feed, checks it against the gates, and makes
// it the IR set's feed content if it passes (ADR 0004).
func (c *Coordinator) RefreshIRFeed(ctx context.Context) error {
	sets, err := c.store.DestinationSets(ctx)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(sets, func(s store.DestinationSet) bool { return s.Feed == "ir" })
	if i < 0 {
		return errors.New("no Destination Set is fed by the IR feed")
	}
	set := sets[i]
	reject := func(err error) error {
		c.log.Error("IR feed rejected; the last good set stays", "err", err)
		c.store.RecordFeedAttempt(ctx, set.ID, err.Error())
		return fmt.Errorf("%w: %v", ErrFeedRejected, err)
	}
	next, err := c.fetchPrefixes(ctx, c.FeedURL, irfeed.Parse)
	if err != nil {
		return reject(err)
	}
	if err := irfeed.Gate(set.FeedContent, next); err != nil {
		return reject(err)
	}
	if c.RIPEstatURL != "" {
		if ripe, err := c.fetchPrefixes(ctx, c.RIPEstatURL, irfeed.ParseRIPEstat); err != nil {
			c.log.Warn("RIPEstat cross-check failed", "err", err)
		} else if d := irfeed.Divergence(next, ripe, irfeed.KnownExtras); d > 0 {
			c.log.Warn("IR feed diverges from RIPEstat beyond the known extras", "addresses", d)
		}
	}
	if err := c.store.SetFeedContent(ctx, set.ID, next); err != nil {
		return err
	}
	c.store.RecordFeedAttempt(ctx, set.ID, "")
	c.log.Info("IR feed accepted", "prefixes", len(next))
	return c.Reconcile(ctx)
}

func (c *Coordinator) fetchPrefixes(ctx context.Context, url string, parse func(io.Reader) ([]netip.Prefix, error)) ([]netip.Prefix, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return parse(io.LimitReader(resp.Body, 32<<20))
}

// RunRollUps stores ended Quota Periods' totals (ADR 0010) and folds usage
// into coarser totals (ADR 0003), now and then every interval until ctx ends.
func (c *Coordinator) RunRollUps(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		// Close Quota Periods first, while their daily rows are still there.
		if err := c.store.ClosePeriods(ctx); err != nil {
			c.log.Error("close quota periods", "err", err)
		}
		if err := c.store.RollUp(ctx); err != nil {
			c.log.Error("usage roll-up", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunIRFeed refreshes the IR feed now and then every interval until ctx
// ends.
func (c *Coordinator) RunIRFeed(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		c.RefreshIRFeed(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
