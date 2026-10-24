package coordinator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/alakiani/ways/internal/cidr"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// The admin panel's operations (the panel prototype, issue #14). Every one
// is an API operation first (ADR 0001).

// adminView is what several admin screens are built from.
type adminView struct {
	nodes  []store.Node
	byID   map[string]store.Node
	health map[string]*protocol.HealthStatus
}

func (c *Coordinator) loadAdminView(ctx context.Context) (adminView, error) {
	v := adminView{byID: map[string]store.Node{}, health: map[string]*protocol.HealthStatus{}}
	var err error
	if v.nodes, err = c.store.Nodes(ctx); err != nil {
		return v, err
	}
	for _, n := range v.nodes {
		v.byID[n.ID] = n
		if v.health[n.ID], err = c.store.Health(ctx, n.ID); err != nil {
			return v, err
		}
	}
	return v, nil
}

func (c *Coordinator) nodeTile(ctx context.Context, v adminView, n store.Node) protocol.NodeTile {
	t := protocol.NodeTile{ID: n.ID, Name: n.Name, Roles: n.Roles, Tags: n.Tags, Enrolled: n.Enrolled()}
	if snap, err := c.store.LatestSnapshot(ctx, n.ID); err == nil {
		t.LatestVersion = snap.Version
	}
	if h := v.health[n.ID]; h != nil {
		at := h.ReceivedAt
		t.LastContact = &at
		t.AppliedVersion, t.AgentVersion, t.Addr, t.SeenAddr = h.AppliedVersion, h.AgentVersion, h.Addr, h.SeenAddr
	}
	return t
}

// linkTiles builds Link tiles from both ends' latest reports.
func (c *Coordinator) linkTiles(ctx context.Context, v adminView, only string) ([]protocol.LinkTile, error) {
	links, err := c.store.Links(ctx)
	if err != nil {
		return nil, err
	}
	insts, err := c.store.Instances(ctx)
	if err != nil {
		return nil, err
	}
	report := func(nodeID string, linkID uint64) *protocol.LinkHealth {
		if h := v.health[nodeID]; h != nil {
			for i := range h.Links {
				if h.Links[i].LinkID == linkID {
					return &h.Links[i]
				}
			}
		}
		return nil
	}
	out := []protocol.LinkTile{}
	for _, l := range links {
		a, b := v.byID[l.NodeA], v.byID[l.NodeB]
		if only != "" && a.ID != only && b.ID != only {
			continue
		}
		initiator, _ := ends(a, b)
		t := protocol.LinkTile{ID: l.ID, A: a.Name, B: b.Name, Crosses: crosses(a, b), Instances: []protocol.InstanceTile{}}
		ra, rb := report(a.ID, l.ID), report(b.ID, l.ID)
		t.UpA, t.UpB = ra != nil && ra.Up, rb != nil && rb.Up
		ri := ra
		if initiator.ID == b.ID {
			ri = rb
		}
		if ri != nil {
			t.Transport, t.RTTMillis = ri.Transport, ri.RTTMillis
		}
		for _, in := range preferenceOrder(insts, t.Crosses) {
			if in.LinkID != l.ID {
				continue
			}
			it := protocol.InstanceTile{ID: in.ID, Transport: in.Transport, ListenPort: in.ListenPort}
			if ri != nil {
				for _, ih := range ri.Instances {
					if ih.ID == in.ID {
						it.Up = ih.Up
					}
				}
			}
			t.Instances = append(t.Instances, it)
		}
		out = append(out, t)
	}
	return out, nil
}

func (c *Coordinator) setInfos(ctx context.Context) ([]protocol.SetInfo, error) {
	sets, err := c.store.DestinationSets(ctx)
	if err != nil {
		return nil, err
	}
	out := []protocol.SetInfo{}
	for _, s := range sets {
		content := s.Content()
		info := protocol.SetInfo{ID: s.ID, Name: s.Name, Feed: s.Feed, Prefixes: len(content), Addresses: cidr.Size(content),
			Additions: prefixStrings(s.Additions), Removals: prefixStrings(s.Removals)}
		if s.Feed != "" {
			st, err := c.store.FeedStatus(ctx, s.ID)
			if err != nil {
				return nil, err
			}
			if !st.UpdatedAt.IsZero() {
				info.UpdatedAt = &st.UpdatedAt
			}
			if !st.LastAttempt.IsZero() {
				info.LastAttempt = &st.LastAttempt
			}
			info.LastError, info.CanRollBack = st.LastError, st.CanRollBack
		}
		out = append(out, info)
	}
	return out, nil
}

func (c *Coordinator) adminOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := c.loadAdminView(ctx)
	var o protocol.Overview
	if err == nil {
		for _, n := range v.nodes {
			o.Nodes = append(o.Nodes, c.nodeTile(ctx, v, n))
		}
		o.Links, err = c.linkTiles(ctx, v, "")
	}
	if err == nil {
		o.Sets, err = c.setInfos(ctx)
	}
	if err == nil {
		o.BridgeAddress, err = c.BridgeAddressStatus(ctx)
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	if err == nil {
		o.Backup, err = c.BackupStatus(ctx)
	}
	if err == nil {
		o.UndeliveredAlerts, err = c.UndeliveredAlerts(ctx)
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	if o.Nodes == nil {
		o.Nodes = []protocol.NodeTile{}
	}
	writeJSON(w, http.StatusOK, o)
}

func (c *Coordinator) adminInvites(w http.ResponseWriter, r *http.Request) {
	recs, err := c.store.Invites(r.Context())
	if err != nil {
		c.internalError(w, err)
		return
	}
	now := c.store.Now()
	out := []protocol.InviteRecord{}
	for _, rec := range recs {
		status := "open"
		switch {
		case rec.Used:
			status = "used"
		case rec.Withdrawn:
			status = "withdrawn"
		case now.After(rec.ExpiresAt):
			status = "expired"
		}
		inv := protocol.InviteRecord{ID: rec.ID, Kind: rec.Kind, Handle: rec.Handle, Admin: rec.Admin,
			DeviceCap: rec.DeviceCap, CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt, Status: status}
		if rec.Kind == "new" {
			inv.Quota, inv.RunningOut = rec.Quota, protocol.RunningOutBlock
			if rec.SlowRate > 0 {
				inv.RunningOut, inv.Rate = protocol.RunningOutSlow, rec.SlowRate
			}
			if rec.Refills > 0 {
				inv.Refills, inv.RefillDays = rec.Refills, int(rec.RefillTTL/(24*time.Hour))
			}
		}
		out = append(out, inv)
	}
	writeJSON(w, http.StatusOK, out)
}

func (c *Coordinator) adminWithdrawInvite(w http.ResponseWriter, r *http.Request) {
	err := c.store.WithdrawInvite(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no open Invite with that id")
		return
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) adminNodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := c.loadAdminView(ctx)
	if err != nil {
		c.internalError(w, err)
		return
	}
	out := []protocol.NodeTile{}
	for _, n := range v.nodes {
		out = append(out, c.nodeTile(ctx, v, n))
	}
	writeJSON(w, http.StatusOK, out)
}

// enrollCommand is the playbook run that enrolls a Node (ADR 0002).
func enrollCommand(host string, n protocol.NodeStatus, token string) string {
	var roles []string
	for _, r := range n.Roles {
		roles = append(roles, string(r))
	}
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	cmd := fmt.Sprintf("ansible-playbook enroll.yml -i %s -e name=%s -e roles=%s", q(host+","), q(n.Name), q(strings.Join(roles, ",")))
	if len(n.Tags) > 0 {
		cmd += " -e tags=" + q(strings.Join(n.Tags, ","))
	}
	return cmd + " -e enroll_token=" + q(token)
}

func (c *Coordinator) adminCreateNode(w http.ResponseWriter, r *http.Request) {
	var req protocol.NewNode
	if !decode(w, r, &req) {
		return
	}
	if req.SSHHost == "" || strings.ContainsAny(req.SSHHost, " ,'\"") {
		writeError(w, http.StatusBadRequest, "ssh_host is the host the playbook connects to")
		return
	}
	resp, ok := c.ensureNode(w, r, protocol.CreateNodeRequest{Name: req.Name, Roles: req.Roles, Tags: req.Tags, Reenroll: req.Reenroll})
	if !ok {
		return
	}
	out := protocol.EnrollCommand{Node: resp.Node, ExpiresAt: resp.TokenExpiresAt}
	if resp.EnrollmentToken != "" {
		out.Command = enrollCommand(req.SSHHost, resp.Node, resp.EnrollmentToken)
	}
	writeJSON(w, http.StatusOK, out)
}

func (c *Coordinator) adminNode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := c.loadAdminView(ctx)
	if err != nil {
		c.internalError(w, err)
		return
	}
	n, ok := v.byID[r.PathValue("id")]
	if !ok {
		writeError(w, http.StatusNotFound, "no such Node")
		return
	}
	d := protocol.NodeDetail{Node: c.nodeTile(ctx, v, n), Paths: []protocol.PathInfo{}}
	if d.Links, err = c.linkTiles(ctx, v, n.ID); err != nil {
		c.internalError(w, err)
		return
	}
	if h := v.health[n.ID]; h != nil && isBridge(n) {
		rules, err := c.store.Rules(ctx)
		if err != nil {
			c.internalError(w, err)
			return
		}
		ruleNames := map[uint64]string{}
		for _, rl := range rules {
			ruleNames[rl.ID] = rl.Name
		}
		peers := map[string]store.Node{}
		for _, l := range d.Links {
			peer := l.B
			if peer == n.Name {
				peer = l.A
			}
			for _, pn := range v.nodes {
				if pn.Name == peer {
					peers["link:"+strconv.FormatUint(l.ID, 10)] = pn
				}
			}
		}
		for _, p := range h.Paths {
			pi := protocol.PathInfo{Rule: ruleNames[p.RuleID], Mode: p.Mode, Eligible: p.Eligible, Shares: []protocol.Share{}}
			for cand, buckets := range p.Shares {
				s := protocol.Share{Candidate: cand, Buckets: buckets}
				if pn, ok := peers[cand]; ok {
					s.Candidate = pn.Name
					s.Transit = !slices.Contains(pn.Roles, protocol.RoleExit) || p.Mode == "transit"
				}
				pi.Shares = append(pi.Shares, s)
			}
			slices.SortFunc(pi.Shares, func(a, b protocol.Share) int { return b.Buckets - a.Buckets })
			d.Paths = append(d.Paths, pi)
		}
	}
	writeJSON(w, http.StatusOK, d)
}

func (c *Coordinator) adminEditNode(w http.ResponseWriter, r *http.Request) {
	var req protocol.NodeEdit
	if !decode(w, r, &req) {
		return
	}
	if len(req.Roles) == 0 {
		writeError(w, http.StatusBadRequest, "a Node needs at least one Role")
		return
	}
	for _, role := range req.Roles {
		if !role.Valid() {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown role %q", role))
			return
		}
	}
	err := c.UpdateNode(r.Context(), r.PathValue("id"), req.Roles, req.Tags)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such Node")
		return
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	n, _ := c.store.Node(r.Context(), r.PathValue("id"))
	writeJSON(w, http.StatusOK, c.nodeStatus(r.Context(), n))
}

func (c *Coordinator) adminDeleteNode(w http.ResponseWriter, r *http.Request) {
	err := c.store.DeleteNode(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such Node")
		return
	}
	if err == nil {
		err = c.Reconcile(r.Context())
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	c.log.Info("node deleted", "node", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) adminLinks(w http.ResponseWriter, r *http.Request) {
	v, err := c.loadAdminView(r.Context())
	var tiles []protocol.LinkTile
	if err == nil {
		tiles, err = c.linkTiles(r.Context(), v, "")
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tiles)
}

var knownTransports = []protocol.Transport{protocol.TransportWireGuard, protocol.TransportAmneziaWG, protocol.TransportGRE}

func (c *Coordinator) adminTransports(w http.ResponseWriter, r *http.Request) {
	ts, err := c.store.Transports(r.Context())
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.TransportList{Enabled: ts, Known: knownTransports})
}

func (c *Coordinator) adminSetTransports(w http.ResponseWriter, r *http.Request) {
	var req protocol.TransportList
	if !decode(w, r, &req) {
		return
	}
	for _, t := range req.Enabled {
		if !slices.Contains(knownTransports, t) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown transport %q", t))
			return
		}
	}
	if len(req.Enabled) == 0 {
		// Every Transport crosses the filter since ADR 0009, but with none
		// no Link could come up at all.
		writeError(w, http.StatusBadRequest, "at least one transport must stay enabled")
		return
	}
	err := c.store.SetTransports(r.Context(), slices.Compact(req.Enabled))
	if err == nil {
		err = c.Reconcile(r.Context())
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	c.adminTransports(w, r)
}

func (c *Coordinator) ruleInfos(ctx context.Context) ([]protocol.RuleInfo, error) {
	rules, err := c.store.Rules(ctx)
	if err != nil {
		return nil, err
	}
	sets, err := c.store.DestinationSets(ctx)
	if err != nil {
		return nil, err
	}
	names := map[uint64]string{}
	for _, s := range sets {
		names[s.ID] = s.Name
	}
	out := []protocol.RuleInfo{}
	for _, rl := range rules {
		out = append(out, protocol.RuleInfo{ID: rl.ID, Name: rl.Name, Priority: rl.Priority, Set: names[rl.SetID],
			RequiredTags: rl.RequiredTags, Fallback: rl.Fallback, Builtin: rl.Builtin})
	}
	return out, nil
}

func (c *Coordinator) adminRules(w http.ResponseWriter, r *http.Request) {
	rules, err := c.ruleInfos(r.Context())
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (c *Coordinator) adminEditRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such Rule")
		return
	}
	var req protocol.RuleEdit
	if !decode(w, r, &req) {
		return
	}
	if req.Fallback != protocol.FallbackNext && req.Fallback != protocol.FallbackDrop {
		writeError(w, http.StatusBadRequest, "fallback is next or drop")
		return
	}
	tags := normalize(req.RequiredTags)
	for _, t := range tags {
		if strings.TrimPrefix(t, "!") == "" || strings.ContainsAny(t, " ,") {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("bad tag %q", t))
			return
		}
	}
	err = c.store.UpdateRule(r.Context(), id, tags, string(req.Fallback))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusForbidden, "only the IR Rule can be changed; the default Rule is locked")
		return
	}
	if err == nil {
		err = c.Reconcile(r.Context())
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	c.adminRules(w, r)
}

func (c *Coordinator) adminSets(w http.ResponseWriter, r *http.Request) {
	sets, err := c.setInfos(r.Context())
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sets)
}

// fedSet is the fed set a route names; it answers 404 itself.
func (c *Coordinator) fedSet(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	sets, err := c.store.DestinationSets(r.Context())
	if err != nil {
		c.internalError(w, err)
		return 0, false
	}
	for _, s := range sets {
		if s.ID == id {
			return id, true
		}
	}
	writeError(w, http.StatusNotFound, "no such Destination Set")
	return 0, false
}

func (c *Coordinator) adminFetchSet(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.fedSet(w, r); !ok {
		return
	}
	// A rejected update is a result, not a failure of this call: the panel
	// shows the reason in the set's last error.
	if err := c.RefreshIRFeed(r.Context()); err != nil && !errors.Is(err, ErrFeedRejected) {
		c.internalError(w, err)
		return
	}
	c.adminSets(w, r)
}

func (c *Coordinator) adminRollBackSet(w http.ResponseWriter, r *http.Request) {
	id, ok := c.fedSet(w, r)
	if !ok {
		return
	}
	if err := c.store.RollBackFeed(r.Context(), id); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err := c.Reconcile(r.Context()); err != nil {
		c.internalError(w, err)
		return
	}
	c.adminSets(w, r)
}

func (c *Coordinator) adminSetOverrides(w http.ResponseWriter, r *http.Request) {
	id, ok := c.fedSet(w, r)
	if !ok {
		return
	}
	var req protocol.Overrides
	if !decode(w, r, &req) {
		return
	}
	adds, err := store.SetPrefixes(req.Additions)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	removes, err := store.SetPrefixes(req.Removals)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	err = c.store.SetOverrides(r.Context(), id, adds, removes)
	if err == nil {
		err = c.Reconcile(r.Context())
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	c.adminSets(w, r)
}

func (c *Coordinator) adminTokens(w http.ResponseWriter, r *http.Request) {
	toks, revoked, err := c.store.APITokens(r.Context())
	if err != nil {
		c.internalError(w, err)
		return
	}
	out := []protocol.TokenInfo{}
	for i, t := range toks {
		out = append(out, protocol.TokenInfo{ID: t.ID, Name: t.Name, Scope: t.Scope, ExpiresAt: t.ExpiresAt, Revoked: revoked[i]})
	}
	writeJSON(w, http.StatusOK, out)
}

// APITokenTTL is how long a nodes:enroll token lasts (ADR 0002).
const APITokenTTL = 90 * 24 * time.Hour

func (c *Coordinator) adminCreateToken(w http.ResponseWriter, r *http.Request) {
	var req protocol.NewToken
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" || len(req.Name) > 64 {
		writeError(w, http.StatusBadRequest, "a token needs a name of up to 64 characters")
		return
	}
	secret, tok, err := c.store.CreateAPIToken(r.Context(), store.ScopeNodesEnroll, req.Name, APITokenTTL)
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.IssuedToken{Secret: secret,
		Token: protocol.TokenInfo{ID: tok.ID, Name: tok.Name, Scope: tok.Scope, ExpiresAt: tok.ExpiresAt}})
}

func (c *Coordinator) adminRevokeToken(w http.ResponseWriter, r *http.Request) {
	if err := c.store.RevokeAPIToken(r.Context(), r.PathValue("id")); err != nil {
		c.internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func prefixStrings[T fmt.Stringer](ps []T) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}
