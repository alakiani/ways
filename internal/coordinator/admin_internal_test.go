package coordinator

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

func TestAdminInvites(t *testing.T) {
	a := newAPI(t)
	admin := a.admin()
	var inv protocol.IssuedInvite
	admin.must(200, "POST", "/v1/admin/invites", protocol.CreateInvite{DeviceCap: 2}, &inv)
	var list []protocol.InviteRecord
	admin.must(200, "GET", "/v1/admin/invites", nil, &list)
	var open protocol.InviteRecord
	for _, r := range list {
		if r.Status == "open" {
			open = r
		}
	}
	if open.ID == "" || open.DeviceCap != 2 {
		t.Fatalf("invites = %+v", list)
	}
	admin.must(204, "POST", "/v1/admin/invites/"+open.ID+"/withdraw", nil, nil)
	admin.must(404, "POST", "/v1/admin/invites/"+open.ID+"/withdraw", nil, nil)
	a.client().must(404, "POST", "/v1/invites/lookup", protocol.InviteToken{Token: inv.Token}, nil)
	admin.must(200, "GET", "/v1/admin/invites", nil, &list)
	for _, r := range list {
		if r.ID == open.ID && r.Status != "withdrawn" {
			t.Errorf("status = %s", r.Status)
		}
	}
}

func TestAdminNodes(t *testing.T) {
	a := newAPI(t)
	admin := a.admin()
	admin.must(400, "POST", "/v1/admin/nodes", protocol.NewNode{Name: "ab1", Roles: []protocol.Role{"exit"}}, nil)
	var cmd protocol.EnrollCommand
	admin.must(200, "POST", "/v1/admin/nodes", protocol.NewNode{Name: "ab1", Roles: []protocol.Role{"exit"}, Tags: []string{"DE"}, SSHHost: "203.0.113.7"}, &cmd)
	for _, want := range []string{"ansible-playbook enroll.yml", "-i '203.0.113.7,'", "-e name='ab1'", "-e roles='exit'", "-e tags='DE'", "-e enroll_token='"} {
		if !strings.Contains(cmd.Command, want) {
			t.Errorf("command %q lacks %q", cmd.Command, want)
		}
	}
	id := cmd.Node.ID

	var nodes []protocol.NodeTile
	admin.must(200, "GET", "/v1/admin/nodes", nil, &nodes)
	if len(nodes) != 1 || nodes[0].Name != "ab1" || nodes[0].Enrolled || nodes[0].LatestVersion == 0 {
		t.Errorf("nodes = %+v", nodes)
	}
	var st protocol.NodeStatus
	admin.must(400, "POST", "/v1/admin/nodes/"+id, protocol.NodeEdit{}, nil)
	admin.must(200, "POST", "/v1/admin/nodes/"+id, protocol.NodeEdit{Roles: []protocol.Role{"exit", "bridge"}, Tags: []string{"NL"}}, &st)
	if len(st.Roles) != 2 || st.Tags[0] != "NL" {
		t.Errorf("after edit: %+v", st)
	}
	var d protocol.NodeDetail
	admin.must(200, "GET", "/v1/admin/nodes/"+id, nil, &d)
	if d.Node.Name != "ab1" || d.Links == nil || d.Paths == nil {
		t.Errorf("detail = %+v", d)
	}
	admin.must(204, "DELETE", "/v1/admin/nodes/"+id, nil, nil)
	admin.must(404, "GET", "/v1/admin/nodes/"+id, nil, nil)
	admin.must(404, "DELETE", "/v1/admin/nodes/"+id, nil, nil)
}

func TestAdminOverviewAndLinks(t *testing.T) {
	a := newAPI(t)
	admin := a.admin()
	ctx := context.Background()
	b, _ := a.s.CreateNode(ctx, "ir1", []protocol.Role{protocol.RoleBridge}, []string{"IR"})
	x, _ := a.s.CreateNode(ctx, "ab1", []protocol.Role{protocol.RoleExit}, nil)
	for _, n := range []store.Node{b, x} {
		a.s.PutHealth(ctx, n.ID, protocol.Health{LinkPublicKey: n.Name + "-key", AppliedVersion: 1}, "192.0.2.1")
		a.s.SetLinkPublicKey(ctx, n.ID, n.Name+"-key")
	}
	a.c.Reconcile(ctx)
	var links []protocol.LinkTile
	admin.must(200, "GET", "/v1/admin/links", nil, &links)
	if len(links) != 1 || !links[0].Crosses || len(links[0].Instances) != 4 || links[0].Instances[0].Transport != protocol.TransportGRE {
		t.Fatalf("links = %+v", links)
	}
	// The initiating end reports the Link up on its first instance.
	l := links[0]
	a.s.PutHealth(ctx, b.ID, protocol.Health{AppliedVersion: 1, Links: []protocol.LinkHealth{{LinkID: l.ID, Up: true,
		Transport: protocol.TransportAmneziaWG, RTTMillis: 42, Instances: []protocol.InstanceHealth{{ID: l.Instances[0].ID, Up: true}}}}}, "192.0.2.1")

	var o protocol.Overview
	admin.must(200, "GET", "/v1/admin/overview", nil, &o)
	if len(o.Nodes) != 2 || o.Nodes[0].LastContact == nil || len(o.Sets) != 2 || o.Backup.Configured || o.UndeliveredAlerts == nil {
		t.Errorf("overview = %+v", o)
	}
	if len(o.Links) != 1 || !o.Links[0].UpA && !o.Links[0].UpB || o.Links[0].RTTMillis != 42 || !o.Links[0].Instances[0].Up {
		t.Errorf("overview links = %+v", o.Links)
	}
}

func TestAdminTransports(t *testing.T) {
	a := newAPI(t)
	admin := a.admin()
	var tl protocol.TransportList
	admin.must(200, "GET", "/v1/admin/transports", nil, &tl)
	if len(tl.Enabled) != 3 || len(tl.Known) != 3 || !slices.Contains(tl.Enabled, protocol.TransportGRE) {
		t.Errorf("transports = %+v", tl)
	}
	admin.must(400, "POST", "/v1/admin/transports", protocol.TransportList{Enabled: []protocol.Transport{}}, nil)
	admin.must(400, "POST", "/v1/admin/transports", protocol.TransportList{Enabled: []protocol.Transport{"amneziawg", "reality"}}, nil)
	// GRE can be disabled, as when the filter is found decapsulating it
	// (ADR 0009).
	admin.must(200, "POST", "/v1/admin/transports", protocol.TransportList{Enabled: []protocol.Transport{"wireguard", "amneziawg"}}, &tl)
	if len(tl.Enabled) != 2 || slices.Contains(tl.Enabled, protocol.TransportGRE) {
		t.Errorf("after disabling gre: %+v", tl)
	}
	admin.must(200, "POST", "/v1/admin/transports", protocol.TransportList{Enabled: []protocol.Transport{"amneziawg"}}, &tl)
	if len(tl.Enabled) != 1 {
		t.Errorf("after disabling wireguard: %+v", tl)
	}
}

func TestAdminRules(t *testing.T) {
	a := newAPI(t)
	admin := a.admin()
	var rules []protocol.RuleInfo
	admin.must(200, "GET", "/v1/admin/rules", nil, &rules)
	// The Abroad Rule first and locked (ADR 0014), then IR, then the default.
	if len(rules) != 3 || rules[0].Source != "10.77.128.0/17" || !rules[0].Builtin || rules[1].Set != "Iran" || !rules[2].Builtin {
		t.Fatalf("rules = %+v", rules)
	}
	admin.must(200, "POST", fmt.Sprint("/v1/admin/rules/", rules[1].ID), protocol.RuleEdit{RequiredTags: []string{"IR"}, Fallback: "drop"}, &rules)
	if rules[1].Fallback != "drop" {
		t.Errorf("IR fallback = %s", rules[1].Fallback)
	}
	admin.must(403, "POST", fmt.Sprint("/v1/admin/rules/", rules[2].ID), protocol.RuleEdit{RequiredTags: []string{"!IR"}, Fallback: "next"}, nil)
	admin.must(403, "POST", fmt.Sprint("/v1/admin/rules/", rules[0].ID), protocol.RuleEdit{RequiredTags: []string{"!IR"}, Fallback: "next"}, nil)
	admin.must(400, "POST", fmt.Sprint("/v1/admin/rules/", rules[1].ID), protocol.RuleEdit{Fallback: "sometimes"}, nil)
}

func TestAdminSets(t *testing.T) {
	a := newAPI(t)
	admin := a.admin()
	var body atomic.Value
	body.Store(":do { add address=2.144.0.0/14 list=NoNAT} on-error={}\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body.Load()) }))
	defer srv.Close()
	a.c.FeedURL, a.c.RIPEstatURL = srv.URL, ""

	var sets []protocol.SetInfo
	admin.must(200, "POST", "/v1/admin/sets/1/fetch", nil, &sets)
	if sets[0].Prefixes != 1 || sets[0].UpdatedAt == nil || sets[0].LastError != "" || sets[0].CanRollBack {
		t.Fatalf("after first fetch: %+v", sets[0])
	}
	body.Store(":do { add address=2.144.0.0/14 list=NoNAT} on-error={}\n:do { add address=2.148.0.0/16 list=NoNAT} on-error={}\n")
	a.tick(time.Second)
	admin.must(200, "POST", "/v1/admin/sets/1/fetch", nil, &sets)
	if sets[0].LastError == "" {
		t.Error("a 25% jump was not rejected")
	}
	// A small change is taken; then it can be rolled back.
	body.Store(":do { add address=2.144.0.0/14 list=NoNAT} on-error={}\n:do { add address=2.148.0.0/24 list=NoNAT} on-error={}\n")
	admin.must(200, "POST", "/v1/admin/sets/1/fetch", nil, &sets)
	if sets[0].Prefixes != 2 || !sets[0].CanRollBack {
		t.Fatalf("after a small change: %+v", sets[0])
	}
	admin.must(200, "POST", "/v1/admin/sets/1/rollback", nil, &sets)
	if sets[0].Prefixes != 1 {
		t.Errorf("after roll back: %+v", sets[0])
	}
	admin.must(400, "POST", "/v1/admin/sets/1/overrides", protocol.Overrides{Additions: []string{"not a prefix"}}, nil)
	admin.must(200, "POST", "/v1/admin/sets/1/overrides", protocol.Overrides{Additions: []string{"185.0.0.0/24"}, Removals: []string{"2.144.0.0/16"}}, &sets)
	if !slices.Contains(sets[0].Additions, "185.0.0.0/24") || sets[0].Removals[0] != "2.144.0.0/16" {
		t.Errorf("overrides = %+v", sets[0])
	}
	admin.must(200, "GET", "/v1/admin/sets", nil, &sets)
	admin.must(404, "POST", "/v1/admin/sets/9/fetch", nil, nil)
}

func TestAdminTokens(t *testing.T) {
	a := newAPI(t)
	admin := a.admin()
	var issued protocol.IssuedToken
	admin.must(400, "POST", "/v1/admin/tokens", protocol.NewToken{}, nil)
	admin.must(200, "POST", "/v1/admin/tokens", protocol.NewToken{Name: "laptop"}, &issued)
	if !strings.HasPrefix(issued.Secret, "ways_") || issued.Token.Scope != "nodes:enroll" {
		t.Errorf("issued = %+v", issued)
	}
	if _, err := a.s.CheckAPIToken(context.Background(), issued.Secret, store.ScopeNodesEnroll); err != nil {
		t.Errorf("the new token does not work: %v", err)
	}
	var list []protocol.TokenInfo
	admin.must(200, "GET", "/v1/admin/tokens", nil, &list)
	if len(list) != 1 || list[0].Revoked {
		t.Errorf("tokens = %+v", list)
	}
	admin.must(204, "POST", "/v1/admin/tokens/"+issued.Token.ID+"/revoke", nil, nil)
	if _, err := a.s.CheckAPIToken(context.Background(), issued.Secret, store.ScopeNodesEnroll); err == nil {
		t.Error("a revoked token still works")
	}
}
