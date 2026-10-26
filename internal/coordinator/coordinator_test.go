package coordinator_test

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/alakiani/ways/internal/ca"
	"github.com/alakiani/ways/internal/coordinator"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
	"github.com/alakiani/ways/internal/testutil"
)

func newAdmin(t *testing.T) (*testutil.AdminClient, *store.Store) {
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
	c := coordinator.New(s, authority, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(c.AdminHandler())
	t.Cleanup(srv.Close)
	secret, _, err := s.CreateAPIToken(context.Background(), store.ScopeNodesEnroll, "laptop", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &testutil.AdminClient{URL: srv.URL, Token: secret}, s
}

var bridge = protocol.CreateNodeRequest{Name: "b1", Roles: []protocol.Role{"bridge"}, Tags: []string{"IR"}}

func TestAdminAPINeedsANodesEnrollToken(t *testing.T) {
	admin, s := newAdmin(t)
	other, _, _ := s.CreateAPIToken(context.Background(), "something-else", "x", time.Hour)
	for _, token := range []string{"", "ways_wrong", other} {
		c := *admin
		c.Token = token
		if status := c.Do(t, http.MethodPost, "/v1/nodes", bridge, nil); status != http.StatusUnauthorized {
			t.Errorf("token %q: status %d, want 401", token, status)
		}
	}
}

func TestCreateNodeValidates(t *testing.T) {
	admin, _ := newAdmin(t)
	for _, req := range []protocol.CreateNodeRequest{
		{Roles: []protocol.Role{"bridge"}},
		{Name: "b1"},
		{Name: "b1", Roles: []protocol.Role{"relay"}},
	} {
		if status := admin.Do(t, http.MethodPost, "/v1/nodes", req, nil); status != http.StatusBadRequest {
			t.Errorf("%+v: status %d, want 400", req, status)
		}
	}
}

func TestCreateNodeIsIdempotent(t *testing.T) {
	admin, s := newAdmin(t)
	first := admin.CreateNode(t, bridge)
	if first.EnrollmentToken == "" || first.Node.Enrolled {
		t.Fatalf("first create = %+v", first)
	}

	// Rerunning before enrollment returns the same Node with a fresh token.
	again := admin.CreateNode(t, bridge)
	if again.Node.ID != first.Node.ID || again.EnrollmentToken == "" || again.EnrollmentToken == first.EnrollmentToken {
		t.Errorf("rerun before enrollment = %+v", again)
	}

	// A duplicated Tag names the same Node.
	reordered := bridge
	reordered.Tags = []string{"IR", "IR"}
	if got := admin.CreateNode(t, reordered); got.Node.ID != first.Node.ID {
		t.Errorf("duplicate tag made a different node")
	}

	// Once enrolled, a rerun gets no token unless it asks to re-enroll.
	if _, err := s.Enroll(context.Background(), admin.CreateNode(t, bridge).EnrollmentToken,
		func(string) (string, error) { return "serial", nil }); err != nil {
		t.Fatal(err)
	}
	if got := admin.CreateNode(t, bridge); got.EnrollmentToken != "" || !got.Node.Enrolled {
		t.Errorf("rerun after enrollment = %+v, want enrolled and no token", got)
	}
	re := bridge
	re.Reenroll = true
	if got := admin.CreateNode(t, re); got.EnrollmentToken == "" {
		t.Error("reenroll gave no token")
	}

	// A rerun must not silently change a live Node.
	changed := bridge
	changed.Tags = []string{"DE"}
	if status := admin.Do(t, http.MethodPost, "/v1/nodes", changed, nil); status != http.StatusConflict {
		t.Errorf("changed tags: status %d, want 409", status)
	}

	// New Roles with the same Tags are taken, so an abroad Exit can become
	// an Abroad Bridge by rerunning the playbook (ADR 0014).
	roles := bridge
	roles.Roles = []protocol.Role{protocol.RoleExit, protocol.RoleBridge}
	got := admin.CreateNode(t, roles)
	if got.Node.ID != first.Node.ID || !slices.Equal(got.Node.Roles, []protocol.Role{protocol.RoleBridge, protocol.RoleExit}) ||
		got.EnrollmentToken != "" {
		t.Errorf("roles changed = %+v", got)
	}
	if n, _ := s.Node(context.Background(), first.Node.ID); len(n.Roles) != 2 {
		t.Errorf("stored roles = %v", n.Roles)
	}
}

func TestGetNode(t *testing.T) {
	admin, _ := newAdmin(t)
	created := admin.CreateNode(t, bridge)
	got := admin.GetNode(t, created.Node.ID)
	if got.Name != "b1" || got.Enrolled || got.LastHealth != nil {
		t.Errorf("node = %+v", got)
	}
	if status := admin.Do(t, http.MethodGet, "/v1/nodes/nd_missing", nil, nil); status != http.StatusNotFound {
		t.Errorf("missing node: status %d, want 404", status)
	}
}
