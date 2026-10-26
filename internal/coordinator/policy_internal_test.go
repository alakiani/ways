package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alakiani/ways/internal/protocol"
)

func TestOnlyBridgesGetDevicesAndTheBridgeKey(t *testing.T) {
	m := newMesh(t, "ir1", "ab1")
	m.c.UpdateNode(bg, m.nodes["ab1"].ID, []protocol.Role{protocol.RoleExit}, nil)
	if st := m.state("ab1"); st.Bridge != nil {
		t.Fatalf("an Exit got the Bridge state: %+v", st.Bridge)
	}
	b := m.state("ir1").Bridge
	if b == nil {
		t.Fatal("a Bridge got no Bridge state")
	}
	if b.ListenPort != DefaultDevicePort || b.Address != "10.77.0.1/16" || len(b.Upstreams) == 0 {
		t.Errorf("bridge state = %+v", b)
	}
	key, err := wgtypes.ParseKey(b.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if pub, _ := m.c.BridgePublicKey(bg); pub != key.PublicKey().String() {
		t.Error("BridgePublicKey does not match the key Bridges get")
	}
	if len(b.Rules) != 2 || b.Rules[0].Name != "IR" || b.Rules[1].Name != "Default" || b.Rules[0].SetHash == "" {
		t.Errorf("rules = %+v", b.Rules)
	}
	if body, err := m.s.SetBlob(bg, b.Rules[1].SetHash); err != nil || strings.TrimSpace(body) != "0.0.0.0/0" {
		t.Errorf("default rule set = %q, %v", body, err)
	}
}

func TestBlockedDevicesLeaveTheBridgeSnapshots(t *testing.T) {
	m := newMesh(t, "ir1")
	u, _ := m.s.CreateUser(bg, "maryam")
	keep, _ := m.s.CreateDevice(bg, u.ID, "phone", "pub-phone")
	gone, _ := m.s.CreateDevice(bg, u.ID, "laptop", "pub-laptop")
	m.s.RevokeDevice(bg, gone.ID)
	m.c.Reconcile(bg)
	devs := m.state("ir1").Bridge.Devices
	if len(devs) != 1 || devs[0].PublicKey != "pub-phone" || devs[0].Address != keep.Address.String()+"/32" {
		t.Fatalf("devices = %+v, want only the phone", devs)
	}

	m.s.SetUserSuspended(bg, u.ID, true)
	m.c.Reconcile(bg)
	if devs := m.state("ir1").Bridge.Devices; len(devs) != 0 {
		t.Errorf("a suspended User's devices stayed: %+v", devs)
	}
}

func TestIRFeedGates(t *testing.T) {
	m := newMesh(t, "ir1")
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body.Load().(string))
	}))
	defer srv.Close()
	m.c.FeedURL, m.c.RIPEstatURL = srv.URL, ""
	feed := func(prefixes ...string) string {
		var b strings.Builder
		b.WriteString("/ip firewall address-list\n")
		for _, p := range prefixes {
			fmt.Fprintf(&b, ":do { add address=%s list=NoNAT} on-error={}\n", p)
		}
		return b.String()
	}
	irSet := func() string {
		body, err := m.s.SetBlob(bg, m.state("ir1").Bridge.Rules[0].SetHash)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}

	body.Store(feed("2.144.0.0/14", "5.0.0.0/8", "10.0.0.0/8"))
	if err := m.c.RefreshIRFeed(bg); err != nil {
		t.Fatal(err)
	}
	good := irSet()
	if good != "2.144.0.0/14\n5.0.0.0/8\n" {
		t.Fatalf("IR set = %q, want the feed without 10.0.0.0/8", good)
	}

	for name, hostile := range map[string]string{
		"0.0.0.0/1 added": feed("2.144.0.0/14", "5.0.0.0/8", "0.0.0.0/1"),
		"empty":           "/ip firewall address-list\n",
		"garbage":         "<html>rate limited</html>",
		"halved":          feed("5.0.0.0/9"),
	} {
		body.Store(hostile)
		if err := m.c.RefreshIRFeed(bg); !errors.Is(err, ErrFeedRejected) {
			t.Errorf("%s: err = %v, want ErrFeedRejected", name, err)
		}
		if got := irSet(); got != good {
			t.Errorf("%s: IR set became %q", name, got)
		}
	}

	// A small change goes through.
	body.Store(feed("2.144.0.0/14", "5.0.0.0/8", "31.0.0.0/16"))
	if err := m.c.RefreshIRFeed(bg); err != nil {
		t.Fatalf("small change rejected: %v", err)
	}
	if got := irSet(); !strings.Contains(got, "31.0.0.0/16") {
		t.Errorf("IR set = %q after a small change", got)
	}
}

// The Abroad Rule travels apart from Rules: an Agent from before it, which
// knows no abroad_rule field, sees only the destination Rules and never
// reads it as "everything, requires IR, first" (ADR 0014).
func TestAbroadRuleTravelsApartFromRules(t *testing.T) {
	m := newMesh(t, "ir1")
	b := m.state("ir1").Bridge
	if len(b.Rules) != 2 || b.Rules[0].Name != "IR" || b.Rules[1].Name != "Default" {
		t.Errorf("rules = %+v", b.Rules)
	}
	ab := b.AbroadRule
	if ab == nil || ab.Source != "10.77.128.0/17" || ab.Fallback != protocol.FallbackDrop || !slices.Equal(ab.RequiredTags, []string{"IR"}) {
		t.Fatalf("Abroad Rule = %+v", ab)
	}
	if !slices.Equal(b.AbroadUpstreams, m.c.Egress.IR.Resolvers) || len(b.AbroadUpstreams) == 0 {
		t.Errorf("abroad upstreams = %v, want the domestic egress resolvers %v", b.AbroadUpstreams, m.c.Egress.IR.Resolvers)
	}

	body, _ := json.Marshal(b)
	var old struct { // BridgeState as Agents before ADR 0014 decode it
		Rules []struct {
			Name    string `json:"name"`
			SetHash string `json:"set_hash"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(body, &old); err != nil {
		t.Fatal(err)
	}
	if len(old.Rules) != 2 || old.Rules[0].Name != "IR" || old.Rules[0].SetHash == "" {
		t.Errorf("an older Agent sees rules %+v", old.Rules)
	}
}

// An Abroad Device reaches the Bridges only while its User has the abroad
// permission; taking it away keeps the Device (ADR 0014).
func TestAbroadDevicesNeedThePermission(t *testing.T) {
	m := newMesh(t, "ir1")
	u, _ := m.s.CreateUser(bg, "maryam")
	m.s.SetUserAbroad(bg, u.ID, true)
	ab, _ := m.s.AddDevice(bg, u.ID, "phone abroad", "pub-abroad", "", true)
	m.s.AddDevice(bg, u.ID, "phone", "pub-phone", "", false)
	m.c.Reconcile(bg)
	has := func(key string) bool {
		return slices.ContainsFunc(m.state("ir1").Bridge.Devices, func(d protocol.Device) bool { return d.PublicKey == key })
	}
	if !has("pub-abroad") || !has("pub-phone") {
		t.Fatalf("devices = %+v", m.state("ir1").Bridge.Devices)
	}

	m.s.SetUserAbroad(bg, u.ID, false)
	m.c.Reconcile(bg)
	if has("pub-abroad") || !has("pub-phone") {
		t.Errorf("without the permission: devices = %+v", m.state("ir1").Bridge.Devices)
	}
	if d, _ := m.s.UserDevice(bg, ab.ID); d.Revoked {
		t.Error("the Abroad Device was revoked")
	}
	m.s.SetUserAbroad(bg, u.ID, true)
	m.c.Reconcile(bg)
	if !has("pub-abroad") {
		t.Error("granting the permission again did not restore the Abroad Device")
	}
}
