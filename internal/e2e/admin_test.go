//go:build linux

package e2e

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alakiani/ways/internal/auth"
	"github.com/alakiani/ways/internal/lab"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// TestAdminPanel is session 9's "proves in the lab" test: a browser walks
// every admin screen against a live lab mesh, and every change it makes
// shows in the Coordinator. Quota session 7 added the Users table's Quota
// columns, remedies and order, and the Invite form's presets (ADR 0010).
func TestAdminPanel(t *testing.T) {
	binDir(t)
	script, _ := filepath.Abs("../../web/e2e/admin.mjs")
	if _, err := os.Stat("../../web/node_modules/@playwright/test"); err != nil {
		t.Skip("web/node_modules is not installed: run npm ci in web/ and npx playwright install chromium")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on PATH")
	}
	if out, err := execCommand("modprobe", "wireguard"); err != nil {
		t.Fatalf("modprobe wireguard: %v: %s", err, out)
	}

	l := lab.StartSpecs(t,
		lab.Spec{Name: "coord"},
		lab.Spec{Name: "ir1"},
		lab.Spec{Name: "ab1"},
		lab.At("egress-ab", "1.0.0.10"),
		lab.At("egress-ir", "2.188.0.10"),
	)
	ctx := context.Background()
	co := startCoordinator(t, l.Node("coord"))
	egressTargets(t, co, l.Node("egress-ab"), l.Node("egress-ir"))

	// The feed starts with three prefixes; the next fetch finds a fourth.
	var feed atomic.Value
	feed.Store(irFeed("2.144.0.0/14", "2.176.0.0/12", "5.0.0.0/8"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, feed.Load().(string))
	}))
	defer srv.Close()
	co.c.FeedURL, co.c.RIPEstatURL = srv.URL, ""
	if err := co.c.RefreshIRFeed(ctx); err != nil {
		t.Fatal(err)
	}
	feed.Store(irFeed("2.144.0.0/14", "2.176.0.0/12", "5.0.0.0/8", "31.0.0.0/24"))

	// An Admin with TOTP, and two Users.
	const adminPassword = "the admin's long password"
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword(adminPassword)
	tok, _, _ := co.store.CreateInvite(ctx, store.Invite{Kind: "new", Admin: true}, time.Hour)
	admin, err := co.store.AcceptNewInvite(ctx, tok, "admin", hash)
	if err != nil {
		t.Fatal(err)
	}
	co.store.SetTOTPPending(ctx, admin.ID, secret)
	co.store.ConfirmTOTP(ctx, admin.ID)
	for _, handle := range []string{"maryam", "reza"} {
		tok, _, _ := co.store.CreateInvite(ctx, store.Invite{Kind: "new"}, time.Hour)
		if _, err := co.store.AcceptNewInvite(ctx, tok, handle, hash); err != nil {
			t.Fatal(err)
		}
	}

	// Three more Users with Usage this Quota Period (ADR 0010): sara has
	// used 80% of her Quota but only 40% with this period's 10 GB Top-up,
	// omid 50%, and nima has no Quota.
	for _, u := range []struct {
		handle string
		quota  uint64
		used   uint64
		topUp  uint64
	}{{"sara", 10e9, 8e9, 10e9}, {"omid", 2e9, 1e9, 0}, {"nima", 0, 3e9, 0}} {
		tok, _, _ := co.store.CreateInvite(ctx, store.Invite{Kind: "new"}, time.Hour)
		acct, err := co.store.AcceptNewInvite(ctx, tok, u.handle, hash)
		if err != nil {
			t.Fatal(err)
		}
		if u.quota > 0 {
			if err := co.store.SetQuota(ctx, acct.ID, store.QuotaSetting{Quota: &u.quota}); err != nil {
				t.Fatal(err)
			}
		}
		if u.topUp > 0 {
			if err := co.store.AddRemedy(ctx, acct.ID, store.TopUp, u.topUp); err != nil {
				t.Fatal(err)
			}
		}
		key, _ := wgtypes.GeneratePrivateKey()
		dev, err := co.store.AddDevice(ctx, acct.ID, "phone", key.PublicKey().String(), "", false)
		if err != nil {
			t.Fatal(err)
		}
		hour := time.Now().UTC().Truncate(time.Hour).Unix()
		if _, err := co.store.PutUsage(ctx, "nd_report", []protocol.UsageBucket{
			{Hour: hour, Device: dev.Address.String(), Exit: "nd_exit", Up: u.used / 4, Down: u.used - u.used/4},
		}); err != nil {
			t.Fatal(err)
		}
	}

	m := &mesh{t: t, l: l, co: co, ids: map[string]string{}, agents: map[string]*agentProc{}}
	m.startAgent("ir1", []protocol.Role{protocol.RoleBridge}, []string{"IR"})
	m.startAgent("ab1", []protocol.Role{protocol.RoleExit}, nil)

	// ir2, a domestic Bridge with no Agent in the Bridge Address's record,
	// so the browser may unlist ir1 (ADR 0015).
	ir2, err := co.store.CreateNode(ctx, "ir2", []protocol.Role{protocol.RoleBridge}, []string{"IR"})
	if err != nil {
		t.Fatal(err)
	}
	if err := co.store.JoinAddress(ctx, store.BridgeRecord, ir2.ID); err != nil {
		t.Fatal(err)
	}

	// An alert no Exit could relay waits on the banner (ADR 0006).
	alert, _ := co.store.QueueAlert(ctx, "WAYS\nFIRING critical NodeUnreachable: Node ab9 is unreachable")
	co.store.AlertFailed(ctx, alert, "no healthy Exit")

	cmd := exec.Command(node, script)
	cmd.Dir = filepath.Dir(script)
	cmd.Env = append(os.Environ(), "PANEL_URL="+co.admin.URL, "ADMIN_HANDLE=admin", "ADMIN_PASSWORD="+adminPassword, "TOTP_SECRET="+secret)
	out, err := cmd.CombinedOutput()
	t.Logf("browser:\n%s", strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("browser: %v", err)
	}

	// What the browser did is in the Coordinator.
	maryam, err := co.store.AccountByHandle(ctx, "maryam")
	if err != nil || maryam.Suspended || maryam.DeviceCap != 5 || !maryam.Abroad {
		t.Errorf("maryam = %+v, %v; want resumed with a cap of 5 and the abroad permission", maryam, err)
	}
	if _, err := co.store.AccountByHandle(ctx, "reza"); err == nil {
		t.Error("reza was not deleted")
	}

	// The Quota set inline, and the remedies.
	if maryam.Quota == nil || *maryam.Quota != 2.5e9 || maryam.SlowRate != 500_000 {
		t.Errorf("maryam's Quota = %v, slow rate %d; want 2.5 GB, slowed to 4 Mbit/s", maryam.Quota, maryam.SlowRate)
	}
	if rs, _ := co.store.Remedies(ctx, maryam.ID); len(rs) != 1 || rs[0].Kind != store.TopUp || rs[0].Bytes != 1.5e9 {
		t.Errorf("maryam's remedies = %+v, want a 1.5 GB Top-up", rs)
	}
	refills, _ := co.store.HeldRefills(ctx, maryam.ID)
	if len(refills) != 2 {
		t.Errorf("maryam holds %d Refills, want 2", len(refills))
	}
	for _, r := range refills {
		if d := time.Until(r.ExpiresAt); d < 44*24*time.Hour || d > 45*24*time.Hour {
			t.Errorf("a Refill expires in %v, want 45 days", d)
		}
	}
	omid, _ := co.store.AccountByHandle(ctx, "omid")
	if rs, _ := co.store.Remedies(ctx, omid.ID); len(rs) != 1 || rs[0].Kind != store.Reset || rs[0].Bytes != 1e9 {
		t.Errorf("omid's remedies = %+v, want a Reset of 1 GB", rs)
	}

	// The Invite made with presets.
	match := regexp.MustCompile(`preset invite: \S*/#/invite/(\S+)`).FindStringSubmatch(string(out))
	if match == nil {
		t.Fatal("the browser printed no preset Invite")
	}
	inv, err := co.store.LookupInvite(ctx, match[1])
	if err != nil || inv.Quota == nil || *inv.Quota != 5e9 || inv.SlowRate != 250_000 || inv.Refills != 2 || inv.RefillTTL != 60*24*time.Hour || !inv.Abroad {
		t.Errorf("preset Invite = %+v, %v; want 5 GB, slow to 2 Mbit/s, 2 Refills for 60 days, abroad", inv, err)
	}
	invites, _ := co.store.Invites(ctx)
	withdrawn, recovery := 0, 0
	for _, inv := range invites {
		if inv.Withdrawn {
			withdrawn++
		}
		if inv.Kind == "recovery" && inv.Handle == "maryam" {
			recovery++
		}
	}
	if withdrawn != 1 || recovery != 1 {
		t.Errorf("invites: %d withdrawn, %d recovery; want 1 and 1", withdrawn, recovery)
	}
	if _, err := co.store.NodeByName(ctx, "ab9"); err == nil {
		t.Error("ab9 was not deleted")
	}
	if ir1, err := co.store.NodeByName(ctx, "ir1"); err != nil || !ir1.Unlisted {
		t.Errorf("ir1 = %+v, %v; want unlisted", ir1, err)
	}
	if ts, _ := co.store.Transports(ctx); len(ts) != 3 {
		t.Errorf("transports = %v, want all three back on", ts)
	}
	rules, _ := co.store.Rules(ctx)
	if rules[1].Fallback != protocol.FallbackNext { // after the Abroad Rule
		t.Errorf("IR fallback = %s, want next", rules[1].Fallback)
	}
	sets, _ := co.store.DestinationSets(ctx)
	if adds := prefixStrings(sets[0].Additions); !slices.Contains(adds, "185.0.0.0/24") {
		t.Errorf("IR additions = %v", adds)
	}
	toks, revoked, _ := co.store.APITokens(ctx)
	for i, tk := range toks {
		if tk.Name == "ops-laptop" && !revoked[i] {
			t.Error("the ops-laptop token was not revoked")
		}
	}
}

func prefixStrings[T interface{ String() string }](ps []T) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}
