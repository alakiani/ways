//go:build linux

package e2e

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alakiani/ways/internal/auth"
	"github.com/alakiani/ways/internal/ca"
	"github.com/alakiani/ways/internal/coordinator"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// TestUserPanelUsage is Quota session 6's browser test (ADR 0010): four
// Users sign in to the panel and see their Quota card at 0%, 85%, 100%
// (blocked) and unlimited; one redeems a Refill, and one revokes a Device
// and finds its Usage in a Revoked Devices row on the Usage page. It needs
// no mesh: Usage is put in the store as Bridges would report it.
func TestUserPanelUsage(t *testing.T) {
	script, _ := filepath.Abs("../../web/e2e/user-usage.mjs")
	if _, err := os.Stat("../../web/node_modules/@playwright/test"); err != nil {
		t.Skip("web/node_modules is not installed: run npm ci in web/ and npx playwright install chromium")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on PATH")
	}

	ctx := context.Background()
	s, err := store.Open(filepath.Join(t.TempDir(), "ways.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// The store's clock runs at an offset the test can move, to register a
	// User 40 days ago.
	var offset atomic.Int64
	s.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := coordinator.New(s, authority, slog.New(slog.NewTextHandler(t.Output(), nil)))
	srv := httptest.NewServer(c.AdminHandler())
	defer srv.Close()

	const password = "a long enough password"
	hash, _ := auth.HashPassword(password)
	gb := func(n float64) uint64 { return uint64(n * 1e9) }
	register := func(handle string, quota *uint64, refills int, ago time.Duration) string {
		t.Helper()
		offset.Store(int64(-ago))
		defer offset.Store(0)
		inv := store.Invite{Kind: "new", QuotaSetting: store.QuotaSetting{Quota: quota}, Refills: refills, RefillTTL: 30 * 24 * time.Hour}
		tok, _, err := s.CreateInvite(ctx, inv, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		a, err := s.AcceptNewInvite(ctx, tok, handle, hash)
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	device := func(userID, name string) store.UserDevice {
		t.Helper()
		key, _ := wgtypes.GeneratePrivateKey()
		d, err := s.AddDevice(ctx, userID, name, key.PublicKey().String(), "", false)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	// use reports a Device's Usage in one hour, as a Bridge would.
	use := func(d store.UserDevice, hour time.Time, bytes uint64) {
		t.Helper()
		b := protocol.UsageBucket{Hour: hour.Truncate(time.Hour).Unix(), Device: d.Address.String(), Exit: "nd_ab1", Up: bytes / 4, Down: bytes - bytes/4}
		if n, err := s.PutUsage(ctx, "nd_ir1", []protocol.UsageBucket{b}); err != nil || n != 1 {
			t.Fatalf("put usage: %d, %v", n, err)
		}
	}
	now := time.Now()
	ten, five := gb(10), gb(5)

	// sara has used none of her 10 GB.
	register("sara", &ten, 0, 0)

	// maryam registered 40 days ago: she has a closed period with 3 GB, and
	// 8.5 GB of 10 GB in this one, 1 GB of it on her laptop.
	maryam := register("maryam", &ten, 0, 40*24*time.Hour)
	phone, laptop := device(maryam, "phone"), device(maryam, "laptop")
	cur, err := s.CurrentQuotaPeriod(ctx, maryam)
	if err != nil {
		t.Fatal(err)
	}
	use(phone, cur.Start.Add(-48*time.Hour), gb(3))
	use(phone, now, gb(7.5))
	use(laptop, now.Add(-time.Hour), gb(1))
	if err := s.ClosePeriods(ctx); err != nil {
		t.Fatal(err)
	}

	// reza has used all of his 5 GB and holds two Refills.
	reza := register("reza", &five, 2, 0)
	use(device(reza, "phone"), now, five)

	// ali is unlimited and has used 2 GB.
	ali := register("ali", nil, 0, 0)
	use(device(ali, "phone"), now, gb(2))

	cmd := exec.Command(node, script)
	cmd.Dir = filepath.Dir(script)
	cmd.Env = append(os.Environ(), "PANEL_URL="+srv.URL, "PASSWORD="+password)
	out, err := cmd.CombinedOutput()
	t.Logf("browser:\n%s", strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("browser: %v", err)
	}

	// What the browser did is in the Coordinator.
	if n, _ := s.HeldRefillCount(ctx, reza); n != 1 {
		t.Errorf("reza holds %d Refills, want 1 after redeeming one", n)
	}
	if q, _ := s.QuotaStanding(ctx, reza); q.Remedies != five {
		t.Errorf("reza's remedies this period = %d, want a %d-byte Reset", q.Remedies, five)
	}
	if d, err := s.UserDevice(ctx, laptop.ID); err != nil || !d.Revoked {
		t.Errorf("maryam's laptop = %+v, %v; want revoked", d, err)
	}
	if d, _ := s.UserDevice(ctx, phone.ID); d.Revoked {
		t.Error("maryam's phone was revoked")
	}
}
