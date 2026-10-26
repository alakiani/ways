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
	"testing"
	"time"

	"github.com/alakiani/ways/internal/auth"
	"github.com/alakiani/ways/internal/ca"
	"github.com/alakiani/ways/internal/coordinator"
	"github.com/alakiani/ways/internal/store"
)

// TestUserPanelAbroadDevices is ADR 0014's browser test: only a User with
// the abroad permission is offered an Abroad Device, and the one they make
// carries its notice and reaches the Abroad Bridge Address. It needs no
// mesh.
func TestUserPanelAbroadDevices(t *testing.T) {
	script, _ := filepath.Abs("../../web/e2e/abroad.mjs")
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
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := coordinator.New(s, authority, slog.New(slog.NewTextHandler(t.Output(), nil)))
	srv := httptest.NewServer(c.AdminHandler())
	defer srv.Close()

	const password = "a long enough password"
	hash, _ := auth.HashPassword(password)
	register := func(handle string) string {
		t.Helper()
		tok, _, err := s.CreateInvite(ctx, store.Invite{Kind: "new"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		a, err := s.AcceptNewInvite(ctx, tok, handle, hash)
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	sara := register("sara")
	if err := s.SetUserAbroad(ctx, sara, true); err != nil {
		t.Fatal(err)
	}
	register("reza")

	cmd := exec.Command(node, script)
	cmd.Dir = filepath.Dir(script)
	cmd.Env = append(os.Environ(), "PANEL_URL="+srv.URL, "PASSWORD="+password, "OUT_DIR="+t.TempDir())
	out, err := cmd.CombinedOutput()
	t.Logf("browser:\n%s", strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("browser: %v", err)
	}

	devs, err := s.UserDevices(ctx, sara)
	if err != nil || len(devs) != 1 || !devs[0].Abroad || !store.AbroadPool.Contains(devs[0].Address) {
		t.Errorf("sara's Devices = %+v, %v; want one Abroad Device", devs, err)
	}
}
