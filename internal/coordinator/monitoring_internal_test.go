package coordinator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/alakiani/ways/internal/backup"
	"github.com/alakiani/ways/internal/protocol"
)

func TestMonitorPortIsInEveryNodesState(t *testing.T) {
	m := newMesh(t, "ir1", "ab1")
	if st := m.state("ir1"); st.Monitor != nil {
		t.Errorf("monitoring is off by default, but ir1 has %+v", st.Monitor)
	}
	m.c.Monitor.Port, m.c.Monitor.AllowFrom = 9443, []string{"192.0.2.100"}
	if err := m.c.Reconcile(bg); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ir1", "ab1"} {
		if st := m.state(n); st.Monitor == nil || st.Monitor.Port != 9443 || st.Monitor.AllowFrom[0] != "192.0.2.100" {
			t.Errorf("%s: monitor = %+v", n, st.Monitor)
		}
	}
}

func internalGet(t *testing.T, c *Coordinator, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	c.InternalHandler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

func TestServiceDiscovery(t *testing.T) {
	m := newMesh(t, "ir1", "ab1")
	if got := internalGet(t, m.c, "/v1/sd/agents"); strings.TrimSpace(got) != "[]" {
		t.Errorf("targets with monitoring off: %s", got)
	}
	m.c.Monitor.Port, m.c.Monitor.AllowFrom = 9443, []string{"192.0.2.100"}
	var targets []struct {
		Targets []string          `json:"targets"`
		Labels  map[string]string `json:"labels"`
	}
	if err := json.Unmarshal([]byte(internalGet(t, m.c, "/v1/sd/agents")), &targets); err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %+v", targets)
	}
	ab1 := targets[0]
	if ab1.Targets[0] != m.addrs["ab1"]+":9443" || ab1.Labels["node"] != "ab1" || ab1.Labels["node_id"] != m.nodes["ab1"].ID ||
		ab1.Labels["roles"] != "bridge,exit" || ab1.Labels["tags"] != "" {
		t.Errorf("ab1 = %+v", ab1)
	}
	if targets[1].Labels["tags"] != "IR" {
		t.Errorf("ir1 = %+v", targets[1])
	}
}

func TestCoordinatorMetrics(t *testing.T) {
	m := newMesh(t, "ir1", "ab1")
	clock := time.Now().Add(time.Hour).Truncate(time.Second)
	m.s.Now = func() time.Time { return clock }
	// ir1's clock is 2 minutes fast.
	m.health("ir1", protocol.Health{LinkPublicKey: "ir1-key", Time: clock.Add(2 * time.Minute)})
	clock = clock.Add(30 * time.Second)
	m.s.QueueAlert(bg, "waiting")
	got := internalGet(t, m.c, "/metrics")
	for _, want := range []string{
		`ways_node_report_age_seconds{node="ir1"} 30`,
		`ways_node_clock_skew_seconds{node="ir1"} 120`,
		"ways_alerts_undelivered 1",
		"ways_ca_expiry_timestamp_seconds ",
		"ways_db_size_bytes ",
		`ways_irfeed_last_rejected{set="Iran"} 0`,
		"ways_bridge_address_eligible_bridges 0",
		"ways_arvan_consecutive_failures 0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("/metrics lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ways_backup_last_success") {
		t.Error("a backup metric with no backup configured")
	}
}

func TestUndeliverableAlertsWaitOnTheBanner(t *testing.T) {
	m := newMesh(t, "ir1")
	m.c.Monitor.Port, m.c.Monitor.Telegram.BotToken, m.c.Monitor.Telegram.ChatID = 9443, "tok", "chat"
	hook := `{"status":"firing","alerts":[{"status":"firing","labels":{"alertname":"NodeUnreachable","severity":"critical","node":"ab1"},"annotations":{"summary":"Node ab1 is unreachable"}}]}`
	rec := httptest.NewRecorder()
	m.c.InternalHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/v1/alerts", strings.NewReader(hook)))
	if rec.Code != http.StatusOK {
		t.Fatalf("webhook: %d %s", rec.Code, rec.Body)
	}
	// Queued, but not yet tried: no banner.
	if got, _ := m.c.UndeliveredAlerts(bg); len(got) != 0 {
		t.Errorf("banner before any attempt: %+v", got)
	}
	// ir1, the only Exit, has not reported for an hour.
	m.s.Now = func() time.Time { return time.Now().Add(time.Hour) }
	m.c.relayPending(bg)
	got, err := m.c.UndeliveredAlerts(bg)
	if err != nil || len(got) != 1 {
		t.Fatalf("banner = %+v, %v", got, err)
	}
	if !strings.Contains(got[0].Text, "FIRING critical NodeUnreachable: Node ab1 is unreachable") || got[0].Attempts != 1 ||
		!strings.Contains(got[0].LastError, "no healthy Exit") {
		t.Errorf("banner = %+v", got[0])
	}
	// An empty group is not queued.
	rec = httptest.NewRecorder()
	m.c.InternalHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/v1/alerts", strings.NewReader(`{"alerts":[]}`)))
	if p, _ := m.s.PendingAlerts(bg); len(p) != 1 {
		t.Errorf("%d pending", len(p))
	}
}

func TestBackups(t *testing.T) {
	m := newMesh(t, "ir1")
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	var uploaded []string
	m.c.Backup = BackupSettings{Recipients: []age.Recipient{id.Recipient()}, Dir: dir, Keep: 2, Every: 24 * time.Hour,
		Upload: uploaderFunc(func(name string, data []byte) error { uploaded = append(uploaded, name); return nil })}
	clock := time.Date(2026, 10, 16, 3, 0, 0, 0, time.UTC)
	m.s.Now = func() time.Time { return clock }

	if err := m.c.backupIfDue(bg); err != nil {
		t.Fatal(err)
	}
	if len(uploaded) != 1 || uploaded[0] != "ways-20261016T030000Z.db.age" {
		t.Fatalf("uploaded %v", uploaded)
	}
	// Not due again within a day.
	clock = clock.Add(23 * time.Hour)
	m.c.backupIfDue(bg)
	if len(uploaded) != 1 {
		t.Errorf("backed up again after 23 h: %v", uploaded)
	}
	clock = clock.Add(time.Hour)
	m.c.backupIfDue(bg)
	clock = clock.Add(24 * time.Hour)
	m.c.backupIfDue(bg)
	if len(uploaded) != 3 {
		t.Errorf("uploaded %v", uploaded)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("%d backups kept, want 2", len(entries))
	}

	// What was uploaded restores.
	f, _ := os.Open(filepath.Join(dir, uploaded[2]))
	defer f.Close()
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := backup.Restore(f, []age.Identity{id}, restored); err != nil {
		t.Fatal(err)
	}

	// A failed upload is recorded and shows on the board.
	m.c.Backup.Upload = uploaderFunc(func(string, []byte) error { return io.ErrUnexpectedEOF })
	clock = clock.Add(25 * time.Hour)
	if err := m.c.backupIfDue(bg); err == nil {
		t.Error("a failed upload was not an error")
	}
	st, err := m.c.BackupStatus(bg)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Configured || st.LastSuccess == nil || !st.LastSuccess.Equal(clock.Add(-25*time.Hour)) ||
		!st.LastAttempt.Equal(clock) || !strings.Contains(st.LastError, "unexpected EOF") || st.SizeBytes == 0 {
		t.Errorf("status = %+v", st)
	}
	if got := internalGet(t, m.c, "/metrics"); !strings.Contains(got, "ways_backup_last_success_timestamp_seconds ") {
		t.Errorf("no backup metric:\n%s", got)
	}
}

type uploaderFunc func(name string, data []byte) error

func (f uploaderFunc) Put(_ context.Context, name string, data []byte) error { return f(name, data) }
