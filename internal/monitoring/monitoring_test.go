package monitoring

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alakiani/ways/internal/ca"
)

var update = flag.Bool("update", false, "rewrite deploy/monitoring from this package")

// The alert table of ADR 0006 as ADR 0011 amends it, by the names the
// rules give its rows.
var alertTable = []string{
	"NodeUnreachable", "CoordinatorUnreachableFromNode", "LinkDown", "BridgeHasNoDefaultPath", "PathFlapping",
	"BridgeRemovedFromBridgeAddress", "BridgeReturnedToBridgeAddress", "BridgeAddressDownToOneBridge", "ArvanCloudDNSFailing",
	"ProbeFailing", "CertificateOrTokenExpiring", "ClockSkew", "CIDRRefresh", "BackupStale", "MeteringBacklog",
	"MeteringMismatch", "SnapshotApplyFailed", "DiskFull", "ConntrackFull",
}

func TestRulesCoverTheAlertTable(t *testing.T) {
	rules := Rules(ADRTiming)
	for _, name := range alertTable {
		if !strings.Contains(rules, "- alert: "+name+"\n") {
			t.Errorf("no rule for %s", name)
		}
	}
	if got := strings.Count(rules, "- alert: "); got < len(alertTable) {
		t.Errorf("%d rules for %d rows", got, len(alertTable))
	}
	for _, want := range []string{
		// ADR 0006's durations and severities.
		`max_over_time(up{job="agents"}[3m]) == 0 and on (node) ways_node_report_age_seconds > 180`,
		"severity: critical",
		"for: 2m",
		`ways_bridge_address_member == 0`,
		`increase(ways_path_moves_total{kind="failure"}[1h]) > 6`,
		`changes((max by (link) (ways_link_instance_up) == bool 0)[1h:]) >= 5`,
		`ways_client_cert_expiry_timestamp_seconds - time() < 2592000`,
		`time() - ways_backup_last_success_timestamp_seconds > 129600`,
	} {
		// Expressions are quoted in the file.
		if !strings.Contains(rules, want) && !strings.Contains(rules, quote(want)) {
			t.Errorf("rules lack %q", want)
		}
	}
	if lab := Rules(LabTiming); !strings.Contains(lab, `[8s]`) {
		t.Errorf("lab rules are not shortened:\n%s", lab)
	}
}

func TestPrometheusConfig(t *testing.T) {
	got := Prometheus(PrometheusConfig{Internal: "127.0.0.1:9101", Alertmanager: "127.0.0.1:9093", TLSDir: "/etc/ways/prometheus",
		RuleFiles: []string{"/etc/ways/prometheus/rules.yml"}, Interval: time.Second, SDRefresh: 2 * time.Second})
	for _, want := range []string{
		"scrape_interval: 1s", "scrape_timeout: 1s",
		"url: http://127.0.0.1:9101/v1/sd/agents", "refresh_interval: 2s",
		"cert_file: /etc/ways/prometheus/prometheus.crt", "server_name: " + ca.AgentServerName,
		`targets: ["127.0.0.1:9093"]`, `targets: ["127.0.0.1:9101"]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("config lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "coordinator-host") {
		t.Error("a host job with no HostExporter")
	}
}

func TestAlertmanagerConfig(t *testing.T) {
	got := Alertmanager(AlertmanagerConfig{Webhook: "http://127.0.0.1:9101/v1/alerts", GroupWait: 30 * time.Second,
		GroupInterval: 5 * time.Minute, RepeatInterval: 4 * time.Hour})
	for _, want := range []string{"url: http://127.0.0.1:9101/v1/alerts", "send_resolved: true", "group_wait: 30s", "repeat_interval: 4h"} {
		if !strings.Contains(got, want) {
			t.Errorf("config lacks %q:\n%s", want, got)
		}
	}
}

func TestMeshDashboard(t *testing.T) {
	var d struct {
		Title  string `json:"title"`
		UID    string `json:"uid"`
		Panels []any  `json:"panels"`
	}
	if err := json.Unmarshal(MeshDashboard(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Title != "Mesh" || d.UID == "" || len(d.Panels) == 0 {
		t.Errorf("dashboard = %q %q with %d panels", d.Title, d.UID, len(d.Panels))
	}
	qs := MeshDashboardQueries()
	joined := strings.Join(qs, "\n")
	// ADR 0006's Mesh dashboard: Nodes, the Link grid, Paths, the Bridge Address.
	for _, want := range []string{`up{job="agents"}`, "ways_link_rtt_seconds", "ways_link_loss_ratio", "ways_link_transport",
		"ways_path_buckets", "ways_bridge_address_member",
		// Issue #51: weights and cutoff, throughput with its age, instances.
		"ways_path_weight", "ways_path_cut_off", "ways_link_throughput_mbps",
		"ways_link_throughput_measured_timestamp_seconds", "ways_link_throughput_transport", "ways_link_instance_up"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no panel queries %s", want)
		}
	}
}

// Issue #51's panels: Path weights per Bridge, Throughput by Link, and an
// Instances Up state timeline per Link, each repeated over a variable the
// dashboard defines.
func TestMeshDashboardRepeatsPerBridgeAndLink(t *testing.T) {
	var d struct {
		Panels []struct {
			Type, Title, Repeat string
		} `json:"panels"`
		Templating struct {
			List []struct {
				Name       string `json:"name"`
				Definition string `json:"definition"`
			} `json:"list"`
		} `json:"templating"`
	}
	if err := json.Unmarshal(MeshDashboard(), &d); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{}
	for _, v := range d.Templating.List {
		vars[v.Name] = v.Definition
	}
	for _, want := range []struct{ typ, title, repeat, varQuery string }{
		{"timeseries", "Path weights: $bridge", "bridge", "label_values(ways_path_weight, node)"},
		{"table", "Throughput by Link", "", ""},
		{"state-timeline", "Instances Up: $link", "link", "label_values(ways_link_instance_up, link)"},
	} {
		found := false
		for _, p := range d.Panels {
			if p.Title == want.title {
				found = true
				if p.Type != want.typ || p.Repeat != want.repeat {
					t.Errorf("%s: a %s repeated over %q, want a %s over %q", p.Title, p.Type, p.Repeat, want.typ, want.repeat)
				}
			}
		}
		if !found {
			t.Errorf("no %q panel", want.title)
		}
		if want.repeat != "" && vars[want.repeat] != want.varQuery {
			t.Errorf("variable %s = %q, want %q", want.repeat, vars[want.repeat], want.varQuery)
		}
	}
}

func TestTelegramText(t *testing.T) {
	var w Webhook
	err := json.Unmarshal([]byte(`{"status":"firing","alerts":[
		{"status":"firing","labels":{"alertname":"NodeUnreachable","severity":"critical","node":"ab1"},
		 "annotations":{"summary":"Node ab1 is unreachable"},"startsAt":"2026-10-16T10:00:00Z"},
		{"status":"resolved","labels":{"alertname":"LinkDown","severity":"warning","link":"ab1/ir1"},
		 "annotations":{"summary":"Link ab1/ir1 is down"},"startsAt":"2026-10-16T09:00:00Z"}]}`), &w)
	if err != nil {
		t.Fatal(err)
	}
	got := w.Text()
	for _, want := range []string{"FIRING critical NodeUnreachable: Node ab1 is unreachable", "RESOLVED warning LinkDown: Link ab1/ir1 is down"} {
		if !strings.Contains(got, want) {
			t.Errorf("text lacks %q:\n%s", want, got)
		}
	}
	if (Webhook{}).Text() != "" {
		t.Error("an empty webhook has text")
	}
}

func TestDurations(t *testing.T) {
	for d, want := range map[time.Duration]string{time.Second: "1s", 90 * time.Second: "90s", 2 * time.Minute: "2m",
		36 * time.Hour: "36h", 1500 * time.Millisecond: "1500ms"} {
		if got := duration(d); got != want {
			t.Errorf("duration(%v) = %q, want %q", d, got, want)
		}
	}
}

// deployFiles are the files the playbook installs on the Coordinator VM.
func deployFiles() map[string][]byte {
	return map[string][]byte{
		"prometheus.yml":                []byte(Prometheus(ProductionPrometheus)),
		"rules.yml":                     []byte(Rules(ADRTiming)),
		"alertmanager.yml":              []byte(Alertmanager(ProductionAlertmanager)),
		"grafana/dashboards/mesh.json":  MeshDashboard(),
		"grafana/provisioning/ways.yml": []byte(GrafanaProvisioning),
		"grafana/datasources/ways.yml":  []byte(GrafanaDatasource),
		"README.md":                     []byte(deployReadme),
	}
}

func TestDeployFilesAreCurrent(t *testing.T) {
	root := filepath.Join("..", "..", "deploy", "monitoring")
	for name, want := range deployFiles() {
		path := filepath.Join(root, name)
		if *update {
			os.MkdirAll(filepath.Dir(path), 0o755)
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(want) {
			t.Errorf("%s is stale: run go test ./internal/monitoring -update", path)
		}
	}
}

// TestConfigsPassPromtool checks the configs with the pinned promtool and
// amtool, when WAYS_BIN holds them (CI downloads them for the lab).
func TestConfigsPassPromtool(t *testing.T) {
	bin := os.Getenv("WAYS_BIN")
	promtool, amtool := filepath.Join(bin, "promtool"), filepath.Join(bin, "amtool")
	if _, err := os.Stat(promtool); bin == "" || err != nil {
		t.Skip("no promtool in WAYS_BIN")
	}
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Errorf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run(promtool, "check", "rules", write("rules.yml", Rules(ADRTiming)))
	run(promtool, "check", "rules", write("lab-rules.yml", Rules(LabTiming)))
	run(promtool, "test", "rules", write("blackout-test.yml", blackoutTest))
	for _, f := range []string{"ca.crt", "prometheus.crt", "prometheus.key"} {
		write(f, "")
	}
	cfg := ProductionPrometheus
	cfg.TLSDir, cfg.RuleFiles = dir, []string{filepath.Join(dir, "rules.yml")}
	run(promtool, "check", "config", "--syntax-only", write("prometheus.yml", Prometheus(cfg)))
	run(amtool, "check-config", write("alertmanager.yml", Alertmanager(ProductionAlertmanager)))
}

// blackoutTest is a promtool rule test of LinkBlackout, every 15 s as in
// production: three blackouts of ab1/ir1 on both ends fire it; one
// transport failing three times, and two blackouts, do not.
const blackoutTest = `rule_files: [rules.yml]
evaluation_interval: 15s
tests:
  - interval: 15s
    input_series:
      - series: 'ways_link_instance_up{node="ir1",link="ab1/ir1",instance_id="1",transport="gre"}'
        values: '1x10 0x4 1x10 0x4 1x10 0x4 1x10'
      - series: 'ways_link_instance_up{node="ir1",link="ab1/ir1",instance_id="2",transport="amneziawg"}'
        values: '1x10 0x4 1x10 0x4 1x10 0x4 1x10'
      - series: 'ways_link_instance_up{node="ab1",link="ab1/ir1",instance_id="1",transport="gre"}'
        values: '1x10 0x4 1x10 0x4 1x10 0x4 1x10'
      - series: 'ways_link_instance_up{node="ab1",link="ab1/ir1",instance_id="2",transport="amneziawg"}'
        values: '1x10 0x4 1x10 0x4 1x10 0x4 1x10'
      - series: 'ways_link_instance_up{node="ir1",link="ab2/ir1",instance_id="3",transport="gre"}'
        values: '1x10 0x4 1x10 0x4 1x10 0x4 1x10'
      - series: 'ways_link_instance_up{node="ir1",link="ab2/ir1",instance_id="4",transport="amneziawg"}'
        values: '1x58'
      - series: 'ways_link_instance_up{node="ir1",link="ab3/ir1",instance_id="5",transport="gre"}'
        values: '1x10 0x4 1x10 0x4 1x26'
    alert_rule_test:
      - eval_time: 5m
        alertname: LinkBlackout
        exp_alerts: []
      - eval_time: 14m
        alertname: LinkBlackout
        exp_alerts:
          - exp_labels:
              severity: warning
              link: ab1/ir1
            exp_annotations:
              summary: "Every instance of Link ab1/ir1 went down at once at least 3 times in an hour"
`

func TestRuleExpressionsUseKnownMetrics(t *testing.T) {
	// Metric names in the rules either come from the exporters this repo
	// writes (ways_*), Prometheus itself (up), or node_exporter (node_*).
	re := regexp.MustCompile(`\b([a-z_]+_(?:seconds|total|ratio|bytes|eligible|ok|up|failures|use|limit|entries|rejected))\b`)
	for _, m := range re.FindAllStringSubmatch(Rules(ADRTiming), -1) {
		if !strings.HasPrefix(m[1], "ways_") && !strings.HasPrefix(m[1], "node_") && m[1] != "up" {
			t.Errorf("unknown metric %s", m[1])
		}
	}
}
