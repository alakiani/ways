// Package monitoring writes the monitoring stack's configuration (ADR
// 0006): Prometheus pulling every Agent's /metrics over mTLS, with its
// targets from the Coordinator; the alert table as Prometheus rules;
// Alertmanager handing every alert to the Coordinator, which relays it to
// Telegram through an Exit; and Grafana's Mesh dashboard.
//
// Configs are generated rather than kept as loose files so the lab runs the
// same rules as production with shorter durations. deploy/monitoring holds
// the production output; a test keeps it current.
package monitoring

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/alakiani/ways/internal/ca"
)

// Timing is the alert table's durations: how long a condition must hold,
// or how long an event keeps its alert firing.
type Timing struct {
	Unreachable   time.Duration // Node unreachable: no scrape and no health report
	ContactLost   time.Duration // a Node has not reached the Coordinator
	LinkDown      time.Duration // no working transport
	NoPath        time.Duration // a Bridge has no Path for the default Rule
	OneBridgeLeft time.Duration // the Bridge Address holds one Bridge
	ProbeFailing  time.Duration // the probe Device fails on a Bridge
	EventWindow   time.Duration // an event alert fires this long after the event
}

// ADRTiming is ADR 0006's.
var ADRTiming = Timing{
	Unreachable:   3 * time.Minute,
	ContactLost:   3 * time.Minute,
	LinkDown:      2 * time.Minute,
	NoPath:        time.Minute,
	OneBridgeLeft: 2 * time.Minute,
	ProbeFailing:  time.Minute,
	EventWindow:   10 * time.Minute,
}

// LabTiming shortens ADRTiming for the lab, where Agents report every
// second and Prometheus scrapes every second.
var LabTiming = Timing{
	Unreachable:   8 * time.Second,
	ContactLost:   8 * time.Second,
	LinkDown:      4 * time.Second,
	NoPath:        3 * time.Second,
	OneBridgeLeft: 4 * time.Second,
	ProbeFailing:  3 * time.Second,
	EventWindow:   30 * time.Second,
}

type rule struct {
	alert, expr string
	hold        time.Duration // Prometheus's "for"
	severity    string
	summary     string // a Prometheus template
}

const (
	day  = 24 * 3600
	hour = 3600
)

// rules is the alert table, row by row. Event rows (returned, apply
// failed) fire for EventWindow after each event.
func rules(t Timing) []rule {
	sec := func(d time.Duration) int { return int(d.Seconds()) }
	return []rule{
		{"NodeUnreachable",
			fmt.Sprintf(`max_over_time(up{job="agents"}[%s]) == 0 and on (node) ways_node_report_age_seconds > %d`, duration(t.Unreachable), sec(t.Unreachable)),
			0, "critical", "Node {{ $labels.node }} is unreachable: no scrape and no health report"},
		{"CoordinatorUnreachableFromNode",
			fmt.Sprintf(`ways_coordinator_last_contact_seconds > %d`, sec(t.ContactLost)),
			0, "warning", "Node {{ $labels.node }} has not reached the Coordinator for {{ $value | humanizeDuration }}"},
		{"LinkDown", `max by (link) (ways_link_up) == 0`,
			t.LinkDown, "warning", "Link {{ $labels.link }} has no working transport"},
		// Every instance down at once, on both ends, is a whole-path blackout
		// rather than one transport failing (issue #51). Three blackouts make
		// at least 5 changes into or out of one within the hour; two make 4
		// at most.
		{"LinkBlackout", `changes((max by (link) (ways_link_instance_up) == bool 0)[1h:]) >= 5`,
			0, "warning", "Every instance of Link {{ $labels.link }} went down at once at least 3 times in an hour"},
		{"BridgeHasNoDefaultPath", `ways_path_ok{default="true"} == 0`,
			t.NoPath, "critical", "Bridge {{ $labels.node }} has no Path for the default Rule"},
		// Rebalancing moves do not count (ADR 0008).
		{"PathFlapping", `increase(ways_path_moves_total{kind="failure"}[1h]) > 6`,
			0, "warning", "Paths of Rule {{ $labels.rule }} on {{ $labels.node }} flap: {{ $value | printf \"%.0f\" }} failure moves in an hour"},
		{"BridgeRemovedFromBridgeAddress", `ways_bridge_address_member == 0`,
			0, "warning", "Bridge {{ $labels.node }} is out of the Bridge Address"},
		{"BridgeReturnedToBridgeAddress", fmt.Sprintf(`increase(ways_bridge_address_joins_total[%s]) > 0`, duration(t.EventWindow)),
			0, "info", "A Bridge joined the Bridge Address"},
		{"BridgeAddressDownToOneBridge", `ways_bridge_address_members == 1`,
			t.OneBridgeLeft, "critical", "The Bridge Address holds only one Bridge"},
		{"ArvanCloudDNSFailing", `ways_arvan_consecutive_failures >= 3`,
			0, "warning", "ArvanCloud's DNS API failed {{ $value }} times in a row"},
		{"ProbeFailing", `ways_probe_ok == 0`,
			t.ProbeFailing, "warning", "The probe Device fails on Bridge {{ $labels.node }}"},
		// Node certificates renew at 30 days left, so less means renewal is broken.
		{"CertificateOrTokenExpiring", fmt.Sprintf(`ways_client_cert_expiry_timestamp_seconds - time() < %d`, 30*day),
			0, "warning", "The client certificate of Node {{ $labels.node }} expires in {{ $value | humanizeDuration }}"},
		{"CertificateOrTokenExpiring", fmt.Sprintf(`ways_public_tls_expiry_timestamp_seconds - time() < %d`, 14*day),
			0, "warning", "The public TLS certificate expires in {{ $value | humanizeDuration }}"},
		{"CertificateOrTokenExpiring", fmt.Sprintf(`ways_api_token_expiry_timestamp_seconds - time() < %d`, 7*day),
			0, "warning", "API token {{ $labels.token }} expires in {{ $value | humanizeDuration }}"},
		{"ClockSkew", `abs(ways_node_clock_skew_seconds) > 60`,
			0, "warning", "The clock of Node {{ $labels.node }} is {{ $value | humanizeDuration }} off"},
		{"CIDRRefresh", fmt.Sprintf(`ways_irfeed_last_rejected == 1 or time() - ways_irfeed_last_success_timestamp_seconds > %d`, 3*day),
			0, "warning", "The feed of Destination Set {{ $labels.set }} was rejected or is over 3 days old"},
		{"BackupStale", fmt.Sprintf(`time() - ways_backup_last_success_timestamp_seconds > %d`, 36*hour),
			0, "warning", "The last good backup is {{ $value | humanizeDuration }} old"},
		// Only Bridges that answer a scrape report a backlog: healthy ones.
		{"MeteringBacklog", fmt.Sprintf(`ways_metering_backlog_seconds > %d`, 3*hour),
			0, "warning", "Bridge {{ $labels.node }} has {{ $value | humanizeDuration }} of metering not acknowledged"},
		// Under 100 MB a day, unmetered traffic such as DNS to the Bridge's
		// own resolver would trip the 20%.
		{"MeteringMismatch",
			`abs(increase(ways_metered_bytes_total[1d]) - increase(ways_bridge_interface_bytes_total[1d])) > 0.2 * increase(ways_bridge_interface_bytes_total[1d]) and increase(ways_bridge_interface_bytes_total[1d]) > 1e8`,
			0, "warning", "Metered bytes on Bridge {{ $labels.node }} differ from its interface bytes by over 20% in a day"},
		{"SnapshotApplyFailed", fmt.Sprintf(`increase(ways_snapshot_apply_failures_total[%s]) > 0`, duration(t.EventWindow)),
			0, "warning", "Node {{ $labels.node }} reverted a snapshot that cut it off from the Coordinator"},
		{"DiskFull", `1 - node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"} > 0.85`,
			0, "warning", "The disk of {{ $labels.node }} is {{ $value | humanizePercentage }} full"},
		{"ConntrackFull", `node_nf_conntrack_entries / node_nf_conntrack_entries_limit > 0.8`,
			0, "warning", "The conntrack table of {{ $labels.node }} is {{ $value | humanizePercentage }} full"},
	}
}

// Rules is the alert table as a Prometheus rule file.
func Rules(t Timing) string {
	var b strings.Builder
	b.WriteString("# The alert table of ADR 0006. Generated by internal/monitoring; do not edit.\n")
	b.WriteString("groups:\n  - name: ways\n    rules:\n")
	for _, r := range rules(t) {
		fmt.Fprintf(&b, "      - alert: %s\n", r.alert)
		fmt.Fprintf(&b, "        expr: %s\n", quote(r.expr))
		if r.hold > 0 {
			fmt.Fprintf(&b, "        for: %s\n", duration(r.hold))
		}
		fmt.Fprintf(&b, "        labels:\n          severity: %s\n", r.severity)
		fmt.Fprintf(&b, "        annotations:\n          summary: %s\n", quote(r.summary))
	}
	return b.String()
}

// PrometheusConfig is what a Prometheus config is made from.
type PrometheusConfig struct {
	// Internal is the Coordinator's internal listener: service discovery,
	// its own metrics, and Alertmanager's webhook.
	Internal     string
	Alertmanager string
	// TLSDir holds ca.crt, prometheus.crt and prometheus.key, written by
	// the Coordinator (coordinator -prometheus-tls-dir).
	TLSDir    string
	RuleFiles []string
	Interval  time.Duration // scrape and rule evaluation
	SDRefresh time.Duration // how often the targets are re-read
	// HostExporter, if set, is the Coordinator VM's own node_exporter.
	HostExporter string
}

// ProductionPrometheus is the Coordinator VM's.
var ProductionPrometheus = PrometheusConfig{
	Internal:     "127.0.0.1:9101",
	Alertmanager: "127.0.0.1:9093",
	TLSDir:       "/etc/ways/prometheus",
	RuleFiles:    []string{"/etc/ways/prometheus/rules.yml"},
	Interval:     15 * time.Second,
	SDRefresh:    30 * time.Second,
	HostExporter: "127.0.0.1:9100",
}

// Prometheus is a Prometheus config. Retention (30 days, ADR 0006) is a
// command-line flag, set in its systemd unit.
func Prometheus(c PrometheusConfig) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# Prometheus on the Coordinator VM (ADR 0006). Generated by internal/monitoring; do not edit.")
	w("global:")
	w("  scrape_interval: %s", duration(c.Interval))
	w("  scrape_timeout: %s", duration(min(c.Interval, 10*time.Second)))
	w("  evaluation_interval: %s", duration(c.Interval))
	w("rule_files:")
	for _, f := range c.RuleFiles {
		w("  - %s", f)
	}
	w("alerting:")
	w("  alertmanagers:")
	w("    - static_configs:")
	w("        - targets: [%q]", c.Alertmanager)
	w("scrape_configs:")
	// Every Agent's one port, behind nftables and mTLS. Targets carry the
	// Node's name, Roles and Tags as labels.
	w("  - job_name: agents")
	w("    scheme: https")
	w("    tls_config:")
	w("      ca_file: %s/ca.crt", c.TLSDir)
	w("      cert_file: %s/prometheus.crt", c.TLSDir)
	w("      key_file: %s/prometheus.key", c.TLSDir)
	w("      server_name: %s", ca.AgentServerName)
	w("    http_sd_configs:")
	w("      - url: http://%s/v1/sd/agents", c.Internal)
	w("        refresh_interval: %s", duration(c.SDRefresh))
	w("  - job_name: coordinator")
	w("    static_configs:")
	w("      - targets: [%q]", c.Internal)
	if c.HostExporter != "" {
		w("  - job_name: coordinator-host")
		w("    static_configs:")
		w("      - targets: [%q]", c.HostExporter)
		w("        labels:")
		w("          node: coordinator")
	}
	return b.String()
}

// AlertmanagerConfig is what an Alertmanager config is made from.
type AlertmanagerConfig struct {
	Webhook                                  string // the Coordinator's /v1/alerts
	GroupWait, GroupInterval, RepeatInterval time.Duration
}

// ProductionAlertmanager is the Coordinator VM's.
var ProductionAlertmanager = AlertmanagerConfig{
	Webhook:        "http://127.0.0.1:9101/v1/alerts",
	GroupWait:      30 * time.Second,
	GroupInterval:  5 * time.Minute,
	RepeatInterval: 4 * time.Hour,
}

// Alertmanager is an Alertmanager config: every alert, firing and
// resolved, goes to the Coordinator, which relays it through an Exit.
func Alertmanager(c AlertmanagerConfig) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# Alertmanager on the Coordinator VM (ADR 0006). Generated by internal/monitoring; do not edit.")
	w("route:")
	w("  receiver: coordinator")
	w("  group_by: [alertname, node, link, rule]")
	w("  group_wait: %s", duration(c.GroupWait))
	w("  group_interval: %s", duration(c.GroupInterval))
	w("  repeat_interval: %s", duration(c.RepeatInterval))
	w("receivers:")
	w("  - name: coordinator")
	w("    webhook_configs:")
	w("      - url: %s", c.Webhook)
	w("        send_resolved: true")
	return b.String()
}

//go:embed grafana/mesh.json
var meshDashboard []byte

// MeshDashboard is Grafana's Mesh dashboard, the only one in the MVP.
func MeshDashboard() []byte { return slices.Clone(meshDashboard) }

// MeshDashboardQueries are the PromQL queries of the Mesh dashboard.
func MeshDashboardQueries() []string {
	var d struct {
		Panels []struct {
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(meshDashboard, &d); err != nil {
		panic(err)
	}
	var out []string
	for _, p := range d.Panels {
		for _, t := range p.Targets {
			out = append(out, t.Expr)
		}
	}
	return out
}

// GrafanaDatasource provisions Prometheus as Grafana's data source.
const GrafanaDatasource = `# Grafana's data source (ADR 0006). Generated by internal/monitoring; do not edit.
apiVersion: 1
datasources:
  - name: Prometheus
    uid: ways-prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:9090
    isDefault: true
`

// GrafanaProvisioning provisions the dashboards directory.
const GrafanaProvisioning = `# Grafana's dashboards (ADR 0006). Generated by internal/monitoring; do not edit.
apiVersion: 1
providers:
  - name: ways
    type: file
    disableDeletion: true
    allowUiUpdates: false
    options:
      path: /etc/ways/grafana/dashboards
`

const deployReadme = `# Monitoring on the Coordinator VM

Generated by ` + "`internal/monitoring`" + `; run ` + "`go test ./internal/monitoring -update`" + ` after changing it.
The playbook (session 13) installs these with the pinned Prometheus, Alertmanager and Grafana (ADR 0006):

- ` + "`prometheus.yml`, `rules.yml`" + ` in /etc/ways/prometheus. Run Prometheus with
  ` + "`--storage.tsdb.retention.time=30d`" + ` and ` + "`--web.listen-address=127.0.0.1:9090`" + `.
  The Coordinator writes the client certificate there when started with
  ` + "`-prometheus-tls-dir /etc/ways/prometheus`" + `.
- ` + "`alertmanager.yml`" + ` in /etc/ways/alertmanager. Run Alertmanager with
  ` + "`--web.listen-address=127.0.0.1:9093 --cluster.listen-address=`" + `.
- ` + "`grafana/`" + `: the data source and dashboard provisioning, and the Mesh dashboard in
  /etc/ways/grafana/dashboards.

Everything listens on localhost; the Coordinator's internal listener is ` + "`-internal-listen 127.0.0.1:9101`" + `.
`

// quote writes s as a YAML double-quoted scalar, which JSON's string
// syntax is.
func quote(s string) string {
	var b strings.Builder
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

// duration writes d as Prometheus writes durations.
func duration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	case d%time.Second == 0:
		return fmt.Sprintf("%ds", d/time.Second)
	}
	return fmt.Sprintf("%dms", d/time.Millisecond)
}
