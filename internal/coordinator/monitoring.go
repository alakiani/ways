package coordinator

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alakiani/ways/internal/ca"
	"github.com/alakiani/ways/internal/metrics"
	"github.com/alakiani/ways/internal/monitoring"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// MonitorSettings are the Coordinator's part in monitoring (ADR 0006).
type MonitorSettings struct {
	// Port is every Node's monitoring port; 0 keeps it shut.
	Port uint16
	// AllowFrom are the Coordinator VM's addresses as Nodes see them, the
	// only ones nftables lets reach the port.
	AllowFrom []string
	Telegram  TelegramSettings
	// Dial, if set, opens connections to Exits for the relay; the lab
	// dials from the Coordinator's namespace.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// RetryEvery is how often undelivered alerts are tried again.
	RetryEvery time.Duration
	// RelayTimeout bounds one Exit's attempt; the Agent gives Telegram 10 s.
	RelayTimeout time.Duration
	// PublicCertFile is the public TLS certificate, watched for expiry.
	PublicCertFile string
}

// TelegramSettings name the bot and channel alerts go to. They live in
// the Coordinator's config, never in the database.
type TelegramSettings struct {
	BotToken, ChatID string
}

// DefaultMonitorSettings keep the port shut until it is configured.
var DefaultMonitorSettings = MonitorSettings{RetryEvery: time.Minute, RelayTimeout: 15 * time.Second}

// monitorState is what the Coordinator keeps in memory for monitoring.
type monitorState struct {
	poke chan struct{} // wakes the relay loop

	mu       sync.Mutex
	identity *tls.Certificate // the Coordinator's client certificate
}

func (c *Coordinator) monitorState(n store.Node) *protocol.Monitor {
	if c.Monitor.Port == 0 || len(c.Monitor.AllowFrom) == 0 {
		return nil
	}
	return &protocol.Monitor{Port: c.Monitor.Port, AllowFrom: slices.Clone(c.Monitor.AllowFrom)}
}

// InternalHandler serves the Coordinator's internal listener, on the VM's
// loopback only: Prometheus's targets and the Coordinator's own metrics,
// and Alertmanager's webhook.
func (c *Coordinator) InternalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sd/agents", c.serviceDiscovery)
	mux.HandleFunc("GET /metrics", c.serveMetrics)
	mux.HandleFunc("POST /v1/alerts", c.alertWebhook)
	return mux
}

// sdTarget is one group of Prometheus's HTTP service discovery.
type sdTarget struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// serviceDiscovery lists every Node that has reported, at the address the
// Coordinator sees it from, so enrolling or deleting a Node needs no
// Prometheus config edit.
func (c *Coordinator) serviceDiscovery(w http.ResponseWriter, r *http.Request) {
	out := []sdTarget{}
	if c.Monitor.Port == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}
	nodes, err := c.store.Nodes(r.Context())
	if err != nil {
		c.internalError(w, err)
		return
	}
	for _, n := range nodes {
		h, err := c.store.Health(r.Context(), n.ID)
		if err != nil {
			c.internalError(w, err)
			return
		}
		if h == nil || h.SeenAddr == "" {
			continue
		}
		roles := make([]string, len(n.Roles))
		for i, role := range n.Roles {
			roles[i] = string(role)
		}
		out = append(out, sdTarget{
			Targets: []string{net.JoinHostPort(h.SeenAddr, strconv.Itoa(int(c.Monitor.Port)))},
			Labels:  map[string]string{"node": n.Name, "node_id": n.ID, "roles": strings.Join(roles, ","), "tags": strings.Join(n.Tags, ",")},
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// serveMetrics is the Coordinator's own /metrics (ADR 0006). Labels name
// Nodes, sets and tokens, never a Device or User.
func (c *Coordinator) serveMetrics(w http.ResponseWriter, r *http.Request) {
	var m metrics.Writer
	if err := c.writeMetrics(r.Context(), &m); err != nil {
		c.internalError(w, err)
		return
	}
	m.Serve(w)
}

func (c *Coordinator) writeMetrics(ctx context.Context, m *metrics.Writer) error {
	now := c.store.Now()
	nodes, err := c.store.Nodes(ctx)
	if err != nil {
		return err
	}
	names := map[string]string{}
	for _, n := range nodes {
		names[n.ID] = n.Name
		h, err := c.store.Health(ctx, n.ID)
		if err != nil {
			return err
		}
		if h == nil {
			continue
		}
		m.Gauge("ways_node_report_age_seconds", "Seconds since the Node's last health report.", now.Sub(h.ReceivedAt).Seconds(), "node", n.Name)
		if !h.Time.IsZero() {
			m.Gauge("ways_node_clock_skew_seconds", "The Node's clock minus the Coordinator's, at its last report.",
				h.Time.Sub(h.ReceivedAt).Round(time.Second).Seconds(), "node", n.Name)
		}
	}

	// The Bridge Address (ADR 0011).
	addr, err := c.BridgeAddressStatus(ctx)
	if err != nil {
		return err
	}
	eligible, members := 0, 0
	for _, b := range addr.Bridges {
		m.Bool("ways_bridge_address_member", "1 while the Bridge is in the Bridge Address's record.", b.InRecord, "node", b.Name)
		if b.InRecord {
			members++
		}
		if b.Probe == nil {
			continue
		}
		m.Bool("ways_probe_ok", "1 while the probe Device passes on the Bridge.", b.Probe.OK, "node", b.Name)
		m.Bool("ways_bridge_eligible", "1 while the Bridge may be in the Bridge Address.", b.Eligible, "node", b.Name)
		if b.Eligible {
			eligible++
		}
	}
	m.Gauge("ways_bridge_address_eligible_bridges", "Bridges that may be in the Bridge Address.", float64(eligible))
	m.Gauge("ways_bridge_address_members", "Bridges in the Bridge Address's record.", float64(members))
	m.Counter("ways_bridge_address_joins_total", "Bridges that joined the Bridge Address's record.", float64(addr.Joins))
	m.Counter("ways_bridge_address_removals_total", "Bridges removed from the Bridge Address's record.", float64(addr.Removals))
	c.address.mu.Lock()
	dnsFailures := c.address.dnsFailures
	c.address.mu.Unlock()
	m.Gauge("ways_arvan_consecutive_failures", "ArvanCloud DNS API calls failed in a row.", float64(dnsFailures))

	// The IR feed (ADR 0004).
	sets, err := c.store.DestinationSets(ctx)
	if err != nil {
		return err
	}
	for _, s := range sets {
		if s.Feed == "" {
			continue
		}
		st, err := c.store.FeedStatus(ctx, s.ID)
		if err != nil {
			return err
		}
		if !st.UpdatedAt.IsZero() {
			m.Gauge("ways_irfeed_last_success_timestamp_seconds", "When the set's feed last passed its gates.", float64(st.UpdatedAt.Unix()), "set", s.Name)
		}
		m.Bool("ways_irfeed_last_rejected", "1 if a gate rejected the set's last feed update.", st.LastError != "", "set", s.Name)
	}

	if c.Backup.configured() {
		good, _, err := c.store.Backups(ctx)
		if err != nil {
			return err
		}
		at := 0.0
		if good != nil {
			at = float64(good.At.Unix())
		}
		m.Gauge("ways_backup_last_success_timestamp_seconds", "When the last nightly backup succeeded; 0 for never.", at)
	}
	size, err := c.store.Size(ctx)
	if err != nil {
		return err
	}
	m.Gauge("ways_db_size_bytes", "The database's size.", float64(size))
	pending, err := c.store.PendingAlerts(ctx)
	if err != nil {
		return err
	}
	m.Gauge("ways_alerts_undelivered", "Alerts no Exit has relayed to Telegram yet.", float64(len(pending)))

	// Expiry of the CA, the public certificate and API tokens.
	if c.ca != nil {
		m.Gauge("ways_ca_expiry_timestamp_seconds", "When the Coordinator's CA certificate expires.", float64(c.ca.NotAfter().Unix()))
	}
	if c.Monitor.PublicCertFile != "" {
		if notAfter, err := certExpiry(c.Monitor.PublicCertFile); err != nil {
			c.log.Warn("read the public TLS certificate", "err", err)
		} else {
			m.Gauge("ways_public_tls_expiry_timestamp_seconds", "When the public TLS certificate expires.", float64(notAfter.Unix()))
		}
	}
	tokens, revoked, err := c.store.APITokens(ctx)
	if err != nil {
		return err
	}
	for i, t := range tokens {
		if !revoked[i] && t.ExpiresAt.After(now) {
			m.Gauge("ways_api_token_expiry_timestamp_seconds", "When the API token expires.", float64(t.ExpiresAt.Unix()), "token", t.Name)
		}
	}
	return nil
}

func certExpiry(path string) (time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return time.Time{}, fmt.Errorf("%s: no PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// alertWebhook takes a group of alerts from Alertmanager and queues it for
// Telegram; the relay loop delivers it.
func (c *Coordinator) alertWebhook(w http.ResponseWriter, r *http.Request) {
	var hook monitoring.Webhook
	if !decode(w, r, &hook) {
		return
	}
	if text := hook.Text(); text != "" {
		if _, err := c.store.QueueAlert(r.Context(), text); err != nil {
			c.internalError(w, err)
			return
		}
		select {
		case c.mon.poke <- struct{}{}:
		default:
		}
	}
	w.WriteHeader(http.StatusOK)
}

// RunAlertRelay delivers queued alerts as they arrive, and retries those
// no Exit could take every RetryEvery, until ctx ends.
func (c *Coordinator) RunAlertRelay(ctx context.Context) {
	t := time.NewTicker(c.Monitor.RetryEvery)
	defer t.Stop()
	for {
		c.relayPending(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-c.mon.poke:
		}
	}
}

// relayPending tries every queued alert, oldest first. When one fails the
// rest would too, so they are counted as failed without waiting on the
// same timeouts again.
func (c *Coordinator) relayPending(ctx context.Context) {
	pending, err := c.store.PendingAlerts(ctx)
	if err != nil {
		c.log.Error("read queued alerts", "err", err)
		return
	}
	var failed error
	for _, a := range pending {
		if failed == nil {
			failed = c.relay(ctx, a.Text)
			if failed == nil {
				if err := c.store.AlertDelivered(ctx, a.ID); err != nil {
					c.log.Error("drop a relayed alert", "err", err)
				}
				continue
			}
			c.log.Warn("alert undeliverable", "err", failed)
		}
		if ctx.Err() != nil {
			return
		}
		if err := c.store.AlertFailed(ctx, a.ID, failed.Error()); err != nil {
			c.log.Error("count a failed alert", "err", err)
		}
	}
}

// relay hands text to the first healthy Exit that takes it: an Exit
// whose Agent reported recently, most recent first. No Exit is special.
func (c *Coordinator) relay(ctx context.Context, text string) error {
	if c.Monitor.Port == 0 || c.Monitor.Telegram.BotToken == "" || c.Monitor.Telegram.ChatID == "" {
		return errors.New("Telegram relay is not configured")
	}
	nodes, err := c.store.Nodes(ctx)
	if err != nil {
		return err
	}
	type exit struct {
		node store.Node
		h    *protocol.HealthStatus
	}
	var exits []exit
	now := c.store.Now()
	for _, n := range nodes {
		if !slices.Contains(n.Roles, protocol.RoleExit) {
			continue
		}
		h, err := c.store.Health(ctx, n.ID)
		if err != nil {
			return err
		}
		if h != nil && h.SeenAddr != "" && now.Sub(h.ReceivedAt) <= c.Address.ReportingWithin {
			exits = append(exits, exit{n, h})
		}
	}
	if len(exits) == 0 {
		return errors.New("no healthy Exit")
	}
	slices.SortStableFunc(exits, func(a, b exit) int { return b.h.ReceivedAt.Compare(a.h.ReceivedAt) })
	identity, err := c.relayIdentity()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(protocol.TelegramMessage{BotToken: c.Monitor.Telegram.BotToken, ChatID: c.Monitor.Telegram.ChatID, Text: text})
	var errs []error
	for _, e := range exits {
		err := c.relayVia(ctx, e.node, e.h.SeenAddr, identity, body)
		if err == nil {
			c.log.Info("alert relayed", "exit", e.node.Name)
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", e.node.Name, err))
	}
	return errors.Join(errs...)
}

func (c *Coordinator) relayVia(ctx context.Context, n store.Node, addr string, identity tls.Certificate, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, c.Monitor.RelayTimeout)
	defer cancel()
	dial := c.Monitor.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	tr := &http.Transport{
		DialContext: dial,
		// The Exit's certificate names its Node id.
		TLSClientConfig: &tls.Config{RootCAs: c.ca.Pool(), Certificates: []tls.Certificate{identity}, ServerName: n.ID, MinVersion: tls.VersionTLS13},
	}
	defer tr.CloseIdleConnections()
	url := "https://" + net.JoinHostPort(addr, strconv.Itoa(int(c.Monitor.Port))) + "/v1/telegram"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// relayIdentity is the Coordinator's client certificate for the Nodes'
// monitoring port, made once per start.
func (c *Coordinator) relayIdentity() (tls.Certificate, error) {
	c.mon.mu.Lock()
	defer c.mon.mu.Unlock()
	if c.mon.identity != nil {
		return *c.mon.identity, nil
	}
	certPEM, keyPEM, err := c.ca.IssueClient(ca.CoordinatorName, c.store.Now())
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	c.mon.identity = &cert
	return cert, nil
}

// UndeliveredAlerts are queued alerts that at least one attempt failed to
// relay, for the panel's banner.
func (c *Coordinator) UndeliveredAlerts(ctx context.Context) ([]protocol.UndeliveredAlert, error) {
	pending, err := c.store.PendingAlerts(ctx)
	if err != nil {
		return nil, err
	}
	out := []protocol.UndeliveredAlert{}
	for _, a := range pending {
		if a.Attempts > 0 {
			out = append(out, protocol.UndeliveredAlert{ID: a.ID, Text: a.Text, ReceivedAt: a.ReceivedAt, Attempts: a.Attempts, LastError: a.LastError})
		}
	}
	return out, nil
}

// WritePrometheusTLS writes Prometheus's client certificate, its key and
// the CA certificate into dir, unless a certificate there lasts another
// 30 days.
func (c *Coordinator) WritePrometheusTLS(dir string) error {
	certPath := filepath.Join(dir, "prometheus.crt")
	if notAfter, err := certExpiry(certPath); err == nil && notAfter.Sub(c.store.Now()) > 30*24*time.Hour {
		return nil
	}
	certPEM, keyPEM, err := c.ca.IssueClient(ca.PrometheusName, c.store.Now())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
		perm os.FileMode
	}{{"ca.crt", c.ca.CertPEM(), 0o644}, {"prometheus.key", keyPEM, 0o640}, {"prometheus.crt", certPEM, 0o644}} {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, f.perm); err != nil {
			return err
		}
	}
	c.log.Info("Prometheus client certificate written", "dir", dir)
	return nil
}
