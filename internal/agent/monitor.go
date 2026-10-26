package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alakiani/ways/internal/ca"
	"github.com/alakiani/ways/internal/metrics"
	"github.com/alakiani/ways/internal/protocol"
)

// MetricsWriter is implemented by an Applier with metrics of its own, such
// as the data plane's active Device count.
type MetricsWriter interface {
	WriteMetrics(w *metrics.Writer)
}

func (as Appliers) WriteMetrics(w *metrics.Writer) {
	for _, a := range as {
		if m, ok := a.(MetricsWriter); ok {
			m.WriteMetrics(w)
		}
	}
}

// DefaultTelegramAPI is where Exits send alerts on to.
const DefaultTelegramAPI = "https://api.telegram.org"

// monitor is the Node's one monitoring port (ADR 0006), open while the
// snapshot asks for it: Prometheus reads /metrics, and the Coordinator
// hands alerts to /v1/telegram. Both callers need a client certificate
// from the Coordinator's CA naming them; nftables keeps everyone but the
// Coordinator VM from reaching the port at all.
type monitor struct {
	a *agent

	mu   sync.Mutex
	cert *tls.Certificate
	want *protocol.Monitor
	port uint16 // where srv listens; 0 when shut
	srv  *http.Server
}

// set takes the snapshot's wish for the port.
func (m *monitor) set(want *protocol.Monitor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.want = want
	m.reconcile()
}

// useCert gives the port the Node's certificate, which serves it.
func (m *monitor) useCert(c tls.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cert = &c
	m.reconcile()
}

// retry opens the port if an earlier attempt failed.
func (m *monitor) retry() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcile()
}

func (m *monitor) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.want = nil
	m.reconcile()
}

func (m *monitor) certificate() *tls.Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cert
}

// reconcile opens, moves or shuts the port. Call with mu held.
func (m *monitor) reconcile() {
	var port uint16
	if m.want != nil && m.cert != nil {
		port = m.want.Port
	}
	if port == m.port {
		return
	}
	if m.srv != nil {
		m.srv.Close()
		m.srv, m.port = nil, 0
	}
	if port == 0 {
		return
	}
	addr := net.JoinHostPort(m.a.cfg.MetricsHost, strconv.Itoa(int(port)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		m.a.log.Error("open monitoring port", "addr", addr, "err", err)
		return
	}
	tc := &tls.Config{
		Certificates: []tls.Certificate{*m.cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    m.a.pool,
		MinVersion:   tls.VersionTLS13,
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", only(ca.PrometheusName, m.a.serveMetrics))
	mux.Handle("POST /v1/telegram", only(ca.CoordinatorName, m.a.relayTelegram))
	m.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	m.port = port
	go m.srv.Serve(tls.NewListener(ln, tc))
	m.a.log.Info("monitoring port open", "addr", addr)
}

// only admits the client certificate named name.
func only(name string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.TLS.VerifiedChains[0][0].Subject.CommonName != name {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// serveMetrics answers a scrape. The figures are the ones the health
// report carries, labelled by name; Prometheus adds the Node's own name.
// No label names a Device.
func (a *agent) serveMetrics(w http.ResponseWriter, r *http.Request) {
	var h protocol.Health
	if rep, ok := a.cfg.Applier.(Reporter); ok {
		rep.Report(r.Context(), &h)
	}
	a.mu.Lock()
	st, current, lastContact, failures := a.state, a.current, a.lastContact, a.applyFailures
	a.mu.Unlock()
	if st == nil {
		st = &protocol.State{}
	}
	now := time.Now()

	var m metrics.Writer
	m.Gauge("ways_agent_info", "The Agent's version.", 1, "version", a.cfg.Version)
	m.Gauge("ways_snapshot_applied_version", "The snapshot version in effect.", float64(current))
	m.Gauge("ways_coordinator_last_contact_seconds", "Seconds since the Agent last reached the Coordinator, or since it started.",
		now.Sub(lastContact).Seconds())
	m.Counter("ways_snapshot_apply_failures_total", "Snapshots reverted because they cut contact with the Coordinator.", float64(failures))
	if c := a.mon.certificate(); c != nil && c.Leaf != nil {
		m.Gauge("ways_client_cert_expiry_timestamp_seconds", "When the Node's certificate expires.", float64(c.Leaf.NotAfter.Unix()))
	}

	// Links, labelled by their two Nodes.
	peers := map[uint64]string{}
	for _, l := range st.Links {
		peers[l.ID] = l.Peer.Name
	}
	peerName := func(id uint64) string {
		if p := peers[id]; p != "" {
			return p
		}
		return fmt.Sprintf("link %d", id)
	}
	for _, lh := range h.Links {
		labels := metrics.LinkLabels(lh.LinkID, st.Node.Name, peers[lh.LinkID])
		m.Bool("ways_link_up", "1 while the Link has a working transport.", lh.Up, labels...)
		m.Gauge("ways_link_rtt_seconds", "Round-trip time over the Link's active instance.", lh.RTTMillis/1000, labels...)
		m.Gauge("ways_link_loss_ratio", "Probe loss over the last 30 s on the active instance.", lh.Loss, labels...)
		if lh.Transport != "" {
			m.Gauge("ways_link_transport", "The transport carrying the Link.", 1, append(labels, "transport", string(lh.Transport))...)
		}
	}

	// Paths, per Rule (ADR 0008).
	if st.Bridge != nil {
		rules := map[uint64]string{}
		var defaultRule uint64
		for _, r := range st.Bridge.AllRules() {
			rules[r.ID], defaultRule = r.Name, r.ID
		}
		for _, rh := range h.Paths {
			labels := []string{"rule_id", strconv.FormatUint(rh.RuleID, 10), "rule", rules[rh.RuleID], "default", strconv.FormatBool(rh.RuleID == defaultRule)}
			m.Bool("ways_path_ok", "1 while the Rule has a Path of its own, direct, local or transit.",
				rh.Mode != "" && rh.Mode != "fallback", labels...)
			m.Gauge("ways_path_eligible_candidates", "Eligible candidates for the Rule.", float64(rh.Eligible), labels...)
			for _, key := range slices.Sorted(maps.Keys(rh.Shares)) {
				cand := key
				if id, ok := strings.CutPrefix(key, "link:"); ok {
					n, _ := strconv.ParseUint(id, 10, 64)
					cand = peerName(n)
				}
				m.Gauge("ways_path_buckets", "Buckets of the Rule's Device traffic on each candidate.", float64(rh.Shares[key]),
					append(labels, "candidate", cand)...)
			}
		}
		// Metering backlog: how long ago the oldest unacknowledged hour ended.
		backlog := 0.0
		for _, u := range h.Usage {
			if age := now.Sub(time.Unix(u.Hour, 0).Add(time.Hour)).Seconds(); age > backlog {
				backlog = age
			}
		}
		m.Gauge("ways_metering_backlog_seconds", "Age of the oldest hour of metering the Coordinator has not acknowledged.", backlog)
	}
	if mw, ok := a.cfg.Applier.(MetricsWriter); ok {
		mw.WriteMetrics(&m)
	}

	// Host metrics, from node_exporter on localhost, so the Node keeps one port.
	if a.cfg.NodeExporter != "" {
		body, err := a.nodeExporter(r.Context())
		m.Bool("ways_node_exporter_up", "1 when node_exporter answered.", err == nil)
		if err == nil {
			m.Raw(body)
		}
	}
	m.Serve(w)
}

func (a *agent) nodeExporter(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.NodeExporter, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("node_exporter: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

// relayTelegram sends the Coordinator's alert on to Telegram.
func (a *agent) relayTelegram(w http.ResponseWriter, r *http.Request) {
	var msg protocol.TelegramMessage
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&msg); err != nil || msg.BotToken == "" || msg.ChatID == "" {
		http.Error(w, "want a bot token, a chat id and text", http.StatusBadRequest)
		return
	}
	if err := a.sendTelegram(r.Context(), msg); err != nil {
		a.log.Warn("relay alert to Telegram", "err", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *agent) sendTelegram(ctx context.Context, msg protocol.TelegramMessage) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"chat_id": msg.ChatID, "text": msg.Text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.TelegramAPI+"/bot"+url.PathEscape(msg.BotToken)+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("telegram: bad request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// The URL holds the bot token: report only what went wrong.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("telegram: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("telegram: %s", resp.Status)
	}
	return nil
}
