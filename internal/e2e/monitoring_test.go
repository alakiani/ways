//go:build linux

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alakiani/ways/internal/ca"
	"github.com/alakiani/ways/internal/lab"
	"github.com/alakiani/ways/internal/monitoring"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/testutil"
)

// Where the lab's fake Telegram listens: an address in Telegram's own
// range, which the filter blocks from the Coordinator as Iran does.
const telegramAddr = "149.154.167.220"

// TestMonitoring is session 11's "proves in the lab" test: Prometheus
// finds every Agent through the Coordinator and scrapes it over the
// allowlisted mTLS port; the alerts the acceptance test relies on (Exit
// down, Link down, Bridge removed from the Bridge Address) fire and reach Telegram
// through a healthy Exit, never from the Coordinator itself; an alert no
// Exit can deliver waits on the panel's banner until one can.
func TestMonitoring(t *testing.T) {
	bin := binDir(t)
	prometheus, alertmanager := filepath.Join(bin, "prometheus"), filepath.Join(bin, "alertmanager")
	for _, b := range []string{prometheus, alertmanager} {
		if !testutil.Exists(b) {
			t.Fatalf("%s is missing: CI downloads the pinned Prometheus and Alertmanager into WAYS_BIN", b)
		}
	}
	if out, err := execCommand("modprobe", "wireguard"); err != nil {
		t.Fatalf("modprobe wireguard: %v: %s", err, out)
	}
	l := lab.StartSpecs(t,
		lab.Spec{Name: "coord"},
		lab.Spec{Name: "ir1"},
		lab.Spec{Name: "ir3"},
		lab.Spec{Name: "ab1"},
		lab.Spec{Name: "ab2"},
		lab.Spec{Name: "scanner"},
		lab.At("tg", telegramAddr),
		lab.At("dns-ab", "9.9.9.9"),
		lab.At("egress-ab", "1.0.0.10"),
		lab.At("egress-ir", "2.188.0.10"),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coordNode := l.Node("coord")
	co := startCoordinator(t, coordNode)
	co.c.Upstreams = []string{"9.9.9.9"}
	egressTargets(t, co, l.Node("egress-ab"), l.Node("egress-ir"))
	upstreamCA := serveEgress(t, l.Node("dns-ab"))
	dumpNetOnFailure(t, l, "ir1", "ab2")

	// Telegram, faked, and blocked from the Coordinator.
	tg := fakeTelegram(t, l.Node("tg"))
	l.Filter(lab.DropBetween(coordNode, l.Node("tg")))

	// Monitoring: the Agents' metrics port open to the Coordinator only,
	// alerts relayed to Telegram through an Exit.
	const port = 9443
	co.c.Monitor.Port = port
	co.c.Monitor.AllowFrom = []string{coordNode.Addr().String()}
	co.c.Monitor.Telegram.BotToken, co.c.Monitor.Telegram.ChatID = "lab-bot-token", "-100123"
	co.c.Monitor.Dial = nsDial(coordNode)
	co.c.Monitor.RetryEvery = time.Second
	co.c.Address.ProbeEvery = 2 * time.Second
	co.c.Address.RemoveAfter, co.c.Address.RejoinAfter = 4*time.Second, 4*time.Second
	co.c.Address.ProbeHostname = "check.abroad"
	co.c.Address.Enter = coordNode.Do
	if err := co.c.InitProbe(ctx); err != nil {
		t.Fatal(err)
	}

	// The Coordinator's internal listener, on the VM's loopback, serves
	// Prometheus its targets and the Coordinator's metrics, and takes
	// Alertmanager's webhook.
	const internal = "127.0.0.1:9101"
	var ln net.Listener
	if err := coordNode.Do(func() (err error) { ln, err = net.Listen("tcp", internal); return err }); err != nil {
		t.Fatal(err)
	}
	isrv := &http.Server{Handler: co.c.InternalHandler()}
	go isrv.Serve(ln)
	t.Cleanup(func() { isrv.Close() })
	go co.c.RunAlertRelay(ctx)

	// Prometheus and Alertmanager, as the playbook installs them, with the
	// alert table's durations shortened.
	dir := t.TempDir()
	tlsDir := filepath.Join(dir, "tls")
	if err := co.c.WritePrometheusTLS(tlsDir); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(dir, "rules.yml")
	writeFile(t, rules, monitoring.Rules(monitoring.LabTiming))
	promConfig := filepath.Join(dir, "prometheus.yml")
	writeFile(t, promConfig, monitoring.Prometheus(monitoring.PrometheusConfig{
		Internal: internal, Alertmanager: "127.0.0.1:9093", TLSDir: tlsDir, RuleFiles: []string{rules},
		Interval: time.Second, SDRefresh: 2 * time.Second,
	}))
	amConfig := filepath.Join(dir, "alertmanager.yml")
	writeFile(t, amConfig, monitoring.Alertmanager(monitoring.AlertmanagerConfig{
		Webhook: "http://" + internal + "/v1/alerts", GroupWait: time.Second, GroupInterval: 2 * time.Second, RepeatInterval: time.Hour,
	}))
	daemon(t, coordNode, "alertmanager", alertmanager, "--config.file="+amConfig, "--storage.path="+filepath.Join(dir, "am"),
		"--web.listen-address=127.0.0.1:9093", "--cluster.listen-address=")
	daemon(t, coordNode, "prometheus", prometheus, "--config.file="+promConfig, "--storage.tsdb.path="+filepath.Join(dir, "tsdb"),
		"--web.listen-address=127.0.0.1:9090")
	prom := &promAPI{t: t, client: &http.Client{Transport: &http.Transport{DialContext: nsDial(coordNode)}, Timeout: 5 * time.Second}}

	m := &mesh{t: t, l: l, co: co, ids: map[string]string{}, agents: map[string]*agentProc{},
		agentArgs: []string{"-telegram-api", "http://" + telegramAddr, "-node-exporter", "", "-upstream-ca", upstreamCA}}
	m.startAgent("ir1", []protocol.Role{protocol.RoleBridge}, []string{"IR"})
	m.startAgent("ir3", []protocol.Role{protocol.RoleBridge}, []string{"IR"})
	m.startAgent("ab1", []protocol.Role{protocol.RoleExit}, nil)
	m.startAgent("ab2", []protocol.Role{protocol.RoleExit}, nil)
	const defaultRule = 2
	for _, b := range []string{"ir1", "ir3"} {
		testutil.Eventually(t, 120*time.Second, b+" has a direct default-Rule Path", func() bool {
			return m.ruleHealth(b, defaultRule).Mode == "direct"
		})
	}
	go co.c.RunBridgeAddress(ctx)

	// Prometheus scrapes every Agent, found through the Coordinator.
	nodes := []string{"ab1", "ab2", "ir1", "ir3"}
	testutil.Eventually(t, 90*time.Second, "Prometheus scrapes every Agent", func() bool {
		up := prom.series(`up{job="agents"} == 1`, "node")
		return slices.Equal(up, nodes)
	})
	testutil.Eventually(t, 30*time.Second, "Link and Path metrics from the Agents", func() bool {
		return len(prom.series(`ways_link_up == 1`, "node")) > 0 &&
			slices.Equal(prom.series(`ways_path_ok{default="true"} == 1`, "node"), []string{"ir1", "ir3"}) &&
			len(prom.series(`ways_coordinator_last_contact_seconds < 30`, "node")) == len(nodes)
	})
	testutil.Eventually(t, 60*time.Second, "both Bridges are eligible and in the Bridge Address", func() bool {
		return slices.Equal(prom.series(`ways_bridge_eligible == 1`, "node"), []string{"ir1", "ir3"}) &&
			slices.Equal(prom.series(`ways_bridge_address_member == 1`, "node"), []string{"ir1", "ir3"})
	})
	for _, q := range monitoring.MeshDashboardQueries() {
		prom.mustParse(q)
	}

	// The metrics port is silent to anyone but the Coordinator, and the
	// Coordinator's host still needs a client certificate.
	ir1 := net.JoinHostPort(l.Node("ir1").Addr().String(), fmt.Sprint(port))
	err := l.Node("scanner").Do(func() error {
		c, err := net.DialTimeout("tcp", ir1, 2*time.Second)
		if err == nil {
			c.Close()
			return fmt.Errorf("a scanner connected to %s", ir1)
		}
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			return fmt.Errorf("a scanner got %v from %s, want silence", err, ir1)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
	noCert := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: nsDial(coordNode),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if resp, err := noCert.Get("https://" + ir1 + "/metrics"); err == nil {
		resp.Body.Close()
		t.Errorf("GET /metrics without a client certificate: %s", resp.Status)
	}

	// Telegram is down for everyone, and ab1 dies. Its alert cannot be
	// delivered, so it waits on the panel's banner.
	// (Alerts may have fired while the mesh came up, such as LinkDown
	// before a Link's first handshake; they went out through either Exit.)
	tgDown := l.Filter(lab.DropAll(l.Node("tg")))
	before := tg.count()
	l.Filter(lab.DropAll(l.Node("ab1")))
	killed := time.Now()
	testutil.Eventually(t, 90*time.Second, "the undeliverable NodeUnreachable alert is on the banner", func() bool {
		alerts, err := co.c.UndeliveredAlerts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(alerts, func(a protocol.UndeliveredAlert) bool {
			return strings.Contains(a.Text, "NodeUnreachable") && strings.Contains(a.Text, "ab1")
		})
	})
	t.Logf("NodeUnreachable for ab1 raised %v after it died", time.Since(killed).Round(time.Second))
	if n := tg.count() - before; n != 0 {
		t.Errorf("Telegram got %d messages while it was down", n)
	}

	// Telegram returns: the alert goes out through ab2, the only healthy
	// Exit, and the banner clears.
	tgDown.Remove()
	ab2 := l.Node("ab2").Addr().String()
	tg.await(t, 60*time.Second, "NodeUnreachable", "ab1", ab2)
	testutil.Eventually(t, 30*time.Second, "the banner clears", func() bool {
		alerts, _ := co.c.UndeliveredAlerts(ctx)
		return len(alerts) == 0
	})

	// Block the Link between ir1 and ab2: Link down.
	l.Filter(lab.DropBetween(l.Node("ir1"), l.Node("ab2")))
	tg.await(t, 90*time.Second, "LinkDown", "ab2/ir1", ab2)
	// Every instance of it is down, as both ends see it: a blackout of the
	// whole path, not one transport failing (issue #51).
	var transports []string
	for _, in := range m.instances(m.linkID("ir1", "ab2")) {
		transports = append(transports, string(in.Transport))
	}
	slices.Sort(transports)
	transports = slices.Compact(transports)
	testutil.Eventually(t, 30*time.Second, "every instance of ab2/ir1 is down on both ends", func() bool {
		down := slices.Compact(prom.series(`ways_link_instance_up{link="ab2/ir1",node="ir1"} == 0`, "transport"))
		ends := slices.Compact(prom.series(`ways_link_instance_up{link="ab2/ir1"} == 0`, "node"))
		up := prom.series(`ways_link_instance_up{link="ab2/ir1"} == 1`, "instance_id")
		return len(transports) > 1 && slices.Equal(down, transports) && slices.Equal(ends, []string{"ab2", "ir1"}) && len(up) == 0
	})
	// A Link left alone still has an instance Up.
	if up := prom.series(`ways_link_instance_up{link="ab2/ir3"} == 1`, "node"); len(up) == 0 {
		t.Errorf("no instance of ab2/ir3 is Up")
	}

	// Kill ir3, a Bridge: it leaves the Bridge Address, which is down to
	// ir1 alone.
	l.Filter(lab.DropAll(l.Node("ir3")))
	tg.await(t, 90*time.Second, "BridgeRemovedFromBridgeAddress", "ir3", ab2)
	tg.await(t, 60*time.Second, "BridgeAddressDownToOneBridge", "", ab2)
	if in := prom.series(`ways_bridge_address_member == 1`, "node"); !slices.Equal(in, []string{"ir1"}) {
		t.Errorf("the Bridge Address holds %v, want ir1 alone", in)
	}

	// Every message came through an Exit, never from the Coordinator, and
	// once ab1 died, through ab2.
	for i, m := range tg.all() {
		if m.from != ab2 && (i >= before || m.from != l.Node("ab1").Addr().String()) {
			t.Errorf("a Telegram message came from %s: %q", m.from, m.text)
		}
		if m.chat != "-100123" || m.token != "lab-bot-token" {
			t.Errorf("a Telegram message went to chat %q with token %q", m.chat, m.token)
		}
	}
}

// fakeTelegram serves Telegram's Bot API sendMessage on n, port 80.
func fakeTelegram(t *testing.T, n *lab.Node) *telegram {
	t.Helper()
	tg := &telegram{}
	var ln net.Listener
	if err := n.Do(func() (err error) { ln, err = net.Listen("tcp", net.JoinHostPort(n.Addr().String(), "80")); return err }); err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/bot"), "/sendMessage")
		var body struct {
			ChatID string `json:"chat_id"`
			Text   string `json:"text"`
		}
		if !ok || r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, `{"ok":false}`, http.StatusBadRequest)
			return
		}
		from, _, _ := net.SplitHostPort(r.RemoteAddr)
		tg.mu.Lock()
		tg.msgs = append(tg.msgs, tgMessage{from: from, token: token, chat: body.ChatID, text: body.Text})
		tg.mu.Unlock()
		io.WriteString(w, `{"ok":true}`)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		if t.Failed() {
			for _, m := range tg.all() {
				t.Logf("telegram from %s:\n%s", m.from, m.text)
			}
		}
	})
	return tg
}

type telegram struct {
	mu   sync.Mutex
	msgs []tgMessage
}

type tgMessage struct{ from, token, chat, text string }

func (tg *telegram) all() []tgMessage {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return slices.Clone(tg.msgs)
}

func (tg *telegram) count() int { return len(tg.all()) }

// await waits for a message that fires alert about subject, sent from addr.
func (tg *telegram) await(t *testing.T, timeout time.Duration, alert, subject, from string) {
	t.Helper()
	start := time.Now()
	testutil.Eventually(t, timeout, alert+" for "+subject+" reaches Telegram", func() bool {
		return slices.ContainsFunc(tg.all(), func(m tgMessage) bool {
			return m.from == from && strings.Contains(m.text, "FIRING") && strings.Contains(m.text, alert) && strings.Contains(m.text, subject)
		})
	})
	t.Logf("%s for %s reached Telegram after %v", alert, subject, time.Since(start).Round(time.Second))
}

// nsDial dials from inside a lab Node's namespace.
func nsDial(n *lab.Node) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (c net.Conn, err error) {
		err = n.Do(func() error {
			c, err = (&net.Dialer{}).DialContext(ctx, network, addr)
			return err
		})
		return c, err
	}
}

// daemon runs a program in a lab Node until the test ends, logging to a
// file shown if the test fails.
func daemon(t *testing.T, n *lab.Node, name, bin string, args ...string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), name+".log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := n.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	dumpOnFailure(t, name, logPath)
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// promAPI queries the lab's Prometheus.
type promAPI struct {
	t      *testing.T
	client *http.Client
}

type promResult struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
	Data      struct {
		Result []struct {
			Metric map[string]string `json:"metric"`
		} `json:"result"`
	} `json:"data"`
}

func (p *promAPI) query(q string) (promResult, error) {
	var r promResult
	resp, err := p.client.Get("http://127.0.0.1:9090/api/v1/query?query=" + url.QueryEscape(q))
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()
	return r, json.NewDecoder(resp.Body).Decode(&r)
}

// series returns the sorted values of label across a query's series, or
// nil if the query fails.
func (p *promAPI) series(q, label string) []string {
	r, err := p.query(q)
	if err != nil || r.Status != "success" {
		return nil
	}
	var out []string
	for _, s := range r.Data.Result {
		out = append(out, s.Metric[label])
	}
	slices.Sort(out)
	return out
}

// scraper reads Agents' /metrics as Prometheus does, from the Coordinator's
// Node with Prometheus's client certificate, for tests that run no
// Prometheus.
type scraper struct {
	client *http.Client
	port   uint16
}

func newScraper(t *testing.T, co *coord, from *lab.Node, port uint16) *scraper {
	t.Helper()
	dir := t.TempDir()
	if err := co.c.WritePrometheusTLS(dir); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "prometheus.crt"), filepath.Join(dir, "prometheus.key"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(co.caPEM)
	tc := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, ServerName: ca.AgentServerName}
	return &scraper{port: port, client: &http.Client{Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: nsDial(from), TLSClientConfig: tc}}}
}

// samples scrapes n and returns each series' value, keyed by the series as
// the Agent writes it: name{labels}.
func (s *scraper) samples(n *lab.Node) (map[string]float64, error) {
	resp, err := s.client.Get("https://" + net.JoinHostPort(n.Addr().String(), fmt.Sprint(s.port)) + "/metrics")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scrape %s: %s %v", n.Name(), resp.Status, err)
	}
	out := map[string]float64{}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if v, err := strconv.ParseFloat(line[i+1:], 64); err == nil {
			out[line[:i]] = v
		}
	}
	return out, nil
}

// mustParse fails the test unless Prometheus accepts q.
func (p *promAPI) mustParse(q string) {
	p.t.Helper()
	r, err := p.query(q)
	if err != nil {
		p.t.Fatal(err)
	}
	if r.Status != "success" {
		p.t.Errorf("dashboard query %q: %s: %s", q, r.ErrorType, r.Error)
	}
}
