// Package coordinator serves the Coordinator's two listeners (ADR 0001,
// ADR 0002):
//
//   - the Admin API, for callers holding a scoped API token, such as the
//     laptop's enroll playbook with a nodes:enroll token;
//   - the Agent API, on its own TLS listener whose server certificate comes
//     from the Coordinator's CA. Enrollment needs no client certificate;
//     every other Agent call needs the Node's current one.
package coordinator

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alakiani/ways/internal/ca"
	"github.com/alakiani/ways/internal/irfeed"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// EnrollmentTokenTTL is how long an enrollment token stays valid (ADR 0002).
const EnrollmentTokenTTL = time.Hour

// Coordinator holds the store and CA and serves both APIs.
type Coordinator struct {
	store *store.Store
	ca    *ca.CA
	log   *slog.Logger

	// LongPoll is how long GET /v1/state waits for a newer version before
	// answering 204 No Content.
	LongPoll time.Duration
	// LinkTiming is pushed to every Agent; ReplaceAfterSeconds is also when
	// the Coordinator replaces an instance that stays down.
	LinkTiming protocol.LinkTiming
	// Egress is what Exits check for egress OK.
	Egress EgressTargets
	// Upstreams are the resolvers abroad Bridges forward DNS to.
	Upstreams []string
	// Scoring is pushed to every Bridge (ADR 0008).
	Scoring protocol.Scoring
	// PanelURL is where the panel is served; Invite links point into it.
	PanelURL string
	// BridgeAddress is the hostname in Device configs (ADR 0011).
	BridgeAddress string
	// DNS sets the Bridge Address's record; nil leaves it alone.
	DNS AddressDNS
	// Address holds the Bridge Address's timings and the probe's settings.
	Address AddressSettings
	// SecureCookies marks session cookies Secure; off only for plain-HTTP
	// development.
	SecureCookies bool
	// Monitor is the Coordinator's part in monitoring (ADR 0006).
	Monitor MonitorSettings
	// Backup configures the nightly backup (ADR 0001).
	Backup BackupSettings
	// GrafanaURL is Grafana on the VM's loopback; Admins reach it through
	// the panel at /grafana/ (ADR 0006). Empty leaves /grafana/ shut.
	GrafanaURL string

	limit limiter // failed sign-ins
	// FeedURL and RIPEstatURL are where the IR feed and its cross-check
	// come from; HTTPClient fetches them.
	FeedURL, RIPEstatURL string
	HTTPClient           *http.Client

	reconcileMu sync.Mutex // one Reconcile at a time
	quotaMu     sync.Mutex
	quotaSeen   map[string]quotaState // the Users out of Quota in the latest snapshots
	address     addressState
	mon         monitorState

	mu      sync.Mutex
	changed chan struct{} // closed and replaced whenever a snapshot changes
}

// New returns a Coordinator over s and c.
func New(s *store.Store, c *ca.CA, log *slog.Logger) *Coordinator {
	return &Coordinator{store: s, ca: c, log: log, LongPoll: 60 * time.Second,
		LinkTiming: protocol.DefaultLinkTiming, Egress: DefaultEgressTargets, Upstreams: DefaultUpstreams, Scoring: protocol.DefaultScoring,
		PanelURL: "https://wayfinder.ir", BridgeAddress: DefaultBridgeAddress, Address: DefaultAddressSettings, SecureCookies: true,
		Monitor: DefaultMonitorSettings, Backup: DefaultBackupSettings, mon: monitorState{poke: make(chan struct{}, 1)},
		FeedURL: irfeed.DefaultURL, RIPEstatURL: irfeed.DefaultRIPEstatURL, HTTPClient: http.DefaultClient,
		address: addressState{probes: map[string]protocol.ProbeResult{}, inelSince: map[string]time.Time{}, elSince: map[string]time.Time{},
			reasons: map[string][]string{}},
		changed: make(chan struct{})}
}

// Reconcile derives the mesh's Links, works out every Node's desired state,
// and stores a new snapshot version for each Node whose state changed. It is
// safe to run any number of times.
func (c *Coordinator) Reconcile(ctx context.Context) error {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	nodes, err := c.store.Nodes(ctx)
	if err != nil {
		return err
	}
	if err := c.deriveLinks(ctx, nodes); err != nil {
		return fmt.Errorf("derive links: %w", err)
	}
	mesh, err := c.loadMesh(ctx, nodes)
	if err != nil {
		return err
	}
	quota, err := c.quotaStates(ctx)
	if err != nil {
		return fmt.Errorf("quota states: %w", err)
	}
	if mesh.bridge, err = c.bridgeState(ctx, quota); err != nil {
		return fmt.Errorf("bridge state: %w", err)
	}
	changed := false
	for _, n := range nodes {
		body, err := json.Marshal(c.desiredState(n, mesh))
		if err != nil {
			return err
		}
		version, isNew, err := c.store.PutSnapshot(ctx, n.ID, body)
		if err != nil {
			return fmt.Errorf("snapshot for %s: %w", n.Name, err)
		}
		if isNew {
			c.log.Info("new snapshot", "node", n.Name, "version", version)
			changed = true
		}
	}
	c.quotaMu.Lock()
	c.quotaSeen = quota
	c.quotaMu.Unlock()
	if changed {
		c.mu.Lock()
		close(c.changed)
		c.changed = make(chan struct{})
		c.mu.Unlock()
	}
	return nil
}

// desiredState is everything a Node is told. Later sessions add Devices,
// Rules and Path scoring here, filtered by the Node's Roles.
func (c *Coordinator) desiredState(n store.Node, mesh meshView) protocol.State {
	st := protocol.State{
		Node:       protocol.NodeInfo{ID: n.ID, Name: n.Name, Roles: n.Roles, Tags: n.Tags},
		Links:      linksFor(n, mesh),
		LinkTiming: c.LinkTiming,
		Monitor:    c.monitorState(n),
	}
	if isBridge(n) {
		st.Bridge = mesh.bridge
	}
	if slices.Contains(n.Roles, protocol.RoleExit) {
		check := c.Egress.Abroad
		if isIR(n) {
			check = c.Egress.IR
		}
		st.EgressCheck = &check
	}
	return st
}

// UpdateNode replaces a Node's Roles and Tags and reconciles.
func (c *Coordinator) UpdateNode(ctx context.Context, id string, roles []protocol.Role, tags []string) error {
	if err := c.store.UpdateNode(ctx, id, normalize(roles), normalize(tags)); err != nil {
		return err
	}
	return c.Reconcile(ctx)
}

func (c *Coordinator) waitChan() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.changed
}

// AgentHandler serves the Agent API. It must sit behind the TLS config from
// AgentTLSConfig.
func (c *Coordinator) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", c.enroll)
	mux.Handle("GET /v1/state", c.requireNode(c.state))
	mux.Handle("POST /v1/health", c.requireNode(c.health))
	mux.Handle("GET /v1/sets/{hash}", c.requireNode(c.setBlob))
	return mux
}

// AgentTLSConfig is the Agent listener's TLS config: a server certificate
// from the CA for hosts, and client certificates verified against the CA
// when given.
func (c *Coordinator) AgentTLSConfig(hosts []string) (*tls.Config, error) {
	cert, err := c.ca.ServerCert(hosts, c.store.Now())
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    c.ca.Pool(),
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func (c *Coordinator) requireScope(scope string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		if _, err := c.store.CheckAPIToken(r.Context(), secret, scope); err != nil {
			if errors.Is(err, store.ErrInvalidToken) {
				writeError(w, http.StatusUnauthorized, err.Error())
			} else {
				c.internalError(w, err)
			}
			return
		}
		next(w, r)
	})
}

type nodeKey struct{}

// requireNode admits a caller presenting the current client certificate of
// an existing Node.
func (c *Coordinator) requireNode(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			writeError(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		n, err := c.store.Node(r.Context(), leaf.Subject.CommonName)
		if errors.Is(err, store.ErrNotFound) || err == nil && n.CertSerial != ca.Serial(leaf) {
			writeError(w, http.StatusForbidden, "certificate is not this Node's current one")
			return
		}
		if err != nil {
			c.internalError(w, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), nodeKey{}, n)))
	})
}

func nodeFrom(r *http.Request) store.Node { return r.Context().Value(nodeKey{}).(store.Node) }

func (c *Coordinator) createNode(w http.ResponseWriter, r *http.Request) {
	var req protocol.CreateNodeRequest
	if !decode(w, r, &req) {
		return
	}
	if resp, ok := c.ensureNode(w, r, req); ok {
		writeJSON(w, http.StatusOK, resp)
	}
}

// ensureNode creates a Node, or finds the one by that name, and mints an
// enrollment token unless it already enrolled and no re-enrollment was
// asked for. It answers errors itself and reports whether it succeeded.
func (c *Coordinator) ensureNode(w http.ResponseWriter, r *http.Request, req protocol.CreateNodeRequest) (protocol.CreateNodeResponse, bool) {
	req.Roles, req.Tags = normalize(req.Roles), normalize(req.Tags)
	if req.Name == "" || len(req.Roles) == 0 {
		writeError(w, http.StatusBadRequest, "name and at least one role are required")
		return protocol.CreateNodeResponse{}, false
	}
	for _, role := range req.Roles {
		if !role.Valid() {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown role %q", role))
			return protocol.CreateNodeResponse{}, false
		}
	}

	ctx := r.Context()
	n, err := c.store.NodeByName(ctx, req.Name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if n, err = c.store.CreateNode(ctx, req.Name, req.Roles, req.Tags); err == nil {
			err = c.Reconcile(ctx)
		}
		if err != nil {
			c.internalError(w, err)
			return protocol.CreateNodeResponse{}, false
		}
	case err != nil:
		c.internalError(w, err)
		return protocol.CreateNodeResponse{}, false
	case !slices.Equal(n.Roles, req.Roles) || !slices.Equal(n.Tags, req.Tags):
		// Rerunning the playbook must not silently change a live Node.
		writeError(w, http.StatusConflict, fmt.Sprintf("node %q exists with roles %v and tags %v", n.Name, n.Roles, n.Tags))
		return protocol.CreateNodeResponse{}, false
	}

	resp := protocol.CreateNodeResponse{Node: c.nodeStatus(ctx, n)}
	if !n.Enrolled() || req.Reenroll {
		token, expires, err := c.store.MintEnrollmentToken(ctx, n.ID, EnrollmentTokenTTL)
		if err != nil {
			c.internalError(w, err)
			return protocol.CreateNodeResponse{}, false
		}
		resp.EnrollmentToken, resp.TokenExpiresAt = token, &expires
	}
	return resp, true
}

func (c *Coordinator) getNode(w http.ResponseWriter, r *http.Request) {
	n, err := c.store.Node(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such node")
		return
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c.nodeStatus(r.Context(), n))
}

func (c *Coordinator) nodeStatus(ctx context.Context, n store.Node) protocol.NodeStatus {
	s := protocol.NodeStatus{ID: n.ID, Name: n.Name, Roles: n.Roles, Tags: n.Tags, Enrolled: n.Enrolled()}
	h, err := c.store.Health(ctx, n.ID)
	if err != nil {
		c.log.Error("read health", "node", n.Name, "err", err)
	}
	s.LastHealth = h
	return s
}

// csrError marks a signing failure caused by the caller's CSR.
type csrError struct{ error }

func (c *Coordinator) enroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollRequest
	if !decode(w, r, &req) {
		return
	}
	var certPEM []byte
	nodeID, err := c.store.Enroll(r.Context(), req.Token, func(nodeID string) (string, error) {
		var serial string
		var err error
		certPEM, serial, err = c.ca.SignClient([]byte(req.CSR), nodeID, c.store.Now())
		if err != nil {
			return "", csrError{err}
		}
		return serial, nil
	})
	var bad csrError
	switch {
	case errors.Is(err, store.ErrInvalidToken):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.As(err, &bad):
		writeError(w, http.StatusBadRequest, bad.Error())
	case err != nil:
		c.internalError(w, err)
	default:
		c.log.Info("node enrolled", "node", nodeID)
		writeJSON(w, http.StatusOK, protocol.EnrollResponse{NodeID: nodeID, Certificate: string(certPEM)})
	}
}

// state is the long-poll: it answers as soon as the Node's latest snapshot
// differs from the version it holds, unless that version is marked bad.
func (c *Coordinator) state(w http.ResponseWriter, r *http.Request) {
	n := nodeFrom(r)
	after, err := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	if err != nil && r.URL.Query().Has("after") {
		writeError(w, http.StatusBadRequest, "after must be a version number")
		return
	}
	timeout := time.NewTimer(c.LongPoll)
	defer timeout.Stop()
	for {
		wait := c.waitChan() // taken before reading, so no change is missed
		snap, err := c.store.LatestSnapshot(r.Context(), n.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			c.internalError(w, err)
			return
		}
		// Versions are compared for difference, not order, so a Coordinator
		// restored from an older backup still reaches its Agents.
		if err == nil && !snap.Bad && snap.Version != after {
			writeJSON(w, http.StatusOK, struct {
				Version uint64          `json:"version"`
				State   json.RawMessage `json:"state"`
			}{snap.Version, snap.Body})
			return
		}
		select {
		case <-wait:
		case <-timeout.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (c *Coordinator) health(w http.ResponseWriter, r *http.Request) {
	n := nodeFrom(r)
	var h protocol.Health
	if !decode(w, r, &h) {
		return
	}
	seen, _, _ := net.SplitHostPort(r.RemoteAddr)
	prev, err := c.store.Health(r.Context(), n.ID)
	if err != nil {
		c.internalError(w, err)
		return
	}
	if err := c.store.PutHealth(r.Context(), n.ID, h, seen); err != nil {
		c.internalError(w, err)
		return
	}
	// A new public address changes the endpoint the Node's peers dial.
	changed := prev == nil || prev.SeenAddr != seen
	// Metering comes from Bridges only (ADR 0002). The Quota is checked as
	// usage arrives (ADR 0010).
	if len(h.Usage) > 0 && isBridge(n) {
		if _, err := c.store.PutUsage(r.Context(), n.ID, h.Usage); err != nil {
			c.internalError(w, err)
			return
		}
		quotaChanged, err := c.quotaChanged(r.Context())
		if err != nil {
			c.internalError(w, err)
			return
		}
		changed = changed || quotaChanged
	}
	linksChanged, err := c.takeLinkHealth(r.Context(), n, h)
	if err != nil {
		c.internalError(w, err)
		return
	}
	if changed || linksChanged {
		if err := c.Reconcile(r.Context()); err != nil {
			c.internalError(w, err)
			return
		}
	}
	for _, v := range h.ApplyFailed {
		c.log.Warn("node reverted a snapshot", "node", n.Name, "version", v)
		if err := c.store.MarkSnapshotBad(r.Context(), n.ID, v); err != nil {
			c.internalError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) internalError(w http.ResponseWriter, err error) {
	c.log.Error("request failed", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, protocol.Error{Error: msg})
}

// normalize sorts and dedupes, and never returns nil, so stored lists
// compare equal however they were given.
func normalize[T ~string](s []T) []T {
	out := slices.Clone(s)
	slices.Sort(out)
	out = slices.Compact(out)
	if out == nil {
		out = []T{}
	}
	return out
}
