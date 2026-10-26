// Package protocol holds the JSON messages the Coordinator and the Agent
// exchange under /v1 (ADR 0002), and the Admin API messages for enrolling
// Nodes.
package protocol

import "time"

// Role is what a Node does.
type Role string

const (
	RoleBridge Role = "bridge"
	RoleExit   Role = "exit"
)

// Valid reports whether r is a known Role.
func (r Role) Valid() bool { return r == RoleBridge || r == RoleExit }

// Snapshot is one version of a Node's complete desired state, as served by
// GET /v1/state.
type Snapshot struct {
	Version uint64 `json:"version"`
	State   State  `json:"state"`
}

// State is a Node's complete desired state. A Node sees only what its Roles
// need. Later sessions add Devices, Rules and the rest.
type State struct {
	Node NodeInfo `json:"node"`
	// Links are this Node's Links, each with its candidate instances in
	// preference order (ADR 0007).
	Links      []Link     `json:"links"`
	LinkTiming LinkTiming `json:"link_timing"`
	// EgressCheck is set for Exits: what the Agent checks every 5 s to set
	// the egress OK flag in its probe replies (ADR 0008).
	EgressCheck *EgressCheck `json:"egress_check,omitempty"`
	// Bridge is set for Bridges only: Exits never see Devices (ADR 0002).
	Bridge *BridgeState `json:"bridge,omitempty"`
	// Monitor opens the Node's metrics port (ADR 0006); nil keeps it shut.
	Monitor *Monitor `json:"monitor,omitempty"`
}

// Monitor is the Node's one monitoring port: Prometheus scrapes /metrics
// there, and the Coordinator hands alerts to it for relay to Telegram.
// Both need a client certificate from the Coordinator's CA.
type Monitor struct {
	Port uint16 `json:"port"`
	// AllowFrom are the only addresses nftables lets reach the port: the
	// Coordinator VM's. Everyone else is dropped without an answer.
	AllowFrom []string `json:"allow_from"`
}

// TelegramMessage is POSTed by the Coordinator to /v1/telegram on an
// Exit's monitoring port, for the Agent to send on to Telegram, which is
// blocked domestically (ADR 0006).
type TelegramMessage struct {
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
	Text     string `json:"text"`
}

// BridgeState is what a Bridge needs to serve Devices (ADR 0004, ADR 0005).
type BridgeState struct {
	// PrivateKey is the shared Bridge identity, base64.
	PrivateKey string `json:"private_key"`
	ListenPort uint16 `json:"listen_port"`
	// Address is the Bridge's in-tunnel address with the Device pool's
	// prefix, such as 10.77.0.1/16. The resolver listens on it.
	Address string `json:"address"`
	// Upstreams are the public resolvers abroad the resolver forwards to.
	Upstreams []string `json:"upstreams"`
	// Devices are every Device whose effective state lets it connect.
	Devices []Device `json:"devices"`
	// Rules in priority order, the default Rule last.
	Rules []Rule `json:"rules"`
	// AbroadRule is the Abroad Rule (ADR 0014), which goes ahead of every
	// Rule. It travels apart from Rules so that an Agent from before it,
	// which ignores fields it does not know, never reads it as "everything,
	// requires IR, first" and sends every Device out of Iran.
	AbroadRule *Rule `json:"abroad_rule,omitempty"`
	// AbroadUpstreams are the domestic resolvers Abroad Devices' lookups
	// go to, as plain DNS through the Abroad Rule (ADR 0014).
	AbroadUpstreams []string `json:"abroad_upstreams,omitempty"`
	// Scoring is how the Bridge ranks and balances candidates (ADR 0008).
	Scoring Scoring `json:"scoring"`
}

// Scoring holds ADR 0008's constants, pushed so they can be tuned without
// a release and shortened in tests.
type Scoring struct {
	RTTFloorMillis          float64 `json:"rtt_floor_ms"`          // RTT counts only above this
	AvailabilityWindowSec   int     `json:"availability_window_s"` // sliding window for availability
	FlapPenaltySec          int     `json:"flap_penalty_s"`        // extra downtime per eligible-to-ineligible switch
	FlapWindowSec           int     `json:"flap_window_s"`         // how far back switches are penalised
	Cutoff                  float64 `json:"cutoff"`                // below this fraction of the best weight: no buckets
	RebalanceThresholdShare float64 `json:"rebalance_threshold"`   // off target by more than this share...
	RebalanceAfterSec       int     `json:"rebalance_after_s"`     // ...for this long...
	RebalanceEverySec       int     `json:"rebalance_every_s"`     // ...moves one bucket this often

	// The throughput test on each of a Bridge's Links: every so often,
	// give or take the jitter, the far end sends up to MaxBytes for up to
	// MaxSec. Zero means the default, for snapshots from before these.
	ThroughputEverySec  int   `json:"throughput_every_s,omitempty"`
	ThroughputJitterSec int   `json:"throughput_jitter_s,omitempty"`
	ThroughputMaxBytes  int64 `json:"throughput_max_bytes,omitempty"`
	ThroughputMaxSec    int   `json:"throughput_max_s,omitempty"`
}

// AllRules are the Rules in the order a Bridge matches them: the Abroad
// Rule, if any, then Rules, the default Rule last.
func (b *BridgeState) AllRules() []Rule {
	if b.AbroadRule == nil {
		return b.Rules
	}
	return append([]Rule{*b.AbroadRule}, b.Rules...)
}

// DefaultScoring is ADR 0008's.
var DefaultScoring = Scoring{
	RTTFloorMillis:          150,
	AvailabilityWindowSec:   6 * 3600,
	FlapPenaltySec:          60,
	FlapWindowSec:           3600,
	Cutoff:                  0.25,
	RebalanceThresholdShare: 0.10,
	RebalanceAfterSec:       15 * 60,
	RebalanceEverySec:       5 * 60,
	// About 4 MB or 3 s, every 2 hours with jitter. The first test of a
	// Link comes within the jitter, ahead of the first rebalancing move.
	ThroughputEverySec:  2 * 3600,
	ThroughputJitterSec: 10 * 60,
	ThroughputMaxBytes:  4 << 20,
	ThroughputMaxSec:    3,
}

// Device is one Device peer of a Bridge.
type Device struct {
	PublicKey string `json:"public_key"`
	Address   string `json:"address"` // its /32 in the Device pool
	// Rate, set only while the Device is throttled, is what the Bridge
	// holds it to: bytes per second of inner traffic, each way (ADR 0010).
	Rate uint64 `json:"rate,omitempty"`
}

// Fallback is what a Rule does when no candidate can carry it.
type Fallback string

const (
	FallbackNext Fallback = "next" // on to the next Rule
	FallbackDrop Fallback = "drop"
)

// Rule maps a Destination Set to the Tags its Exit must carry.
type Rule struct {
	ID       uint64 `json:"id"`
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	// SetHash names the Destination Set's content; fetch it from
	// GET /v1/sets/{hash}. A Rule with a Source has none.
	SetHash string `json:"set_hash"`
	// Source, set on the Abroad Rule only, is the prefix of the Devices it
	// takes, whatever their destination (ADR 0014).
	Source string `json:"source,omitempty"`
	// RequiredTags are ANDed; "!IR" means the Exit must not carry IR.
	RequiredTags []string `json:"required_tags"`
	Fallback     Fallback `json:"fallback"`
}

// Matches reports whether a Node with tags may be the Exit for r.
func (r Rule) Matches(tags []string) bool {
	for _, req := range r.RequiredTags {
		neg := len(req) > 0 && req[0] == '!'
		name := req
		if neg {
			name = req[1:]
		}
		has := false
		for _, t := range tags {
			if t == name {
				has = true
			}
		}
		if has == neg {
			return false
		}
	}
	return true
}

// Transport is a way of carrying a Link's traffic.
type Transport string

const (
	TransportWireGuard Transport = "wireguard"
	TransportAmneziaWG Transport = "amneziawg"
	// TransportGRE is plain GRE, IP protocol 47 (ADR 0009). It has no
	// port, parameters or handshake.
	TransportGRE Transport = "gre"
)

// Link is one tunnel to a peer Node, carried by one of its instances.
type Link struct {
	ID   uint64 `json:"id"`
	Peer Peer   `json:"peer"`
	// Initiator is set on the end that has the peer's endpoint configured:
	// the IR end of a Link that crosses the filter, otherwise the Node with
	// the lower id. The other end listens.
	Initiator bool `json:"initiator"`
	// Instances are the Link's candidates, most preferred first. An instance
	// appears only once both ends' Link keys are known, and, on the
	// initiating end, once the listening end has chosen its port.
	Instances []Instance `json:"instances"`
}

// Peer is the Node at the far end of a Link.
type Peer struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Roles     []Role   `json:"roles"`
	Tags      []string `json:"tags"`
	PublicKey string   `json:"public_key"` // the peer's Link key, base64
}

// Instance is one candidate Transport instance of a Link. Its port and, for
// AmneziaWG, its parameters are chosen by the listening end and never
// change; an instance is replaced instead. A GRE instance has neither.
type Instance struct {
	ID        uint64    `json:"id"`
	Transport Transport `json:"transport"`
	Iface     string    `json:"iface"`
	Addr      string    `json:"addr"`      // this end's inner address, with its /31
	PeerAddr  string    `json:"peer_addr"` // the far end's inner address
	// ListenPort is the listening end's UDP port. On the listening end, 0
	// means the Agent must choose one and report it.
	ListenPort uint16 `json:"listen_port,omitempty"`
	// Endpoint is the listening end's address and port, set on the
	// initiating end only.
	Endpoint string `json:"endpoint,omitempty"`
	// Remote is the far end's public address, its seen address (ADR 0002),
	// set on both ends of a GRE instance: GRE does not roam (ADR 0009).
	Remote string `json:"remote,omitempty"`
	// AWG holds AmneziaWG parameters. On the listening end, nil means the
	// Agent must choose them and report them.
	AWG *AWGParams `json:"awg,omitempty"`
}

// AWGParams are an AmneziaWG instance's obfuscation parameters (protocol
// 2.0), in the form amneziawg-go's UAPI takes them.
type AWGParams struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	S3   int    `json:"s3"`
	S4   int    `json:"s4"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
	I1   string `json:"i1,omitempty"`
	I2   string `json:"i2,omitempty"`
	I3   string `json:"i3,omitempty"`
	I4   string `json:"i4,omitempty"`
	I5   string `json:"i5,omitempty"`
}

// LinkTiming holds ADR 0007's timings, pushed so tests can shorten them.
type LinkTiming struct {
	SwitchBackSeconds   int `json:"switch_back_seconds"`
	RetryMinSeconds     int `json:"retry_min_seconds"`
	RetryMaxSeconds     int `json:"retry_max_seconds"`
	ReplaceAfterSeconds int `json:"replace_after_seconds"`
}

// DefaultLinkTiming is ADR 0007's: switch back after 5 minutes Up, retry
// from 30 s to 15 min, replace after 24 h down.
var DefaultLinkTiming = LinkTiming{
	SwitchBackSeconds:   300,
	RetryMinSeconds:     30,
	RetryMaxSeconds:     900,
	ReplaceAfterSeconds: 24 * 3600,
}

// EgressCheck is what an Exit resolves and fetches to decide that its own
// internet works.
type EgressCheck struct {
	Resolvers []string `json:"resolvers"` // IP addresses
	Hostname  string   `json:"hostname"`
	URL       string   `json:"url"`
}

// NodeInfo is what a Node is told about itself.
type NodeInfo struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Roles []Role   `json:"roles"`
	Tags  []string `json:"tags"`
}

// Health is what an Agent POSTs to /v1/health every 30 s, and to confirm a
// freshly applied snapshot.
type Health struct {
	AppliedVersion uint64    `json:"applied_version"`
	AgentVersion   string    `json:"agent_version"`
	Time           time.Time `json:"time"` // the Agent's clock
	Addr           string    `json:"addr"` // the source address the Agent dialled from
	// ApplyFailed lists snapshot versions the Agent applied and then reverted
	// because it lost the Coordinator within the confirm window.
	ApplyFailed []uint64 `json:"apply_failed,omitempty"`

	// LinkPublicKey is the Agent's Link key, generated on the Node.
	LinkPublicKey string `json:"link_public_key,omitempty"`
	// Listening reports the ports and parameters this Node chose for the
	// instances it listens on.
	Listening []ListenChoice `json:"listening,omitempty"`
	Links     []LinkHealth   `json:"links,omitempty"`
	// Paths are a Bridge's bucket shares per candidate per Rule (ADR 0008).
	Paths []RuleHealth `json:"paths,omitempty"`
	// Usage carries metering from Bridges: hourly buckets, each sent until
	// a health POST carrying it succeeds (ADR 0002).
	Usage []UsageBucket `json:"usage,omitempty"`
}

// UsageBucket is one Device's bytes through one Exit in one hour, by the
// Bridge's clock. Uploads replace, never add, so resending is harmless.
type UsageBucket struct {
	Hour   int64  `json:"hour"`   // Unix time of the hour's start
	Device string `json:"device"` // the Device's tunnel address
	Exit   string `json:"exit"`   // the Exit's Node id; a transit Bridge's while in transit
	Up     uint64 `json:"up"`     // bytes from the Device
	Down   uint64 `json:"down"`   // bytes to the Device
}

// RuleHealth is how a Bridge is carrying one Rule.
type RuleHealth struct {
	RuleID uint64 `json:"rule_id"`
	// Mode is "local", "direct", "transit" or "fallback".
	Mode string `json:"mode"`
	// Shares counts buckets per candidate, such as "local", "link:4" or
	// "drop"; a Rule in fallback reports the buckets of the Rule it fell to.
	Shares   map[string]int `json:"shares"`
	Eligible int            `json:"eligible"`
}

// ListenChoice is a listening end's choice for one instance.
type ListenChoice struct {
	InstanceID uint64     `json:"instance_id"`
	Port       uint16     `json:"port"`
	AWG        *AWGParams `json:"awg,omitempty"`
}

// LinkHealth is one Link as this end measures it. The top-level figures are
// the active instance's (ADR 0007).
type LinkHealth struct {
	LinkID         uint64    `json:"link_id"`
	Up             bool      `json:"up"`
	ActiveInstance uint64    `json:"active_instance,omitempty"`
	Transport      Transport `json:"transport,omitempty"`
	RTTMillis      float64   `json:"rtt_ms"`
	Loss           float64   `json:"loss"` // 0 to 1, over the last 30 s
	// LastSuccessSeconds is the age of the last answered probe; -1 if none.
	LastSuccessSeconds float64 `json:"last_success_s"`
	// PeerEgressOK and PeerTransitRules are the flags in the peer's latest
	// probe reply on the active instance (ADR 0008).
	PeerEgressOK     bool     `json:"peer_egress_ok"`
	PeerTransitRules []uint32 `json:"peer_transit_rules,omitempty"`
	// ThroughputMbps is what the far end can still send this end, from the
	// throughput test and raised by observed peaks; 0 until the first test.
	// Only Bridges measure it (ADR 0008).
	ThroughputMbps float64          `json:"throughput_mbps,omitempty"`
	Instances      []InstanceHealth `json:"instances"`
}

// InstanceHealth is one instance as this end measures it.
type InstanceHealth struct {
	ID        uint64     `json:"id"`
	Up        bool       `json:"up"`
	DownSince *time.Time `json:"down_since,omitempty"` // set while not Up
	RTTMillis float64    `json:"rtt_ms"`
	Loss      float64    `json:"loss"`
}

// EnrollRequest is POSTed to /v1/enroll by a new Agent.
type EnrollRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"` // PEM
}

// EnrollResponse carries the Agent's client certificate.
type EnrollResponse struct {
	NodeID      string `json:"node_id"`
	Certificate string `json:"certificate"` // PEM
}

// CreateNodeRequest is POSTed to /v1/nodes with a nodes:enroll API token.
type CreateNodeRequest struct {
	Name  string   `json:"name"`
	Roles []Role   `json:"roles"`
	Tags  []string `json:"tags"`
	// Reenroll mints a new enrollment token for a Node that already enrolled,
	// so it can re-key.
	Reenroll bool `json:"reenroll,omitempty"`
}

// CreateNodeResponse reports the Node and, unless it already enrolled and no
// re-enrollment was asked for, a fresh one-time enrollment token.
type CreateNodeResponse struct {
	Node            NodeStatus `json:"node"`
	EnrollmentToken string     `json:"enrollment_token,omitempty"`
	TokenExpiresAt  *time.Time `json:"token_expires_at,omitempty"`
}

// NodeStatus is a Node as the Admin API reports it, from GET /v1/nodes/{id}.
type NodeStatus struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Roles    []Role   `json:"roles"`
	Tags     []string `json:"tags"`
	Enrolled bool     `json:"enrolled"`
	// LastHealth is the latest health report, absent until the first one.
	LastHealth *HealthStatus `json:"last_health,omitempty"`
}

// HealthStatus is the latest health report as the Coordinator stored it.
type HealthStatus struct {
	Health
	ReceivedAt time.Time `json:"received_at"`
	// SeenAddr is the source address the Coordinator saw. A mismatch with
	// Health.Addr is shown to the Admin.
	SeenAddr string `json:"seen_addr"`
}

// Error is the body of every non-2xx response.
type Error struct {
	Error string `json:"error"`
}
