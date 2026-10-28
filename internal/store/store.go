// Package store is the Coordinator's only path to its SQLite database
// (ADR 0001). Migrations are embedded in the binary and run on Open.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/alakiani/ways/internal/protocol"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrExists       = errors.New("already exists")
	ErrInvalidToken = errors.New("invalid, used, expired or revoked token")
)

// ScopeNodesEnroll lets an API token create Nodes, mint enrollment tokens,
// and read the result, nothing else (ADR 0002).
const ScopeNodesEnroll = "nodes:enroll"

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the Coordinator's database.
type Store struct {
	db *sql.DB
	// Now is the clock the store stamps and checks expiry with.
	Now func() time.Time
}

// Open opens or creates the database at path and brings its schema up to date.
func Open(path string) (*Store, error) {
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() +
		"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serialises every write; at this scale that costs nothing
	// and rules out SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, Now: time.Now}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY)`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var done int
		if err := s.db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE name = ?`, name).Scan(&done); err != nil {
			return err
		}
		if done > 0 {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		err = s.tx(context.Background(), func(tx *sql.Tx) error {
			if _, err := tx.Exec(string(body)); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			_, err := tx.Exec(`INSERT INTO schema_migrations (name) VALUES (?)`, name)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) unix() int64 { return s.Now().Unix() }

// Node is a Node as stored.
type Node struct {
	ID         string
	Name       string
	Roles      []protocol.Role
	Tags       []string
	CertSerial string // empty until the Node enrolls
	CreatedAt  time.Time
	// LinkPublicKey is the Node's Link key, empty until its Agent reports it.
	LinkPublicKey string
	// Unlisted is set while an Admin keeps the Bridge out of the Bridge
	// Address (ADR 0015).
	Unlisted bool
}

// Enrolled reports whether the Node holds a client certificate.
func (n Node) Enrolled() bool { return n.CertSerial != "" }

// CreateNode adds a Node. Its name must be unused.
func (s *Store) CreateNode(ctx context.Context, name string, roles []protocol.Role, tags []string) (Node, error) {
	n := Node{ID: "nd_" + randomHex(8), Name: name, Roles: nonNil(roles), Tags: nonNil(tags), CreatedAt: time.Unix(s.unix(), 0).UTC()}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO nodes (id, name, roles, tags, created_at) VALUES (?, ?, ?, ?, ?)`,
		n.ID, n.Name, mustJSON(n.Roles), mustJSON(n.Tags), n.CreatedAt.Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return Node{}, fmt.Errorf("node %q: %w", name, ErrExists)
	}
	return n, err
}

// UpdateNode replaces a Node's Roles and Tags.
func (s *Store) UpdateNode(ctx context.Context, id string, roles []protocol.Role, tags []string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE nodes SET roles = ?, tags = ? WHERE id = ?`,
		mustJSON(nonNil(roles)), mustJSON(nonNil(tags)), id)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return fmt.Errorf("node %s: %w", id, ErrNotFound)
	}
	return nil
}

// SetNodeUnlisted unlists a Node from the Bridge Address or lists it again.
func (s *Store) SetNodeUnlisted(ctx context.Context, id string, unlisted bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE nodes SET unlisted = ? WHERE id = ?`, unlisted, id)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return fmt.Errorf("node %s: %w", id, ErrNotFound)
	}
	return nil
}

const nodeColumns = `id, name, roles, tags, coalesce(cert_serial, ''), created_at, coalesce(link_public_key, ''), unlisted`

func scanNode(row interface{ Scan(...any) error }) (Node, error) {
	var n Node
	var roles, tags string
	var created int64
	if err := row.Scan(&n.ID, &n.Name, &roles, &tags, &n.CertSerial, &created, &n.LinkPublicKey, &n.Unlisted); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Node{}, ErrNotFound
		}
		return Node{}, err
	}
	n.CreatedAt = time.Unix(created, 0).UTC()
	if err := json.Unmarshal([]byte(roles), &n.Roles); err != nil {
		return Node{}, err
	}
	return n, json.Unmarshal([]byte(tags), &n.Tags)
}

// Node returns the Node with the given id.
func (s *Store) Node(ctx context.Context, id string) (Node, error) {
	return scanNode(s.db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, id))
}

// NodeByName returns the Node with the given name.
func (s *Store) NodeByName(ctx context.Context, name string) (Node, error) {
	return scanNode(s.db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE name = ?`, name))
}

// Nodes returns every Node, by name.
func (s *Store) Nodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+nodeColumns+` FROM nodes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

// MintEnrollmentToken returns a one-time token that enrolls the given Node
// until it expires. It replaces any unused token the Node had.
func (s *Store) MintEnrollmentToken(ctx context.Context, nodeID string, ttl time.Duration) (string, time.Time, error) {
	token := randomToken()
	expires := time.Unix(s.unix(), 0).Add(ttl).UTC()
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM enrollment_tokens WHERE node_id = ? AND used_at IS NULL`, nodeID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO enrollment_tokens (hash, node_id, expires_at) VALUES (?, ?, ?)`,
			hash(token), nodeID, expires.Unix())
		return err
	})
	return token, expires, err
}

// Enroll consumes an enrollment token. It calls sign with the token's Node
// id to issue a certificate, and records the serial sign returns as the
// Node's only accepted certificate. If sign fails, the token is not consumed.
func (s *Store) Enroll(ctx context.Context, token string, sign func(nodeID string) (serial string, err error)) (string, error) {
	var nodeID string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var expires int64
		err := tx.QueryRow(`SELECT node_id, expires_at FROM enrollment_tokens WHERE hash = ? AND used_at IS NULL`,
			hash(token)).Scan(&nodeID, &expires)
		if errors.Is(err, sql.ErrNoRows) || err == nil && s.unix() > expires {
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		serial, err := sign(nodeID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE enrollment_tokens SET used_at = ? WHERE hash = ?`, s.unix(), hash(token)); err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE nodes SET cert_serial = ? WHERE id = ?`, serial, nodeID)
		return err
	})
	return nodeID, err
}

// APIToken is a scoped credential for a non-interactive caller.
type APIToken struct {
	ID        string
	Scope     string
	Name      string
	ExpiresAt time.Time
}

// CreateAPIToken returns a new token's secret, which is shown once and never
// stored, and its record.
func (s *Store) CreateAPIToken(ctx context.Context, scope, name string, ttl time.Duration) (string, APIToken, error) {
	secret := "ways_" + randomToken()
	t := APIToken{ID: "tok_" + randomHex(8), Scope: scope, Name: name, ExpiresAt: time.Unix(s.unix(), 0).Add(ttl).UTC()}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_tokens (id, hash, scope, name, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, hash(secret), t.Scope, t.Name, s.unix(), t.ExpiresAt.Unix())
	return secret, t, err
}

// CheckAPIToken returns the token with the given secret if it carries scope
// and is neither expired nor revoked.
func (s *Store) CheckAPIToken(ctx context.Context, secret, scope string) (APIToken, error) {
	var t APIToken
	var expires int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, scope, name, expires_at FROM api_tokens WHERE hash = ? AND revoked_at IS NULL`,
		hash(secret)).Scan(&t.ID, &t.Scope, &t.Name, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return APIToken{}, ErrInvalidToken
	}
	if err != nil {
		return APIToken{}, err
	}
	if t.Scope != scope || s.unix() > expires {
		return APIToken{}, ErrInvalidToken
	}
	t.ExpiresAt = time.Unix(expires, 0).UTC()
	return t, nil
}

// RevokeAPIToken revokes a token by id.
func (s *Store) RevokeAPIToken(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, s.unix(), id)
	return err
}

// Snapshot is one stored version of a Node's desired state.
type Snapshot struct {
	Version uint64
	Body    []byte
	// Bad is set once the Node reported that applying this version cut it off.
	Bad bool
}

// PutSnapshot stores body as the Node's next version, unless it equals the
// latest version's body. It returns the latest version and whether it is new.
func (s *Store) PutSnapshot(ctx context.Context, nodeID string, body []byte) (uint64, bool, error) {
	h := hash(string(body))
	var version uint64
	var changed bool
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var latestHash []byte
		err := tx.QueryRow(`SELECT version, hash FROM snapshots WHERE node_id = ? ORDER BY version DESC LIMIT 1`,
			nodeID).Scan(&version, &latestHash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && string(latestHash) == string(h) {
			return nil
		}
		version++
		changed = true
		_, err = tx.Exec(`INSERT INTO snapshots (node_id, version, hash, body, created_at) VALUES (?, ?, ?, ?, ?)`,
			nodeID, version, h, body, s.unix())
		return err
	})
	return version, changed, err
}

// LatestSnapshot returns the Node's newest version.
func (s *Store) LatestSnapshot(ctx context.Context, nodeID string) (Snapshot, error) {
	var snap Snapshot
	var bad sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT version, body, bad_at FROM snapshots WHERE node_id = ? ORDER BY version DESC LIMIT 1`,
		nodeID).Scan(&snap.Version, &snap.Body, &bad)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrNotFound
	}
	snap.Bad = bad.Valid
	return snap, err
}

// MarkSnapshotBad records that the Node reverted the given version.
func (s *Store) MarkSnapshotBad(ctx context.Context, nodeID string, version uint64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE snapshots SET bad_at = ? WHERE node_id = ? AND version = ? AND bad_at IS NULL`,
		s.unix(), nodeID, version)
	return err
}

// PutHealth replaces the Node's latest health report.
func (s *Store) PutHealth(ctx context.Context, nodeID string, h protocol.Health, seenAddr string) error {
	status := protocol.HealthStatus{Health: h, ReceivedAt: time.Unix(s.unix(), 0).UTC(), SeenAddr: seenAddr}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO node_health (node_id, body) VALUES (?, ?) ON CONFLICT (node_id) DO UPDATE SET body = excluded.body`,
		nodeID, mustJSON(status))
	return err
}

// Health returns the Node's latest health report, or nil if it has sent none.
func (s *Store) Health(ctx context.Context, nodeID string) (*protocol.HealthStatus, error) {
	var body string
	err := s.db.QueryRowContext(ctx, `SELECT body FROM node_health WHERE node_id = ?`, nodeID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var h protocol.HealthStatus
	return &h, json.Unmarshal([]byte(body), &h)
}

func hash(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
