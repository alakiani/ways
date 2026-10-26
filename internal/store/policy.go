package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/alakiani/ways/internal/cidr"
	"github.com/alakiani/ways/internal/protocol"
)

// DevicePool holds every Device's /32. Its first address belongs to the
// Bridges' resolver (ADR 0004).
var DevicePool = netip.MustParsePrefix("10.77.0.0/16")

// OrdinaryPool and AbroadPool split DevicePool between ordinary Devices
// and Abroad Devices, which a Bridge matches by AbroadPool (ADR 0014).
var (
	OrdinaryPool = netip.MustParsePrefix("10.77.0.0/17")
	AbroadPool   = netip.MustParsePrefix("10.77.128.0/17")
)

// User is a User as stored.
type User struct {
	ID        string
	Handle    string
	Suspended bool
}

// CreateUser adds a User.
func (s *Store) CreateUser(ctx context.Context, handle string) (User, error) {
	u := User{ID: "us_" + randomHex(8), Handle: handle}
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (id, handle, created_at) VALUES (?, ?, ?)`, u.ID, handle, s.unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return User{}, fmt.Errorf("user %q: %w", handle, ErrExists)
	}
	return u, err
}

// SetUserAbroad gives a User the abroad permission, or takes it away; their
// Abroad Devices stay, cut off while they lack it (ADR 0014).
func (s *Store) SetUserAbroad(ctx context.Context, id string, abroad bool) error {
	return s.setUser(ctx, id, `abroad = ?`, abroad)
}

// SetUserSuspended suspends or reinstates a User.
func (s *Store) SetUserSuspended(ctx context.Context, id string, suspended bool) error {
	var v any
	if suspended {
		v = s.unix()
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET suspended_at = ? WHERE id = ?`, v, id)
	return err
}

// Device is a Device as stored.
type Device struct {
	ID            string
	UserID        string // empty for the probe Device
	Name          string
	PublicKey     string // empty once revoked
	Address       netip.Addr
	Revoked       bool
	UserSuspended bool
	// Abroad is set on an Abroad Device; UserAbroad while its User has the
	// abroad permission (ADR 0014).
	Abroad, UserAbroad bool
}

// CreateDevice adds a Device on the next unused address of the pool.
// Addresses are never reused while a Device's row exists, so metering never
// mixes two Devices.
func (s *Store) CreateDevice(ctx context.Context, userID, name, publicKey string) (Device, error) {
	d := Device{ID: "dv_" + randomHex(8), UserID: userID, Name: name, PublicKey: publicKey}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		a, err := nextDeviceAddr(tx, false)
		if err != nil {
			return err
		}
		d.Address = a
		var uid any
		if userID != "" {
			uid = userID
		}
		_, err = tx.Exec(`INSERT INTO devices (id, user_id, name, public_key, address, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			d.ID, uid, name, publicKey, a.String(), s.unix())
		return err
	})
	return d, err
}

// RevokeDevice takes a Device out of service and erases its public key.
func (s *Store) RevokeDevice(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET revoked_at = ?, public_key = NULL WHERE id = ? AND revoked_at IS NULL`, s.unix(), id)
	return err
}

// Devices returns every Device with its User's status.
func (s *Store) Devices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT d.id, coalesce(d.user_id, ''), d.name, coalesce(d.public_key, ''), d.address,
		d.revoked_at IS NOT NULL, coalesce(u.suspended_at IS NOT NULL, 0), d.abroad, coalesce(u.abroad, 0)
		FROM devices d LEFT JOIN users u ON u.id = d.user_id ORDER BY d.address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var addr string
		if err := rows.Scan(&d.ID, &d.UserID, &d.Name, &d.PublicKey, &addr, &d.Revoked, &d.UserSuspended, &d.Abroad, &d.UserAbroad); err != nil {
			return nil, err
		}
		d.Address = netip.MustParseAddr(addr)
		out = append(out, d)
	}
	return out, rows.Err()
}

// DestinationSet is a Destination Set as stored.
type DestinationSet struct {
	ID          uint64
	Name        string
	Feed        string
	FeedContent []netip.Prefix // last good feed update
	Additions   []netip.Prefix
	Removals    []netip.Prefix
	ContentHash string
}

// Content is the set's prefixes: the feed plus additions, minus removals.
func (d DestinationSet) Content() []netip.Prefix {
	return cidr.Subtract(cidr.Merge(append(append([]netip.Prefix{}, d.FeedContent...), d.Additions...)), d.Removals)
}

// DestinationSets returns every Destination Set.
func (s *Store) DestinationSets(ctx context.Context) ([]DestinationSet, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, feed, feed_content, additions, removals, content_hash FROM destination_sets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DestinationSet
	for rows.Next() {
		var d DestinationSet
		var feed, adds, rems string
		if err := rows.Scan(&d.ID, &d.Name, &d.Feed, &feed, &adds, &rems, &d.ContentHash); err != nil {
			return nil, err
		}
		for _, f := range []struct {
			src string
			dst *[]netip.Prefix
		}{{feed, &d.FeedContent}, {adds, &d.Additions}, {rems, &d.Removals}} {
			if err := json.Unmarshal([]byte(f.src), f.dst); err != nil {
				return nil, fmt.Errorf("set %s: %w", d.Name, err)
			}
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetFeedContent records a feed update that passed its gates as the set's
// last good feed content, and refreshes the set's content.
func (s *Store) SetFeedContent(ctx context.Context, setID uint64, content []netip.Prefix) error {
	_, err := s.db.ExecContext(ctx, `UPDATE destination_sets SET feed_previous = feed_content, feed_content = ?, feed_updated_at = ? WHERE id = ?`,
		mustJSON(nonNil(content)), s.unix(), setID)
	if err != nil {
		return err
	}
	return s.RefreshSetContent(ctx, setID)
}

// SetOverrides replaces a set's Admin additions and removals.
func (s *Store) SetOverrides(ctx context.Context, setID uint64, additions, removals []netip.Prefix) error {
	_, err := s.db.ExecContext(ctx, `UPDATE destination_sets SET additions = ?, removals = ? WHERE id = ?`,
		mustJSON(nonNil(additions)), mustJSON(nonNil(removals)), setID)
	if err != nil {
		return err
	}
	return s.RefreshSetContent(ctx, setID)
}

// RefreshSetContent stores the set's current content under its hash.
func (s *Store) RefreshSetContent(ctx context.Context, setID uint64) error {
	sets, err := s.DestinationSets(ctx)
	if err != nil {
		return err
	}
	for _, d := range sets {
		if d.ID != setID {
			continue
		}
		var b strings.Builder
		for _, p := range d.Content() {
			b.WriteString(p.String() + "\n")
		}
		sum := sha256.Sum256([]byte(b.String()))
		h := hex.EncodeToString(sum[:])
		return s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.Exec(`INSERT INTO set_blobs (hash, body) VALUES (?, ?) ON CONFLICT DO NOTHING`, h, b.String()); err != nil {
				return err
			}
			_, err := tx.Exec(`UPDATE destination_sets SET content_hash = ? WHERE id = ?`, h, setID)
			return err
		})
	}
	return fmt.Errorf("set %d: %w", setID, ErrNotFound)
}

// SetBlob returns a set's content by hash.
func (s *Store) SetBlob(ctx context.Context, hash string) (string, error) {
	var body string
	err := s.db.QueryRowContext(ctx, `SELECT body FROM set_blobs WHERE hash = ?`, hash).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return body, err
}

// Rule is a Rule as stored.
type Rule struct {
	ID           uint64
	Name         string
	Priority     int
	SetID        uint64
	RequiredTags []string
	Fallback     protocol.Fallback
	Builtin      bool
	// Source is set on the Abroad Rule only: it takes the Devices in this
	// prefix, whatever their destination (ADR 0014).
	Source string
}

// Rules returns every Rule in priority order.
func (s *Store) Rules(ctx context.Context) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, priority, set_id, required_tags, fallback, builtin, coalesce(source, '') FROM rules ORDER BY priority`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var tags string
		if err := rows.Scan(&r.ID, &r.Name, &r.Priority, &r.SetID, &tags, &r.Fallback, &r.Builtin, &r.Source); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(tags), &r.RequiredTags); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Setting returns a global setting, or "" if unset.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSettingIfUnset stores a global setting unless it already has a value,
// and returns the value in force.
func (s *Store) SetSettingIfUnset(ctx context.Context, key, value string) (string, error) {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT DO NOTHING`, key, value); err != nil {
		return "", err
	}
	return s.Setting(ctx, key)
}
