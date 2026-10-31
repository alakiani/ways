package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// InviteRecord is an Invite as Admins list it. Its secret is never kept.
type InviteRecord struct {
	ID        string
	Kind      string
	Handle    string // for recovery: the User; for new: who redeemed it
	Admin     bool
	DeviceCap int
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
	Withdrawn bool
	// What a new-User Invite presets (ADR 0010), as Invite holds it.
	QuotaSetting
	Refills   int
	RefillTTL time.Duration
	Abroad    bool
}

// Invites lists Invites, newest first.
func (s *Store) Invites(ctx context.Context) ([]InviteRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT i.id, i.kind, coalesce(u.handle, ''), i.is_admin, coalesce(i.device_cap, 0),
		i.created_at, i.expires_at, i.used_at IS NOT NULL, i.withdrawn_at IS NOT NULL,
		i.quota, coalesce(i.slow_rate, 0), i.refills, i.refill_ttl, i.abroad
		FROM invites i LEFT JOIN users u ON u.id = i.user_id ORDER BY i.created_at DESC, i.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InviteRecord
	for rows.Next() {
		var r InviteRecord
		var created, expires, refillTTL int64
		if err := rows.Scan(&r.ID, &r.Kind, &r.Handle, &r.Admin, &r.DeviceCap, &created, &expires, &r.Used, &r.Withdrawn,
			&r.Quota, &r.SlowRate, &r.Refills, &refillTTL, &r.Abroad); err != nil {
			return nil, err
		}
		r.CreatedAt, r.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(expires, 0).UTC()
		r.RefillTTL = time.Duration(refillTTL) * time.Second
		out = append(out, r)
	}
	return out, rows.Err()
}

// WithdrawInvite makes an unused Invite unredeemable.
func (s *Store) WithdrawInvite(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE invites SET withdrawn_at = ? WHERE id = ? AND used_at IS NULL AND withdrawn_at IS NULL`, s.unix(), id)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return fmt.Errorf("invite %s: %w", id, ErrNotFound)
	}
	return nil
}

// DeleteNode removes a Node with its Links, instances, snapshots and
// health. Its certificate stops working at once (ADR 0002).
func (s *Store) DeleteNode(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return fmt.Errorf("node %s: %w", id, ErrNotFound)
	}
	return nil
}

// FeedStatus is how a fed Destination Set's feed has gone.
type FeedStatus struct {
	UpdatedAt   time.Time // when the last good update was taken; zero if never
	LastAttempt time.Time
	LastError   string // empty if the last attempt was taken
	CanRollBack bool
}

// FeedStatus returns a set's feed status.
func (s *Store) FeedStatus(ctx context.Context, setID uint64) (FeedStatus, error) {
	var st FeedStatus
	var updated, attempt sql.NullInt64
	var prev string
	err := s.db.QueryRowContext(ctx, `SELECT feed_updated_at, feed_last_attempt, feed_last_error, feed_previous FROM destination_sets WHERE id = ?`,
		setID).Scan(&updated, &attempt, &st.LastError, &prev)
	if errors.Is(err, sql.ErrNoRows) {
		return st, ErrNotFound
	}
	if updated.Valid {
		st.UpdatedAt = time.Unix(updated.Int64, 0).UTC()
	}
	if attempt.Valid {
		st.LastAttempt = time.Unix(attempt.Int64, 0).UTC()
	}
	st.CanRollBack = prev != "[]" && prev != ""
	return st, err
}

// RecordFeedAttempt notes a fetch of a set's feed: errMsg is empty when the
// update was taken.
func (s *Store) RecordFeedAttempt(ctx context.Context, setID uint64, errMsg string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE destination_sets SET feed_last_attempt = ?, feed_last_error = ? WHERE id = ?`, s.unix(), errMsg, setID)
	return err
}

// RollBackFeed swaps a set's feed content with the previous good one.
func (s *Store) RollBackFeed(ctx context.Context, setID uint64) error {
	var prev string
	if err := s.db.QueryRowContext(ctx, `SELECT feed_previous FROM destination_sets WHERE id = ?`, setID).Scan(&prev); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if prev == "[]" || prev == "" {
		return errors.New("nothing to roll back to")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE destination_sets SET feed_previous = feed_content, feed_content = feed_previous, feed_updated_at = ? WHERE id = ?`,
		s.unix(), setID); err != nil {
		return err
	}
	return s.RefreshSetContent(ctx, setID)
}

// UpdateRule changes a Rule's required Tags and fallback. The built-in
// default Rule cannot be changed (ADR 0004).
func (s *Store) UpdateRule(ctx context.Context, id uint64, tags []string, fallback string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE rules SET required_tags = ?, fallback = ? WHERE id = ? AND builtin = 0`,
		mustJSON(nonNil(tags)), fallback, id)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return fmt.Errorf("rule %d: %w", id, ErrNotFound)
	}
	return nil
}

// APITokens lists API tokens, newest first. Their secrets are never kept.
func (s *Store) APITokens(ctx context.Context) ([]APIToken, []bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, scope, name, expires_at, revoked_at IS NOT NULL FROM api_tokens ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []APIToken
	var revoked []bool
	for rows.Next() {
		var t APIToken
		var expires int64
		var r bool
		if err := rows.Scan(&t.ID, &t.Scope, &t.Name, &expires, &r); err != nil {
			return nil, nil, err
		}
		t.ExpiresAt = time.Unix(expires, 0).UTC()
		out = append(out, t)
		revoked = append(revoked, r)
	}
	return out, revoked, rows.Err()
}

// SetPrefixes parses a list of prefixes as an Admin types them.
func SetPrefixes(ss []string) ([]netip.Prefix, error) {
	out := []netip.Prefix{}
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("%q is not an IPv4 prefix", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
