package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

var (
	// ErrCapReached means the User already has as many Devices as allowed.
	ErrCapReached = errors.New("device cap reached")
	// ErrKeyInUse means another Device already has this public key.
	ErrKeyInUse = errors.New("public key already in use")
)

// Account is a User with what identity needs.
type Account struct {
	User
	Admin        bool
	DeviceCap    int
	PasswordHash string
	TOTPSecret   string // empty unless TOTP is on
	TOTPPending  string
	QuotaSetting
}

const accountColumns = `id, handle, suspended_at IS NOT NULL, is_admin, device_cap, coalesce(password_hash, ''),
	coalesce(totp_secret, ''), coalesce(totp_pending, ''), quota, coalesce(slow_rate, 0)`

func scanAccount(row interface{ Scan(...any) error }) (Account, error) {
	var a Account
	err := row.Scan(&a.ID, &a.Handle, &a.Suspended, &a.Admin, &a.DeviceCap, &a.PasswordHash, &a.TOTPSecret, &a.TOTPPending,
		&a.Quota, &a.SlowRate)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	return a, err
}

// Account returns a User by id.
func (s *Store) Account(ctx context.Context, id string) (Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx, `SELECT `+accountColumns+` FROM users WHERE id = ?`, id))
}

// AccountByHandle returns a User by handle.
func (s *Store) AccountByHandle(ctx context.Context, handle string) (Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx, `SELECT `+accountColumns+` FROM users WHERE handle = ?`, handle))
}

// Accounts returns every User, by handle.
func (s *Store) Accounts(ctx context.Context) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+accountColumns+` FROM users ORDER BY handle`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) setUser(ctx context.Context, id, set string, args ...any) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET `+set+` WHERE id = ?`, append(args, id)...)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return fmt.Errorf("user %s: %w", id, ErrNotFound)
	}
	return nil
}

// SetPassword replaces a User's password hash.
func (s *Store) SetPassword(ctx context.Context, id, hash string) error {
	return s.setUser(ctx, id, `password_hash = ?`, hash)
}

// SetTOTPPending stores a TOTP secret offered to the User, not yet in force.
func (s *Store) SetTOTPPending(ctx context.Context, id, secret string) error {
	return s.setUser(ctx, id, `totp_pending = ?`, secret)
}

// ConfirmTOTP puts the pending TOTP secret in force.
func (s *Store) ConfirmTOTP(ctx context.Context, id string) error {
	return s.setUser(ctx, id, `totp_secret = totp_pending, totp_pending = NULL`)
}

// ClearTOTP turns TOTP off.
func (s *Store) ClearTOTP(ctx context.Context, id string) error {
	return s.setUser(ctx, id, `totp_secret = NULL, totp_pending = NULL`)
}

// SetDeviceCap sets how many active Devices a User may have.
func (s *Store) SetDeviceCap(ctx context.Context, id string, cap int) error {
	return s.setUser(ctx, id, `device_cap = ?`, cap)
}

// DeleteUser removes a User with their Devices, sessions and Invites.
// Session 8 removes their usage with them.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return fmt.Errorf("user %s: %w", id, ErrNotFound)
	}
	return nil
}

// Invite is an Invite as stored.
type Invite struct {
	Kind      string // "new" or "recovery"
	UserID    string // for recovery
	Admin     bool
	DeviceCap int // 0: the default
	ExpiresAt time.Time
	// What a new-User Invite presets (ADR 0010): the Quota and running-out
	// setting, and Refills lasting RefillTTL from registration.
	QuotaSetting
	Refills   int
	RefillTTL time.Duration
}

// CreateInvite returns a single-use Invite's secret.
func (s *Store) CreateInvite(ctx context.Context, inv Invite, ttl time.Duration) (string, time.Time, error) {
	token := randomToken()
	expires := time.Unix(s.unix(), 0).Add(ttl).UTC()
	var uid, cap any
	if inv.UserID != "" {
		uid = inv.UserID
	}
	if inv.DeviceCap > 0 {
		cap = inv.DeviceCap
	}
	var rate any
	if inv.SlowRate > 0 {
		rate = inv.SlowRate
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO invites (hash, id, kind, user_id, is_admin, device_cap, created_at, expires_at,
			quota, slow_rate, refills, refill_ttl)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, hash(token), "inv_"+randomHex(8), inv.Kind, uid, inv.Admin, cap, s.unix(), expires.Unix(),
		inv.Quota, rate, inv.Refills, int64(inv.RefillTTL/time.Second))
	return token, expires, err
}

// LookupInvite returns an unused, unexpired Invite.
func (s *Store) LookupInvite(ctx context.Context, token string) (Invite, error) {
	return s.lookupInvite(ctx, s.db, token)
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Store) lookupInvite(ctx context.Context, q queryer, token string) (Invite, error) {
	var inv Invite
	var uid sql.NullString
	var cap sql.NullInt64
	var expires, refillTTL int64
	err := q.QueryRowContext(ctx, `SELECT kind, user_id, is_admin, device_cap, expires_at, quota, coalesce(slow_rate, 0), refills, refill_ttl
		FROM invites WHERE hash = ? AND used_at IS NULL AND withdrawn_at IS NULL`, hash(token)).
		Scan(&inv.Kind, &uid, &inv.Admin, &cap, &expires, &inv.Quota, &inv.SlowRate, &inv.Refills, &refillTTL)
	if errors.Is(err, sql.ErrNoRows) || err == nil && s.unix() > expires {
		return Invite{}, ErrInvalidToken
	}
	inv.UserID, inv.DeviceCap, inv.ExpiresAt = uid.String, int(cap.Int64), time.Unix(expires, 0).UTC()
	inv.RefillTTL = time.Duration(refillTTL) * time.Second
	return inv, err
}

// AcceptNewInvite consumes a new-User Invite and creates the User.
func (s *Store) AcceptNewInvite(ctx context.Context, token, handle, passwordHash string) (Account, error) {
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		inv, err := s.lookupInvite(ctx, tx, token)
		if err != nil {
			return err
		}
		if inv.Kind != "new" {
			return ErrInvalidToken
		}
		if _, err := tx.Exec(`UPDATE invites SET used_at = ? WHERE hash = ?`, s.unix(), hash(token)); err != nil {
			return err
		}
		id = "us_" + randomHex(8)
		cap := 3
		if inv.DeviceCap > 0 {
			cap = inv.DeviceCap
		}
		var rate any
		if inv.SlowRate > 0 {
			rate = inv.SlowRate
		}
		_, err = tx.Exec(`INSERT INTO users (id, handle, password_hash, is_admin, device_cap, created_at, quota, slow_rate)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id, handle, passwordHash, inv.Admin, cap, s.unix(), inv.Quota, rate)
		if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("handle %q: %w", handle, ErrExists)
		}
		if err != nil {
			return err
		}
		// Preset Refills are given now, so their lifetime counts from
		// registration.
		return s.giveRefills(ctx, tx, id, inv.Refills, inv.RefillTTL)
	})
	if err != nil {
		return Account{}, err
	}
	return s.Account(ctx, id)
}

// AcceptRecoveryInvite consumes a recovery Invite: the User's password is
// replaced, TOTP is turned off, and every session ends. Devices stay.
func (s *Store) AcceptRecoveryInvite(ctx context.Context, token, passwordHash string) (Account, error) {
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		inv, err := s.lookupInvite(ctx, tx, token)
		if err != nil {
			return err
		}
		if inv.Kind != "recovery" {
			return ErrInvalidToken
		}
		id = inv.UserID
		if _, err := tx.Exec(`UPDATE invites SET used_at = ? WHERE hash = ?`, s.unix(), hash(token)); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE users SET password_hash = ?, totp_secret = NULL, totp_pending = NULL WHERE id = ?`, passwordHash, id); err != nil {
			return err
		}
		_, err = tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id)
		return err
	})
	if err != nil {
		return Account{}, err
	}
	return s.Account(ctx, id)
}

// Session is a panel session as stored.
type Session struct {
	UserID    string
	MFA       bool
	ExpiresAt time.Time
}

// CreateSession returns a new session's secret.
func (s *Store) CreateSession(ctx context.Context, userID string, mfa bool, ttl time.Duration) (string, error) {
	token := randomToken()
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (hash, user_id, mfa, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		hash(token), userID, mfa, s.unix(), s.unix()+int64(ttl/time.Second))
	return token, err
}

// LookupSession returns an unexpired session.
func (s *Store) LookupSession(ctx context.Context, token string) (Session, error) {
	var sess Session
	var expires int64
	err := s.db.QueryRowContext(ctx, `SELECT user_id, mfa, expires_at FROM sessions WHERE hash = ?`, hash(token)).
		Scan(&sess.UserID, &sess.MFA, &expires)
	if errors.Is(err, sql.ErrNoRows) || err == nil && s.unix() > expires {
		return Session{}, ErrInvalidToken
	}
	sess.ExpiresAt = time.Unix(expires, 0).UTC()
	return sess, err
}

// SetSessionMFA records that a session proved a second factor.
func (s *Store) SetSessionMFA(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET mfa = 1 WHERE hash = ?`, hash(token))
	return err
}

// DeleteSession ends one session.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE hash = ?`, hash(token))
	return err
}

// DeleteUserSessions ends every session of a User but, optionally, one.
func (s *Store) DeleteUserSessions(ctx context.Context, userID, keepToken string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND hash != ?`, userID, hash(keepToken))
	return err
}

// UserDevice is a Device as its owner and Admins see it.
type UserDevice struct {
	ID        string
	UserID    string
	Seq       int64 // the Device's number, in order of creation
	Name      string
	Address   netip.Addr
	CreatedAt time.Time
	Revoked   bool
}

const userDeviceColumns = `rowid, id, coalesce(user_id, ''), name, address, created_at, revoked_at IS NOT NULL`

func scanUserDevice(row interface{ Scan(...any) error }) (UserDevice, error) {
	var d UserDevice
	var addr string
	var created int64
	err := row.Scan(&d.Seq, &d.ID, &d.UserID, &d.Name, &addr, &created, &d.Revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return UserDevice{}, ErrNotFound
	}
	if err != nil {
		return UserDevice{}, err
	}
	d.Address, d.CreatedAt = netip.MustParseAddr(addr), time.Unix(created, 0).UTC()
	return d, nil
}

// UserDevices returns a User's Devices, revoked ones included, oldest first.
func (s *Store) UserDevices(ctx context.Context, userID string) ([]UserDevice, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userDeviceColumns+` FROM devices WHERE user_id = ? ORDER BY rowid`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserDevice
	for rows.Next() {
		d, err := scanUserDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// UserDevice returns one Device.
func (s *Store) UserDevice(ctx context.Context, id string) (UserDevice, error) {
	return scanUserDevice(s.db.QueryRowContext(ctx, `SELECT `+userDeviceColumns+` FROM devices WHERE id = ?`, id))
}

// AddDevice creates a Device for a User within their Device cap. If
// replaces is set, that Device of the same User is revoked in the same
// transaction, so a replacement never needs room under the cap.
func (s *Store) AddDevice(ctx context.Context, userID, name, publicKey, replaces string) (UserDevice, error) {
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if replaces != "" {
			res, err := tx.Exec(`UPDATE devices SET revoked_at = ?, public_key = NULL WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
				s.unix(), replaces, userID)
			if err != nil {
				return err
			}
			if k, _ := res.RowsAffected(); k == 0 {
				return fmt.Errorf("device %s: %w", replaces, ErrNotFound)
			}
		}
		var active, cap int
		if err := tx.QueryRow(`SELECT count(*) FROM devices WHERE user_id = ? AND revoked_at IS NULL`, userID).Scan(&active); err != nil {
			return err
		}
		if err := tx.QueryRow(`SELECT device_cap FROM users WHERE id = ?`, userID).Scan(&cap); err != nil {
			return err
		}
		if active >= cap {
			return ErrCapReached
		}
		var used int
		if err := tx.QueryRow(`SELECT count(*) FROM devices WHERE public_key = ?`, publicKey).Scan(&used); err != nil {
			return err
		}
		if used > 0 {
			return ErrKeyInUse
		}
		addr, err := nextDeviceAddr(tx)
		if err != nil {
			return err
		}
		id = "dv_" + randomHex(8)
		_, err = tx.Exec(`INSERT INTO devices (id, user_id, name, public_key, address, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			id, userID, name, publicKey, addr.String(), s.unix())
		return err
	})
	if err != nil {
		return UserDevice{}, err
	}
	return s.UserDevice(ctx, id)
}

// nextDeviceAddr is the lowest pool address no Device row holds, skipping
// the network address and the resolver's.
func nextDeviceAddr(tx *sql.Tx) (netip.Addr, error) {
	rows, err := tx.Query(`SELECT address FROM devices`)
	if err != nil {
		return netip.Addr{}, err
	}
	used := map[netip.Addr]bool{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			rows.Close()
			return netip.Addr{}, err
		}
		used[netip.MustParseAddr(a)] = true
	}
	rows.Close()
	a := DevicePool.Addr().Next().Next()
	for used[a] {
		a = a.Next()
	}
	if !DevicePool.Contains(a) {
		return netip.Addr{}, errors.New("device pool exhausted")
	}
	return a, nil
}
