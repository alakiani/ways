package coordinator

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alakiani/ways/internal/auth"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// ADR 0003's lifetimes.
const (
	SessionTTL = 30 * 24 * time.Hour
	InviteTTL  = 7 * 24 * time.Hour
)

// IPv6Placeholder is the ULA /128 every config carries, so dual-stack apps
// keep IPv6 inside the tunnel, where Bridges drop it (ADR 0003).
const IPv6Placeholder = "fd77::1/128"

var handleRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,31}$`)

// limiter refuses sign-ins after too many failures for one handle or one
// address within a window.
type limiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

const (
	maxFailures   = 10
	failureWindow = 15 * time.Minute
)

func (l *limiter) blocked(now time.Time, keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failures == nil {
		l.failures = map[string][]time.Time{}
	}
	for _, k := range keys {
		recent := l.failures[k][:0]
		for _, t := range l.failures[k] {
			if now.Sub(t) < failureWindow {
				recent = append(recent, t)
			}
		}
		l.failures[k] = recent
		if len(recent) >= maxFailures {
			return true
		}
	}
	return false
}

// fail records a failure; call it after blocked, which makes the map.
func (l *limiter) fail(now time.Time, keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		l.failures[k] = append(l.failures[k], now)
	}
}

func (c *Coordinator) meOf(r *http.Request, acct store.Account, mfa bool) (protocol.Me, error) {
	devs, err := c.store.UserDevices(r.Context(), acct.ID)
	if err != nil {
		return protocol.Me{}, err
	}
	return protocol.Me{ID: acct.ID, Handle: acct.Handle, Admin: acct.Admin, TOTPEnabled: acct.TOTPSecret != "",
		MFA: mfa, DeviceCap: acct.DeviceCap, DeviceCount: activeCount(devs)}, nil
}

func activeCount(devs []store.UserDevice) int {
	n := 0
	for _, d := range devs {
		if !d.Revoked {
			n++
		}
	}
	return n
}

func (c *Coordinator) lookupInvite(w http.ResponseWriter, r *http.Request) {
	var req protocol.InviteToken
	if !decode(w, r, &req) {
		return
	}
	inv, err := c.store.LookupInvite(r.Context(), req.Token)
	if errors.Is(err, store.ErrInvalidToken) {
		writeError(w, http.StatusNotFound, "this Invite is used, expired or unknown")
		return
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	info := protocol.InviteInfo{Kind: inv.Kind, Admin: inv.Admin, ExpiresAt: inv.ExpiresAt}
	if inv.Kind == "recovery" {
		if acct, err := c.store.Account(r.Context(), inv.UserID); err == nil {
			info.Handle, info.Admin = acct.Handle, acct.Admin
		}
	}
	writeJSON(w, http.StatusOK, info)
}

func (c *Coordinator) acceptInvite(w http.ResponseWriter, r *http.Request) {
	var req protocol.AcceptInvite
	if !decode(w, r, &req) {
		return
	}
	if err := auth.CheckPassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	inv, err := c.store.LookupInvite(r.Context(), req.Token)
	if errors.Is(err, store.ErrInvalidToken) {
		writeError(w, http.StatusNotFound, "this Invite is used, expired or unknown")
		return
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		c.internalError(w, err)
		return
	}
	var acct store.Account
	if inv.Kind == "recovery" {
		acct, err = c.store.AcceptRecoveryInvite(r.Context(), req.Token, hash)
	} else {
		if !handleRE.MatchString(req.Handle) {
			writeError(w, http.StatusBadRequest, "a handle is 3 to 32 of a-z, 0-9, '.', '_' and '-', starting with a letter or digit")
			return
		}
		acct, err = c.store.AcceptNewInvite(r.Context(), req.Token, req.Handle, hash)
	}
	switch {
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, "that handle is taken")
		return
	case errors.Is(err, store.ErrInvalidToken):
		writeError(w, http.StatusNotFound, "this Invite is used, expired or unknown")
		return
	case err != nil:
		c.internalError(w, err)
		return
	}
	c.log.Info("invite accepted", "kind", inv.Kind, "user", acct.ID)
	if _, err := c.setSession(w, r, acct.ID, false); err != nil {
		c.internalError(w, err)
		return
	}
	me, err := c.meOf(r, acct, false)
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, me)
}

func (c *Coordinator) login(w http.ResponseWriter, r *http.Request) {
	var req protocol.Login
	if !decode(w, r, &req) {
		return
	}
	now := c.store.Now()
	keys := []string{"handle:" + req.Handle, "ip:" + clientIP(r)}
	if c.limit.blocked(now, keys...) {
		writeError(w, http.StatusTooManyRequests, "too many failed sign-ins; try again later")
		return
	}
	acct, err := c.store.AccountByHandle(r.Context(), req.Handle)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		c.internalError(w, err)
		return
	}
	// Verify against a dummy hash for unknown handles, so timing does not
	// tell which handles exist.
	hash := acct.PasswordHash
	if hash == "" {
		hash = dummyHash
	}
	if !auth.VerifyPassword(hash, req.Password) || acct.ID == "" || acct.Suspended {
		c.limit.fail(now, keys...)
		writeError(w, http.StatusUnauthorized, "wrong handle or password")
		return
	}
	mfa := false
	if acct.TOTPSecret != "" {
		if req.TOTPCode == "" {
			writeError(w, http.StatusUnauthorized, "totp_required")
			return
		}
		if !auth.VerifyTOTP(acct.TOTPSecret, req.TOTPCode, now) {
			c.limit.fail(now, keys...)
			writeError(w, http.StatusUnauthorized, "wrong TOTP code")
			return
		}
		mfa = true
	}
	if _, err := c.setSession(w, r, acct.ID, mfa); err != nil {
		c.internalError(w, err)
		return
	}
	me, err := c.meOf(r, acct, mfa)
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, me)
}

var dummyHash, _ = auth.HashPassword("not a real password, only for timing")

func (c *Coordinator) logout(w http.ResponseWriter, r *http.Request) {
	if err := c.store.DeleteSession(r.Context(), callerFrom(r).token); err != nil {
		c.internalError(w, err)
		return
	}
	clearSession(w, c.SecureCookies)
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) logoutEverywhere(w http.ResponseWriter, r *http.Request) {
	if err := c.store.DeleteUserSessions(r.Context(), callerFrom(r).account.ID, ""); err != nil {
		c.internalError(w, err)
		return
	}
	clearSession(w, c.SecureCookies)
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) me(w http.ResponseWriter, r *http.Request) {
	cl := callerFrom(r)
	me, err := c.meOf(r, cl.account, cl.session.MFA)
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, me)
}

func (c *Coordinator) changePassword(w http.ResponseWriter, r *http.Request) {
	cl := callerFrom(r)
	var req protocol.ChangePassword
	if !decode(w, r, &req) {
		return
	}
	if !auth.VerifyPassword(cl.account.PasswordHash, req.Current) {
		writeError(w, http.StatusForbidden, "wrong current password")
		return
	}
	if err := auth.CheckPassword(req.New); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.New)
	if err == nil {
		err = c.store.SetPassword(r.Context(), cl.account.ID, hash)
	}
	if err == nil {
		err = c.store.DeleteUserSessions(r.Context(), cl.account.ID, cl.token)
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) offerTOTP(w http.ResponseWriter, r *http.Request) {
	cl := callerFrom(r)
	if cl.account.TOTPSecret != "" {
		writeError(w, http.StatusConflict, "TOTP is already on")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err == nil {
		err = c.store.SetTOTPPending(r.Context(), cl.account.ID, secret)
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.TOTPOffer{Secret: secret, URI: auth.TOTPURI(secret, cl.account.Handle)})
}

func (c *Coordinator) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	cl := callerFrom(r)
	var req protocol.TOTPCode
	if !decode(w, r, &req) {
		return
	}
	if cl.account.TOTPPending == "" || !auth.VerifyTOTP(cl.account.TOTPPending, req.Code, c.store.Now()) {
		writeError(w, http.StatusForbidden, "wrong TOTP code")
		return
	}
	// Proving the code also proves this session's second factor.
	err := c.store.ConfirmTOTP(r.Context(), cl.account.ID)
	if err == nil {
		err = c.store.SetSessionMFA(r.Context(), cl.token)
	}
	if err == nil {
		err = c.store.DeleteUserSessions(r.Context(), cl.account.ID, cl.token)
	}
	c.respondMe(w, r, cl.account.ID, true, err)
}

func (c *Coordinator) disableTOTP(w http.ResponseWriter, r *http.Request) {
	cl := callerFrom(r)
	var req protocol.TOTPCode
	if !decode(w, r, &req) {
		return
	}
	if cl.account.Admin {
		writeError(w, http.StatusForbidden, "TOTP is mandatory for Admins")
		return
	}
	if cl.account.TOTPSecret == "" || !auth.VerifyTOTP(cl.account.TOTPSecret, req.Code, c.store.Now()) {
		writeError(w, http.StatusForbidden, "wrong TOTP code")
		return
	}
	c.respondMe(w, r, cl.account.ID, false, c.store.ClearTOTP(r.Context(), cl.account.ID))
}

func (c *Coordinator) respondMe(w http.ResponseWriter, r *http.Request, userID string, mfa bool, err error) {
	var acct store.Account
	if err == nil {
		acct, err = c.store.Account(r.Context(), userID)
	}
	var me protocol.Me
	if err == nil {
		me, err = c.meOf(r, acct, mfa)
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, me)
}

func (c *Coordinator) deviceInfo(r *http.Request, d store.UserDevice, acct store.Account) protocol.DeviceInfo {
	quota := c.userQuotaState(r.Context(), acct)
	state, reason := effectiveState(d.Revoked, acct.Suspended, quota)
	recent, err := c.store.RecentBytes(r.Context(), d.ID)
	if err != nil {
		c.log.Error("recent usage", "device", d.ID, "err", err)
	}
	info := protocol.DeviceInfo{ID: d.ID, Name: d.Name, Address: d.Address.String(), CreatedAt: d.CreatedAt,
		Revoked: d.Revoked, State: string(state), Reason: reason, RecentBytes: recent}
	if state == StateThrottled {
		info.Rate = quota.rate
	}
	return info
}

// userQuotaState is what a User's Quota does to their Devices now.
func (c *Coordinator) userQuotaState(ctx context.Context, acct store.Account) quotaState {
	if acct.Quota == nil {
		return quotaState{}
	}
	q, err := c.store.QuotaStanding(ctx, acct.ID)
	if err != nil {
		c.log.Error("quota standing", "user", acct.ID, "err", err)
	}
	return quotaStateOf(q)
}

func (c *Coordinator) deviceUsage(w http.ResponseWriter, r *http.Request) {
	cl := callerFrom(r)
	d, err := c.store.UserDevice(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || err == nil && d.UserID != cl.account.ID {
		writeError(w, http.StatusNotFound, "no such Device of yours")
		return
	}
	var u store.DeviceUsage
	if err == nil {
		u, err = c.store.Usage(r.Context(), d.ID)
	}
	var names map[string]string
	if err == nil {
		names, err = c.nodeNames(r)
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	conv := func(rows []store.UsageRow) []protocol.UsageRow {
		out := []protocol.UsageRow{}
		for _, row := range rows {
			exit := names[row.Exit]
			if exit == "" && row.Exit != "" {
				exit = "?" // a Node since deleted
			}
			out = append(out, protocol.UsageRow{Period: row.Period, Exit: exit, Up: row.Up, Down: row.Down})
		}
		return out
	}
	writeJSON(w, http.StatusOK, protocol.DeviceUsage{Hourly: conv(u.Hourly), Daily: conv(u.Daily),
		Period: protocol.UsageRow{Period: u.Period.Period, Up: u.Period.Up, Down: u.Period.Down}})
}

// nodeNames maps Node ids to names, which usage shows Exits by.
func (c *Coordinator) nodeNames(r *http.Request) (map[string]string, error) {
	nodes, err := c.store.Nodes(r.Context())
	names := map[string]string{}
	for _, n := range nodes {
		names[n.ID] = n.Name
	}
	return names, err
}

func (c *Coordinator) myDevices(w http.ResponseWriter, r *http.Request) {
	c.listDevices(w, r, callerFrom(r).account)
}

func (c *Coordinator) listDevices(w http.ResponseWriter, r *http.Request, acct store.Account) {
	devs, err := c.store.UserDevices(r.Context(), acct.ID)
	if err != nil {
		c.internalError(w, err)
		return
	}
	out := []protocol.DeviceInfo{}
	for _, d := range devs {
		out = append(out, c.deviceInfo(r, d, acct))
	}
	writeJSON(w, http.StatusOK, out)
}

func (c *Coordinator) createDevice(w http.ResponseWriter, r *http.Request) {
	c.issueDevice(w, r, "")
}

func (c *Coordinator) replaceDevice(w http.ResponseWriter, r *http.Request) {
	c.issueDevice(w, r, r.PathValue("id"))
}

// issueDevice creates a Device, revoking replaces in the same step if set.
func (c *Coordinator) issueDevice(w http.ResponseWriter, r *http.Request, replaces string) {
	cl := callerFrom(r)
	var req protocol.NewDevice
	if !decode(w, r, &req) {
		return
	}
	key, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil || key == (wgtypes.Key{}) {
		writeError(w, http.StatusBadRequest, "public_key must be a WireGuard public key")
		return
	}
	if req.Name == "" || len(req.Name) > 64 {
		writeError(w, http.StatusBadRequest, "a Device needs a name of up to 64 characters")
		return
	}
	d, err := c.store.AddDevice(r.Context(), cl.account.ID, req.Name, key.String(), replaces)
	switch {
	case errors.Is(err, store.ErrCapReached):
		writeError(w, http.StatusConflict, "you already have as many Devices as you may; revoke or replace one")
		return
	case errors.Is(err, store.ErrKeyInUse):
		writeError(w, http.StatusConflict, "that key is already in use")
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such Device of yours")
		return
	case err != nil:
		c.internalError(w, err)
		return
	}
	if err := c.Reconcile(r.Context()); err != nil {
		c.internalError(w, err)
		return
	}
	cfg, err := c.deviceConfig(r, d)
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.IssuedDevice{Device: c.deviceInfo(r, d, cl.account), Config: cfg})
}

// deviceConfig is what the browser needs to render a Device's config,
// which reaches whichever Bridge the Bridge Address answers with (ADR 0011).
func (c *Coordinator) deviceConfig(r *http.Request, d store.UserDevice) (protocol.DeviceConfig, error) {
	pub, err := c.BridgePublicKey(r.Context())
	if err != nil {
		return protocol.DeviceConfig{}, err
	}
	b, err := c.bridgeState(r.Context(), nil) // for its address and port only
	if err != nil {
		return protocol.DeviceConfig{}, err
	}
	resolver, _ := netip.ParsePrefix(b.Address)
	cfg := protocol.DeviceConfig{
		Address: netip.PrefixFrom(d.Address, 32).String(), IPv6Placeholder: IPv6Placeholder,
		DNS: resolver.Addr().String(), BridgePublicKey: pub, AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		Endpoint: protocol.Endpoint{Host: c.BridgeAddress, Port: int(b.ListenPort)},
	}
	return cfg, nil
}

func (c *Coordinator) revokeMyDevice(w http.ResponseWriter, r *http.Request) {
	cl := callerFrom(r)
	d, err := c.store.UserDevice(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || err == nil && d.UserID != cl.account.ID {
		writeError(w, http.StatusNotFound, "no such Device of yours")
		return
	}
	c.revoke(w, r, d, cl.account, err)
}

func (c *Coordinator) revoke(w http.ResponseWriter, r *http.Request, d store.UserDevice, owner store.Account, err error) {
	if err == nil {
		err = c.store.RevokeDevice(r.Context(), d.ID)
	}
	if err == nil {
		err = c.Reconcile(r.Context())
	}
	if err == nil {
		d, err = c.store.UserDevice(r.Context(), d.ID)
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c.deviceInfo(r, d, owner))
}

func (c *Coordinator) issueInvite(w http.ResponseWriter, r *http.Request, inv store.Invite) {
	token, expires, err := c.store.CreateInvite(r.Context(), inv, InviteTTL)
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.IssuedInvite{Token: token, URL: c.InviteURL(token), ExpiresAt: expires})
}

// InviteURL is the panel link that carries an Invite. The token is in the
// fragment, which browsers never send to the server.
func (c *Coordinator) InviteURL(token string) string { return c.PanelURL + "/#/invite/" + token }

func (c *Coordinator) adminCreateInvite(w http.ResponseWriter, r *http.Request) {
	var req protocol.CreateInvite
	if !decode(w, r, &req) {
		return
	}
	if req.DeviceCap < 0 || req.DeviceCap > 100 {
		writeError(w, http.StatusBadRequest, "device_cap must be 0 to 100")
		return
	}
	q, msg := quotaSettingOf(req.Quota, req.RunningOut, req.Rate, true)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	ttl, ok := refillTTL(req.RefillDays)
	if req.Refills < 0 || req.Refills > maxRefills || !ok {
		writeError(w, http.StatusBadRequest, "refills must be 0 to 100, and refill_days 1 to 3650")
		return
	}
	c.issueInvite(w, r, store.Invite{Kind: "new", Admin: req.Admin, DeviceCap: req.DeviceCap,
		QuotaSetting: q, Refills: req.Refills, RefillTTL: ttl})
}

func (c *Coordinator) userInfo(r *http.Request, a store.Account) (protocol.UserInfo, error) {
	devs, err := c.store.UserDevices(r.Context(), a.ID)
	if err != nil {
		return protocol.UserInfo{}, err
	}
	refills, err := c.store.HeldRefillCount(r.Context(), a.ID)
	if err != nil {
		return protocol.UserInfo{}, err
	}
	q, err := c.store.QuotaStanding(r.Context(), a.ID)
	u := protocol.UserInfo{Refills: refills, ID: a.ID, Handle: a.Handle, Admin: a.Admin, Suspended: a.Suspended,
		TOTPEnabled: a.TOTPSecret != "", DeviceCap: a.DeviceCap, DeviceCount: activeCount(devs),
		PeriodBytes: q.Usage, PeriodRemedies: q.Remedies, Quota: a.Quota, RenewalDay: q.RenewalDay, RenewsAt: q.Period.End, RunningOut: protocol.RunningOutBlock}
	if a.SlowRate > 0 {
		u.RunningOut, u.Rate = protocol.RunningOutSlow, a.SlowRate
	}
	return u, err
}

func (c *Coordinator) adminUsers(w http.ResponseWriter, r *http.Request) {
	accts, err := c.store.Accounts(r.Context())
	if err != nil {
		c.internalError(w, err)
		return
	}
	out := []protocol.UserInfo{}
	for _, a := range accts {
		u, err := c.userInfo(r, a)
		if err != nil {
			c.internalError(w, err)
			return
		}
		out = append(out, u)
	}
	writeJSON(w, http.StatusOK, out)
}

// target is the User an Admin route names; it answers 404 itself.
func (c *Coordinator) target(w http.ResponseWriter, r *http.Request) (store.Account, bool) {
	a, err := c.store.Account(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such User")
		return a, false
	}
	if err != nil {
		c.internalError(w, err)
		return a, false
	}
	return a, true
}

func (c *Coordinator) adminRecoveryInvite(w http.ResponseWriter, r *http.Request) {
	if a, ok := c.target(w, r); ok {
		c.issueInvite(w, r, store.Invite{Kind: "recovery", UserID: a.ID})
	}
}

func (c *Coordinator) adminSuspend(w http.ResponseWriter, r *http.Request) {
	c.setSuspended(w, r, true)
}
func (c *Coordinator) adminResume(w http.ResponseWriter, r *http.Request) {
	c.setSuspended(w, r, false)
}

func (c *Coordinator) setSuspended(w http.ResponseWriter, r *http.Request, suspended bool) {
	a, ok := c.target(w, r)
	if !ok {
		return
	}
	if a.ID == callerFrom(r).account.ID {
		writeError(w, http.StatusConflict, "you cannot suspend yourself")
		return
	}
	err := c.store.SetUserSuspended(r.Context(), a.ID, suspended)
	if err == nil && suspended {
		err = c.store.DeleteUserSessions(r.Context(), a.ID, "")
	}
	c.afterUserChange(w, r, a.ID, err)
}

func (c *Coordinator) adminSetCap(w http.ResponseWriter, r *http.Request) {
	a, ok := c.target(w, r)
	if !ok {
		return
	}
	var req protocol.SetDeviceCap
	if !decode(w, r, &req) {
		return
	}
	if req.DeviceCap < 0 || req.DeviceCap > 100 {
		writeError(w, http.StatusBadRequest, "device_cap must be 0 to 100")
		return
	}
	// Lowering the cap keeps existing Devices; it only stops new ones.
	c.afterUserChange(w, r, a.ID, c.store.SetDeviceCap(r.Context(), a.ID, req.DeviceCap))
}

func (c *Coordinator) adminSetQuota(w http.ResponseWriter, r *http.Request) {
	a, ok := c.target(w, r)
	if !ok {
		return
	}
	var req protocol.SetQuota
	if !decode(w, r, &req) {
		return
	}
	q, msg := quotaSettingOf(req.Quota, req.RunningOut, req.Rate, false)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	// Every Quota edit takes effect on the next snapshot (ADR 0010).
	c.afterUserChange(w, r, a.ID, c.store.SetQuota(r.Context(), a.ID, q))
}

func (c *Coordinator) afterUserChange(w http.ResponseWriter, r *http.Request, id string, err error) {
	if err == nil {
		err = c.Reconcile(r.Context())
	}
	var a store.Account
	if err == nil {
		a, err = c.store.Account(r.Context(), id)
	}
	var u protocol.UserInfo
	if err == nil {
		u, err = c.userInfo(r, a)
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (c *Coordinator) adminDelete(w http.ResponseWriter, r *http.Request) {
	a, ok := c.target(w, r)
	if !ok {
		return
	}
	if a.ID == callerFrom(r).account.ID {
		writeError(w, http.StatusConflict, "you cannot delete yourself")
		return
	}
	err := c.store.DeleteUser(r.Context(), a.ID)
	if err == nil {
		err = c.Reconcile(r.Context())
	}
	if err != nil {
		c.internalError(w, err)
		return
	}
	c.log.Info("user deleted", "user", a.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) adminUserDevices(w http.ResponseWriter, r *http.Request) {
	if a, ok := c.target(w, r); ok {
		c.listDevices(w, r, a)
	}
}

func (c *Coordinator) adminRevokeDevice(w http.ResponseWriter, r *http.Request) {
	d, err := c.store.UserDevice(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such Device")
		return
	}
	var owner store.Account
	if err == nil && d.UserID != "" {
		owner, err = c.store.Account(r.Context(), d.UserID)
	}
	c.revoke(w, r, d, owner, err)
}
