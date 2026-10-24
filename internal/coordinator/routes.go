package coordinator

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"strings"

	"github.com/alakiani/ways/internal/panel"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// authLevel is who may call a route of the Admin API listener.
type authLevel int

const (
	authNone  authLevel = iota // anyone: Invites and sign-in
	authToken                  // a nodes:enroll API token
	authUser                   // a signed-in User
	authAdmin                  // a signed-in Admin whose session proved TOTP (ADR 0001)
)

// route is one operation of the Admin API listener. The mux and the OpenAPI
// spec are both built from the table, so they cannot drift apart.
type route struct {
	method, path string
	auth         authLevel
	summary      string
	request      any // zero value of the body type, or nil
	response     any // zero value of the 2xx body type, or nil for 204
	handler      http.HandlerFunc
}

func (c *Coordinator) routes() []route {
	return []route{
		// Nodes, for the enroll playbook (ADR 0002).
		{"POST", "/v1/nodes", authToken, "Create a Node, or get a fresh enrollment token for one", protocol.CreateNodeRequest{}, protocol.CreateNodeResponse{}, c.createNode},
		{"GET", "/v1/nodes/{id}", authToken, "Read a Node and its latest health", nil, protocol.NodeStatus{}, c.getNode},

		// Invites and sign-in.
		{"POST", "/v1/invites/lookup", authNone, "See what an Invite offers", protocol.InviteToken{}, protocol.InviteInfo{}, c.lookupInvite},
		{"POST", "/v1/invites/accept", authNone, "Redeem an Invite and sign in", protocol.AcceptInvite{}, protocol.Me{}, c.acceptInvite},
		{"POST", "/v1/login", authNone, "Sign in", protocol.Login{}, protocol.Me{}, c.login},
		{"POST", "/v1/logout", authUser, "End this session", nil, nil, c.logout},
		{"POST", "/v1/me/logout-everywhere", authUser, "End every session of mine, this one too", nil, nil, c.logoutEverywhere},

		// The signed-in User.
		{"GET", "/v1/me", authUser, "The signed-in User", nil, protocol.Me{}, c.me},
		{"POST", "/v1/me/password", authUser, "Change password; ends every other session", protocol.ChangePassword{}, nil, c.changePassword},
		{"POST", "/v1/me/totp", authUser, "Offer a new TOTP secret", nil, protocol.TOTPOffer{}, c.offerTOTP},
		{"POST", "/v1/me/totp/confirm", authUser, "Confirm the offered TOTP secret with a code", protocol.TOTPCode{}, protocol.Me{}, c.confirmTOTP},
		{"POST", "/v1/me/totp/disable", authUser, "Turn TOTP off (not allowed for Admins)", protocol.TOTPCode{}, protocol.Me{}, c.disableTOTP},
		{"GET", "/v1/me/devices", authUser, "My Devices", nil, []protocol.DeviceInfo{}, c.myDevices},
		{"POST", "/v1/me/devices", authUser, "Create a Device from a public key made in the browser", protocol.NewDevice{}, protocol.IssuedDevice{}, c.createDevice},
		{"GET", "/v1/me/devices/{id}/usage", authUser, "One of my Devices' usage: hourly, daily, and in this Quota Period", nil, protocol.DeviceUsage{}, c.deviceUsage},
		{"GET", "/v1/me/usage", authUser, "My Usage and Quota: this Quota Period, past ones, the Device split and held Refills", nil, protocol.MyUsage{}, c.myUsage},
		{"POST", "/v1/me/refills/{id}/redeem", authUser, "Redeem a held Refill: a Reset of this Quota Period. Unlimited Quotas can't", nil, protocol.MyUsage{}, c.redeemRefill},
		{"POST", "/v1/me/devices/{id}/revoke", authUser, "Revoke one of my Devices", nil, protocol.DeviceInfo{}, c.revokeMyDevice},
		{"POST", "/v1/me/devices/{id}/replace", authUser, "Issue a new Device and revoke this one in one step", protocol.NewDevice{}, protocol.IssuedDevice{}, c.replaceDevice},

		// Admins.
		{"POST", "/v1/admin/invites", authAdmin, "Create a new-User Invite", protocol.CreateInvite{}, protocol.IssuedInvite{}, c.adminCreateInvite},
		{"GET", "/v1/admin/users", authAdmin, "Every User", nil, []protocol.UserInfo{}, c.adminUsers},
		{"POST", "/v1/admin/users/{id}/recovery-invite", authAdmin, "Create a recovery Invite: new credentials, same Devices", nil, protocol.IssuedInvite{}, c.adminRecoveryInvite},
		{"POST", "/v1/admin/users/{id}/suspend", authAdmin, "Suspend a User: their Devices leave the Bridges", nil, protocol.UserInfo{}, c.adminSuspend},
		{"POST", "/v1/admin/users/{id}/resume", authAdmin, "Resume a suspended User", nil, protocol.UserInfo{}, c.adminResume},
		{"POST", "/v1/admin/users/{id}/device-cap", authAdmin, "Set a User's Device cap", protocol.SetDeviceCap{}, protocol.UserInfo{}, c.adminSetCap},
		{"POST", "/v1/admin/users/{id}/quota", authAdmin, "Set a User's Quota (bytes per Quota Period, or null for unlimited) and what happens when they run out", protocol.SetQuota{}, protocol.UserInfo{}, c.adminSetQuota},
		{"POST", "/v1/admin/users/{id}/top-up", authAdmin, "Add bytes to what a User may use in this Quota Period only", protocol.TopUp{}, protocol.UserInfo{}, c.adminTopUp},
		{"POST", "/v1/admin/users/{id}/reset", authAdmin, "Reset now: bring a User back to a full Quota (not for unlimited Quotas)", nil, protocol.UserInfo{}, c.adminReset},
		{"POST", "/v1/admin/users/{id}/refills", authAdmin, "Give a User Refills to hold, each with its expiry", protocol.GiveRefills{}, protocol.UserInfo{}, c.adminGiveRefills},
		{"DELETE", "/v1/admin/users/{id}", authAdmin, "Delete a User with their Devices and usage", nil, nil, c.adminDelete},
		{"GET", "/v1/admin/overview", authAdmin, "The status board: Nodes, Links, the feed", nil, protocol.Overview{}, c.adminOverview},
		{"GET", "/v1/admin/invites", authAdmin, "Invites, newest first", nil, []protocol.InviteRecord{}, c.adminInvites},
		{"POST", "/v1/admin/invites/{id}/withdraw", authAdmin, "Withdraw an open Invite", nil, nil, c.adminWithdrawInvite},
		{"GET", "/v1/admin/nodes", authAdmin, "Every Node", nil, []protocol.NodeTile{}, c.adminNodes},
		{"POST", "/v1/admin/nodes", authAdmin, "Add a Node and get its enroll command", protocol.NewNode{}, protocol.EnrollCommand{}, c.adminCreateNode},
		{"GET", "/v1/admin/nodes/{id}", authAdmin, "A Node with its Links and Paths", nil, protocol.NodeDetail{}, c.adminNode},
		{"POST", "/v1/admin/nodes/{id}", authAdmin, "Change a Node's Roles and Tags", protocol.NodeEdit{}, protocol.NodeStatus{}, c.adminEditNode},
		{"DELETE", "/v1/admin/nodes/{id}", authAdmin, "Delete a Node; its certificate stops working", nil, nil, c.adminDeleteNode},
		{"GET", "/v1/admin/links", authAdmin, "Every Link with its health", nil, []protocol.LinkTile{}, c.adminLinks},
		{"GET", "/v1/admin/transports", authAdmin, "The candidate Transport list", nil, protocol.TransportList{}, c.adminTransports},
		{"POST", "/v1/admin/transports", authAdmin, "Change the candidate Transport list", protocol.TransportList{}, protocol.TransportList{}, c.adminSetTransports},
		{"GET", "/v1/admin/rules", authAdmin, "The Rules", nil, []protocol.RuleInfo{}, c.adminRules},
		{"POST", "/v1/admin/rules/{id}", authAdmin, "Change the IR Rule's Tags and fallback", protocol.RuleEdit{}, []protocol.RuleInfo{}, c.adminEditRule},
		{"GET", "/v1/admin/sets", authAdmin, "Destination Sets with their feeds", nil, []protocol.SetInfo{}, c.adminSets},
		{"POST", "/v1/admin/sets/{id}/fetch", authAdmin, "Fetch a set's feed now", nil, []protocol.SetInfo{}, c.adminFetchSet},
		{"POST", "/v1/admin/sets/{id}/rollback", authAdmin, "Roll a set's feed back to its previous good update", nil, []protocol.SetInfo{}, c.adminRollBackSet},
		{"POST", "/v1/admin/sets/{id}/overrides", authAdmin, "Replace a set's Admin additions and removals", protocol.Overrides{}, []protocol.SetInfo{}, c.adminSetOverrides},
		{"GET", "/v1/admin/tokens", authAdmin, "API tokens", nil, []protocol.TokenInfo{}, c.adminTokens},
		{"POST", "/v1/admin/tokens", authAdmin, "Make a nodes:enroll token; its secret is shown once", protocol.NewToken{}, protocol.IssuedToken{}, c.adminCreateToken},
		{"POST", "/v1/admin/tokens/{id}/revoke", authAdmin, "Revoke an API token", nil, nil, c.adminRevokeToken},
		{"GET", "/v1/admin/users/{id}/devices", authAdmin, "A User's Devices", nil, []protocol.DeviceInfo{}, c.adminUserDevices},
		{"POST", "/v1/admin/devices/{id}/revoke", authAdmin, "Revoke any Device", nil, protocol.DeviceInfo{}, c.adminRevokeDevice},

		{"GET", "/v1/openapi.json", authNone, "This API's OpenAPI description", nil, nil, c.serveSpec},
	}
}

// AdminHandler serves the Admin API listener: the panel's API and the
// enroll playbook's.
func (c *Coordinator) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	for _, r := range c.routes() {
		var h http.Handler
		switch r.auth {
		case authNone:
			h = r.handler
		case authToken:
			h = c.requireScope(store.ScopeNodesEnroll, r.handler)
		case authUser:
			h = c.requireSession(false, r.handler)
		case authAdmin:
			h = c.requireSession(true, r.handler)
		}
		if r.request != nil || r.method != "GET" {
			h = requireJSON(h)
		}
		mux.Handle(r.method+" "+r.path, h)
	}
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		mux.HandleFunc(m+" /grafana/", c.grafana)
	}
	mux.Handle("GET /", panel.Handler())
	return mux
}

// requireJSON refuses state-changing requests that are not JSON. A
// cross-site form cannot send application/json without a CORS preflight,
// which this API never grants, so this and SameSite=Strict cookies close
// off CSRF.
func requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, "requests must be application/json")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

const sessionCookie = "ways_session"

type sessionKey struct{}

// caller is the signed-in User of a request.
type caller struct {
	account store.Account
	session store.Session
	token   string
}

func callerFrom(r *http.Request) caller { return r.Context().Value(sessionKey{}).(caller) }

// requireSession admits a request with a live session of a User who is not
// suspended; with admin set, only an Admin whose session proved TOTP.
func (c *Coordinator) requireSession(admin bool, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, status, msg, err := c.authenticate(r, admin)
		if err != nil {
			c.internalError(w, err)
			return
		}
		if status != 0 {
			writeError(w, status, msg)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, cl)))
	})
}

// authenticate is requireSession's check. A refused request gets a status
// and message; err is set only when the store failed.
func (c *Coordinator) authenticate(r *http.Request, admin bool) (cl caller, status int, msg string, err error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return caller{}, http.StatusUnauthorized, "not signed in", nil
	}
	sess, err := c.store.LookupSession(r.Context(), cookie.Value)
	if errors.Is(err, store.ErrInvalidToken) {
		return caller{}, http.StatusUnauthorized, "session expired", nil
	}
	if err != nil {
		return caller{}, 0, "", err
	}
	acct, err := c.store.Account(r.Context(), sess.UserID)
	if err != nil || acct.Suspended {
		return caller{}, http.StatusUnauthorized, "not signed in", nil
	}
	if admin {
		switch {
		case !acct.Admin:
			return caller{}, http.StatusForbidden, "Admins only", nil
		case acct.TOTPSecret == "":
			return caller{}, http.StatusForbidden, "Admins must turn on TOTP first", nil
		case !sess.MFA:
			return caller{}, http.StatusForbidden, "sign in again with your TOTP code", nil
		}
	}
	return caller{account: acct, session: sess, token: cookie.Value}, 0, "", nil
}

// setSession starts a session and hands its cookie to the browser.
func (c *Coordinator) setSession(w http.ResponseWriter, r *http.Request, userID string, mfa bool) (string, error) {
	token, err := c.store.CreateSession(r.Context(), userID, mfa, SessionTTL)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		MaxAge: int(SessionTTL.Seconds()), HttpOnly: true, Secure: c.SecureCookies, SameSite: http.SameSiteStrictMode,
	})
	return token, nil
}

func clearSession(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteStrictMode})
}

// clientIP is the address a request came from, for rate limiting.
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return host
}
