package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alakiani/ways/internal/auth"
	"github.com/alakiani/ways/internal/ca"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// covered records every route pattern that answered 2xx in some test, so
// TestMain can insist that every operation has an API test.
var covered sync.Map

func TestMain(m *testing.M) {
	code := m.Run()
	if !testing.Short() && flagRanEverything() {
		c := New(nil, nil, slog.New(slog.DiscardHandler))
		var missing []string
		for _, r := range c.routes() {
			if _, ok := covered.Load(r.method + " " + r.path); !ok {
				missing = append(missing, r.method+" "+r.path)
			}
		}
		if len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "operations with no successful API test:\n  %s\n", strings.Join(missing, "\n  "))
			code = 1
		}
	}
	os.Exit(code)
}

// flagRanEverything is false when -run narrows the tests.
func flagRanEverything() bool {
	for _, a := range os.Args {
		if strings.HasPrefix(a, "-test.run") {
			return false
		}
	}
	return true
}

type api struct {
	t     *testing.T
	c     *Coordinator
	s     *store.Store
	srv   *httptest.Server
	clock *time.Time
}

func newAPI(t *testing.T) *api {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "ways.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	now := time.Now()
	s.Now = func() time.Time { return now }
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := New(s, authority, slog.New(slog.DiscardHandler))
	c.SecureCookies = false // httptest serves plain HTTP
	mux := c.AdminHandler().(*http.ServeMux)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		mux.ServeHTTP(rec, r)
		if rec.status < 300 {
			covered.Store(pattern, true)
		}
	}))
	t.Cleanup(srv.Close)
	return &api{t: t, c: c, s: s, srv: srv, clock: &now}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) { r.status = code; r.ResponseWriter.WriteHeader(code) }

// tick moves the store's clock on.
func (a *api) tick(d time.Duration) { *a.clock = a.clock.Add(d) }

type client struct {
	a    *api
	http *http.Client
}

func (a *api) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{a: a, http: &http.Client{Jar: jar}}
}

// call sends a JSON request and decodes a 2xx JSON answer into out.
func (cl *client) call(method, path string, body, out any) int {
	cl.a.t.Helper()
	var buf bytes.Buffer
	if body == nil {
		body = struct{}{}
	}
	json.NewEncoder(&buf).Encode(body)
	req, _ := http.NewRequest(method, cl.a.srv.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.http.Do(req)
	if err != nil {
		cl.a.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(b, out); err != nil {
			cl.a.t.Fatalf("%s %s: %v: %s", method, path, err, b)
		}
	}
	return resp.StatusCode
}

// must is call that fails the test unless the answer is want.
func (cl *client) must(want int, method, path string, body, out any) {
	cl.a.t.Helper()
	if got := cl.call(method, path, body, out); got != want {
		cl.a.t.Fatalf("%s %s: status %d, want %d", method, path, got, want)
	}
}

const password = "a long enough password"

// invite creates an Invite directly, as the bootstrap CLI does.
func (a *api) invite(inv store.Invite) string {
	tok, _, err := a.s.CreateInvite(context.Background(), inv, InviteTTL)
	if err != nil {
		a.t.Fatal(err)
	}
	return tok
}

// user is a signed-in User created through an Invite.
func (a *api) user(handle string) (*client, protocol.Me) {
	a.t.Helper()
	cl := a.client()
	var me protocol.Me
	cl.must(200, "POST", "/v1/invites/accept", protocol.AcceptInvite{Token: a.invite(store.Invite{Kind: "new"}), Handle: handle, Password: password}, &me)
	return cl, me
}

// enrollTOTP turns TOTP on for cl's User and returns the secret.
func (cl *client) enrollTOTP() string {
	cl.a.t.Helper()
	var offer protocol.TOTPOffer
	cl.must(200, "POST", "/v1/me/totp", nil, &offer)
	cl.must(200, "POST", "/v1/me/totp/confirm", protocol.TOTPCode{Code: auth.TOTP(offer.Secret, *cl.a.clock)}, nil)
	return offer.Secret
}

// admin is a signed-in Admin with TOTP, whose session proved it.
func (a *api) admin() *client {
	a.t.Helper()
	cl := a.client()
	cl.must(200, "POST", "/v1/invites/accept", protocol.AcceptInvite{Token: a.invite(store.Invite{Kind: "new", Admin: true}), Handle: "admin", Password: password}, nil)
	cl.enrollTOTP()
	return cl
}

func pubKey(t *testing.T) string {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().String()
}

func TestInviteSignInAndOut(t *testing.T) {
	a := newAPI(t)
	tok := a.invite(store.Invite{Kind: "new", DeviceCap: 5})
	cl := a.client()

	var info protocol.InviteInfo
	cl.must(200, "POST", "/v1/invites/lookup", protocol.InviteToken{Token: tok}, &info)
	if info.Kind != "new" || info.Admin {
		t.Errorf("invite info = %+v", info)
	}
	cl.must(404, "POST", "/v1/invites/lookup", protocol.InviteToken{Token: "nope"}, nil)
	cl.must(400, "POST", "/v1/invites/accept", protocol.AcceptInvite{Token: tok, Handle: "maryam", Password: "short"}, nil)
	cl.must(400, "POST", "/v1/invites/accept", protocol.AcceptInvite{Token: tok, Handle: "Bad Handle!", Password: password}, nil)

	var me protocol.Me
	cl.must(200, "POST", "/v1/invites/accept", protocol.AcceptInvite{Token: tok, Handle: "maryam", Password: password}, &me)
	if me.Handle != "maryam" || me.DeviceCap != 5 || me.Admin || me.MFA {
		t.Errorf("me = %+v", me)
	}
	cl.must(404, "POST", "/v1/invites/accept", protocol.AcceptInvite{Token: tok, Handle: "again", Password: password}, nil)
	cl.must(200, "GET", "/v1/me", nil, &me)

	// The handle is taken now.
	other := a.client()
	other.must(409, "POST", "/v1/invites/accept", protocol.AcceptInvite{Token: a.invite(store.Invite{Kind: "new"}), Handle: "maryam", Password: password}, nil)

	cl.must(204, "POST", "/v1/logout", nil, nil)
	cl.must(401, "GET", "/v1/me", nil, nil)
	cl.must(200, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: password}, &me)
	cl.must(200, "GET", "/v1/me", nil, nil)
}

func TestStateChangesMustBeJSON(t *testing.T) {
	a := newAPI(t)
	cl, _ := a.user("maryam")
	req, _ := http.NewRequest("POST", a.srv.URL+"/v1/logout", strings.NewReader("x=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := cl.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("form POST: status %d, want 415", resp.StatusCode)
	}
	cl.must(200, "GET", "/v1/me", nil, nil) // still signed in
}

func TestSessionCookieIsLockedDown(t *testing.T) {
	a := newAPI(t)
	a.c.SecureCookies = true
	body, _ := json.Marshal(protocol.AcceptInvite{Token: a.invite(store.Invite{Kind: "new"}), Handle: "maryam", Password: password})
	resp, err := http.Post(a.srv.URL+"/v1/invites/accept", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cookie := resp.Header.Get("Set-Cookie")
	for _, want := range []string{"ways_session=", "HttpOnly", "Secure", "SameSite=Strict", "Max-Age=2592000"} {
		if !strings.Contains(cookie, want) {
			t.Errorf("cookie %q lacks %s", cookie, want)
		}
	}
}

func TestLoginFailuresAndLimits(t *testing.T) {
	a := newAPI(t)
	a.user("maryam")
	cl := a.client()
	cl.must(401, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: "wrong password!"}, nil)
	cl.must(401, "POST", "/v1/login", protocol.Login{Handle: "nobody", Password: password}, nil)
	for i := 0; i < 10; i++ {
		cl.call("POST", "/v1/login", protocol.Login{Handle: "maryam", Password: "wrong password!"}, nil)
	}
	cl.must(429, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: password}, nil)
	a.tick(failureWindow)
	cl.must(200, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: password}, nil)
}

func TestTOTP(t *testing.T) {
	a := newAPI(t)
	cl, _ := a.user("maryam")
	var offer protocol.TOTPOffer
	cl.must(200, "POST", "/v1/me/totp", nil, &offer)
	if !strings.HasPrefix(offer.URI, "otpauth://totp/WAYS:maryam?") {
		t.Errorf("uri = %s", offer.URI)
	}
	cl.must(403, "POST", "/v1/me/totp/confirm", protocol.TOTPCode{Code: "000000"}, nil)
	var me protocol.Me
	cl.must(200, "POST", "/v1/me/totp/confirm", protocol.TOTPCode{Code: auth.TOTP(offer.Secret, *a.clock)}, &me)
	if !me.TOTPEnabled || !me.MFA {
		t.Errorf("after confirming: %+v", me)
	}
	cl.must(409, "POST", "/v1/me/totp", nil, nil)

	// Signing in now needs a code.
	other := a.client()
	other.must(401, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: password}, nil)
	other.must(401, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: password, TOTPCode: "123456"}, nil)
	other.must(200, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: password, TOTPCode: auth.TOTP(offer.Secret, *a.clock)}, &me)
	if !me.MFA {
		t.Error("a session signed in with a code has no MFA")
	}

	// A User may turn it off with a code.
	cl.must(403, "POST", "/v1/me/totp/disable", protocol.TOTPCode{Code: "000000"}, nil)
	cl.must(200, "POST", "/v1/me/totp/disable", protocol.TOTPCode{Code: auth.TOTP(offer.Secret, *a.clock)}, &me)
	if me.TOTPEnabled {
		t.Error("TOTP still on")
	}
}

func TestAdminActionsNeedTOTP(t *testing.T) {
	a := newAPI(t)
	cl := a.client()
	cl.must(200, "POST", "/v1/invites/accept", protocol.AcceptInvite{Token: a.invite(store.Invite{Kind: "new", Admin: true}), Handle: "admin", Password: password}, nil)
	cl.must(403, "GET", "/v1/admin/users", nil, nil) // no TOTP yet
	secret := cl.enrollTOTP()
	cl.must(200, "GET", "/v1/admin/users", nil, nil)

	// A session without the code cannot act as Admin, and an Admin cannot
	// turn TOTP off.
	cl.must(403, "POST", "/v1/me/totp/disable", protocol.TOTPCode{Code: auth.TOTP(secret, *a.clock)}, nil)
	fresh := a.client()
	fresh.must(401, "POST", "/v1/login", protocol.Login{Handle: "admin", Password: password}, nil)
	fresh.must(200, "POST", "/v1/login", protocol.Login{Handle: "admin", Password: password, TOTPCode: auth.TOTP(secret, *a.clock)}, nil)
	fresh.must(200, "GET", "/v1/admin/users", nil, nil)

	user, _ := a.user("maryam")
	user.must(403, "GET", "/v1/admin/users", nil, nil)
	a.client().must(401, "GET", "/v1/admin/users", nil, nil)
}

func TestChangePasswordEndsOtherSessions(t *testing.T) {
	a := newAPI(t)
	cl, _ := a.user("maryam")
	other := a.client()
	other.must(200, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: password}, nil)
	cl.must(403, "POST", "/v1/me/password", protocol.ChangePassword{Current: "wrong one!!", New: "a new long password"}, nil)
	cl.must(400, "POST", "/v1/me/password", protocol.ChangePassword{Current: password, New: "short"}, nil)
	cl.must(204, "POST", "/v1/me/password", protocol.ChangePassword{Current: password, New: "a new long password"}, nil)
	cl.must(200, "GET", "/v1/me", nil, nil)
	other.must(401, "GET", "/v1/me", nil, nil)
	a.client().must(200, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: "a new long password"}, nil)
}

func TestDevices(t *testing.T) {
	a := newAPI(t)
	cl, _ := a.user("maryam")
	cl.must(400, "POST", "/v1/me/devices", protocol.NewDevice{Name: "phone", PublicKey: "not a key"}, nil)
	cl.must(400, "POST", "/v1/me/devices", protocol.NewDevice{PublicKey: pubKey(t)}, nil)

	var issued protocol.IssuedDevice
	cl.must(200, "POST", "/v1/me/devices", protocol.NewDevice{Name: "phone", PublicKey: pubKey(t)}, &issued)
	cfg := issued.Config
	if issued.Device.State != "active" || cfg.Address != issued.Device.Address+"/32" || cfg.DNS != "10.77.0.1" ||
		cfg.IPv6Placeholder != IPv6Placeholder || !slices.Equal(cfg.AllowedIPs, []string{"0.0.0.0/0", "::/0"}) {
		t.Errorf("issued = %+v", issued)
	}
	pub, _ := a.c.BridgePublicKey(context.Background())
	if cfg.BridgePublicKey != pub {
		t.Error("config names another Bridge key")
	}
	// One config, reaching whichever Bridge the Bridge Address answers with.
	if cfg.Endpoint != (protocol.Endpoint{Host: "bridge.wayfinder.ir", Port: DefaultDevicePort}) {
		t.Errorf("endpoint = %+v", cfg.Endpoint)
	}
	var second protocol.IssuedDevice
	cl.must(200, "POST", "/v1/me/devices", protocol.NewDevice{Name: "laptop", PublicKey: pubKey(t)}, &second)
	if second.Config.Endpoint != cfg.Endpoint {
		t.Errorf("a second Device reaches %+v", second.Config.Endpoint)
	}
	cl.must(200, "POST", "/v1/me/devices", protocol.NewDevice{Name: "tablet", PublicKey: pubKey(t)}, nil)
	cl.must(409, "POST", "/v1/me/devices", protocol.NewDevice{Name: "fourth", PublicKey: pubKey(t)}, nil) // cap 3

	// Replace issues a new Device and revokes the old one in one step.
	var replaced protocol.IssuedDevice
	cl.must(200, "POST", "/v1/me/devices/"+issued.Device.ID+"/replace", protocol.NewDevice{Name: "phone", PublicKey: pubKey(t)}, &replaced)
	if replaced.Device.ID == issued.Device.ID || replaced.Device.Address == issued.Device.Address {
		t.Errorf("replacement = %+v", replaced.Device)
	}
	var revoked protocol.DeviceInfo
	cl.must(200, "POST", "/v1/me/devices/"+second.Device.ID+"/revoke", nil, &revoked)
	if !revoked.Revoked || revoked.State != "blocked" {
		t.Errorf("revoked = %+v", revoked)
	}
	var list []protocol.DeviceInfo
	cl.must(200, "GET", "/v1/me/devices", nil, &list)
	if len(list) != 4 {
		t.Errorf("%d devices listed, want 4 (two revoked)", len(list))
	}

	// Nobody touches another User's Devices.
	other, _ := a.user("reza")
	other.must(404, "POST", "/v1/me/devices/"+replaced.Device.ID+"/revoke", nil, nil)
	other.must(404, "POST", "/v1/me/devices/"+replaced.Device.ID+"/replace", protocol.NewDevice{Name: "x", PublicKey: pubKey(t)}, nil)
}

// bridgeDevices is what a Bridge's snapshot lets in.
func (a *api) bridgeDevices(bridgeID string) []string {
	a.t.Helper()
	snap, err := a.s.LatestSnapshot(context.Background(), bridgeID)
	if err != nil {
		a.t.Fatal(err)
	}
	var st protocol.State
	json.Unmarshal(snap.Body, &st)
	var keys []string
	for _, d := range st.Bridge.Devices {
		keys = append(keys, d.PublicKey)
	}
	return keys
}

func TestSuspendedUsersDevicesLeaveTheBridgesAndReturnOnResume(t *testing.T) {
	a := newAPI(t)
	bridge, err := a.s.CreateNode(context.Background(), "ir1", []protocol.Role{protocol.RoleBridge}, []string{"IR"})
	if err != nil {
		t.Fatal(err)
	}
	admin := a.admin()
	cl, me := a.user("maryam")
	key := pubKey(t)
	cl.must(200, "POST", "/v1/me/devices", protocol.NewDevice{Name: "phone", PublicKey: key}, nil)
	if !slices.Contains(a.bridgeDevices(bridge.ID), key) {
		t.Fatal("a new Device is not on the Bridge")
	}

	var u protocol.UserInfo
	admin.must(200, "POST", "/v1/admin/users/"+me.ID+"/suspend", nil, &u)
	if !u.Suspended {
		t.Errorf("suspend answered %+v", u)
	}
	if slices.Contains(a.bridgeDevices(bridge.ID), key) {
		t.Error("a suspended User's Device is still on the Bridge")
	}
	cl.must(401, "GET", "/v1/me", nil, nil) // their sessions ended
	a.client().must(401, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: password}, nil)
	var devs []protocol.DeviceInfo
	admin.must(200, "GET", "/v1/admin/users/"+me.ID+"/devices", nil, &devs)
	if len(devs) != 1 || devs[0].State != "blocked" || devs[0].Reason != "user suspended" {
		t.Errorf("devices while suspended = %+v", devs)
	}

	admin.must(200, "POST", "/v1/admin/users/"+me.ID+"/resume", nil, &u)
	if u.Suspended || !slices.Contains(a.bridgeDevices(bridge.ID), key) {
		t.Error("the Device did not return on resume")
	}
	a.client().must(200, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: password}, nil)
}

func TestAdminUserOperations(t *testing.T) {
	a := newAPI(t)
	bridge, _ := a.s.CreateNode(context.Background(), "ir1", []protocol.Role{protocol.RoleBridge}, nil)
	admin := a.admin()

	var inv protocol.IssuedInvite
	admin.must(200, "POST", "/v1/admin/invites", protocol.CreateInvite{DeviceCap: 1}, &inv)
	if !strings.HasPrefix(inv.URL, "https://wayfinder.ir/#/invite/") || !strings.HasSuffix(inv.URL, inv.Token) {
		t.Errorf("invite url = %s", inv.URL)
	}
	admin.must(400, "POST", "/v1/admin/invites", protocol.CreateInvite{DeviceCap: -1}, nil)
	cl := a.client()
	var me protocol.Me
	cl.must(200, "POST", "/v1/invites/accept", protocol.AcceptInvite{Token: inv.Token, Handle: "maryam", Password: password}, &me)
	if me.DeviceCap != 1 {
		t.Errorf("preset cap = %d", me.DeviceCap)
	}

	var users []protocol.UserInfo
	admin.must(200, "GET", "/v1/admin/users", nil, &users)
	if len(users) != 2 {
		t.Errorf("%d users, want 2", len(users))
	}
	var u protocol.UserInfo
	admin.must(200, "POST", "/v1/admin/users/"+me.ID+"/device-cap", protocol.SetDeviceCap{DeviceCap: 4}, &u)
	if u.DeviceCap != 4 {
		t.Errorf("cap = %d", u.DeviceCap)
	}
	admin.must(404, "POST", "/v1/admin/users/us_nope/suspend", nil, nil)
	var adminMe protocol.Me
	admin.must(200, "GET", "/v1/me", nil, &adminMe)
	admin.must(409, "POST", "/v1/admin/users/"+adminMe.ID+"/suspend", nil, nil)
	admin.must(409, "DELETE", "/v1/admin/users/"+adminMe.ID, nil, nil)

	// An Admin revokes any Device.
	key := pubKey(t)
	var issued protocol.IssuedDevice
	cl.must(200, "POST", "/v1/me/devices", protocol.NewDevice{Name: "phone", PublicKey: key}, &issued)
	var d protocol.DeviceInfo
	admin.must(200, "POST", "/v1/admin/devices/"+issued.Device.ID+"/revoke", nil, &d)
	if !d.Revoked || slices.Contains(a.bridgeDevices(bridge.ID), key) {
		t.Error("an Admin's revoke did not take the Device off the Bridge")
	}

	// A recovery Invite replaces credentials and keeps Devices.
	cl.must(200, "POST", "/v1/me/devices", protocol.NewDevice{Name: "laptop", PublicKey: pubKey(t)}, nil)
	admin.must(200, "POST", "/v1/admin/users/"+me.ID+"/recovery-invite", nil, &inv)
	var info protocol.InviteInfo
	a.client().must(200, "POST", "/v1/invites/lookup", protocol.InviteToken{Token: inv.Token}, &info)
	if info.Kind != "recovery" || info.Handle != "maryam" {
		t.Errorf("recovery invite info = %+v", info)
	}
	rec := a.client()
	rec.must(200, "POST", "/v1/invites/accept", protocol.AcceptInvite{Token: inv.Token, Password: "the recovered password"}, &me)
	if me.Handle != "maryam" || me.DeviceCount != 1 {
		t.Errorf("after recovery: %+v", me)
	}
	cl.must(401, "GET", "/v1/me", nil, nil)
	a.client().must(401, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: password}, nil)

	// Delete removes the User and their Devices.
	admin.must(204, "DELETE", "/v1/admin/users/"+me.ID, nil, nil)
	if keys := a.bridgeDevices(bridge.ID); len(keys) != 0 {
		t.Errorf("devices of a deleted User remain: %v", keys)
	}
	admin.must(404, "GET", "/v1/admin/users/"+me.ID+"/devices", nil, nil)
}

func TestNodesRoutesAndSpec(t *testing.T) {
	a := newAPI(t)
	secret, _, err := a.s.CreateAPIToken(context.Background(), store.ScopeNodesEnroll, "laptop", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, body any) int {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, a.srv.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out protocol.CreateNodeResponse
		json.NewDecoder(resp.Body).Decode(&out)
		if out.Node.ID != "" {
			a.t.Setenv("WAYS_TEST_NODE", out.Node.ID)
		}
		return resp.StatusCode
	}
	if got := call("POST", "/v1/nodes", protocol.CreateNodeRequest{Name: "b1", Roles: []protocol.Role{"bridge"}}); got != 200 {
		t.Fatalf("create node: %d", got)
	}
	if got := call("GET", "/v1/nodes/"+os.Getenv("WAYS_TEST_NODE"), nil); got != 200 {
		t.Errorf("get node: %d", got)
	}
	resp, err := http.Get(a.srv.URL + "/v1/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var spec map[string]any
	if json.NewDecoder(resp.Body).Decode(&spec) != nil || spec["openapi"] != "3.1.0" {
		t.Errorf("served spec = %v", spec["openapi"])
	}
}

func TestLogoutEverywhere(t *testing.T) {
	a := newAPI(t)
	cl, _ := a.user("maryam")
	other := a.client()
	other.must(200, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: password}, nil)
	cl.must(204, "POST", "/v1/me/logout-everywhere", nil, nil)
	cl.must(401, "GET", "/v1/me", nil, nil)
	other.must(401, "GET", "/v1/me", nil, nil)
}

func TestDeviceUsage(t *testing.T) {
	a := newAPI(t)
	exit, _ := a.s.CreateNode(context.Background(), "ab1", []protocol.Role{protocol.RoleExit}, nil)
	admin := a.admin()
	cl, me := a.user("maryam")
	var issued protocol.IssuedDevice
	cl.must(200, "POST", "/v1/me/devices", protocol.NewDevice{Name: "phone", PublicKey: pubKey(t)}, &issued)
	hour := a.clock.UTC().Truncate(time.Hour)
	if _, err := a.s.PutUsage(context.Background(), "nd_bridge", []protocol.UsageBucket{
		{Hour: hour.Unix(), Device: issued.Device.Address, Exit: exit.ID, Up: 1000, Down: 5000},
	}); err != nil {
		t.Fatal(err)
	}

	var u protocol.DeviceUsage
	cl.must(200, "GET", "/v1/me/devices/"+issued.Device.ID+"/usage", nil, &u)
	if len(u.Hourly) != 1 || u.Hourly[0].Exit != "ab1" || u.Hourly[0].Up != 1000 || u.Hourly[0].Down != 5000 {
		t.Errorf("hourly = %+v", u.Hourly)
	}
	if len(u.Daily) != 1 || u.Period.Up != 1000 || u.Period.Down != 5000 || u.Period.Exit != "" {
		t.Errorf("daily %+v, period %+v", u.Daily, u.Period)
	}
	var list []protocol.DeviceInfo
	cl.must(200, "GET", "/v1/me/devices", nil, &list)
	if list[0].RecentBytes != 6000 {
		t.Errorf("recent bytes = %d", list[0].RecentBytes)
	}

	other, _ := a.user("reza")
	other.must(404, "GET", "/v1/me/devices/"+issued.Device.ID+"/usage", nil, nil)

	// Admins see a total per User, not per Device.
	var users []protocol.UserInfo
	admin.must(200, "GET", "/v1/admin/users", nil, &users)
	for _, u := range users {
		if u.ID == me.ID && u.PeriodBytes != 6000 {
			t.Errorf("period bytes = %d", u.PeriodBytes)
		}
	}
}
