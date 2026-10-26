package coordinator

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

func TestEffectiveStateRanksItsReasons(t *testing.T) {
	out, slow := quotaState{ranOut: true}, quotaState{ranOut: true, rate: 125_000}
	for _, tc := range []struct {
		revoked, suspended, abroadDenied bool
		quota                            quotaState
		state                            EffectiveState
		reason                           string
	}{
		{false, false, false, quotaState{}, StateActive, ""},
		{false, false, false, out, StateBlocked, "quota used up"},
		{false, false, false, slow, StateThrottled, "quota used up"},
		{false, true, false, out, StateBlocked, "user suspended"},
		{false, true, false, slow, StateBlocked, "user suspended"},
		{true, true, false, out, StateBlocked, "device revoked"},
		{true, false, false, slow, StateBlocked, "device revoked"},
		// An Abroad Device whose User lost the permission (ADR 0014).
		{false, false, true, quotaState{}, StateBlocked, "abroad not allowed"},
		{false, false, true, slow, StateBlocked, "abroad not allowed"},
		{false, true, true, quotaState{}, StateBlocked, "user suspended"},
	} {
		if st, reason := effectiveState(tc.revoked, tc.suspended, tc.abroadDenied, tc.quota); st != tc.state || reason != tc.reason {
			t.Errorf("effectiveState(%v, %v, %v, %+v) = %s, %q; want %s, %q", tc.revoked, tc.suspended, tc.abroadDenied, tc.quota, st, reason, tc.state, tc.reason)
		}
	}
}

// quotaFixture is a Bridge, an Admin, and a User with one Device.
func quotaFixture(t *testing.T) (a *api, admin *client, user protocol.Me, dev protocol.DeviceInfo, bridgeID string) {
	t.Helper()
	a = newAPI(t)
	bridge, err := a.s.CreateNode(context.Background(), "ir1", []protocol.Role{protocol.RoleBridge}, []string{"IR"})
	if err != nil {
		t.Fatal(err)
	}
	admin = a.admin()
	cl, me := a.user("maryam")
	var issued protocol.IssuedDevice
	cl.must(200, "POST", "/v1/me/devices", protocol.NewDevice{Name: "phone", PublicKey: pubKey(t)}, &issued)
	return a, admin, me, issued.Device, bridge.ID
}

// use stores bytes of Usage for dev in the current hour, as a Bridge's
// report would, and checks Quotas as the health handler does.
func (a *api) use(dev protocol.DeviceInfo, up, down uint64) {
	a.t.Helper()
	hour := a.clock.UTC().Truncate(time.Hour).Unix()
	if _, err := a.s.PutUsage(context.Background(), "nd_bridge", []protocol.UsageBucket{
		{Hour: hour, Device: dev.Address, Exit: "nd_exit", Up: up, Down: down},
	}); err != nil {
		a.t.Fatal(err)
	}
	if err := a.c.CheckQuotas(context.Background()); err != nil {
		a.t.Fatal(err)
	}
}

func (cl *client) device(userID string) protocol.DeviceInfo {
	cl.a.t.Helper()
	var devs []protocol.DeviceInfo
	cl.must(200, "GET", "/v1/admin/users/"+userID+"/devices", nil, &devs)
	return devs[0]
}

func TestRunningOutBlocksOrSlowsUntilTheQuotaIsRaised(t *testing.T) {
	a, admin, me, dev, bridge := quotaFixture(t)
	onBridge := func() bool { return len(a.bridgeDevices(bridge)) == 1 }
	path := "/v1/admin/users/" + me.ID + "/quota"

	var u protocol.UserInfo
	admin.must(200, "POST", path, protocol.SetQuota{Quota: new(uint64(1000)), RunningOut: protocol.RunningOutBlock}, &u)
	if u.Quota == nil || *u.Quota != 1000 || u.RunningOut != "block" || u.Rate != 0 || u.RenewalDay != a.clock.UTC().Day() {
		t.Errorf("after setting the Quota: %+v", u)
	}
	a.use(dev, 300, 300) // 600 of 1000
	if !onBridge() {
		t.Fatal("a User with Quota left is off the Bridge")
	}
	a.use(dev, 500, 500) // the same hour again, now 1000 of 1000
	if onBridge() {
		t.Error("a User who ran out is still on the Bridge")
	}
	if d := admin.device(me.ID); d.State != "blocked" || d.Reason != "quota used up" {
		t.Errorf("out of Quota: %s (%s)", d.State, d.Reason)
	}
	var users []protocol.UserInfo
	admin.must(200, "GET", "/v1/admin/users", nil, &users)
	if i := slices.IndexFunc(users, func(u protocol.UserInfo) bool { return u.ID == me.ID }); i < 0 || users[i].PeriodBytes != 1000 {
		t.Errorf("users = %+v, want maryam at 1000 bytes this period", users)
	}

	// Suspended outranks quota used up, and resuming leaves them blocked.
	admin.must(200, "POST", "/v1/admin/users/"+me.ID+"/suspend", nil, nil)
	if d := admin.device(me.ID); d.Reason != "user suspended" {
		t.Errorf("suspended and out: %s (%s)", d.State, d.Reason)
	}
	admin.must(200, "POST", "/v1/admin/users/"+me.ID+"/resume", nil, nil)
	if d := admin.device(me.ID); d.State != "blocked" || d.Reason != "quota used up" || onBridge() {
		t.Errorf("resumed and out: %s (%s)", d.State, d.Reason)
	}

	// Slow instead: the Device stays in, throttled.
	admin.must(200, "POST", path, protocol.SetQuota{Quota: new(uint64(1000)), RunningOut: protocol.RunningOutSlow, Rate: 125_000}, &u)
	if u.RunningOut != "slow" || u.Rate != 125_000 {
		t.Errorf("after choosing slow: %+v", u)
	}
	if d := admin.device(me.ID); d.State != "throttled" || d.Rate != 125_000 || d.Reason != "quota used up" || !onBridge() {
		t.Errorf("slowed: %+v, on the Bridge %v", d, onBridge())
	}

	// A Top-up gives room again, without changing Usage.
	admin.must(200, "POST", path, protocol.SetQuota{Quota: new(uint64(1000)), RunningOut: protocol.RunningOutBlock}, nil)
	if onBridge() {
		t.Fatal("blocking again left the Device in")
	}
	a.s.AddRemedy(context.Background(), me.ID, store.TopUp, 1)
	if err := a.c.CheckQuotas(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !onBridge() || admin.device(me.ID).State != "active" {
		t.Error("a Top-up did not bring the Device back")
	}

	// Raising the Quota, or making it unlimited, brings them back at once.
	admin.must(200, "POST", path, protocol.SetQuota{Quota: new(uint64(0)), RunningOut: protocol.RunningOutBlock}, nil)
	if onBridge() {
		t.Fatal("a Quota of 0 left the Device in")
	}
	admin.must(200, "POST", path, protocol.SetQuota{Quota: new(uint64(5000)), RunningOut: protocol.RunningOutBlock}, nil)
	if !onBridge() {
		t.Error("raising the Quota did not bring the Device back")
	}
	admin.must(200, "POST", path, protocol.SetQuota{Quota: new(uint64(0)), RunningOut: protocol.RunningOutBlock}, nil)
	admin.must(200, "POST", path, protocol.SetQuota{RunningOut: protocol.RunningOutBlock}, &u)
	if u.Quota != nil || !onBridge() {
		t.Errorf("unlimited: %+v, on the Bridge %v", u, onBridge())
	}

	for _, bad := range []protocol.SetQuota{
		{RunningOut: protocol.RunningOutSlow},
		{RunningOut: protocol.RunningOutBlock, Rate: 10},
		{RunningOut: "throttle", Rate: 10},
		{},
		{Quota: new(uint64(1 << 63)), RunningOut: protocol.RunningOutBlock},
	} {
		admin.must(400, "POST", path, bad, nil)
	}
	admin.must(404, "POST", "/v1/admin/users/us_nope/quota", protocol.SetQuota{RunningOut: protocol.RunningOutBlock}, nil)
	cl, _ := a.user("reza")
	cl.must(403, "POST", path, protocol.SetQuota{RunningOut: protocol.RunningOutBlock}, nil)
}

func TestNewQuotaPeriodBringsAUserBackWithoutTraffic(t *testing.T) {
	a, admin, me, dev, bridge := quotaFixture(t)
	admin.must(200, "POST", "/v1/admin/users/"+me.ID+"/quota", protocol.SetQuota{Quota: new(uint64(100)), RunningOut: protocol.RunningOutBlock}, nil)
	a.use(dev, 100, 0)
	if len(a.bridgeDevices(bridge)) != 0 {
		t.Fatal("a User who ran out is still on the Bridge")
	}
	// Only the period check runs: a whole minute passes in a few ms.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.tick(store.QuotaPeriodAt(a.clock.UTC().Day(), *a.clock).End.Sub(*a.clock))
	go a.c.RunQuotaPeriods(ctx, time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for len(a.bridgeDevices(bridge)) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the new Quota Period did not bring the Device back")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The Admin's Users table shows when each User's Quota renews, as a date.
func TestAdminUsersShowWhenTheQuotaRenews(t *testing.T) {
	a, admin, me, dev, _ := quotaFixture(t)
	a.use(dev, 1000, 2000)
	maryam := a.client()
	maryam.must(200, "POST", "/v1/login", protocol.Login{Handle: "maryam", Password: password}, nil)
	var mine protocol.MyUsage
	maryam.must(200, "GET", "/v1/me/usage", nil, &mine)
	if u := admin.userInfo(me.ID); !u.RenewsAt.Equal(mine.RenewsAt) || !u.RenewsAt.After(*a.clock) || u.PeriodBytes != 3000 {
		t.Errorf("renews at %v with %d bytes, want %v with 3000", u.RenewsAt, u.PeriodBytes, mine.RenewsAt)
	}
}
