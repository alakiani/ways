package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// quotaFixture registers a User on 2026-10-16 (Renewal Day 16) with two
// Devices.
func quotaFixture(t *testing.T) (*store.Store, *clock, string, store.UserDevice, store.UserDevice) {
	t.Helper()
	s, c, d1, user := usageFixture(t)
	d2, err := s.AddDevice(ctx, user, "laptop", "k2", "", false)
	if err != nil {
		t.Fatal(err)
	}
	return s, c, user, d1, d2
}

func TestPeriodUsageSumsAllDevicesRevokedIncludedAcrossAMonth(t *testing.T) {
	s, c, user, d1, d2 := quotaFixture(t)
	a1, a2 := d1.Address.String(), d2.Address.String()
	s.PutUsage(ctx, "nd_b1", []protocol.UsageBucket{
		bucket(day(2026, 10, 15).Add(23*time.Hour), a1, "nd_x1", 1000, 1000), // the period before
		bucket(day(2026, 10, 16), a1, "nd_x1", 1, 2),
		bucket(day(2026, 10, 31).Add(23*time.Hour), a2, "nd_x1", 3, 4),
	})
	if err := s.RevokeDevice(ctx, d2.ID); err != nil {
		t.Fatal(err)
	}
	// Into November: the period runs 10-16 to 11-16, and the October days
	// have been rolled up to daily rows by now.
	c.t = day(2026, 11, 15).Add(12 * time.Hour)
	s.PutUsage(ctx, "nd_b2", []protocol.UsageBucket{
		bucket(day(2026, 11, 15).Add(12*time.Hour), a1, "nd_x2", 10, 20),
	})
	if err := s.RollUp(ctx); err != nil {
		t.Fatal(err)
	}
	n, err := s.PeriodUsage(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1+2+3+4+10+20 {
		t.Errorf("period usage = %d, want 40", n)
	}
	// The next period starts from zero.
	c.t = day(2026, 11, 16)
	if n, _ := s.PeriodUsage(ctx, user); n != 0 {
		t.Errorf("new period usage = %d, want 0", n)
	}
}

func TestUsageHistorySplitsRecentPeriodsByDevice(t *testing.T) {
	s, c, user, d1, d2 := quotaFixture(t)
	d3, _ := s.AddDevice(ctx, user, "tablet", "k3", "", false)
	s.PutUsage(ctx, "nd_b1", []protocol.UsageBucket{
		bucket(day(2026, 10, 20), d1.Address.String(), "nd_x1", 5, 5),
		bucket(day(2026, 10, 21), d2.Address.String(), "nd_x1", 1, 1),
		bucket(day(2026, 10, 22), d3.Address.String(), "nd_x1", 2, 2),
	})
	s.RevokeDevice(ctx, d2.ID)
	s.RevokeDevice(ctx, d3.ID)
	c.t = day(2026, 11, 20)
	s.PutUsage(ctx, "nd_b1", []protocol.UsageBucket{bucket(day(2026, 11, 20), d1.Address.String(), "nd_x1", 50, 50)})
	s.ClosePeriods(ctx)

	h, err := s.UsageHistory(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 2 {
		t.Fatalf("history = %+v, want the closed and the current period", h)
	}
	closed, current := h[0], h[1]
	if !closed.Start.Equal(day(2026, 10, 16)) || closed.Bytes != 16 || closed.Current || !closed.Detailed {
		t.Errorf("closed = %+v", closed)
	}
	if len(closed.Devices) != 1 || closed.Devices[0].ID != d1.ID || closed.Devices[0].Name != "phone" || closed.Devices[0].Bytes != 10 || closed.Revoked != 6 {
		t.Errorf("closed split = %+v, revoked %d; want phone 10, revoked 6", closed.Devices, closed.Revoked)
	}
	if !current.Start.Equal(day(2026, 11, 16)) || !current.End.Equal(day(2026, 12, 16)) || !current.Current || current.Bytes != 100 {
		t.Errorf("current = %+v", current)
	}
	if len(current.Devices) != 1 || current.Devices[0].Bytes != 100 || current.Revoked != 0 {
		t.Errorf("current split = %+v, revoked %d", current.Devices, current.Revoked)
	}

	// Past 90 days, a period keeps its total but loses its split.
	c.t = day(2027, 2, 20)
	s.ClosePeriods(ctx)
	s.RollUp(ctx)
	h, _ = s.UsageHistory(ctx, user)
	if len(h) == 0 || h[0].Bytes != 16 || h[0].Detailed || h[0].Devices != nil || h[0].Revoked != 0 {
		t.Errorf("old period = %+v, want a total of 16 without a split", h[0])
	}
	if last := h[len(h)-1]; !last.Detailed || !last.Current {
		t.Errorf("the current period = %+v, want it split", last)
	}
}

func TestClosingAPeriodTwiceStoresOneTotalErasedWithTheUser(t *testing.T) {
	s, c, user, d1, d2 := quotaFixture(t)
	s.PutUsage(ctx, "nd_b1", []protocol.UsageBucket{
		bucket(day(2026, 10, 20), d1.Address.String(), "nd_x1", 5, 5),
		bucket(day(2026, 11, 1), d2.Address.String(), "nd_x1", 1, 1),
	})
	s.RevokeDevice(ctx, d2.ID)

	// The period is still open: nothing to close.
	if err := s.ClosePeriods(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ClosedPeriods(ctx, user); len(got) != 0 {
		t.Fatalf("an open period was closed: %+v", got)
	}

	c.t = day(2026, 11, 16).Add(time.Hour)
	if err := s.ClosePeriods(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.ClosePeriods(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := s.ClosedPeriods(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Start.Equal(day(2026, 10, 16)) || !got[0].End.Equal(day(2026, 11, 16)) || got[0].Bytes != 12 {
		t.Fatalf("closed periods = %+v, want one 10-16..11-16 of 12 bytes", got)
	}

	// Late backlog for a closed period still counts toward it.
	s.PutUsage(ctx, "nd_b2", []protocol.UsageBucket{bucket(day(2026, 11, 15), d1.Address.String(), "nd_x1", 4, 4)})
	s.ClosePeriods(ctx)
	if got, _ := s.ClosedPeriods(ctx, user); len(got) != 1 || got[0].Bytes != 20 {
		t.Errorf("after backlog: %+v, want one total of 20", got)
	}

	if err := s.DeleteUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ClosedPeriods(ctx, user); len(got) != 0 {
		t.Errorf("a deleted User's period totals remain: %+v", got)
	}
}

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func TestQuotaPeriodsFollowTheRenewalDayThroughShortMonths(t *testing.T) {
	for _, tc := range []struct {
		name       string
		renewalDay int
		at         time.Time
		start, end time.Time
	}{
		{"31st: January to February", 31, day(2027, 1, 31).Add(5 * time.Hour), day(2027, 1, 31), day(2027, 2, 28)},
		{"31st: February ends on the 28th", 31, day(2027, 3, 15), day(2027, 2, 28), day(2027, 3, 31)},
		{"31st: back on the 31st in March", 31, day(2027, 3, 31), day(2027, 3, 31), day(2027, 4, 30)},
		{"31st: a 30-day month", 31, day(2027, 5, 1), day(2027, 4, 30), day(2027, 5, 31)},
		{"30th: February", 30, day(2027, 2, 28), day(2027, 2, 28), day(2027, 3, 30)},
		{"30th: the day before February's start", 30, day(2027, 2, 27), day(2027, 1, 30), day(2027, 2, 28)},
		{"30th: a 30-day month keeps the 30th", 30, day(2027, 4, 30), day(2027, 4, 30), day(2027, 5, 30)},
		{"29th: February in a common year", 29, day(2027, 2, 28), day(2027, 2, 28), day(2027, 3, 29)},
		{"29th: February in a leap year", 29, day(2028, 2, 28), day(2028, 1, 29), day(2028, 2, 29)},
		{"29th: leap day itself", 29, day(2028, 2, 29), day(2028, 2, 29), day(2028, 3, 29)},
		{"31st: leap February ends on the 29th", 31, day(2028, 3, 1), day(2028, 2, 29), day(2028, 3, 31)},
		{"crossing a calendar month and year", 16, day(2027, 1, 3), day(2026, 12, 16), day(2027, 1, 16)},
		{"one second before the next start", 16, day(2026, 11, 16).Add(-time.Second), day(2026, 10, 16), day(2026, 11, 16)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := store.QuotaPeriodAt(tc.renewalDay, tc.at)
			if !p.Start.Equal(tc.start) || !p.End.Equal(tc.end) {
				t.Errorf("period at %s = %s..%s, want %s..%s", tc.at, p.Start, p.End, tc.start, tc.end)
			}
		})
	}
}

func TestRenewalDayIsTheRegistrationDayInUTC(t *testing.T) {
	c := newClock()
	c.t = time.Date(2026, 1, 31, 23, 30, 0, 0, time.UTC)
	s := open(t, c)
	tok, _, _ := s.CreateInvite(ctx, store.Invite{Kind: "new"}, time.Hour)
	a, err := s.AcceptNewInvite(ctx, tok, "sara", "h")
	if err != nil {
		t.Fatal(err)
	}
	c.t = day(2026, 2, 10)
	p, err := s.CurrentQuotaPeriod(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Start.Equal(day(2026, 1, 31)) || !p.End.Equal(day(2026, 2, 28)) {
		t.Errorf("current period = %s..%s", p.Start, p.End)
	}
}

func TestQuotaStandingCountsRemediesInTheirPeriodOnly(t *testing.T) {
	s, c, user, d1, d2 := quotaFixture(t)
	q, err := s.QuotaStanding(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if left, limited := q.Left(); limited || left != 0 || q.RanOut() || q.SlowRate != 0 || q.RenewalDay != 16 {
		t.Errorf("a new User = %+v, want unlimited and blocked on running out", q)
	}
	if got, _ := s.QuotaStandings(ctx); len(got) != 0 {
		t.Errorf("standings without a Quota = %+v", got)
	}

	if err := s.SetQuota(ctx, user, store.QuotaSetting{Quota: new(uint64(100)), SlowRate: 125_000}); err != nil {
		t.Fatal(err)
	}
	s.PutUsage(ctx, "nd_b1", []protocol.UsageBucket{
		bucket(day(2026, 10, 16), d1.Address.String(), "nd_x1", 30, 30),
		bucket(day(2026, 10, 17), d2.Address.String(), "nd_x1", 20, 20),
	})
	s.RevokeDevice(ctx, d2.ID) // its Usage still counts
	q, _ = s.QuotaStanding(ctx, user)
	if !q.RanOut() || q.Usage != 100 || q.SlowRate != 125_000 {
		t.Errorf("at 100 of 100 = %+v, want ran out", q)
	}
	s.AddRemedy(ctx, user, store.TopUp, 30)
	s.AddRemedy(ctx, user, store.Reset, 100)
	q, _ = s.QuotaStanding(ctx, user)
	if left, _ := q.Left(); q.RanOut() || left != 130 || q.Remedies != 130 || q.Usage != 100 {
		t.Errorf("after a Top-up and a Reset = %+v, want 130 left and Usage unchanged", q)
	}
	if a, _ := s.Account(ctx, user); a.Quota == nil || *a.Quota != 100 || a.SlowRate != 125_000 {
		t.Errorf("account = %+v", a.QuotaSetting)
	}

	// The next period starts from zero, without the last one's remedies.
	c.t = day(2026, 11, 16)
	q, _ = s.QuotaStanding(ctx, user)
	if left, _ := q.Left(); left != 100 || q.Remedies != 0 || !q.Period.Start.Equal(day(2026, 11, 16)) {
		t.Errorf("next period = %+v", q)
	}
	s.PutUsage(ctx, "nd_b1", []protocol.UsageBucket{bucket(day(2026, 11, 16), d1.Address.String(), "nd_x1", 200, 0)})
	q, _ = s.QuotaStanding(ctx, user)
	if left, _ := q.Left(); left != 0 || !q.RanOut() {
		t.Errorf("past the Quota = %+v, want nothing left", q)
	}
	if got, _ := s.QuotaStandings(ctx); len(got) != 1 || got[0].UserID != user {
		t.Errorf("standings = %+v", got)
	}

	// Back to unlimited and blocking.
	s.SetQuota(ctx, user, store.QuotaSetting{})
	if a, _ := s.Account(ctx, user); a.Quota != nil || a.SlowRate != 0 {
		t.Errorf("after unlimited: %+v", a.QuotaSetting)
	}
	if err := s.SetQuota(ctx, "us_nope", store.QuotaSetting{}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown User: %v", err)
	}
	if err := s.DeleteUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QuotaStanding(ctx, user); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("deleted User: %v", err)
	}
}
