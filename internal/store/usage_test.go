package store_test

import (
	"testing"
	"time"

	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

func usageFixture(t *testing.T) (*store.Store, *clock, store.UserDevice, string) {
	t.Helper()
	c := newClock() // 2026-10-16 12:00 UTC
	s := open(t, c)
	tok, _, _ := s.CreateInvite(ctx, store.Invite{Kind: "new"}, time.Hour)
	a, _ := s.AcceptNewInvite(ctx, tok, "maryam", "h")
	d, err := s.AddDevice(ctx, a.ID, "phone", "k1", "", false)
	if err != nil {
		t.Fatal(err)
	}
	return s, c, d, a.ID
}

func bucket(hour time.Time, addr, exit string, up, down uint64) protocol.UsageBucket {
	return protocol.UsageBucket{Hour: hour.Unix(), Device: addr, Exit: exit, Up: up, Down: down}
}

func TestUsageUploadsReplaceAndSkipStrangers(t *testing.T) {
	s, c, d, _ := usageFixture(t)
	h := c.t.Truncate(time.Hour)
	addr := d.Address.String()
	n, err := s.PutUsage(ctx, "nd_b1", []protocol.UsageBucket{
		bucket(h, addr, "nd_x1", 100, 1000),
		bucket(h, "10.77.9.9", "nd_x1", 5, 5),              // no such Device
		{Hour: h.Unix() + 60, Device: addr, Exit: "nd_x1"}, // not an hour boundary
	})
	if err != nil || n != 1 {
		t.Fatalf("stored %d, %v; want 1", n, err)
	}
	// Resending, with the open hour grown, replaces.
	s.PutUsage(ctx, "nd_b1", []protocol.UsageBucket{bucket(h, addr, "nd_x1", 150, 1500)})
	s.PutUsage(ctx, "nd_b1", []protocol.UsageBucket{bucket(h, addr, "nd_x1", 150, 1500)})
	// Another Bridge's bytes for the same Device and hour add up.
	s.PutUsage(ctx, "nd_b2", []protocol.UsageBucket{bucket(h, addr, "nd_x1", 1, 2)})

	u, err := s.Usage(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Hourly) != 1 || u.Hourly[0].Up != 151 || u.Hourly[0].Down != 1502 || u.Hourly[0].Exit != "nd_x1" {
		t.Errorf("hourly = %+v", u.Hourly)
	}
	if len(u.Daily) != 1 || u.Daily[0].Period != "2026-10-16" || u.Daily[0].Up != 151 {
		t.Errorf("daily = %+v", u.Daily)
	}
	if len(u.Monthly) != 1 || u.Monthly[0].Period != "2026-10" || u.Monthly[0].Down != 1502 {
		t.Errorf("monthly = %+v", u.Monthly)
	}
	if n, _ := s.RecentBytes(ctx, d.ID); n != 151+1502 {
		t.Errorf("recent bytes = %d", n)
	}
}

func TestRollUpKeepsTotalsAndDropsDetail(t *testing.T) {
	s, c, d, _ := usageFixture(t)
	addr := d.Address.String()
	start := c.t.Truncate(24 * time.Hour) // 2026-10-16 00:00
	// Two hours on one day, through two Exits.
	s.PutUsage(ctx, "nd_b1", []protocol.UsageBucket{
		bucket(start.Add(1*time.Hour), addr, "nd_x1", 10, 100),
		bucket(start.Add(2*time.Hour), addr, "nd_x1", 20, 200),
		bucket(start.Add(2*time.Hour), addr, "nd_x2", 1, 1),
	})

	// Within 7 days nothing folds.
	c.advance(6 * 24 * time.Hour)
	s.RollUp(ctx)
	if u, _ := s.Usage(ctx, d.ID); len(u.Hourly) != 3 {
		t.Fatalf("hourly folded early: %+v", u.Hourly)
	}

	// After 7 days the hours are a day per Exit, and the hours are gone.
	c.advance(2 * 24 * time.Hour)
	if err := s.RollUp(ctx); err != nil {
		t.Fatal(err)
	}
	s.RollUp(ctx) // twice is harmless
	u, _ := s.Usage(ctx, d.ID)
	if len(u.Hourly) != 0 {
		t.Errorf("hourly rows survived 7 days: %+v", u.Hourly)
	}
	if len(u.Daily) != 2 || u.Daily[0].Up != 30 || u.Daily[0].Down != 300 || u.Daily[1].Exit != "nd_x2" {
		t.Errorf("daily = %+v", u.Daily)
	}

	// After 90 days the days are a month per Device.
	c.advance(90 * 24 * time.Hour)
	s.RollUp(ctx)
	u, _ = s.Usage(ctx, d.ID)
	if len(u.Daily) != 0 || len(u.Monthly) != 1 || u.Monthly[0].Up != 31 || u.Monthly[0].Down != 301 {
		t.Errorf("after 90 days: daily %+v, monthly %+v", u.Daily, u.Monthly)
	}
}

func TestDeleteUserRemovesUsage(t *testing.T) {
	s, c, d, user := usageFixture(t)
	s.PutUsage(ctx, "nd_b1", []protocol.UsageBucket{bucket(c.t.Truncate(time.Hour), d.Address.String(), "nd_x1", 7, 3)})
	if n, _ := s.PeriodUsage(ctx, user); n != 10 {
		t.Errorf("period bytes = %d", n)
	}
	if err := s.DeleteUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.Usage(ctx, d.ID); len(u.Hourly)+len(u.Daily)+len(u.Monthly) != 0 {
		t.Errorf("a deleted User's usage remains: %+v", u)
	}
}
