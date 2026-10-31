package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/alakiani/ways/internal/store"
)

func TestNewInviteIsSingleUseAndExpires(t *testing.T) {
	c := newClock()
	s := open(t, c)
	tok, _, err := s.CreateInvite(ctx, store.Invite{Kind: "new", DeviceCap: 5}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.AcceptNewInvite(ctx, tok, "maryam", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if a.Handle != "maryam" || a.DeviceCap != 5 || a.Admin || a.PasswordHash != "hash" {
		t.Errorf("account = %+v", a)
	}
	if _, err := s.AcceptNewInvite(ctx, tok, "other", "hash"); !errors.Is(err, store.ErrInvalidToken) {
		t.Errorf("reused invite: %v", err)
	}
	tok2, _, _ := s.CreateInvite(ctx, store.Invite{Kind: "new"}, time.Hour)
	if _, err := s.AcceptNewInvite(ctx, tok2, "maryam", "h"); !errors.Is(err, store.ErrExists) {
		t.Errorf("taken handle: %v", err)
	}
	// A failed accept does not consume the Invite.
	if a, err := s.AcceptNewInvite(ctx, tok2, "reza", "h"); err != nil || a.DeviceCap != 3 {
		t.Errorf("retry with a free handle: %+v, %v", a, err)
	}
	tok3, _, _ := s.CreateInvite(ctx, store.Invite{Kind: "new"}, time.Hour)
	c.advance(time.Hour + time.Second)
	if _, err := s.LookupInvite(ctx, tok3); !errors.Is(err, store.ErrInvalidToken) {
		t.Errorf("expired invite: %v", err)
	}
}

// An Invite may give the new User the abroad permission (ADR 0014), so an
// Admin need not wait for them to register.
func TestAnInvitePresetsTheAbroadPermission(t *testing.T) {
	s := open(t, newClock())
	tok, _, err := s.CreateInvite(ctx, store.Invite{Kind: "new", Abroad: true}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if inv, err := s.LookupInvite(ctx, tok); err != nil || !inv.Abroad {
		t.Errorf("looked up = %+v, %v", inv, err)
	}
	if recs, _ := s.Invites(ctx); len(recs) != 1 || !recs[0].Abroad {
		t.Errorf("listed = %+v", recs)
	}
	a, err := s.AcceptNewInvite(ctx, tok, "sara", "h")
	if err != nil || !a.Abroad {
		t.Errorf("sara = %+v, %v; want the abroad permission", a, err)
	}
	tok, _, _ = s.CreateInvite(ctx, store.Invite{Kind: "new"}, time.Hour)
	if a, err := s.AcceptNewInvite(ctx, tok, "reza", "h"); err != nil || a.Abroad {
		t.Errorf("reza = %+v, %v; want no abroad permission", a, err)
	}
}

func TestRecoveryInviteReplacesCredentialsAndEndsSessions(t *testing.T) {
	s := open(t, newClock())
	tok, _, _ := s.CreateInvite(ctx, store.Invite{Kind: "new"}, time.Hour)
	a, _ := s.AcceptNewInvite(ctx, tok, "maryam", "old")
	s.SetTOTPPending(ctx, a.ID, "SECRET")
	s.ConfirmTOTP(ctx, a.ID)
	sess, _ := s.CreateSession(ctx, a.ID, true, time.Hour)
	d, err := s.AddDevice(ctx, a.ID, "phone", "pub1", "", false)
	if err != nil {
		t.Fatal(err)
	}

	rec, _, _ := s.CreateInvite(ctx, store.Invite{Kind: "recovery", UserID: a.ID}, time.Hour)
	if _, err := s.AcceptNewInvite(ctx, rec, "x", "h"); !errors.Is(err, store.ErrInvalidToken) {
		t.Errorf("recovery invite accepted as a new one: %v", err)
	}
	got, err := s.AcceptRecoveryInvite(ctx, rec, "new")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != a.ID || got.PasswordHash != "new" || got.TOTPSecret != "" {
		t.Errorf("after recovery: %+v", got)
	}
	if _, err := s.LookupSession(ctx, sess); !errors.Is(err, store.ErrInvalidToken) {
		t.Error("an old session survived recovery")
	}
	if devs, _ := s.UserDevices(ctx, a.ID); len(devs) != 1 || devs[0].ID != d.ID || devs[0].Revoked {
		t.Errorf("devices after recovery: %+v", devs)
	}
}

func TestDeviceCapAndReplace(t *testing.T) {
	s := open(t, newClock())
	tok, _, _ := s.CreateInvite(ctx, store.Invite{Kind: "new", DeviceCap: 2}, time.Hour)
	a, _ := s.AcceptNewInvite(ctx, tok, "maryam", "h")
	d1, _ := s.AddDevice(ctx, a.ID, "phone", "k1", "", false)
	if _, err := s.AddDevice(ctx, a.ID, "laptop", "k1", "", false); !errors.Is(err, store.ErrKeyInUse) {
		t.Errorf("duplicate key: %v", err)
	}
	s.AddDevice(ctx, a.ID, "laptop", "k2", "", false)
	if _, err := s.AddDevice(ctx, a.ID, "tablet", "k3", "", false); !errors.Is(err, store.ErrCapReached) {
		t.Errorf("over the cap: %v", err)
	}
	// Replacing needs no room: the old one is revoked in the same step.
	d3, err := s.AddDevice(ctx, a.ID, "phone", "k3", d1.ID, false)
	if err != nil {
		t.Fatalf("replace at the cap: %v", err)
	}
	if old, _ := s.UserDevice(ctx, d1.ID); !old.Revoked || d3.Address == d1.Address || d3.Seq <= d1.Seq {
		t.Errorf("old %+v, new %+v", old, d3)
	}
}

func TestSessionsExpireAndCarryMFA(t *testing.T) {
	c := newClock()
	s := open(t, c)
	tok, _, _ := s.CreateInvite(ctx, store.Invite{Kind: "new"}, time.Hour)
	a, _ := s.AcceptNewInvite(ctx, tok, "maryam", "h")
	sess, _ := s.CreateSession(ctx, a.ID, false, 30*24*time.Hour)
	if got, err := s.LookupSession(ctx, sess); err != nil || got.MFA || got.UserID != a.ID {
		t.Fatalf("session = %+v, %v", got, err)
	}
	s.SetSessionMFA(ctx, sess)
	if got, _ := s.LookupSession(ctx, sess); !got.MFA {
		t.Error("MFA not recorded")
	}
	c.advance(30*24*time.Hour + time.Second)
	if _, err := s.LookupSession(ctx, sess); !errors.Is(err, store.ErrInvalidToken) {
		t.Error("a 30-day session outlived 30 days")
	}
}
