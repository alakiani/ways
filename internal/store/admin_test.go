package store_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

func TestInvitesListAndWithdraw(t *testing.T) {
	s := open(t, newClock())
	tok, _, _ := s.CreateInvite(ctx, store.Invite{Kind: "new", DeviceCap: 2}, time.Hour)
	used, _, _ := s.CreateInvite(ctx, store.Invite{Kind: "new"}, time.Hour)
	s.AcceptNewInvite(ctx, used, "maryam", "h")
	list, err := s.Invites(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("invites = %+v, %v", list, err)
	}
	var open store.InviteRecord
	for _, r := range list {
		if !r.Used {
			open = r
		}
	}
	if open.ID == "" || open.DeviceCap != 2 {
		t.Fatalf("open invite = %+v", open)
	}
	if err := s.WithdrawInvite(ctx, open.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupInvite(ctx, tok); !errors.Is(err, store.ErrInvalidToken) {
		t.Error("a withdrawn Invite still works")
	}
	if err := s.WithdrawInvite(ctx, open.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("withdrew twice")
	}
}

func TestDeleteNodeTakesItsLinksWithIt(t *testing.T) {
	s := open(t, newClock())
	a, b := mustNode(t, s, "a"), mustNode(t, s, "b")
	l, _ := s.EnsureLink(ctx, a.ID, b.ID)
	s.CreateInstance(ctx, l.ID, protocol.TransportAmneziaWG, b.ID)
	if err := s.DeleteNode(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if links, _ := s.Links(ctx); len(links) != 0 {
		t.Errorf("links survive: %+v", links)
	}
	if insts, _ := s.Instances(ctx); len(insts) != 0 {
		t.Errorf("instances survive: %+v", insts)
	}
	if err := s.DeleteNode(ctx, b.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("deleted twice")
	}
}

func TestFeedRollBackAndAttempts(t *testing.T) {
	s := open(t, newClock())
	p := func(x string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(x)} }
	s.SetFeedContent(ctx, 1, p("2.144.0.0/14"))
	if st, _ := s.FeedStatus(ctx, 1); st.CanRollBack {
		t.Error("roll back offered with one update")
	}
	s.SetFeedContent(ctx, 1, p("5.0.0.0/8"))
	s.RecordFeedAttempt(ctx, 1, "address space changed by +50%")
	st, _ := s.FeedStatus(ctx, 1)
	if !st.CanRollBack || st.LastError == "" || st.LastAttempt.IsZero() || st.UpdatedAt.IsZero() {
		t.Errorf("status = %+v", st)
	}
	if err := s.RollBackFeed(ctx, 1); err != nil {
		t.Fatal(err)
	}
	sets, _ := s.DestinationSets(ctx)
	if body, _ := s.SetBlob(ctx, sets[0].ContentHash); body != "2.144.0.0/14\n" {
		t.Errorf("after roll back: %q", body)
	}
}

func TestOnlyTheIRRuleIsEditable(t *testing.T) {
	s := open(t, newClock())
	if err := s.UpdateRule(ctx, 1, []string{"IR", "fast"}, "drop"); err != nil {
		t.Fatal(err)
	}
	rules, _ := s.Rules(ctx)
	if rules[1].Fallback != "drop" || len(rules[1].RequiredTags) != 2 { // after the Abroad Rule
		t.Errorf("IR rule = %+v", rules[1])
	}
	if err := s.UpdateRule(ctx, 2, nil, "next"); !errors.Is(err, store.ErrNotFound) {
		t.Error("the default Rule changed")
	}
}
