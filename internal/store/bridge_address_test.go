package store_test

import (
	"testing"
	"time"
)

func TestBridgeAddress(t *testing.T) {
	clock := newClock()
	s := open(t, clock)
	if got, err := s.BridgeAddress(ctx); err != nil || len(got) != 0 {
		t.Fatalf("BridgeAddress = %v, %v; want none", got, err)
	}
	if err := s.JoinBridgeAddress(ctx, "nd_2"); err != nil {
		t.Fatal(err)
	}
	joined := clock.now().Unix()
	clock.advance(time.Minute)
	s.JoinBridgeAddress(ctx, "nd_1")
	s.JoinBridgeAddress(ctx, "nd_2") // already in: keeps its join time
	got, _ := s.BridgeAddress(ctx)
	if len(got) != 2 || got[0].NodeID != "nd_1" || got[1].NodeID != "nd_2" || got[1].Joined != joined {
		t.Fatalf("after joining: %+v", got)
	}

	if err := s.LeaveBridgeAddress(ctx, "nd_2"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.BridgeAddress(ctx)
	if len(got) != 1 || got[0].NodeID != "nd_1" {
		t.Fatalf("after leaving: %+v", got)
	}
}
