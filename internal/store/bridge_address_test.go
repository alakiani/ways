package store_test

import (
	"testing"
	"time"

	"github.com/alakiani/ways/internal/store"
)

func TestBridgeAddress(t *testing.T) {
	clock := newClock()
	s := open(t, clock)
	if got, err := s.AddressMembers(ctx, store.BridgeRecord); err != nil || len(got) != 0 {
		t.Fatalf("BridgeAddress = %v, %v; want none", got, err)
	}
	if err := s.JoinAddress(ctx, store.BridgeRecord, "nd_2"); err != nil {
		t.Fatal(err)
	}
	joined := clock.now().Unix()
	clock.advance(time.Minute)
	s.JoinAddress(ctx, store.BridgeRecord, "nd_1")
	s.JoinAddress(ctx, store.BridgeRecord, "nd_2") // already in: keeps its join time
	got, _ := s.AddressMembers(ctx, store.BridgeRecord)
	if len(got) != 2 || got[0].NodeID != "nd_1" || got[1].NodeID != "nd_2" || got[1].Joined != joined {
		t.Fatalf("after joining: %+v", got)
	}

	if err := s.LeaveAddress(ctx, store.BridgeRecord, "nd_2"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.AddressMembers(ctx, store.BridgeRecord)
	if len(got) != 1 || got[0].NodeID != "nd_1" {
		t.Fatalf("after leaving: %+v", got)
	}
}

// The Abroad Bridge Address keeps a record of its own (ADR 0014).
func TestAbroadAddressIsASeparateRecord(t *testing.T) {
	s := open(t, newClock())
	s.JoinAddress(ctx, store.AbroadRecord, "nd_9")
	if got, _ := s.AddressMembers(ctx, store.BridgeRecord); len(got) != 0 {
		t.Errorf("Bridge Address = %+v", got)
	}
	if got, _ := s.AddressMembers(ctx, store.AbroadRecord); len(got) != 1 || got[0].NodeID != "nd_9" {
		t.Errorf("Abroad Bridge Address = %+v", got)
	}
}
