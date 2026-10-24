package arvan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func newClient(t *testing.T, f *Fake) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL, APIKey: "secret", Zone: "wayfinder.ir", TTL: 120}
}

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestSetAUpdatesTheExistingRecord(t *testing.T) {
	f := NewFake("secret", "wayfinder.ir")
	f.Put("bridge", "192.0.2.1")
	f.Put("panel", "192.0.2.2")
	c := newClient(t, f)

	if err := c.SetA(context.Background(), "bridge.wayfinder.ir", addrs("203.0.113.7", "203.0.113.8")); err != nil {
		t.Fatal(err)
	}
	if got := f.A("bridge"); !slices.Equal(got, []string{"203.0.113.7", "203.0.113.8"}) {
		t.Errorf("bridge = %q, want both new addresses", got)
	}
	if !f.OneInTurn("bridge") {
		t.Error("bridge does not answer one address per lookup in turn")
	}
	if got := f.A("panel"); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Errorf("panel changed to %q", got)
	}
	if f.Records() != 2 {
		t.Errorf("%d records, want the 2 there were", f.Records())
	}
	if ttl := f.TTL("bridge"); ttl != 120 {
		t.Errorf("ttl = %d, want 120", ttl)
	}

	// Shrinking the set replaces the list, it does not append.
	if err := c.SetA(context.Background(), "bridge.wayfinder.ir", addrs("203.0.113.8")); err != nil {
		t.Fatal(err)
	}
	if got := f.A("bridge"); !slices.Equal(got, []string{"203.0.113.8"}) {
		t.Errorf("bridge = %q, want the one address left", got)
	}
}

func TestSetACreatesAMissingRecord(t *testing.T) {
	f := NewFake("secret", "wayfinder.ir")
	c := newClient(t, f)
	if err := c.SetA(context.Background(), "bridge.wayfinder.ir", addrs("203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	if got := f.A("bridge"); !slices.Equal(got, []string{"203.0.113.9"}) || !f.OneInTurn("bridge") {
		t.Errorf("bridge = %q, one in turn %v", got, f.OneInTurn("bridge"))
	}
}

func TestSetAFindsRecordsOnLaterPages(t *testing.T) {
	f := NewFake("secret", "wayfinder.ir")
	f.PerPage = 2
	for _, n := range []string{"w", "x", "y", "z", "bridge"} {
		f.Put(n, "192.0.2.1")
	}
	c := newClient(t, f)
	if err := c.SetA(context.Background(), "bridge.wayfinder.ir", addrs("203.0.113.7")); err != nil {
		t.Fatal(err)
	}
	if got := f.A("bridge"); f.Records() != 5 || !slices.Equal(got, []string{"203.0.113.7"}) {
		t.Errorf("records = %d, bridge = %q; want 5 and the update in place", f.Records(), got)
	}
}

func TestSetARejectsBadRecords(t *testing.T) {
	c := newClient(t, NewFake("secret", "wayfinder.ir"))
	ctx := context.Background()
	if err := c.SetA(ctx, "bridge.example.com", addrs("203.0.113.7")); err == nil {
		t.Error("want an error for a name outside the zone")
	}
	// An empty record would fail every lookup (ADR 0011).
	if err := c.SetA(ctx, "bridge.wayfinder.ir", nil); err == nil {
		t.Error("want an error for no addresses")
	}
	if err := c.SetA(ctx, "bridge.wayfinder.ir", addrs("2001:db8::1")); err == nil {
		t.Error("want an error for an IPv6 address")
	}
}

func TestSetAReportsAPIErrors(t *testing.T) {
	f := NewFake("other-key", "wayfinder.ir")
	c := newClient(t, f)
	err := c.SetA(context.Background(), "bridge.wayfinder.ir", addrs("203.0.113.7"))
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v, want the 401", err)
	}

	f = NewFake("secret", "wayfinder.ir")
	f.FailWith = http.StatusServiceUnavailable
	c = newClient(t, f)
	if err := c.SetA(context.Background(), "bridge.wayfinder.ir", addrs("203.0.113.7")); err == nil {
		t.Error("want an error while the API fails")
	}
}

// The panel shows a key as "apikey <key>"; operators paste it in any form.
func TestNormalizeKey(t *testing.T) {
	const key = "0a1b2c3d-4e5f-6789-abcd-ef0123456789"
	for _, in := range []string{
		key,
		"apikey " + key,
		"Apikey " + key,
		"APIKEY " + key,
		"apikey" + key, // the space lost on the way
		"  apikey " + key + "\n",
	} {
		if got := NormalizeKey(in); got != key {
			t.Errorf("NormalizeKey(%q) = %q, want the bare key", in, got)
		}
	}
}
