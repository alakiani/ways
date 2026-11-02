package link

import "testing"

// A lone missed check is a slow resolver or object, not a lost uplink: on
// 2026-11-01 every failed spell on both Sotoon Bridges was one check long,
// and each pulled the local Exit out and back in.
func TestEgressFailsOnlyAfterMissesInARow(t *testing.T) {
	var v egressVerdict
	step := func(passed, want bool, what string) {
		t.Helper()
		v.observe(passed)
		if v.ok != want {
			t.Fatalf("%s: ok = %v, want %v", what, v.ok, want)
		}
	}

	step(false, false, "a miss before any pass")
	step(true, true, "the first pass")
	for i := range egressMisses - 1 {
		step(false, true, "a miss short of the limit")
		if v.misses != i+1 {
			t.Fatalf("misses = %d, want %d", v.misses, i+1)
		}
	}
	step(true, true, "a pass after misses")
	if v.misses != 0 {
		t.Fatalf("a pass left misses = %d", v.misses)
	}
	for range egressMisses - 1 {
		step(false, true, "misses counted afresh after a pass")
	}
	step(false, false, "the last miss in a row")
	step(false, false, "a further miss")
	step(true, true, "a pass after failing counts at once")
}
