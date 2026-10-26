package dataplane

import (
	"cmp"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/alakiani/ways/internal/metrics"
)

// activeWithin is how recent a Device's handshake must be for it to count
// as active (ADR 0006).
const activeWithin = 3 * time.Minute

// countMoves counts one step's bucket moves of a Rule. Call with mu held.
func (p *Plane) countMoves(rule string, moves []move) {
	kinds := map[string]bool{}
	for _, m := range moves {
		p.movedBuckets[[2]string{rule, m.kind}]++
		kinds[m.kind] = true
	}
	for k := range kinds {
		p.moves[[2]string{rule, k}]++
	}
}

// WriteMetrics implements agent.MetricsWriter: bucket moves, and on a
// Bridge how it weighs its candidates, its active Devices, as a count
// only, and the bytes through its Device interface beside the bytes
// metered.
func (p *Plane) WriteMetrics(w *metrics.Writer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, k := range sortedPairs(p.moves) {
		w.Counter("ways_path_moves_total", "Steps that moved buckets of a Rule's Device traffic, by kind; Path flapping counts failures.",
			float64(p.moves[k]), "rule", k[0], "kind", k[1])
	}
	for _, k := range sortedPairs(p.movedBuckets) {
		w.Counter("ways_path_bucket_moves_total", "Buckets of a Rule's Device traffic moved, by kind.",
			float64(p.movedBuckets[k]), "rule", k[0], "kind", k[1])
	}
	p.writePaths(w)
	if p.st == nil || p.st.Bridge == nil {
		return
	}
	if dev, err := p.wg.Device(DeviceIface); err == nil {
		active := 0
		for _, peer := range dev.Peers {
			if time.Since(peer.LastHandshakeTime) < activeWithin {
				active++
			}
		}
		w.Gauge("ways_bridge_active_devices", "Devices with a handshake in the last 3 minutes.", float64(active))
	}
	if n, ok := ifaceBytes(DeviceIface); ok {
		w.Counter("ways_bridge_interface_bytes_total", "Bytes through the Device interface, both ways.", float64(n))
	}
	w.Counter("ways_metered_bytes_total", "Bytes metered since the Agent started, both ways.", float64(p.meter.metered()))
}

// writePaths writes, on a Bridge, how the last step weighed each Rule's
// candidates for its own Devices (ADR 0008). The labels are
// ways_path_buckets', so the two join: a candidate is its Link's far end
// by name, or "local". Call with mu held.
func (p *Plane) writePaths(w *metrics.Writer) {
	if p.st == nil || p.st.Bridge == nil {
		return
	}
	peers := map[string]string{}
	for _, l := range p.st.Links {
		peers[linkKey(l.ID)] = l.Peer.Name
	}
	rules := p.st.Bridge.AllRules()
	for i, r := range rules {
		labels := []string{"rule_id", strconv.FormatUint(r.ID, 10), "rule", r.Name, "default", strconv.FormatBool(i == len(rules)-1)}
		for _, v := range p.views[r.ID] {
			cand := v.key
			if name := peers[v.key]; name != "" {
				cand = name
			} else if id, ok := strings.CutPrefix(v.key, "link:"); ok {
				cand = "link " + id
			}
			l := append(slices.Clip(labels), "candidate", cand)
			w.Gauge("ways_path_weight", "The candidate's weight for the Rule: throughput in Mbit/s × availability² × RTT factor.", v.weight, l...)
			w.Gauge("ways_path_target_share", "The share of the Rule's buckets the candidate's weight asks for, before the cutoff.", v.target, l...)
			w.Bool("ways_path_cut_off", "1 while the candidate's weight is under the cutoff fraction of the best, so it gets no buckets.", v.cut, l...)
			w.Gauge("ways_path_availability", "The candidate's availability over the window, less the flap penalty, as its weight uses it.", v.avail, l...)
		}
	}
}

// ifaceBytes is an interface's received plus sent bytes.
func ifaceBytes(iface string) (uint64, bool) {
	var total uint64
	for _, f := range []string{"rx_bytes", "tx_bytes"} {
		b, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "statistics", f))
		if err != nil {
			return 0, false
		}
		n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return 0, false
		}
		total += n
	}
	return total, true
}

func sortedPairs(m map[[2]string]uint64) [][2]string {
	return slices.SortedFunc(maps.Keys(m), func(a, b [2]string) int {
		return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
	})
}
