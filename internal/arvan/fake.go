package arvan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Fake is an in-memory stand-in for ArvanCloud's DNS records API, as much
// of it as Client uses. The lab and the tests serve it with httptest.
type Fake struct {
	// PerPage is the page size of the record list; 0 means 100.
	PerPage int
	// FailWith, when set, answers every request with this status.
	FailWith int

	key, zone string
	mu        sync.Mutex
	records   []record
	next      int
}

// NewFake returns a Fake for one zone that accepts one API key.
func NewFake(key, zone string) *Fake { return &Fake{key: key, zone: zone} }

// Put sets an A record directly, as the operator would in the dashboard.
func (f *Fake) Put(name string, ips ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var v []aValue
	for _, ip := range ips {
		v = append(v, aValue{IP: ip})
	}
	if i := f.find(name); i >= 0 {
		f.records[i].Value = v
		return
	}
	f.next++
	f.records = append(f.records, record{ID: strconv.Itoa(f.next), Type: "a", Name: name, Value: v, TTL: 120})
}

// A returns the addresses of the A record name, in order; none if missing.
func (f *Fake) A(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	if i := f.find(name); i >= 0 {
		for _, v := range f.records[i].Value {
			out = append(out, v.IP)
		}
	}
	return out
}

// OneInTurn reports whether the A record name answers each lookup with
// one of its addresses in turn.
func (f *Fake) OneInTurn(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.find(name)
	return i >= 0 && f.records[i].IPFilterMode != nil && *f.records[i].IPFilterMode == oneInTurn
}

// TTL returns the TTL of the A record name.
func (f *Fake) TTL(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i := f.find(name); i >= 0 {
		return f.records[i].TTL
	}
	return 0
}

// Records counts the zone's records.
func (f *Fake) Records() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.records)
}

func (f *Fake) find(name string) int {
	return slices.IndexFunc(f.records, func(r record) bool { return r.Type == "a" && r.Name == name })
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := func(status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
	}
	if f.FailWith != 0 {
		reply(f.FailWith, envelope{Message: "unavailable"})
		return
	}
	if r.Header.Get("Authorization") != "Apikey "+f.key {
		reply(http.StatusUnauthorized, envelope{Message: "Unauthenticated."})
		return
	}
	prefix := "/domains/" + f.zone + "/dns-records"
	rest, ok := strings.CutPrefix(r.URL.Path, prefix)
	if !ok {
		reply(http.StatusNotFound, envelope{Message: "no such domain"})
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case rest == "" && r.Method == http.MethodGet:
		per := f.PerPage
		if per == 0 {
			per = 100
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		page = max(page, 1)
		last := max((len(f.records)+per-1)/per, 1)
		lo, hi := min((page-1)*per, len(f.records)), min(page*per, len(f.records))
		data, _ := json.Marshal(f.records[lo:hi])
		reply(http.StatusOK, envelope{Data: data, Meta: &meta{CurrentPage: page, LastPage: last}})
	case rest == "" && r.Method == http.MethodPost:
		var rec record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil || rec.Type != "a" || len(rec.Value) == 0 {
			reply(http.StatusUnprocessableEntity, envelope{Message: "bad record"})
			return
		}
		f.next++
		rec.ID = strconv.Itoa(f.next)
		f.records = append(f.records, rec)
		data, _ := json.Marshal(rec)
		reply(http.StatusCreated, envelope{Data: data})
	case strings.HasPrefix(rest, "/") && r.Method == http.MethodPut:
		id := rest[1:]
		i := slices.IndexFunc(f.records, func(r record) bool { return r.ID == id })
		if i < 0 {
			reply(http.StatusNotFound, envelope{Message: "no such record"})
			return
		}
		var rec record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil || rec.Type != f.records[i].Type || len(rec.Value) == 0 {
			reply(http.StatusUnprocessableEntity, envelope{Message: "bad record"})
			return
		}
		rec.ID = id
		f.records[i] = rec
		data, _ := json.Marshal(rec)
		reply(http.StatusOK, envelope{Data: data})
	default:
		reply(http.StatusMethodNotAllowed, envelope{Message: fmt.Sprintf("%s %s", r.Method, r.URL.Path)})
	}
}
