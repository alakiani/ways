// Package arvan points A records at addresses through ArvanCloud's DNS API
// (CDN API 4.0), which hosts the zone of the Bridge Address (ADR 0011).
package arvan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// DefaultBaseURL is ArvanCloud's CDN API.
const DefaultBaseURL = "https://napi.arvancloud.ir/cdn/4.0"

// NormalizeKey returns the bare API key from one pasted as ArvanCloud's
// panel shows it, "apikey <key>", in any case and with or without the space.
func NormalizeKey(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > len("apikey") && strings.EqualFold(s[:len("apikey")], "apikey") {
		s = strings.TrimSpace(s[len("apikey"):])
	}
	return s
}

// Client edits A records in one zone.
type Client struct {
	BaseURL string // DefaultBaseURL if empty
	APIKey  string // needs DNS administrator rights on the zone
	Zone    string // such as wayfinder.ir
	// TTL is the records' TTL in seconds: the lowest ArvanCloud allows,
	// targeting 60 s (ADR 0005).
	TTL  int
	HTTP *http.Client // http.DefaultClient if nil
}

type aValue struct {
	IP string `json:"ip"`
}

// ipFilterMode is how ArvanCloud answers from a record holding several
// IPs: the panel's "DNS record load balancing".
type ipFilterMode struct {
	Count     string `json:"count"`      // "single": one IP per answer
	Order     string `json:"order"`      // "rr": round robin
	GeoFilter string `json:"geo_filter"` // "none"
}

// oneInTurn answers each lookup with one of the record's IPs, taking turns.
var oneInTurn = ipFilterMode{Count: "single", Order: "rr", GeoFilter: "none"}

type record struct {
	ID           string        `json:"id,omitempty"`
	Type         string        `json:"type"`
	Name         string        `json:"name"`
	Value        []aValue      `json:"value"`
	TTL          int           `json:"ttl"`
	Cloud        bool          `json:"cloud"`
	IPFilterMode *ipFilterMode `json:"ip_filter_mode,omitempty"`
}

// listed is a record as listed; other types carry other value shapes.
type listed struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type meta struct {
	CurrentPage int `json:"current_page"`
	LastPage    int `json:"last_page"`
}

type envelope struct {
	Data    json.RawMessage `json:"data,omitempty"`
	Message string          `json:"message,omitempty"`
	Meta    *meta           `json:"meta,omitempty"`
}

// SetA makes host's A record hold addrs, answering each lookup with one
// of them in turn, creating the record if missing. The record stays
// unproxied, so Devices reach the Bridge itself.
func (c *Client) SetA(ctx context.Context, host string, addrs []netip.Addr) error {
	name, ok := strings.CutSuffix(host, "."+c.Zone)
	if !ok || name == "" || len(addrs) == 0 {
		return fmt.Errorf("arvan: %s is not an A record in zone %s with an address", host, c.Zone)
	}
	mode := oneInTurn
	rec := record{Type: "a", Name: name, TTL: c.TTL, Cloud: false, IPFilterMode: &mode}
	for _, a := range addrs {
		if !a.Is4() {
			return fmt.Errorf("arvan: %s is not IPv4", a)
		}
		rec.Value = append(rec.Value, aValue{IP: a.String()})
	}
	id, err := c.find(ctx, name)
	if err != nil {
		return err
	}
	if id == "" {
		return c.do(ctx, http.MethodPost, "", rec, nil)
	}
	return c.do(ctx, http.MethodPut, "/"+url.PathEscape(id), rec, nil)
}

// find returns the id of the A record name, or "".
func (c *Client) find(ctx context.Context, name string) (string, error) {
	for page := 1; ; page++ {
		var recs []listed
		var m meta
		if err := c.do(ctx, http.MethodGet, fmt.Sprintf("?page=%d&per_page=100", page), nil, &struct {
			Data *[]listed `json:"data"`
			Meta *meta     `json:"meta"`
		}{&recs, &m}); err != nil {
			return "", err
		}
		for _, r := range recs {
			if strings.EqualFold(r.Type, "a") && r.Name == name {
				return r.ID, nil
			}
		}
		if len(recs) == 0 || m.CurrentPage >= m.LastPage {
			return "", nil
		}
	}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+"/domains/"+url.PathEscape(c.Zone)+"/dns-records"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Apikey "+c.APIKey)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("arvan: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("arvan: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		var e envelope
		json.Unmarshal(raw, &e)
		return fmt.Errorf("arvan: %s %s: %s %s", method, req.URL.Path, resp.Status, e.Message)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("arvan: decode %s: %w", req.URL.Path, err)
		}
	}
	return nil
}
