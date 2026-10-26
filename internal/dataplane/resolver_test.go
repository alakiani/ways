package dataplane

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// testCert is a self-signed certificate for 127.0.0.1, as public
// resolvers have for their IP addresses, and a pool that trusts it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "resolver"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// fakeUpstream is a DNS-over-TLS resolver: it answers every query with
// "answer:" + query, on as many queries per connection as it is sent. It
// counts the connections it accepted.
func fakeUpstream(t *testing.T, cert tls.Certificate) (string, *atomic.Int32) {
	t.Helper()
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var conns atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer c.Close()
				for {
					q, err := readMsg(c)
					if err != nil {
						return
					}
					writeMsg(c, append([]byte("answer:"), q...))
				}
			}()
		}
	}()
	return ln.Addr().String(), &conns
}

func startResolver(t *testing.T, roots *x509.CertPool, port string, upstreams ...string) *resolver {
	t.Helper()
	r := newResolver("127.0.0.1:0", upstreams, func() uint32 { return 0 })
	r.roots, r.upstreamPort = roots, port
	if err := r.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.stop)
	return r
}

func askUDP(t *testing.T, r *resolver, q string, timeout time.Duration) (string, error) {
	t.Helper()
	c, err := net.Dial("udp4", r.addrUDP())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	c.Write([]byte(q))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	return string(buf[:n]), err
}

// Devices ask over UDP or TCP; the resolver asks its upstreams over TLS
// on port 853, never plain DNS (ADR 0009, amending ADR 0004).
func TestResolverRelaysUDPAndTCPOverTLS(t *testing.T) {
	cert, roots := testCert(t)
	up, conns := fakeUpstream(t, cert)
	host, port, _ := net.SplitHostPort(up)
	if newResolver("", nil, nil).upstreamPort != "853" {
		t.Error("upstreams are not asked on port 853")
	}
	r := startResolver(t, roots, port, host)

	if got, err := askUDP(t, r, "q1", 2*time.Second); err != nil || got != "answer:q1" {
		t.Errorf("UDP answer = %q, %v", got, err)
	}

	tc, err := net.Dial("tcp4", r.addrTCP())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(2 * time.Second))
	for _, q := range []string{"q2", "q3"} {
		writeMsg(tc, []byte(q))
		a, err := readMsg(tc)
		if err != nil || string(a) != "answer:"+q {
			t.Errorf("TCP answer = %q, %v", a, err)
		}
	}
	for _, q := range []string{"q4", "q5"} {
		if got, err := askUDP(t, r, q, 2*time.Second); err != nil || got != "answer:"+q {
			t.Errorf("UDP answer = %q, %v", got, err)
		}
	}
	// Queries one after another reuse a connection rather than paying a
	// TLS handshake across the filter each time.
	if n := conns.Load(); n != 1 {
		t.Errorf("%d upstream connections for 5 queries in turn, want 1", n)
	}
}

// A connection the upstream closed while it sat idle is replaced, and the
// query still answered.
func TestResolverRedialsAClosedConnection(t *testing.T) {
	cert, roots := testCert(t)
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { // one query per connection, then hang up
				defer c.Close()
				if q, err := readMsg(c); err == nil {
					writeMsg(c, append([]byte("answer:"), q...))
				}
			}()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	r := startResolver(t, roots, port, host)
	for _, q := range []string{"q1", "q2", "q3"} {
		if got, err := askUDP(t, r, q, 3*time.Second); err != nil || got != "answer:"+q {
			t.Errorf("answer = %q, %v", got, err)
		}
	}
}

// The filter could answer in a resolver's name; an upstream whose
// certificate does not verify is not used.
func TestResolverRefusesAnUnverifiedUpstream(t *testing.T) {
	cert, _ := testCert(t)
	_, otherRoots := testCert(t)
	up, _ := fakeUpstream(t, cert)
	host, port, _ := net.SplitHostPort(up)
	r := startResolver(t, otherRoots, port, host)
	if got, err := askUDP(t, r, "q", 2*time.Second); err == nil {
		t.Errorf("answered %q through an upstream that failed verification", got)
	}
}

func TestResolverTriesTheNextUpstream(t *testing.T) {
	cert, roots := testCert(t)
	up, _ := fakeUpstream(t, cert)
	host, port, _ := net.SplitHostPort(up)
	r := startResolver(t, roots, port, "127.0.0.2", host)
	if got, err := askUDP(t, r, "q", 8*time.Second); err != nil || !bytes.Equal([]byte(got), []byte("answer:q")) {
		t.Errorf("answer = %q, %v", got, err)
	}
}

// fakePlainUpstream is a plain DNS resolver on one port, UDP and TCP: it
// answers every query with "plain:" + query. It counts the queries.
func fakePlainUpstream(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	var queries atomic.Int32
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			queries.Add(1)
			udp.WriteTo(append([]byte("plain:"), buf[:n]...), from)
		}
	}()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					q, err := readMsg(c)
					if err != nil {
						return
					}
					queries.Add(1)
					writeMsg(c, append([]byte("plain:"), q...))
				}
			}()
		}
	}()
	return udp.LocalAddr().String(), &queries
}

// An Abroad Device's lookups go to the domestic resolvers in plain DNS,
// over UDP or TCP as they came, with the Abroad Rule's mark; every other
// Device's still go abroad over TLS (ADR 0014).
func TestResolverSendsAbroadDevicesToDomesticResolvers(t *testing.T) {
	cert, roots := testCert(t)
	tlsUp, tlsConns := fakeUpstream(t, cert)
	tlsHost, tlsPort, _ := net.SplitHostPort(tlsUp)
	plainUp, plainQueries := fakePlainUpstream(t)
	plainHost, plainPort, _ := net.SplitHostPort(plainUp)
	if newResolver("", nil, nil).plainPort != "53" {
		t.Error("domestic resolvers are not asked on port 53")
	}

	var abroadMarks atomic.Int32
	start := func(abroad string) *resolver {
		r := newResolver("127.0.0.1:0", []string{tlsHost}, func() uint32 { return 0 })
		r.roots, r.upstreamPort, r.plainPort = roots, tlsPort, plainPort
		r.abroad, r.abroadUpstreams = netip.MustParsePrefix(abroad), []string{"127.0.0.2", plainHost}
		r.abroadMark = func() uint32 { abroadMarks.Add(1); return 0 }
		if err := r.start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(r.stop)
		return r
	}

	// The test's client is 127.0.0.1: inside the abroad prefix...
	r := start("127.0.0.0/8")
	if got, err := askUDP(t, r, "q1", 8*time.Second); err != nil || got != "plain:q1" {
		t.Errorf("UDP answer = %q, %v", got, err)
	}
	tc, err := net.Dial("tcp4", r.addrTCP())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(8 * time.Second))
	writeMsg(tc, []byte("q2"))
	if a, err := readMsg(tc); err != nil || string(a) != "plain:q2" {
		t.Errorf("TCP answer = %q, %v", a, err)
	}
	if plainQueries.Load() != 2 || tlsConns.Load() != 0 || abroadMarks.Load() == 0 {
		t.Errorf("plain queries %d, TLS connections %d, abroad marks %d; want 2, 0, some",
			plainQueries.Load(), tlsConns.Load(), abroadMarks.Load())
	}

	// ...and outside it.
	r = start("10.77.128.0/17")
	if got, err := askUDP(t, r, "q3", 2*time.Second); err != nil || got != "answer:q3" {
		t.Errorf("answer = %q, %v", got, err)
	}
	if plainQueries.Load() != 2 {
		t.Error("an ordinary Device's lookup went to a domestic resolver")
	}
}
