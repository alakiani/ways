package dataplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// resolver is the Bridge's DNS relay (ADR 0004, amended in MVP 04 and by
// ADR 0009). It passes Devices' queries, UDP and TCP, to public resolvers
// abroad and their answers back, without parsing or logging anything. It
// asks them over DNS over TLS on port 853: a Link may carry traffic on
// plain GRE, and the filter rewrites DNS answers on port 53. Its upstream
// sockets carry the default Rule's mark, so its queries leave through an
// abroad Exit rather than the domestic uplink.
//
// An Abroad Device's lookups are the exception (ADR 0014): they go in
// plain DNS to domestic resolvers, with the Abroad Rule's mark, so they
// leave from Iran and CDNs answer with their Iranian edges.
type resolver struct {
	listen       string // host:port
	upstreams    []string
	upstreamPort string         // "853"; tests point it elsewhere
	roots        *x509.CertPool // what upstream certificates verify against; nil for the system's
	mark         func() uint32  // the mark upstream sockets carry, read per query

	// Clients in abroad ask abroadUpstreams in plain DNS on plainPort, with
	// abroadMark. With no abroadUpstreams, they ask as everyone else does.
	abroad          netip.Prefix
	abroadUpstreams []string
	plainPort       string // "53"; tests point it elsewhere
	abroadMark      func() uint32

	udpAddr, tcpAddr string // where it ended up listening

	cancel context.CancelFunc
	wg     sync.WaitGroup

	sessions tls.ClientSessionCache
	mu       sync.Mutex
	idle     map[string][]*upstreamConn // by upstream, most recently used last
}

// upstreamConn is one DNS-over-TLS connection, kept between queries so a
// query costs one round trip abroad rather than three.
type upstreamConn struct {
	*tls.Conn
	mark     uint32 // the mark it was dialled with
	lastUsed time.Time
}

const (
	upstreamTimeout = 3 * time.Second
	tcpIdle         = 10 * time.Second
	// Idle upstream connections are kept this long, a few per upstream.
	upstreamIdle       = 20 * time.Second
	maxIdlePerUpstream = 4
)

func newResolver(listen string, upstreams []string, mark func() uint32) *resolver {
	return &resolver{listen: listen, upstreams: upstreams, upstreamPort: "853", plainPort: "53", mark: mark,
		sessions: tls.NewLRUClientSessionCache(16), idle: map[string][]*upstreamConn{}}
}

// exchange asks one upstream one query over a pooled connection, or a new
// one. A pooled connection the upstream has closed in the meantime fails
// at once, and the query goes again over a fresh connection.
func (r *resolver) exchange(ctx context.Context, upstream string, query []byte) ([]byte, error) {
	mark := r.mark()
	if c := r.takeIdle(upstream, mark); c != nil {
		if answer, err := c.ask(query); err == nil {
			r.putIdle(upstream, c)
			return answer, nil
		}
		c.Close()
	}
	c, err := r.dial(ctx, upstream, mark)
	if err != nil {
		return nil, err
	}
	answer, err := c.ask(query)
	if err != nil {
		c.Close()
		return nil, err
	}
	r.putIdle(upstream, c)
	return answer, nil
}

// dial opens a DNS-over-TLS connection carrying mark, the one in force
// now, so the resolver's queries follow the default Rule's buckets as they
// move. Upstreams are named by IP address, which their certificates carry.
func (r *resolver) dial(ctx context.Context, upstream string, mark uint32) (*upstreamConn, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: upstreamTimeout, Control: markControl(mark)},
		Config:    &tls.Config{ServerName: upstream, RootCAs: r.roots, MinVersion: tls.VersionTLS12, ClientSessionCache: r.sessions},
	}
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(upstream, r.upstreamPort))
	if err != nil {
		return nil, err
	}
	return &upstreamConn{Conn: c.(*tls.Conn), mark: mark}, nil
}

func (c *upstreamConn) ask(query []byte) ([]byte, error) {
	c.SetDeadline(time.Now().Add(upstreamTimeout))
	if err := writeMsg(c, query); err != nil {
		return nil, err
	}
	return readMsg(c)
}

// takeIdle returns a pooled connection to upstream dialled with mark, if
// one is fresh enough. Older or differently marked ones are closed.
func (r *resolver) takeIdle(upstream string, mark uint32) *upstreamConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.idle == nil { // stopped
		return nil
	}
	list := r.idle[upstream]
	for len(list) > 0 {
		c := list[len(list)-1]
		list = list[:len(list)-1]
		if c.mark == mark && time.Since(c.lastUsed) < upstreamIdle {
			r.idle[upstream] = list
			return c
		}
		c.Close()
	}
	r.idle[upstream] = list
	return nil
}

func (r *resolver) putIdle(upstream string, c *upstreamConn) {
	c.lastUsed = time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.idle == nil || len(r.idle[upstream]) >= maxIdlePerUpstream {
		c.Close()
		return
	}
	r.idle[upstream] = append(r.idle[upstream], c)
}

// start listens on both UDP and TCP.
func (r *resolver) start() error {
	ctx, cancel := context.WithCancel(context.Background())
	udp, err := net.ListenPacket("udp4", r.listen)
	if err != nil {
		cancel()
		return err
	}
	// TCP on the port UDP got, so listening on port 0 works too.
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		cancel()
		return err
	}
	r.cancel = cancel
	r.udpAddr, r.tcpAddr = udp.LocalAddr().String(), tcp.Addr().String()
	r.wg.Add(3)
	go func() {
		defer r.wg.Done()
		<-ctx.Done()
		udp.Close()
		tcp.Close()
	}()
	go r.serveUDP(ctx, udp)
	go func() {
		defer r.wg.Done()
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go r.serveTCP(ctx, c)
		}
	}()
	return nil
}

func (r *resolver) addrUDP() string { return r.udpAddr }
func (r *resolver) addrTCP() string { return r.tcpAddr }

func (r *resolver) stop() {
	if r.cancel != nil {
		r.cancel()
		r.wg.Wait()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, list := range r.idle {
		for _, c := range list {
			c.Close()
		}
	}
	r.idle = nil
}

func (r *resolver) serveUDP(ctx context.Context, conn net.PacketConn) {
	defer r.wg.Done()
	for {
		buf := make([]byte, 4096)
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		go func() {
			if answer, err := r.ask(ctx, "udp4", from, buf[:n]); err == nil {
				conn.WriteTo(answer, from)
			}
		}()
	}
}

// ask tries each upstream in turn: the domestic ones over network, as the
// query came, for an Abroad Device, and the ones abroad over TLS for
// everyone else.
func (r *resolver) ask(ctx context.Context, network string, from net.Addr, query []byte) ([]byte, error) {
	err := errors.New("no upstream resolver")
	if r.isAbroad(from) {
		for _, up := range r.abroadUpstreams {
			var answer []byte
			if answer, err = r.exchangePlain(ctx, network, up, query); err == nil {
				return answer, nil
			}
		}
		return nil, err
	}
	for _, up := range r.upstreams {
		var answer []byte
		if answer, err = r.exchange(ctx, up, query); err == nil {
			return answer, nil
		}
	}
	return nil, err
}

// serveTCP relays length-prefixed queries on one connection until it goes
// idle.
func (r *resolver) serveTCP(ctx context.Context, c net.Conn) {
	defer c.Close()
	for {
		c.SetDeadline(time.Now().Add(tcpIdle))
		query, err := readMsg(c)
		if err != nil {
			return
		}
		answer, err := r.ask(ctx, "tcp4", c.RemoteAddr(), query)
		if err != nil {
			return
		}
		if err := writeMsg(c, answer); err != nil {
			return
		}
	}
}

// isAbroad reports whether a client is an Abroad Device whose lookups go
// to the domestic resolvers.
func (r *resolver) isAbroad(from net.Addr) bool {
	if len(r.abroadUpstreams) == 0 || !r.abroad.IsValid() {
		return false
	}
	ap, err := netip.ParseAddrPort(from.String())
	return err == nil && r.abroad.Contains(ap.Addr().Unmap())
}

// exchangePlain asks one domestic upstream one query in plain DNS, over a
// fresh socket carrying the Abroad Rule's mark. Abroad Devices are few and
// occasional, so nothing is pooled.
func (r *resolver) exchangePlain(ctx context.Context, network, upstream string, query []byte) ([]byte, error) {
	d := &net.Dialer{Timeout: upstreamTimeout, Control: markControl(r.abroadMark())}
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	c, err := d.DialContext(ctx, network, net.JoinHostPort(upstream, r.plainPort))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(upstreamTimeout))
	if network == "tcp4" {
		if err := writeMsg(c, query); err != nil {
			return nil, err
		}
		return readMsg(c)
	}
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func readMsg(r io.Reader) ([]byte, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	msg := make([]byte, n)
	_, err := io.ReadFull(r, msg)
	return msg, err
}

func writeMsg(w io.Writer, msg []byte) error {
	b := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(b, uint16(len(msg)))
	copy(b[2:], msg)
	_, err := w.Write(b)
	return err
}
