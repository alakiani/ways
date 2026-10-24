//go:build linux

package e2e

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/alakiani/ways/internal/lab"
	"github.com/alakiani/ways/internal/protocol"
	"github.com/alakiani/ways/internal/store"
)

// wgConf is a parsed WireGuard config, as the stock apps read it.
type wgConf struct {
	privateKey wgtypes.Key
	addresses  []netip.Prefix
	dns        string
	peerKey    wgtypes.Key
	allowedIPs []string
	endpoint   string
	keepalive  time.Duration
}

func parseConf(t *testing.T, text string) wgConf {
	t.Helper()
	var c wgConf
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " = ")
		if !ok {
			continue
		}
		var err error
		switch k {
		case "PrivateKey":
			c.privateKey, err = wgtypes.ParseKey(v)
		case "PublicKey":
			c.peerKey, err = wgtypes.ParseKey(v)
		case "Address":
			for _, a := range strings.Split(v, ", ") {
				c.addresses = append(c.addresses, netip.MustParsePrefix(a))
			}
		case "DNS":
			c.dns = v
		case "AllowedIPs":
			c.allowedIPs = strings.Split(v, ", ")
		case "Endpoint":
			c.endpoint = v
		case "PersistentKeepalive":
			c.keepalive = 25 * time.Second
		}
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	return c
}

// phoneFromConf sets up a lab Node as a Device from a config file, the way
// wg-quick would: the tunnel, its IPv4 address, and every route into it.
func phoneFromConf(t *testing.T, n *lab.Node, c wgConf) *phone {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		if out, err := n.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	endpoint, err := net.ResolveUDPAddr("udp4", c.endpoint)
	if err != nil {
		t.Fatal(err)
	}
	var allowed []net.IPNet
	for _, a := range c.allowedIPs {
		_, ipnet, _ := net.ParseCIDR(a)
		allowed = append(allowed, *ipnet)
	}
	run("ip", "link", "add", "wg0", "type", "wireguard")
	if err := n.Do(func() error {
		wc, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer wc.Close()
		return wc.ConfigureDevice("wg0", wgtypes.Config{PrivateKey: &c.privateKey, Peers: []wgtypes.PeerConfig{{
			PublicKey: c.peerKey, Endpoint: endpoint, AllowedIPs: allowed, PersistentKeepaliveInterval: &c.keepalive,
		}}})
	}); err != nil {
		t.Fatal(err)
	}
	for _, a := range c.addresses {
		if a.Addr().Is4() {
			run("ip", "addr", "add", a.String(), "dev", "wg0")
		}
	}
	gw := netip.PrefixFrom(n.Addr(), 24).Masked().Addr().Next()
	run("ip", "link", "set", "wg0", "up")
	run("ip", "route", "add", endpoint.IP.String()+"/32", "via", gw.String(), "dev", "wan0")
	run("ip", "route", "replace", "default", "dev", "wg0")
	return &phone{t: t, node: n}
}

// TestPanelIssuesAWorkingDevice is session 7's "proves in the lab" test: a
// browser issues a Device through the panel, and a lab Device imports the
// generated config and browses through the mesh.
func TestPanelIssuesAWorkingDevice(t *testing.T) {
	binDir(t)
	script, _ := filepath.Abs("../../web/e2e/issue-device.mjs")
	if _, err := os.Stat("../../web/node_modules/@playwright/test"); err != nil {
		t.Skip("web/node_modules is not installed: run npm ci in web/ and npx playwright install chromium")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on PATH")
	}
	if out, err := execCommand("modprobe", "wireguard"); err != nil {
		t.Fatalf("modprobe wireguard: %v: %s", err, out)
	}

	l := lab.StartSpecs(t,
		lab.Spec{Name: "coord"},
		lab.Spec{Name: "ir1"},
		lab.Spec{Name: "ab1"},
		lab.Spec{Name: "phone1"},
		lab.At("web-ab", "93.184.215.14"),
		lab.At("dns-ab", "9.9.9.9"),
		lab.At("egress-ab", "1.0.0.10"),
		lab.At("egress-ir", "2.188.0.10"),
	)
	ctx := context.Background()
	co := startCoordinator(t, l.Node("coord"))
	co.c.Upstreams = []string{"9.9.9.9"}
	// In the lab the Bridge Address is the one Bridge's address.
	co.c.BridgeAddress = l.Node("ir1").Addr().String()
	egressTargets(t, co, l.Node("egress-ab"), l.Node("egress-ir"))
	co.c.FeedURL, co.c.RIPEstatURL = serveFeed(t, irFeed("2.144.0.0/14", "5.0.0.0/8")), ""
	if err := co.c.RefreshIRFeed(ctx); err != nil {
		t.Fatal(err)
	}
	whoami(t, l.Node("web-ab"), 7)
	upstreamCA := dnsServer(t, l.Node("dns-ab"))

	m := &mesh{t: t, l: l, co: co, ids: map[string]string{}, agents: map[string]*agentProc{},
		agentArgs: []string{"-upstream-ca", upstreamCA}}
	m.startAgent("ir1", []protocol.Role{protocol.RoleBridge}, []string{"IR"})
	m.startAgent("ab1", []protocol.Role{protocol.RoleExit}, nil)

	// The browser redeems an Invite and issues a Device.
	token, _, err := co.store.CreateInvite(ctx, store.Invite{Kind: "new"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	cmd := exec.Command(node, script)
	cmd.Dir = filepath.Dir(script)
	cmd.Env = append(os.Environ(), "PANEL_URL="+co.admin.URL, "INVITE_TOKEN="+token, "OUT_DIR="+out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("browser: %v\n%s", err, b)
	} else {
		t.Logf("browser: %s", strings.TrimSpace(string(b)))
	}

	// The one config, saved as the browser offered it.
	conf, err := os.ReadFile(filepath.Join(out, "ways.conf"))
	if err != nil {
		t.Fatal(err)
	}
	main := parseConf(t, string(conf))
	if pub, _ := co.c.BridgePublicKey(ctx); main.peerKey.String() != pub {
		t.Error("the config names another Bridge key")
	}
	if main.dns != "10.77.0.1" || !slices.Contains(main.allowedIPs, "::/0") {
		t.Errorf("config = %+v", main)
	}

	// A lab Device imports the config and browses through the mesh.
	p := phoneFromConf(t, l.Node("phone1"), main)
	ab1 := l.Node("ab1").Addr().String()
	p.leavesFrom("the panel's config browses abroad", func() (string, error) { return p.ask("93.184.215.14:7") }, ab1, 120*time.Second)
	p.leavesFrom("its DNS resolves abroad", func() (string, error) { return p.ask(main.dns + ":53") }, "dns:"+ab1, 30*time.Second)
}
