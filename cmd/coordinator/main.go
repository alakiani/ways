// Command coordinator runs the WAYS Coordinator: identity, topology, policy and metering for the mesh.
// It never touches a packet on the data path.
//
// Usage:
//
//	coordinator [serve flags]               run the Coordinator
//	coordinator token create [flags]        mint a scoped API token and print its secret once
//	coordinator invite create [flags]       make an Invite, such as the first Admin's, and print its link
//	coordinator backup restore [flags]      decrypt a nightly backup into a new database, on the operator's laptop
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alakiani/ways/internal/arvan"
	"github.com/alakiani/ways/internal/ca"
	"github.com/alakiani/ways/internal/coordinator"
	"github.com/alakiani/ways/internal/irfeed"
	"github.com/alakiani/ways/internal/store"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var err error
	switch {
	case len(os.Args) > 2 && os.Args[1] == "token" && os.Args[2] == "create":
		err = tokenCreate(os.Args[3:])
	case len(os.Args) > 2 && os.Args[1] == "invite" && os.Args[2] == "create":
		err = inviteCreate(os.Args[3:], log)
	case len(os.Args) > 2 && os.Args[1] == "backup" && os.Args[2] == "restore":
		err = backupRestore(os.Args[3:])
	default:
		err = serve(os.Args[1:], log)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "coordinator:", err)
		os.Exit(1)
	}
}

func serve(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("coordinator", flag.ExitOnError)
	showVersion := fs.Bool("version", false, "print the version and exit")
	dbPath := fs.String("db", "/var/lib/ways/ways.db", "SQLite database")
	caDir := fs.String("ca-dir", "/etc/ways/ca", "directory holding ca.crt and ca.key, created if empty")
	adminListen := fs.String("admin-listen", ":443", "Admin API listen address")
	adminCert := fs.String("admin-tls-cert", "", "public TLS certificate for the Admin API; plain HTTP if unset")
	adminKey := fs.String("admin-tls-key", "", "key for -admin-tls-cert")
	agentListen := fs.String("agent-listen", ":8443", "Agent API listen address")
	agentHosts := fs.String("agent-hosts", "wayfinder.ir", "comma-separated hostnames and IPs Agents dial")
	panelURL := fs.String("panel-url", "https://wayfinder.ir", "where the panel is served; Invite links point here")
	feedURL := fs.String("feed-url", irfeed.DefaultURL, "the IR feed (list.rsc)")
	ripeURL := fs.String("ripestat-url", irfeed.DefaultRIPEstatURL, "RIPEstat's list for the cross-check; empty to skip it")
	bridgeAddress := fs.String("bridge-address", coordinator.DefaultBridgeAddress, "the Bridge Address: the hostname in every Device's config, in -arvan-zone; changing it affects only configs issued afterwards")
	arvanKeyFile := fs.String("arvan-api-key-file", "", "file holding the ArvanCloud API key that edits the Bridge Address's record; unset leaves the record alone")
	arvanZone := fs.String("arvan-zone", "wayfinder.ir", "the ArvanCloud zone holding the Bridge Address")
	arvanTTL := fs.Int("arvan-ttl", 120, "TTL of the Bridge Address's record, in seconds: the lowest ArvanCloud allows")
	arvanURL := fs.String("arvan-url", arvan.DefaultBaseURL, "ArvanCloud's CDN API")
	internalListen := fs.String("internal-listen", "127.0.0.1:9101", "internal listener for Prometheus and Alertmanager; keep it on loopback")
	monitorPort := fs.Uint("monitor-port", 9443, "every Node's monitoring port (ADR 0006)")
	monitorFrom := fs.String("monitor-from", "", "comma-separated addresses Nodes see this VM come from; the only ones let into the monitoring port. Unset keeps the port shut")
	promTLSDir := fs.String("prometheus-tls-dir", "", "where to write Prometheus's client certificate, its key and the CA certificate")
	tgTokenFile := fs.String("telegram-token-file", "", "file holding the Telegram bot token alerts are sent with")
	tgChat := fs.String("telegram-chat", "", "the Telegram chat id alerts go to")
	backupRecipient := fs.String("backup-age-recipient", "", "the operator's age public key (age1...); unset turns nightly backups off")
	backupDir := fs.String("backup-dir", coordinator.DefaultBackupSettings.Dir, "where encrypted backups are kept; the newest -backup-keep stay")
	backupKeep := fs.Int("backup-keep", coordinator.DefaultBackupSettings.Keep, "how many encrypted backups stay on this VM")
	s3Endpoint := fs.String("backup-s3-endpoint", "", "S3-compatible object storage abroad that backups are pushed to, such as https://s3.eu-central-1.amazonaws.com; unset keeps them here only")
	s3Region := fs.String("backup-s3-region", "us-east-1", "the bucket's region")
	s3Bucket := fs.String("backup-s3-bucket", "", "the bucket")
	s3KeyFile := fs.String("backup-s3-key-file", "", "file holding the access key id and the secret key, one per line")
	grafanaURL := fs.String("grafana-url", "http://127.0.0.1:3000", "Grafana on loopback, which Admins reach through the panel at /grafana/; empty shuts /grafana/")
	fs.Parse(args)
	if *showVersion {
		fmt.Println(version)
		return nil
	}

	s, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer s.Close()
	authority, err := ca.LoadOrCreate(*caDir)
	if err != nil {
		return err
	}
	c := coordinator.New(s, authority, log)
	c.PanelURL = *panelURL
	c.BridgeAddress = *bridgeAddress
	c.GrafanaURL = *grafanaURL
	c.FeedURL, c.RIPEstatURL = *feedURL, *ripeURL
	c.SecureCookies = *adminCert != "" // plain HTTP is for development only
	if *arvanKeyFile != "" {
		key, err := os.ReadFile(*arvanKeyFile)
		if err != nil {
			return err
		}
		c.DNS = &arvan.Client{BaseURL: *arvanURL, APIKey: arvan.NormalizeKey(string(key)), Zone: *arvanZone, TTL: *arvanTTL,
			HTTP: &http.Client{Timeout: 30 * time.Second}}
	}
	if err := configureMonitoring(c, *adminCert, uint16(*monitorPort), *monitorFrom, *promTLSDir, *tgTokenFile, *tgChat); err != nil {
		return err
	}
	if err := configureBackups(c, *backupRecipient, *backupDir, *backupKeep, *s3Endpoint, *s3Region, *s3Bucket, *s3KeyFile); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := c.InitProbe(ctx); err != nil {
		return err
	}
	if err := c.Reconcile(ctx); err != nil {
		return err
	}
	go c.RunIRFeed(ctx, 24*time.Hour)
	go c.RunRollUps(ctx, time.Hour)
	go c.RunQuotaPeriods(ctx, time.Minute)
	go c.RunBridgeAddress(ctx)
	go c.RunAlertRelay(ctx)
	go c.RunBackups(ctx)

	agentTLS, err := c.AgentTLSConfig(strings.Split(*agentHosts, ","))
	if err != nil {
		return err
	}
	agentLn, err := net.Listen("tcp", *agentListen)
	if err != nil {
		return err
	}
	agentSrv := &http.Server{Handler: c.AgentHandler(), ReadHeaderTimeout: 10 * time.Second}
	adminSrv := &http.Server{Addr: *adminListen, Handler: c.AdminHandler(), ReadHeaderTimeout: 10 * time.Second}
	internalSrv := &http.Server{Addr: *internalListen, Handler: c.InternalHandler(), ReadHeaderTimeout: 10 * time.Second}

	errs := make(chan error, 3)
	go func() { errs <- agentSrv.Serve(tls.NewListener(agentLn, agentTLS)) }()
	go func() { errs <- internalSrv.ListenAndServe() }()
	go func() {
		if *adminCert != "" {
			errs <- adminSrv.ListenAndServeTLS(*adminCert, *adminKey)
		} else {
			log.Warn("Admin API is plain HTTP; set -admin-tls-cert outside development")
			errs <- adminSrv.ListenAndServe()
		}
	}()
	log.Info("coordinator started", "version", version, "admin", *adminListen, "agent", *agentListen)

	select {
	case err = <-errs:
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	agentSrv.Shutdown(shutdown)
	adminSrv.Shutdown(shutdown)
	internalSrv.Shutdown(shutdown)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

func tokenCreate(args []string) error {
	fs := flag.NewFlagSet("coordinator token create", flag.ExitOnError)
	dbPath := fs.String("db", "/var/lib/ways/ways.db", "SQLite database")
	scope := fs.String("scope", store.ScopeNodesEnroll, "token scope")
	name := fs.String("name", "", "what the token is for, such as laptop (required)")
	ttl := fs.Duration("ttl", 90*24*time.Hour, "how long the token lasts")
	fs.Parse(args)
	if *name == "" {
		return errors.New("token create: -name is required")
	}
	if *scope != store.ScopeNodesEnroll {
		return fmt.Errorf("token create: unknown scope %q", *scope)
	}
	s, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer s.Close()
	secret, tok, err := s.CreateAPIToken(context.Background(), *scope, *name, *ttl)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "created %s (%s), expires %s\n", tok.ID, tok.Scope, tok.ExpiresAt.Format(time.RFC3339))
	fmt.Println(secret)
	return nil
}

func inviteCreate(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("coordinator invite create", flag.ExitOnError)
	dbPath := fs.String("db", "/var/lib/ways/ways.db", "SQLite database")
	admin := fs.Bool("admin", false, "the Invite makes an Admin, who must turn on TOTP before acting as one")
	deviceCap := fs.Int("device-cap", 0, "Device cap for the new User; 0 for the default of 3")
	panelURL := fs.String("panel-url", "https://wayfinder.ir", "where the panel is served")
	fs.Parse(args)
	s, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer s.Close()
	token, expires, err := s.CreateInvite(context.Background(), store.Invite{Kind: "new", Admin: *admin, DeviceCap: *deviceCap}, coordinator.InviteTTL)
	if err != nil {
		return err
	}
	c := coordinator.New(s, nil, log)
	c.PanelURL = *panelURL
	fmt.Fprintf(os.Stderr, "single-use Invite, expires %s; hand it over out of band\n", expires.Format(time.RFC3339))
	fmt.Println(c.InviteURL(token))
	return nil
}
