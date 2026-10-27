package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/comma-compliance/arc-relay/internal/config"
	"github.com/comma-compliance/arc-relay/internal/docker"
	"github.com/comma-compliance/arc-relay/internal/llm"
	"github.com/comma-compliance/arc-relay/internal/middleware"
	"github.com/comma-compliance/arc-relay/internal/oauth"
	"github.com/comma-compliance/arc-relay/internal/optimizer"
	"github.com/comma-compliance/arc-relay/internal/proxy"
	"github.com/comma-compliance/arc-relay/internal/server"
	"github.com/comma-compliance/arc-relay/internal/store"
	"github.com/comma-compliance/arc-relay/migrations"
)

func main() {
	configPath := flag.String("config", "", "path to config file (TOML)")
	flag.Parse()

	// Initialize a default JSON logger before config loads so early errors are structured.
	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelInfo)
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	// Reinitialize logger with the configured level
	logLevel.Set(cfg.SlogLevel())
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Initialize Sentry error tracking
	if cfg.SentryDSN != "" {
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:              cfg.SentryDSN,
			EnableTracing:    false,
			AttachStacktrace: true,
		}); err != nil {
			slog.Warn("sentry init failed", "err", err)
		} else {
			slog.Info("sentry error tracking enabled")
			defer sentry.Flush(2 * time.Second)
		}
	}

	// Open database with embedded migrations
	db, err := store.Open(cfg.Database.Path, migrations.FS)
	if err != nil {
		slog.Error("failed to open database", "err", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	// Initialize stores
	crypto := store.NewConfigEncryptor(cfg.Encryption.Key)
	serverStore := store.NewServerStore(db, crypto)
	userStore := store.NewUserStore(db)
	accessStore := store.NewAccessStore(db)
	profileStore := store.NewProfileStore(db)
	requestLogStore := store.NewRequestLogStore(db)
	sessionStore := store.NewSessionStore(db)

	// Ensure default admin user exists
	adminPw := cfg.Auth.AdminPassword
	if adminPw == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			slog.Error("failed to generate random admin password", "err", err)
			os.Exit(1)
		}
		adminPw = hex.EncodeToString(b)
		// SECURITY: Do not log the generated password in cleartext.
		// It is printed to stderr only so the operator can retrieve it
		// from a secure log sink at startup.
		slog.Warn("no admin password configured, generated random password - set ARC_RELAY_ADMIN_PASSWORD to use a fixed password")
	}
	if err := userStore.EnsureAdmin(adminPw); err != nil {
		slog.Error("failed to ensure admin user", "err", err)
		os.Exit(1)
	}

	// Initialize Docker manager
	dockerMgr, err := docker.NewManager(cfg.Docker.Socket, cfg.Docker.Network)
	if err != nil {
		slog.Warn("docker not available - managed servers will not work, remote servers still available", "err", err)
		dockerMgr = nil
	}

	// Initialize OAuth manager
	oauthMgr := oauth.NewManager(serverStore, cfg.PublicBaseURL())

	// Initialize middleware
	middlewareStore := store.NewMiddlewareStore(db)
	archiveQueueStore := store.NewArchiveQueueStore(db, crypto)
	archiveEventLogger := func(evt *store.MiddlewareEvent) {
		if err := middlewareStore.LogEvent(evt); err != nil {
			slog.Warn("archive dispatcher: failed to log event", "err", err)
		}
	}
	archiveDispatcher := middleware.NewArchiveDispatcher(archiveQueueStore, archiveEventLogger)
	archiveDispatcher.Start()
	mwRegistry := middleware.NewRegistry(middlewareStore, archiveDispatcher)

	// Register custom middleware here. Any type implementing middleware.Middleware
	// can be registered with mwRegistry.Register(descriptor, factoryFunc) and then
	// enabled per-server via the web UI or API. See README.md "Writing Custom
	// Middleware" for a working example.
	//
	// mwRegistry.Register(middleware.Descriptor{
	//     Name: "tenant_tagger", DisplayName: "Tenant Tagger",
	//     Description: "Tags requests with tenant ID",
	//     DefaultPriority: 50, DisplayOrder: 50, Scope: "server",
	// }, mymiddleware.Factory)

	// Initialize proxy manager
	proxyMgr := proxy.NewManager(serverStore, dockerMgr, oauthMgr, accessStore)

	// Auto-start all configured servers
	go func() {
		servers, err := serverStore.List()
		if err != nil {
			slog.Warn("failed to list servers for auto-start", "err", err)
			return
		}
		ctx := context.Background()
		for _, s := range servers {
			if err := proxyMgr.StartServer(ctx, s); err != nil {
				slog.Error("auto-start failed", "server", s.Name, "err", err)
			} else {
				slog.Info("auto-started server", "server", s.Name)
			}
		}
	}()

	// Initialize invite store
	inviteStore := store.NewInviteStore(db)

	// Initialize OAuth token store (for Claude Desktop and other OAuth clients)
	oauthTokenStore := store.NewOAuthTokenStore(db)

	// Start health monitor
	healthMon := proxy.NewHealthMonitor(proxyMgr, serverStore, 30*time.Second)
	healthMon.Start()

	// Start periodic database backup (every 6 hours, keeps 2 copies)
	db.StartBackup(6 * time.Hour)

	// Periodic cleanup of expired OAuth tokens and refresh tokens
	oauthRefreshStore := store.NewOAuthRefreshTokenStore(db)
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			oauthTokenStore.Cleanup()
			oauthRefreshStore.Cleanup()
		}
	}()

	// Initialize tool optimization stores and LLM client
	optimizeStore := store.NewOptimizeStore(db)
	if cfg.LLM.Timeout != "" && cfg.LLM.TimeoutDuration() == 0 {
		slog.Warn("invalid LLM timeout, using default", "value", cfg.LLM.Timeout, "default", llm.DefaultTimeout)
	}
	llmClient := llm.NewClient(cfg.LLM.APIKey, cfg.LLM.Model, cfg.LLM.TimeoutDuration())
	if llmClient.Available() {
		slog.Info("LLM tool optimizer available", "model", llmClient.Model(), "timeout", llmClient.Timeout())
	}
	if n, err := optimizeStore.ResetInFlight(); err != nil {
		slog.Warn("optimize: failed to reset interrupted jobs", "err", err)
	} else if n > 0 {
		slog.Info("optimize: reset jobs interrupted by restart", "count", n)
	}
	optimizeRunner := optimizer.NewRunner(optimizeStore, llmClient, 0)
	proxyMgr.OptimizeStore = optimizeStore

	// Start HTTP server
	srv := server.New(cfg, serverStore, userStore, proxyMgr, oauthMgr, accessStore, profileStore, requestLogStore, sessionStore, middlewareStore, mwRegistry, healthMon, inviteStore, oauthTokenStore, optimizeStore, llmClient, optimizeRunner)

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		slog.Info("shutting down")
		healthMon.Stop()
		archiveDispatcher.Stop()
		db.StopBackup()
		proxyMgr.StopAll(ctx)
		if dockerMgr != nil {
			_ = dockerMgr.Close()
		}
		// Close DB explicitly before exiting so WAL is checkpointed cleanly.
		if err := db.Close(); err != nil {
			slog.Warn("error closing database", "err", err)
		}
		os.Exit(0)
	}()

	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}
