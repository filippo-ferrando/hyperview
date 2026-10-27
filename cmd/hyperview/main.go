package main

import (
	"context"
	"flag"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hyperview/internal/collect"
	"hyperview/internal/probe"
	"hyperview/internal/store"
	"hyperview/internal/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	intervalFlag := flag.Int("interval", 250, "Data collection refresh interval window in milliseconds")
	logLevelFlag := flag.String("log-level", "info", "Structured file logging granularity target (debug|info|warn|error)")
	domainFilterFlag := flag.String("domain", "", "Optional domain instance name keyword string to filter viewport matches on start")
	flag.Parse()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = os.TempDir()
	}
	logDir := filepath.Join(homeDir, ".local", "share", "hyperview")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		log.Fatalf("Fatal directory instantiation collision: %v", err)
	}
	logFilePath := filepath.Join(logDir, "hyperview.log")

	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("Fatal system file access lock: %v", err)
	}
	defer logFile.Close()

	var level slog.Level
	switch strings.ToLower(*logLevelFlag) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	multiWriter := io.MultiWriter(logFile, &tui.GlobalLogRing)
	logger := slog.New(slog.NewTextHandler(multiWriter, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	slog.Info("Hyperview collection runtime engine online",
		slog.Duration("tick_interval", time.Duration(*intervalFlag)*time.Millisecond),
		slog.String("log_path", logFilePath))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	domainStore := store.NewDomainStore()
	poller := collect.NewPoller(domainStore)
	kvmProcs := collect.NewProcessIndex(5 * time.Second)
	libvirtColl := collect.NewLibvirtCollector(kvmProcs)
	poller.Register(libvirtColl)
	poller.Register(collect.NewScanCollector(kvmProcs, libvirtColl.PIDs))
	if procColl, err := collect.NewProcCollector(); err == nil {
		poller.Register(procColl)
	} else {
		slog.Warn("Host OS procfs engine offline", slog.Any("err", err))
	}
	ebpfColl := collect.NewEBPFCollector(probe.Config{})
	poller.Register(ebpfColl)
	go ebpfColl.RunEvents(ctx, func(ev collect.KernelEvent) {
		slog.Info("kernel event", slog.Any("event", ev))
	})
	defer poller.Close()

	tickDuration := time.Duration(*intervalFlag) * time.Millisecond
	go poller.Run(ctx, tickDuration)

	rootModel := tui.NewRootModel(domainStore)
	rootModel.SetTickInterval(tickDuration)
	if *domainFilterFlag != "" {
		rootModel.SetDomainFilter(*domainFilterFlag)
	}

	p := tea.NewProgram(rootModel, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		slog.Error("Fatal UI view engine crash event detected", slog.Any("err", err))
		os.Exit(1)
	}

	cancel()
	slog.Info("Clean shutdown completed cleanly.")
}
