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
	registry := collect.NewRegistry()

	registry.Register(collect.NewLibvirtCollector("/var/run/libvirt/libvirt-sock"))

	procColl, err := collect.NewProcCollector()
	if err == nil {
		registry.Register(procColl)
	} else {
		slog.Warn("Host OS procfs engine offline", slog.Any("err", err))
	}

	registry.Register(collect.NewEBPFCollector())
	registry.Register(collect.NewQMPCollector("/var/run/libvirt/qemu"))

	tickDuration := time.Duration(*intervalFlag) * time.Millisecond
	go func() {
		ticker := time.NewTicker(tickDuration)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, col := range registry.Collectors() {
					if err := col.Collect(ctx, domainStore); err != nil {
						slog.Debug("Poller transaction timeout skipped",
							slog.String("collector", col.Name()),
							slog.Any("err", err))
					}
				}
			}
		}
	}()

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

	for _, col := range registry.Collectors() {
		_ = col.Close()
	}
	slog.Info("Clean shutdown completed cleanly.")
}
