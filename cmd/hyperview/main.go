package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"hyperview/internal/alert"
	"hyperview/internal/collect"
	"hyperview/internal/config"
	"hyperview/internal/kmsg"
	"hyperview/internal/probe"
	"hyperview/internal/store"
	"hyperview/internal/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	configFlag := flag.String("config", "", "TOML configuration file (default "+config.DefaultPath+" when present)")
	intervalFlag := flag.Duration("interval", 0, "collection interval, overrides the config file (e.g. 1s, 500ms)")
	logLevelFlag := flag.String("log-level", "", "log level: debug|info|warn|error, overrides the config file")
	domainFilterFlag := flag.String("domain", "", "initial VM name filter")
	flag.Parse()

	cfg, err := config.Load(*configFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hyperview:", err)
		os.Exit(2)
	}
	if *intervalFlag > 0 {
		cfg.Interval.Duration = *intervalFlag
	}
	if *logLevelFlag != "" {
		cfg.LogLevel = *logLevelFlag
	}
	for _, f := range cfg.Probes.Disabled {
		if !slices.Contains(probe.AllFeatures, f) {
			fmt.Fprintf(os.Stderr, "hyperview: unknown probe feature %q (known: %s)\n", f, strings.Join(probe.AllFeatures, ", "))
			os.Exit(2)
		}
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = os.TempDir()
	}
	logDir := filepath.Join(homeDir, ".local", "share", "hyperview")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		log.Fatalf("create log directory: %v", err)
	}
	logFilePath := filepath.Join(logDir, "hyperview.log")
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("open log file: %v", err)
	}
	defer logFile.Close()

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(io.MultiWriter(logFile, &tui.GlobalLogRing), &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	slog.Info("hyperview starting", slog.Duration("interval", cfg.Interval.Duration), slog.String("log", logFilePath))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	domainStore := store.NewDomainStore()
	engine := alert.NewEngine(cfg.Alerts)
	engine.Subscribe(func(a alert.Alert, t alert.Transition) {
		if t == alert.Repeated {
			return
		}
		slog.Info("alert "+string(t), slog.String("alert", a.String()))
	})

	poller := collect.NewPoller(domainStore)
	defer poller.Close()
	kvmProcs := collect.NewProcessIndex(5 * time.Second)
	libvirtColl := collect.NewLibvirtCollector(kvmProcs)
	poller.Register(libvirtColl)
	poller.Register(collect.NewScanCollector(kvmProcs, libvirtColl.PIDs))
	if cfg.QMP.Enabled {
		poller.Register(collect.NewQMPCollector(kvmProcs, cfg.QMP.Interval.Duration, cfg.QMP.Timeout.Duration))
	}
	if hostColl, err := collect.NewHostCollector(); err == nil {
		poller.Register(hostColl)
	} else {
		slog.Warn("host statistics unavailable", slog.Any("err", err))
	}
	if procColl, err := collect.NewProcCollector(); err == nil {
		poller.Register(procColl)
	} else {
		slog.Warn("process statistics unavailable", slog.Any("err", err))
	}
	ebpfColl := collect.NewEBPFCollector(probe.Config{Disabled: cfg.ProbeDisabled()})
	poller.Register(ebpfColl)

	go ebpfColl.RunEvents(ctx, func(ev collect.KernelEvent) {
		if a, ok := alert.FromProbeEvent(ev.Event, ev.DomainID, ev.DomainName); ok {
			engine.Raise(a)
		}
	})

	if cfg.Kmsg.Enabled {
		if r, err := kmsg.Open(); err == nil {
			lookup := func(pid int) (string, string, bool) {
				d, ok := collect.DomainByPID(domainStore, pid)
				return d.ID, d.Name, ok
			}
			go func() {
				if err := alert.FollowKmsg(ctx, r, cfg.Kmsg.Replay.Duration, lookup, engine.Raise); err != nil {
					slog.Warn("kernel log reader stopped", slog.Any("err", err))
				}
			}()
		} else {
			slog.Warn("kernel log unavailable", slog.Any("err", err))
		}
	}

	detector := alert.NewDetector(engine, cfg.Thresholds)
	poller.AfterTick(func(now time.Time) {
		detector.Run(now, domainStore.Host(), domainStore.Snapshot())
	})
	go poller.Run(ctx, cfg.Interval.Duration)

	rootModel := tui.NewRootModel(domainStore)
	rootModel.SetTickInterval(cfg.Interval.Duration)
	if *domainFilterFlag != "" {
		rootModel.SetDomainFilter(*domainFilterFlag)
	}

	p := tea.NewProgram(rootModel, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		slog.Error("UI failed", slog.Any("err", err))
		os.Exit(1)
	}
	cancel()
	slog.Info("hyperview stopped")
}
