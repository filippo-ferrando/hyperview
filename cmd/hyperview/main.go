package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"hyperview/internal/alert"
	"hyperview/internal/collect"
	"hyperview/internal/config"
	"hyperview/internal/kmsg"
	"hyperview/internal/metrics"
	"hyperview/internal/probe"
	"hyperview/internal/sink"
	"hyperview/internal/store"
	"hyperview/internal/tui"

	tea "charm.land/bubbletea/v2"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// listenFlag is a flag usable both as "--listen" (default address) and
// "--listen=ADDR".
type listenFlag struct{ addr string }

func (l *listenFlag) String() string   { return l.addr }
func (l *listenFlag) IsBoolFlag() bool { return true }
func (l *listenFlag) Set(s string) error {
	switch s {
	case "true":
		l.addr = metrics.DefaultListen
	case "false":
		l.addr = ""
	default:
		l.addr = s
	}
	return nil
}

func main() {
	var listen listenFlag
	configFlag := flag.String("config", "", "TOML configuration file (default "+config.DefaultPath+" when present)")
	intervalFlag := flag.Duration("interval", 0, "collection interval, overrides the config file (e.g. 1s, 500ms)")
	logLevelFlag := flag.String("log-level", "", "log level: debug|info|warn|error, overrides the config file")
	domainFilterFlag := flag.String("domain", "", "initial VM name filter")
	headless := flag.Bool("headless", false, "run without the UI and write alerts to journald or as JSON lines to stdout")
	flag.Var(&listen, "listen", "serve Prometheus metrics; --listen uses "+metrics.DefaultListen+", --listen=ADDR picks the address")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("hyperview", version)
		return
	}
	cfg, err := config.Load(*configFlag)
	if err != nil {
		fatal(err)
	}
	if *intervalFlag > 0 {
		cfg.Interval.Duration = *intervalFlag
	}
	if *logLevelFlag != "" {
		cfg.LogLevel = *logLevelFlag
	}
	if listen.addr != "" {
		cfg.Listen = listen.addr
	}
	for _, f := range cfg.Probes.Disabled {
		if !slices.Contains(probe.AllFeatures, f) {
			fatal(fmt.Errorf("unknown probe feature %q (known: %s)", f, strings.Join(probe.AllFeatures, ", ")))
		}
	}

	closeLog := setupLogging(cfg.LogLevel, *headless)
	defer closeLog()
	slog.Info("hyperview starting", slog.String("version", version), slog.Duration("interval", cfg.Interval.Duration))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	rt := build(cfg)
	defer rt.poller.Close()

	if cfg.Listen != "" {
		mc := metrics.NewCollector(metrics.Sources{
			Store: rt.store, Alerts: rt.engine, Probes: rt.ebpf.Status, EBPF: rt.ebpf.Enabled,
			Kmsg: rt.KmsgState, Version: version,
		})
		go func() {
			if err := metrics.Serve(ctx, cfg.Listen, mc); err != nil {
				slog.Error("metrics endpoint failed", slog.String("addr", cfg.Listen), slog.Any("err", err))
				if *headless {
					cancel()
				}
			}
		}()
	}

	// Subscribers are in place before sources start, so alerts from the
	// kernel log replay are not missed.
	if *headless {
		closeSink := headlessSink(rt)
		defer closeSink()
		rt.run(ctx)
		logProbeStatus(rt)
		<-ctx.Done()
		slog.Info("hyperview stopped")
		return
	}

	rt.engine.Subscribe(func(a alert.Alert, t alert.Transition) {
		if sink.Emitted(t) {
			slog.Info("alert "+string(t), slog.String("alert", a.String()))
		}
	})
	rt.run(ctx)
	ui := tui.New(tui.Sources{
		Store:   rt.store,
		Alerts:  rt.engine,
		Config:  cfg,
		Probes:  rt.ebpf.Status,
		EBPF:    rt.ebpf.Enabled,
		Kmsg:    rt.KmsgState,
		Libvirt: rt.libvirt.Connected,
	}, *domainFilterFlag)
	if _, err := tea.NewProgram(ui, tea.WithContext(ctx)).Run(); err != nil && ctx.Err() == nil {
		slog.Error("UI failed", slog.Any("err", err))
		os.Exit(1)
	}
	slog.Info("hyperview stopped")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "hyperview:", err)
	os.Exit(2)
}

// setupLogging logs to stderr in headless mode (journald under systemd) and
// to a file plus the UI's log view otherwise.
func setupLogging(levelName string, headless bool) (closeFn func()) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(levelName)); err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if headless {
		if sink.UnderJournald() {
			slog.SetDefault(slog.New(sink.NewJournalLevelHandler(os.Stderr, opts)))
		} else {
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, opts)))
		}
		return func() {}
	}

	dir := filepath.Join(os.TempDir(), "hyperview")
	if home, err := os.UserHomeDir(); err == nil {
		dir = filepath.Join(home, ".local", "share", "hyperview")
	}
	var w io.Writer = &tui.GlobalLogRing
	f, err := openLog(dir)
	if err == nil {
		w = io.MultiWriter(f, &tui.GlobalLogRing)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(w, opts)))
	if err != nil {
		slog.Warn("log file unavailable, logging to the UI only", slog.Any("err", err))
		return func() {}
	}
	return func() { f.Close() }
}

func openLog(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(dir, "hyperview.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}

// runtime holds the collection pipeline.
type runtime struct {
	cfg       config.Config
	store     *store.DomainStore
	engine    *alert.Engine
	poller    *collect.Poller
	libvirt   *collect.LibvirtCollector
	ebpf      *collect.EBPFCollector
	kmsgState atomic.Value // string: empty while following the kernel log
}

// build creates collectors and loads the eBPF probes without starting
// anything.
func build(cfg config.Config) *runtime {
	rt := &runtime{cfg: cfg, store: store.NewDomainStore(), engine: alert.NewEngine(cfg.Alerts)}
	rt.poller = collect.NewPoller(rt.store)

	kvmProcs := collect.NewProcessIndex(5 * time.Second)
	rt.libvirt = collect.NewLibvirtCollector(kvmProcs)
	rt.poller.Register(rt.libvirt)
	rt.poller.Register(collect.NewScanCollector(kvmProcs, rt.libvirt.PIDs))
	if cfg.QMP.Enabled {
		rt.poller.Register(collect.NewQMPCollector(kvmProcs, cfg.QMP.Interval.Duration, cfg.QMP.Timeout.Duration))
	}
	if hostColl, err := collect.NewHostCollector(); err == nil {
		rt.poller.Register(hostColl)
	} else {
		slog.Warn("host statistics unavailable", slog.Any("err", err))
	}
	if procColl, err := collect.NewProcCollector(); err == nil {
		rt.poller.Register(procColl)
	} else {
		slog.Warn("process statistics unavailable", slog.Any("err", err))
	}
	rt.ebpf = collect.NewEBPFCollector(probe.Config{Disabled: cfg.ProbeDisabled()})
	rt.poller.Register(rt.ebpf)
	rt.kmsgState.Store("disabled in config")
	return rt
}

// KmsgState is empty while the kernel log is followed, otherwise the reason.
func (rt *runtime) KmsgState() string { return rt.kmsgState.Load().(string) }

// run starts event sources, detectors and polling.
func (rt *runtime) run(ctx context.Context) {
	cfg := rt.cfg
	go rt.ebpf.RunEvents(ctx, func(ev collect.KernelEvent) {
		if a, ok := alert.FromProbeEvent(ev.Event, ev.DomainID, ev.DomainName); ok {
			rt.engine.Raise(a)
		}
	})

	if cfg.Kmsg.Enabled {
		if r, err := kmsg.Open(); err == nil {
			rt.kmsgState.Store("")
			lookup := func(pid int) (string, string, bool) {
				d, ok := collect.DomainByPID(rt.store, pid)
				return d.ID, d.Name, ok
			}
			go func() {
				if err := alert.FollowKmsg(ctx, r, cfg.Kmsg.Replay.Duration, lookup, rt.engine.Raise); err != nil {
					rt.kmsgState.Store("stopped: " + err.Error())
					slog.Warn("kernel log reader stopped", slog.Any("err", err))
				}
			}()
		} else {
			rt.kmsgState.Store(err.Error())
			slog.Warn("kernel log unavailable", slog.Any("err", err))
		}
	}

	detector := alert.NewDetector(rt.engine, cfg.Thresholds)
	rt.poller.AfterTick(func(now time.Time) {
		detector.Run(now, rt.store.Host(), rt.store.Snapshot())
	})
	go rt.poller.Run(ctx, cfg.Interval.Duration)
}

// headlessSink subscribes the journald or JSON sink to the alert engine.
func headlessSink(rt *runtime) (closeFn func()) {
	if sink.UnderJournald() {
		if j, err := sink.NewJournal(); err == nil {
			rt.engine.Subscribe(j.Write)
			slog.Info("writing alerts to journald")
			return func() { j.Close() }
		} else {
			slog.Warn("journald unavailable, writing JSON to stdout", slog.Any("err", err))
		}
	}
	rt.engine.Subscribe(sink.NewJSON(os.Stdout).Write)
	return func() {}
}

func logProbeStatus(rt *runtime) {
	if ok, _ := rt.ebpf.Enabled(); !ok {
		return // already logged when loading
	}
	for _, st := range rt.ebpf.Status() {
		if st.State != probe.Attached {
			slog.Info("eBPF probe inactive", slog.String("feature", st.Feature), slog.String("probe", st.Probe),
				slog.String("state", st.State.String()), slog.String("reason", st.Err))
		}
	}
}
