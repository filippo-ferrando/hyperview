package tui

import (
	"cmp"
	"fmt"
	"image/color"
	"maps"
	"slices"
	"strings"

	"charm.land/lipgloss/v2"

	"hyperview/internal/alert"
	"hyperview/internal/store"
)

func (m *Model) detailTabs() []string {
	tabs := []string{"Overview", "CPU", "Memory", "Network", "Disk", "KVM", "Alerts"}
	if d, ok := m.selected(); ok && d.Migration != nil {
		tabs = append(tabs, "Migration")
	}
	return tabs
}

func (m *Model) viewDetail(d store.DomainSnapshot) string {
	header := m.viewHeader()
	tabs := m.detailTabs()
	m.tab = min(m.tab, len(tabs)-1)

	// Full labels when they fit, otherwise only the active tab is named.
	tabBar := func(compact bool) string {
		var bar []string
		for i, t := range tabs {
			label := fmt.Sprintf("%d %s", i+1, t)
			if compact && i != m.tab {
				label = fmt.Sprint(i + 1)
			}
			if t == "Alerts" {
				if c := m.counts[d.ID]; c.N > 0 {
					label += fg(severityColor(c.Worst)).Render(fmt.Sprintf(" %s%d", severityIcon(c.Worst), c.N))
				}
			}
			if i == m.tab {
				bar = append(bar, stTabOn.Render(label))
			} else {
				bar = append(bar, stTabOff.Render(label))
			}
		}
		return " " + strings.Join(bar, "")
	}
	state := fg(stateColor(d.State, d.Reason)).Render("● " + d.State)
	if d.Reason != "" {
		state += stMuted.Render(" (" + d.Reason + ")")
	}
	tabLine := tabBar(false) + "  " + state
	if lipgloss.Width(tabLine) > m.width {
		tabLine = tabBar(true) + "  " + state
	}

	footer := m.viewFooter([][2]string{{"←→/1-9", "tab"}, {"esc", "back"}, {"↑↓", "scroll"}, {"a", "alerts"}, {"p", "probes"}, {"?", "help"}})
	bodyH := m.height - lipgloss.Height(header) - lipgloss.Height(footer) - 1
	inner := m.width - 4

	var content string
	switch tabs[m.tab] {
	case "Overview":
		content = m.detailOverview(&d, inner)
	case "CPU":
		content = m.detailCPU(&d, inner)
	case "Memory":
		content = m.detailMemory(&d, inner)
	case "Network":
		content = m.detailNet(&d, inner)
	case "Disk":
		content = m.detailDisk(&d, inner)
	case "KVM":
		content = m.detailKVM(&d, inner)
	case "Alerts":
		content = m.detailAlerts(&d, inner, bodyH-2)
	case "Migration":
		content = m.detailMigration(&d, inner)
	}
	lines := strings.Split(content, "\n")
	maxScroll := max(len(lines)-(bodyH-2), 0)
	m.scroll = min(m.scroll, maxScroll)
	lines = lines[m.scroll:]
	if len(lines) > bodyH-2 {
		lines = lines[:bodyH-2]
	}
	for len(lines) < bodyH-2 {
		lines = append(lines, "")
	}

	title := " " + d.Name + " "
	right := fmt.Sprintf(" %s · pid %d ", d.Source, d.PID)
	panel := box(strings.Join(lines, "\n"), m.width, title, right, true)
	return lipgloss.JoinVertical(lipgloss.Left, header, fit(tabLine, m.width), panel, footer)
}

// kv renders "label value" pairs in aligned columns.
func kvGrid(pairs [][2]string, cols, width int) string {
	// Each column needs room for a 16-cell label and a value.
	cols = max(min(cols, width/34), 1)
	colW := width / cols
	var rows []string
	for i := 0; i < len(pairs); i += cols {
		var b strings.Builder
		for j := i; j < i+cols && j < len(pairs); j++ {
			b.WriteString(fit(stLabel.Render(fit(pairs[j][0], 16))+pairs[j][1], colW-2) + "  ")
		}
		rows = append(rows, b.String())
	}
	return strings.Join(rows, "\n")
}

func section(title string) string {
	return stTitle.Render(title)
}

// chart renders a labeled sparkline with its current value.
func chart(label string, vals []float64, width int, ceil float64, c color.Color, value string) string {
	valW := min(18, max(width/5, 10))
	return stLabel.Render(fit(label, 14)) + sparkline(vals, max(width-16-valW, 4), ceil, c) + "  " + fg(c).Render(fit(value, valW))
}

// tallChart renders a multi-row area chart with the label and current
// value on its first row.
func tallChart(label string, vals []float64, width, rows int, ceil float64, c color.Color, value string) string {
	valW := min(18, max(width/5, 10))
	graph := areaChart(vals, max(width-16-valW, 4), rows, ceil, c)
	out := strings.Split(graph, "\n")
	for i := range out {
		left, right := "", ""
		if i == 0 {
			left, right = label, fg(c).Render(value)
		}
		out[i] = stLabel.Render(fit(left, 14)) + out[i] + "  " + right
	}
	return strings.Join(out, "\n")
}

func last(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	return v[len(v)-1]
}

func (m *Model) detailOverview(d *store.DomainSnapshot, w int) string {
	// Taller charts only when the terminal has the rows for them.
	big, small := 1, 1
	if m.height >= 40 {
		big, small = 3, 2
	} else if m.height >= 32 {
		big = 2
	}
	h := m.src.Store.History(d.ID)
	nv := max(len(d.VCPUs), 1)
	rx, tx := d.NetRates()
	rd, wr := d.DiskRates()
	memMax := max(d.Mem.MaxKiB, d.Mem.BalloonKiB)
	pairs := [][2]string{
		{"UUID", stBase.Render(orDash(d.UUID))},
		{"vCPUs", stBase.Render(fmt.Sprint(len(d.VCPUs)))},
		{"Memory", stBase.Render(fmtKiB(memMax))},
		{"Host RSS", stBase.Render(fmtKiB(d.Mem.RssKiB))},
		{"Interfaces", stBase.Render(fmt.Sprint(len(d.Ifaces)))},
		{"Disks", stBase.Render(fmt.Sprint(len(d.Disks)))},
	}
	var out []string
	out = append(out, kvGrid(pairs, 3, w), "")
	cpuC := levelColor(d.CPUPercent()/float64(nv), 80, 95)
	out = append(out,
		tallChart("CPU", h.CPU, w, big, float64(nv)*100, cpuC, fmt.Sprintf("%.1f%% of %d vCPU", d.CPUPercent(), nv)),
		tallChart("Net ↓ rx", h.RX, w, small, 0, colRx, fmtRate(rx)),
		tallChart("Net ↑ tx", h.TX, w, small, 0, colTx, fmtRate(tx)),
		tallChart("Disk read", h.DiskRd, w, small, 0, colCyan, fmtRate(rd)),
		tallChart("Disk write", h.DiskWr, w, small, 0, colPurple, fmtRate(wr)),
	)
	if d.KVM.Available {
		th := m.src.Config.Thresholds.RunqP99Us
		out = append(out,
			tallChart("VM exits", h.ExitRate, w, small, 0, colAccent, fmtNum(d.KVM.ExitRate)+"/s"),
			tallChart("Run-queue p99", h.RunqP99, w, small, 0, levelColor(d.KVM.RunqP99Us, th.Warn, th.Crit), fmtUs(d.KVM.RunqP99Us)),
		)
	}
	if as := m.domainAlerts(d.ID); len(as) > 0 {
		out = append(out, "", section("Latest alerts"))
		for i := 0; i < len(as) && i < 5; i++ {
			out = append(out, alertLine(&as[i], w, false))
		}
	}
	return strings.Join(out, "\n")
}

func (m *Model) detailCPU(d *store.DomainSnapshot, w int) string {
	th := m.src.Config.Thresholds
	cols := layout([]column{
		{title: "vCPU", width: 5},
		{title: "TID", width: 8, right: true, prio: 2},
		{title: "HOST CPU", width: 9, right: true, prio: 1},
		{title: "USAGE", flex: 1, min: 6, prio: 3},
		{title: "%", width: 6, right: true},
		{title: "EXITS/s", width: 9, right: true, prio: 6},
		{title: "HALTS/s", width: 9, right: true, prio: 4},
		{title: "RUNQ avg", width: 9, right: true, prio: 5},
		{title: "p99", width: 9, right: true},
		{title: "max", width: 9, right: true, prio: 7},
	}, w)
	out := []string{stHeadRow.Render(renderRow(cols, titles(cols)))}
	for _, v := range d.VCPUs {
		c := levelColor(v.CPUPercent, 80, 95)
		host := "–"
		if v.HostCPU >= 0 && v.TID > 0 {
			host = fmt.Sprint(v.HostCPU)
		}
		runqC := levelColor(v.RunqP99Us, th.RunqP99Us.Warn, th.RunqP99Us.Crit)
		out = append(out, renderRow(cols, []string{
			stBold.Render(fmt.Sprint(v.Index)), stMuted.Render(fmt.Sprint(v.TID)), stBase.Render(host),
			bar(v.CPUPercent/100, cols[3].width, c), fg(c).Render(fmt.Sprintf("%.1f", v.CPUPercent)),
			fg(levelColor(v.ExitRate, th.VCPUExitRate.Warn, th.VCPUExitRate.Crit)).Render(fmtNum(v.ExitRate)),
			stBase.Render(fmtNum(v.HaltWaitRate)),
			stBase.Render(fmtUs(v.RunqAvgUs)), fg(runqC).Render(fmtUs(v.RunqP99Us)), stMuted.Render(fmtUs(v.RunqMaxUs)),
		}))
	}
	if len(d.VCPUs) == 0 {
		out = append(out, stMuted.Render("no vCPU threads found"))
	}
	h := m.src.Store.History(d.ID)
	nv := max(len(d.VCPUs), 1)
	out = append(out, "", chart("CPU", h.CPU, w, float64(nv)*100, colGreen, fmt.Sprintf("%.1f%%", d.CPUPercent())))
	if d.KVM.Available {
		out = append(out, chart("Run-queue p99", h.RunqP99, w, 0, colAmber, fmtUs(d.KVM.RunqP99Us)))
		out = append(out, "")
		for _, l := range wrap("Run-queue delay is the time a runnable vCPU thread waited for a host CPU (steal time seen by the guest).", w) {
			out = append(out, stMuted.Render(l))
		}
	} else {
		out = append(out, "", m.ebpfHint(w))
	}
	return strings.Join(out, "\n")
}

func (m *Model) detailMemory(d *store.DomainSnapshot, w int) string {
	mm := d.Mem
	total := max(mm.MaxKiB, mm.BalloonKiB, mm.AvailableKiB)
	gauge := func(label string, v uint64, c color.Color) string {
		if total == 0 {
			return stLabel.Render(fit(label, 16)) + stMuted.Render("–")
		}
		return stLabel.Render(fit(label, 16)) + bar(float64(v)/float64(total), max(w-40, 6), c) + "  " +
			fg(c).Render(fmtKiB(v)) + stMuted.Render(fmt.Sprintf(" (%.0f%%)", 100*float64(v)/float64(total)))
	}
	out := []string{section("Allocation"),
		kvGrid([][2]string{
			{"Configured", stBase.Render(fmtKiB(mm.MaxKiB))},
			{"Balloon", stBase.Render(orDashKiB(mm.BalloonKiB))},
			{"Guest total", stBase.Render(orDashKiB(mm.AvailableKiB))},
		}, 3, w), "",
		gauge("Host RSS", mm.RssKiB, colAccent),
	}
	if mm.AvailableKiB > 0 {
		th := m.src.Config.Thresholds.GuestMemFreePct
		freePct := 100 * float64(mm.UsableKiB) / float64(mm.AvailableKiB)
		c := colGreen
		if th.Crit > 0 && freePct <= th.Crit {
			c = colRed
		} else if th.Warn > 0 && freePct <= th.Warn {
			c = colAmber
		}
		out = append(out, gauge("Guest usable", mm.UsableKiB, c), gauge("Guest unused", mm.UnusedKiB, colCyan))
	} else {
		out = append(out, "", stMuted.Render(strings.Join(wrap("Guest memory statistics need the virtio balloon driver (libvirt guests).", w), "\n")))
	}
	th := m.src.Config.Thresholds
	out = append(out, "", section("Pressure"), kvGrid([][2]string{
		{"Guest swap in", fg(levelColor(mm.SwapInRate, th.GuestSwapInKiBs.Warn, th.GuestSwapInKiBs.Crit)).Render(fmtKiBRate(mm.SwapInRate))},
		{"Guest swap out", stBase.Render(fmtKiBRate(mm.SwapOutRate))},
		{"Hugetlb fails", stBase.Render(fmt.Sprint(mm.HugetlbFail))},
		{"Host major flt", fg(levelColor(mm.MajorFltRate, th.MajorFaultRate.Warn, th.MajorFaultRate.Crit)).Render(fmtNum(mm.MajorFltRate) + "/s")},
		{"Host minor flt", stBase.Render(fmtNum(mm.MinorFltRate) + "/s")},
	}, 3, w))
	return strings.Join(out, "\n")
}

func (m *Model) detailNet(d *store.DomainSnapshot, w int) string {
	if len(d.Ifaces) == 0 {
		return stMuted.Render("no network interfaces")
	}
	cols := layout([]column{
		{title: "IFACE", flex: 1, min: 8, max: 16},
		{title: "↓ RX", width: 10, right: true},
		{title: "↑ TX", width: 10, right: true},
		{title: "RX pps", width: 8, right: true, prio: 2},
		{title: "TX pps", width: 8, right: true, prio: 1},
		{title: "ERRORS", width: 7, right: true, prio: 5},
		{title: "DROPS", width: 8, right: true, prio: 3},
		{title: "DROP/s", width: 7, right: true, prio: 6},
		{title: "KERN DROP/s", width: 11, right: true, prio: 4},
	}, w)
	th := m.src.Config.Thresholds.NetDropRate
	out := []string{stHeadRow.Render(renderRow(cols, titles(cols)))}
	for _, i := range d.Ifaces {
		errC := colFg
		if i.RxErrs+i.TxErrs > 0 {
			errC = colAmber
		}
		kd := "–"
		if d.KVM.Available {
			kd = fmtNum(i.KernelDropRate)
		}
		out = append(out, renderRow(cols, []string{
			stBold.Render(i.Name), fg(colRx).Render(fmtRate(i.RxBps)), fg(colTx).Render(fmtRate(i.TxBps)),
			stBase.Render(fmtNum(i.RxPps)), stBase.Render(fmtNum(i.TxPps)),
			fg(errC).Render(fmt.Sprint(i.RxErrs + i.TxErrs)), stBase.Render(fmt.Sprint(i.RxDrops + i.TxDrops)),
			fg(levelColor(i.DropRate, th.Warn, th.Crit)).Render(fmtNum(i.DropRate)),
			fg(levelColor(i.KernelDropRate, th.Warn, th.Crit)).Render(kd),
		}))
	}
	var reasons []string
	for _, i := range d.Ifaces {
		for _, r := range sortedByValue(i.DropReasons) {
			reasons = append(reasons, fmt.Sprintf("  %s %s %s", stBold.Render(fit(i.Name, min(14, w/5))),
				fg(colAmber).Render(fitRight(fmtNum(i.DropReasons[r])+"/s", 9)), stBase.Render(r)))
		}
	}
	if len(reasons) > 0 {
		out = append(out, "", section("Kernel drop reasons (eBPF)"))
		out = append(out, reasons...)
	}
	h := m.src.Store.History(d.ID)
	rx, tx := d.NetRates()
	out = append(out, "", chart("Total ↓ rx", h.RX, w, 0, colRx, fmtRate(rx)), chart("Total ↑ tx", h.TX, w, 0, colTx, fmtRate(tx)))
	return strings.Join(out, "\n")
}

func (m *Model) detailDisk(d *store.DomainSnapshot, w int) string {
	var out []string
	if len(d.Disks) == 0 {
		out = append(out, stMuted.Render("no disks"))
	} else {
		cols := layout([]column{
			{title: "DEVICE", flex: 1, min: 8, max: 20},
			{title: "READ", width: 10, right: true},
			{title: "WRITE", width: 10, right: true},
			{title: "R IOPS", width: 8, right: true, prio: 2},
			{title: "W IOPS", width: 8, right: true, prio: 1},
			{title: "ERRORS", width: 7, right: true, prio: 3},
		}, w)
		out = append(out, stHeadRow.Render(renderRow(cols, titles(cols))))
		for _, dk := range d.Disks {
			errs := stMuted.Render("n/a")
			if dk.ErrsTotal > 0 {
				errs = fg(colRed).Render(fmt.Sprint(dk.ErrsTotal))
			} else if dk.ErrsTotal == 0 {
				errs = stBase.Render("0")
			}
			out = append(out, renderRow(cols, []string{
				stBold.Render(dk.Dev), fg(colCyan).Render(fmtRate(dk.RdBps)), fg(colPurple).Render(fmtRate(dk.WrBps)),
				stBase.Render(fmtNum(dk.RdIOPS)), stBase.Render(fmtNum(dk.WrIOPS)), errs,
			}))
		}
	}
	if d.KVM.Available {
		th := m.src.Config.Thresholds.VMBlockP99Us
		out = append(out, "", section("Block latency of this VM's I/O (eBPF)"), kvGrid([][2]string{
			{"Average", stBase.Render(fmtUs(d.BlkLatAvgUs))},
			{"p99", fg(levelColor(d.BlkLatP99Us, th.Warn, th.Crit)).Render(fmtUs(d.BlkLatP99Us))},
		}, 3, w))
	}
	h := m.src.Store.History(d.ID)
	rd, wr := d.DiskRates()
	out = append(out, "", chart("Read", h.DiskRd, w, 0, colCyan, fmtRate(rd)), chart("Write", h.DiskWr, w, 0, colPurple, fmtRate(wr)))
	return strings.Join(out, "\n")
}

func (m *Model) detailKVM(d *store.DomainSnapshot, w int) string {
	k := d.KVM
	if !k.Available {
		return m.ebpfHint(w)
	}
	out := []string{kvGrid([][2]string{
		{"Exits", stBold.Render(fmtNum(k.ExitRate) + "/s")},
		{"IRQ injections", stBase.Render(fmtNum(k.IRQRate) + "/s")},
		{"Exceptions", stBase.Render(fmtNum(k.ExceptionRate) + "/s")},
		{"Halt polls ok", stBase.Render(fmtNum(k.HaltPollRate) + "/s")},
		{"Halt sleeps", stBase.Render(fmtNum(k.HaltWaitRate) + "/s")},
		{"Emulation fails", errCount(k.EmulFailTotal)},
	}, 3, w), ""}

	nameW := min(26, max(w/3, 12))
	barW := max(w-nameW-16, 4)
	rateTable := func(title string, m map[string]float64, c color.Color) {
		if len(m) == 0 {
			return
		}
		out = append(out, section(title))
		keys := sortedByValue(m)
		top := m[keys[0]]
		for i, name := range keys {
			if i == 12 {
				out = append(out, stMuted.Render(fmt.Sprintf("  … %d more", len(keys)-i)))
				break
			}
			v := m[name]
			frac := 0.0
			if top > 0 {
				frac = v / top
			}
			out = append(out, "  "+stBase.Render(fit(name, nameW))+bar(frac, barW, c)+" "+fitRight(fmtNum(v)+"/s", 10))
		}
		out = append(out, "")
	}
	rateTable("Exit reasons", k.ExitReasons, colAccent)
	rateTable("Returns to userspace (KVM_EXIT_*)", k.UserExits, colPurple)
	h := m.src.Store.History(d.ID)
	out = append(out, chart("Exits/s", h.ExitRate, w, 0, colAccent, fmtNum(k.ExitRate)))
	return strings.Join(out, "\n")
}

func (m *Model) detailAlerts(d *store.DomainSnapshot, w, h int) string {
	as := m.domainAlerts(d.ID)
	if len(as) == 0 {
		return fg(colGreen).Render("✔ ") + stMuted.Render("no alerts for this VM")
	}
	var out []string
	for i := range as {
		out = append(out, alertLine(&as[i], w, false))
	}
	return strings.Join(out, "\n")
}

func (m *Model) detailMigration(d *store.DomainSnapshot, w int) string {
	mg := d.Migration
	if mg == nil {
		return stMuted.Render("no migration in progress")
	}
	frac := 0.0
	if mg.MemTotal > 0 {
		frac = float64(mg.MemTotal-min(mg.MemRemaining, mg.MemTotal)) / float64(mg.MemTotal)
	}
	statusC := colAccent
	switch mg.Status {
	case "completed":
		statusC = colGreen
	case "failed", "cancelled":
		statusC = colRed
	}
	return strings.Join([]string{
		kvGrid([][2]string{
			{"Operation", stBase.Render(mg.Operation)},
			{"Status", fg(statusC).Bold(true).Render(mg.Status)},
			{"Elapsed", stBase.Render(fmtMs(mg.ElapsedMs))},
		}, 3, w), "",
		stLabel.Render(fit("Memory", 16)) + bar(frac, max(w-30, 6), statusC) + fmt.Sprintf("  %.1f%%", frac*100), "",
		kvGrid([][2]string{
			{"Transferred", stBase.Render(fmtBytes(float64(mg.MemProcessed)))},
			{"Remaining", stBase.Render(fmtBytes(float64(mg.MemRemaining)))},
			{"Total", stBase.Render(fmtBytes(float64(mg.MemTotal)))},
			{"Bandwidth", stBase.Render(fmtRate(float64(mg.Bps)))},
			{"Dirty rate", stBase.Render(fmtNum(float64(mg.DirtyPageRate)) + " pages/s")},
			{"Exp. downtime", stBase.Render(fmtMs(mg.ExpectedDownMs))},
		}, 3, w),
	}, "\n")
}

func (m *Model) ebpfHint(w int) string {
	reason := "eBPF probes are not loaded"
	if m.src.EBPF != nil {
		if ok, why := m.src.EBPF(); !ok && why != "" {
			reason = "eBPF disabled: " + why
		}
	}
	return stMuted.Render(strings.Join(wrap(reason+" — KVM exits, run-queue latency and kernel drop reasons are unavailable.", w), "\n"))
}

func (m *Model) domainAlerts(id string) []alert.Alert {
	var out []alert.Alert
	for _, a := range m.alerts {
		if a.DomainID == id {
			out = append(out, a)
		}
	}
	return out
}

func sortedByValue(m map[string]float64) []string {
	keys := slices.Collect(maps.Keys(m))
	slices.SortFunc(keys, func(a, b string) int {
		if c := cmp.Compare(m[b], m[a]); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
	})
	return keys
}

func errCount(n uint64) string {
	if n > 0 {
		return fg(colRed).Render(fmt.Sprint(n))
	}
	return stBase.Render("0")
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

func orDashKiB(k uint64) string {
	if k == 0 {
		return "–"
	}
	return fmtKiB(k)
}

func fmtKiBRate(k float64) string { return fmtRate(k * 1024) }

func fmtMs(ms uint64) string { return fmtUs(float64(ms) * 1000) }
