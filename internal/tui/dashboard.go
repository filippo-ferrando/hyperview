package tui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"hyperview/internal/alert"
	"hyperview/internal/probe"
	"hyperview/internal/store"
)

func (m *Model) viewDashboard() string {
	header := m.viewHeader()
	footer := m.viewFooter([][2]string{{"enter", "details"}, {"/", "filter"}, {"a", "alerts"},
		{"s", "sort:" + sortNames[m.sort]}, {"↑↓", "select"}, {"p", "probes"}, {"q", "quit"}, {"?", "help"}})

	avail := m.height - lipgloss.Height(header) - lipgloss.Height(footer)
	// The alerts pane shows what it has, up to 40% of the space; the VM
	// table gets the rest.
	alertsH := min(max(len(m.alerts)+2, 5), max(avail*2/5, 5))
	tableH := max(avail-alertsH, 4)

	table := m.viewVMTable(m.width, tableH)
	pane := m.viewAlertPane(m.width, alertsH)
	return lipgloss.JoinVertical(lipgloss.Left, header, table, pane, footer)
}

// viewHeader renders the host summary: identity and source status on the
// first line, utilization gauges and pressure on the second.
func (m *Model) viewHeader() string {
	h := &m.host
	w := m.width

	title := lipgloss.NewStyle().Foreground(colBg).Background(colAccent).Bold(true).Padding(0, 1).Render("hyperview")
	status := m.sourceBadges()
	if w >= 90 {
		status += "  " + stMuted.Render(m.now.Format("15:04:05"))
	}
	// The hostname always shows; kernel details only when they fit.
	ident := stBold.Render(" " + h.Hostname)
	details := stMuted.Render(fmt.Sprintf("  %s · %s · %d CPU · up %s", h.Kernel, h.Arch, h.CPUs, fmtDuration(h.Uptime)))
	if lipgloss.Width(title+ident+details+status)+2 <= w {
		ident += details
	}
	line1 := lipgloss.NewStyle().Background(colTitleBar).Width(w).
		Render(spread(title+ident, status+" ", w))

	cpuC := levelColor(h.CPUPercent, 80, 95)
	memPct := h.MemUsedPercent()
	memC := levelColor(memPct, 85, 95)
	load := stLabel.Render("  LOAD ") + stBase.Render(fmt.Sprintf("%.2f", h.Load1))
	if h.SwapTotalKiB > 0 {
		used := h.SwapTotalKiB - h.SwapFreeKiB
		load += stLabel.Render("  SWAP ") + fg(levelColor(float64(used)/float64(h.SwapTotalKiB)*100, 25, 60)).Render(fmtKiB(used))
	}
	psi := ""
	if h.PSI.Available {
		th := m.src.Config.Thresholds
		p := func(name string, v, warn, crit float64) string {
			return stLabel.Render(name) + fg(levelColor(v, warn, crit)).Render(fmt.Sprintf("%.1f", v))
		}
		psi = stLabel.Render("  PSI ") + p("cpu ", h.PSI.CPUSome, th.PSICPUSome.Warn, th.PSICPUSome.Crit) +
			p(" mem ", h.PSI.MemSome, th.PSIMemSome.Warn, th.PSIMemSome.Crit) +
			p("/", h.PSI.MemFull, th.PSIMemFull.Warn, th.PSIMemFull.Crit) +
			p(" io ", h.PSI.IOSome, th.PSIIOFull.Warn, th.PSIIOFull.Crit) +
			p("/", h.PSI.IOFull, th.PSIIOFull.Warn, th.PSIIOFull.Crit)
	}
	memTxt := fmt.Sprintf(" %s/%s ", fmtKiB(h.MemTotalKiB-h.MemAvailKiB), fmtKiB(h.MemTotalKiB))
	// Sparklines share whatever width the text leaves; PSI goes first when
	// the terminal is too narrow.
	fixedW := 2*12 + lipgloss.Width(memTxt) + lipgloss.Width(load)
	if w-fixedW-lipgloss.Width(psi) < 2*8 {
		psi = ""
	}
	sparkW := min(max((w-fixedW-lipgloss.Width(psi))/2, 0), 30)
	if sparkW < 6 {
		sparkW = 0
	}
	cpu := stLabel.Render(" CPU ") + fg(cpuC).Render(fmt.Sprintf("%5.1f%%", h.CPUPercent))
	if sparkW > 0 {
		cpu += " " + sparkline(m.hostH.CPU, sparkW, 100, cpuC)
	}
	mem := stLabel.Render("  MEM ") + fg(memC).Render(fmt.Sprintf("%5.1f%%", memPct)) + stMuted.Render(memTxt) +
		sparkline(m.hostH.Mem, sparkW, 100, memC)
	line2 := fit(cpu+mem+load+psi, w)

	disks := m.diskLine()
	if disks == "" {
		return lipgloss.JoinVertical(lipgloss.Left, line1, line2)
	}
	return lipgloss.JoinVertical(lipgloss.Left, line1, line2, disks)
}

// diskLine summarizes eBPF host disk latency, busiest devices first.
func (m *Model) diskLine() string {
	var parts []string
	th := m.src.Config.Thresholds.DiskP99Us
	for _, d := range m.host.Disks {
		if d.IOPS < 0.5 && d.Errors == 0 {
			continue
		}
		s := stBase.Render(d.Name) + stMuted.Render(fmt.Sprintf(" %s iops p99 ", fmtNum(d.IOPS))) +
			fg(levelColor(d.P99Us, th.Warn, th.Crit)).Render(fmtUs(d.P99Us))
		if d.Errors > 0 {
			s += fg(colRed).Render(fmt.Sprintf(" %d err", d.Errors))
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return ""
	}
	return fit(stLabel.Render(" DISK ")+strings.Join(parts, stDim.Render("  │  ")), m.width)
}

func (m *Model) sourceBadges() string {
	badge := func(name string, ok bool, detail string) string {
		dot := fg(colGreen).Render("●")
		if !ok {
			dot = fg(colDim).Render("○")
		}
		return dot + stMuted.Render(" "+name+detail)
	}
	var parts []string
	if m.src.EBPF != nil {
		ok, _ := m.src.EBPF()
		detail := ""
		if ok && m.src.Probes != nil {
			st := m.src.Probes()
			n := 0
			for _, s := range st {
				if s.State == probe.Attached {
					n++
				}
			}
			detail = fmt.Sprintf(" %d/%d", n, len(st))
		}
		parts = append(parts, badge("eBPF", ok, detail))
	}
	if m.src.Kmsg != nil {
		parts = append(parts, badge("kmsg", m.src.Kmsg() == "", ""))
	}
	if m.src.Libvirt != nil {
		parts = append(parts, badge("libvirt", m.src.Libvirt() != "", ""))
	}
	return strings.Join(parts, "  ")
}

// VM table columns, indexes used by vmRow.
const (
	vcMarker = iota
	vcName
	vcSource
	vcState
	vcVCPU
	vcCPU
	vcPct
	vcMem
	vcNet
	vcDisk
	vcAlerts
)

func (m *Model) vmColumns(w int) []column {
	return layout([]column{
		vcMarker: {width: 2},
		vcName:   {title: "NAME", flex: 4, min: 10, max: 40},
		vcSource: {title: "SOURCE", width: 8, prio: 1},
		vcState:  {title: "STATE", flex: 6, min: 8, max: 16},
		vcVCPU:   {title: "vCPU", width: 4, right: true, prio: 3},
		vcCPU:    {title: "CPU", flex: 4, min: 6, prio: 5},
		vcPct:    {title: "%", width: 6, right: true, prio: 6},
		vcMem:    {title: "MEMORY", width: 15, right: true, prio: 8},
		vcNet:    {title: "NET ↓/↑", width: 17, right: true, prio: 4},
		vcDisk:   {title: "DISK rd/wr", width: 17, right: true, prio: 2},
		vcAlerts: {title: "⚠", width: 4, right: true},
	}, w)
}

func renderRow(cols []column, cells []string) string {
	var b strings.Builder
	for i, c := range cols {
		if c.width == 0 {
			continue
		}
		if c.right {
			b.WriteString(fitRight(cells[i], c.width))
		} else {
			b.WriteString(fit(cells[i], c.width))
		}
		b.WriteByte(' ')
	}
	return b.String()
}

func (m *Model) viewVMTable(w, h int) string {
	inner := w - 4
	cols := m.vmColumns(inner)
	lines := []string{stHeadRow.Render(renderRow(cols, titles(cols)))}

	rows := h - 3 // border + header
	start := 0
	if m.cursor >= rows {
		start = m.cursor - rows + 1
	}
	for i := start; i < len(m.visible) && i < start+rows; i++ {
		d := &m.visible[i]
		lines = append(lines, m.vmRow(cols, d, i == m.cursor))
	}
	if len(m.visible) == 0 {
		msg := "no KVM guests found"
		if m.filter != "" {
			msg = "no VM matches “" + m.filter + "”"
		}
		lines = append(lines, "", lipgloss.PlaceHorizontal(inner, lipgloss.Center, stMuted.Render(msg)))
	}
	for len(lines) < h-2 {
		lines = append(lines, "")
	}

	title := fmt.Sprintf(" Virtual machines (%d) ", len(m.visible))
	if m.filter != "" || m.filtering {
		cursor := ""
		if m.filtering {
			cursor = "█"
		}
		title += stAccent.Render("filter: "+m.filter+cursor) + " "
	}
	sortTitle := fmt.Sprintf(" sort: %s%s ", sortNames[m.sort], map[bool]string{true: " ↑", false: ""}[m.reverse])
	return box(strings.Join(lines, "\n"), w, title, sortTitle, m.screen == scrDashboard)
}

func (m *Model) vmRow(cols []column, d *store.DomainSnapshot, selected bool) string {
	hist := m.src.Store.History(d.ID)
	cpu := d.CPUPercent()
	nv := max(len(d.VCPUs), 1)
	cpuC := levelColor(cpu/float64(nv), 80, 95)

	mem := "–"
	if used := d.Mem.RssKiB; used > 0 || d.Mem.MaxKiB > 0 {
		mem = fmtKiB(used) + stMuted.Render("/"+fmtKiB(max(d.Mem.MaxKiB, d.Mem.BalloonKiB)))
	}
	rx, tx := d.NetRates()
	rd, wr := d.DiskRates()

	alerts := ""
	if c, ok := m.counts[d.ID]; ok && c.N > 0 {
		alerts = fg(severityColor(c.Worst)).Render(fmt.Sprintf("%s%d", severityIcon(c.Worst), c.N))
	}
	running := d.Running()
	dim := func(s string) string {
		if running {
			return s
		}
		return stDim.Render(s)
	}
	stateTxt := d.State
	if d.Reason != "" && d.State != "running" {
		stateTxt += " (" + d.Reason + ")"
	}
	marker, name := " ", stBold.Render(d.Name)
	if selected {
		marker, name = stAccent.Render("▌"), stAccent.Bold(true).Render(d.Name)
	}
	cells := []string{
		marker + fg(stateColor(d.State, d.Reason)).Render("●"),
		name,
		stMuted.Render(d.Source),
		fg(stateColor(d.State, d.Reason)).Render(stateTxt),
		dim(fmt.Sprint(len(d.VCPUs))),
		sparkline(hist.CPU, cols[vcCPU].width, float64(nv)*100, cpuC),
		fg(cpuC).Render(fmt.Sprintf("%.1f", cpu)),
		mem,
		fg(colRx).Render(fmtBytes(rx)) + stMuted.Render("/") + fg(colTx).Render(fmtBytes(tx)),
		stBase.Render(fmtBytes(rd)) + stMuted.Render("/") + stBase.Render(fmtBytes(wr)),
		alerts,
	}
	if !running {
		cells[vcCPU], cells[vcPct], cells[vcNet], cells[vcDisk] = "", stDim.Render("–"), stDim.Render("–"), stDim.Render("–")
	}
	return renderRow(cols, cells)
}

func (m *Model) viewAlertPane(w, h int) string {
	inner := w - 4
	var active, recent int
	for _, a := range m.alerts {
		if a.Active {
			active++
		} else {
			recent++
		}
	}
	rows := h - 2
	var lines []string
	for i := 0; i < len(m.alerts) && len(lines) < rows; i++ {
		lines = append(lines, alertLine(&m.alerts[i], inner, false))
	}
	if len(lines) == 0 {
		lines = append(lines, fg(colGreen).Render("✔ ")+stMuted.Render("no alerts — all monitored subsystems look healthy"))
	}
	for len(lines) < rows {
		lines = append(lines, "")
	}
	title := fmt.Sprintf(" Alerts · %d active · %d recent ", active, recent)
	return box(strings.Join(lines, "\n"), w, title, " a: all alerts ", false)
}

// alertLine renders one alert in a single row. Narrow rows merge the state
// into the time column and shrink or drop the rule column, so the message
// keeps most of the space.
func alertLine(a *alert.Alert, w int, selected bool) string {
	c := severityColor(a.Severity)
	marker := " "
	if selected {
		marker = stAccent.Render("▌")
	}
	head := marker + fg(c).Render(severityIcon(a.Severity)) + " "

	when := stMuted.Render(a.Last.Format("15:04:05"))
	state := "      "
	switch {
	case a.Active:
		state = fg(c).Bold(true).Render("ACTIVE")
	case !a.Resolved.IsZero():
		state = fg(colGreen).Render("solved")
	}
	ruleW, whereW := 22, 20
	if w < 110 {
		// One column: ACTIVE replaces the time of firing conditions.
		if a.Active {
			when = fit(state, 8)
		}
		state = ""
		ruleW, whereW = 18, 14
	}
	if w < 75 {
		ruleW, whereW = 0, 12
	}

	where := a.DomainName
	if a.Subject != "" {
		if where != "" {
			where += "/"
		}
		where += a.Subject
	}
	if where == "" {
		where = "host"
	}
	count := ""
	if a.Count > 1 {
		count = stMuted.Render(fmt.Sprintf(" ×%d", a.Count))
	}
	line := head + when + " "
	if state != "" {
		line += state + " "
	}
	if ruleW > 0 {
		line += fit(fg(c).Render(a.Rule), ruleW) + " "
	}
	line += fit(stBold.Render(where), whereW) + " " + stBase.Render(a.Message) + count
	return fit(line, w)
}

// viewFooter lists key hints in priority order, dropping the tail when the
// terminal is narrow; the last hint (help) is always kept.
func (m *Model) viewFooter(keys [][2]string) string {
	hint := func(k [2]string) string { return stKey.Render(k[0]) + " " + stMuted.Render(k[1]) }
	sep := stDim.Render("  ·  ")
	if len(keys) == 0 {
		return ""
	}
	last := hint(keys[len(keys)-1])
	out := " "
	for _, k := range keys[:len(keys)-1] {
		h := hint(k)
		if lipgloss.Width(out+h+sep+sep+last) > m.width {
			break
		}
		out += h + sep
	}
	return fit(out+last, m.width)
}

// box draws a rounded panel of total width w with a left and right title
// embedded in the top border.
func box(content string, w int, left, right string, hot bool) string {
	bc := colBorder
	if hot {
		bc = colAccent
	}
	b := lipgloss.RoundedBorder()
	bs := fg(bc)
	inner := w - 2
	l := stTitle.Render(ansi.Truncate(left, max(inner-4, 0), "… "))
	r := stMuted.Render(right)
	fill := inner - 1 - lipgloss.Width(l) - lipgloss.Width(r) - 1
	if fill < 0 {
		r, fill = "", max(inner-2-lipgloss.Width(l), 0)
	}
	top := bs.Render(b.TopLeft+b.Top) + l + bs.Render(strings.Repeat(b.Top, fill)) + r + bs.Render(b.Top+b.TopRight)
	if lipgloss.Width(top) > w {
		top = fit(top, w)
	}
	var out []string
	out = append(out, top)
	for _, line := range strings.Split(content, "\n") {
		out = append(out, bs.Render(b.Left)+" "+fit(line, inner-2)+" "+bs.Render(b.Right))
	}
	out = append(out, bs.Render(b.BottomLeft+strings.Repeat(b.Bottom, inner)+b.BottomRight))
	return strings.Join(out, "\n")
}
