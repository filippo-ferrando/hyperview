package tui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"hyperview/internal/alert"
	"hyperview/internal/probe"
)

func (m *Model) filteredAlerts() []alert.Alert {
	var out []alert.Alert
	for _, a := range m.alerts {
		if a.Severity >= m.alertMin {
			out = append(out, a)
		}
	}
	return out
}

func (m *Model) viewAlerts() string {
	header := m.viewHeader()
	footer := m.viewFooter([][2]string{{"↑↓", "select"}, {"f", "min severity: " + m.alertMin.String()}, {"esc", "back"}, {"?", "help"}})
	bodyH := m.height - lipgloss.Height(header) - lipgloss.Height(footer)
	inner := m.width - 4
	as := m.filteredAlerts()
	m.alertCursor = min(m.alertCursor, max(len(as)-1, 0))

	detailH := 7
	listH := max(bodyH-detailH-2, 3)
	start := 0
	if m.alertCursor >= listH {
		start = m.alertCursor - listH + 1
	}
	var lines []string
	for i := start; i < len(as) && len(lines) < listH; i++ {
		lines = append(lines, alertLine(&as[i], inner, i == m.alertCursor))
	}
	if len(as) == 0 {
		lines = append(lines, fg(colGreen).Render("✔ ")+stMuted.Render("no alerts at this severity"))
	}
	for len(lines) < listH {
		lines = append(lines, "")
	}
	list := box(strings.Join(lines, "\n"), m.width, fmt.Sprintf(" Alerts (%d) ", len(as)), "", true)

	var det []string
	if len(as) > 0 {
		a := as[m.alertCursor]
		c := severityColor(a.Severity)
		where := orDash(a.DomainName)
		status := "event"
		switch {
		case a.Active:
			status = fg(c).Bold(true).Render("active")
		case !a.Resolved.IsZero():
			status = fg(colGreen).Render("resolved " + a.Resolved.Format("15:04:05"))
		}
		det = append(det,
			fg(c).Bold(true).Render(strings.ToUpper(a.Severity.String()))+"  "+stBold.Render(a.Rule)+stMuted.Render("  ·  "+string(a.Category)+"  ·  source "+a.Source),
			kvGrid([][2]string{
				{"VM", stBase.Render(where)},
				{"Subject", stBase.Render(orDash(a.Subject))},
				{"Status", status},
				{"First seen", stBase.Render(a.First.Format("2006-01-02 15:04:05"))},
				{"Last seen", stBase.Render(a.Last.Format("15:04:05"))},
				{"Occurrences", stBase.Render(fmt.Sprint(a.Count))},
			}, 3, inner),
		)
		det = append(det, wrap(a.Message, inner)...)
	}
	for len(det) < detailH-2 {
		det = append(det, "")
	}
	detail := box(strings.Join(det[:detailH-2], "\n"), m.width, " Details ", "", false)
	return lipgloss.JoinVertical(lipgloss.Left, header, list, detail, footer)
}

func wrap(s string, w int) []string {
	return strings.Split(lipgloss.NewStyle().Width(w).Render(s), "\n")
}

func (m *Model) viewStatus() string {
	header := m.viewHeader()
	footer := m.viewFooter([][2]string{{"↑↓", "scroll"}, {"esc", "back"}, {"?", "help"}})
	bodyH := m.height - lipgloss.Height(header) - lipgloss.Height(footer)
	inner := m.width - 4

	ok := func(b bool, yes, no string) string {
		if b {
			return fg(colGreen).Render("● ") + stBase.Render(yes)
		}
		return fg(colDim).Render("○ ") + stMuted.Render(no)
	}
	var out []string
	out = append(out, section("Data sources"))
	if m.src.Libvirt != nil {
		sock := m.src.Libvirt()
		out = append(out, "  "+fit(stLabel.Render("libvirt"), 14)+ok(sock != "", "connected "+sock, "not connected (no libvirtd/virtqemud socket)"))
	}
	out = append(out, "  "+fit(stLabel.Render("/proc scan"), 14)+ok(true, "KVM processes from any hypervisor", ""))
	out = append(out, "  "+fit(stLabel.Render("QMP"), 14)+ok(m.src.Config.QMP.Enabled,
		fmt.Sprintf("polling non-libvirt QEMU every %s", m.src.Config.QMP.Interval.Duration), "disabled (enable [qmp] in the config)"))
	if m.src.Kmsg != nil {
		why := m.src.Kmsg()
		out = append(out, "  "+fit(stLabel.Render("kernel log"), 14)+ok(why == "", "following /dev/kmsg", why))
	}
	out = append(out, "  "+fit(stLabel.Render("PSI"), 14)+ok(m.host.PSI.Available, "/proc/pressure", "unavailable (kernel without CONFIG_PSI or psi=0)"))

	out = append(out, "", section("eBPF probes"))
	if m.src.EBPF != nil {
		if en, why := m.src.EBPF(); !en {
			out = append(out, "  "+fg(colAmber).Render("▲ ")+stBase.Render("disabled: "+why))
		}
	}
	if m.src.Probes != nil {
		cols := layout([]column{
			{title: "FEATURE", width: 11, prio: 1},
			{title: "PROBE", flex: 1, min: 14, max: 28},
			{title: "STATE", width: 11},
			{title: "DETAIL", flex: 2, min: 10, prio: 2},
		}, inner-2)
		out = append(out, "  "+stHeadRow.Render(renderRow(cols, titles(cols))))
		for _, s := range m.src.Probes() {
			c := colGreen
			switch s.State {
			case probe.Failed:
				c = colRed
			case probe.Unavailable, probe.Disabled:
				c = colDim
			}
			out = append(out, "  "+renderRow(cols, []string{stBold.Render(s.Feature), stBase.Render(s.Probe),
				fg(c).Render(s.State.String()), stMuted.Render(s.Err)}))
		}
	}

	out = scrollLines(out, &m.scroll, bodyH-2)
	return lipgloss.JoinVertical(lipgloss.Left, header,
		box(strings.Join(out, "\n"), m.width, " Status ", "", true), footer)
}

func (m *Model) viewLog() string {
	header := m.viewHeader()
	footer := m.viewFooter([][2]string{{"↑↓", "scroll"}, {"esc", "back"}})
	bodyH := m.height - lipgloss.Height(header) - lipgloss.Height(footer)
	lines := GlobalLogRing.GetTail(500)
	for i, l := range lines {
		lines[i] = stMuted.Render(strings.TrimRight(l, "\n"))
	}
	// Newest at the bottom; scrolling moves back in time.
	rows := bodyH - 2
	end := max(len(lines)-m.scroll, min(rows, len(lines)))
	m.scroll = len(lines) - end
	start := max(end-rows, 0)
	view := lines[start:end]
	for len(view) < rows {
		view = append(view, "")
	}
	return lipgloss.JoinVertical(lipgloss.Left, header,
		box(strings.Join(view, "\n"), m.width, " Log ", "", true), footer)
}

func scrollLines(lines []string, scroll *int, rows int) []string {
	*scroll = min(*scroll, max(len(lines)-rows, 0))
	lines = lines[*scroll:]
	if len(lines) > rows {
		lines = lines[:rows]
	}
	for len(lines) < rows {
		lines = append(lines, "")
	}
	return lines
}

func (m *Model) viewHelp() string {
	keys := [][2]string{
		{"↑ ↓  j k", "move selection / scroll"},
		{"PgUp PgDn", "page up / down"},
		{"g G", "first / last"},
		{"enter → l", "open VM details"},
		{"← → h l  1-9", "switch detail tab"},
		{"esc q", "back (q quits on the dashboard)"},
		{"/", "filter VMs by name or source"},
		{"s  r", "cycle sort column  /  reverse"},
		{"a", "alerts view"},
		{"f", "alerts: minimum severity"},
		{"p", "probe and data source status"},
		{"L", "internal log"},
		{"ctrl+c", "quit"},
	}
	var lines []string
	for _, k := range keys {
		lines = append(lines, stKey.Render(fit(k[0], 15))+stBase.Render(k[1]))
	}
	lines = append(lines, "", stMuted.Render("Severity: ")+fg(colRed).Render("✖ critical  ")+fg(colAmber).Render("▲ warning  ")+fg(colAccent).Render("● info"))
	return stBoxHot.Background(colPanel).Render(stTitle.Render("Keys") + "\n\n" + strings.Join(lines, "\n"))
}
